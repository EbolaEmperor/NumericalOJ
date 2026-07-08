#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import hashlib
import os
import posixpath
import zipfile
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher

import pymysql
from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request, session, url_for

from oj_modules.db_services import (
    CLASS_ADJUST_FLAG_KEY,
    get_all_classes_except_admin,
    get_all_problems,
    get_class_by_en,
    get_db_connection,
    get_problem,
    get_problem_title,
    get_user_by_username,
    safe_table_name,
    set_setting,
)
from oj_modules.ranking_db import get_competition, list_competitions
from oj_modules.repository_services import extract_includes_from_code, get_user_repository_files_by_names


homework_bp = Blueprint('homework', __name__)

_rds = None
_rds_binary = None
_export_task = None
_plagiarism_task = None

_PLAGIARISM_TARGET_PROBLEM = 'problem'
_PLAGIARISM_TARGET_RANKING = 'ranking'
_PLAGIARISM_TEX_MAX_FILES = 256
_PLAGIARISM_TEX_MAX_TOTAL_BYTES = 20 * 1024 * 1024


def _wants_json_response():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    if request.is_json:
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept and 'text/html' not in accept


def _json_or_homework_redirect(message, status=400, *, class_en=None):
    if _wants_json_response():
        return jsonify(success=False, message=message), status
    flash(message, 'danger')
    if class_en:
        return redirect(url_for('homework.admin_homework', sclass=class_en))
    return redirect(url_for('homework.admin_homework'))


def _invalidate_problem_list_cache_for_class(class_en):
    try:
        from oj_modules.routes.problem_core_routes import invalidate_problem_list_cache_for_class
        invalidate_problem_list_cache_for_class(class_en)
    except Exception:
        # 缓存失效失败不影响主流程
        pass


from oj_modules.auth_helpers import current_user, is_admin


def init_homework_module(celery_app, redis_client, redis_binary_client):
    global _rds, _rds_binary, _export_task, _plagiarism_task
    _rds = redis_client
    _rds_binary = redis_binary_client

    if _export_task is None:
        @celery_app.task(bind=True, name='oj.homework.export_codes_with_plagiarism_check_task')
        def export_codes_with_plagiarism_check_task(self, selected_class):
            task_id = self.request.id

            try:
                class_info = get_class_by_en(selected_class)
                if not class_info:
                    update_export_progress(task_id, 'error', 0, 1, '班级不存在')
                    return None

                update_export_progress(task_id, 'collecting', 0, 100, '开始收集学生代码...')

                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute(f"SELECT problem_id FROM {safe_table_name(selected_class)} ORDER BY id ASC")
                        homework_problems = cursor.fetchall()
                finally:
                    conn.close()
                if not homework_problems:
                    update_export_progress(task_id, 'error', 0, 1, '该班级没有布置任何作业')
                    return None

                problem_ids = [p['problem_id'] for p in homework_problems if p.get('problem_id') is not None]
                if not problem_ids:
                    update_export_progress(
                        task_id,
                        'error',
                        0,
                        1,
                        '该班级没有可导出的普通题作业（打榜赛暂不导出代码）',
                    )
                    return None

                problems_map = {}
                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        fmt = ','.join(['%s'] * len(problem_ids))
                        cursor.execute(f"SELECT id, title, lang FROM problems WHERE id IN ({fmt})", problem_ids)
                        for row in cursor.fetchall():
                            problems_map[row['id']] = {'title': row['title'], 'lang': (row.get('lang') or 'matlab').lower()}
                finally:
                    conn.close()

                conn = get_db_connection()
                try:
                    with conn.cursor() as cursor:
                        cursor.execute(
                            """
                            SELECT u.id, u.username
                            FROM user_class_map m
                            JOIN users u ON u.id = m.user_id
                            WHERE m.class_en = %s
                            ORDER BY u.id ASC
                            """,
                            (selected_class,),
                        )
                        students = cursor.fetchall()
                        if not students:
                            cursor.execute("SELECT id, username FROM users WHERE class = %s ORDER BY id ASC", (selected_class,))
                            students = cursor.fetchall()
                finally:
                    conn.close()
                if not students:
                    update_export_progress(task_id, 'error', 0, 1, '该班级没有学生')
                    return None

                update_export_progress(task_id, 'collecting', 10, 100, f'找到 {len(students)} 名学生，{len(problem_ids)} 道题目')

                from io import BytesIO
                import re
                import zipfile

                zip_buffer = BytesIO()

                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for idx, pid in enumerate(problem_ids):
                        pmeta = problems_map.get(pid, {})
                        ptitle = pmeta.get('title') or f'Problem_{pid}'
                        plang = (pmeta.get('lang') or 'matlab').lower()

                        update_export_progress(
                            task_id,
                            'collecting',
                            10 + idx * 40 // len(problem_ids),
                            100,
                            f'正在收集题目 {idx + 1}/{len(problem_ids)}: {ptitle}',
                        )

                        folder_name = re.sub(r'[\\/*?:"<>|]', '_', ptitle)

                        if plang == 'matlab':
                            ext = '.m'
                        elif plang == 'c':
                            ext = '.c'
                        elif plang == 'cpp':
                            ext = '.cpp'
                        elif plang in ('python', 'py'):
                            ext = '.py'
                        else:
                            ext = '.txt'

                        conn = get_db_connection()
                        try:
                            with conn.cursor() as cursor:
                                sql = """
                                    WITH class_users AS (
                                        SELECT u.id, u.username
                                        FROM user_class_map m
                                        JOIN users u ON u.id = m.user_id
                                        WHERE m.class_en = %s
                                        UNION
                                        SELECT u2.id, u2.username
                                        FROM users u2
                                        WHERE u2.class = %s
                                          AND NOT EXISTS (
                                              SELECT 1 FROM user_class_map m2
                                              WHERE m2.user_id = u2.id AND m2.class_en = %s
                                          )
                                    ),
                                    ranked_submissions AS (
                                        SELECT s.id, s.username, s.code, s.score, s.created_at,
                                               ROW_NUMBER() OVER (
                                                   PARTITION BY cu.id
                                                   ORDER BY s.score DESC, s.created_at DESC
                                               ) AS rn
                                        FROM submissions s
                                        JOIN class_users cu ON cu.username = s.username
                                        WHERE s.problem_id = %s
                                    )
                                    SELECT username, code
                                    FROM ranked_submissions
                                    WHERE rn = 1
                                    ORDER BY username ASC
                                """
                                cursor.execute(sql, (selected_class, selected_class, selected_class, pid))
                                best_rows = cursor.fetchall()
                        finally:
                            conn.close()

                        for row in best_rows:
                            uname = row['username']
                            code = row.get('code') or ""

                            safe_uname = re.sub(r'[\\/*?:"<>|]', '_', uname)
                            file_name = f"{folder_name}/{safe_uname}{ext}"
                            try:
                                info = zipfile.ZipInfo(file_name)
                                info.flag_bits |= 0x800
                                zip_file.writestr(info, code.encode('utf-8'))
                            except Exception:
                                info = zipfile.ZipInfo(file_name)
                                info.flag_bits |= 0x800
                                zip_file.writestr(info, code)

                    update_export_progress(task_id, 'collecting', 60, 100, '题目代码收集完成，开始收集代码仓库...')

                    for idx, student in enumerate(students):
                        user_id = student['id']
                        username = student['username']

                        update_export_progress(
                            task_id,
                            'collecting',
                            60 + idx * 30 // len(students),
                            100,
                            f'正在收集 {username} 的代码仓库 ({idx + 1}/{len(students)})',
                        )

                        repo_files = get_student_repository_files(user_id)

                        if repo_files:
                            safe_uname = re.sub(r'[\\/*?:"<>|]', '_', username)
                            for repo_file in repo_files:
                                file_name = f"代码仓库/{safe_uname}/{repo_file['filename']}"
                                try:
                                    info = zipfile.ZipInfo(file_name)
                                    info.flag_bits |= 0x800
                                    zip_file.writestr(info, repo_file['content'].encode('utf-8'))
                                except Exception:
                                    info = zipfile.ZipInfo(file_name)
                                    info.flag_bits |= 0x800
                                    zip_file.writestr(info, repo_file['content'])

                    update_export_progress(task_id, 'generating', 92, 100, '正在生成代码压缩包...')

                update_export_progress(task_id, 'generating', 95, 100, '准备下载文件...')

                zip_data = zip_buffer.getvalue()
                _rds_binary.setex(f'export_zip:{task_id}', 600, zip_data)

                update_export_progress(
                    task_id,
                    'completed',
                    100,
                    100,
                    '导出完成',
                )
                return task_id

            except Exception as e:
                import traceback

                error_msg = f'导出失败: {str(e)}'
                update_export_progress(task_id, 'error', 0, 1, error_msg)
                print(traceback.format_exc())
                return None

        _export_task = export_codes_with_plagiarism_check_task

    if _plagiarism_task is None:
        @celery_app.task(bind=True, name='oj.homework.mark_plagiarism_task')
        def mark_plagiarism_task(self, class_en, mode, threshold, targets):
            task_id = self.request.id
            try:
                class_en = str(class_en or '').strip()
                mode = str(mode or 'threshold').strip()
                threshold = float(threshold)
                normalized_targets = []
                for item in (targets or []):
                    if isinstance(item, dict):
                        normalized_targets.append(item)
                    else:
                        normalized_targets.append(_normalize_plagiarism_target(item))

                class_info = get_class_by_en(class_en)
                if not class_info:
                    update_plagiarism_progress(task_id, 'error', 0, 1, '班级不存在')
                    return None

                update_plagiarism_progress(task_id, 'collecting', 0, 100, '正在收集提交材料...')

                def status_callback(stage, current, total, message):
                    update_plagiarism_progress(task_id, stage, current, total, message)

                def compare_callback(current, total, message):
                    update_plagiarism_progress(task_id, 'checking', current, total, message)

                result = mark_class_plagiarism(
                    class_en,
                    class_info.get('class_cn'),
                    normalized_targets,
                    mode,
                    threshold,
                    progress_callback=compare_callback,
                    status_callback=status_callback,
                )

                _invalidate_problem_list_cache_for_class(class_en)
                update_plagiarism_progress(
                    task_id,
                    'completed',
                    100,
                    100,
                    f"标记完成：发现 {result['group_count']} 组，写入 {result['record_count']} 条记录",
                    result=result,
                )
                return result
            except pymysql.Error:
                update_plagiarism_progress(task_id, 'error', 0, 1, '数据库操作失败，请稍后再试')
                return None
            except Exception as exc:
                update_plagiarism_progress(task_id, 'error', 0, 1, f'标记失败: {exc}')
                return None

        _plagiarism_task = mark_plagiarism_task


@homework_bp.route('/admin/homework')
def admin_homework():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    selected_class = request.args.get('sclass')
    classes = get_all_classes_except_admin()

    valid_classes = [cls['class_en'] for cls in classes]
    if selected_class and selected_class not in valid_classes:
        flash('无效的班级选择', 'danger')
        return redirect(url_for('homework.admin_homework'))

    homework_list = []
    plagiarism_problem_options = []
    if selected_class:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"SELECT * FROM {safe_table_name(selected_class)} ORDER BY id ASC"
                cursor.execute(sql)
                homework_list = cursor.fetchall()
                for hw in homework_list:
                    if hw.get('ranking_competition_id'):
                        hw['is_ranking'] = True
                        # ranking 作业：沿用入库时存的比赛标题（problem_title 列）
                        if not hw.get('problem_title'):
                            hw['problem_title'] = '未知打榜赛'
                        try:
                            cid = int(hw['ranking_competition_id'])
                        except (TypeError, ValueError):
                            cid = None
                        if cid is not None and not any(
                            item.get('kind') == _PLAGIARISM_TARGET_RANKING and item.get('id') == cid
                            for item in plagiarism_problem_options
                        ):
                            plagiarism_problem_options.append({
                                'kind': _PLAGIARISM_TARGET_RANKING,
                                'id': cid,
                                'target': f'{_PLAGIARISM_TARGET_RANKING}:{cid}',
                                'title': hw['problem_title'],
                            })
                    else:
                        hw['is_ranking'] = False
                        problem = get_problem(hw['problem_id'])
                        hw['problem_title'] = problem['title'] if problem else '未知题目'
                        try:
                            pid = int(hw['problem_id'])
                        except (TypeError, ValueError):
                            pid = None
                        if pid is not None and not any(
                            item.get('kind') == _PLAGIARISM_TARGET_PROBLEM and item.get('id') == pid
                            for item in plagiarism_problem_options
                        ):
                            plagiarism_problem_options.append({
                                'kind': _PLAGIARISM_TARGET_PROBLEM,
                                'id': pid,
                                'target': f'{_PLAGIARISM_TARGET_PROBLEM}:{pid}',
                                'title': hw['problem_title'],
                            })
        except pymysql.Error as e:
            flash(f'数据库操作失败，请稍后再试', 'danger')
        finally:
            conn.close()

    all_problems = [{'id': p['id'], 'title': p['title']} for p in (get_all_problems() or [])]
    try:
        all_competitions = [
            {'id': c['id'], 'title': c['title'], 'scoring_mode': c.get('scoring_mode')}
            for c in (list_competitions(include_inactive=True) or [])
        ]
    except Exception:
        all_competitions = []

    return render_template(
        'admin_homework.html',
        classes=classes,
        selected_class=selected_class,
        homework_list=homework_list,
        all_problems=all_problems,
        all_competitions=all_competitions,
        plagiarism_problem_options=plagiarism_problem_options,
        user=user,
    )


@homework_bp.route('/admin/class_adjust', methods=['POST'])
def admin_class_adjust():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    enabled = request.form.get('enabled', '0')
    set_setting(CLASS_ADJUST_FLAG_KEY, '1' if enabled == '1' else '0')
    return jsonify(success=True, enabled=(enabled == '1'))


@homework_bp.route('/admin/update_ddl', methods=['POST'])
def admin_update_ddl():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    data = request.get_json()
    class_en = data.get('class_en')
    homework_id = data.get('homework_id')
    new_ddl = data.get('new_ddl')

    if not all([class_en, homework_id, new_ddl]):
        return jsonify(success=False, message='参数不完整'), 400

    if not get_class_by_en(class_en):
        return jsonify(success=False, message='班级不存在'), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"UPDATE {safe_table_name(class_en)} SET ddl=%s WHERE id=%s"
            cursor.execute(sql, (new_ddl, homework_id))
        conn.commit()
        _invalidate_problem_list_cache_for_class(class_en)
        return jsonify(success=True, message='DDL更新成功')
    except pymysql.Error as e:
        return jsonify(success=False, message=f'数据库操作失败，请稍后再试'), 500
    finally:
        conn.close()


@homework_bp.route('/admin/add_homework', methods=['POST'])
def admin_add_homework():
    user = current_user()
    if not is_admin(user):
        return _json_or_homework_redirect('无权限操作', 403)

    class_en = request.form.get('class_en')
    ddl = request.form.get('ddl')
    problem_id = (request.form.get('problem_id') or '').strip()
    ranking_competition_id = (request.form.get('ranking_competition_id') or '').strip()

    if not class_en or not ddl:
        return _json_or_homework_redirect('缺少必要参数', 400, class_en=class_en)
    # 题目 / 打榜赛 必须恰好二选一
    if bool(problem_id) == bool(ranking_competition_id):
        return _json_or_homework_redirect('请选择一项作业内容：题目 或 打榜赛', 400, class_en=class_en)
    if not get_class_by_en(class_en):
        return _json_or_homework_redirect('班级不存在', 404)

    try:
        if problem_id:
            try:
                pid = int(problem_id)
            except ValueError:
                return _json_or_homework_redirect('题目ID必须是数字', 400, class_en=class_en)
            problem = get_problem_title(pid)
            if not problem:
                return _json_or_homework_redirect('题目不存在', 404, class_en=class_en)
            col, val, title = 'problem_id', pid, problem['title']
        else:
            try:
                cid = int(ranking_competition_id)
            except ValueError:
                return _json_or_homework_redirect('打榜赛ID非法', 400, class_en=class_en)
            comp = get_competition(cid)
            if not comp:
                return _json_or_homework_redirect('打榜赛不存在', 404, class_en=class_en)
            col, val, title = 'ranking_competition_id', cid, comp['title']

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"INSERT INTO {safe_table_name(class_en)} ({col}, ddl, complete_cnt, problem_title) VALUES (%s, %s, 0, %s)"
                cursor.execute(sql, (val, ddl, title))
                homework_id = cursor.lastrowid
            conn.commit()
            _invalidate_problem_list_cache_for_class(class_en)
            if _wants_json_response():
                return jsonify(success=True, message='作业添加成功', class_en=class_en, homework_id=homework_id)
            flash('作业添加成功', 'success')
        finally:
            conn.close()
    except pymysql.Error as e:
        if _wants_json_response():
            return jsonify(success=False, message='数据库操作失败，请稍后再试'), 500
        flash(f'数据库操作失败，请稍后再试', 'danger')

    return redirect(url_for('homework.admin_homework', sclass=class_en))


@homework_bp.route('/admin/delete_homework', methods=['POST'])
def admin_delete_homework():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    data = request.get_json()
    class_en = data.get('class_en')
    homework_id = data.get('homework_id')

    if not all([class_en, homework_id]):
        return jsonify(success=False, message="参数不完整"), 400

    if not get_class_by_en(class_en):
        return jsonify(success=False, message="班级不存在"), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = f"DELETE FROM {safe_table_name(class_en)} WHERE id=%s"
            cursor.execute(sql, (homework_id,))
        conn.commit()
        _invalidate_problem_list_cache_for_class(class_en)
        flash("删除成功", "success")
        return jsonify(success=True, message="删除成功")
    except pymysql.Error as e:
        return jsonify(success=False, message=f"数据库操作失败，请稍后再试"), 500
    finally:
        conn.close()


@homework_bp.route('/export_scores')
def export_scores():
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    selected_class = request.args.get('sclass')
    if not selected_class:
        return "班级参数错误", 400

    class_info = get_class_by_en(selected_class)
    if not class_info:
        return "班级不存在", 404

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT hw.id,
                       hw.problem_id,
                       hw.ranking_competition_id,
                       hw.problem_title,
                       rc.title AS ranking_title
                FROM {safe_table_name(selected_class)} hw
                LEFT JOIN ranking_competitions rc ON rc.id = hw.ranking_competition_id
                ORDER BY hw.id ASC
                """
            )
            homework_rows = cursor.fetchall()
    finally:
        conn.close()

    if not homework_rows:
        return "该班级没有布置任何作业", 404

    score_columns = []
    for hw in homework_rows:
        problem_id = hw.get('problem_id')
        ranking_competition_id = hw.get('ranking_competition_id')
        if problem_id is not None:
            score_columns.append({
                'kind': 'problem',
                'id': int(problem_id),
                'title': None,
            })
        elif ranking_competition_id is not None:
            title = hw.get('problem_title') or hw.get('ranking_title') or f"打榜赛 {ranking_competition_id}"
            score_columns.append({
                'kind': 'ranking',
                'id': int(ranking_competition_id),
                'title': title,
            })

    if not score_columns:
        return "该班级没有可导出的作业", 404

    problem_ids = [c['id'] for c in score_columns if c['kind'] == 'problem']
    ranking_competition_ids = [c['id'] for c in score_columns if c['kind'] == 'ranking']

    problem_titles = {}
    if problem_ids:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                fmt = ','.join(['%s'] * len(problem_ids))
                cursor.execute(f"SELECT id, title FROM problems WHERE id IN ({fmt})", problem_ids)
                for p in cursor.fetchall():
                    title = p['title'].encode('gbk', errors='replace').decode('gbk')
                    problem_titles[int(p['id'])] = title
        finally:
            conn.close()

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT u.id, u.username
                FROM user_class_map m
                JOIN users u ON u.id = m.user_id
                WHERE m.class_en = %s
                ORDER BY u.id ASC
                """,
                (selected_class,),
            )
            students = cursor.fetchall()

            if not students:
                cursor.execute("SELECT id, username FROM users WHERE class = %s ORDER BY id ASC", (selected_class,))
                students = cursor.fetchall()
    finally:
        conn.close()

    if not students:
        return "该班级没有学生", 404

    user_ids = [s['id'] for s in students]
    max_score_map = {}
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            uid_placeholders = ','.join(['%s'] * len(user_ids))
            pid_placeholders = ','.join(['%s'] * len(problem_ids))
            cursor.execute(
                f"""
                SELECT userid, problem_id, score
                FROM max_score
                WHERE userid IN ({uid_placeholders}) AND problem_id IN ({pid_placeholders})
                """,
                tuple(user_ids + problem_ids),
            )
            for row in cursor.fetchall():
                uid = row['userid']
                if uid not in max_score_map:
                    max_score_map[uid] = {}
                max_score_map[uid][row['problem_id']] = row['score']
    finally:
        conn.close()

    from io import BytesIO
    import codecs
    import csv

    ranking_score_map = {}
    if ranking_competition_ids:
        usernames = [s['username'] for s in students]
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                username_placeholders = ','.join(['%s'] * len(usernames))
                cid_placeholders = ','.join(['%s'] * len(ranking_competition_ids))
                cursor.execute(
                    f"""
                    SELECT username, competition_id, MAX(score) AS score
                    FROM ranking_submissions
                    WHERE username IN ({username_placeholders})
                      AND competition_id IN ({cid_placeholders})
                      AND score IS NOT NULL
                    GROUP BY username, competition_id
                    """,
                    tuple(usernames + ranking_competition_ids),
                )
                for row in cursor.fetchall():
                    ranking_score_map.setdefault(row['username'], {})[int(row['competition_id'])] = row['score']
        finally:
            conn.close()

    output = BytesIO()
    writer = csv.writer(codecs.getwriter('gbk')(output))

    column_titles = []
    for col in score_columns:
        if col['kind'] == 'problem':
            column_titles.append(problem_titles.get(col['id']) or f"题目 {col['id']}")
        else:
            column_titles.append(col['title'])

    headers = ['用户名'] + column_titles + ['总分']
    writer.writerow([h.encode('gbk', 'replace').decode('gbk') for h in headers])

    for stu in students:
        uid = stu['id']
        row = [stu['username']]
        total = 0

        ms = max_score_map.get(uid, {})
        ranking_scores = ranking_score_map.get(stu['username'], {})
        for col in score_columns:
            if col['kind'] == 'problem':
                score = ms.get(col['id'], 0) if ms else 0
            else:
                score = ranking_scores.get(col['id'], 0) if ranking_scores else 0
            score = score or 0
            total += score
            row.append(str(score))
        row.append(str(total))
        writer.writerow([cell.encode('gbk', 'replace').decode('gbk') for cell in row])

    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=GBK'
    resp.headers['Content-Disposition'] = f'attachment; filename="{selected_class}_scores.csv"'
    return resp


def parse_plagiarism_mark_payload(data):
    data = data or {}
    class_en = str(data.get('class_en') or '').strip()
    mode = str(data.get('mode') or 'threshold').strip()
    if mode not in ('threshold', 'byte'):
        raise ValueError('查重规则非法')

    class_info = get_class_by_en(class_en)
    if not class_info:
        raise ValueError('班级不存在')

    threshold = _parse_threshold(data.get('threshold', 90)) if mode == 'threshold' else 1.0

    raw_targets = data.get('targets')
    selected_targets = []
    if raw_targets:
        if not isinstance(raw_targets, (list, tuple)):
            raise ValueError('作业项非法')
        selected_targets = [_normalize_plagiarism_target(item) for item in raw_targets]
    else:
        try:
            selected_problem_ids = [int(pid) for pid in (data.get('problem_ids') or [])]
        except (TypeError, ValueError):
            raise ValueError('题目 ID 非法')
        selected_targets = [
            {
                'kind': _PLAGIARISM_TARGET_PROBLEM,
                'id': pid,
                'key': _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, pid),
            }
            for pid in selected_problem_ids
        ]

    deduped_targets = []
    seen_keys = set()
    for target in selected_targets:
        key = target.get('key')
        if key and key not in seen_keys:
            seen_keys.add(key)
            deduped_targets.append(target)
    selected_targets = deduped_targets

    homework_target_map = _get_class_homework_target_map(class_en)
    valid_target_keys = set(homework_target_map.keys())
    if not selected_targets:
        raise ValueError('请至少选择一道作业题')
    if any(target.get('key') not in valid_target_keys for target in selected_targets):
        raise ValueError('只能选择该班级已布置的作业')
    if mode == 'threshold' and any(target.get('kind') == _PLAGIARISM_TARGET_RANKING for target in selected_targets):
        raise ValueError('相似度查重暂不支持打榜赛，请改用字节级一致或取消打榜赛')

    resolved_targets = [dict(homework_target_map[target['key']]) for target in selected_targets]
    selected_problem_ids = [
        int(target['id'])
        for target in resolved_targets
        if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM
    ]

    return {
        'class_en': class_en,
        'class_cn': class_info.get('class_cn'),
        'mode': mode,
        'threshold': threshold,
        'targets': resolved_targets,
        'problem_ids': selected_problem_ids,
    }


def start_plagiarism_mark_task(class_en, mode, threshold, targets):
    if _plagiarism_task is None:
        raise RuntimeError('查重模块未初始化')
    task = _plagiarism_task.delay(class_en, mode, float(threshold), list(targets or []))
    return task.id


def get_plagiarism_progress_payload(task_id):
    if not _rds:
        return None
    progress_data = _rds.get(f'plagiarism_progress:{task_id}')
    if not progress_data:
        return None
    if isinstance(progress_data, bytes):
        progress_data = progress_data.decode('utf-8')
    return json.loads(progress_data)


@homework_bp.route('/admin/plagiarism/mark', methods=['POST'])
def admin_mark_plagiarism():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    data = request.get_json(silent=True) or {}
    try:
        payload = parse_plagiarism_mark_payload(data)
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400

    try:
        task_id = start_plagiarism_mark_task(
            payload['class_en'],
            payload['mode'],
            payload['threshold'],
            payload['targets'],
        )
    except RuntimeError as exc:
        return jsonify(success=False, message=str(exc)), 500
    except Exception as exc:
        return jsonify(success=False, message=f'启动失败: {exc}'), 500

    return jsonify(
        success=True,
        message='查重任务已启动',
        task_id=task_id,
    )


@homework_bp.route('/admin/plagiarism/progress/<task_id>')
def admin_plagiarism_progress(task_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    progress = get_plagiarism_progress_payload(task_id)
    if not progress:
        return jsonify(success=False, message='任务不存在或已过期'), 404
    return jsonify(success=True, progress=progress)


@homework_bp.route('/admin/plagiarism/records')
def admin_plagiarism_records():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    class_en = request.args.get('sclass', '').strip()
    if not get_class_by_en(class_en):
        return jsonify(success=False, message='班级不存在'), 400

    try:
        records = _load_plagiarism_records_for_class(class_en)
    except pymysql.Error:
        return jsonify(success=False, message='数据库操作失败，请稍后再试'), 500
    return jsonify(success=True, records=records, count=len(records))


@homework_bp.route('/admin/plagiarism/records/download')
def admin_download_plagiarism_records():
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    class_en = request.args.get('sclass', '').strip()
    if not get_class_by_en(class_en):
        return '班级不存在', 400

    return build_plagiarism_records_csv_response(class_en)


def build_plagiarism_records_csv_response(class_en):
    records = _load_plagiarism_records_for_class(class_en)

    from io import BytesIO
    import codecs
    import csv

    output = BytesIO()
    writer = csv.writer(codecs.getwriter('gbk')(output))
    headers = [
        '抄袭记录ID',
        '用户ID',
        '用户名',
        '班级',
        '题目ID',
        '题目名称',
        '提交ID',
        '比较规则',
        '相同用户名',
        '标记时间',
    ]
    writer.writerow([h.encode('gbk', 'replace').decode('gbk') for h in headers])
    for record in records:
        row = [
            record.get('id'),
            record.get('user_id'),
            record.get('username'),
            record.get('class_cn') or record.get('class_en'),
            record.get('problem_id'),
            record.get('problem_title') or '',
            record.get('submission_id'),
            record.get('comparison_rule'),
            record.get('matched_usernames_text') or '',
            record.get('created_at') or '',
        ]
        writer.writerow([str(cell if cell is not None else '').encode('gbk', 'replace').decode('gbk') for cell in row])

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv; charset=GBK'
    response.headers['Content-Disposition'] = f'attachment; filename="{class_en}_plagiarism_records.csv"'
    return response


def delete_plagiarism_records_for_class(class_en, record_ids):
    placeholders = ','.join(['%s'] * len(record_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"DELETE FROM plagiarism_records WHERE class_en=%s AND id IN ({placeholders})",
                tuple([class_en] + record_ids),
            )
            deleted = cursor.rowcount
        conn.commit()
    finally:
        conn.close()
    _invalidate_problem_list_cache_for_class(class_en)
    return deleted


@homework_bp.route('/admin/plagiarism/records/delete', methods=['POST'])
def admin_delete_plagiarism_records():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限'), 403

    data = request.get_json(silent=True) or {}
    class_en = str(data.get('class_en') or '').strip()
    if not get_class_by_en(class_en):
        return jsonify(success=False, message='班级不存在'), 400

    try:
        record_ids = [int(rid) for rid in (data.get('record_ids') or [])]
    except (TypeError, ValueError):
        return jsonify(success=False, message='记录 ID 非法'), 400
    record_ids = list(dict.fromkeys(record_ids))
    if not record_ids:
        return jsonify(success=False, message='请选择要删除的记录'), 400

    try:
        deleted = delete_plagiarism_records_for_class(class_en, record_ids)
    except pymysql.Error:
        return jsonify(success=False, message='数据库操作失败，请稍后再试'), 500
    return jsonify(success=True, message=f'已删除 {deleted} 条记录', deleted=deleted)


def update_export_progress(task_id, stage, current, total, message, sub_progress=None):
    progress_data = {
        'stage': stage,
        'current': current,
        'total': total,
        'message': message,
        'percentage': int((current / total * 100)) if total > 0 else 0,
        'sub_progress': sub_progress or {},
    }
    _rds.setex(f'export_progress:{task_id}', 600, json.dumps(progress_data))


def update_plagiarism_progress(task_id, stage, current, total, message, result=None):
    progress_data = {
        'stage': stage,
        'current': current,
        'total': total,
        'message': message,
        'percentage': int((current / total * 100)) if total > 0 else 0,
    }
    if result is not None:
        progress_data['result'] = result
    _rds.setex(f'plagiarism_progress:{task_id}', 1800, json.dumps(progress_data, ensure_ascii=False))


def normalize_code(code):
    import re

    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'%.*?$', '', code, flags=re.MULTILINE)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
    code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)
    code = re.sub(r'\s+', ' ', code)
    return code.strip()


def calculate_code_similarity(code1, code2):
    norm_code1 = normalize_code(code1)
    norm_code2 = normalize_code(code2)

    if not norm_code1 or not norm_code2:
        return 0.0

    return SequenceMatcher(None, norm_code1, norm_code2).ratio()


def _format_threshold_rule(threshold):
    return f"{float(threshold):.2f}"


def _parse_threshold(raw_value):
    try:
        threshold = float(raw_value)
    except (TypeError, ValueError):
        raise ValueError("查重阈值必须是数字")
    if threshold > 1:
        threshold = threshold / 100.0
    if threshold <= 0 or threshold > 1:
        raise ValueError("查重阈值必须在 0 到 100 之间")
    return threshold


def _plagiarism_target_key(kind, target_id):
    return f"{str(kind or '').strip()}:{int(target_id)}"


def _normalize_plagiarism_target(raw_value):
    if isinstance(raw_value, dict):
        kind = str(raw_value.get('kind') or raw_value.get('type') or '').strip().lower()
        target_id = raw_value.get('id') or raw_value.get('target_id') or raw_value.get('problem_id') or raw_value.get('competition_id')
    else:
        text = str(raw_value or '').strip()
        if not text:
            raise ValueError('作业项非法')
        if ':' in text:
            kind, target_id = text.split(':', 1)
            kind = kind.strip().lower()
        else:
            kind, target_id = _PLAGIARISM_TARGET_PROBLEM, text

    if kind in ('problem', 'ordinary'):
        kind = _PLAGIARISM_TARGET_PROBLEM
    elif kind in ('ranking', 'competition'):
        kind = _PLAGIARISM_TARGET_RANKING
    else:
        raise ValueError('作业项类型非法')

    try:
        target_id = int(target_id)
    except (TypeError, ValueError):
        raise ValueError('作业项 ID 非法')
    if target_id <= 0:
        raise ValueError('作业项 ID 非法')

    return {
        'kind': kind,
        'id': target_id,
        'key': _plagiarism_target_key(kind, target_id),
    }


def _get_class_homework_target_map(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT hw.problem_id,
                       hw.ranking_competition_id,
                       COALESCE(p.title, hw.problem_title) AS problem_title,
                       COALESCE(rc.title, hw.problem_title) AS ranking_title
                FROM {safe_table_name(class_en)} hw
                LEFT JOIN problems p ON p.id = hw.problem_id
                LEFT JOIN ranking_competitions rc ON rc.id = hw.ranking_competition_id
                WHERE hw.problem_id IS NOT NULL
                   OR hw.ranking_competition_id IS NOT NULL
                ORDER BY hw.id ASC
                """
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    target_map = {}
    for row in rows:
        if row.get('problem_id') is not None:
            try:
                pid = int(row.get('problem_id'))
            except (TypeError, ValueError):
                pid = None
            if pid:
                key = _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, pid)
                target_map.setdefault(key, {
                    'kind': _PLAGIARISM_TARGET_PROBLEM,
                    'id': pid,
                    'key': key,
                    'title': row.get('problem_title') or f'题目 {pid}',
                })
        if row.get('ranking_competition_id') is not None:
            try:
                cid = int(row.get('ranking_competition_id'))
            except (TypeError, ValueError):
                cid = None
            if cid:
                key = _plagiarism_target_key(_PLAGIARISM_TARGET_RANKING, cid)
                target_map.setdefault(key, {
                    'kind': _PLAGIARISM_TARGET_RANKING,
                    'id': cid,
                    'key': key,
                    'title': row.get('ranking_title') or f'打榜赛 {cid}',
                })
    return target_map


def _get_class_homework_problem_map(class_en):
    target_map = _get_class_homework_target_map(class_en)
    problem_map = {}
    for target in target_map.values():
        if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM:
            problem_map[int(target['id'])] = target.get('title') or f"题目 {target['id']}"
    return problem_map


def _json_lines_to_list(value):
    if not value:
        return []
    items = []
    for line in str(value or '').strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except Exception:
            items.append(line)
    return items


def _submission_upload_file_path(submission_id, test_points):
    points = _json_lines_to_list(test_points)
    if not points:
        return ''
    first = points[0]
    filename = ''
    if isinstance(first, str):
        filename = first
    elif isinstance(first, dict):
        filename = first.get('filename') or first.get('file') or first.get('name') or ''
    filename = os.path.basename(str(filename or '').strip())
    if not filename:
        return ''
    return os.path.join('uploads', str(submission_id), filename)


def _file_sha256_fingerprint(path, label='file'):
    if not path or not os.path.isfile(path):
        return ''
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            if chunk:
                digest.update(chunk)
    return f"{label}:{digest.hexdigest()}"


def _zip_content_sha256_fingerprint(path, label='zip-content'):
    if not path or not os.path.isfile(path):
        return ''
    digest = hashlib.sha256()
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            infos = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = _safe_zip_member_name(info.filename)
                if name:
                    infos.append((name, info))
            for name, info in sorted(infos, key=lambda item: item[0]):
                try:
                    content = zf.read(info)
                except Exception:
                    return ''
                digest.update(name.encode('utf-8', errors='replace'))
                digest.update(b'\0')
                digest.update(content)
                digest.update(b'\0')
    except (OSError, zipfile.BadZipFile):
        return ''
    return f"{label}:{digest.hexdigest()}"


def _safe_zip_member_name(name):
    raw = str(name or '').replace('\\', '/')
    normalized = posixpath.normpath(raw)
    if not normalized or normalized == '.':
        return ''
    if normalized.startswith('../') or normalized.startswith('/') or '/../' in f"/{normalized}/":
        return ''
    return normalized


def _read_tex_files_from_zip(zip_path):
    if not zip_path or not os.path.isfile(zip_path):
        return {}
    tex_files = {}
    total_bytes = 0
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for info in sorted(zf.infolist(), key=lambda item: str(item.filename or '')):
                if info.is_dir():
                    continue
                name = _safe_zip_member_name(info.filename)
                if not name or not name.lower().endswith('.tex'):
                    continue
                if len(tex_files) >= _PLAGIARISM_TEX_MAX_FILES:
                    break
                total_bytes += int(info.file_size or 0)
                if total_bytes > _PLAGIARISM_TEX_MAX_TOTAL_BYTES:
                    break
                try:
                    content = zf.read(info)
                except Exception:
                    continue
                tex_files[name] = content.decode('utf-8', errors='replace')
    except (OSError, zipfile.BadZipFile):
        return {}
    return tex_files


def _calculate_tex_files_similarity(files1, files2):
    left = files1 or {}
    right = files2 or {}
    common_names = sorted(set(left.keys()) & set(right.keys()))
    if not common_names:
        return 0.0
    best = 0.0
    for name in common_names:
        score = calculate_code_similarity(left.get(name) or '', right.get(name) or '')
        if score > best:
            best = score
    return best


def _class_users_cte_sql():
    return """
        SELECT u.id AS user_id, u.username
        FROM user_class_map m
        JOIN users u ON u.id = m.user_id
        WHERE m.class_en = %s
        UNION
        SELECT u2.id AS user_id, u2.username
        FROM users u2
        WHERE u2.class = %s
    """


def _problem_plagiarism_target_title(row):
    return row.get('problem_title') or f"题目 {row.get('problem_id')}"


def _build_problem_plagiarism_item(row, include_includes=False):
    problem_id = int(row.get('problem_id') or 0)
    problem_type = int(row.get('problem_type') or 1)
    programming_mode = int(row.get('programming_grading_mode') or 1)
    written_mode = int(row.get('written_grading_mode') or 1)
    raw_code = row.get('code') or ''
    compare_code = raw_code
    compare_kind = 'code'
    compare_files = None
    byte_fingerprints = []
    material_label = '代码'

    if problem_type == 1 and programming_mode == 3:
        raw_code = row.get('prompt_text') or ''
        compare_code = raw_code
        compare_kind = 'prompt'
        material_label = 'Prompt'
    elif problem_type == 2:
        file_path = _submission_upload_file_path(row.get('submission_id'), row.get('test_points'))
        byte_fp = _file_sha256_fingerprint(file_path, label='submission-file')
        if byte_fp:
            byte_fingerprints.append(byte_fp)
        raw_code = ''
        compare_code = ''
        compare_kind = 'none'
        material_label = '提交文件'
        if written_mode == 3:
            compare_files = _read_tex_files_from_zip(file_path)
            compare_kind = 'tex_files' if compare_files else 'none'
            material_label = 'TeX'
    else:
        if include_includes:
            included_files = extract_includes_from_code(raw_code)
            if included_files and row.get('user_id'):
                repository_files = get_user_repository_files_by_names(row.get('user_id'), included_files)
                if repository_files:
                    compare_code += "\n\n// ===== 以下是引用的代码仓库文件 =====\n"
                    for filename, content in repository_files.items():
                        compare_code += f"\n// ===== {filename} =====\n{content or ''}\n"

    return {
        'target_kind': _PLAGIARISM_TARGET_PROBLEM,
        'target_key': _plagiarism_target_key(_PLAGIARISM_TARGET_PROBLEM, problem_id),
        'user_id': row.get('user_id'),
        'username': row.get('username'),
        'submission_id': row.get('submission_id'),
        'problem_id': problem_id,
        'problem_title': _problem_plagiarism_target_title(row),
        'raw_code': raw_code,
        'compare_code': compare_code,
        'compare_kind': compare_kind,
        'compare_files': compare_files,
        'byte_fingerprints': byte_fingerprints,
        'material_label': material_label,
    }


def _collect_best_first_submissions_for_plagiarism(class_en, problem_targets, include_includes=False):
    problem_ids = [int(target['id']) for target in (problem_targets or [])]
    if not problem_ids:
        return []

    placeholders = ','.join(['%s'] * len(problem_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                WITH class_users AS (
                    {_class_users_cte_sql()}
                ),
                ranked_submissions AS (
                    SELECT cu.user_id,
                           cu.username,
                           s.id AS submission_id,
                           s.problem_id,
                           s.code,
                           s.prompt_text,
                           s.test_points,
                           s.score,
                           s.created_at,
                           p.title AS problem_title,
                           p.type AS problem_type,
                           p.programming_grading_mode,
                           p.written_grading_mode,
                           ROW_NUMBER() OVER (
                               PARTITION BY cu.user_id, s.problem_id
                               ORDER BY s.score DESC, s.created_at ASC, s.id ASC
                           ) AS rn
                    FROM class_users cu
                    JOIN submissions s ON s.username = cu.username
                    LEFT JOIN problems p ON p.id = s.problem_id
                    WHERE s.problem_id IN ({placeholders})
                )
                SELECT user_id, username, submission_id, problem_id, code, prompt_text, test_points,
                       score, created_at, problem_title, problem_type, programming_grading_mode, written_grading_mode
                FROM ranked_submissions
                WHERE rn = 1
                ORDER BY problem_id ASC, username ASC
                """,
                tuple([class_en, class_en] + list(problem_ids)),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    return [_build_problem_plagiarism_item(row, include_includes=include_includes) for row in rows]


def _ranking_byte_fingerprints_for_submission(row):
    scoring_mode = str(row.get('scoring_mode') or 'absolute').strip().lower()
    fingerprints = []
    if scoring_mode == 'agent_judge':
        code_fp = _zip_content_sha256_fingerprint(row.get('code_path'), label='agent-files')
        if not code_fp:
            code_fp = _file_sha256_fingerprint(row.get('code_path'), label='agent-code-zip')
        if code_fp:
            fingerprints.append(code_fp)
    elif scoring_mode == 'elo':
        answer_fp = _file_sha256_fingerprint(row.get('answer_path'), label='answer-zip')
        code_fp = _file_sha256_fingerprint(row.get('code_path'), label='code-zip')
        if answer_fp:
            fingerprints.append(answer_fp)
        if code_fp:
            fingerprints.append(code_fp)
    else:
        code_fp = _file_sha256_fingerprint(row.get('code_path'), label='code-zip')
        if code_fp:
            fingerprints.append(code_fp)
    return fingerprints


def _collect_best_first_ranking_submissions_for_plagiarism(class_en, ranking_targets):
    competition_ids = [int(target['id']) for target in (ranking_targets or [])]
    if not competition_ids:
        return []

    placeholders = ','.join(['%s'] * len(competition_ids))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                WITH class_users AS (
                    {_class_users_cte_sql()}
                ),
                ranked_submissions AS (
                    SELECT cu.user_id,
                           cu.username,
                           rs.id AS submission_id,
                           rs.competition_id,
                           rs.answer_path,
                           rs.code_path,
                           rs.score,
                           rs.created_at,
                           rc.title AS competition_title,
                           rc.scoring_mode,
                           ROW_NUMBER() OVER (
                               PARTITION BY cu.user_id, rs.competition_id
                               ORDER BY (rs.score IS NULL) ASC, rs.score DESC, rs.created_at ASC, rs.id ASC
                           ) AS rn
                    FROM class_users cu
                    JOIN ranking_submissions rs ON rs.username = cu.username
                    LEFT JOIN ranking_competitions rc ON rc.id = rs.competition_id
                    WHERE rs.competition_id IN ({placeholders})
                )
                SELECT user_id, username, submission_id, competition_id, answer_path, code_path,
                       score, created_at, competition_title, scoring_mode
                FROM ranked_submissions
                WHERE rn = 1
                ORDER BY competition_id ASC, username ASC
                """,
                tuple([class_en, class_en] + list(competition_ids)),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    submissions = []
    for row in rows:
        competition_id = int(row.get('competition_id') or 0)
        scoring_mode = str(row.get('scoring_mode') or 'absolute').strip().lower()
        title = row.get('competition_title') or f"打榜赛 {competition_id}"
        submissions.append({
            'target_kind': _PLAGIARISM_TARGET_RANKING,
            'target_key': _plagiarism_target_key(_PLAGIARISM_TARGET_RANKING, competition_id),
            'user_id': row.get('user_id'),
            'username': row.get('username'),
            'submission_id': row.get('submission_id'),
            # 负数写入 plagiarism_records.problem_id，避免与普通题记录唯一键冲突。
            'problem_id': -competition_id,
            'competition_id': competition_id,
            'problem_title': f"打榜赛：{title}",
            'raw_code': '',
            'compare_code': '',
            'compare_kind': 'ranking_zip',
            'byte_fingerprints': _ranking_byte_fingerprints_for_submission(row),
            'material_label': '打榜赛提交',
            'scoring_mode': scoring_mode,
        })
    return submissions


def _byte_fingerprints_for_plagiarism_item(item):
    if '_byte_fingerprints_cache' in item:
        return item.get('_byte_fingerprints_cache') or []

    fingerprints = []
    for value in item.get('byte_fingerprints') or []:
        text = str(value or '').strip()
        if text:
            fingerprints.append(text)
    if fingerprints:
        item['_byte_fingerprints_cache'] = sorted(set(fingerprints))
        return item['_byte_fingerprints_cache']

    raw_code = item.get('raw_code') or ''
    if not raw_code:
        item['_byte_fingerprints_cache'] = []
        return []
    payload = raw_code.encode('utf-8')
    item['_byte_fingerprints_cache'] = [f"submission:{hashlib.sha256(payload).hexdigest()}"]
    return item['_byte_fingerprints_cache']


def _plagiarism_similarity(item1, item2):
    kind1 = str(item1.get('compare_kind') or 'code')
    kind2 = str(item2.get('compare_kind') or 'code')
    if kind1 == 'tex_files' and kind2 == 'tex_files':
        return _calculate_tex_files_similarity(item1.get('compare_files'), item2.get('compare_files'))
    if kind1 == 'none' or kind2 == 'none':
        return 0.0
    return calculate_code_similarity(item1.get('compare_code') or '', item2.get('compare_code') or '')


def _build_plagiarism_components(codes_data, mode='threshold', threshold=0.9, progress_callback=None):
    problem_groups = defaultdict(list)
    for item in codes_data:
        group_key = item.get('target_key') or _plagiarism_target_key(
            item.get('target_kind') or _PLAGIARISM_TARGET_PROBLEM,
            abs(int(item.get('problem_id') or 0)),
        )
        problem_groups[group_key].append(item)

    if mode == 'byte':
        total_items = sum(len(group) for group in problem_groups.values())
        completed_items = 0
        progress_step = max(1, total_items // 100) if total_items else 1
        components = []

        if progress_callback and total_items == 0:
            progress_callback(1, 1, '没有需要计算哈希的提交代码')

        for _, group in problem_groups.items():
            by_hash = defaultdict(list)
            parent = list(range(len(group)))

            def find(x):
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            def union(a, b):
                ra = find(a)
                rb = find(b)
                if ra != rb:
                    parent[rb] = ra

            for idx, item in enumerate(group):
                for fingerprint in _byte_fingerprints_for_plagiarism_item(item):
                    by_hash[fingerprint].append(idx)
                completed_items += 1
                if progress_callback and (
                    completed_items == total_items
                    or completed_items % progress_step == 0
                ):
                    problem_title = item.get('problem_title') or f"题目 {item.get('problem_id')}"
                    progress_callback(
                        completed_items,
                        total_items,
                        f"正在计算字节哈希 {problem_title}: {item.get('username')}",
                    )
            for indexes in by_hash.values():
                if len(indexes) >= 2:
                    first = indexes[0]
                    for other in indexes[1:]:
                        union(first, other)

            by_root = defaultdict(list)
            for idx, item in enumerate(group):
                if _byte_fingerprints_for_plagiarism_item(item):
                    by_root[find(idx)].append(item)
            for members in by_root.values():
                if len(members) >= 2:
                    components.append(members)

        return components

    total_comparisons = sum(len(group) * (len(group) - 1) // 2 for group in problem_groups.values() if len(group) >= 2)
    completed_comparisons = 0
    progress_step = max(1, total_comparisons // 100) if total_comparisons else 1
    if progress_callback and total_comparisons == 0:
        progress_callback(1, 1, '没有需要比较的提交代码')

    components = []
    for _, group in problem_groups.items():
        if len(group) < 2:
            continue

        parent = list(range(len(group)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra = find(a)
            rb = find(b)
            if ra != rb:
                parent[rb] = ra

        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if mode == 'byte':
                    code1 = group[i].get('raw_code') or ''
                    code2 = group[j].get('raw_code') or ''
                    matched = bool(code1) and code1 == code2
                else:
                    matched = _plagiarism_similarity(group[i], group[j]) >= threshold
                if matched:
                    union(i, j)
                completed_comparisons += 1
                if progress_callback and (
                    completed_comparisons == total_comparisons
                    or completed_comparisons % progress_step == 0
                ):
                    problem_title = group[i].get('problem_title') or f"题目 {group[i].get('problem_id')}"
                    progress_callback(
                        completed_comparisons,
                        total_comparisons,
                        f"正在比较 {problem_title}: {group[i].get('username')} vs {group[j].get('username')}",
                    )

        by_root = defaultdict(list)
        for idx, item in enumerate(group):
            by_root[find(idx)].append(item)
        for members in by_root.values():
            if len(members) >= 2:
                components.append(members)

    return components


def _build_plagiarism_record_rows(components, class_en, class_cn, comparison_rule):
    rows = []
    for members in components:
        ordered_members = sorted(members, key=lambda item: str(item.get('username') or ''))
        usernames = [item.get('username') for item in ordered_members if item.get('username')]
        for item in ordered_members:
            username = item.get('username')
            matched_usernames = [name for name in usernames if name != username]
            if not username or not matched_usernames:
                continue
            rows.append({
                'user_id': int(item.get('user_id') or 0),
                'username': username,
                'class_en': class_en,
                'class_cn': class_cn,
                'problem_id': int(item.get('problem_id') or 0),
                'problem_title': item.get('problem_title') or f"题目 {item.get('problem_id')}",
                'submission_id': int(item.get('submission_id') or 0),
                'comparison_rule': comparison_rule,
                'matched_usernames': matched_usernames,
                'target_kind': item.get('target_kind') or _PLAGIARISM_TARGET_PROBLEM,
            })
    return rows


def _save_plagiarism_records(records):
    if not records:
        return 0

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO plagiarism_records
                    (user_id, username, class_en, class_cn, problem_id, problem_title,
                     submission_id, comparison_rule, matched_usernames)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    user_id=VALUES(user_id),
                    class_cn=VALUES(class_cn),
                    problem_title=VALUES(problem_title),
                    matched_usernames=VALUES(matched_usernames),
                    created_at=CURRENT_TIMESTAMP
                """,
                [
                    (
                        record['user_id'],
                        record['username'],
                        record['class_en'],
                        record['class_cn'],
                        record['problem_id'],
                        record['problem_title'],
                        record['submission_id'],
                        record['comparison_rule'],
                        json.dumps(record['matched_usernames'], ensure_ascii=False),
                    )
                    for record in records
                ],
            )
        conn.commit()
    finally:
        conn.close()
    return len(records)


def _decode_matched_usernames(raw_value):
    if not raw_value:
        return []
    if isinstance(raw_value, list):
        return raw_value
    try:
        value = json.loads(raw_value)
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
    except Exception:
        pass
    return [part.strip() for part in str(raw_value).split(',') if part.strip()]


def _serialize_plagiarism_record(row):
    matched_usernames = _decode_matched_usernames(row.get('matched_usernames'))
    created_at = row.get('created_at')
    raw_problem_id = int(row.get('problem_id') or 0)
    title = row.get('problem_title') or ''
    target_kind = _PLAGIARISM_TARGET_RANKING if raw_problem_id < 0 or str(title).startswith('打榜赛：') else _PLAGIARISM_TARGET_PROBLEM
    display_problem_id = abs(raw_problem_id) if target_kind == _PLAGIARISM_TARGET_RANKING else raw_problem_id
    return {
        'id': row.get('id'),
        'user_id': row.get('user_id'),
        'username': row.get('username'),
        'class_en': row.get('class_en'),
        'class_cn': row.get('class_cn'),
        'problem_id': display_problem_id,
        'problem_title': title,
        'submission_id': row.get('submission_id'),
        'comparison_rule': row.get('comparison_rule'),
        'matched_usernames': matched_usernames,
        'matched_usernames_text': '、'.join(matched_usernames),
        'target_kind': target_kind,
        'competition_id': display_problem_id if target_kind == _PLAGIARISM_TARGET_RANKING else None,
        'created_at': created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else '',
    }


def _load_plagiarism_records_for_class(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, username, class_en, class_cn, problem_id, problem_title,
                       submission_id, comparison_rule, matched_usernames, created_at
                FROM plagiarism_records
                WHERE class_en=%s
                ORDER BY created_at DESC, id DESC
                """,
                (class_en,),
            )
            return [_serialize_plagiarism_record(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def mark_class_plagiarism(class_en, class_cn, targets, mode, threshold, progress_callback=None, status_callback=None):
    if status_callback:
        status_callback('collecting', 0, 100, '正在收集提交材料...')
    include_includes = False
    normalized_targets = []
    for target in (targets or []):
        if isinstance(target, dict):
            normalized_targets.append(target)
        else:
            normalized_targets.append(_normalize_plagiarism_target(target))

    problem_targets = [target for target in normalized_targets if target.get('kind') == _PLAGIARISM_TARGET_PROBLEM]
    ranking_targets = [target for target in normalized_targets if target.get('kind') == _PLAGIARISM_TARGET_RANKING]
    if mode == 'threshold' and ranking_targets:
        raise ValueError('相似度查重暂不支持打榜赛')

    codes_data = _collect_best_first_submissions_for_plagiarism(
        class_en,
        problem_targets,
        include_includes=include_includes,
    )
    if mode == 'byte' and ranking_targets:
        codes_data.extend(_collect_best_first_ranking_submissions_for_plagiarism(class_en, ranking_targets))
    if status_callback:
        action = '开始计算字节哈希...' if mode == 'byte' else '开始比较...'
        status_callback('checking', 0, 1, f'已收集 {len(codes_data)} 份提交，{action}')
    comparison_rule = 'byte-identical' if mode == 'byte' else _format_threshold_rule(threshold)
    components = _build_plagiarism_components(
        codes_data,
        mode=mode,
        threshold=threshold,
        progress_callback=progress_callback,
    )
    if status_callback:
        status_callback('saving', 0, 1, '正在写入抄袭记录...')
    records = _build_plagiarism_record_rows(components, class_en, class_cn, comparison_rule)
    inserted_count = _save_plagiarism_records(records)
    if status_callback:
        status_callback('saving', 1, 1, '抄袭记录写入完成')
    return {
        'submission_count': len(codes_data),
        'group_count': len(components),
        'record_count': inserted_count,
        'comparison_rule': comparison_rule,
    }


def detect_plagiarism(codes_data, threshold=0.9, task_id=None):
    results = []
    problem_groups = {}
    for item in codes_data:
        pid = item['problem_id']
        if pid not in problem_groups:
            problem_groups[pid] = []
        problem_groups[pid].append(item)

    total_comparisons = 0
    for group in problem_groups.values():
        if len(group) >= 2:
            total_comparisons += len(group) * (len(group) - 1) // 2

    if total_comparisons == 0:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '没有需要查重的代码')
        return results

    completed_comparisons = 0
    for pid, group in problem_groups.items():
        if len(group) < 2:
            continue

        problem_title = group[0]['problem_title']
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                user1 = group[i]['username']
                user2 = group[j]['username']
                code1 = group[i]['code']
                code2 = group[j]['code']

                if task_id:
                    message = f'正在比较: 题目 {problem_title} - {user1} vs {user2}'
                    sub_progress = {
                        'problem_check': {
                            'current': completed_comparisons,
                            'total': total_comparisons,
                            'percentage': int((completed_comparisons / total_comparisons * 100)) if total_comparisons > 0 else 0,
                            'message': message,
                        }
                    }
                    update_export_progress(
                        task_id,
                        'plagiarism_check',
                        completed_comparisons,
                        total_comparisons,
                        '题目代码查重中...',
                        sub_progress,
                    )

                similarity = calculate_code_similarity(code1, code2)
                if similarity >= threshold:
                    results.append({
                        'problem_id': pid,
                        'problem_title': problem_title,
                        'user1': user1,
                        'user2': user2,
                        'similarity': similarity,
                    })

                completed_comparisons += 1

    if task_id:
        sub_progress = {
            'problem_check': {
                'current': total_comparisons,
                'total': total_comparisons,
                'percentage': 100,
                'message': f'题目代码查重完成，发现 {len(results)} 组相似代码',
            }
        }
        update_export_progress(
            task_id,
            'plagiarism_check',
            total_comparisons,
            total_comparisons,
            f'题目代码查重完成，发现 {len(results)} 组相似代码',
            sub_progress,
        )

    return results


def get_student_repository_files(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT filename, file_content
            FROM user_code_repository
            WHERE user_id = %s
            ORDER BY filename
            """
            cursor.execute(sql, (user_id,))
            files = cursor.fetchall()
            return [{'filename': f['filename'], 'content': f['file_content'] or ''} for f in files]
    except Exception as e:
        print(f"获取代码仓库文件失败: {e}")
        return []
    finally:
        conn.close()


def detect_repository_plagiarism(students_data, threshold=0.9, task_id=None):
    results = []
    students_with_files = [s for s in students_data if s['files']]

    if len(students_with_files) < 2:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '代码仓库文件不足，跳过查重')
        return results

    total_comparisons = 0
    for i in range(len(students_with_files)):
        for j in range(i + 1, len(students_with_files)):
            files1 = students_with_files[i]['files']
            files2 = students_with_files[j]['files']
            total_comparisons += len(files1) * len(files2)

    if total_comparisons == 0:
        if task_id:
            update_export_progress(task_id, 'plagiarism_check', 1, 1, '没有需要比较的代码仓库文件')
        return results

    completed_comparisons = 0
    for i in range(len(students_with_files)):
        for j in range(i + 1, len(students_with_files)):
            student1 = students_with_files[i]
            student2 = students_with_files[j]
            user1 = student1['username']
            user2 = student2['username']

            for file1 in student1['files']:
                for file2 in student2['files']:
                    if task_id:
                        message = f'正在比较: {user1}/{file1["filename"]} vs {user2}/{file2["filename"]}'
                        sub_progress = {
                            'repo_check': {
                                'current': completed_comparisons,
                                'total': total_comparisons,
                                'percentage': int((completed_comparisons / total_comparisons * 100)) if total_comparisons > 0 else 0,
                                'message': message,
                            }
                        }
                        update_export_progress(
                            task_id,
                            'plagiarism_check',
                            completed_comparisons,
                            total_comparisons,
                            '代码仓库查重中...',
                            sub_progress,
                        )

                    similarity = calculate_code_similarity(file1['content'], file2['content'])
                    if similarity >= threshold:
                        results.append({
                            'user1': user1,
                            'user2': user2,
                            'file1': file1['filename'],
                            'file2': file2['filename'],
                            'similarity': similarity,
                            'type': 'repository',
                        })

                    completed_comparisons += 1

    if task_id:
        sub_progress = {
            'repo_check': {
                'current': total_comparisons,
                'total': total_comparisons,
                'percentage': 100,
                'message': f'代码仓库查重完成，发现 {len(results)} 组相似文件',
            }
        }
        update_export_progress(
            task_id,
            'plagiarism_check',
            total_comparisons,
            total_comparisons,
            f'代码仓库查重完成，发现 {len(results)} 组相似文件',
            sub_progress,
        )

    return results


def generate_plagiarism_report(plagiarism_results, repository_results=None):
    if not plagiarism_results and not repository_results:
        return "未发现相似度达到90%以上的代码。\n"

    report = "=" * 80 + "\n"
    report += "代码查重报告\n"
    report += "=" * 80 + "\n"
    report += f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += "查重阈值: 90%\n"
    report += f"题目代码: 发现 {len(plagiarism_results) if plagiarism_results else 0} 组疑似相似代码\n"
    report += f"代码仓库: 发现 {len(repository_results) if repository_results else 0} 组疑似相似文件\n"
    report += "=" * 80 + "\n\n"

    if plagiarism_results:
        report += "\n" + "=" * 80 + "\n"
        report += "一、题目代码查重结果\n"
        report += "=" * 80 + "\n\n"

        by_problem = {}
        for result in plagiarism_results:
            pid = result['problem_id']
            if pid not in by_problem:
                by_problem[pid] = []
            by_problem[pid].append(result)

        for pid, items in by_problem.items():
            report += f"\n题目 ID: {pid}\n"
            report += f"题目标题: {items[0]['problem_title']}\n"
            report += "-" * 80 + "\n"

            for idx, item in enumerate(items, 1):
                report += f"  [{idx}] 学生1: {item['user1']}  <-->  学生2: {item['user2']}\n"
                report += f"       相似度: {item['similarity'] * 100:.2f}%\n\n"

            report += "\n"

    if repository_results:
        report += "\n" + "=" * 80 + "\n"
        report += "二、代码仓库查重结果\n"
        report += "=" * 80 + "\n\n"

        by_student_pair = {}
        for result in repository_results:
            key = f"{result['user1']} <--> {result['user2']}"
            if key not in by_student_pair:
                by_student_pair[key] = []
            by_student_pair[key].append(result)

        for pair, items in by_student_pair.items():
            report += f"\n学生对: {pair}\n"
            report += "-" * 80 + "\n"

            for idx, item in enumerate(items, 1):
                report += f"  [{idx}] 文件1: {item['file1']}  <-->  文件2: {item['file2']}\n"
                report += f"       相似度: {item['similarity'] * 100:.2f}%\n\n"

            report += "\n"

    report += "=" * 80 + "\n"
    report += "说明:\n"
    report += "1. 本报告列出了相似度达到90%以上的代码对和文件对\n"
    report += "2. 相似度计算基于代码文本比对，已排除注释和空白的影响\n"
    report += "3. 题目代码查重：比较同一题目内不同学生的提交代码\n"
    report += "4. 代码仓库查重：比较不同学生代码仓库中的所有文件\n"
    report += "5. 高相似度可能由于：代码抄袭、共同参考答案、题目简单导致解法相似等\n"
    report += "6. 建议人工审核高相似度代码，结合提交时间等信息综合判断\n"
    report += "=" * 80 + "\n"
    return report


@homework_bp.route('/export_student_codes')
def export_student_codes():
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    if _export_task is None:
        return jsonify({'success': False, 'message': '导出模块未初始化'}), 500

    selected_class = request.args.get('sclass')
    if not selected_class:
        return jsonify({'success': False, 'message': '班级参数错误'}), 400

    task = _export_task.delay(selected_class)
    return jsonify({'success': True, 'task_id': task.id, 'message': '导出任务已启动'})


@homework_bp.route('/export_progress/<task_id>')
def export_progress(task_id):
    user = current_user()
    if not is_admin(user):
        return jsonify({'success': False, 'message': '权限不足'}), 403

    progress_key = f'export_progress:{task_id}'
    progress_data = _rds.get(progress_key)

    if not progress_data:
        return jsonify({'success': False, 'message': '任务不存在或已过期'}), 404

    progress = json.loads(progress_data)
    return jsonify({'success': True, 'progress': progress})


@homework_bp.route('/download_export/<task_id>')
def download_export(task_id):
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    zip_key = f'export_zip:{task_id}'
    zip_data = _rds_binary.get(zip_key)

    if not zip_data:
        return "文件不存在或已过期", 404

    progress_key = f'export_progress:{task_id}'
    progress_data = _rds.get(progress_key)
    filename = 'student_codes.zip'
    if progress_data:
        filename = 'student_codes.zip'

    from flask import make_response

    response = make_response(zip_data)
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
