#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from difflib import SequenceMatcher

import pymysql
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

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


def _invalidate_problem_list_cache_for_class(class_en):
    try:
        from oj_modules.routes.problem_core_routes import invalidate_problem_list_cache_for_class
        invalidate_problem_list_cache_for_class(class_en)
    except Exception:
        # 缓存失效失败不影响主流程
        pass


from oj_modules.auth_helpers import current_user, is_admin


def init_homework_module(celery_app, redis_client, redis_binary_client):
    global _rds, _rds_binary, _export_task
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
                        '该班级没有可导出查重的普通题作业（打榜赛暂不查重）',
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
                codes_for_plagiarism_check = []

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

                            user_id = None
                            for student in students:
                                if student['username'] == uname:
                                    user_id = student['id']
                                    break

                            included_files = extract_includes_from_code(code)
                            code_with_includes = code

                            if included_files and user_id:
                                repository_files = get_user_repository_files_by_names(user_id, included_files)
                                if repository_files:
                                    code_with_includes += "\n\n// ===== 以下是引用的代码仓库文件 =====\n"
                                    for filename, content in repository_files.items():
                                        code_with_includes += f"\n// ===== {filename} =====\n"
                                        code_with_includes += content + "\n"

                            codes_for_plagiarism_check.append({
                                'username': uname,
                                'code': code_with_includes,
                                'problem_id': pid,
                                'problem_title': ptitle,
                            })

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

                    update_export_progress(task_id, 'collecting', 50, 100, '题目代码收集完成，开始收集代码仓库...')

                    repository_data = []
                    for idx, student in enumerate(students):
                        user_id = student['id']
                        username = student['username']

                        update_export_progress(
                            task_id,
                            'collecting',
                            50 + idx * 10 // len(students),
                            100,
                            f'正在收集 {username} 的代码仓库 ({idx + 1}/{len(students)})',
                        )

                        repo_files = get_student_repository_files(user_id)

                        if repo_files:
                            repository_data.append({
                                'user_id': user_id,
                                'username': username,
                                'files': repo_files,
                            })

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

                    update_export_progress(task_id, 'collecting', 60, 100, '代码仓库收集完成，开始题目代码查重...')

                    plagiarism_results = detect_plagiarism(codes_for_plagiarism_check, threshold=0.9, task_id=task_id)
                    update_export_progress(task_id, 'plagiarism_check', 75, 100, '题目代码查重完成，开始代码仓库查重...')

                    repository_results = detect_repository_plagiarism(repository_data, threshold=0.9, task_id=task_id)
                    update_export_progress(task_id, 'generating', 90, 100, '查重完成，生成报告...')

                    plagiarism_report = generate_plagiarism_report(plagiarism_results, repository_results)
                    info = zipfile.ZipInfo("查重报告.txt")
                    info.flag_bits |= 0x800
                    zip_file.writestr(info, plagiarism_report.encode('utf-8'))

                update_export_progress(task_id, 'generating', 95, 100, '准备下载文件...')

                zip_data = zip_buffer.getvalue()
                _rds_binary.setex(f'export_zip:{task_id}', 600, zip_data)

                sub_progress = {
                    'problem_check': {
                        'current': 100,
                        'total': 100,
                        'percentage': 100,
                        'message': f'题目代码查重完成，发现 {len(plagiarism_results)} 组相似代码',
                    },
                    'repo_check': {
                        'current': 100,
                        'total': 100,
                        'percentage': 100,
                        'message': f'代码仓库查重完成，发现 {len(repository_results)} 组相似文件',
                    },
                }
                update_export_progress(
                    task_id,
                    'completed',
                    100,
                    100,
                    f'导出完成！题目代码: {len(plagiarism_results)} 组，代码仓库: {len(repository_results)} 组',
                    sub_progress,
                )
                return task_id

            except Exception as e:
                import traceback

                error_msg = f'导出失败: {str(e)}'
                update_export_progress(task_id, 'error', 0, 1, error_msg)
                print(traceback.format_exc())
                return None

        _export_task = export_codes_with_plagiarism_check_task


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
                    else:
                        hw['is_ranking'] = False
                        problem = get_problem(hw['problem_id'])
                        hw['problem_title'] = problem['title'] if problem else '未知题目'
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
        flash('无权限操作', 'danger')
        return redirect(url_for('homework.admin_homework'))

    class_en = request.form.get('class_en')
    ddl = request.form.get('ddl')
    problem_id = (request.form.get('problem_id') or '').strip()
    ranking_competition_id = (request.form.get('ranking_competition_id') or '').strip()

    if not class_en or not ddl:
        flash('缺少必要参数', 'danger')
        return redirect(url_for('homework.admin_homework', sclass=class_en))
    # 题目 / 打榜赛 必须恰好二选一
    if bool(problem_id) == bool(ranking_competition_id):
        flash('请选择一项作业内容：题目 或 打榜赛', 'danger')
        return redirect(url_for('homework.admin_homework', sclass=class_en))
    if not get_class_by_en(class_en):
        flash('班级不存在', 'danger')
        return redirect(url_for('homework.admin_homework'))

    try:
        if problem_id:
            try:
                pid = int(problem_id)
            except ValueError:
                flash('题目ID必须是数字', 'danger')
                return redirect(url_for('homework.admin_homework', sclass=class_en))
            problem = get_problem_title(pid)
            if not problem:
                flash('题目不存在', 'danger')
                return redirect(url_for('homework.admin_homework', sclass=class_en))
            col, val, title = 'problem_id', pid, problem['title']
        else:
            try:
                cid = int(ranking_competition_id)
            except ValueError:
                flash('打榜赛ID非法', 'danger')
                return redirect(url_for('homework.admin_homework', sclass=class_en))
            comp = get_competition(cid)
            if not comp:
                flash('打榜赛不存在', 'danger')
                return redirect(url_for('homework.admin_homework', sclass=class_en))
            col, val, title = 'ranking_competition_id', cid, comp['title']

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"INSERT INTO {safe_table_name(class_en)} ({col}, ddl, complete_cnt, problem_title) VALUES (%s, %s, 0, %s)"
                cursor.execute(sql, (val, ddl, title))
            conn.commit()
            _invalidate_problem_list_cache_for_class(class_en)
            flash('作业添加成功', 'success')
        finally:
            conn.close()
    except pymysql.Error as e:
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

    from flask import make_response

    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=GBK'
    resp.headers['Content-Disposition'] = f'attachment; filename="{selected_class}_scores.csv"'
    return resp


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
