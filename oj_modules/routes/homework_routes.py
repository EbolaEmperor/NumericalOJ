#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pymysql
from flask import Blueprint, flash, jsonify, make_response, redirect, render_template, request, url_for

from oj_modules.db_services import (
    CLASS_ADJUST_FLAG_KEY,
    get_all_classes,
    get_all_problems,
    get_class_by_en,
    get_problem_title,
    get_user_by_username,
    set_setting,
)
from oj_modules.homework.records import (
    _load_plagiarism_records_for_class,
    build_plagiarism_records_csv,
    delete_plagiarism_records_for_class as _delete_plagiarism_records_for_class,
)
from oj_modules.homework.runtime import (
    configure_homework_runtime,
    get_export_progress_payload,
    get_export_zip,
    get_plagiarism_progress_payload,
    invalidate_problem_list_cache_for_class as _invalidate_problem_list_cache_for_class,
    start_export_codes_task,
    start_plagiarism_mark_task,
)
from oj_modules.homework.scores import (
    NON_TERMINAL_SUBMISSION_STATUSES,
    homework_score_snapshot,
)
from oj_modules.homework.targets import (
    _PLAGIARISM_TARGET_PROBLEM,
    _PLAGIARISM_TARGET_RANKING,
    parse_plagiarism_mark_payload,
)
from oj_modules.infrastructure.mysql import get_db_connection, safe_table_name
from oj_modules.ranking.db import get_competition, list_competitions
from oj_modules.security.auth import current_user, is_admin


homework_bp = Blueprint('homework', __name__)


def _homework_completion_counts(cursor, class_en, homeworks):
    """用至多两条聚合查询计算整班作业完成数，避免管理页逐条查询。"""
    counts = {int(item['id']): 0 for item in homeworks}
    table_name = safe_table_name(class_en)
    if any(item.get('problem_id') is not None for item in homeworks):
        statuses = sorted(NON_TERMINAL_SUBMISSION_STATUSES)
        excluded = ','.join(['%s'] * len(statuses))
        cursor.execute(
            f"""
            SELECT h.id AS homework_id, COUNT(DISTINCT u.id) AS completed_count
            FROM `{table_name}` h
            JOIN problems p ON p.id = h.problem_id
            JOIN user_class_map m ON m.class_en = %s
            JOIN users u ON u.id = m.user_id
            JOIN submissions s
              ON s.username = u.username
             AND s.problem_id = h.problem_id
             AND s.created_at <= COALESCE(h.ddl, s.created_at)
            WHERE h.problem_id IS NOT NULL
              AND u.is_admin = 0
              AND s.status NOT IN ({excluded})
              AND s.score >= p.max_score
            GROUP BY h.id
            """,
            tuple([class_en, *statuses]),
        )
        for row in cursor.fetchall() or []:
            counts[int(row['homework_id'])] = int(row.get('completed_count') or 0)

    if any(item.get('ranking_competition_id') is not None for item in homeworks):
        cursor.execute(
            f"""
            SELECT h.id AS homework_id, COUNT(DISTINCT u.id) AS completed_count
            FROM `{table_name}` h
            JOIN user_class_map m ON m.class_en = %s
            JOIN users u ON u.id = m.user_id
            JOIN ranking_submissions rs
              ON rs.username = u.username
             AND rs.competition_id = h.ranking_competition_id
             AND rs.created_at <= COALESCE(h.ddl, rs.created_at)
            WHERE h.ranking_competition_id IS NOT NULL
              AND u.is_admin = 0
              AND rs.score IS NOT NULL
            GROUP BY h.id
            """,
            (class_en,),
        )
        for row in cursor.fetchall() or []:
            counts[int(row['homework_id'])] = int(row.get('completed_count') or 0)

    return counts

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


def init_homework_module(
    redis_client,
    redis_binary_client,
    export_task,
    plagiarism_task,
    *,
    problem_list_cache_invalidator=None,
):
    """注入两个 HTTP 适配层共享的 Redis、任务与缓存失效端口。"""

    configure_homework_runtime(
        redis_client,
        redis_binary_client,
        export_task,
        plagiarism_task,
        problem_list_cache_invalidator=problem_list_cache_invalidator,
    )


@homework_bp.route('/admin/homework')
def admin_homework():
    user = current_user()
    if not is_admin(user):
        return "<h3>无权限</h3>"

    selected_class = request.args.get('sclass')
    classes = get_all_classes()

    valid_classes = [cls['class_en'] for cls in classes]
    if selected_class and selected_class not in valid_classes:
        flash('无效的班级选择', 'danger')
        return redirect(url_for('homework.admin_homework'))

    problem_records = get_all_problems() or []
    problems_by_id = {int(item['id']): item for item in problem_records}
    homework_list = []
    plagiarism_problem_options = []
    if selected_class:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = f"SELECT * FROM {safe_table_name(selected_class)} ORDER BY id ASC"
                cursor.execute(sql)
                homework_list = cursor.fetchall()
                completion_counts = _homework_completion_counts(
                    cursor, selected_class, homework_list,
                )
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
                        problem = problems_by_id.get(int(hw['problem_id']))
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
                    hw['complete_cnt'] = completion_counts.get(int(hw['id']), 0)
        except pymysql.Error as e:
            flash(f'数据库操作失败，请稍后再试', 'danger')
        finally:
            conn.close()

    all_problems = [{'id': p['id'], 'title': p['title']} for p in problem_records]
    try:
        all_competitions = [
            {'id': c['id'], 'title': c['title'], 'scoring_mode': c.get('scoring_mode')}
            for c in (list_competitions(include_inactive=True) or [])
        ]
    except Exception:
        all_competitions = []

    return render_template(
        'admin/homework.html',
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
                       hw.ddl,
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
                'ddl': hw.get('ddl'),
            })
        elif ranking_competition_id is not None:
            title = hw.get('problem_title') or hw.get('ranking_title') or f"打榜赛 {ranking_competition_id}"
            score_columns.append({
                'kind': 'ranking',
                'id': int(ranking_competition_id),
                'title': title,
                'ddl': hw.get('ddl'),
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
                  AND u.is_admin = 0
                ORDER BY u.id ASC
                """,
                (selected_class,),
            )
            students = cursor.fetchall()
    finally:
        conn.close()

    if not students:
        return "该班级没有学生", 404

    problem_submission_map = {}
    if problem_ids:
        usernames = [s['username'] for s in students]
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                username_placeholders = ','.join(['%s'] * len(usernames))
                pid_placeholders = ','.join(['%s'] * len(problem_ids))
                cursor.execute(
                    f"""
                    SELECT id, username, problem_id, score, status, created_at
                    FROM submissions
                    WHERE username IN ({username_placeholders})
                      AND problem_id IN ({pid_placeholders})
                    ORDER BY id ASC
                    """,
                    tuple(usernames + problem_ids),
                )
                for submission in cursor.fetchall() or []:
                    problem_submission_map.setdefault(
                        (submission['username'], int(submission['problem_id'])), []
                    ).append(submission)
        finally:
            conn.close()

    from io import BytesIO
    import codecs
    import csv

    ranking_submission_map = {}
    if ranking_competition_ids:
        usernames = [s['username'] for s in students]
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                username_placeholders = ','.join(['%s'] * len(usernames))
                cid_placeholders = ','.join(['%s'] * len(ranking_competition_ids))
                cursor.execute(
                    f"""
                    SELECT id, username, competition_id, score, status, created_at
                    FROM ranking_submissions
                    WHERE username IN ({username_placeholders})
                      AND competition_id IN ({cid_placeholders})
                      AND score IS NOT NULL
                    ORDER BY id ASC
                    """,
                    tuple(usernames + ranking_competition_ids),
                )
                for submission in cursor.fetchall() or []:
                    ranking_submission_map.setdefault(
                        (
                            submission['username'],
                            int(submission['competition_id']),
                        ),
                        [],
                    ).append(submission)
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
        row = [stu['username']]
        total = 0

        for col in score_columns:
            if col['kind'] == 'problem':
                snapshot = homework_score_snapshot(
                    problem_submission_map.get(
                        (stu['username'], col['id']), []
                    ),
                    col.get('ddl'),
                )
            else:
                snapshot = homework_score_snapshot(
                    ranking_submission_map.get(
                        (stu['username'], col['id']), []
                    ),
                    col.get('ddl'),
                    require_terminal=False,
                )
            best = snapshot['best']
            score = (best or {}).get('score') or 0
            total += score
            row.append(str(score))
        row.append(str(total))
        writer.writerow([cell.encode('gbk', 'replace').decode('gbk') for cell in row])

    resp = make_response(output.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=GBK'
    resp.headers['Content-Disposition'] = f'attachment; filename="{selected_class}_scores.csv"'
    return resp




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
    artifact = build_plagiarism_records_csv(class_en)
    response = make_response(artifact.content)
    response.headers['Content-Type'] = artifact.content_type
    response.headers['Content-Disposition'] = (
        f'attachment; filename="{artifact.filename}"'
    )
    return response


def delete_plagiarism_records_for_class(class_en, record_ids):
    return _delete_plagiarism_records_for_class(
        class_en,
        record_ids,
        invalidate_callback=_invalidate_problem_list_cache_for_class,
    )


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


@homework_bp.post('/export_student_codes')
def export_student_codes():
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    payload = request.get_json(silent=True) or {}
    selected_class = request.form.get('sclass') or payload.get('sclass')
    if not selected_class:
        return jsonify({'success': False, 'message': '班级参数错误'}), 400

    try:
        task_id = start_export_codes_task(selected_class)
    except RuntimeError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 500
    return jsonify({'success': True, 'task_id': task_id, 'message': '导出任务已启动'})


@homework_bp.route('/export_progress/<task_id>')
def export_progress(task_id):
    user = current_user()
    if not is_admin(user):
        return jsonify({'success': False, 'message': '权限不足'}), 403

    progress = get_export_progress_payload(task_id)
    if not progress:
        return jsonify({'success': False, 'message': '任务不存在或已过期'}), 404
    return jsonify({'success': True, 'progress': progress})


@homework_bp.route('/download_export/<task_id>')
def download_export(task_id):
    user = current_user()
    if not is_admin(user):
        return redirect(url_for('auth.login'))

    zip_data = get_export_zip(task_id)
    if not zip_data:
        return "文件不存在或已过期", 404

    filename = 'student_codes.zip'

    response = make_response(zip_data)
    response.headers['Content-Type'] = 'application/zip'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
