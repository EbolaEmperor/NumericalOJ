#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
from datetime import datetime, timedelta

import markdown
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import (
    can_submit,
    create_submission,
    get_all_problems,
    get_db_connection,
    get_problem,
    get_remaining_submissions,
    get_submissions_by_user_and_problem,
    get_user_classes,
    get_user_by_username,
    increment_submission_count,
)


problem_core_bp = Blueprint('problem_core', __name__)

_evaluate_submission_task = None
_transcribe_written_homework_task = None
_DASHBOARD_STATS_CACHE_TTL_SECONDS = 15
_dashboard_stats_cache = {
    "expires_at": 0.0,
    "total_submissions": 0,
    "total_accepted": 0,
    "last_10_days": [],
    "daily_counts": [],
}


def init_problem_core_module(evaluate_submission_task, transcribe_written_homework_task):
    global _evaluate_submission_task, _transcribe_written_homework_task
    _evaluate_submission_task = evaluate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def _get_homeworks_for_classes(user_id, class_en_list):
    """
    批量读取多个班级作业，并一次性补齐题目标题、AC 状态、最高分。
    返回: {class_en: [hw, ...]}
    """
    result = {cls: [] for cls in class_en_list}
    if not class_en_list:
        return result

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            placeholders = ",".join(["%s"] * len(class_en_list))
            cursor.execute(
                f"SELECT class_en FROM class_table WHERE class_en IN ({placeholders})",
                tuple(class_en_list),
            )
            valid_class_set = {row["class_en"] for row in cursor.fetchall()}
            valid_classes = [cls for cls in class_en_list if cls in valid_class_set]
            if not valid_classes:
                return result

            union_parts = []
            union_params = []
            for cls in valid_classes:
                union_parts.append(
                    f"SELECT %s AS class_en, id, problem_id, ddl, complete_cnt FROM `{cls}`"
                )
                union_params.append(cls)

            cursor.execute(
                " UNION ALL ".join(union_parts) + " ORDER BY class_en ASC, id ASC",
                tuple(union_params),
            )
            homework_rows = cursor.fetchall()

            problem_ids = set()
            for row in homework_rows:
                cls = row["class_en"]
                if cls not in result:
                    continue
                hw = {
                    "id": row["id"],
                    "problem_id": row["problem_id"],
                    "ddl": row["ddl"],
                    "complete_cnt": row["complete_cnt"],
                }
                result[cls].append(hw)
                problem_ids.add(row["problem_id"])

            problem_map = {}
            if problem_ids:
                pid_placeholders = ",".join(["%s"] * len(problem_ids))
                cursor.execute(
                    f"SELECT id, title, max_score FROM problems WHERE id IN ({pid_placeholders})",
                    tuple(problem_ids),
                )
                problem_map = {row["id"]: row for row in cursor.fetchall()}

            cursor.execute("SELECT * FROM ac_record WHERE userid=%s", (user_id,))
            ac_row = cursor.fetchone() or {}

            cursor.execute("SELECT * FROM max_score WHERE userid=%s", (user_id,))
            max_score_row = cursor.fetchone() or {}

        for cls, hw_list in result.items():
            for hw in hw_list:
                pid = hw["problem_id"]
                ac_key = f"ACP{pid}"
                score_key = f"P{pid}"
                problem = problem_map.get(pid)

                hw["is_completed"] = (ac_row.get(ac_key) == 1)
                hw["max_score"] = max_score_row.get(score_key)
                hw["problem_title"] = (
                    problem["title"] if problem and problem.get("title") else f"Problem {pid}"
                )
                hw["total_score"] = (
                    problem["max_score"] if problem and problem.get("max_score") is not None else 0
                )
        return result
    finally:
        conn.close()


def get_class_grades_map(student_id, class_en_list):
    if not class_en_list:
        return {}
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            placeholders = ",".join(["%s"] * len(class_en_list))
            cursor.execute(
                f"""
                SELECT class_en, regular_score, final_score
                FROM final_exam_scores
                WHERE student_id=%s AND class_en IN ({placeholders})
                """,
                tuple([student_id] + class_en_list),
            )
            rows = cursor.fetchall()
    except Exception:
        return {}
    finally:
        if "conn" in locals():
            conn.close()

    grades_map = {}
    for row in rows:
        grades_map[row["class_en"]] = {
            "regular_score": (
                round(row["regular_score"], 1) if row["regular_score"] is not None else None
            ),
            "final_score": (
                round(row["final_score"], 1) if row["final_score"] is not None else None
            ),
        }
    return grades_map


def get_homeworks(user):
    classes = get_user_classes(user['id'])
    class_tables = [c['class_en'] for c in classes]
    if not class_tables:
        return []

    homeworks_by_class = _get_homeworks_for_classes(user['id'], class_tables)
    merged = {}
    for cls in class_tables:
        for hw in homeworks_by_class.get(cls, []):
            pid = hw['problem_id']
            existing = merged.get(pid)
            if existing is None:
                merged[pid] = {
                    "problem_id": pid,
                    "ddl": hw.get("ddl"),
                    "problem_title": hw.get("problem_title", f"Problem {pid}"),
                    "complete_cnt": 1 if hw.get("is_completed") else 0,
                }
                continue

            old_ddl = existing.get("ddl")
            new_ddl = hw.get("ddl")
            if old_ddl is None or (new_ddl is not None and new_ddl > old_ddl):
                existing["ddl"] = new_ddl
                existing["problem_title"] = hw.get("problem_title", existing["problem_title"])
            if hw.get("is_completed"):
                existing["complete_cnt"] = 1

    return [merged[pid] for pid in sorted(merged.keys())]


def get_homeworks_for_class(user_id, class_en):
    return _get_homeworks_for_classes(user_id, [class_en]).get(class_en, [])


def get_today_submission_counts():
    today_start = datetime.combine(datetime.today().date(), datetime.min.time())
    tomorrow_start = today_start + timedelta(days=1)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                  COUNT(*) AS total_submissions,
                  SUM(CASE WHEN status = 'Accepted' THEN 1 ELSE 0 END) AS total_accepted
                FROM submissions
                WHERE created_at >= %s AND created_at < %s
                """,
                (today_start, tomorrow_start),
            )
            row = cursor.fetchone() or {}
            return int(row.get('total_submissions') or 0), int(row.get('total_accepted') or 0)
    finally:
        conn.close()


def get_last_10_days_submission_counts():
    today = datetime.today().date()
    range_start = datetime.combine(today + timedelta(days=-9), datetime.min.time())
    range_end = datetime.combine(today + timedelta(days=1), datetime.min.time())
    last_10_days = [(today + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(-9, 1)]
    counts = {day: 0 for day in last_10_days}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DATE(created_at) AS day, COUNT(*) AS cnt
                FROM submissions
                WHERE created_at >= %s AND created_at < %s
                GROUP BY DATE(created_at)
                """,
                (range_start, range_end),
            )
            for row in cursor.fetchall():
                day_obj = row.get('day')
                if hasattr(day_obj, 'strftime'):
                    day_key = day_obj.strftime('%Y-%m-%d')
                else:
                    day_key = str(day_obj)
                if day_key in counts:
                    counts[day_key] = int(row.get('cnt') or 0)
    finally:
        conn.close()

    return last_10_days, [counts[day] for day in last_10_days]


def get_dashboard_submission_stats():
    now_ts = time.time()
    if now_ts < _dashboard_stats_cache["expires_at"]:
        return (
            _dashboard_stats_cache["total_submissions"],
            _dashboard_stats_cache["total_accepted"],
            _dashboard_stats_cache["last_10_days"],
            _dashboard_stats_cache["daily_counts"],
        )

    total_submissions, total_accepted = get_today_submission_counts()
    last_10_days, daily_counts = get_last_10_days_submission_counts()

    _dashboard_stats_cache.update({
        "expires_at": now_ts + _DASHBOARD_STATS_CACHE_TTL_SECONDS,
        "total_submissions": total_submissions,
        "total_accepted": total_accepted,
        "last_10_days": last_10_days,
        "daily_counts": daily_counts,
    })
    return total_submissions, total_accepted, last_10_days, daily_counts


def get_submissions_by_user_paginated(username, page=1, per_page=20):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = "SELECT COUNT(*) AS total FROM submissions WHERE username=%s"
            cursor.execute(count_sql, (username,))
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            data_sql = """SELECT * FROM submissions
                        WHERE username=%s
                        ORDER BY id DESC
                        LIMIT %s OFFSET %s"""
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (username, per_page, offset))
            submissions = cursor.fetchall()
            return submissions, total_pages
    finally:
        conn.close()


def get_all_submissions_paginated(page=1, per_page=20):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = "SELECT COUNT(*) AS total FROM submissions"
            cursor.execute(count_sql)
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            data_sql = """SELECT * FROM submissions
                        ORDER BY id DESC
                        LIMIT %s OFFSET %s"""
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (per_page, offset))
            submissions = cursor.fetchall()
            return submissions, total_pages
    finally:
        conn.close()


@problem_core_bp.route('/problems', methods=['GET'])
def problem_list():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    total_submissions, total_accepted, last_10_days, daily_counts = get_dashboard_submission_stats()

    total_grade = 100

    if user['is_admin'] == 1:
        problems = get_all_problems()
        return render_template(
            'problem_list.html',
            problems=problems,
            user=user,
            total_submissions=total_submissions,
            total_accepted=total_accepted,
            total_grade=total_grade,
            last_10_days=last_10_days,
            daily_counts=daily_counts,
        )

    classes = get_user_classes(user['id'])
    now_ts = datetime.now()

    if not classes:
        return render_template(
            'problem_list.html',
            homeworks=[],
            user=user,
            now=now_ts,
            total_submissions=total_submissions,
            total_accepted=total_accepted,
            total_grade=total_grade,
            last_10_days=last_10_days,
            daily_counts=daily_counts,
        )

    if len(classes) == 1:
        cls = classes[0]['class_en']
        homeworks = get_homeworks_for_class(user['id'], cls)
        class_grades = get_class_grades_map(user['username'], [cls]).get(cls)
        return render_template(
            'problem_list.html',
            homeworks=homeworks,
            user=user,
            now=now_ts,
            total_submissions=total_submissions,
            total_accepted=total_accepted,
            total_grade=total_grade,
            last_10_days=last_10_days,
            daily_counts=daily_counts,
            single_class_en=cls,
            single_class_cn=classes[0]['class_cn'],
            class_grades=class_grades,
        )

    class_en_list = [c['class_en'] for c in classes]
    class_homeworks_map = _get_homeworks_for_classes(user['id'], class_en_list)
    class_grades_map = get_class_grades_map(user['username'], class_en_list)

    homeworks_by_class = []
    for c in classes:
        items = class_homeworks_map.get(c['class_en'], [])
        grades = class_grades_map.get(c['class_en'])
        homeworks_by_class.append({
            "class_en": c['class_en'],
            "class_cn": c['class_cn'],
            "is_primary": c['is_primary'],
            "hw_list": items,
            "grades": grades,
        })

    return render_template(
        'problem_list.html',
        homeworks_by_class=homeworks_by_class,
        user=user,
        now=now_ts,
        total_submissions=total_submissions,
        total_accepted=total_accepted,
        total_grade=total_grade,
        last_10_days=last_10_days,
        daily_counts=daily_counts,
    )


@problem_core_bp.route('/problem/<int:problem_id>', methods=['GET'])
def problem_detail(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        if not any(hw['problem_id'] == problem_id for hw in homeworks):
            flash('无权限访问该题目', 'danger')
            return redirect(url_for('problem_core.problem_list'))

    rendered_content = markdown.markdown(
        problem['content'],
        extensions=['extra', 'md_in_html', 'fenced_code', 'tables'],
    )

    submissions = get_submissions_by_user_and_problem(user['username'], problem_id)
    last_submissions = submissions[:3]
    initial_code = problem.get('initial_code', '')

    submission_limit = problem.get('submission_limit', 10)
    remaining_submissions = get_remaining_submissions(user['username'], problem_id, submission_limit) if user['is_admin'] != 1 else None
    can_submit_flag = can_submit(user['username'], problem_id, submission_limit) if user['is_admin'] != 1 else True

    return render_template(
        'problem_detail.html',
        problem=problem,
        rendered_content=rendered_content,
        user=user,
        last_submissions=last_submissions,
        initial_code=initial_code,
        remaining_submissions=remaining_submissions,
        can_submit=can_submit_flag,
    )


@problem_core_bp.route('/submit/<int:problem_id>', methods=['GET', 'POST'])
def submit_solution(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    problem = get_problem(problem_id)
    if not problem:
        return "<h3>题目不存在</h3>"

    if user['is_admin'] != 1:
        homeworks = get_homeworks(user)
        ddls = []
        for hw in homeworks:
            if hw['problem_id'] == problem_id:
                if hw['ddl']:
                    ddls.append(hw['ddl'])

        if ddls:
            latest_ddl = max(ddls)
            if latest_ddl < datetime.now():
                flash('无法提交已过期的作业', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    submission_limit = problem.get('submission_limit', 10)

    if user['is_admin'] != 1:
        if not can_submit(user['username'], problem_id, submission_limit):
            flash(f'您对此题的提交次数已达到上限（{submission_limit}次）！', 'danger')
            return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

    remaining_submissions = get_remaining_submissions(user['username'], problem_id, submission_limit) if user['is_admin'] != 1 else None

    if request.method == 'POST':
        if problem['type'] == 1:
            code = request.form.get('code', '')
            if not code.strip():
                flash('代码不能为空。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            submission_id = create_submission(
                problem_id=problem_id,
                problem_title=problem['title'],
                username=user['username'],
                code=code,
                score=0,
                test_points=[],
            )

            if user['is_admin'] != 1:
                increment_submission_count(user['username'], problem_id)

            if _evaluate_submission_task is None:
                flash('提交成功，但评测任务未初始化。', 'warning')
            else:
                _evaluate_submission_task.delay(submission_id)

            flash('提交成功，正在评测中...', 'success')
            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

        if problem['type'] == 2:
            if 'file' not in request.files:
                flash('请上传文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            file = request.files['file']
            if file.filename == '':
                flash('未选择文件。', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            filename = secure_filename(f"file_{file.filename}")

            if not filename.lower().endswith('.pdf'):
                flash(f'错误：{filename} 不是 PDF 文件', 'danger')
                return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            submission_id = create_submission(
                problem_id=problem_id,
                problem_title=problem['title'],
                username=user['username'],
                code=" ",
                score=0,
                test_points=[filename],
            )

            if user['is_admin'] != 1:
                increment_submission_count(user['username'], problem_id)

            upload_folder = os.path.join('uploads', f"{submission_id}")
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            file_path = os.path.join(upload_folder, filename)
            file.save(file_path)

            try:
                if _transcribe_written_homework_task is None:
                    raise RuntimeError("自动评分任务未初始化")
                _transcribe_written_homework_task.delay(submission_id)
            except Exception as e:
                flash(f'文件已提交，但自动评分任务入队失败：{str(e)}', 'warning')

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

    return render_template('problem_detail.html', problem=problem, user=user, remaining_submissions=remaining_submissions)


@problem_core_bp.route('/my_submissions')
def all_submissions():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    page = request.args.get('page', 1, type=int)
    per_page = 20

    if user['is_admin']:
        submissions, total_pages = get_all_submissions_paginated(page=page, per_page=per_page)
    else:
        submissions, total_pages = get_submissions_by_user_paginated(user['username'], page=page, per_page=per_page)

    return render_template(
        'all_submission.html',
        submissions=submissions,
        user=user,
        current_page=page,
        total_pages=total_pages,
    )
