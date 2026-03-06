#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import time
from datetime import datetime, timedelta

import markdown
from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, session, stream_with_context, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import (
    can_submit,
    create_submission,
    get_all_problems,
    get_db_connection,
    get_problem,
    get_remaining_submissions,
    get_submission_summaries_by_user_and_problem,
    get_user_classes,
    get_user_by_username,
    increment_submission_count,
)
from oj_modules.tasks.agent_tasks import get_agent_run_snapshot, subscribe_agent_run_events


problem_core_bp = Blueprint('problem_core', __name__)

_evaluate_submission_task = None
_transcribe_written_homework_task = None
_agent_solve_problem_task = None
_DASHBOARD_STATS_CACHE_TTL_SECONDS = 15
_USER_CLASSES_CACHE_TTL_SECONDS = 30
_HOMEWORKS_CACHE_TTL_SECONDS = 10
_CLASS_GRADES_CACHE_TTL_SECONDS = 20
_USER_CACHE_TTL_SECONDS = 30
_dashboard_stats_cache = {
    "expires_at": 0.0,
    "total_submissions": 0,
    "total_accepted": 0,
    "last_10_days": [],
    "daily_counts": [],
}
_user_classes_cache = {}
_homeworks_cache = {}
_class_grades_cache = {}
_user_cache = {}


def _strip_problem_title_tags(title):
    """
    去掉题目标题中的分组标签，如「NA-1」。
    仅用于普通用户展示，不改动数据库原始标题。
    """
    if title is None:
        return title
    original = str(title).strip()
    text = original
    # 移除所有全角书名号里的短标签
    text = re.sub(r'\s*「[^」]{1,32}」\s*', ' ', text)
    # 合并多余空白
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else original


def init_problem_core_module(evaluate_submission_task, transcribe_written_homework_task, agent_solve_problem_task=None):
    global _evaluate_submission_task, _transcribe_written_homework_task, _agent_solve_problem_task
    _evaluate_submission_task = evaluate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task
    _agent_solve_problem_task = agent_solve_problem_task


def _is_agent_state_finished(state):
    if not isinstance(state, dict):
        return False
    status = str(state.get("status") or "").strip().lower()
    return status in ("completed", "failed", "canceled", "cancelled")


def _build_agent_state_from_async_result(task_id):
    if not task_id or _agent_solve_problem_task is None:
        return None
    try:
        async_result = _agent_solve_problem_task.AsyncResult(task_id)
    except Exception:
        return None

    celery_state = str(async_result.state or "PENDING").upper()
    now = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    state = {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
        "updated_at": now,
        "celery_state": celery_state,
    }

    if celery_state in ("RECEIVED", "STARTED", "RETRY"):
        state["status"] = "Running"
        state["message"] = "任务执行中"
        return state

    if celery_state == "FAILURE":
        state["status"] = "Failed"
        state["message"] = str(async_result.result) if async_result.result is not None else "任务执行失败"
        return state

    if celery_state == "SUCCESS":
        result_data = async_result.result if isinstance(async_result.result, dict) else {}
        state["status"] = "Completed" if result_data.get("success") else "Failed"
        state["message"] = result_data.get("message") or "任务已结束"
        state["final_submission_id"] = result_data.get("final_submission_id")
        state["latest_submission_id"] = result_data.get("final_submission_id")
        state["attempts"] = result_data.get("attempts") or []
        return state

    return state


def _get_agent_run_state(task_id):
    state = get_agent_run_snapshot(task_id)
    if isinstance(state, dict):
        return state
    return _build_agent_state_from_async_result(task_id)


def current_user():
    username = session.get('username')
    if not username:
        return None
    now_ts = time.time()
    cached = _user_cache.get(username)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    user = get_user_by_username(username)
    _user_cache[username] = {
        "expires_at": now_ts + _USER_CACHE_TTL_SECONDS,
        "value": user,
    }
    return user


def get_user_classes_cached(user_id):
    now_ts = time.time()
    cached = _user_classes_cache.get(user_id)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    classes = get_user_classes(user_id)
    _user_classes_cache[user_id] = {
        "expires_at": now_ts + _USER_CLASSES_CACHE_TTL_SECONDS,
        "value": classes,
    }
    return classes


def _get_homeworks_for_classes(user_id, class_en_list, cursor=None):
    """
    批量读取多个班级作业，并一次性补齐题目标题、AC 状态、最高分。
    返回: {class_en: [hw, ...]}
    """
    result = {cls: [] for cls in class_en_list}
    if not class_en_list:
        return result

    cache_key = (user_id, tuple(class_en_list))
    now_ts = time.time()
    cached = _homeworks_cache.get(cache_key)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    db_cursor = cursor
    conn = None
    try:
        if db_cursor is None:
            conn = get_db_connection()
            db_cursor = conn.cursor()

        union_parts = []
        union_params = []
        for cls in class_en_list:
            union_parts.append(
                f"SELECT %s AS class_en, id, problem_id, ddl, complete_cnt FROM `{cls}`"
            )
            union_params.append(cls)
        if not union_parts:
            return result

        union_sql = " UNION ALL ".join(union_parts)
        db_cursor.execute(
            f"""
            SELECT t.class_en, t.id, t.problem_id, t.ddl, t.complete_cnt,
                   p.title AS problem_title, p.max_score AS total_score,
                   ar.is_ac, ms.score AS user_score
            FROM ({union_sql}) t
            LEFT JOIN problems p ON p.id = t.problem_id
            LEFT JOIN ac_record ar ON ar.userid=%s AND ar.problem_id = t.problem_id
            LEFT JOIN max_score ms ON ms.userid=%s AND ms.problem_id = t.problem_id
            ORDER BY t.class_en ASC, t.id ASC
            """,
            tuple(union_params + [user_id, user_id]),
        )
        homework_rows = db_cursor.fetchall()

        for row in homework_rows:
            cls = row["class_en"]
            if cls not in result:
                continue
            pid = row["problem_id"]
            try:
                pid = int(pid)
            except Exception:
                pass
            hw = {
                "id": row["id"],
                "problem_id": pid,
                "ddl": row["ddl"],
                "complete_cnt": row["complete_cnt"],
                "problem_title": row.get("problem_title"),
                "total_score": row.get("total_score"),
                "is_completed": (row.get("is_ac") == 1),
                "max_score": row.get("user_score"),
            }
            result[cls].append(hw)

        for cls, hw_list in result.items():
            for hw in hw_list:
                pid = hw["problem_id"]
                hw["problem_title"] = (
                    hw.get("problem_title") if hw.get("problem_title") else f"Problem {pid}"
                )
                hw["problem_title"] = _strip_problem_title_tags(hw["problem_title"])
                hw["total_score"] = (
                    hw.get("total_score") if hw.get("total_score") is not None else 0
                )
                hw["has_submission"] = bool(
                    hw["max_score"] is not None
                    or hw["is_completed"]
                )
        _homeworks_cache[cache_key] = {
            "expires_at": now_ts + _HOMEWORKS_CACHE_TTL_SECONDS,
            "value": result,
        }
        return result
    finally:
        if conn is not None:
            conn.close()


def get_class_grades_map(student_id, class_en_list, cursor=None):
    if not class_en_list:
        return {}

    cache_key = (student_id, tuple(class_en_list))
    now_ts = time.time()
    cached = _class_grades_cache.get(cache_key)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    db_cursor = cursor
    conn = None
    try:
        if db_cursor is None:
            conn = get_db_connection()
            db_cursor = conn.cursor()

        placeholders = ",".join(["%s"] * len(class_en_list))
        db_cursor.execute(
            f"""
            SELECT class_en, regular_score, final_score
            FROM final_exam_scores
            WHERE student_id=%s AND class_en IN ({placeholders})
            """,
            tuple([student_id] + class_en_list),
        )
        rows = db_cursor.fetchall()
    except Exception:
        return {}
    finally:
        if conn is not None:
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
    _class_grades_cache[cache_key] = {
        "expires_at": now_ts + _CLASS_GRADES_CACHE_TTL_SECONDS,
        "value": grades_map,
    }
    return grades_map


def get_homeworks_and_grades_map(user_id, student_id, class_en_list):
    """
    在缓存未命中时复用同一连接拿到作业数据与班级成绩，减少 problem_list 路径连接数。
    """
    if not class_en_list:
        return {}, {}

    class_key = tuple(class_en_list)
    now_ts = time.time()
    h_cached = _homeworks_cache.get((user_id, class_key))
    g_cached = _class_grades_cache.get((student_id, class_key))
    if (
        h_cached and g_cached
        and now_ts < h_cached["expires_at"]
        and now_ts < g_cached["expires_at"]
    ):
        return h_cached["value"], g_cached["value"]

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            homeworks_map = _get_homeworks_for_classes(user_id, class_en_list, cursor=cursor)
            grades_map = get_class_grades_map(student_id, class_en_list, cursor=cursor)
    finally:
        conn.close()
    return homeworks_map, grades_map


def get_homeworks(user):
    classes = get_user_classes_cached(user['id'])
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

            data_sql = """
                SELECT id, username, status, score, problem_title, created_at
                FROM submissions
                WHERE username=%s
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """
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

            data_sql = """
                SELECT id, username, status, score, problem_title, created_at
                FROM submissions
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """
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

    classes = get_user_classes_cached(user['id'])
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
        homeworks_map, grades_map = get_homeworks_and_grades_map(user['id'], user['username'], [cls])
        homeworks = homeworks_map.get(cls, [])
        class_grades = grades_map.get(cls)
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
    class_homeworks_map, class_grades_map = get_homeworks_and_grades_map(
        user['id'],
        user['username'],
        class_en_list,
    )

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

    submissions = get_submission_summaries_by_user_and_problem(user['username'], problem_id)
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


@problem_core_bp.route('/admin/agent_solve_problem/<int:problem_id>', methods=['POST'])
def admin_agent_solve_problem(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_solve_problem_task is None:
        return jsonify(success=False, message='Agent 任务未初始化'), 500

    task = _agent_solve_problem_task.delay(problem_id, user['username'])
    return jsonify(
        success=True,
        message='Agent 任务已启动',
        task_id=task.id,
        view_url=url_for('problem_core.admin_agent_run', task_id=task.id),
    )


@problem_core_bp.route('/admin/agent_run/<task_id>', methods=['GET'])
def admin_agent_run(task_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if user.get('is_admin') != 1:
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    state = _get_agent_run_state(task_id) or {"task_id": task_id}
    problem_id = state.get("problem_id")
    if not problem_id:
        problem_id = request.args.get("problem_id", type=int)
    problem = get_problem(problem_id) if problem_id else None

    latest_submission_id = state.get("latest_submission_id") or state.get("final_submission_id")
    return render_template(
        'agent_run.html',
        user=user,
        task_id=task_id,
        problem=problem,
        initial_state=state,
        latest_submission_id=latest_submission_id,
    )


@problem_core_bp.route('/admin/agent_run_status/<task_id>', methods=['GET'])
def admin_agent_run_status(task_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message='未登录'), 401
    if user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    state = _get_agent_run_state(task_id) or {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
    }
    return jsonify(success=True, state=state)


@problem_core_bp.route('/admin/agent_run_stream/<task_id>', methods=['GET'])
def admin_agent_run_stream(task_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    if user.get('is_admin') != 1:
        return jsonify({'error': 'Access denied'}), 403

    initial_state = _get_agent_run_state(task_id) or {
        "task_id": task_id,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [],
    }

    def _encode_sse(event_name, payload):
        return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        first_payload = initial_state
        yield _encode_sse("status", first_payload)
        if _is_agent_state_finished(first_payload):
            yield _encode_sse("done", first_payload)
            return

        start_ts = time.time()
        pubsub = subscribe_agent_run_events(task_id)
        if pubsub is None:
            last_marker = (
                first_payload.get("status"),
                first_payload.get("round"),
                first_payload.get("latest_submission_id"),
                first_payload.get("updated_at"),
            )
            while True:
                snapshot = _get_agent_run_state(task_id) or first_payload
                marker = (
                    snapshot.get("status"),
                    snapshot.get("round"),
                    snapshot.get("latest_submission_id"),
                    snapshot.get("updated_at"),
                )
                if marker != last_marker:
                    yield _encode_sse("status", snapshot)
                    last_marker = marker
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
                if time.time() - start_ts > 3600:
                    yield _encode_sse("timeout", snapshot)
                    return
                time.sleep(1.0)

        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                now = time.time()
                if now - start_ts > 3600:
                    latest = _get_agent_run_state(task_id) or initial_state
                    yield _encode_sse("timeout", latest)
                    return

                if not msg:
                    yield ": keepalive\n\n"
                    continue

                if msg.get("type") != "message":
                    continue

                raw = msg.get("data")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="ignore")
                try:
                    snapshot = json.loads(raw) if isinstance(raw, str) else raw
                except Exception:
                    continue
                if not isinstance(snapshot, dict):
                    continue

                yield _encode_sse("status", snapshot)
                if _is_agent_state_finished(snapshot):
                    yield _encode_sse("done", snapshot)
                    return
        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
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

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 20

    if user['is_admin']:
        submissions, total_pages = get_all_submissions_paginated(page=page, per_page=per_page)
    else:
        submissions, total_pages = get_submissions_by_user_paginated(user['username'], page=page, per_page=per_page)
    for sub in submissions:
        sub['display_problem_title'] = _strip_problem_title_tags(sub.get('problem_title'))
        sub['is_ac'] = (sub.get('status') == 'Accepted')

    page_start = max(1, page - 10)
    page_end = min(total_pages, page + 10)
    page_numbers = list(range(page_start, page_end + 1))

    return render_template(
        'all_submission.html',
        submissions=submissions,
        user=user,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
    )
