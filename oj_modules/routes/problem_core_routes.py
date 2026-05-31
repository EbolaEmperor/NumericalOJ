#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import re
import time
from datetime import datetime, timedelta
from uuid import uuid4

import markdown
from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, session, stream_with_context, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import (
    can_submit,
    create_submission,
    ensure_class_homework_columns,
    get_all_problems,
    get_agent_run_by_task_id,
    get_agent_runs_paginated,
    get_db_connection,
    get_last_10_days_counts_from_counter,
    get_latest_written_submission,
    get_problem,
    get_remaining_submissions,
    get_submission_summaries_by_user_and_problem,
    get_today_submission_total_from_counter,
    get_user_classes,
    get_user_by_username,
    increment_submission_count,
    overwrite_written_submission,
    upsert_agent_run_snapshot,
)
from oj_modules.tasks.agent_tasks import get_agent_run_snapshot, subscribe_agent_run_events


problem_core_bp = Blueprint('problem_core', __name__)

_evaluate_submission_task = None
_transcribe_written_homework_task = None
_agent_solve_problem_task = None
_agent_generate_testdata_task = None
_USER_CLASSES_CACHE_TTL_SECONDS = 30
_HOMEWORKS_CACHE_TTL_SECONDS = 10
_CLASS_GRADES_CACHE_TTL_SECONDS = 20
_USER_CACHE_TTL_SECONDS = 30
_user_classes_cache = {}
_homeworks_cache = {}
_class_grades_cache = {}
_user_cache = {}


def invalidate_problem_list_cache_for_user(user_id=None, username=None):
    """
    失效指定用户在 problem list 相关路径上的缓存。
    """
    if user_id is not None:
        _user_classes_cache.pop(user_id, None)
        for cache_key in list(_homeworks_cache.keys()):
            if cache_key[0] == user_id:
                _homeworks_cache.pop(cache_key, None)

    if username:
        _user_cache.pop(username, None)
        for cache_key in list(_class_grades_cache.keys()):
            if cache_key[0] == username:
                _class_grades_cache.pop(cache_key, None)


def invalidate_problem_list_cache_for_class(class_en):
    """
    失效包含指定班级的作业/成绩缓存。
    """
    if not class_en:
        return

    for cache_key in list(_homeworks_cache.keys()):
        class_list = cache_key[1]
        if class_en in class_list:
            _homeworks_cache.pop(cache_key, None)

    for cache_key in list(_class_grades_cache.keys()):
        class_list = cache_key[1]
        if class_en in class_list:
            _class_grades_cache.pop(cache_key, None)


def invalidate_problem_list_cache_all():
    """
    全量失效 problem list 相关缓存。
    """
    _user_classes_cache.clear()
    _homeworks_cache.clear()
    _class_grades_cache.clear()
    _user_cache.clear()


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


def init_problem_core_module(
    evaluate_submission_task,
    transcribe_written_homework_task,
    agent_solve_problem_task=None,
    agent_generate_testdata_task=None,
):
    global _evaluate_submission_task, _transcribe_written_homework_task, _agent_solve_problem_task, _agent_generate_testdata_task
    _evaluate_submission_task = evaluate_submission_task
    _transcribe_written_homework_task = transcribe_written_homework_task
    _agent_solve_problem_task = agent_solve_problem_task
    _agent_generate_testdata_task = agent_generate_testdata_task


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
    state = get_agent_run_by_task_id(task_id)
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


def _get_homeworks_for_classes(user_id, class_en_list, cursor=None, username=None):
    """
    批量读取多个班级作业，并一次性补齐题目标题、AC 状态、最高分。
    支持两类作业：题目（problem_id）与打榜赛（ranking_competition_id）。
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

    # 保证各班表已有 ranking_competition_id 列、打榜赛相关表已建（惰性、幂等）
    for cls in class_en_list:
        ensure_class_homework_columns(cls)
    try:
        from oj_modules.ranking_db import ensure_ranking_tables
        ensure_ranking_tables()
    except Exception:
        pass

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
                f"SELECT %s AS class_en, id, problem_id, ranking_competition_id, ddl, complete_cnt FROM `{cls}`"
            )
            union_params.append(cls)
        if not union_parts:
            return result

        union_sql = " UNION ALL ".join(union_parts)
        db_cursor.execute(
            f"""
            SELECT t.class_en, t.id, t.problem_id, t.ranking_competition_id, t.ddl, t.complete_cnt,
                   p.title AS problem_title, p.max_score AS total_score,
                   ar.is_ac, ms.score AS user_score,
                   rc.title AS rk_title, rc.max_score AS rk_total, rc.scoring_mode AS rk_mode,
                   rk.rk_best
            FROM ({union_sql}) t
            LEFT JOIN problems p ON p.id = t.problem_id
            LEFT JOIN ac_record ar ON ar.userid=%s AND ar.problem_id = t.problem_id
            LEFT JOIN max_score ms ON ms.userid=%s AND ms.problem_id = t.problem_id
            LEFT JOIN ranking_competitions rc ON rc.id = t.ranking_competition_id
            LEFT JOIN (
                SELECT competition_id, MAX(score) AS rk_best
                FROM ranking_submissions
                WHERE username=%s AND score IS NOT NULL
                GROUP BY competition_id
            ) rk ON rk.competition_id = t.ranking_competition_id
            ORDER BY t.class_en ASC, t.id ASC
            """,
            tuple(union_params + [user_id, user_id, username]),
        )
        homework_rows = db_cursor.fetchall()

        for row in homework_rows:
            cls = row["class_en"]
            if cls not in result:
                continue
            rcid = row.get("ranking_competition_id")
            if rcid:
                best = row.get("rk_best")
                is_elo = (row.get("rk_mode") == "elo")
                hw = {
                    "id": row["id"],
                    "kind": "ranking",
                    "competition_id": int(rcid),
                    "problem_id": None,
                    "ddl": row["ddl"],
                    "complete_cnt": row["complete_cnt"],
                    "problem_title": row.get("rk_title") or row.get("problem_title") or f"打榜赛 {rcid}",
                    "total_score": (None if is_elo else row.get("rk_total")),
                    "is_completed": (best is not None),
                    "max_score": best,
                    "has_submission": (best is not None),
                }
            else:
                pid = row["problem_id"]
                try:
                    pid = int(pid)
                except Exception:
                    pass
                hw = {
                    "id": row["id"],
                    "kind": "problem",
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
                if hw.get("kind") == "ranking":
                    continue
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
            homeworks_map = _get_homeworks_for_classes(user_id, class_en_list, cursor=cursor, username=student_id)
            grades_map = get_class_grades_map(student_id, class_en_list, cursor=cursor)
    finally:
        conn.close()
    return homeworks_map, grades_map


def get_homeworks(user):
    classes = get_user_classes_cached(user['id'])
    class_tables = [c['class_en'] for c in classes]
    if not class_tables:
        return []

    homeworks_by_class = _get_homeworks_for_classes(user['id'], class_tables, username=user.get('username'))
    merged = {}
    for cls in class_tables:
        for hw in homeworks_by_class.get(cls, []):
            # 本函数仅用于题目访问/DDL 判定，跳过打榜赛作业行
            if hw.get('kind') == 'ranking' or hw.get('problem_id') is None:
                continue
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
    """返回 (total_submissions, total_accepted)。

    total_submissions 走 daily_submission_stats 计数表（含 programming + ranking 两类提交）。
    total_accepted 仍直接查 submissions 表（仅 programming），单日范围 + idx_submissions_created_status，
    本身已经很快，没必要也搬到计数表。
    """
    total_submissions = get_today_submission_total_from_counter()

    today_start = datetime.combine(datetime.today().date(), datetime.min.time())
    tomorrow_start = today_start + timedelta(days=1)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS total_accepted
                FROM submissions
                WHERE created_at >= %s AND created_at < %s
                  AND status = 'Accepted'
                """,
                (today_start, tomorrow_start),
            )
            row = cursor.fetchone() or {}
            total_accepted = int(row.get('total_accepted') or 0)
    finally:
        conn.close()
    return total_submissions, total_accepted


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

    total_submissions, total_accepted = get_today_submission_counts()
    last_10_days, daily_counts = get_last_10_days_counts_from_counter()

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

    payload = request.get_json(silent=True) or {}
    extra_prompt = str(payload.get('extra_prompt') or '').strip()
    if len(extra_prompt) > 4000:
        extra_prompt = extra_prompt[:4000]

    task_id = uuid4().hex
    pending_state = {
        "task_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "extra_prompt": extra_prompt,
        "status": "Pending",
        "message": "任务排队中",
        "round": 0,
        "max_rounds": 0,
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [{
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "info",
            "message": "任务已创建，等待执行",
            "event_type": "created",
        }],
    }
    upsert_agent_run_snapshot(pending_state)

    try:
        _agent_solve_problem_task.apply_async(args=(problem_id, user['username'], extra_prompt), task_id=task_id)
    except Exception as e:
        pending_state["status"] = "Failed"
        pending_state["message"] = f"任务入队失败：{e}"
        pending_state["events"].append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "error",
            "message": pending_state["message"],
            "event_type": "enqueue_error",
        })
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    return jsonify(
        success=True,
        message='Agent 任务已启动',
        task_id=task_id,
        view_url=url_for('problem_core.admin_agent_run', task_id=task_id),
    )


@problem_core_bp.route('/admin/agent_generate_testdata/<int:problem_id>', methods=['POST'])
def admin_agent_generate_testdata(problem_id):
    user = current_user()
    if not user or user.get('is_admin') != 1:
        return jsonify(success=False, message='无权限'), 403

    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if int(problem.get('type') or 1) != 1:
        return jsonify(success=False, message='仅支持编程题'), 400
    if _agent_generate_testdata_task is None:
        return jsonify(success=False, message='数据生成 Agent 任务未初始化'), 500

    payload = request.get_json(silent=True) or {}
    standard_code = str(payload.get('standard_code') or '').strip()
    if not standard_code:
        return jsonify(success=False, message='标准程序不能为空'), 400
    data_requirement = str(payload.get('data_requirement') or '').strip()
    if len(data_requirement) > 4000:
        data_requirement = data_requirement[:4000]

    try:
        test_point_count = int(payload.get('test_point_count'))
    except Exception:
        return jsonify(success=False, message='测试点数量无效'), 400
    if test_point_count < 1 or test_point_count > 5000:
        return jsonify(success=False, message='测试点数量需在 1-5000 之间'), 400

    task_id = uuid4().hex
    pending_state = {
        "task_id": task_id,
        "problem_id": int(problem.get("id") or problem_id),
        "problem_title": problem.get("title"),
        "requested_by": user.get("username"),
        "status": "Pending",
        "message": "数据生成 Agent 任务排队中",
        "round": 0,
        "max_rounds": 0,
        "best_score": 0,
        "latest_submission_id": None,
        "final_submission_id": None,
        "attempts": [],
        "events": [{
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "info",
            "message": "数据生成 Agent 任务已创建，等待执行",
            "event_type": "created",
            "details": {
                "test_point_count": test_point_count,
                "has_data_requirement": bool(data_requirement),
            },
        }],
    }
    upsert_agent_run_snapshot(pending_state)

    try:
        _agent_generate_testdata_task.apply_async(
            args=(problem_id, user['username'], test_point_count, standard_code, data_requirement),
            task_id=task_id,
        )
    except Exception as e:
        pending_state["status"] = "Failed"
        pending_state["message"] = f"任务入队失败：{e}"
        pending_state["events"].append({
            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "level": "error",
            "message": pending_state["message"],
            "event_type": "enqueue_error",
        })
        upsert_agent_run_snapshot(pending_state)
        return jsonify(success=False, message=pending_state["message"]), 500

    return jsonify(
        success=True,
        message='数据生成 Agent 任务已启动',
        task_id=task_id,
        view_url=url_for('problem_core.admin_agent_run', task_id=task_id),
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

            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1

            lower_filename = filename.lower()
            if written_mode == 3:
                if not lower_filename.endswith('.zip'):
                    flash(f'错误：{filename} 不是 ZIP 文件（tex 文本批改模式仅支持 .zip）', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))
            else:
                if not lower_filename.endswith('.pdf'):
                    flash(f'错误：{filename} 不是 PDF 文件', 'danger')
                    return redirect(url_for('problem_core.problem_detail', problem_id=problem_id))

            # 纯人工批改：覆盖上一次提交
            if written_mode == 4:
                existing = get_latest_written_submission(user['username'], problem_id)
                if existing:
                    submission_id = existing['id']
                    # 清空旧文件
                    old_folder = os.path.join('uploads', str(submission_id))
                    if os.path.isdir(old_folder):
                        import shutil
                        shutil.rmtree(old_folder)
                    os.makedirs(old_folder)
                    file.save(os.path.join(old_folder, filename))
                    overwrite_written_submission(submission_id, filename)
                    if user['is_admin'] != 1:
                        increment_submission_count(user['username'], problem_id)
                    return redirect(url_for('submission.submission_detail', submission_id=submission_id))
                # 首次提交：走普通 INSERT 流程（下方）

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

            if written_mode != 4:
                try:
                    if _transcribe_written_homework_task is None:
                        raise RuntimeError("自动评分任务未初始化")
                    _transcribe_written_homework_task.delay(submission_id)
                except Exception as e:
                    flash(f'文件已提交，但自动评分任务入队失败：{str(e)}', 'warning')

            return redirect(url_for('submission.submission_detail', submission_id=submission_id))

    return render_template('problem_detail.html', problem=problem, user=user, remaining_submissions=remaining_submissions)


@problem_core_bp.route('/admin/agent_tasks')
def admin_agent_tasks():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    if user.get('is_admin') != 1:
        flash('无权限访问该页面', 'danger')
        return redirect(url_for('problem_core.problem_list'))

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 20
    runs, total_pages = get_agent_runs_paginated(page=page, per_page=per_page)

    for run in runs:
        run['display_problem_title'] = (
            str(run.get('problem_title') or '').strip()
            or f"Problem {run.get('problem_id') or '-'}"
        )
        run['display_status'] = str(run.get('status') or 'Pending')
        run['display_rounds'] = f"{int(run.get('rounds_run') or 0)}"
        run['display_best_score'] = int(run.get('best_score') or 0)

    page_start = max(1, page - 8)
    page_end = min(total_pages, page + 8)
    page_numbers = list(range(page_start, page_end + 1))

    return render_template(
        'admin_agent_tasks.html',
        user=user,
        agent_runs=runs,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
    )


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
