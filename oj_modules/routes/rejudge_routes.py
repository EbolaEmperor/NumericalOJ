#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime

from flask import Blueprint, jsonify, request, session

from oj_modules.db_services import (
    get_db_connection,
    get_submission_by_id,
    get_submissions_in_time_range,
    get_user_by_username,
    reset_submission_for_rejudge,
)
from oj_modules.tasks.evaluate_tasks import clear_submission_lock


rejudge_bp = Blueprint('rejudge', __name__)

_rds = None
_evaluate_submission = None
_transcribe_written_task = None
_rejudge_task = None

# 时间范围重测共用的进度键（同一时刻只跑一次，足够）
_TIME_RANGE_PROGRESS_KEY = "rejudge:timerange"
_TIME_RANGE_MAX_TOTAL = 500
_REJUDGE_STAGGER_SECONDS = 1


from oj_modules.auth_helpers import current_user, is_admin


def init_rejudge_module(celery_app, redis_client, evaluate_submission_func, transcribe_written_func=None):
    global _rds, _evaluate_submission, _transcribe_written_task, _rejudge_task
    _rds = redis_client
    _evaluate_submission = evaluate_submission_func
    _transcribe_written_task = transcribe_written_func

    if _rejudge_task is None:
        @celery_app.task(name='oj.rejudge.evaluate_submission_and_update')
        def evaluate_submission_and_update(submission_id, progress_key):
            # 按 problem_type 分派：书面作业(type 2) 走转写评分任务，其余走程序题评测。
            try:
                submission = get_submission_by_id(submission_id)
                if submission and submission.get('problem_type') == 2:
                    if _transcribe_written_task is not None:
                        _transcribe_written_task(submission_id)
                else:
                    _evaluate_submission(submission_id)
            finally:
                if _rds is not None and progress_key:
                    _rds.hincrby(progress_key, "done", 1)

        _rejudge_task = evaluate_submission_and_update


def get_all_submissions_for_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, problem_type, status
                FROM submissions
                WHERE problem_id=%s
                ORDER BY id ASC
            """
            cursor.execute(sql, (problem_id,))
            return cursor.fetchall()
    finally:
        conn.close()


def _enqueue_rejudge(submissions, progress_key, clear_running_lock=False):
    """重置每条提交状态为 Pending 并按 problem_type 分派重测；进度写入 progress_key。

    clear_running_lock=True 时，对状态为 'Running' 的提交清除残留的评测幂等锁
    （用于时间范围重测：区间内可能包含上次崩溃时评测到一半、锁还没过期的提交）。
    """
    _rds.hset(progress_key, mapping={"total": len(submissions), "done": 0})

    for sub in submissions:
        if clear_running_lock and sub.get("status") == "Running":
            clear_submission_lock(sub["id"])
        reset_submission_for_rejudge(sub["id"], sub.get("problem_type"))

    for idx, sub in enumerate(submissions):
        _rejudge_task.apply_async(
            args=[sub["id"], progress_key],
            countdown=idx * _REJUDGE_STAGGER_SECONDS,
        )


@rejudge_bp.route('/admin/rejudge_problem/<int:problem_id>', methods=['POST'])
def rejudge_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if _rejudge_task is None or _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    submissions = get_all_submissions_for_problem(problem_id)
    if not submissions:
        return jsonify(success=False, message="该题暂无提交"), 400

    _enqueue_rejudge(submissions, f"rejudge:{problem_id}")
    return jsonify(success=True, message="已开始重测")


@rejudge_bp.route('/admin/rejudge_status/<int:problem_id>', methods=['GET'])
def rejudge_status(problem_id):
    if _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    key = f"rejudge:{problem_id}"
    if not _rds.exists(key):
        return jsonify(success=False, message="该题未在重测或已结束")

    info = _rds.hgetall(key)
    total = int(info.get("total", 0))
    done = int(info.get("done", 0))

    if total <= 0:
        return jsonify(success=False, message="总数异常")
    progress = int(done / total * 100)

    return jsonify(success=True, progress=progress, done=done, total=total)


def _normalize_dt(raw):
    """把前端 datetime-local 的 'YYYY-MM-DDTHH:MM' 规整为 MySQL 可用的 'YYYY-MM-DD HH:MM:SS'。"""
    text = str(raw or "").strip().replace("T", " ")
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def _format_dt(value):
    if not value:
        return ""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except AttributeError:
        return str(value)


def _summarize_time_range_rows(rows):
    created_values = [row.get("created_at") for row in rows if row.get("created_at")]
    return {
        "total": len(rows),
        "min_created_at": _format_dt(min(created_values)) if created_values else "",
        "max_created_at": _format_dt(max(created_values)) if created_values else "",
    }


@rejudge_bp.route('/admin/rejudge_time_range', methods=['POST'])
def rejudge_time_range():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if _rejudge_task is None or _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    payload = request.get_json(silent=True) or request.form
    start = _normalize_dt(payload.get("start"))
    end = _normalize_dt(payload.get("end"))
    if not start or not end:
        return jsonify(success=False, message="请提供有效的起始与结束时间"), 400
    if start > end:
        return jsonify(success=False, message="起始时间不能晚于结束时间"), 400

    submissions = get_submissions_in_time_range(start, end)
    if not submissions:
        return jsonify(success=False, message="该时间范围内没有提交"), 400

    summary = _summarize_time_range_rows(submissions)
    print(
        "[TimeRangeRejudge] "
        f"user={user.get('username')} start={start} end={end} "
        f"total={summary['total']} min={summary['min_created_at']} max={summary['max_created_at']}"
    )

    confirm_total = payload.get("confirm_total")
    try:
        confirm_total = int(confirm_total)
    except (TypeError, ValueError):
        confirm_total = None

    if confirm_total != len(submissions):
        return jsonify(
            success=True,
            preview=True,
            too_many=(len(submissions) > _TIME_RANGE_MAX_TOTAL),
            max_total=_TIME_RANGE_MAX_TOTAL,
            start=start,
            end=end,
            **summary,
        )

    if len(submissions) > _TIME_RANGE_MAX_TOTAL:
        return jsonify(
            success=False,
            message=f"单次时间范围重测最多允许 {_TIME_RANGE_MAX_TOTAL} 条提交，请缩小时间范围",
            **summary,
        ), 400

    _enqueue_rejudge(submissions, _TIME_RANGE_PROGRESS_KEY, clear_running_lock=True)
    return jsonify(success=True, message="已开始重测", total=len(submissions))


@rejudge_bp.route('/admin/rejudge_time_range_status', methods=['GET'])
def rejudge_time_range_status():
    if _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    if not _rds.exists(_TIME_RANGE_PROGRESS_KEY):
        return jsonify(success=False, message="当前没有进行中的时间范围重测")

    info = _rds.hgetall(_TIME_RANGE_PROGRESS_KEY)
    total = int(info.get("total", 0))
    done = int(info.get("done", 0))

    if total <= 0:
        return jsonify(success=False, message="总数异常")
    progress = int(done / total * 100)

    return jsonify(success=True, progress=progress, done=done, total=total)
