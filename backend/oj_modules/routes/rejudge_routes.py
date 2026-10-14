#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, current_app, jsonify, request

from backend.oj_modules.db_services import (
    get_db_connection,
    get_submission_by_id,
    reset_submission_for_rejudge,
)
from backend.oj_modules.observability import emit_audit
from backend.oj_modules.security.auth import current_user, is_admin
from backend.oj_modules.submissions.locks import clear_submission_lock
from backend.oj_modules.submissions.rejudge_filters import (
    LATEST_REJUDGE_BATCH_KEY,
    RejudgeConfirmationUnavailable,
    batch_progress_key,
    build_rejudge_preview,
    consume_rejudge_confirmation,
    get_filtered_rejudge_submissions,
    get_rejudge_filter_options,
    normalize_rejudge_filters,
    resolve_rejudge_progress_key,
)
from backend.oj_modules.submissions.written_voting import supersede_latest_attempt


rejudge_bp = Blueprint('rejudge', __name__)

_rds = None
_rejudge_task = None
_bulk_rejudge_task = None

_REJUDGE_STAGGER_SECONDS = 1


def init_rejudge_module(redis_client, rejudge_task, bulk_rejudge_task=None):
    """注入重测路由所需的 Redis 客户端与已注册任务。"""

    global _rds, _rejudge_task, _bulk_rejudge_task
    _rds = redis_client
    _rejudge_task = rejudge_task
    _bulk_rejudge_task = bulk_rejudge_task


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
    （筛选范围可能包含上次崩溃时评测到一半、锁还没过期的提交）。
    """
    _rds.hset(progress_key, mapping={"total": len(submissions), "done": 0})

    for sub in submissions:
        if clear_running_lock and sub.get("status") == "Running":
            clear_submission_lock(sub["id"])
        if int(sub.get("problem_type") or 0) == 2:
            supersede_latest_attempt(sub["id"])
        reset_submission_for_rejudge(sub["id"], sub.get("problem_type"))

    for idx, sub in enumerate(submissions):
        _rejudge_task.apply_async(
            args=[sub["id"], progress_key],
            countdown=idx * _REJUDGE_STAGGER_SECONDS,
        )


@rejudge_bp.route('/api/admin/problems/<int:problem_id>/rejudge', methods=['POST'])
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


@rejudge_bp.route(
    '/admin/rejudge_submission/<int:submission_id>',
    methods=['POST'],
)
@rejudge_bp.route(
    '/api/submissions/<int:submission_id>/rejudge',
    methods=['POST'],
)
def rejudge_submission(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if _rejudge_task is None or _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    _enqueue_rejudge(
        [submission],
        f"rejudge:submission:{submission_id}",
        clear_running_lock=True,
    )
    return jsonify(
        success=True,
        message="已开始重测",
        submission_id=submission_id,
    )


@rejudge_bp.route('/api/admin/problems/<int:problem_id>/rejudge-status', methods=['GET'])
@rejudge_bp.route('/admin/rejudge_status/<int:problem_id>', methods=['GET'])
def rejudge_status(problem_id):
    if not is_admin(current_user()):
        return jsonify(success=False, message="无权限"), 403

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

    response = jsonify(success=True, progress=progress, done=done, total=total)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@rejudge_bp.get('/api/admin/rejudge-ranges/options')
def rejudge_filter_options():
    if not is_admin(current_user()):
        return jsonify(success=False, message="无权限"), 403
    response = jsonify(success=True, **get_rejudge_filter_options())
    response.headers["Cache-Control"] = "private, no-store"
    return response


@rejudge_bp.post('/api/admin/rejudge-ranges')
@rejudge_bp.route('/admin/rejudge_time_range', methods=['POST'])
def rejudge_time_range():
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if _bulk_rejudge_task is None or _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    payload = request.get_json(silent=True) if request.is_json else request.form
    try:
        filters = normalize_rejudge_filters(payload)
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400

    submissions = get_filtered_rejudge_submissions(filters)
    try:
        if not consume_rejudge_confirmation(_rds, user["username"], filters, submissions, payload):
            return jsonify(
                success=True,
                **build_rejudge_preview(_rds, user["username"], filters, submissions),
            )
    except RejudgeConfirmationUnavailable as exc:
        current_app.logger.exception("批量重测确认存储不可用")
        return jsonify(success=False, message=str(exc)), 503

    batch_id = payload["confirmation_token"]
    progress_key = batch_progress_key(batch_id)
    job_submissions = [
        {"id": row["id"], "problem_type": row.get("problem_type"), "status": row.get("status")}
        for row in submissions
    ]
    try:
        _rds.hset(progress_key, mapping={"total": len(submissions), "done": 0, "scheduled": 0, "dispatch_status": "queued"})
        _bulk_rejudge_task.apply_async(args=[job_submissions, progress_key], queue="celery", task_id=batch_id)
    except Exception:
        current_app.logger.exception("批量重测任务投递失败")
        try:
            _rds.hset(progress_key, mapping={"dispatch_status": "failed", "error": "重测任务投递失败"})
        except Exception:
            current_app.logger.exception("批量重测任务投递失败后写入进度失败")
        return jsonify(success=False, message="重测任务投递失败，请重试"), 503
    try:
        _rds.set(LATEST_REJUDGE_BATCH_KEY, batch_id)
    except Exception:
        # 已成功投递的任务不能因兼容查询指针故障向前端伪装成失败。
        current_app.logger.exception("批量重测已投递，但最新批次指针写入失败")
    emit_audit(
        "submissions",
        action="bulk_rejudge",
        outcome="queued",
        message="已开始批量重测",
        actor={"id": user.get("id"), "name": user["username"], "is_admin": True},
        change={"filters": filters, "total": len(submissions)},
    )
    return jsonify(
        success=True,
        preview=False,
        message="已开始重测",
        total=len(submissions),
        batch_id=batch_id,
        progress_url=f"/api/admin/rejudge-ranges/status?batch_id={batch_id}",
    )


@rejudge_bp.get('/api/admin/rejudge-ranges/status')
@rejudge_bp.route('/admin/rejudge_time_range_status', methods=['GET'])
def rejudge_time_range_status():
    if not is_admin(current_user()):
        return jsonify(success=False, message="无权限"), 403

    if _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    try:
        progress_key = resolve_rejudge_progress_key(_rds, request.args.get("batch_id"))
    except ValueError as exc:
        return jsonify(success=False, message=str(exc)), 400

    if not _rds.exists(progress_key):
        return jsonify(success=False, message="当前没有进行中的重测")

    info = _rds.hgetall(progress_key)
    if info.get("dispatch_status") == "failed":
        response = jsonify(success=False, message=info.get("error") or "重测调度失败")
        response.headers["Cache-Control"] = "private, no-store"
        return response
    total = int(info.get("total", 0))
    done = int(info.get("done", 0))

    if total <= 0:
        return jsonify(success=False, message="总数异常")
    progress = int(done / total * 100)

    response = jsonify(success=True, progress=progress, done=done, total=total)
    response.headers["Cache-Control"] = "private, no-store"
    return response
