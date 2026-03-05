#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, session

from oj_modules.db_services import get_db_connection, get_user_by_username, update_submission_status


rejudge_bp = Blueprint('rejudge', __name__)

_rds = None
_evaluate_submission = None
_evaluate_submission_and_update_task = None


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    return user and user.get('is_admin') == 1


def init_rejudge_module(celery_app, redis_client, evaluate_submission_func):
    global _rds, _evaluate_submission, _evaluate_submission_and_update_task
    _rds = redis_client
    _evaluate_submission = evaluate_submission_func

    if _evaluate_submission_and_update_task is None:
        @celery_app.task(name='oj.rejudge.evaluate_submission_and_update')
        def evaluate_submission_and_update(submission_id, problem_id):
            _evaluate_submission(submission_id)
            key = f"rejudge:{problem_id}"
            _rds.hincrby(key, "done", 1)

        _evaluate_submission_and_update_task = evaluate_submission_and_update


def get_all_submissions_for_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id
                FROM submissions
                WHERE problem_id=%s
                ORDER BY id ASC
            """
            cursor.execute(sql, (problem_id,))
            return cursor.fetchall()
    finally:
        conn.close()


@rejudge_bp.route('/admin/rejudge_problem/<int:problem_id>', methods=['POST'])
def rejudge_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403

    if _evaluate_submission_and_update_task is None or _rds is None:
        return jsonify(success=False, message="重测模块未初始化"), 500

    submissions = get_all_submissions_for_problem(problem_id)
    if not submissions:
        return jsonify(success=False, message="该题暂无提交"), 400

    key = f"rejudge:{problem_id}"
    _rds.hset(key, mapping={"total": len(submissions), "done": 0})

    for sub in submissions:
        update_submission_status(sub["id"], "Pending")

    chain_tasks = None
    for sub in submissions:
        sid = sub["id"]
        task = _evaluate_submission_and_update_task.si(sid, problem_id)
        if chain_tasks is None:
            chain_tasks = task
        else:
            chain_tasks = chain_tasks | task

    if chain_tasks is not None:
        chain_tasks.apply_async()

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
