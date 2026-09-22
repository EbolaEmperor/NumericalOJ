#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging

from flask import Blueprint, flash, jsonify, request, send_file, session, url_for

from backend.oj_modules.db_services import (
    get_db_connection,
    get_problem,
    get_submission_by_id,
    get_user_by_username,
    update_submission_status,
)
from backend.oj_modules.submissions.grading import (
    get_file_path_for_submission,
    invalidate_previous_pending_submissions,
    update_submission_score_and_comment,
)
from backend.oj_modules.submissions.faithsieve import (
    finish_run,
    latest_submissions_for_problem,
    queue_runs,
    set_run_task_id,
)
from backend.oj_modules.problems.agent_launch import (
    AgentLaunchValidationError,
    normalize_launch_harness,
    resolve_launch_endpoint,
)
from backend.oj_modules.problems.agent_preferences import save_agent_launch_preference


grading_bp = Blueprint('grading', __name__)
logger = logging.getLogger(__name__)
_faithsieve_grading_task = None


from backend.oj_modules.security.auth import current_user, is_admin


def init_grading_routes(faithsieve_grading_task):
    global _faithsieve_grading_task
    _faithsieve_grading_task = faithsieve_grading_task


def _manual_written_problem(problem):
    return bool(
        problem
        and int(problem.get('type') or 0) == 2
        and int(problem.get('written_grading_mode') or 1) == 4
    )


def _faithsieve_runtime(user):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        raise AgentLaunchValidationError('请求参数格式无效')
    harness = normalize_launch_harness(payload.get('harness'))
    endpoint = resolve_launch_endpoint(
        harness, payload.get('endpoint_id'), include_secret=False,
    )
    save_agent_launch_preference(user['id'], harness, int(endpoint['id']))
    return harness, int(endpoint['id'])


def _enqueue_faithsieve(submissions, *, user, harness, endpoint_id):
    queued, skipped = queue_runs(
        submissions,
        requested_by=user['username'],
        harness=harness,
        endpoint_id=endpoint_id,
    )
    accepted = []
    failed = []
    for item in queued:
        try:
            result = _faithsieve_grading_task.apply_async(
                args=(item['attempt_id'],), queue='celery',
            )
            set_run_task_id(item['attempt_id'], result.id)
            accepted.append(item)
        except Exception as exc:
            logger.exception(
                'FaithSieve 控制任务入队失败',
                extra={'submission_id': item['submission_id']},
            )
            finish_run(item['attempt_id'], 'failed', f'任务入队失败：{exc}')
            failed.append(item['submission_id'])
    return accepted, skipped, failed


def _find_written_submission_pdf(submission, problem):
    if not submission or not problem:
        return None

    try:
        written_mode = int(problem.get('written_grading_mode') or 1)
    except Exception:
        written_mode = 1

    submission_id = submission.get('id')
    upload_dir = os.path.join('uploads', str(submission_id))
    if not submission_id or not os.path.isdir(upload_dir):
        return None

    if written_mode == 3:
        test_points = submission.get('test_points')
        source_filename = ""
        if isinstance(test_points, list) and test_points:
            source_filename = os.path.basename(str(test_points[0] or "").strip())
        if source_filename:
            source_base, _ = os.path.splitext(source_filename)
            if source_base:
                pdf_path = os.path.join(upload_dir, f"{source_base}.pdf")
                if os.path.isfile(pdf_path):
                    return pdf_path
        try:
            for name in sorted(os.listdir(upload_dir)):
                if str(name).lower().endswith('.pdf'):
                    path = os.path.join(upload_dir, name)
                    if os.path.isfile(path):
                        return path
        except Exception:
            return None
        return None

    file_path = get_file_path_for_submission(submission_id)
    if file_path and os.path.isfile(file_path):
        return file_path
    return None


@grading_bp.get('/api/submissions/<int:submission_id>/file')
@grading_bp.route('/download_submission_file/<int:submission_id>')
def download_submission_file(submission_id):
    user = current_user()
    if not user:
        return "请先登录", 401

    submission = get_submission_by_id(submission_id)
    if not submission:
        return "提交记录不存在", 404

    # 仅提交者本人或管理员可下载，防止越权枚举他人书面作业 PDF。
    if submission.get('username') != user['username'] and not is_admin(user):
        return "无权访问", 403

    if submission['problem_type'] != 2:
        return "不是书面作业题", 400

    problem = get_problem(submission.get('problem_id'))
    file_path = _find_written_submission_pdf(submission, problem)
    if not file_path or not os.path.exists(file_path):
        return "文件不存在", 404

    return send_file(
        os.path.abspath(file_path),
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f'submission_{submission_id}.pdf',
    )


@grading_bp.post('/api/admin/submissions/<int:submission_id>/grade')
@grading_bp.route('/submit_grading/<int:submission_id>', methods=['POST'])
def submit_grading(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限批改作业"), 403

    score = request.form.get('score', type=int)
    comment = request.form.get('comment', '').strip()

    if score is None or not (0 <= score <= 5):
        return jsonify(success=False, message="得分必须在 0 到 5 之间"), 400

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    update_submission_score_and_comment(submission_id, score, comment)

    new_status = 'Accepted' if score == 5 else 'Unaccepted'
    update_submission_status(submission_id, new_status)

    flash('批改结果提交成功', 'success')
    return jsonify(success=True, message="批改结果已提交")


@grading_bp.post('/api/admin/problems/<int:problem_id>/faithsieve')
def faithsieve_grade_problem(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限启动 FaithSieve'), 403
    if _faithsieve_grading_task is None:
        return jsonify(success=False, message='FaithSieve 任务未初始化'), 500
    problem = get_problem(problem_id)
    if not problem:
        return jsonify(success=False, message='题目不存在'), 404
    if not _manual_written_problem(problem):
        return jsonify(success=False, message='仅支持纯人工批改的书面题'), 400
    try:
        harness, endpoint_id = _faithsieve_runtime(user)
        submissions = latest_submissions_for_problem(problem_id)
        queued, skipped, failed = _enqueue_faithsieve(
            submissions,
            user=user,
            harness=harness,
            endpoint_id=endpoint_id,
        )
    except AgentLaunchValidationError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('创建 FaithSieve 批量任务失败', extra={'problem_id': problem_id})
        return jsonify(success=False, message='无法创建 FaithSieve 批量任务'), 500
    if failed:
        return jsonify(
            success=False,
            message=f'已加入 {len(queued)} 条，另有 {len(failed)} 条入队失败',
            queued=len(queued),
            skipped=len(skipped),
            failed=len(failed),
            submission_ids=[item['submission_id'] for item in queued],
        ), 500
    return jsonify(
        success=True,
        message=f'已加入 {len(queued)} 条 FaithSieve 评测',
        queued=len(queued),
        skipped=len(skipped),
        submission_ids=[item['submission_id'] for item in queued],
    )


@grading_bp.post('/api/admin/submissions/<int:submission_id>/faithsieve')
def faithsieve_grade_submission(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message='无权限启动 FaithSieve'), 403
    if _faithsieve_grading_task is None:
        return jsonify(success=False, message='FaithSieve 任务未初始化'), 500
    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message='提交记录不存在'), 404
    problem = get_problem(submission.get('problem_id'))
    if not _manual_written_problem(problem) or int(submission.get('problem_type') or 0) != 2:
        return jsonify(success=False, message='仅支持纯人工批改的书面题'), 400
    try:
        harness, endpoint_id = _faithsieve_runtime(user)
        queued, skipped, failed = _enqueue_faithsieve(
            [submission],
            user=user,
            harness=harness,
            endpoint_id=endpoint_id,
        )
    except AgentLaunchValidationError as exc:
        return jsonify(success=False, message=str(exc)), 400
    except Exception:
        logger.exception('创建 FaithSieve 单条任务失败', extra={'submission_id': submission_id})
        return jsonify(success=False, message='无法创建 FaithSieve 任务'), 500
    if failed:
        return jsonify(success=False, message='FaithSieve 任务入队失败'), 500
    if skipped:
        return jsonify(
            success=True,
            message='这条提交已有 FaithSieve 任务在排队或运行',
            queued=0,
            skipped=1,
        )
    return jsonify(
        success=True,
        message='已加入 FaithSieve 评测',
        queued=len(queued),
        skipped=0,
    )


@grading_bp.get('/api/admin/submissions/<int:submission_id>/next-pending')
@grading_bp.route('/get_next_pending_submission/<int:submission_id>', methods=['GET'])
def get_next_pending_submission(submission_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限查看待批改作业"), 403

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify(success=False, message="提交记录不存在"), 404

    problem_type = submission['problem_type']
    if problem_type == 2:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """
                    SELECT id
                    FROM submissions
                    WHERE status = 'Pending' AND problem_type = 2
                    AND id > %s
                    ORDER BY id ASC
                    LIMIT 1
                """
                cursor.execute(sql, (submission_id,))
                next_submission = cursor.fetchone()
                if next_submission:
                    next_submission_id = next_submission['id']
                    next_submission_url = url_for('submission.submission_detail', submission_id=next_submission_id)
                    return jsonify(
                        success=True,
                        next_submission_id=next_submission_id,
                        next_submission_url=next_submission_url,
                    )

            with conn.cursor() as cursor:
                sql = """
                    SELECT id
                    FROM submissions
                    WHERE status = 'Pending' AND problem_type = 2
                    ORDER BY id ASC
                    LIMIT 1
                """
                cursor.execute(sql)
                next_submission = cursor.fetchone()
                if next_submission:
                    next_submission_id = next_submission['id']
                    next_submission_url = url_for('submission.submission_detail', submission_id=next_submission_id)
                    return jsonify(
                        success=True,
                        next_submission_id=next_submission_id,
                        next_submission_url=next_submission_url,
                    )
        finally:
            conn.close()

    flash("已全部批改完成", 'success')
    return jsonify(success=False, message="无待批改的书面作业")


@grading_bp.post('/api/admin/problems/<int:problem_id>/invalidate-submissions')
@grading_bp.route('/invalidate_invalid_submissions/<int:problem_id>', methods=['POST'])
def invalidate_invalid_submissions(problem_id):
    user = current_user()
    if not is_admin(user):
        return jsonify(success=False, message="无权限"), 403
    try:
        invalidate_previous_pending_submissions(problem_id)
        return jsonify(success=True, message="无效提交已移除")
    except Exception as e:
        return jsonify(success=False, message=f"错误: {str(e)}"), 500
