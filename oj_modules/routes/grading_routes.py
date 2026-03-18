#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from flask import Blueprint, flash, jsonify, request, send_file, session, url_for

from oj_modules.db_services import (
    get_db_connection,
    get_problem,
    get_submission_by_id,
    get_user_by_username,
    update_submission_status,
)
from oj_modules.grading_services import (
    get_file_path_for_submission,
    invalidate_previous_pending_submissions,
    update_submission_score_and_comment,
)


grading_bp = Blueprint('grading', __name__)


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    return user and user.get('is_admin') == 1


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


@grading_bp.route('/download_submission_file/<int:submission_id>')
def download_submission_file(submission_id):
    submission = get_submission_by_id(submission_id)
    if not submission:
        return "提交记录不存在", 404

    if submission['problem_type'] != 2:
        return "不是书面作业题", 400

    problem = get_problem(submission.get('problem_id'))
    file_path = _find_written_submission_pdf(submission, problem)
    if not file_path or not os.path.exists(file_path):
        return "文件不存在", 404

    return send_file(
        file_path,
        mimetype='application/pdf',
        as_attachment=False,
        download_name=f'submission_{submission_id}.pdf',
    )


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
                    return jsonify(success=True, next_submission_url=next_submission_url)

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
                    return jsonify(success=True, next_submission_url=next_submission_url)
        finally:
            conn.close()

    flash("已全部批改完成", 'success')
    return jsonify(success=False, message="无待批改的书面作业")


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
