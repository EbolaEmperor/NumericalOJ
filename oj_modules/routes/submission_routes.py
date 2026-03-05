#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from flask import Blueprint, jsonify, redirect, render_template, send_file, session, url_for

from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_problem,
    get_submission_by_id,
    get_submissions_by_user_and_problem,
    get_user_by_username,
)


submission_bp = Blueprint('submission', __name__)


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    return user and user.get('is_admin') == 1


@submission_bp.route('/submissionslist/<int:problem_id>')
def submission_list(problem_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    subs = get_submissions_by_user_and_problem(user['username'], problem_id)
    return render_template(
        'submission_list.html',
        problem_id=problem_id,
        user_submissions=subs,
        user=user,
    )


@submission_bp.route('/submission_detail/<int:submission_id>')
def submission_detail(submission_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    submission = get_submission_by_id(submission_id)
    if not submission:
        return "<h3>提交记录不存在</h3>"

    if submission['username'] != user['username'] and not is_admin(user):
        return "<h3>无权查看他人提交</h3>"

    problem = get_problem(submission['problem_id'])
    plang = (problem.get('lang') or 'matlab').lower()
    cached_ai_code_marks = None
    if submission.get('problem_type') == 1:
        cached_ai_code_marks = get_cached_ai_code_marks_for_submission(submission)
    if problem and problem['type'] == 2:
        file_path = f"uploads/{submission['username']}_{submission['problem_id']}_*"
        submission['file_url'] = file_path

    return render_template(
        'submission_detail.html',
        submission=submission,
        test_points=submission['test_points'],
        user=user,
        plang=plang,
        problem=problem,
        cached_ai_code_marks=cached_ai_code_marks,
    )


@submission_bp.route('/submission_status/<int:submission_id>')
def submission_status(submission_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404

    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    is_judging = (
        submission['status'] in ['Pending', 'Waiting', 'Running']
        or (submission['test_points'] and len(submission['test_points']) == 0)
        or submission['score'] is None
    )

    return jsonify({
        'status': submission['status'],
        'score': submission['score'],
        'is_judging': is_judging,
        'test_points_count': len(submission['test_points']) if submission['test_points'] else 0,
        'last_updated': submission.get('updated_at', submission.get('submit_time', '')),
    })


@submission_bp.route('/api/get_last_submission_code/<int:problem_id>')
def get_last_submission_code(problem_id):
    user = current_user()
    if not user:
        return jsonify({'success': False, 'message': '未登录'}), 401

    submissions = get_submissions_by_user_and_problem(user['username'], problem_id)
    if not submissions or len(submissions) == 0:
        return jsonify({'success': False, 'message': '没有找到之前的提交记录'}), 404

    last_submission = submissions[0]
    if not last_submission.get('code'):
        return jsonify({'success': False, 'message': '上一次提交没有代码'}), 404

    return jsonify({
        'success': True,
        'code': last_submission['code'],
        'submission_id': last_submission['id'],
        'score': last_submission['score'],
    })


@submission_bp.route('/submission_output_image/<int:submission_id>/<int:test_index>')
def get_submission_output_image(submission_id, test_index):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    submission = get_submission_by_id(submission_id)
    if not submission:
        return jsonify({'error': 'Submission not found'}), 404

    if submission['username'] != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    batch_sid = f"eoj-batch-{submission_id}"
    batch_image_filename = f"output_{test_index-1}.png"

    individual_sid = f"eoj-{submission_id}-{test_index}"
    individual_image_filename = "output.png"

    possible_paths = [
        f"/Users/wenchong/code/NumericalOJ/judger/{batch_sid}/{batch_image_filename}",
        f"./judger/{batch_sid}/{batch_image_filename}",
        f"/tmp/{batch_sid}/{batch_image_filename}",
        f"./{batch_sid}/{batch_image_filename}",
        f"~/oj/judger/{batch_sid}/{batch_image_filename}",
        f"/Users/wenchong/code/NumericalOJ/judger/{individual_sid}/{individual_image_filename}",
        f"./judger/{individual_sid}/{individual_image_filename}",
        f"/tmp/{individual_sid}/{individual_image_filename}",
        f"./{individual_sid}/{individual_image_filename}",
        f"~/oj/judger/{individual_sid}/{individual_image_filename}",
    ]

    for img_path in possible_paths:
        expanded_path = os.path.expanduser(img_path)
        if os.path.exists(expanded_path):
            return send_file(expanded_path, mimetype='image/png')

    return jsonify({'error': 'Output image not found'}), 404
