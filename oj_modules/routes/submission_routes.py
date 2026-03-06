#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import re

from flask import Blueprint, Response, jsonify, redirect, render_template, request, send_file, session, stream_with_context, url_for

from oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_latest_submission_code_by_user_and_problem,
    get_problem,
    get_submission_by_id,
    get_submission_status_snapshot,
    subscribe_submission_status_events,
    get_submission_summaries_by_user_and_problem_paginated,
    get_user_by_username,
)


submission_bp = Blueprint('submission', __name__)


def _strip_problem_title_tags(title):
    if title is None:
        return title
    original = str(title).strip()
    text = re.sub(r'\s*「[^」]{1,32}」\s*', ' ', original)
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else original


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

    page = max(1, request.args.get('page', 1, type=int))
    per_page = 30
    subs, total_pages = get_submission_summaries_by_user_and_problem_paginated(
        user['username'], problem_id, page=page, per_page=per_page
    )
    for sub in subs:
        sub['display_problem_title'] = _strip_problem_title_tags(sub.get('problem_title'))
        sub['is_ac'] = (sub.get('status') == 'Accepted')
    page_start = max(1, page - 8)
    page_end = min(total_pages, page + 8)
    page_numbers = list(range(page_start, page_end + 1))
    return render_template(
        'submission_list.html',
        problem_id=problem_id,
        user_submissions=subs,
        user=user,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
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

    snapshot = get_submission_status_snapshot(submission_id, prefer_cache=True)
    if not snapshot:
        return jsonify({'error': 'Submission not found'}), 404

    if snapshot.get('username') != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    is_judging = (
        snapshot.get('status') in ['Pending', 'Waiting', 'Running']
        or snapshot.get('score') is None
    )

    return jsonify({
        'status': snapshot.get('status'),
        'score': snapshot.get('score'),
        'is_judging': is_judging,
        'test_points_count': snapshot.get('test_points_count', 0),
        'test_points': snapshot.get('test_points', []),
        'last_updated': snapshot.get('last_updated', ''),
    })


@submission_bp.route('/submission_status_stream/<int:submission_id>')
def submission_status_stream(submission_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    initial_snapshot = get_submission_status_snapshot(submission_id, prefer_cache=True)
    if not initial_snapshot:
        return jsonify({'error': 'Submission not found'}), 404

    if initial_snapshot.get('username') != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    def _build_payload(snapshot):
        is_judging = (
            snapshot.get('status') in ['Pending', 'Waiting', 'Running']
            or snapshot.get('score') is None
        )
        return {
            'status': snapshot.get('status'),
            'score': snapshot.get('score'),
            'is_judging': is_judging,
            'test_points_count': snapshot.get('test_points_count', 0),
            'test_points': snapshot.get('test_points', []),
            'last_updated': snapshot.get('last_updated', ''),
        }

    def _encode_sse(event_name, payload):
        return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    @stream_with_context
    def generate():
        # 首帧立即推送
        first_payload = _build_payload(initial_snapshot)
        yield _encode_sse("status", first_payload)
        if not first_payload['is_judging']:
            yield _encode_sse("done", first_payload)
            return

        start_ts = time.time()
        pubsub = subscribe_submission_status_events(submission_id)
        if pubsub is None:
            # Redis 订阅不可用时，回退到慢轮询
            last_marker = (
                first_payload.get('status'),
                first_payload.get('score'),
                first_payload.get('test_points_count'),
                first_payload.get('last_updated'),
            )
            last_ping = start_ts
            while True:
                snapshot = get_submission_status_snapshot(submission_id, prefer_cache=True)
                if not snapshot:
                    yield _encode_sse("error", {"error": "Submission not found"})
                    return

                payload = _build_payload(snapshot)
                marker = (
                    payload.get('status'),
                    payload.get('score'),
                    payload.get('test_points_count'),
                    payload.get('last_updated'),
                )
                if marker != last_marker:
                    yield _encode_sse("status", payload)
                    last_marker = marker
                if not payload['is_judging']:
                    yield _encode_sse("done", payload)
                    return

                now = time.time()
                if now - start_ts > 360:
                    yield _encode_sse("timeout", payload)
                    return
                if now - last_ping > 15:
                    yield ": keepalive\n\n"
                    last_ping = now
                time.sleep(0.5)

        try:
            while True:
                msg = pubsub.get_message(timeout=15.0)
                now = time.time()
                if now - start_ts > 360:
                    latest = get_submission_status_snapshot(submission_id, prefer_cache=True) or initial_snapshot
                    yield _encode_sse("timeout", _build_payload(latest))
                    return

                if not msg:
                    # 心跳，维持连接
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

                payload = _build_payload(snapshot)
                yield _encode_sse("status", payload)
                if not payload['is_judging']:
                    yield _encode_sse("done", payload)
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


@submission_bp.route('/api/get_last_submission_code/<int:problem_id>')
def get_last_submission_code(problem_id):
    user = current_user()
    if not user:
        return jsonify({'success': False, 'message': '未登录'}), 401

    last_submission = get_latest_submission_code_by_user_and_problem(user['username'], problem_id)
    if not last_submission:
        return jsonify({'success': False, 'message': '没有找到之前的提交记录'}), 404

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
