#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time

from flask import Blueprint, Response, jsonify, redirect, request, send_file, session, stream_with_context, url_for

from backend.oj_modules.judging import core as judger_core

from backend.oj_modules.db_services import (
    get_latest_submission_code_by_user_and_problem,
    get_problem,
    get_submission_by_id,
    get_submission_status_snapshot,
    subscribe_submission_status_events,
    get_user_by_username,
)
from backend.oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from backend.oj_modules.problems.lean_workspace import (
    get_latest_submission_lean_workspace,
)
from backend.oj_modules.submissions.presentation import (
    load_written_submission_latex_and_error as _load_written_submission_latex_and_error,
    render_written_markdown_to_html as _render_written_markdown_to_html,
    summarize_panel_test_points as _summarize_panel_test_points,
)
from backend.oj_modules.shared.sse import (
    guard_sse_stream,
    sse_capacity_response,
    try_acquire_sse_slot,
)


submission_bp = Blueprint('submission', __name__)


from backend.oj_modules.security.auth import current_user, is_admin


def _get_authorized_submission_snapshot(submission_id, user):
    """缓存身份不匹配时回源一次，避免改名后的旧快照误拒绝。"""
    snapshot = get_submission_status_snapshot(submission_id, prefer_cache=True)
    if (
        snapshot
        and snapshot.get('username') != user['username']
        and not is_admin(user)
    ):
        snapshot = get_submission_status_snapshot(submission_id, prefer_cache=False)
    return snapshot


@submission_bp.route('/submission_detail/<int:submission_id>')
def submission_detail(submission_id):
    return redirect(f'/submissions/{submission_id}')


@submission_bp.get('/api/submissions/<int:submission_id>/status')
@submission_bp.route('/submission_status/<int:submission_id>')
def submission_status(submission_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    snapshot = _get_authorized_submission_snapshot(submission_id, user)
    if not snapshot:
        return jsonify({'error': 'Submission not found'}), 404

    if snapshot.get('username') != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    is_judging = (
        snapshot.get('status') in ['Pending', 'Waiting', 'Running', 'Generating']
        or snapshot.get('score') is None
    )
    promptly_review_reply = str(
        snapshot.get('promptly_review_reply') or snapshot.get('prompt_generation_error') or ''
    ).strip()

    return jsonify({
        'status': snapshot.get('status'),
        'score': snapshot.get('score'),
        'is_judging': is_judging,
        'generated_from_prompt': bool(snapshot.get('generated_from_prompt')),
        'prompt_generation_error': promptly_review_reply,
        'promptly_review_reply': promptly_review_reply,
        'test_points_count': snapshot.get('test_points_count', 0),
        'test_points': snapshot.get('test_points', []),
        'last_updated': snapshot.get('last_updated', ''),
    })


@submission_bp.get('/api/submissions/<int:submission_id>/events')
@submission_bp.route('/submission_status_stream/<int:submission_id>')
def submission_status_stream(submission_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    panel_view = str(request.args.get('view') or '').strip().lower() == 'panel'
    initial_snapshot = _get_authorized_submission_snapshot(submission_id, user)
    if not initial_snapshot:
        return jsonify({'error': 'Submission not found'}), 404

    if initial_snapshot.get('username') != user['username'] and not is_admin(user):
        return jsonify({'error': 'Access denied'}), 403

    def _build_payload(snapshot):
        is_judging = (
            snapshot.get('status') in ['Pending', 'Waiting', 'Running', 'Generating']
            or snapshot.get('score') is None
        )
        if panel_view:
            test_points = _summarize_panel_test_points(
                snapshot.get('test_points')
            )
            return {
                'submission_id': snapshot.get('id'),
                'status': snapshot.get('status'),
                'score': snapshot.get('score'),
                'is_judging': is_judging,
                'test_points_count': len(test_points),
                'test_points': test_points,
                'last_updated': snapshot.get('last_updated', ''),
            }

        payload = {
            'submission_id': snapshot.get('id'),
            'problem_type': snapshot.get('problem_type'),
            'status': snapshot.get('status'),
            'score': snapshot.get('score'),
            'is_judging': is_judging,
            'generated_from_prompt': bool(snapshot.get('generated_from_prompt')),
            'prompt_generation_error': str(
                snapshot.get('promptly_review_reply') or snapshot.get('prompt_generation_error') or ''
            ).strip(),
            'test_points_count': snapshot.get('test_points_count', 0),
            'test_points': snapshot.get('test_points', []),
            'last_updated': snapshot.get('last_updated', ''),
        }
        payload['promptly_review_reply'] = payload['prompt_generation_error']
        if int(snapshot.get('problem_type') or 0) == 2:
            sid = snapshot.get('id')
            row = get_submission_by_id(sid) if sid else None
            if row:
                problem = get_problem(row.get('problem_id'))
                written_mode = 1
                if problem:
                    try:
                        written_mode = int(problem.get('written_grading_mode') or 1)
                    except Exception:
                        written_mode = 1
                payload['written_grading_mode'] = written_mode
                if written_mode == 1:
                    latex_text, latex_error = _load_written_submission_latex_and_error(row)
                    payload['written_latex_text'] = latex_text
                    payload['written_latex_html'] = _render_written_markdown_to_html(latex_text)
                    payload['written_latex_error'] = latex_error
                payload['written_comment'] = str(row.get('code') or '')
        return payload

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

    lease = try_acquire_sse_slot()
    if lease is None:
        return sse_capacity_response()

    return Response(
        guard_sse_stream(generate(), lease),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
        },
    )


@submission_bp.route('/api/problems/<int:problem_id>/last-submission-code')
@submission_bp.route('/api/get_last_submission_code/<int:problem_id>')
def get_last_submission_code(problem_id):
    user = current_user()
    if not user:
        return jsonify({'success': False, 'message': '未登录'}), 401

    last_submission = get_latest_submission_code_by_user_and_problem(user['username'], problem_id)
    if not last_submission:
        return jsonify({'success': False, 'message': '没有找到之前的提交记录'}), 404

    problem = get_problem(problem_id)
    is_lean4 = bool(
        problem
        and str(problem.get('lang') or '').strip().lower() in {'lean', 'lean4'}
    )
    workspace = None
    if is_lean4:
        workspace = get_latest_submission_lean_workspace(
            username=user['username'], problem_id=problem_id
        )
    if not workspace and not last_submission.get('code'):
        return jsonify({'success': False, 'message': '上一次提交没有代码'}), 404

    payload = {
        'success': True,
        'code': last_submission.get('code') or '',
        'submission_id': last_submission['id'],
        'score': last_submission['score'],
    }
    if workspace:
        payload['revision'] = workspace['revision']
        payload['files'] = workspace['submitted_files']
        payload['default_file'] = workspace['default_file']
    return jsonify(payload)


@submission_bp.get('/api/submissions/<int:submission_id>/outputs/<int:test_index>/image')
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

    preferred_filenames = []
    test_points = submission.get('test_points') if isinstance(submission.get('test_points'), list) else []
    if test_points and 0 <= test_index - 1 < len(test_points):
        tp = test_points[test_index - 1] or {}
        preferred_name = os.path.basename(str(tp.get('output_image_filename') or '').strip())
        if preferred_name:
            preferred_filenames.append(preferred_name)
    preferred_filenames.extend([
        f"output_{test_index - 1}.png",
        f"output_{test_index - 1}.jpg",
        f"output_{test_index - 1}.jpeg",
        f"output_{test_index - 1}.webp",
        f"output_{test_index - 1}.bmp",
        "output.png",
        "output.jpg",
        "output.jpeg",
        "output.webp",
        "output.bmp",
    ])

    batch_sid = f"eoj-batch-{submission_id}"
    individual_sid = f"eoj-{submission_id}-{test_index}"
    # The judger writes run dirs under JUDGER_RUN_ROOT (judger_core.run_dir_for);
    # that is where the captured output image actually lives. Resolve it via the
    # same source of truth the judging side uses, so this route stays correct if
    # JUDGER_RUN_ROOT is overridden. The remaining dirs are legacy fallbacks.
    legacy_base_dirs = [
        "./judger",
        "/tmp",
        ".",
        "~/oj/judger",
    ]
    possible_paths = []
    seen_names = set()
    for filename in preferred_filenames:
        clean_name = str(filename or "").strip()
        if not clean_name or clean_name in seen_names:
            continue
        seen_names.add(clean_name)
        for sid in (batch_sid, individual_sid):
            possible_paths.append(os.path.join(judger_core.run_dir_for(sid), clean_name))
            for base_dir in legacy_base_dirs:
                possible_paths.append(os.path.join(base_dir, sid, clean_name))

    for img_path in possible_paths:
        expanded_path = os.path.expanduser(img_path)
        try:
            image_file = judger_core.open_safe_regular_artifact(expanded_path)
        except Exception:
            continue
        # 用真实文件名（含正确扩展名，如 .bmp）作为下载名，并让 Flask 按扩展名
        # 推断 Content-Type。传入已用 O_NOFOLLOW 固定的 fd，避免检查后替换竞态。
        download_name = f"submission_{submission_id}_test_{test_index}" \
            + os.path.splitext(expanded_path)[1]
        try:
            response = send_file(image_file, download_name=download_name)
        except Exception:
            image_file.close()
            continue
        response.call_on_close(image_file.close)
        return response

    return jsonify({'error': 'Output image not found'}), 404
