#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import re
import html

import markdown

from flask import Blueprint, Response, jsonify, redirect, render_template, request, send_file, session, stream_with_context, url_for

from oj_modules import judger_core

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
_EXACT_DOUBLE_BACKSLASH_PATTERN = re.compile(r'(?<!\\)\\\\(?!\\)')


def _strip_problem_title_tags(title):
    if title is None:
        return title
    original = str(title).strip()
    text = re.sub(r'\s*「[^」]{1,32}」\s*', ' ', original)
    text = re.sub(r'\s+', ' ', text).strip()
    return text if text else original


from oj_modules.auth_helpers import current_user, is_admin


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


def _read_text_file_safe(path, max_chars=200000):
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return (f.read() or "")[:max_chars]
    except Exception:
        return ""


def _normalize_transcribed_backslashes_for_mathjax(text):
    """
    只把“恰好两个反斜杠”替换为“四个反斜杠”。
    已经是四个及以上连续反斜杠的片段保持不变。
    """
    raw = str(text or "")
    if not raw:
        return ""
    return _EXACT_DOUBLE_BACKSLASH_PATTERN.sub(r"\\\\\\\\", raw)


def _render_written_markdown_to_html(markdown_text):
    raw_text = str(markdown_text or "")
    if not raw_text.strip():
        return ""

    # 转写内容来自用户上传文件，先转义原始 HTML 再解析 Markdown，避免注入。
    escaped_text = html.escape(raw_text, quote=False)
    try:
        rendered = markdown.markdown(
            escaped_text,
            extensions=['extra', 'fenced_code', 'tables', 'sane_lists'],
        )
    except Exception:
        return escaped_text.replace("\n", "<br>")

    # 限制危险链接协议。
    rendered = re.sub(
        r'(?i)\s(href|src)\s*=\s*([\'"])\s*(javascript:|vbscript:|data:)',
        r' \1=\2#',
        rendered,
    )
    return rendered


def _load_written_submission_latex_and_error(submission):
    if not submission or int(submission.get("problem_type") or 0) != 2:
        return "", ""

    sid = submission.get("id")
    if not sid:
        return "", ""

    upload_dir = os.path.join("uploads", str(sid))
    if not os.path.isdir(upload_dir):
        return "", ""

    test_points = submission.get("test_points")
    source_filename = ""
    if isinstance(test_points, list) and test_points:
        source_filename = os.path.basename(str(test_points[0] or "").strip())

    latex_candidates = []
    err_candidates = []
    if source_filename:
        base_name, _ = os.path.splitext(source_filename)
        if base_name:
            latex_candidates.append(os.path.join(upload_dir, f"{base_name}.md"))
            latex_candidates.append(os.path.join(upload_dir, f"{base_name}.tex"))
            err_candidates.append(os.path.join(upload_dir, f"{base_name}_latex_error.txt"))

    try:
        for name in sorted(os.listdir(upload_dir)):
            lower = name.lower()
            abs_path = os.path.join(upload_dir, name)
            if lower.endswith(".md") or lower.endswith(".tex"):
                latex_candidates.append(abs_path)
            elif lower.endswith("_latex_error.txt"):
                err_candidates.append(abs_path)
    except Exception:
        pass

    latex_text = ""
    seen_latex = set()
    for path in latex_candidates:
        if path in seen_latex:
            continue
        seen_latex.add(path)
        latex_text = _read_text_file_safe(path)
        if latex_text.strip():
            break
    latex_text = _normalize_transcribed_backslashes_for_mathjax(latex_text)

    error_text = ""
    seen_err = set()
    for path in err_candidates:
        if path in seen_err:
            continue
        seen_err.add(path)
        error_text = _read_text_file_safe(path, max_chars=12000)
        if error_text.strip():
            break

    return latex_text, error_text


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
        'submissions/list.html',
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

    embed_raw = str(request.args.get('embed') or request.args.get('embedded') or '').strip().lower()
    embedded = embed_raw in ('1', 'true', 'yes', 'on')

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
    submission_latex_text = ""
    submission_latex_error = ""
    submission_latex_html = ""
    written_grading_mode = 1
    if problem and problem['type'] == 2:
        try:
            written_grading_mode = int(problem.get('written_grading_mode') or 1)
        except Exception:
            written_grading_mode = 1
        file_path = f"uploads/{submission['username']}_{submission['problem_id']}_*"
        submission['file_url'] = file_path
        if written_grading_mode == 1:
            submission_latex_text, submission_latex_error = _load_written_submission_latex_and_error(submission)
            submission_latex_html = _render_written_markdown_to_html(submission_latex_text)

    return render_template(
        'submissions/detail.html',
        submission=submission,
        test_points=submission['test_points'],
        user=user,
        embedded=embedded,
        layout_template='layouts/embedded.html' if embedded else 'layouts/site.html',
        plang=plang,
        problem=problem,
        cached_ai_code_marks=cached_ai_code_marks,
        submission_latex_text=submission_latex_text,
        submission_latex_error=submission_latex_error,
        submission_latex_html=submission_latex_html,
        written_grading_mode=written_grading_mode,
    )


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


@submission_bp.route('/submission_status_stream/<int:submission_id>')
def submission_status_stream(submission_id):
    user = current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

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
        if os.path.exists(expanded_path):
            # 用真实文件名（含正确扩展名，如 .bmp）作为下载名，并让 Flask 按扩展名
            # 推断 Content-Type，保证 bmp 等非 png 格式也能正确显示/下载。
            download_name = f"submission_{submission_id}_test_{test_index}" \
                + os.path.splitext(expanded_path)[1]
            return send_file(expanded_path, download_name=download_name)

    return jsonify({'error': 'Output image not found'}), 404
