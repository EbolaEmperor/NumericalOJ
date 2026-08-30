#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
import json
from queue import Empty, Queue
from threading import Thread

from flask import (
    Blueprint,
    Response,
    copy_current_request_context,
    jsonify,
    request,
    stream_with_context,
)

from backend.oj_modules.ai.code_feedback import (
    generate_ai_code_marks_from_submission_context,
)
from backend.oj_modules.ai.client import resolve_llm_endpoint_snapshot
from backend.oj_modules.db_services import (
    get_cached_ai_code_marks_for_submission,
    get_submission_by_id,
    save_submission_ai_code_marks_json,
)
from backend.oj_modules.infrastructure.mysql import MySQLPoolExhausted
from backend.oj_modules.problems.context import build_problem_detail_context
from backend.oj_modules.repository.includes import (
    extract_includes_from_code,
    get_user_repository_files_by_names,
)
from backend.oj_modules.submissions.repository_snapshots import (
    resolve_submission_repository_user_id,
)
from backend.oj_modules.security.throttling import rate_limit_hit
from backend.oj_modules.shared.sse import (
    guard_sse_stream,
    sse_capacity_response,
    try_acquire_sse_slot,
)


ai_bp = Blueprint('ai', __name__)

# Redis 客户端（限流）。由 oj.py 的 init_ai_module 注入；为空时限流 fail-open。
_rds = None
# AI 标注是昂贵的 LLM 调用，按用户限流。
_MARKS_MAX_PER_WINDOW = 15
_MARKS_WINDOW = 300


class _AiRequestError(RuntimeError):
    """将批注请求的预检错误转换为稳定的 HTTP 响应。"""

    def __init__(self, message, status_code):
        super().__init__(message)
        self.message = str(message)
        self.status_code = int(status_code)


def _truthy(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def init_ai_module(redis_client):
    global _rds
    _rds = redis_client


from backend.oj_modules.security.auth import current_user, is_admin


def _load_accessible_problem(user, raw_problem_id):
    try:
        problem_id = int(raw_problem_id)
    except (TypeError, ValueError):
        return None, None, (jsonify(success=False, message="题目不存在"), 404)

    context, error_code = build_problem_detail_context(user, problem_id)
    if error_code == "not_found":
        return None, None, (jsonify(success=False, message="题目不存在"), 404)
    if error_code == "forbidden":
        return None, None, (jsonify(success=False, message="无权限访问该题目"), 403)
    return context["problem"], problem_id, None


def _prepare_ai_code_marks_request(data):
    """完成鉴权、限流和上下文准备；不会发起模型调用。"""

    if not isinstance(data, dict) or not data:
        raise _AiRequestError("缺少请求体", 400)
    unsupported_keys = sorted(set(data) - {"submission_id", "force_refresh"})
    if unsupported_keys:
        raise _AiRequestError(f"不支持的参数：{', '.join(unsupported_keys)}", 400)

    user = current_user()
    if not user:
        raise _AiRequestError("未登录", 401)

    sid = data.get('submission_id', '')
    submission = get_submission_by_id(sid)
    if not submission:
        raise _AiRequestError("提交记录不存在", 404)

    if submission['username'] != user['username'] and not is_admin(user):
        raise _AiRequestError("无权访问该提交", 403)

    problem, problem_id, error_response = _load_accessible_problem(user, submission.get('problem_id'))
    if error_response is not None:
        response, status_code = error_response
        payload = response.get_json(silent=True) or {}
        raise _AiRequestError(payload.get("message") or "无法访问题目", status_code)

    problem_content = problem.get('content') or ''
    if not problem_content:
        raise _AiRequestError("缺少题目内容", 400)

    user_code = str(submission.get('code') or '').replace('\r\n', '\n').replace('\r', '\n')
    if not user_code.strip():
        raise _AiRequestError("提交记录没有可标注的代码", 400)

    force_refresh = bool(data.get('force_refresh'))
    cached_result = None
    if not force_refresh:
        cached_result = get_cached_ai_code_marks_for_submission(submission)
        if cached_result:
            return {
                "sid": sid,
                "submission": submission,
                "problem_content": problem_content,
                "user_code": user_code,
                "test_points": submission.get("test_points") or [],
                "test_points_text": "",
                "repository_files": {},
                "cached_result": cached_result,
                "marks_endpoint": None,
                "image_endpoint": None,
            }

    # 仅在需要真正生成（缓存未命中或 force_refresh 绕过缓存）时限流，避免被反复刷生成昂贵标注。
    allowed, retry = rate_limit_hit(_rds, f"ai:marks:{user['username']}", _MARKS_MAX_PER_WINDOW, _MARKS_WINDOW)
    if not allowed:
        raise _AiRequestError(f"请求过于频繁，请 {retry} 秒后再试", 429)

    test_points = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in (submission.get("test_points") or [])])

    included_files = extract_includes_from_code(user_code)
    repository_files = {}
    if included_files:
        submission_owner_id = resolve_submission_repository_user_id(sid)
        repository_files = get_user_repository_files_by_names(
            submission_owner_id,
            included_files,
            submission_id=sid,
        )

    return {
        "sid": sid,
        "submission": submission,
        "problem_content": problem_content,
        "user_code": user_code,
        "test_points": submission.get("test_points") or [],
        "test_points_text": test_points,
        "repository_files": repository_files,
        "cached_result": None,
        "marks_endpoint": None,
        "image_endpoint": None,
    }


def _resolve_ai_code_marks_endpoints(prepared):
    if prepared["marks_endpoint"] is not None:
        return prepared["marks_endpoint"], prepared["image_endpoint"]

    marks_endpoint = resolve_llm_endpoint_snapshot(
        feature_key="ai_code_annotation",
        allowed_categories={"omni", "text"},
        purpose="AI 代码标注",
    )
    needs_image_analysis = any(
        _truthy((point or {}).get("has_output_image"))
        and str((point or {}).get("status") or "").strip().lower() != "accepted"
        for point in prepared["test_points"]
        if isinstance(point, dict)
    )
    image_endpoint = None
    if needs_image_analysis:
        image_endpoint = resolve_llm_endpoint_snapshot(
            feature_key="code_image_analysis",
            allowed_categories={"omni", "vision"},
            purpose="代码图片分析",
        )
    prepared["marks_endpoint"] = marks_endpoint
    prepared["image_endpoint"] = image_endpoint
    return marks_endpoint, image_endpoint


def _generate_prepared_ai_code_marks(
    prepared,
    *,
    timeout,
    on_text_delta=None,
    on_reasoning_delta=None,
):
    marks_endpoint, image_endpoint = _resolve_ai_code_marks_endpoints(prepared)
    result = generate_ai_code_marks_from_submission_context(
        problem_content=prepared["problem_content"],
        user_code=prepared["user_code"],
        test_points_text=prepared["test_points_text"],
        repository_files=prepared["repository_files"],
        submission_id=prepared["sid"],
        test_points=prepared["test_points"],
        max_issues=8,
        timeout=timeout,
        endpoint=marks_endpoint,
        image_endpoint=image_endpoint,
        on_text_delta=on_text_delta,
        on_reasoning_delta=on_reasoning_delta,
    )
    issues = result.get('issues') or []
    summary = str(result.get('summary') or '').strip()
    code_used = str(result.get('code_used') or prepared["user_code"])
    image_mismatch_analysis = str(result.get('image_mismatch_analysis') or '').strip()
    image_analysis_test_index = result.get('image_analysis_test_index')
    cache_payload = {
        "issues": issues,
        "summary": summary,
        "code_used": code_used,
        "image_mismatch_analysis": image_mismatch_analysis,
        "image_analysis_test_index": image_analysis_test_index,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": marks_endpoint.model,
    }
    save_submission_ai_code_marks_json(prepared["sid"], cache_payload)
    return {
        "success": True,
        "issues": issues,
        "summary": summary,
        "code_used": code_used,
        "image_mismatch_analysis": image_mismatch_analysis,
        "image_analysis_test_index": image_analysis_test_index,
        "source": "generated",
    }


def _sse_event(event_name, payload):
    body = json.dumps(payload or {}, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event_name}\ndata: {body}\n\n"


def _stream_prepared_ai_code_marks(prepared):
    yield _sse_event("ready", {"message": "已连接 AI 分析流"})
    if prepared["cached_result"]:
        yield _sse_event("result", {**prepared["cached_result"], "source": "cache"})
        yield _sse_event("done", {})
        return

    events = Queue()
    progress_state = {"sent": False}

    def on_reasoning_delta(delta):
        events.put(("reasoning", {"delta": str(delta)}))

    def on_text_delta(_delta):
        # 传入回调以强制启用上游 SSE；最终 JSON 不直接展示给用户，避免把
        # 尚未解析完成的协议内容当作“思考过程”渲染。
        if not progress_state["sent"]:
            progress_state["sent"] = True
            events.put(("progress", {"message": "模型已开始整理诊断结果"}))

    @copy_current_request_context
    def run_generation():
        try:
            result = _generate_prepared_ai_code_marks(
                prepared,
                timeout=None,
                on_text_delta=on_text_delta,
                on_reasoning_delta=on_reasoning_delta,
            )
            events.put(("result", result))
        except Exception as exc:
            events.put(("error", {"message": f"标注生成失败：{exc}"}))
        finally:
            events.put(("done", {}))

    worker = Thread(target=run_generation, name="ai-code-marks-stream", daemon=True)
    worker.start()

    while True:
        try:
            event_name, payload = events.get(timeout=10)
        except Empty:
            # 保活不仅覆盖首 token 慢的情况，也让 Gunicorn/反向代理知道上游仍在工作。
            yield _sse_event("heartbeat", {})
            continue
        yield _sse_event(event_name, payload)
        if event_name == "done":
            return


def _json_error_from_ai_request_error(error):
    return jsonify(success=False, message=error.message), error.status_code


@ai_bp.route('/ask_ai_code_marks', methods=['POST'])
def ask_ai_code_marks():
    try:
        prepared = _prepare_ai_code_marks_request(request.get_json())
        if prepared["cached_result"]:
            return jsonify(**prepared["cached_result"], source='cache')
        result = _generate_prepared_ai_code_marks(prepared, timeout=240)
        return jsonify(**result)
    except _AiRequestError as error:
        return _json_error_from_ai_request_error(error)
    except MySQLPoolExhausted:
        # 由应用级处理器返回统一的可重试 503，避免池背压被误报为 500。
        raise
    except Exception as e:
        return jsonify(success=False, message=f"标注生成失败：{str(e)}"), 500


@ai_bp.route('/ask_ai_code_marks_stream', methods=['POST'])
def ask_ai_code_marks_stream():
    try:
        prepared = _prepare_ai_code_marks_request(request.get_json())
    except _AiRequestError as error:
        return _json_error_from_ai_request_error(error)

    lease = try_acquire_sse_slot()
    if lease is None:
        return sse_capacity_response()

    response = Response(
        guard_sse_stream(
            stream_with_context(_stream_prepared_ai_code_marks(prepared)),
            lease,
        ),
        mimetype="text/event-stream",
    )
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response
