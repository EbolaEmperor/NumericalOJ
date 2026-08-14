"""Authenticated Lean 4 goal-state endpoint."""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from oj_modules.editor.language_server import (
    LanguageServiceBusyError,
    LanguageServiceError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
)
from oj_modules.editor.lean import (
    LEAN_SOURCE_MAX_BYTES,
    get_lean_interactive_service,
)
from oj_modules.security.auth import current_user, login_required
from oj_modules.security.throttling import rate_limit_hit


lean_bp = Blueprint("lean", __name__)
_rds = None
_REQUEST_MAX_BYTES = LEAN_SOURCE_MAX_BYTES + 16 * 1024
_CHECKS_MAX_PER_WINDOW = 240
_CHECKS_WINDOW_SECONDS = 60


def init_lean_module(redis_client) -> None:
    global _rds
    _rds = redis_client


def _error_response(error: Exception):
    if isinstance(error, LanguageServiceBusyError):
        response = jsonify(
            success=False,
            code="service_busy",
            message=str(error),
        )
        response.headers["Retry-After"] = "1"
        return response, 429
    if isinstance(error, LanguageServiceUnavailableError):
        return jsonify(
            success=False,
            code="service_unavailable",
            message=str(error),
        ), 503
    if isinstance(error, LanguageServiceTimeoutError):
        return jsonify(
            success=False,
            code="service_timeout",
            message="Lean 4 实时解析超时",
        ), 504
    if isinstance(error, LanguageServiceProtocolError):
        return jsonify(
            success=False,
            code="service_protocol_error",
            message="Lean 4 实时解析失败",
        ), 502
    return jsonify(
        success=False,
        code="invalid_lean_request",
        message=str(error),
    ), 400


@lean_bp.post("/api/lean/check")
@login_required
def check_lean_source():
    request.max_content_length = _REQUEST_MAX_BYTES
    if (
        request.content_length is not None
        and request.content_length > _REQUEST_MAX_BYTES
    ):
        return jsonify(success=False, message="请求体过大"), 413
    try:
        payload = request.get_json(silent=True)
    except RequestEntityTooLarge:
        return jsonify(success=False, message="请求体过大"), 413
    if not isinstance(payload, dict):
        return jsonify(success=False, message="请求体必须是 JSON 对象"), 400

    source = payload.get("source")
    problem_id = payload.get("problem_id")
    client_version = payload.get("version")
    position = payload.get("position")
    if not isinstance(source, str):
        return jsonify(success=False, message="source 必须是字符串"), 400
    if (
        not isinstance(problem_id, int)
        or isinstance(problem_id, bool)
        or problem_id <= 0
    ):
        return jsonify(success=False, message="problem_id 无效"), 400
    if not isinstance(client_version, int) or isinstance(client_version, bool):
        return jsonify(success=False, message="version 无效"), 400
    if not isinstance(position, dict):
        return jsonify(success=False, message="position 无效"), 400
    line = position.get("line")
    character = position.get("character")
    if (
        not isinstance(line, int)
        or isinstance(line, bool)
        or line < 0
        or not isinstance(character, int)
        or isinstance(character, bool)
        or character < 0
    ):
        return jsonify(success=False, message="position 无效"), 400

    user = current_user()
    assert user is not None
    user_id = user.get("id") or user.get("username")
    allowed, retry = rate_limit_hit(
        _rds,
        f"editor:lean-check:{user_id}",
        _CHECKS_MAX_PER_WINDOW,
        _CHECKS_WINDOW_SECONDS,
    )
    if not allowed:
        return jsonify(
            success=False,
            code="rate_limited",
            message=f"Lean 4 实时解析请求过于频繁，请 {retry} 秒后再试",
        ), 429

    try:
        result = get_lean_interactive_service().check(
            f"{user_id}:{problem_id}",
            source,
            {"line": line, "character": character},
        )
    except (LanguageServiceError, ValueError) as exc:
        return _error_response(exc)

    diagnostics = result["diagnostics"]
    error_count = sum(
        1 for diagnostic in diagnostics if diagnostic.get("severity", 1) == 1
    )
    if error_count:
        message = f"发现 {error_count} 个错误"
    elif result["goals"]:
        message = f"光标处有 {len(result['goals'])} 个证明目标"
    elif result["goal_rendered"]:
        message = result["goal_rendered"]
    else:
        message = "光标处没有证明目标"
    return jsonify(
        success=True,
        version=client_version,
        goals=result["goals"],
        goal_rendered=result["goal_rendered"],
        diagnostics=diagnostics,
        processing=result["processing"],
        document_version=result["document_version"],
        semantic_tokens=result["semantic_tokens"],
        message=message,
    )
