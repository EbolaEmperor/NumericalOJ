"""Authenticated HTTP adapter for editor semantic-token services."""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from oj_modules.auth_helpers import current_user, login_required
from oj_modules.clangd_services import get_clangd_service
from oj_modules.language_server_services import (
    LANGUAGE_SOURCE_MAX_BYTES,
    LanguageServiceBusyError,
    LanguageServiceError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
)
from oj_modules.octave_language_services import get_octave_language_service
from oj_modules.python_language_services import get_python_language_service
from oj_modules.security_utils import rate_limit_hit


editor_language_bp = Blueprint("editor_language", __name__)
_rds = None
_REQUEST_MAX_BYTES = LANGUAGE_SOURCE_MAX_BYTES * 6 + 16 * 1024
_TOKENS_MAX_PER_WINDOW = 240
_TOKENS_WINDOW_SECONDS = 60


def init_editor_language_module(redis_client) -> None:
    global _rds
    _rds = redis_client


def _error_response(error: Exception):
    if isinstance(error, LanguageServiceBusyError):
        response = jsonify(success=False, message=str(error))
        response.headers["Retry-After"] = "1"
        return response, 429
    if isinstance(error, LanguageServiceUnavailableError):
        return jsonify(success=False, message=str(error)), 503
    if isinstance(error, LanguageServiceTimeoutError):
        return jsonify(
            success=False,
            message=f"{error.service_name} 实时解析超时",
        ), 504
    if isinstance(error, LanguageServiceProtocolError):
        return jsonify(
            success=False,
            message=f"{error.service_name} 实时解析失败",
        ), 502
    return jsonify(success=False, message=str(error)), 400


def get_editor_language_service(language: str):
    if language in {"c", "cpp"}:
        return get_clangd_service(language)
    if language in {"py", "python"}:
        return get_python_language_service(language)
    if language in {"matlab", "octave"}:
        return get_octave_language_service(language)
    raise ValueError("该语言暂不支持结构化高亮")


@editor_language_bp.get("/api/editor/semantic-token-legend")
@login_required
def semantic_token_legend():
    language = str(request.args.get("language") or "cpp").lower()
    try:
        legend = get_editor_language_service(language).legend()
    except (LanguageServiceError, ValueError) as exc:
        return _error_response(exc)
    return jsonify(success=True, legend=legend)


@editor_language_bp.post("/api/editor/semantic-tokens")
@login_required
def semantic_tokens():
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
    language = str(payload.get("language") or "").lower()
    problem_id = payload.get("problem_id")
    if not isinstance(source, str):
        return jsonify(success=False, message="source 必须是字符串"), 400
    if not isinstance(problem_id, int) or isinstance(problem_id, bool) or problem_id <= 0:
        return jsonify(success=False, message="problem_id 无效"), 400
    user = current_user()
    assert user is not None
    user_id = user.get("id") or user.get("username")
    allowed, retry = rate_limit_hit(
        _rds,
        f"editor:semantic-tokens:{user_id}",
        _TOKENS_MAX_PER_WINDOW,
        _TOKENS_WINDOW_SECONDS,
    )
    if not allowed:
        return jsonify(
            success=False,
            message=f"实时解析请求过于频繁，请 {retry} 秒后再试",
        ), 429
    document_key = f"{user_id}:{problem_id}:{language}"
    try:
        result = get_editor_language_service(language).semantic_tokens(
            document_key, source
        )
    except (LanguageServiceError, ValueError) as exc:
        return _error_response(exc)
    return jsonify(success=True, **result)
