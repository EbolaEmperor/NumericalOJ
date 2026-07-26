"""Authenticated HTTP adapter for editor semantic-token services."""

from __future__ import annotations

import hashlib
import re
import threading

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from oj_modules.auth_helpers import current_user, login_required
from oj_modules.clangd_services import (
    get_clangd_service,
    get_repository_clangd_service,
)
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
from oj_modules.repository import tree as repository_tree
from oj_modules.repository.language import (
    capture_repository_semantic_snapshot,
    ensure_repository_semantic_target_current,
    get_repository_semantic_target,
)
from oj_modules.security_utils import rate_limit_hit
from oj_modules.semantic_token_cache import SemanticTokenResultCache


editor_language_bp = Blueprint("editor_language", __name__)
_rds = None
_REQUEST_MAX_BYTES = LANGUAGE_SOURCE_MAX_BYTES * 6 + 16 * 1024
_TOKENS_MAX_PER_WINDOW = 240
_TOKENS_WINDOW_SECONDS = 60
_MARKDOWN_SEMANTIC_CONTEXT = "markdown"
_GENERIC_EDITOR_DOCUMENT_ID_RE = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z"
)
_MARKDOWN_CPP_PREAMBLE = "#include <bits/stdc++.h>\n"
_MARKDOWN_CACHE_KEY_VERSION = b"markdown-cpp-bits-v2-tokens-12000\0"
_MARKDOWN_SOURCE_MAX_BYTES = 512 * 1024
_MARKDOWN_MAX_TOKENS = 12_000
_markdown_semantic_cache = SemanticTokenResultCache()
_semantic_legend_cache: dict[str, dict[str, list[str]]] = {}
_semantic_legend_inflight: set[str] = set()
_semantic_legend_lock = threading.Lock()


def init_editor_language_module(redis_client) -> None:
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
            message=f"{error.service_name} 实时解析超时",
        ), 504
    if isinstance(error, LanguageServiceProtocolError):
        return jsonify(
            success=False,
            code="service_protocol_error",
            message=f"{error.service_name} 实时解析失败",
        ), 502
    return jsonify(
        success=False,
        code="invalid_language_request",
        message=str(error),
    ), 400


def get_editor_language_service(language: str):
    if language in {"c", "cpp"}:
        return get_clangd_service(language)
    if language in {"py", "python"}:
        return get_python_language_service(language)
    if language in {"matlab", "octave"}:
        return get_octave_language_service(language)
    raise ValueError("该语言暂不支持结构化高亮")


def _without_semantic_prefix_lines(data: list[int], prefix_lines: int) -> list[int]:
    """删除虚拟前导行，并重新编码 LSP delta token 坐标。"""
    absolute_tokens: list[tuple[int, int, int, int, int]] = []
    line = 0
    start = 0
    for index in range(0, len(data), 5):
        delta_line, delta_start, length, token_type, modifiers = data[
            index : index + 5
        ]
        line += delta_line
        start = delta_start if delta_line else start + delta_start
        if line < prefix_lines:
            continue
        absolute_tokens.append(
            (line - prefix_lines, start, length, token_type, modifiers)
        )

    encoded: list[int] = []
    previous_line = 0
    previous_start = 0
    for line, start, length, token_type, modifiers in absolute_tokens:
        delta_line = line - previous_line
        delta_start = start if delta_line else start - previous_start
        encoded.extend((delta_line, delta_start, length, token_type, modifiers))
        previous_line = line
        previous_start = start
    return encoded


def _markdown_cache_key(source: str) -> str:
    digest = hashlib.sha256()
    digest.update(_MARKDOWN_CACHE_KEY_VERSION)
    digest.update(source.encode("utf-8"))
    return digest.hexdigest()


def _markdown_result_pending_response():
    response = jsonify(
        success=False,
        code="result_pending",
        message="相同 C++ 代码正在解析，请稍后重试",
    )
    response.headers["Retry-After"] = "1"
    return response, 429


def _legend_cache_claim(
    language: str,
) -> tuple[str, dict[str, list[str]] | None]:
    with _semantic_legend_lock:
        cached = _semantic_legend_cache.get(language)
        if cached is not None:
            return "hit", {
                "tokenTypes": list(cached["tokenTypes"]),
                "tokenModifiers": list(cached["tokenModifiers"]),
            }
        if language in _semantic_legend_inflight:
            return "pending", None
        _semantic_legend_inflight.add(language)
        return "owner", None


def _legend_cache_publish(
    language: str,
    legend: dict[str, list[str]] | None,
) -> None:
    with _semantic_legend_lock:
        _semantic_legend_inflight.discard(language)
        if legend is not None:
            _semantic_legend_cache[language] = {
                "tokenTypes": list(legend["tokenTypes"]),
                "tokenModifiers": list(legend["tokenModifiers"]),
            }


@editor_language_bp.get("/api/editor/semantic-token-legend")
@login_required
def semantic_token_legend():
    language = str(request.args.get("language") or "cpp").lower()
    cache_state, cached = _legend_cache_claim(language)
    if cache_state == "hit":
        return jsonify(success=True, legend=cached)
    if cache_state == "pending":
        response = jsonify(
            success=False,
            code="legend_pending",
            message="语言语义图例正在初始化，请稍后重试",
        )
        response.headers["Retry-After"] = "1"
        return response, 429
    try:
        legend = get_editor_language_service(language).legend()
    except (LanguageServiceError, ValueError) as exc:
        _legend_cache_publish(language, None)
        return _error_response(exc)
    except Exception:
        _legend_cache_publish(language, None)
        raise
    _legend_cache_publish(language, legend)
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
    semantic_context = payload.get("context")
    document_id = payload.get("document_id")
    repository_entry_id = payload.get("repository_entry_id")
    if not isinstance(source, str):
        return jsonify(success=False, message="source 必须是字符串"), 400
    markdown_request = semantic_context == _MARKDOWN_SEMANTIC_CONTEXT
    repository_request = semantic_context == "repository"
    generic_editor_request = semantic_context == "problem-form"
    if markdown_request:
        if (
            problem_id is not None
            or document_id is not None
            or repository_entry_id is not None
            or language != "cpp"
        ):
            return jsonify(success=False, message="Markdown 语义请求无效"), 400
        if len(source.encode("utf-8")) > _MARKDOWN_SOURCE_MAX_BYTES:
            return jsonify(
                success=False,
                code="source_too_large",
                message="Markdown C++ 代码块超过结构化高亮大小限制",
            ), 413
    elif repository_request:
        if problem_id is not None or document_id is not None:
            return jsonify(success=False, message="仓库语义请求无效"), 400
        if (
            not isinstance(repository_entry_id, int)
            or isinstance(repository_entry_id, bool)
            or repository_entry_id <= 0
        ):
            return jsonify(
                success=False,
                message="repository_entry_id 无效",
            ), 400
    elif generic_editor_request:
        if problem_id is not None or repository_entry_id is not None:
            return jsonify(success=False, message="编辑器语义请求无效"), 400
        if (
            not isinstance(document_id, str)
            or _GENERIC_EDITOR_DOCUMENT_ID_RE.fullmatch(document_id) is None
        ):
            return jsonify(success=False, message="document_id 无效"), 400
    else:
        if semantic_context is not None:
            return jsonify(success=False, message="语义请求 context 无效"), 400
        if document_id is not None or repository_entry_id is not None:
            return jsonify(success=False, message="document_id 无效"), 400
        if (
            not isinstance(problem_id, int)
            or isinstance(problem_id, bool)
            or problem_id <= 0
        ):
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
            code="rate_limited",
            message=f"实时解析请求过于频繁，请 {retry} 秒后再试",
        ), 429
    markdown_cache_key = None
    if markdown_request:
        markdown_cache_key = _markdown_cache_key(source)
        cache_claim = _markdown_semantic_cache.claim(markdown_cache_key)
        if cache_claim.state == "hit":
            assert cache_claim.result is not None
            return jsonify(success=True, **cache_claim.result)
        if cache_claim.state == "pending":
            return _markdown_result_pending_response()
        document_key = f"{user_id}:markdown:{language}"
        analysis_source = _MARKDOWN_CPP_PREAMBLE + source
    elif generic_editor_request:
        document_key = (
            f"{user_id}:editor:{semantic_context}:{document_id}:{language}"
        )
        analysis_source = source
    elif repository_request:
        document_key = None
        analysis_source = source
    else:
        document_key = f"{user_id}:{problem_id}:{language}"
        analysis_source = source
    try:
        if repository_request:
            numeric_user_id = user.get("id")
            if (
                not isinstance(numeric_user_id, int)
                or isinstance(numeric_user_id, bool)
                or numeric_user_id <= 0
            ):
                raise repository_tree.RepositoryDomainError(
                    "登录身份缺少仓库所有者编号",
                    code="invalid_owner",
                    status=403,
                )
            target = get_repository_semantic_target(
                numeric_user_id,
                repository_entry_id,
                language,
            )
            if language in {"c", "cpp"}:
                result = get_repository_clangd_service(
                    language
                ).semantic_tokens(
                    target,
                    analysis_source,
                    lambda: capture_repository_semantic_snapshot(target),
                )
            else:
                result = get_editor_language_service(language).semantic_tokens(
                    (
                        f"{numeric_user_id}:editor:repository:"
                        f"{target.entry_id}:{language}"
                    ),
                    analysis_source,
                )
            ensure_repository_semantic_target_current(target)
        else:
            assert document_key is not None
            result = get_editor_language_service(language).semantic_tokens(
                document_key, analysis_source
            )
        if markdown_request:
            result = dict(result)
            result["data"] = _without_semantic_prefix_lines(
                result["data"],
                1,
            )[: _MARKDOWN_MAX_TOKENS * 5]
            assert markdown_cache_key is not None
            result["result_id"] = f"markdown:{markdown_cache_key[:12]}"
    except repository_tree.RepositoryDomainError as exc:
        if markdown_cache_key is not None:
            _markdown_semantic_cache.cancel(markdown_cache_key)
        return jsonify(exc.as_payload()), exc.status
    except (LanguageServiceError, ValueError) as exc:
        if markdown_cache_key is not None:
            _markdown_semantic_cache.cancel(markdown_cache_key)
        return _error_response(exc)
    except Exception:
        if markdown_cache_key is not None:
            _markdown_semantic_cache.cancel(markdown_cache_key)
        raise
    if markdown_request:
        assert markdown_cache_key is not None
        _markdown_semantic_cache.store(markdown_cache_key, result)
    return jsonify(success=True, **result)
