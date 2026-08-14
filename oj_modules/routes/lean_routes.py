"""Authenticated Lean 4 goal-state endpoint."""

from __future__ import annotations

import re

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
    LeanSourceStateError,
    get_lean_interactive_service,
)
from oj_modules.problems.lean_workspace import (
    LeanWorkspaceError,
    LeanWorkspaceStaleError,
    merge_workspace_sources,
    normalize_lean_submission_payload,
)
from oj_modules.security.auth import current_user, login_required
from oj_modules.security.throttling import rate_limit_hit


lean_bp = Blueprint("lean", __name__)
_rds = None
_REQUEST_MAX_BYTES = LEAN_SOURCE_MAX_BYTES + 512 * 1024
_CHECKS_MAX_PER_WINDOW = 240
_CHECKS_WINDOW_SECONDS = 60
_CLIENT_SESSION_RE = re.compile(r"[A-Za-z0-9-]{1,64}\Z")


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


def _success_response(
    result: dict,
    *,
    client_version: int,
    active_file: str,
):
    diagnostics = result.get("diagnostics")
    diagnostic_items = diagnostics or []
    goals = result.get("goals") or []
    goal_rendered = result.get("goal_rendered") or ""
    error_count = sum(
        1
        for diagnostic in diagnostic_items
        if diagnostic.get("severity", 1) == 1
    )
    if error_count:
        message = f"发现 {error_count} 个错误"
    elif goals:
        message = f"光标处有 {len(goals)} 个证明目标"
    elif goal_rendered:
        message = goal_rendered
    else:
        message = "光标处没有证明目标"
    return jsonify(
        success=True,
        version=client_version,
        active_file=active_file,
        source_state_id=result["source_state_id"],
        goals=result.get("goals"),
        goal_rendered=result.get("goal_rendered"),
        diagnostics=diagnostics,
        processing=result.get("processing"),
        document_version=result["document_version"],
        semantic_tokens=result.get("semantic_tokens"),
        message=message,
    )


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

    request_kind = payload.get("request_kind", "source")
    problem_id = payload.get("problem_id")
    revision = payload.get("revision")
    client_session_id = payload.get("client_session_id")
    active_file = payload.get("active_file")
    client_version = payload.get("version")
    position = payload.get("position")
    known_semantic_result_id = payload.get("known_semantic_result_id")
    if request_kind not in {"source", "cursor"}:
        return jsonify(success=False, message="request_kind 无效"), 400
    if (
        not isinstance(problem_id, int)
        or isinstance(problem_id, bool)
        or problem_id <= 0
    ):
        return jsonify(success=False, message="problem_id 无效"), 400
    if not isinstance(revision, str) or not revision.strip():
        return jsonify(success=False, message="revision 无效"), 400
    if client_session_id is not None and (
        not isinstance(client_session_id, str)
        or _CLIENT_SESSION_RE.fullmatch(client_session_id) is None
    ):
        return jsonify(success=False, message="client_session_id 无效"), 400
    if not isinstance(active_file, str) or not active_file:
        return jsonify(success=False, message="active_file 无效"), 400
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
    if known_semantic_result_id is not None and not isinstance(
        known_semantic_result_id, str
    ):
        return jsonify(
            success=False,
            message="known_semantic_result_id 无效",
        ), 400

    if request_kind == "source":
        files = payload.get("files")
        if not isinstance(files, dict):
            return jsonify(
                success=False,
                message="files 必须是 JSON 对象",
            ), 400
        source_state_id = None
        document_version = None
    else:
        if client_session_id is None:
            return jsonify(
                success=False,
                message="client_session_id 无效",
            ), 400
        if "files" in payload:
            return jsonify(
                success=False,
                message="cursor 请求不能包含 files",
            ), 400
        files = None
        source_state_id = payload.get("source_state_id")
        document_version = payload.get("document_version")
        if not isinstance(source_state_id, str) or not source_state_id:
            return jsonify(success=False, message="source_state_id 无效"), 400
        if (
            not isinstance(document_version, int)
            or isinstance(document_version, bool)
            or document_version <= 0
        ):
            return jsonify(success=False, message="document_version 无效"), 400

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

    position_payload = {"line": line, "character": character}
    service = get_lean_interactive_service()
    if request_kind == "source":
        assert files is not None
        try:
            workspace, writable_files = normalize_lean_submission_payload(
                problem_id=problem_id,
                revision=revision,
                files=files,
            )
        except LeanWorkspaceStaleError as exc:
            return jsonify(
                success=False,
                code="lean_workspace_stale",
                message=str(exc),
            ), 409
        except LeanWorkspaceError as exc:
            return jsonify(success=False, message=str(exc)), 400
        sources = merge_workspace_sources(workspace, writable_files)
        if active_file not in sources:
            return jsonify(success=False, message="active_file 无效"), 400
        session_key = f"{user_id}:{problem_id}:{workspace['revision']}"
        if client_session_id is not None:
            session_key += f":{client_session_id}"
        try:
            result = service.check_source(
                session_key,
                sources,
                active_file,
                position_payload,
                known_semantic_result_id,
            )
        except (LanguageServiceError, ValueError) as exc:
            return _error_response(exc)
    else:
        assert source_state_id is not None
        assert document_version is not None
        session_key = f"{user_id}:{problem_id}:{revision}:{client_session_id}"
        try:
            result = service.check_cursor(
                session_key,
                source_state_id,
                document_version,
                active_file,
                position_payload,
                known_semantic_result_id,
            )
        except LeanSourceStateError as exc:
            return jsonify(
                success=False,
                code="resync_required",
                message=str(exc),
            ), 409
        except (LanguageServiceError, ValueError) as exc:
            return _error_response(exc)

    return _success_response(
        result,
        client_version=client_version,
        active_file=active_file,
    )
