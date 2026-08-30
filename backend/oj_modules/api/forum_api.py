#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""讨论区 JSON API。

HTTP 层只负责解析请求与映射领域错误；作者权限、匿名快照、幂等写入及公开字段
白名单均由服务层执行。
"""

from __future__ import annotations

from datetime import timezone

from flask import Blueprint, current_app, request

from backend.oj_modules.api.helpers import json_error, json_success
from backend.oj_modules.security.auth import current_user
from backend.oj_modules.forum.identity import (
    AnonymousIdentityCooldownError,
    AnonymousIdentityRequiredError,
    AnonymousNameValidationError,
    ForumIdentityError,
    ForumIdentityStateError,
    ForumIdentityUserNotFoundError,
    IdentityNameConflictError,
    IdentityNamespaceLockError,
    IdentityOperationConflictError,
    PostingIdentityConflictError,
    avatar_presentation,
    draft_namespace_token,
    get_identity_state,
    posting_identity_token_from_state,
    rotate_anonymous_identity,
    set_anonymous_mode,
)
from backend.oj_modules.forum.services import (
    ForumError,
    count_thread_replies,
    create_reply,
    create_thread,
    edit_reply,
    edit_thread,
    get_replies_before,
    get_thread_detail,
    list_threads,
    render_forum_markdown,
    validate_content,
)


forum_api_bp = Blueprint("forum_api", __name__, url_prefix="/api")


def _authenticated_user():
    user = current_user()
    if not user:
        return None, json_error("请先登录", 401)
    return user, None


def _json_object():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None, json_error("请求体必须是 JSON 对象", 400)
    return payload, None


def _client_request_id(payload: dict):
    # 浏览器草稿沿用面向用户的 idempotency_key 命名；CLI 与数据库使用
    # client_request_id。两者表达同一 UUID，服务层只接收规范化后的单一概念。
    return payload.get("client_request_id", payload.get("idempotency_key"))


def _forum_error(exc: ForumError):
    return json_error(exc.message, exc.status_code, **exc.payload)


def _identity_error(exc: ForumIdentityError):
    status = 400
    payload = {"code": exc.code}
    if isinstance(
        exc,
        (
            AnonymousIdentityRequiredError,
            AnonymousIdentityCooldownError,
            IdentityNameConflictError,
            IdentityOperationConflictError,
            PostingIdentityConflictError,
        ),
    ):
        status = 409
    elif isinstance(exc, ForumIdentityStateError):
        status = 500
    elif isinstance(exc, ForumIdentityUserNotFoundError):
        status = 404
    elif isinstance(exc, IdentityNamespaceLockError):
        status = 503
    elif isinstance(exc, AnonymousNameValidationError):
        status = 400
    if isinstance(exc, AnonymousIdentityCooldownError):
        available_at = exc.available_at.replace(tzinfo=timezone.utc)
        payload.update(
            cooldown_remaining_seconds=exc.retry_after_seconds,
            can_change_at=available_at.isoformat().replace("+00:00", "Z"),
        )
    return json_error(str(exc), status, **payload)


def _public_identity(state: dict, secret_key) -> dict:
    """去掉 identity service 中仅供事务使用的真实 ID 与匿名记录 ID。"""

    real_name = str(state.get("real_username") or "")
    anonymous = state.get("anonymous_identity") or {}
    effective = state.get("effective_identity") or {}
    anonymous_name = anonymous.get("display_name")
    posting_name = str(effective.get("display_name") or real_name)
    posting_token = posting_identity_token_from_state(state, secret_key)
    return {
        "real_name": real_name,
        "real_avatar": avatar_presentation(real_name),
        "use_anonymous": bool(state.get("use_anonymous")),
        "anonymous_name": anonymous_name,
        "anonymous_avatar": (
            avatar_presentation(anonymous_name) if anonymous_name else None
        ),
        "can_change_at": state.get("refresh_available_at"),
        "cooldown_remaining_seconds": int(
            state.get("refresh_retry_after_seconds") or 0
        ),
        "can_change_anonymous": bool(state.get("can_refresh")),
        "posting_name": posting_name,
        "posting_avatar": avatar_presentation(posting_name),
        "posting_is_anonymous": effective.get("kind") == "anonymous",
        "draft_namespace": draft_namespace_token(int(state["user_id"]), secret_key),
        "posting_token": posting_token,
    }


@forum_api_bp.route("/forum", methods=["GET"])
def forum_list():
    user, error = _authenticated_user()
    if error:
        return error
    try:
        result = list_threads(
            int(user["id"]),
            scope=request.args.get("scope", "all"),
            query=request.args.get("q", ""),
            page=request.args.get("page", 1),
            limit=request.args.get("limit", 30),
        )
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(**result)


@forum_api_bp.route("/forum/threads/<int:thread_id>", methods=["GET"])
def forum_thread(thread_id):
    user, error = _authenticated_user()
    if error:
        return error
    try:
        result = get_thread_detail(
            int(user["id"]),
            thread_id,
            reply_limit=request.args.get("limit", 50),
        )
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(**result)


@forum_api_bp.route("/forum/threads/<int:thread_id>/replies", methods=["GET"])
def forum_thread_replies(thread_id):
    user, error = _authenticated_user()
    if error:
        return error
    try:
        result = get_replies_before(
            int(user["id"]),
            thread_id,
            before=request.args.get("before"),
            limit=request.args.get("limit", 50),
        )
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(**result)


@forum_api_bp.route("/forum/threads", methods=["POST"])
def forum_create_thread():
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    try:
        thread, created = create_thread(
            int(user["id"]),
            title=payload.get("title"),
            content=payload.get("content"),
            client_request_id=_client_request_id(payload),
            expected_identity_token=payload.get("expected_identity_token"),
            token_secret=current_app.secret_key,
        )
    except ForumError as exc:
        return _forum_error(exc)
    except ForumIdentityError as exc:
        return _identity_error(exc)
    return (
        json_success(
            message="讨论发布成功" if created else "讨论已成功发布",
            thread=thread,
            created=created,
        ),
        201 if created else 200,
    )


@forum_api_bp.route("/forum/threads/<int:thread_id>/replies", methods=["POST"])
def forum_create_reply(thread_id):
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    try:
        reply, created = create_reply(
            int(user["id"]),
            thread_id,
            content=payload.get("content"),
            client_request_id=_client_request_id(payload),
            expected_identity_token=payload.get("expected_identity_token"),
            token_secret=current_app.secret_key,
        )
    except ForumError as exc:
        return _forum_error(exc)
    except ForumIdentityError as exc:
        return _identity_error(exc)
    return (
        json_success(
            message="回复成功" if created else "回复已成功提交",
            reply=reply,
            reply_count=count_thread_replies(thread_id),
            created=created,
        ),
        201 if created else 200,
    )


@forum_api_bp.route("/forum/threads/<int:thread_id>", methods=["PATCH"])
def forum_edit_thread(thread_id):
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    try:
        thread = edit_thread(
            int(user["id"]),
            thread_id,
            title=payload.get("title"),
            content=payload.get("content"),
            edit_version=payload.get("edit_version"),
            client_request_id=_client_request_id(payload),
        )
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(message="讨论已更新", thread=thread)


@forum_api_bp.route("/forum/replies/<int:reply_id>", methods=["PATCH"])
def forum_edit_reply(reply_id):
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    try:
        reply = edit_reply(
            int(user["id"]),
            reply_id,
            content=payload.get("content"),
            edit_version=payload.get("edit_version"),
            client_request_id=_client_request_id(payload),
        )
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(message="回复已更新", reply=reply)


@forum_api_bp.route("/forum/preview", methods=["POST"])
def forum_preview():
    _user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    try:
        content = validate_content(payload.get("content"))
    except ForumError as exc:
        return _forum_error(exc)
    return json_success(rendered_content=render_forum_markdown(content))


@forum_api_bp.route("/forum/identity", methods=["GET"])
def forum_identity():
    user, error = _authenticated_user()
    if error:
        return error
    try:
        state = get_identity_state(int(user["id"]))
    except ForumIdentityError as exc:
        return _identity_error(exc)
    return json_success(identity=_public_identity(state, current_app.secret_key))


@forum_api_bp.route("/forum/identity/mode", methods=["PUT"])
def forum_identity_mode():
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    enabled = payload.get("use_anonymous")
    if not isinstance(enabled, bool):
        return json_error("use_anonymous 必须是布尔值", 400)
    try:
        state = set_anonymous_mode(int(user["id"]), enabled)
    except ForumIdentityError as exc:
        return _identity_error(exc)
    return json_success(
        message="身份模式已更新",
        identity=_public_identity(state, current_app.secret_key),
    )


@forum_api_bp.route("/forum/identity/anonymous", methods=["POST"])
def forum_anonymous_identity():
    user, error = _authenticated_user()
    if error:
        return error
    payload, error = _json_object()
    if error:
        return error
    enable = payload.get("enable")
    if enable is not None and not isinstance(enable, bool):
        return json_error("enable 必须是布尔值", 400)
    try:
        state = rotate_anonymous_identity(
            int(user["id"]),
            payload.get("display_name"),
            enable=enable,
            client_request_id=_client_request_id(payload),
        )
    except ForumIdentityError as exc:
        return _identity_error(exc)
    return json_success(
        message="匿名身份已更新",
        identity=_public_identity(state, current_app.secret_key),
    )


@forum_api_bp.route("/forum/new-context", methods=["GET"])
def forum_new_context():
    """保留 CLI 的只读命令名；返回新的 JSON 写入契约，不提供 HTML form 降级。"""

    _user, error = _authenticated_user()
    if error:
        return error
    return json_success(
        action="/api/forum/threads",
        method="POST",
        content_type="application/json",
        fields=[
            {"name": "title", "type": "text", "required": True},
            {"name": "content", "type": "markdown", "required": True},
            {"name": "client_request_id", "type": "uuid", "required": True},
            {
                "name": "expected_identity_token",
                "type": "opaque",
                "required": True,
            },
        ],
    )
