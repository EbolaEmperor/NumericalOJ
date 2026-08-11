"""Agent 身份 relay 使用的短链路签名能力。"""

from __future__ import annotations

import secrets

from itsdangerous import BadData, SignatureExpired, URLSafeSerializer, URLSafeTimedSerializer

from config import SECRET_KEY


AGENT_IDENTITY_HEADER = "X-NumOJ-Agent-Identity"
_SERIALIZER_SALT = "numericaloj-agent-identity-v1"
_TASK_SERIALIZER_SALT = "numericaloj-agent-identity-v2"
_TASK_CAPABILITY_MAX_AGE_SECONDS = 48 * 60 * 60
_ALLOWED_ROLES = frozenset({"user", "admin"})


def _serializer():
    return URLSafeSerializer(str(SECRET_KEY), salt=_SERIALIZER_SALT)


def _task_serializer():
    return URLSafeTimedSerializer(str(SECRET_KEY), salt=_TASK_SERIALIZER_SALT)


def create_agent_identity_capability(
    username,
    access_role,
    *,
    session_id="",
    task_id="",
):
    normalized_username = str(username or "").strip()
    normalized_role = str(access_role or "").strip().lower()
    if not normalized_username or normalized_role not in _ALLOWED_ROLES:
        raise ValueError("Agent 身份能力参数无效")
    normalized_session_id = str(session_id or "").strip()
    normalized_task_id = str(task_id or "").strip()
    if bool(normalized_session_id) != bool(normalized_task_id):
        raise ValueError("Agent 身份能力任务绑定无效")
    payload = {
        "v": 2 if normalized_session_id else 1,
        "username": normalized_username,
        "access_role": normalized_role,
        "nonce": secrets.token_urlsafe(18),
    }
    if normalized_session_id:
        payload["session_id"] = normalized_session_id
        payload["task_id"] = normalized_task_id
        return _task_serializer().dumps(payload)
    return _serializer().dumps(payload)


def resolve_agent_identity_capability(
    value,
    *,
    session_username="",
    max_age_seconds=_TASK_CAPABILITY_MAX_AGE_SECONDS,
):
    """验签并解析 Agent 身份能力；任务能力仍需调用方核对数据库绑定。"""

    raw = str(value or "").strip()
    if not raw:
        return None
    payload = None
    try:
        payload = _task_serializer().loads(
            raw,
            max_age=max(1, int(max_age_seconds)),
        )
    except (BadData, SignatureExpired, TypeError, ValueError):
        try:
            payload = _serializer().loads(raw)
        except BadData:
            return False
    if not isinstance(payload, dict):
        return False
    version = payload.get("v")
    username = str(payload.get("username") or "").strip()
    access_role = str(payload.get("access_role") or "").strip().lower()
    nonce = str(payload.get("nonce") or "").strip()
    if not username or access_role not in _ALLOWED_ROLES or len(nonce) < 16:
        return False
    if version == 1:
        if username != str(session_username or "").strip():
            return False
        return {
            "version": 1,
            "username": username,
            "access_role": access_role,
            "session_id": "",
            "task_id": "",
        }
    if version != 2:
        return False
    session_id = str(payload.get("session_id") or "").strip()
    task_id = str(payload.get("task_id") or "").strip()
    if not session_id or not task_id:
        return False
    browser_username = str(session_username or "").strip()
    if browser_username and browser_username != username:
        return False
    return {
        "version": 2,
        "username": username,
        "access_role": access_role,
        "session_id": session_id,
        "task_id": task_id,
    }


def verify_agent_identity_capability(value, *, session_username):
    resolved = resolve_agent_identity_capability(
        value,
        session_username=session_username,
    )
    if resolved is None or resolved is False:
        return resolved
    # 旧兼容入口不能建立无浏览器会话的身份；v2 必须走 current_user() 的
    # 数据库任务绑定校验。
    if resolved["version"] != 1:
        return False
    return resolved["access_role"]


__all__ = [
    "AGENT_IDENTITY_HEADER",
    "create_agent_identity_capability",
    "resolve_agent_identity_capability",
    "verify_agent_identity_capability",
]
