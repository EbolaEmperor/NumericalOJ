"""Agent 身份 relay 使用的短链路签名能力。"""

from __future__ import annotations

import secrets

from itsdangerous import BadData, URLSafeSerializer

from config import SECRET_KEY


AGENT_IDENTITY_HEADER = "X-NumOJ-Agent-Identity"
_SERIALIZER_SALT = "numericaloj-agent-identity-v1"
_ALLOWED_ROLES = frozenset({"user", "admin"})


def _serializer():
    return URLSafeSerializer(str(SECRET_KEY), salt=_SERIALIZER_SALT)


def create_agent_identity_capability(username, access_role):
    normalized_username = str(username or "").strip()
    normalized_role = str(access_role or "").strip().lower()
    if not normalized_username or normalized_role not in _ALLOWED_ROLES:
        raise ValueError("Agent 身份能力参数无效")
    return _serializer().dumps({
        "v": 1,
        "username": normalized_username,
        "access_role": normalized_role,
        "nonce": secrets.token_urlsafe(18),
    })


def verify_agent_identity_capability(value, *, session_username):
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        payload = _serializer().loads(raw)
    except BadData:
        return False
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return False
    username = str(payload.get("username") or "").strip()
    access_role = str(payload.get("access_role") or "").strip().lower()
    nonce = str(payload.get("nonce") or "").strip()
    if (
        not username
        or username != str(session_username or "").strip()
        or access_role not in _ALLOWED_ROLES
        or len(nonce) < 16
    ):
        return False
    return access_role


__all__ = [
    "AGENT_IDENTITY_HEADER",
    "create_agent_identity_capability",
    "verify_agent_identity_capability",
]
