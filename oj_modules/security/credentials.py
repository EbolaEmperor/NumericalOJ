"""用户名校验与密码哈希原语。"""

import hashlib
import re

from werkzeug.security import check_password_hash, generate_password_hash


_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,49}$")


def validate_username(username):
    """校验用户名并返回 ``(ok, cleaned, message)``。"""
    cleaned = str(username or "").strip()
    if not cleaned:
        return False, cleaned, "用户名不能为空"
    if not _USERNAME_RE.fullmatch(cleaned):
        return (
            False,
            cleaned,
            "用户名只能包含字母、数字、下划线、点和连字符，长度不超过 50，且必须以字母、数字或下划线开头",
        )
    return True, cleaned, ""


def hash_password(password):
    """返回带盐慢哈希。"""
    return generate_password_hash(str(password or ""))


def verify_password(stored_hash, password):
    """校验口令，返回 ``(是否正确, 是否需要升级重哈希)``。"""
    if not stored_hash:
        return False, False
    stored = str(stored_hash)
    password_text = str(password or "")
    if _SHA256_HEX_RE.match(stored):
        ok = hashlib.sha256(password_text.encode()).hexdigest() == stored
        return ok, ok
    try:
        ok = check_password_hash(stored, password_text)
    except Exception:
        ok = False
    return ok, False


__all__ = ["hash_password", "validate_username", "verify_password"]
