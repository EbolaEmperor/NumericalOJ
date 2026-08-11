"""应用级登录边界与登录后本地跳转校验。"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

from flask import jsonify, redirect, request, url_for


_PUBLIC_AUTH_ENDPOINTS = frozenset(
    {"auth.login", "auth.register", "auth.send_verification", "auth.forgot_password"}
)
_PUBLIC_CAPABILITY_ENDPOINTS = frozenset({"vibehub.runtime_proxy"})
_PUBLIC_EXACT_PATHS = frozenset({"/favicon.ico", "/health/live", "/health/ready"})


def safe_local_next(value):
    """只接受站内绝对路径，拒绝开放重定向与浏览器路径歧义。"""
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    if (
        not candidate
        or not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in candidate)
    ):
        return None

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return None

    decoded_path = parsed.path
    for _ in range(3):
        next_decoded_path = unquote(decoded_path)
        if next_decoded_path == decoded_path:
            break
        decoded_path = next_decoded_path
    if (
        decoded_path.startswith("//")
        or "\\" in decoded_path
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded_path)
    ):
        return None
    return candidate


def _original_request_target():
    target = request.full_path
    if target.endswith("?"):
        target = target[:-1]
    return target


def _is_public_request():
    if request.endpoint in _PUBLIC_AUTH_ENDPOINTS:
        return True
    if request.endpoint in _PUBLIC_CAPABILITY_ENDPOINTS:
        return True
    if request.path in _PUBLIC_EXACT_PATHS:
        return True
    return request.path.startswith("/static/")


def _is_api_request():
    if request.path == "/api" or request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def install_global_login_guard(app, *, user_loader):
    """为应用安装默认拒绝的全站登录守卫。"""
    extension_key = "numericaloj_global_login_guard"
    existing = app.extensions.get(extension_key)
    if existing is not None:
        return existing

    @app.before_request
    def _require_authenticated_user():
        if _is_public_request():
            return None
        if user_loader():
            return None
        if _is_api_request():
            return jsonify(success=False, message="请先登录"), 401

        target = safe_local_next(_original_request_target())
        return redirect(url_for("auth.login", next=target))

    app.extensions[extension_key] = _require_authenticated_user
    return _require_authenticated_user


__all__ = ["install_global_login_guard", "safe_local_next"]
