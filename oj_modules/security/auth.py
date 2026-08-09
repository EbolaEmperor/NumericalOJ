"""统一的会话用户与权限装饰器。"""

from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from oj_modules.db_services import get_user_by_username
from oj_modules.security.agent_identity import (
    AGENT_IDENTITY_HEADER,
    verify_agent_identity_capability,
)


def current_user():
    """返回当前登录用户的完整记录（含 is_admin 字段），未登录返回 None。"""
    username = session.get("username")
    agent_capability = str(request.headers.get(AGENT_IDENTITY_HEADER) or "")
    cache_key = (username, agent_capability)
    if getattr(g, "_numoj_current_user_key", object()) == cache_key:
        return getattr(g, "_numoj_current_user", None)
    if not username:
        g._numoj_current_user_key = cache_key
        g._numoj_current_user = None
        return None
    user = get_user_by_username(username)
    access_role = verify_agent_identity_capability(
        agent_capability,
        session_username=username,
    )
    if access_role is False:
        user = None
    elif user and access_role == "user":
        user = dict(user)
        user["is_admin"] = 0
        user["agent_access_role"] = "user"
    elif user and access_role == "admin":
        user = dict(user)
        user["agent_access_role"] = "admin"
    g._numoj_current_user_key = cache_key
    g._numoj_current_user = user
    return user


def is_admin(user):
    """判断给定用户记录是否为管理员。"""
    return bool(user and user.get("is_admin") == 1)


def _wants_json():
    """AJAX / JSON 请求应返回 JSON 错误码，而非重定向到登录页。"""
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept and "text/html" not in accept


def login_required(view):
    """要求已登录，否则 JSON 请求返回 401、普通请求重定向登录页。"""

    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if _wants_json():
                return jsonify(success=False, message="请先登录"), 401
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    """要求管理员，否则 JSON 请求返回 403、普通请求重定向登录页。"""

    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not is_admin(user):
            if _wants_json():
                return jsonify(success=False, message="无权限"), 403
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapper


__all__ = ["admin_required", "current_user", "is_admin", "login_required"]
