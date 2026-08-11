"""统一的会话用户与权限装饰器。"""

from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from oj_modules.db_services import get_user_by_username
from oj_modules.security.agent_identity import (
    AGENT_IDENTITY_HEADER,
    resolve_agent_identity_capability,
)


def _task_capability_matches_active_session(capability):
    """任务能力只能用于其绑定且仍活动的 Agent 轮次。"""

    if not capability or capability.get("version") != 2:
        return False
    # 延迟导入避免普通登录路径加载 Agent 会话模块；只有 relay 请求会查库。
    from oj_modules.agents.sessions import get_agent_session

    try:
        agent_session = get_agent_session(capability.get("session_id"))
    except Exception:
        return False
    if not agent_session:
        return False
    status = str(agent_session.get("status") or "").strip().lower()
    return bool(
        status not in {"completed", "failed", "canceled", "cancelled", "cleanupfailed", "cleanup_failed"}
        and str(agent_session.get("current_task_id") or "") == capability.get("task_id")
        and str(agent_session.get("requested_by") or "") == capability.get("username")
        and str(agent_session.get("access_role") or "").lower() == capability.get("access_role")
    )


def current_user():
    """返回当前登录用户的完整记录（含 is_admin 字段），未登录返回 None。"""
    browser_username = str(session.get("username") or "").strip()
    agent_capability = str(request.headers.get(AGENT_IDENTITY_HEADER) or "")
    cache_key = (browser_username, agent_capability)
    if getattr(g, "_numoj_current_user_key", object()) == cache_key:
        return getattr(g, "_numoj_current_user", None)
    capability = resolve_agent_identity_capability(
        agent_capability,
        session_username=browser_username,
    )
    if capability is False:
        user = None
    elif capability and capability.get("version") == 2:
        if not _task_capability_matches_active_session(capability):
            user = None
        else:
            user = get_user_by_username(capability["username"])
    elif browser_username:
        user = get_user_by_username(browser_username)
    else:
        user = None
    access_role = capability.get("access_role") if capability else None
    if user and access_role == "user":
        user = dict(user)
        user["is_admin"] = 0
        user["agent_access_role"] = "user"
    elif user and access_role == "admin":
        if int(user.get("is_admin") or 0) != 1:
            user = None
        else:
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
