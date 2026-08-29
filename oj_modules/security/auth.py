"""统一的会话用户与权限装饰器。"""

import threading
import time
from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from oj_modules.db_services import get_user_by_username
from oj_modules.security.agent_identity import (
    AGENT_IDENTITY_HEADER,
    resolve_agent_identity_capability,
)


# 普通浏览器请求会先经过全局登录守卫，随后路由与模板再次读取 current_user。
# Flask g 已合并同一请求内的读取；这个极短缓存继续合并用户连续点击页面及页面并发
# 拉取的 JSON/Fragment 请求。管理员与 Agent capability 请求不进入跨请求缓存，确保
# 高权限身份始终逐请求从数据库确认。
_BROWSER_USER_CACHE_TTL_SECONDS = 2.0
_BROWSER_USER_CACHE_MAX_ENTRIES = 2048
_browser_user_cache = {}
_browser_user_cache_guard = threading.Lock()
_browser_user_cache_locks = tuple(threading.Lock() for _ in range(64))


def _browser_user_cache_lock(username):
    return _browser_user_cache_locks[
        hash(username) % len(_browser_user_cache_locks)
    ]


def _cached_browser_user(username):
    """短暂缓存普通用户；返回副本，禁止请求之间共享可变 dict。"""
    normalized = str(username or "").strip()
    if not normalized:
        return None
    loader_identity = id(get_user_by_username)
    lock = _browser_user_cache_lock(normalized)
    with lock:
        now = time.monotonic()
        with _browser_user_cache_guard:
            cached = _browser_user_cache.get(normalized)
        if (
            cached is not None
            and cached[0] > now
            and cached[1] == loader_identity
        ):
            return dict(cached[2])

        user = get_user_by_username(normalized)
        # 管理员权限逐请求回源；不存在的用户也不做 negative cache，使删除/改名后的
        # 会话尽快失效，并避免短暂数据库故障被缓存为未登录。
        if not user or int(user.get("is_admin") or 0) == 1:
            with _browser_user_cache_guard:
                _browser_user_cache.pop(normalized, None)
            return user

        snapshot = dict(user)
        with _browser_user_cache_guard:
            expired = [
                key
                for key, item in _browser_user_cache.items()
                if item[0] <= now
            ]
            for key in expired:
                _browser_user_cache.pop(key, None)
            while (
                len(_browser_user_cache) >= _BROWSER_USER_CACHE_MAX_ENTRIES
                and normalized not in _browser_user_cache
            ):
                oldest = min(
                    _browser_user_cache,
                    key=lambda key: _browser_user_cache[key][0],
                )
                _browser_user_cache.pop(oldest, None)
            _browser_user_cache[normalized] = (
                now + _BROWSER_USER_CACHE_TTL_SECONDS,
                loader_identity,
                snapshot,
            )
        return dict(snapshot)


def invalidate_cached_browser_user(*, username=None, user_id=None, email=None):
    """失效用户写路径对应的本进程认证缓存；无条件参数时清空全部。"""
    normalized_username = str(username or "").strip()
    normalized_email = str(email or "").strip()
    normalized_user_id = None
    if user_id is not None:
        try:
            normalized_user_id = int(user_id)
        except (TypeError, ValueError):
            normalized_user_id = None

    with _browser_user_cache_guard:
        if not any((normalized_username, normalized_email, normalized_user_id is not None)):
            _browser_user_cache.clear()
            return
        for key, item in list(_browser_user_cache.items()):
            user = item[2]
            if normalized_username and key == normalized_username:
                _browser_user_cache.pop(key, None)
                continue
            if normalized_user_id is not None:
                try:
                    cached_user_id = int(user.get("id"))
                except (TypeError, ValueError):
                    cached_user_id = None
                if cached_user_id == normalized_user_id:
                    _browser_user_cache.pop(key, None)
                    continue
            if normalized_email and str(user.get("email") or "").strip() == normalized_email:
                _browser_user_cache.pop(key, None)


def _active_task_session(capability):
    """返回能力绑定且仍活动的 Agent 会话，否则返回 None。"""

    if not capability or capability.get("version") != 2:
        return None
    # 延迟导入避免普通登录路径加载 Agent 会话模块；只有 relay 请求会查库。
    from oj_modules.agents.sessions import get_agent_session

    try:
        agent_session = get_agent_session(capability.get("session_id"))
    except Exception:
        return None
    if not agent_session:
        return None
    status = str(agent_session.get("status") or "").strip().lower()
    if not (
        status not in {"completed", "failed", "canceled", "cancelled", "cleanupfailed", "cleanup_failed"}
        and str(agent_session.get("current_task_id") or "") == capability.get("task_id")
        and str(agent_session.get("requested_by") or "") == capability.get("username")
        and str(agent_session.get("access_role") or "").lower() == capability.get("access_role")
    ):
        return None
    return agent_session


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
    active_task_session = None
    if capability is False:
        user = None
    elif capability and capability.get("version") == 2:
        active_task_session = _active_task_session(capability)
        if not active_task_session:
            user = None
        else:
            user = get_user_by_username(capability["username"])
    elif browser_username:
        user = _cached_browser_user(browser_username)
    else:
        user = None
    access_role = capability.get("access_role") if capability else None
    if user and access_role == "user":
        user = dict(user)
        user["is_admin"] = 0
        user["agent_access_role"] = "user"
        if active_task_session:
            user["agent_task_kind"] = str(
                active_task_session.get("task_kind") or ""
            ).strip().lower()
            user["agent_problem_id"] = active_task_session.get("problem_id")
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


__all__ = [
    "admin_required",
    "current_user",
    "invalidate_cached_browser_user",
    "is_admin",
    "login_required",
]
