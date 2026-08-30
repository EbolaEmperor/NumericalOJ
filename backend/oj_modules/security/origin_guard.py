"""应用级浏览器同源请求安全策略。"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import abort, request


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_NULL_ORIGIN_CAPABILITY_ENDPOINTS = frozenset({"vibehub.runtime_proxy"})


def _origin_key(value):
    try:
        parsed = urlsplit(str(value or "").strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def is_same_origin(candidate, request_url, trusted_origins=()):
    """判断 Origin/Referer 是否来自当前站点或显式可信站点。"""
    candidate_key = _origin_key(candidate)
    if candidate_key is None:
        return False
    allowed = {_origin_key(request_url)}
    allowed.update(_origin_key(origin) for origin in trusted_origins)
    allowed.discard(None)
    return candidate_key in allowed


def install_same_origin_protection(app, *, trusted_origins=()):
    """拒绝带有跨站 Origin/Referer 的浏览器写请求。"""
    if isinstance(trusted_origins, str):
        trusted_origins = tuple(
            item.strip() for item in trusted_origins.split(",") if item.strip()
        )
    else:
        trusted_origins = tuple(trusted_origins or ())

    @app.before_request
    def _reject_cross_origin_write():
        if request.method.upper() in _SAFE_METHODS:
            return None

        # 不可信作品位于没有 allow-same-origin 的 sandbox iframe 中，浏览器写请求
        # 必然携带 Origin: null。仅短期 capability 代理 endpoint 接受该来源；启动、
        # 上传、审核等其余 VibeHub 写入口仍走常规同源保护。
        if (
            request.endpoint in _NULL_ORIGIN_CAPABILITY_ENDPOINTS
            and request.headers.get("Origin") == "null"
        ):
            return None

        source = request.headers.get("Origin") or request.headers.get("Referer")
        if not source:
            return None
        if not is_same_origin(source, request.host_url, trusted_origins):
            abort(403, description="跨站写请求已拒绝")
        return None

    return _reject_cross_origin_write


__all__ = ["install_same_origin_protection", "is_same_origin"]
