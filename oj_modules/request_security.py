#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""应用级浏览器请求安全策略。"""

from __future__ import annotations

from urllib.parse import urlsplit

from flask import abort, request


_SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS', 'TRACE'})


def _origin_key(value):
    """把绝对 URL 归一化为可比较的 (scheme, host, port)。"""
    try:
        parsed = urlsplit(str(value or '').strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower()
        if scheme not in {'http', 'https'} or not host:
            return None
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if port is None:
        port = 443 if scheme == 'https' else 80
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
    """拒绝带有跨站 Origin/Referer 的浏览器写请求。

    非浏览器 CLI 通常不会发送这两个请求头，因此保持兼容；浏览器提交则至少会
    携带 Origin 或 Referer，可在不改造现有大量表单的情况下形成统一 CSRF 防线。
    """
    if isinstance(trusted_origins, str):
        trusted_origins = tuple(
            item.strip() for item in trusted_origins.split(',') if item.strip()
        )
    else:
        trusted_origins = tuple(trusted_origins or ())

    @app.before_request
    def _reject_cross_origin_write():
        if request.method.upper() in _SAFE_METHODS:
            return None

        source = request.headers.get('Origin') or request.headers.get('Referer')
        if not source:
            return None
        if not is_same_origin(source, request.host_url, trusted_origins):
            abort(403, description='跨站写请求已拒绝')
        return None

    return _reject_cross_origin_write
