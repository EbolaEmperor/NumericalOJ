#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""统一的会话/权限工具。

历史上 current_user()/is_admin() 被逐字复制进十多个路由模块，一处遗漏即是一个静默越权
（grading 的未授权下载就是这么来的）。这里收敛为单一实现，并提供 login_required/admin_required
装饰器，便于把鉴权变成可强制的边界而非各处手抄的约定。
"""

from functools import wraps

from flask import jsonify, redirect, request, session, url_for

from oj_modules.db_services import get_user_by_username


def current_user():
    """返回当前登录用户的完整记录（含 is_admin 字段），未登录返回 None。"""
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


def is_admin(user):
    """判断给定用户记录是否为管理员。"""
    return bool(user and user.get('is_admin') == 1)


def _wants_json():
    """AJAX / JSON 请求应返回 JSON 错误码，而非重定向到登录页。"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    if request.is_json:
        return True
    accept = request.headers.get('Accept', '')
    return 'application/json' in accept and 'text/html' not in accept


def login_required(view):
    """要求已登录，否则 JSON 请求返回 401、普通请求重定向登录页。"""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            if _wants_json():
                return jsonify(success=False, message='请先登录'), 401
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    """要求管理员，否则 JSON 请求返回 403、普通请求重定向登录页。"""
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not is_admin(user):
            if _wants_json():
                return jsonify(success=False, message='无权限'), 403
            return redirect(url_for('auth.login'))
        return view(*args, **kwargs)
    return wrapper
