#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""讨论区页面路由。

所有读写数据均由 JSON API 驱动；这里仅提供同一个主从工作台的规范 URL。
"""

from flask import Blueprint, jsonify, redirect, url_for

from backend.oj_modules.security.auth import login_required


forum_bp = Blueprint("forum", __name__)


@forum_bp.route("/forum", methods=["GET"])
@login_required
def forum_index():
    return jsonify(
        success=False,
        message="该页面由 React 前端提供",
        path="/forum",
    ), 406


@forum_bp.route("/forum/thread/<int:thread_id>", methods=["GET"])
@login_required
def view_thread(thread_id):
    return jsonify(
        success=False,
        message="该页面由 React 前端提供",
        path=f"/forum/{thread_id}",
    ), 406


@forum_bp.route("/forum/new", methods=["GET"])
@login_required
def create_thread():
    return redirect(url_for("forum.forum_index", compose="new"))
