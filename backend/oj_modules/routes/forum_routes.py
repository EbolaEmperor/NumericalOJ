#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""讨论区页面路由。

所有读写数据均由 JSON API 驱动；这里仅提供同一个主从工作台的规范 URL。
"""

from flask import Blueprint, redirect, render_template, request, url_for

from backend.oj_modules.security.auth import current_user, login_required


forum_bp = Blueprint("forum", __name__)


@forum_bp.route("/forum", methods=["GET"])
@login_required
def forum_index():
    return render_template(
        "forum/index.html",
        user=current_user(),
        initial_thread_id=None,
        open_composer=request.args.get("compose") == "new",
    )


@forum_bp.route("/forum/thread/<int:thread_id>", methods=["GET"])
@login_required
def view_thread(thread_id):
    return render_template(
        "forum/index.html",
        user=current_user(),
        initial_thread_id=thread_id,
        open_composer=False,
    )


@forum_bp.route("/forum/new", methods=["GET"])
@login_required
def create_thread():
    return redirect(url_for("forum.forum_index", compose="new"))
