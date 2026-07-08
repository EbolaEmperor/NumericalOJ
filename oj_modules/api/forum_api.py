#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import math

from flask import Blueprint, request

from oj_modules.api.helpers import json_error, json_success, public_user
from oj_modules.auth_helpers import current_user
from oj_modules.db_services import get_db_connection
from oj_modules.routes.forum_routes import (
    get_last_10_days_forum_counts,
    get_today_forum_counts,
    render_markdown_with_highlighting,
)


forum_api_bp = Blueprint("forum_api", __name__, url_prefix="/api")


@forum_api_bp.route("/forum", methods=["GET"])
def forum_list():
    user = current_user()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        limit = int(request.args.get("limit", 50))
    except (TypeError, ValueError):
        limit = 50
    limit = min(max(limit, 1), 100)
    offset = (page - 1) * limit

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM forum_threads")
            total = int((cursor.fetchone() or {}).get("total") or 0)
            cursor.execute(
                """
                SELECT t.*, u.username
                FROM forum_threads t
                LEFT JOIN users u ON u.id = t.user_id
                ORDER BY t.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (limit, offset),
            )
            threads = cursor.fetchall() or []
    finally:
        conn.close()

    total_submissions, total_accepted = get_today_forum_counts()
    last_10_days, daily_counts = get_last_10_days_forum_counts()
    for thread in threads:
        thread["url"] = f"/forum/thread/{thread.get('id')}"

    return json_success(
        user=public_user(user),
        threads=threads,
        total_submissions=total_submissions,
        total_accepted=total_accepted,
        last_10_days=last_10_days,
        daily_counts=daily_counts,
        count=len(threads),
        total=total,
        page=page,
        limit=limit,
        total_pages=max(1, math.ceil(total / limit)) if total else 0,
    )


@forum_api_bp.route("/forum/threads/<int:thread_id>", methods=["GET"])
def forum_thread(thread_id):
    user = current_user()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT t.*, u.username
                FROM forum_threads t
                LEFT JOIN users u ON u.id = t.user_id
                WHERE t.id = %s
                """,
                (thread_id,),
            )
            thread = cursor.fetchone()
            if not thread:
                return json_error("帖子不存在", 404)

            cursor.execute(
                """
                SELECT r.*, u.username
                FROM forum_replies r
                LEFT JOIN users u ON u.id = r.user_id
                WHERE r.thread_id = %s
                ORDER BY r.created_at ASC
                """,
                (thread_id,),
            )
            replies = cursor.fetchall() or []
    finally:
        conn.close()

    thread["rendered_content"] = render_markdown_with_highlighting(thread.get("content") or "")
    for reply in replies:
        reply["rendered_content"] = render_markdown_with_highlighting(reply.get("content") or "")

    return json_success(
        user=public_user(user),
        thread=thread,
        replies=replies,
        reply_count=len(replies),
    )


@forum_api_bp.route("/forum/new-context", methods=["GET"])
def forum_new_context():
    user = current_user()
    if not user:
        return json_error("请先登录", 401)
    return json_success(
        user=public_user(user),
        action="/forum/new",
        method="POST",
        fields=[
            {"name": "title", "type": "text", "required": True},
            {"name": "content", "type": "markdown", "required": True},
        ],
    )
