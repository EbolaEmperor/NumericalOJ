#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta

import markdown
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from oj_modules.db_services import get_db_connection, get_user_by_username
from oj_modules.markdown_utils import sanitize_html


forum_bp = Blueprint('forum', __name__)


from oj_modules.auth_helpers import current_user, is_admin


def get_today_forum_counts():
    today = datetime.today().date()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) FROM forum_threads
                WHERE DATE(created_at) = %s
                """,
                (today,),
            )
            total_threads = cursor.fetchone()['COUNT(*)']

            cursor.execute(
                """
                SELECT COUNT(*) FROM forum_replies
                WHERE DATE(created_at) = %s
                """,
                (today,),
            )
            total_replies = cursor.fetchone()['COUNT(*)']

        return total_threads, total_replies
    finally:
        conn.close()


def get_last_10_days_forum_counts():
    today = datetime.today().date()
    last_10_days = [(today + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(-9, 1)]
    counts = {day: 0 for day in last_10_days}

    # 单条范围查询 + GROUP BY 取代过去的 10 次 COUNT；WHERE 用 created_at 范围（非 DATE() 包列），
    # 可命中 idx_forum_replies_created 索引。
    start_dt = datetime.combine(today + timedelta(days=-9), datetime.min.time())
    end_dt = datetime.combine(today + timedelta(days=1), datetime.min.time())
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT DATE(created_at) AS d, COUNT(*) AS c
                FROM forum_replies
                WHERE created_at >= %s AND created_at < %s
                GROUP BY DATE(created_at)
                """,
                (start_dt, end_dt),
            )
            for row in cursor.fetchall():
                key = row['d'].strftime('%Y-%m-%d') if hasattr(row['d'], 'strftime') else str(row['d'])
                if key in counts:
                    counts[key] = row['c']
    finally:
        conn.close()

    return last_10_days, [counts[day] for day in last_10_days]


def render_markdown_with_highlighting(text):
    # 去掉 md_in_html（最易透传裸 HTML 的扩展），并对输出做白名单消毒，防存储型 XSS。
    md = markdown.Markdown(extensions=['fenced_code', 'codehilite', 'extra', 'tables'])
    return sanitize_html(md.convert(text))


@forum_bp.route('/forum')
def forum_index():
    user = current_user()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM forum_threads ORDER BY created_at DESC"
            cursor.execute(sql)
            threads = cursor.fetchall()
    finally:
        conn.close()

    total_submissions, total_accepted = get_today_forum_counts()
    last_10_days, daily_counts = get_last_10_days_forum_counts()

    return render_template(
        'forum/index.html',
        threads=threads,
        user=user,
        total_submissions=total_submissions,
        total_accepted=total_accepted,
        last_10_days=last_10_days,
        daily_counts=daily_counts,
    )


@forum_bp.route('/forum/thread/<int:thread_id>', methods=['GET', 'POST'])
def view_thread(thread_id):
    user = current_user()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM forum_threads WHERE id = %s"
            cursor.execute(sql, (thread_id,))
            thread = cursor.fetchone()

            if not thread:
                flash('帖子不存在', 'danger')
                return redirect(url_for('forum.forum_index'))

            sql = "SELECT * FROM forum_replies WHERE thread_id = %s ORDER BY created_at ASC"
            cursor.execute(sql, (thread_id,))
            replies = cursor.fetchall()

            thread['content'] = render_markdown_with_highlighting(thread['content'])
            for reply in replies:
                reply['content'] = render_markdown_with_highlighting(reply['content'])
    finally:
        conn.close()

    if request.method == 'POST':
        content = request.form.get('content').strip()

        if not content:
            flash('回复内容不能为空', 'danger')
            return redirect(url_for('forum.view_thread', thread_id=thread_id))

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """INSERT INTO forum_replies (thread_id, content, user_id)
                         VALUES (%s, %s, %s)"""
                cursor.execute(sql, (thread_id, content, user['id']))
            conn.commit()
            flash('回复成功', 'success')
        finally:
            conn.close()

        return redirect(url_for('forum.view_thread', thread_id=thread_id))

    return render_template('forum/thread.html', thread=thread, replies=replies, user=user)


@forum_bp.route('/forum/new', methods=['GET', 'POST'])
def create_thread():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        title = request.form.get('title').strip()
        content = request.form.get('content').strip()

        if not title or not content:
            flash('标题和内容不能为空', 'danger')
            return redirect(url_for('forum.create_thread'))

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                sql = """INSERT INTO forum_threads (title, content, user_id)
                         VALUES (%s, %s, %s)"""
                cursor.execute(sql, (title, content, user['id']))
                thread_id = cursor.lastrowid
            conn.commit()
            flash('帖子创建成功', 'success')
        finally:
            conn.close()

        return redirect(url_for('forum.view_thread', thread_id=thread_id))

    return render_template('forum/create.html', user=user)


@forum_bp.route('/forum/reply/<int:thread_id>', methods=['POST'])
def reply_thread(thread_id):
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))

    content = request.form.get('content').strip()

    if not content:
        flash('回复内容不能为空', 'danger')
        return redirect(url_for('forum.view_thread', thread_id=thread_id))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO forum_replies (thread_id, content, user_id)
                     VALUES (%s, %s, %s)"""
            cursor.execute(sql, (thread_id, content, user['id']))
        conn.commit()
        flash('回复成功', 'success')
    finally:
        conn.close()

    return redirect(url_for('forum.view_thread', thread_id=thread_id))
