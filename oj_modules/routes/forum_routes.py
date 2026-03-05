#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta

import markdown
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

from oj_modules.db_services import get_db_connection, get_user_by_username


forum_bp = Blueprint('forum', __name__)


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


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
    counts = {}

    conn = get_db_connection()
    try:
        for day in last_10_days:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM forum_replies
                    WHERE DATE(created_at) = %s
                    """,
                    (day,),
                )
                count = cursor.fetchone()['COUNT(*)']
                counts[day] = count
    finally:
        conn.close()

    return last_10_days, [counts[day] for day in last_10_days]


def render_markdown_with_highlighting(text):
    md = markdown.Markdown(extensions=['fenced_code', 'codehilite', 'extra', 'md_in_html', 'tables'])
    return md.convert(text)


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
        'forum_index.html',
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

    return render_template('view_thread.html', thread=thread, replies=replies, user=user)


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
            conn.commit()
            flash('帖子创建成功', 'success')
        finally:
            conn.close()

        return redirect(url_for('forum.forum_index'))

    return render_template('create_thread.html', user=user)


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
