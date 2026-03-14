#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import pymysql
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename
from config import AGENT_REPOSITORY_KNN_SCORE_THRESHOLD, AGENT_REPOSITORY_KNN_TOP_K

from oj_modules.db_services import get_db_connection, get_user_by_username
from oj_modules.repository_index_services import (
    create_repository_index_job,
    ensure_repository_index_tables,
    get_repository_index_job,
    get_latest_active_repository_index_job,
    list_repository_classes,
    request_cancel_repository_index_job,
    search_repository_chunks,
    update_repository_index_job,
)


repository_bp = Blueprint('repository', __name__)
_repository_build_index_task = None
try:
    _DEFAULT_REPOSITORY_SEARCH_TOP_K = max(1, int(AGENT_REPOSITORY_KNN_TOP_K))
except Exception:
    _DEFAULT_REPOSITORY_SEARCH_TOP_K = 1
try:
    _DEFAULT_REPOSITORY_SEARCH_SCORE_THRESHOLD = float(AGENT_REPOSITORY_KNN_SCORE_THRESHOLD)
except Exception:
    _DEFAULT_REPOSITORY_SEARCH_SCORE_THRESHOLD = 0.0


def init_repository_index_module(repository_build_index_task):
    global _repository_build_index_task
    _repository_build_index_task = repository_build_index_task
    try:
        ensure_repository_index_tables()
    except Exception:
        # 避免初始化失败阻断主站运行；真正调用接口时会再确保建表。
        pass


def current_user():
    username = session.get('username')
    if not username:
        return None
    return get_user_by_username(username)


@repository_bp.route('/code_repository')
def code_repository():
    user = current_user()
    if not user:
        return redirect(url_for('auth.login'))
    return render_template('code_repository.html', user=user)


@repository_bp.route('/api/repository/files', methods=['GET'])
def get_repository_files():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT id, filename, file_size, created_at, updated_at
            FROM user_code_repository
            WHERE user_id = %s
            ORDER BY filename
            """
            cursor.execute(sql, (user['id'],))
            files = cursor.fetchall()

            for file in files:
                file['created_at'] = file['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                file['updated_at'] = file['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
                file['file_size_kb'] = round(file['file_size'] / 1024, 2) if file['file_size'] > 0 else 0

            return jsonify(success=True, files=files)
    except Exception as e:
        return jsonify(success=False, message=f"获取文件列表失败: {str(e)}"), 500
    finally:
        conn.close()


@repository_bp.route('/api/repository/file/<int:file_id>', methods=['GET'])
def get_repository_file(file_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            SELECT filename, file_content
            FROM user_code_repository
            WHERE id = %s AND user_id = %s
            """
            cursor.execute(sql, (file_id, user['id']))
            file_data = cursor.fetchone()

            if not file_data:
                return jsonify(success=False, message="文件不存在"), 404

            return jsonify(success=True, filename=file_data['filename'], content=file_data['file_content'])
    except Exception as e:
        return jsonify(success=False, message=f"获取文件失败: {str(e)}"), 500
    finally:
        conn.close()


@repository_bp.route('/api/repository/file', methods=['POST'])
def save_repository_file():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    data = request.get_json() or {}
    filename = data.get('filename', '').strip()
    content = data.get('content', '')
    file_id = data.get('file_id')

    if not filename:
        return jsonify(success=False, message="文件名不能为空"), 400

    if not filename.endswith(('.h', '.hpp', '.c', '.cpp')):
        return jsonify(success=False, message="只允许上传 .h, .hpp, .c, .cpp 文件"), 400

    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return jsonify(success=False, message="文件名只能包含字母、数字、下划线、连字符和点"), 400

    file_size = len(content.encode('utf-8'))
    if file_size > 100 * 1024:
        return jsonify(success=False, message="文件大小不能超过100KB"), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if file_id:
                sql = """
                UPDATE user_code_repository
                SET filename = %s, file_content = %s, file_size = %s
                WHERE id = %s AND user_id = %s
                """
                cursor.execute(sql, (filename, content, file_size, file_id, user['id']))

                if cursor.rowcount == 0:
                    return jsonify(success=False, message="文件不存在或无权限"), 404

                message = "文件更新成功"
            else:
                sql = """
                INSERT INTO user_code_repository (user_id, filename, file_content, file_size)
                VALUES (%s, %s, %s, %s)
                """
                try:
                    cursor.execute(sql, (user['id'], filename, content, file_size))
                    message = "文件创建成功"
                except pymysql.IntegrityError:
                    return jsonify(success=False, message="文件名已存在"), 409

            conn.commit()
            return jsonify(success=True, message=message)
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"保存文件失败: {str(e)}"), 500
    finally:
        conn.close()


@repository_bp.route('/api/repository/file/<int:file_id>', methods=['DELETE'])
def delete_repository_file(file_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "DELETE FROM user_code_repository WHERE id = %s AND user_id = %s"
            cursor.execute(sql, (file_id, user['id']))

            if cursor.rowcount == 0:
                return jsonify(success=False, message="文件不存在或无权限"), 404

            conn.commit()
            return jsonify(success=True, message="文件删除成功")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"删除文件失败: {str(e)}"), 500
    finally:
        conn.close()


@repository_bp.route('/api/repository/upload', methods=['POST'])
def upload_repository_file():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    if 'file' not in request.files:
        return jsonify(success=False, message="没有选择文件"), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify(success=False, message="没有选择文件"), 400

    filename = secure_filename(file.filename)

    if not filename.endswith(('.h', '.hpp', '.c', '.cpp')):
        return jsonify(success=False, message="只允许上传 .h, .hpp, .c, .cpp 文件"), 400

    try:
        content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify(success=False, message="文件编码错误，请使用UTF-8编码"), 400

    file_size = len(content.encode('utf-8'))
    if file_size > 100 * 1024:
        return jsonify(success=False, message="文件大小不能超过100KB"), 400

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
            INSERT INTO user_code_repository (user_id, filename, file_content, file_size)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            file_content = VALUES(file_content),
            file_size = VALUES(file_size)
            """
            cursor.execute(sql, (user['id'], filename, content, file_size))

            conn.commit()
            return jsonify(success=True, message="文件上传成功")
    except Exception as e:
        conn.rollback()
        return jsonify(success=False, message=f"上传文件失败: {str(e)}"), 500
    finally:
        conn.close()


@repository_bp.route('/api/repository/index/build', methods=['POST'])
def build_repository_index():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    if _repository_build_index_task is None:
        return jsonify(success=False, message="结构化整理任务未初始化"), 500

    try:
        payload = request.get_json(silent=True) or {}
        force_restart = bool(payload.get('force_restart'))
        active_job = get_latest_active_repository_index_job(user_id=user['id'])

        if active_job and not force_restart:
            return jsonify(
                success=False,
                need_confirm=True,
                active_job_id=int(active_job['id']),
                message='上一个整理任务正在运行，是否终止？',
            ), 409

        cancelled_job_id = None
        if active_job and force_restart:
            cancelled_job_id = int(active_job['id'])
            cancelled = request_cancel_repository_index_job(
                job_id=cancelled_job_id,
                user_id=user['id'],
                reason='用户确认终止上一个整理任务并重启。',
            )
            task_id = str((cancelled or {}).get('task_id') or '').strip()
            if task_id:
                try:
                    _repository_build_index_task.app.control.revoke(task_id, terminate=True, signal='SIGTERM')
                except Exception:
                    # revoke 失败时依赖协作式 cancel 标记在任务内尽快退出
                    pass

        job_id = create_repository_index_job(user['id'])
        async_result = _repository_build_index_task.delay(user['id'], job_id)
        update_repository_index_job(
            job_id,
            task_id=str(async_result.id),
            cancel_requested=0,
        )
        message = '已开始结构化整理'
        if cancelled_job_id is not None:
            message = f'已终止任务 #{cancelled_job_id}，并开始新的结构化整理'
        return jsonify(
            success=True,
            message=message,
            job_id=job_id,
            task_id=async_result.id,
            replaced_job_id=cancelled_job_id,
        )
    except Exception as e:
        return jsonify(success=False, message=f"启动结构化整理失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/rebuild_file', methods=['POST'])
def rebuild_repository_index_for_file():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    if _repository_build_index_task is None:
        return jsonify(success=False, message="结构化整理任务未初始化"), 500

    try:
        payload = request.get_json(silent=True) or {}
        file_id = int(payload.get('file_id') or 0)
        force_restart = bool(payload.get('force_restart'))
        if file_id <= 0:
            return jsonify(success=False, message='file_id 非法'), 400

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, filename
                    FROM user_code_repository
                    WHERE user_id = %s AND id = %s
                    LIMIT 1
                    """,
                    (int(user['id']), int(file_id)),
                )
                target_file = cursor.fetchone()
        finally:
            conn.close()

        if not target_file:
            return jsonify(success=False, message='文件不存在或无权限'), 404

        active_job = get_latest_active_repository_index_job(user_id=user['id'])
        if active_job and not force_restart:
            return jsonify(
                success=False,
                need_confirm=True,
                active_job_id=int(active_job['id']),
                message='上一个整理任务正在运行，是否终止？',
            ), 409

        cancelled_job_id = None
        if active_job and force_restart:
            cancelled_job_id = int(active_job['id'])
            cancelled = request_cancel_repository_index_job(
                job_id=cancelled_job_id,
                user_id=user['id'],
                reason='用户确认终止上一个整理任务并重启。',
            )
            task_id = str((cancelled or {}).get('task_id') or '').strip()
            if task_id:
                try:
                    _repository_build_index_task.app.control.revoke(task_id, terminate=True, signal='SIGTERM')
                except Exception:
                    pass

        job_id = create_repository_index_job(user['id'])
        async_result = _repository_build_index_task.delay(user['id'], job_id, int(file_id))
        update_repository_index_job(
            job_id,
            task_id=str(async_result.id),
            cancel_requested=0,
        )
        message = f"已开始重建文件索引：{target_file['filename']}"
        if cancelled_job_id is not None:
            message = f'已终止任务 #{cancelled_job_id}，并开始重建文件索引：{target_file["filename"]}'
        return jsonify(
            success=True,
            message=message,
            job_id=job_id,
            task_id=async_result.id,
            file_id=int(file_id),
            filename=target_file['filename'],
            replaced_job_id=cancelled_job_id,
        )
    except Exception as e:
        return jsonify(success=False, message=f"启动单文件索引重建失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/status/<int:job_id>', methods=['GET'])
def get_repository_index_status(job_id):
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        row = get_repository_index_job(job_id=job_id, user_id=user['id'])
        if not row:
            return jsonify(success=False, message='任务不存在'), 404
        return jsonify(success=True, job=row)
    except Exception as e:
        return jsonify(success=False, message=f"获取任务状态失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/status/active', methods=['GET'])
def get_active_repository_index_status():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    try:
        row = get_latest_active_repository_index_job(user_id=user['id'])
        if not row:
            return jsonify(success=True, has_active=False, job=None)
        return jsonify(success=True, has_active=True, job=row)
    except Exception as e:
        return jsonify(success=False, message=f"获取活跃任务失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/search', methods=['POST'])
def search_repository_index():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401

    data = request.get_json() or {}
    query = str(data.get('query') or '').strip()
    if not query:
        return jsonify(success=False, message='query 不能为空'), 400
    top_k = data.get('top_k', _DEFAULT_REPOSITORY_SEARCH_TOP_K)
    score_threshold = data.get('score_threshold', _DEFAULT_REPOSITORY_SEARCH_SCORE_THRESHOLD)

    try:
        result = search_repository_chunks(
            user_id=user['id'],
            query=query,
            top_k=top_k,
            score_threshold=score_threshold,
        )
        return jsonify(success=True, **result)
    except Exception as e:
        return jsonify(success=False, message=f"检索失败: {str(e)}"), 500


@repository_bp.route('/api/repository/index/classes', methods=['GET'])
def get_repository_classes():
    user = current_user()
    if not user:
        return jsonify(success=False, message="未登录"), 401
    limit = request.args.get('limit', 300)
    try:
        classes = list_repository_classes(user_id=user['id'], limit=limit)
        return jsonify(success=True, classes=classes, count=len(classes))
    except Exception as e:
        return jsonify(success=False, message=f"获取类结构失败: {str(e)}"), 500
