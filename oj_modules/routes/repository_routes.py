#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

import pymysql
from flask import Blueprint, jsonify, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename

from oj_modules.db_services import get_db_connection, get_user_by_username


repository_bp = Blueprint('repository', __name__)


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

    data = request.get_json()
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
