#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from oj_modules.db_services import get_db_connection


def extract_includes_from_code(code):
    """
    从代码中提取 #include 的文件名
    支持 #include "xxx.h" 和 #include"xxx.h" 等格式（空格可选）
    返回文件名列表
    """
    pattern = r'#include\s*["\']([^"\']+\.(?:h|hpp|c|cpp))["\']'
    matches = re.findall(pattern, code)
    return matches


def get_user_repository_files_by_names(user_id, filenames):
    """
    根据文件名列表获取用户代码仓库中的文件内容
    返回 {filename: content} 字典
    """
    if not filenames:
        return {}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            placeholders = ','.join(['%s'] * len(filenames))
            sql = f"""
            SELECT filename, file_content
            FROM user_code_repository
            WHERE user_id = %s AND filename IN ({placeholders})
            """
            cursor.execute(sql, (user_id, *filenames))
            files = cursor.fetchall()
            return {f['filename']: f['file_content'] for f in files}
    except Exception as e:
        print(f"获取代码仓库文件失败: {e}")
        return {}
    finally:
        conn.close()
