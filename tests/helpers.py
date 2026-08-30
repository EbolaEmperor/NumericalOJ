# -*- coding: utf-8 -*-
"""测试数据工厂。所有写库走 db_services / 直接 SQL，配合 conftest 的 reset。"""
import hashlib

from backend.oj_modules import db_services

_counter = {'n': 0}


def _uniq(prefix):
    _counter['n'] += 1
    return f"{prefix}{_counter['n']}"


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_class(class_en=None, class_cn=None):
    """确保 class_table 里有一行（不建物理动态表）。返回 (class_en, class_cn)。"""
    class_en = class_en or _uniq('Cgrp')
    class_cn = class_cn or class_en
    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT IGNORE INTO class_table (class_en, class_cn, class_cnt) "
                "VALUES (%s,%s,0)", (class_en, class_cn))
            # 物理动态班级表（作业表），与 add_class_ajax 建的结构一致
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS `{class_en}` ("
                "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, problem_id INT, "
                "ddl DATETIME, complete_cnt INT DEFAULT 0, problem_title TEXT, "
                "ranking_competition_id INT DEFAULT NULL) "
                "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
        conn.commit()
    finally:
        conn.close()
    return class_en, class_cn


def make_user(username=None, password='pw123456', email=None,
              class_en='Cclass1', class_cn='测试班级', is_admin=False):
    """创建带一条初始班级关系的用户；默认加入种子班级 Cclass1。"""
    username = username or _uniq('user')
    email = email or f"{username}@example.com"
    make_class(class_en, class_cn)
    db_services.create_user(
        username, sha256_hex(password), email,
        {'class_en': class_en, 'class_cn': class_cn})
    if is_admin:
        conn = db_services.get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_admin=1 WHERE username=%s", (username,))
            conn.commit()
        finally:
            conn.close()
    return db_services.get_user_by_username(username)


def make_problem(title=None, content='题面', lang='python', type=1,
                 time_limit_ms=2000, submission_limit=10, test_code='',
                 forbidden_func='', initial_code=''):
    """创建题目，返回 problem id。"""
    title = title or _uniq('题目')
    db_services.create_problem(
        title=title, content=content, initial_code=initial_code,
        test_code=test_code, forbidden_func=forbidden_func, type=type,
        lang=lang, time_limit_ms=time_limit_ms, submission_limit=submission_limit)
    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM problems WHERE title=%s ORDER BY id DESC LIMIT 1", (title,))
            row = cur.fetchone()
    finally:
        conn.close()
    return row['id']


def make_submission(problem_id, username, code='print(1)', score=0,
                    test_points=None, problem_title='题目', status=None):
    """创建提交，返回 submission id。"""
    sid = db_services.create_submission(
        problem_id, problem_title, username, code, score, test_points or [])
    if status:
        db_services.update_submission_status(sid, status)
    return sid
