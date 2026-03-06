#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import atexit
import json
import os
import queue
import threading
import time

import pymysql
from flask import session

from config import MYSQL_PASSWORD, MYSQL_USERNAME
from oj_modules.ai_utils import _normalize_ai_code_issues


CLASS_ADJUST_FLAG_KEY = 'class_adjust_enabled'
_settings_table_ready = False


def _create_raw_mysql_connection():
    return pymysql.connect(
        host='localhost',
        user=MYSQL_USERNAME,
        password=MYSQL_PASSWORD,
        database='myojdb',
        charset='utf8mb4',
        connect_timeout=int(os.getenv('MYSQL_CONNECT_TIMEOUT', '5')),
        cursorclass=pymysql.cursors.DictCursor,
    )


class _PooledConnectionProxy:
    """
    连接代理：
    - 对外表现与 pymysql Connection 一致
    - close() 时将连接归还池，而不是实际断开
    """

    def __init__(self, pool, raw_conn):
        self._pool = pool
        self._raw_conn = raw_conn
        self._closed = False

    def __getattr__(self, item):
        return getattr(self._raw_conn, item)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._pool.release(self._raw_conn)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _MySQLConnectionPool:
    def __init__(self, min_size=2, max_size=6, wait_timeout=5, recycle_seconds=1200):
        self._min_size = max(1, int(min_size))
        self._max_size = max(self._min_size, int(max_size))
        self._wait_timeout = max(1, int(wait_timeout))
        self._recycle_seconds = max(60, int(recycle_seconds))

        self._idle = queue.Queue(maxsize=self._max_size)
        self._lock = threading.Lock()
        self._created = 0
        self._conn_birth = {}

        self._warm_up()
        atexit.register(self.close_idle_connections)

    def _warm_up(self):
        target = self._min_size
        for _ in range(target):
            try:
                conn = _create_raw_mysql_connection()
            except Exception:
                # 启动阶段不因预热失败中断，后续按需创建
                break
            with self._lock:
                conn_id = id(conn)
                self._conn_birth[conn_id] = time.time()
                self._idle.put_nowait(conn)
                self._created += 1

    def _should_recycle(self, conn):
        born_at = self._conn_birth.get(id(conn), 0)
        return (time.time() - born_at) >= self._recycle_seconds

    def _discard(self, conn):
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            self._conn_birth.pop(id(conn), None)
            if self._created > 0:
                self._created -= 1

    def _prepare_for_checkout(self, conn):
        if self._should_recycle(conn):
            self._discard(conn)
            new_conn = _create_raw_mysql_connection()
            with self._lock:
                self._created += 1
            return new_conn

        try:
            conn.ping(reconnect=True)
            return conn
        except Exception:
            self._discard(conn)
            new_conn = _create_raw_mysql_connection()
            with self._lock:
                self._created += 1
            return new_conn

    def acquire(self):
        conn = None
        with self._lock:
            if not self._idle.empty():
                conn = self._idle.get_nowait()
            elif self._created < self._max_size:
                conn = _create_raw_mysql_connection()
                self._created += 1

        if conn is None:
            try:
                conn = self._idle.get(timeout=self._wait_timeout)
            except queue.Empty as e:
                raise RuntimeError("MySQL 连接池耗尽，请稍后重试") from e

        prepared = self._prepare_for_checkout(conn)
        with self._lock:
            if id(prepared) not in self._conn_birth:
                self._conn_birth[id(prepared)] = time.time()
        return _PooledConnectionProxy(self, prepared)

    def release(self, conn):
        try:
            # 避免事务泄露到下一次使用
            conn.rollback()
        except Exception:
            self._discard(conn)
            return

        if self._should_recycle(conn):
            self._discard(conn)
            return

        try:
            self._idle.put_nowait(conn)
        except queue.Full:
            self._discard(conn)

    def close_idle_connections(self):
        while not self._idle.empty():
            conn = self._idle.get_nowait()
            try:
                conn.close()
            except Exception:
                pass
        with self._lock:
            self._conn_birth.clear()
            self._created = 0


_db_pool = _MySQLConnectionPool(
    min_size=int(os.getenv('MYSQL_POOL_MIN_SIZE', '2')),
    max_size=int(os.getenv('MYSQL_POOL_MAX_SIZE', '6')),
    wait_timeout=int(os.getenv('MYSQL_POOL_WAIT_TIMEOUT', '3')),
    recycle_seconds=int(os.getenv('MYSQL_POOL_RECYCLE_SECONDS', '1200')),
)


def get_db_connection():
    """返回一个连接池代理连接（close() 时归还池）。"""
    return _db_pool.acquire()


def ensure_settings_table():
    global _settings_table_ready
    if _settings_table_ready:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS site_settings (
                    k VARCHAR(64) PRIMARY KEY,
                    v VARCHAR(255)
                ) CHARACTER SET utf8mb4
                """
            )
        conn.commit()
        _settings_table_ready = True
    finally:
        conn.close()


def get_setting(key, default=None):
    ensure_settings_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT v FROM site_settings WHERE k=%s", (key,))
            row = cursor.fetchone()
            return (row and row.get('v')) if row else default
    finally:
        conn.close()


def set_setting(key, value):
    ensure_settings_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_settings (k, v) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE v=VALUES(v)
                """,
                (key, str(value))
            )
        conn.commit()
    finally:
        conn.close()


def is_class_adjust_enabled():
    val = get_setting(CLASS_ADJUST_FLAG_KEY, default='1')
    return str(val) == '1'


def get_user_by_username(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (username,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE id=%s"
            cursor.execute(sql, (user_id,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_current_user():
    if 'username' not in session:
        return None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (session['username'],))
            user = cursor.fetchone()
    finally:
        conn.close()
    return user


def get_user_by_email(email):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s"
            cursor.execute(sql, (email,))
            return cursor.fetchone()
    finally:
        conn.close()


def create_user(username, password_hash, email, user_class):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = 'INSERT INTO users (username, password_hash, email, class, class_cn) VALUES (%s, %s, %s, %s, %s)'
            cursor.execute(sql, (username, password_hash, email, user_class['class_en'], user_class['class_cn']))
        conn.commit()
        with conn.cursor() as cursor:
            sql = 'UPDATE class_table SET class_cnt=class_cnt+1 WHERE class_en=%s'
            cursor.execute(sql, (user_class['class_en'],))
        conn.commit()
        user = get_user_by_username(username)
        with conn.cursor() as cursor:
            sql = 'INSERT INTO user_class_map (user_id, class_en, is_primary) VALUES (%s, %s, %s)'
            cursor.execute(sql, (user['id'], user_class['class_en'], 1))
        conn.commit()
    finally:
        conn.close()


def get_user_classes(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
              SELECT m.class_en, ct.class_cn, m.is_primary
              FROM user_class_map m
              LEFT JOIN class_table ct ON m.class_en = ct.class_en
              WHERE m.user_id=%s
              ORDER BY m.is_primary DESC, m.class_en ASC
            """
            cursor.execute(sql, (user_id,))
            rows = cursor.fetchall()
            if rows and len(rows) > 0:
                return rows

            cursor.execute("SELECT class FROM users WHERE id=%s", (user_id,))
            u = cursor.fetchone()
            class_en = u.get('class')
            if not class_en:
                return []
            cursor.execute("SELECT class_en, class_cn FROM class_table WHERE class_en=%s", (class_en,))
            c = cursor.fetchone()
            if not c:
                return [{'class_en': class_en, 'class_cn': class_en, 'is_primary': 1}]
            return [{'class_en': c['class_en'], 'class_cn': c['class_cn'], 'is_primary': 1}]
    finally:
        conn.close()


def get_all_classes():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table ORDER BY class_cn ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def get_all_classes_except_admin():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_en != 'Cadmin' ORDER BY class_cn ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def get_class_by_en(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_en=%s"
            cursor.execute(sql, (class_en,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_class_by_cn(class_cn):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT class_en, class_cn FROM class_table WHERE class_cn=%s"
            cursor.execute(sql, (class_cn,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_all_problems():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type,lang,max_score,time_limit_ms FROM problems ORDER BY id ASC"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def get_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,content,initial_code,test_code,cnt,forbidden_func,type,lang,max_score,time_limit_ms,submission_limit FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_problem_title(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id,title,cnt,type,lang,max_score,time_limit_ms,submission_limit FROM problems WHERE id=%s"
            cursor.execute(sql, (problem_id,))
            return cursor.fetchone()
    finally:
        conn.close()


def create_problem(title, content, initial_code='', test_code='', forbidden_func='', type=1, lang='matlab', time_limit_ms=2000, submission_limit=10):
    conn = get_db_connection()
    try:
        max_score = (0 if int(type) == 1 else 5)
        with conn.cursor() as cursor:
            sql = """INSERT INTO problems
                     (title, content, initial_code, test_code, forbidden_func, type, lang, max_score, time_limit_ms, submission_limit)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (title, content, initial_code, test_code, forbidden_func, type, lang, max_score, time_limit_ms, submission_limit))
        conn.commit()
    finally:
        conn.close()


def upsert_user_problem_max_score(user_id, problem_id, score):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO max_score (userid, problem_id, score)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE score=VALUES(score)
                """,
                (user_id, problem_id, score),
            )
        conn.commit()
    finally:
        conn.close()


def upsert_user_problem_max_score_if_higher(user_id, problem_id, score):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO max_score (userid, problem_id, score)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                score = IF(score < VALUES(score), VALUES(score), score)
                """,
                (user_id, problem_id, score),
            )
        conn.commit()
    finally:
        conn.close()


def delete_user_problem_max_score(user_id, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM max_score WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
        conn.commit()
    finally:
        conn.close()


def insert_user_problem_ac_record_if_absent(user_id, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT IGNORE INTO ac_record (userid, problem_id, is_ac)
                VALUES (%s, %s, 1)
                """,
                (user_id, problem_id),
            )
            inserted = cursor.rowcount > 0
        conn.commit()
        return inserted
    finally:
        conn.close()


def update_problem(problem_id, new_title, new_content, new_initial_code='', new_test_code='', new_forbidden_func='', new_lang='matlab', new_time_limit_ms=None, new_submission_limit=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """UPDATE problems
                     SET title=%s, content=%s, initial_code=%s, test_code=%s, forbidden_func=%s, lang=%s, time_limit_ms=%s, submission_limit=%s
                     WHERE id=%s"""
            cursor.execute(sql, (new_title, new_content, new_initial_code, new_test_code, new_forbidden_func, new_lang, new_time_limit_ms, new_submission_limit, problem_id))
        conn.commit()
    finally:
        conn.close()


def create_submission(problem_id, problem_title, username, code, score, test_points):
    conn = get_db_connection()
    try:
        problem = get_problem(problem_id)
        problem_type = problem['type']

        if problem_type == 2:
            with conn.cursor() as cursor:
                test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_points])
                sql = "UPDATE submissions SET status='Unaccepted' WHERE username=%s AND problem_id=%s"
                cursor.execute(sql, (username, problem_id))
                sql = "SELECT COUNT(*) FROM submissions WHERE username=%s AND problem_id=%s"
                cursor.execute(sql, (username, problem_id))
                total_submissions = cursor.fetchone()['COUNT(*)']
                if total_submissions == 0:
                    user = get_user_by_username(username)
                    if user["is_admin"] != 1:
                        class_en = user["class"]
                        sql = f"UPDATE {class_en} SET complete_cnt=complete_cnt+1 WHERE problem_id={problem_id}"
                        cursor.execute(sql)
                    sql = f"UPDATE problems SET cnt=cnt+1 WHERE id={problem_id}"
                    cursor.execute(sql)
            conn.commit()

        with conn.cursor() as cursor:
            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_points])
            sql = """INSERT INTO submissions (problem_id, username, code, score, test_points, status, problem_title, problem_type)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (
                problem_id,
                username,
                code,
                score,
                test_points_str,
                "Pending",
                problem_title,
                problem_type,
            ))
        conn.commit()
        subid = cursor.lastrowid
        return subid
    finally:
        conn.close()


def get_submissions_by_user_and_problem(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s AND problem_id=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username, problem_id))
            submissions = cursor.fetchall()
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
                submission['problem_type'] = submission['problem_type']
            return submissions
    finally:
        conn.close()


def get_submission_summaries_by_user_and_problem(username, problem_id):
    """
    仅返回列表页展示所需字段，避免把 code/test_points 大字段拉出。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, problem_id, username, score, status, problem_title, created_at
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
            """
            cursor.execute(sql, (username, problem_id))
            return cursor.fetchall()
    finally:
        conn.close()


def get_submission_summaries_by_user_and_problem_paginated(username, problem_id, page=1, per_page=30):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = """
                SELECT COUNT(*) AS total
                FROM submissions
                WHERE username=%s AND problem_id=%s
            """
            cursor.execute(count_sql, (username, problem_id))
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            data_sql = """
                SELECT id, problem_id, username, score, status, problem_title, created_at
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (username, problem_id, per_page, offset))
            return cursor.fetchall(), total_pages
    finally:
        conn.close()


def get_submissions_by_user(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username,))
            submissions = cursor.fetchall()
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
            return submissions
    finally:
        conn.close()


def get_latest_submission_code_by_user_and_problem(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, code, score
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
                LIMIT 1
            """
            cursor.execute(sql, (username, problem_id))
            return cursor.fetchone()
    finally:
        conn.close()


def get_submission_by_id(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM submissions WHERE id=%s"
            cursor.execute(sql, (submission_id,))
            submission = cursor.fetchone()
            if submission and submission['test_points']:
                submission['test_points'] = [
                    json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                ]
            return submission
    finally:
        conn.close()


def get_cached_ai_code_marks_for_submission(submission):
    if not submission or not isinstance(submission, dict):
        return None

    raw = submission.get('ai_code_marks_json')
    if not raw:
        return None

    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as e:
        print(f"[AI Code Marks] 缓存 JSON 解析失败(submission_id={submission.get('id')}): {e}")
        return None

    if not isinstance(data, dict):
        return None

    code_used_raw = data.get('code_used')
    if code_used_raw is None:
        code_used_raw = submission.get('code') or ''
    code_used = str(code_used_raw).replace('\r\n', '\n').replace('\r', '\n')
    issues = _normalize_ai_code_issues(data.get('issues') or [], code_used, max_issues=8)
    summary = str(data.get('summary') or '').strip()
    cached_at = str(data.get('generated_at') or '').strip()

    return {
        "success": True,
        "issues": issues,
        "summary": summary,
        "code_used": code_used,
        "cached": True,
        "cached_at": cached_at,
    }


def save_submission_ai_code_marks_json(submission_id, payload):
    if not payload or not isinstance(payload, dict):
        return False

    payload_text = json.dumps(payload, ensure_ascii=False)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET ai_code_marks_json=%s WHERE id=%s"
            cursor.execute(sql, (payload_text, submission_id))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        msg = str(e)
        if ('ai_code_marks_json' in msg) and ('Unknown column' in msg or '1054' in msg):
            print("[AI Code Marks] 缺少 ai_code_marks_json 字段，已跳过缓存写入。")
            return False
        raise
    finally:
        conn.close()


def get_user_submission_count(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT submission_count FROM submission_limits WHERE username=%s AND problem_id=%s"
            cursor.execute(sql, (username, problem_id))
            result = cursor.fetchone()
            return result['submission_count'] if result else 0
    finally:
        conn.close()


def increment_submission_count(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """INSERT INTO submission_limits (username, problem_id, submission_count)
                     VALUES (%s, %s, 1)
                     ON DUPLICATE KEY UPDATE
                     submission_count = submission_count + 1,
                     updated_at = CURRENT_TIMESTAMP"""
            cursor.execute(sql, (username, problem_id))
        conn.commit()
    finally:
        conn.close()


def can_submit(username, problem_id, max_submissions=10):
    current_count = get_user_submission_count(username, problem_id)
    return current_count < max_submissions


def get_remaining_submissions(username, problem_id, max_submissions=10):
    current_count = get_user_submission_count(username, problem_id)
    return max(0, max_submissions - current_count)


def update_submission_status(submission_id, new_status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET status=%s WHERE id=%s"
            cursor.execute(sql, (new_status, submission_id))
        conn.commit()
    finally:
        conn.close()


def update_submission_evaluation(submission_id, test_point_statuses, score, status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_point_statuses])
            sql = """UPDATE submissions
                     SET test_points=%s, score=%s, status=%s
                     WHERE id=%s"""
            cursor.execute(sql, (test_points_str, score, status, submission_id))
        conn.commit()
    finally:
        conn.close()
