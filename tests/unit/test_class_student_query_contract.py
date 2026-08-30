# -*- coding: utf-8 -*-

import re
from pathlib import Path

from backend.oj_modules import db_services


ROOT = Path(__file__).resolve().parents[2]
HOMEWORK_QUERY_SOURCE = '\n'.join(
    (
        ROOT / 'backend' / 'oj_modules' / relative_path
    ).read_text(encoding='utf-8')
    for relative_path in (
        'routes/homework_routes.py',
        'homework/plagiarism.py',
        'tasks/homework_admin_tasks.py',
    )
)


class _Cursor:
    def __init__(self):
        self.executions = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        self.executions.append((' '.join(str(sql).split()), params))

    def fetchall(self):
        return []


class _Connection:
    def __init__(self, cursor):
        self.cursor_object = cursor
        self.closed = False

    def cursor(self):
        return self.cursor_object

    def close(self):
        self.closed = True


def test_homework_student_queries_exclude_administrator_memberships():
    membership_queries = re.findall(
        r'(?:FROM|JOIN)\s+user_class_map\s+m\b',
        HOMEWORK_QUERY_SOURCE,
        flags=re.IGNORECASE,
    )
    student_queries = re.findall(
        r'AND\s+u\.is_admin\s*=\s*0',
        HOMEWORK_QUERY_SOURCE,
        flags=re.IGNORECASE,
    )

    # 另含普通题与打榜赛作业的截止前完成人数查询。
    assert len(membership_queries) == 6
    assert len(student_queries) == len(membership_queries)


def test_class_scoped_detection_excludes_administrators(monkeypatch):
    cursor = _Cursor()
    conn = _Connection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    rows = db_services.get_filtered_submissions_for_detection(
        class_en='C1',
        deduplicate=False,
    )

    assert rows == []
    assert conn.closed is True
    sql, params = cursor.executions[-1]
    assert 'JOIN users _u ON _u.username = s.username' in sql
    assert 'JOIN user_class_map _ucm ON _ucm.user_id = _u.id' in sql
    assert '_ucm.class_en = %s' in sql
    assert '_u.is_admin = 0' in sql
    assert params == ['C1']


def test_multi_class_student_lookup_excludes_administrators(monkeypatch):
    cursor = _Cursor()
    conn = _Connection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    rows = db_services.get_users_in_classes(['C2', 'C1'])

    assert rows == []
    assert conn.closed is True
    sql, params = cursor.executions[-1]
    assert 'JOIN user_class_map ucm ON ucm.user_id = u.id' in sql
    assert 'u.is_admin = 0' in sql
    assert params == ('C2', 'C1')
