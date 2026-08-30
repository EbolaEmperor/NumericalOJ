# -*- coding: utf-8 -*-

import inspect

import pytest

from backend.oj_modules.classroom import membership as memberships


class _FakeCursor:
    def __init__(
            self,
            *,
            user_exists=True,
            membership_exists=False,
            membership_count=0,
            class_count_rowcount=1,
            class_exists=True,
            class_count=0,
            is_admin=False,
            fail_when=None,
    ):
        self.user_exists = user_exists
        self.membership_exists = membership_exists
        self.membership_count = membership_count
        self.class_count_rowcount = class_count_rowcount
        self.class_exists = class_exists
        self.class_count = class_count
        self.is_admin = is_admin
        self.fail_when = fail_when
        self.calls = []
        self.rowcount = 0
        self._fetchone_result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        normalized = ' '.join(str(sql).split())
        self.calls.append((normalized, params))
        if self.fail_when and self.fail_when in normalized:
            raise RuntimeError('模拟事务中途失败')

        self.rowcount = 1
        if normalized.startswith('SELECT id, is_admin FROM users'):
            self._fetchone_result = (
                {'id': params[0], 'is_admin': int(self.is_admin)}
                if self.user_exists else None
            )
        elif normalized.startswith('SELECT 1 FROM user_class_map'):
            self._fetchone_result = (
                {'exists': 1} if self.membership_exists else None
            )
        elif normalized.startswith('SELECT COUNT(*) AS membership_count'):
            self._fetchone_result = {
                'membership_count': self.membership_count,
            }
        elif normalized.startswith('DELETE FROM user_class_map'):
            self.rowcount = 1 if self.membership_exists else 0
        elif normalized.startswith('SELECT class_cnt FROM class_table'):
            self._fetchone_result = (
                {'class_cnt': self.class_count}
                if self.class_exists else None
            )
        elif normalized.startswith('UPDATE class_table SET class_cnt'):
            self.rowcount = self.class_count_rowcount

    def fetchone(self):
        result = self._fetchone_result
        self._fetchone_result = None
        return result


class _FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commit_count += 1

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


def _install_connection(monkeypatch, cursor):
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(memberships, 'get_db_connection', lambda: conn)
    return conn


def _sql_calls(cursor):
    return [sql for sql, _params in cursor.calls]


def test_add_membership_updates_relation_and_count_in_one_transaction(monkeypatch):
    cursor = _FakeCursor()
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.add_class_membership(7, 'C1') is True

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert conn.closed is True
    sqls = _sql_calls(cursor)
    assert sqls[0] == (
        'SELECT id, is_admin FROM users WHERE id=%s FOR UPDATE'
    )
    assert sqls[1].startswith('SELECT 1 FROM user_class_map')
    assert sqls[2] == (
        'INSERT INTO user_class_map (user_id, class_en) VALUES (%s, %s)'
    )
    assert sqls[3] == (
        'UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s'
    )


def test_add_membership_rolls_back_relation_when_count_update_fails(monkeypatch):
    cursor = _FakeCursor(fail_when='UPDATE class_table SET class_cnt')
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(RuntimeError, match='模拟事务中途失败'):
        memberships.add_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert conn.closed is True


def test_add_membership_rolls_back_when_target_class_disappears(monkeypatch):
    cursor = _FakeCursor(class_count_rowcount=0, class_exists=False)
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(memberships.MembershipNotFoundError, match='班级不存在'):
        memberships.add_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_duplicate_membership_does_not_change_count(monkeypatch):
    cursor = _FakeCursor(membership_exists=True, membership_count=1)
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.add_class_membership(7, 'C1') is False

    assert conn.commit_count == 1
    assert not any('UPDATE class_table' in sql for sql in _sql_calls(cursor))
    assert not any(sql.startswith('INSERT') for sql in _sql_calls(cursor))


@pytest.mark.parametrize(
    ('user_exists', 'membership_exists'),
    ((False, False), (True, False)),
)
def test_remove_missing_membership_is_idempotent(
        monkeypatch,
        user_exists,
        membership_exists,
):
    cursor = _FakeCursor(
        user_exists=user_exists,
        membership_exists=membership_exists,
    )
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.remove_class_membership(7, 'C1') is False

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert not any('class_cnt' in sql for sql in _sql_calls(cursor))


def test_remove_membership_allows_administrator_last_relation(
        monkeypatch,
):
    cursor = _FakeCursor(
        membership_exists=True,
        membership_count=1,
        is_admin=True,
    )
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.remove_class_membership(7, 'C1') is True

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert not any(
        sql.startswith('SELECT COUNT(*) AS membership_count')
        for sql in _sql_calls(cursor)
    )
    assert any('class_cnt = class_cnt - 1' in sql for sql in _sql_calls(cursor))


def test_remove_membership_rejects_student_last_relation(
        monkeypatch,
):
    cursor = _FakeCursor(membership_exists=True, membership_count=1)
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
        memberships.LastMembershipError,
        match='至少需要保留一个班级',
    ):
        memberships.remove_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(
        sql.startswith('DELETE FROM user_class_map')
        for sql in _sql_calls(cursor)
    )


def test_leave_membership_removes_one_of_multiple_relations(monkeypatch):
    cursor = _FakeCursor(membership_exists=True, membership_count=2)
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.leave_class_membership(7, 'C1') is True

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    sqls = _sql_calls(cursor)
    assert 'DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s' in sqls
    assert any('SET class_cnt = class_cnt - 1' in sql for sql in sqls)
    assert not any(sql.startswith('UPDATE users') for sql in sqls)


def test_leave_membership_rejects_last_relation_by_default(monkeypatch):
    cursor = _FakeCursor(membership_exists=True, membership_count=1)
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(memberships.LastMembershipError):
        memberships.leave_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_leave_membership_allows_admin_policy_to_remove_last_relation(monkeypatch):
    cursor = _FakeCursor(
        membership_exists=True,
        membership_count=1,
        is_admin=True,
    )
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.leave_class_membership(7, 'C1') is True

    assert conn.commit_count == 1
    assert conn.rollback_count == 0


def test_leave_missing_relation_rolls_back(monkeypatch):
    cursor = _FakeCursor(membership_exists=False)
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
        memberships.MembershipNotFoundError,
        match='班级成员关系不存在',
    ):
        memberships.leave_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_remove_rolls_back_when_class_count_cannot_be_decremented(monkeypatch):
    cursor = _FakeCursor(
        membership_exists=True,
        membership_count=2,
        class_count_rowcount=0,
    )
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
        memberships.MembershipConsistencyError,
        match='人数计数与成员关系不一致',
    ):
        memberships.leave_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_remove_treats_missing_class_for_existing_membership_as_corruption(
        monkeypatch):
    cursor = _FakeCursor(
        membership_exists=True,
        membership_count=2,
        class_count_rowcount=0,
        class_exists=False,
    )
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
        memberships.MembershipConsistencyError,
        match='成员关系缺少对应班级',
    ):
        memberships.leave_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_membership_service_contains_no_primary_or_user_snapshot_writes():
    source = inspect.getsource(memberships)

    assert 'is_primary' not in source
    assert 'UPDATE users SET class' not in source
    assert 'set_primary_membership' not in source
