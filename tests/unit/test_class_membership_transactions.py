# -*- coding: utf-8 -*-

import inspect

import pytest
from flask import Flask

from oj_modules import class_membership_services as memberships
from oj_modules.routes import admin_user_routes, class_management_routes


class _FakeCursor:
    def __init__(
            self,
            *,
            membership=None,
            replacement_exists=True,
            class_count_rowcount=1,
            fail_when=None,
    ):
        self.membership = membership
        self.replacement_exists = replacement_exists
        self.class_count_rowcount = class_count_rowcount
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
        if normalized.startswith('SELECT id FROM users'):
            self._fetchone_result = {'id': params[0]}
        elif normalized.startswith('SELECT 1 FROM user_class_map'):
            self._fetchone_result = self.membership
        elif normalized.startswith('SELECT is_primary FROM user_class_map'):
            self._fetchone_result = self.membership
        elif normalized.startswith('SELECT class_en FROM user_class_map'):
            self._fetchone_result = (
                {'class_en': params[1]} if self.replacement_exists else None
            )
        elif normalized.startswith('DELETE FROM user_class_map'):
            self.rowcount = 1 if self.membership else 0
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
    assert sqls[0] == 'SELECT id FROM users WHERE id=%s FOR UPDATE'
    assert sqls[1].startswith('SELECT 1 FROM user_class_map')
    assert sqls[2].startswith('INSERT INTO user_class_map')
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
    cursor = _FakeCursor(class_count_rowcount=0)
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(memberships.MembershipNotFoundError, match='班级不存在'):
        memberships.add_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_duplicate_membership_does_not_change_primary_flag_or_count(monkeypatch):
    cursor = _FakeCursor(membership={'is_primary': 1})
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.add_class_membership(7, 'C1') is False

    assert conn.commit_count == 1
    assert not any('UPDATE class_table' in sql for sql in _sql_calls(cursor))
    assert not any(sql.startswith('INSERT') for sql in _sql_calls(cursor))


def test_remove_missing_membership_does_not_decrement_count(monkeypatch):
    cursor = _FakeCursor(membership=None)
    conn = _install_connection(monkeypatch, cursor)

    assert memberships.remove_secondary_membership(7, 'C1') is False

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert not any('class_cnt' in sql for sql in _sql_calls(cursor))


def test_remove_primary_membership_rolls_back_without_delete(monkeypatch):
    cursor = _FakeCursor(membership={'is_primary': 1})
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(memberships.PrimaryMembershipError):
        memberships.remove_secondary_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(sql.startswith('DELETE') for sql in _sql_calls(cursor))


def test_leave_primary_updates_snapshot_mapping_and_count_in_one_transaction(monkeypatch):
    cursor = _FakeCursor(membership={'is_primary': 1})
    conn = _install_connection(monkeypatch, cursor)

    memberships.leave_class_membership(
        7,
        'C1',
        replacement_class_en='C2',
        replacement_class_cn='二班',
    )

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    sqls = _sql_calls(cursor)
    assert 'UPDATE users SET class=%s, class_cn=%s WHERE id=%s' in sqls
    assert 'UPDATE user_class_map SET is_primary=0 WHERE user_id=%s' in sqls
    assert any(
        sql.startswith('UPDATE user_class_map SET is_primary=1') for sql in sqls
    )
    assert 'DELETE FROM user_class_map WHERE user_id=%s AND class_en=%s' in sqls
    assert any('SET class_cnt = class_cnt - 1' in sql for sql in sqls)


def test_leave_rolls_back_primary_change_when_count_update_fails(monkeypatch):
    cursor = _FakeCursor(
        membership={'is_primary': 1},
        fail_when='UPDATE class_table SET class_cnt',
    )
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(RuntimeError, match='模拟事务中途失败'):
        memberships.leave_class_membership(
            7,
            'C1',
            replacement_class_en='C2',
            replacement_class_cn='二班',
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_leave_primary_rejects_the_membership_being_removed_as_replacement(monkeypatch):
    cursor = _FakeCursor(membership={'is_primary': 1})
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
            memberships.PrimaryMembershipError,
            match='新的主班级不能是正在退出的班级',
    ):
        memberships.leave_class_membership(
            7,
            'C1',
            replacement_class_en='C1',
            replacement_class_cn='一班',
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(sql.startswith('UPDATE users') for sql in _sql_calls(cursor))
    assert not any(sql.startswith('DELETE') for sql in _sql_calls(cursor))


def test_leave_rolls_back_when_class_count_cannot_be_decremented(monkeypatch):
    cursor = _FakeCursor(
        membership={'is_primary': 0},
        class_count_rowcount=0,
    )
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(
            memberships.MembershipNotFoundError,
            match='班级不存在或班级人数计数异常',
    ):
        memberships.leave_class_membership(7, 'C1')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_set_primary_rolls_back_users_and_mapping_together(monkeypatch):
    cursor = _FakeCursor(fail_when='SET is_primary=1')
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(RuntimeError, match='模拟事务中途失败'):
        memberships.set_primary_membership(7, 'C2', '二班', 0)

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert any(sql.startswith('UPDATE users SET class=') for sql in _sql_calls(cursor))


def test_admin_primary_change_adds_only_missing_membership_and_count(monkeypatch):
    cursor = _FakeCursor(replacement_exists=False)
    conn = _install_connection(monkeypatch, cursor)

    added = memberships.set_primary_membership(
        7,
        'C2',
        '二班',
        0,
        create_if_missing=True,
    )

    assert added is True
    assert conn.commit_count == 1
    sqls = _sql_calls(cursor)
    assert any(sql.startswith('INSERT INTO user_class_map') for sql in sqls)
    assert sqls.count(
        'UPDATE class_table SET class_cnt = class_cnt + 1 WHERE class_en=%s'
    ) == 1
    assert not any('class_cnt = class_cnt - 1' in sql for sql in sqls)


def test_admin_primary_change_does_not_recount_existing_memberships(monkeypatch):
    cursor = _FakeCursor(replacement_exists=True)
    conn = _install_connection(monkeypatch, cursor)

    added = memberships.set_primary_membership(
        7,
        'C2',
        '二班',
        0,
        create_if_missing=True,
    )

    assert added is False
    assert conn.commit_count == 1
    assert not any('class_cnt' in sql for sql in _sql_calls(cursor))


def test_admin_primary_change_rolls_back_new_membership_when_count_fails(monkeypatch):
    cursor = _FakeCursor(
        replacement_exists=False,
        fail_when='UPDATE class_table SET class_cnt',
    )
    conn = _install_connection(monkeypatch, cursor)

    with pytest.raises(RuntimeError, match='模拟事务中途失败'):
        memberships.set_primary_membership(
            7,
            'C2',
            '二班',
            0,
            create_if_missing=True,
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


@pytest.mark.parametrize(
    ('route', 'service_call'),
    (
        (class_management_routes.add_user_to_class, 'add_class_membership'),
        (class_management_routes.remove_user_from_class, 'remove_secondary_membership'),
        (class_management_routes.join_class, 'add_class_membership'),
        (class_management_routes.leave_class, 'leave_class_membership'),
        (class_management_routes.set_primary_class, 'set_primary_membership'),
    ),
)
def test_membership_routes_delegate_transaction_boundaries(route, service_call):
    source = inspect.getsource(route)
    assert service_call in source
    assert 'get_db_connection' not in source
    assert '.commit()' not in source
    assert '.rollback()' not in source


def test_admin_primary_class_edit_delegates_transaction_boundary():
    source = inspect.getsource(admin_user_routes.edit_user_ajax)
    assert 'set_primary_membership' in source
    assert 'create_if_missing=True' in source
    assert '.commit()' not in source
    assert '.rollback()' not in source
    assert 'class_cnt' not in source


def test_admin_primary_class_edit_noop_does_not_open_transaction(monkeypatch):
    app = Flask(__name__)
    app.secret_key = 'test-secret'
    admin = {'id': 1, 'username': 'admin', 'is_admin': 1}
    target = {
        'id': 7,
        'username': 'student',
        'class': 'C1',
        'class_cn': '一班',
        'is_admin': 0,
    }
    target_class = {'class_en': 'C1', 'class_cn': '一班'}
    monkeypatch.setattr(admin_user_routes, 'current_user', lambda: admin)
    monkeypatch.setattr(admin_user_routes, 'get_user_by_id', lambda _uid: target)
    monkeypatch.setattr(admin_user_routes, 'get_class_by_en', lambda _name: target_class)
    monkeypatch.setattr(
        admin_user_routes,
        'set_primary_membership',
        lambda *_args, **_kwargs: pytest.fail('无变化请求不应打开事务'),
    )

    with app.test_request_context(
            '/admin/edit_user_ajax',
            method='POST',
            data={'user_id': '7', 'class': 'C1'},
    ):
        response = admin_user_routes.edit_user_ajax()

    assert response.get_json()['success'] is True
    assert response.get_json()['message'] == '主班级未变化'
