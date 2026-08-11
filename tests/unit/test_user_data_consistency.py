# -*- coding: utf-8 -*-

import json

import pytest
from flask import Flask

from oj_modules import db_services
from oj_modules.routes import admin_user_routes, submission_routes


class _FakeCursor:
    def __init__(self, *, user=None, conflicting_user=None, schema_rows=None,
                 plagiarism_rows=None, namespace_users=None,
                 anonymous_identity=None, fail_when=None, lastrowid=73):
        self.user = user
        self.conflicting_user = conflicting_user
        self.schema_rows = list(schema_rows or [])
        self.plagiarism_rows = list(plagiarism_rows or [])
        self.namespace_users = (
            list(namespace_users) if namespace_users is not None else None
        )
        self.anonymous_identity = anonymous_identity
        self.fail_when = fail_when
        self.lastrowid = lastrowid
        self.calls = []
        self._fetchone_result = None
        self._fetchall_result = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        compact_sql = ' '.join(str(sql).split())
        self.calls.append((compact_sql, params))
        if self.fail_when and self.fail_when in compact_sql:
            raise RuntimeError('模拟写入失败')

        if compact_sql.startswith('SELECT GET_LOCK'):
            self._fetchone_result = {'identity_namespace_locked': 1}
        elif compact_sql.startswith('SELECT RELEASE_LOCK'):
            self._fetchone_result = {'identity_namespace_released': 1}
        elif compact_sql == 'SELECT id, username FROM users':
            self._fetchall_result = (
                self.namespace_users
                if self.namespace_users is not None
                else ([self.user] if self.user else [])
            )
        elif compact_sql.startswith(
                'SELECT id FROM forum_anonymous_identities'):
            self._fetchone_result = self.anonymous_identity
        elif compact_sql.startswith('SELECT id, username FROM users WHERE id='):
            self._fetchone_result = self.user
        elif compact_sql.startswith('SELECT id FROM users WHERE username='):
            self._fetchone_result = self.conflicting_user
        elif 'FROM INFORMATION_SCHEMA.COLUMNS' in compact_sql:
            self._fetchall_result = self.schema_rows
        elif compact_sql.startswith(
                'SELECT id, matched_usernames FROM plagiarism_records'):
            self._fetchall_result = self.plagiarism_rows

    def fetchone(self):
        result = self._fetchone_result
        self._fetchone_result = None
        return result

    def fetchall(self):
        result = self._fetchall_result
        self._fetchall_result = []
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


def _complete_rename_schema_rows(*, excluded_tables=()):
    columns = (
        db_services._RENAME_USER_REQUIRED_COLUMNS
        + db_services._RENAME_USER_OPTIONAL_COLUMNS
    )
    return [
        {'TABLE_NAME': table_name, 'COLUMN_NAME': column_name}
        for table_name, column_name in columns
        if table_name not in excluded_tables
    ]


def test_create_user_uses_one_transaction_and_insert_id(monkeypatch):
    cursor = _FakeCursor(lastrowid=73)
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)
    monkeypatch.setattr(
        db_services,
        'get_user_by_username',
        lambda _username: pytest.fail('create_user 不应另开连接反查用户'),
    )

    db_services.create_user(
        'alice',
        'password-hash',
        'alice@example.com',
        {'class_en': 'C1', 'class_cn': '一班'},
    )

    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert conn.closed is True
    writes = [
        call for call in cursor.calls
        if call[0].startswith(('INSERT', 'UPDATE'))
    ]
    assert len(writes) == 3
    assert writes[0][0] == (
        'INSERT INTO users (username, password_hash, email) '
        'VALUES (%s, %s, %s)'
    )
    assert writes[2][0] == (
        'INSERT INTO user_class_map (user_id, class_en) VALUES (%s, %s)'
    )
    assert writes[2][1] == (73, 'C1')
    assert cursor.calls[0][0].startswith('SELECT GET_LOCK')
    assert cursor.calls[-1][0].startswith('SELECT RELEASE_LOCK')


def test_create_user_rolls_back_all_writes_on_failure(monkeypatch):
    cursor = _FakeCursor(fail_when='INSERT INTO user_class_map')
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='模拟写入失败'):
        db_services.create_user(
            'alice',
            'password-hash',
            'alice@example.com',
            {'class_en': 'C1', 'class_cn': '一班'},
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert conn.closed is True


def test_create_user_rejects_name_reserved_by_historical_anonymous_identity(
        monkeypatch):
    cursor = _FakeCursor(anonymous_identity={'id': 17})
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(ValueError, match='已被其他身份使用'):
        db_services.create_user(
            'Old-Owl',
            'password-hash',
            'owl@example.com',
            {'class_en': 'C1', 'class_cn': '一班'},
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(
        sql.startswith(('INSERT', 'UPDATE'))
        for sql, _params in cursor.calls
    )
    assert cursor.calls[-1][0].startswith('SELECT RELEASE_LOCK')


def test_create_user_compares_existing_real_names_after_nfkc_ascii_fold(
        monkeypatch):
    cursor = _FakeCursor(
        namespace_users=[{'id': 8, 'username': 'Alice'}],
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(ValueError, match='已被其他身份使用'):
        db_services.create_user(
            'ALICE',
            'password-hash',
            'alice-2@example.com',
            {'class_en': 'C1', 'class_cn': '一班'},
        )

    assert conn.commit_count == 0
    assert conn.rollback_count == 1


def test_rename_user_updates_all_known_identity_columns_atomically(monkeypatch):
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=_complete_rename_schema_rows(),
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    old_username = db_services.rename_user(9, 'alice-new')

    assert old_username == 'alice'
    assert conn.commit_count == 1
    assert conn.rollback_count == 0
    assert conn.closed is True

    updates = {
        call[0]
        for call in cursor.calls
        if call[0].startswith('UPDATE')
    }
    expected_reference_updates = {
        f'UPDATE `{table_name}` SET `{column_name}`=%s WHERE `{column_name}`=%s'
        for table_name, column_name in (
            db_services._RENAME_USER_REQUIRED_COLUMNS
            + db_services._RENAME_USER_OPTIONAL_COLUMNS
        )
        if table_name != 'users'
    }
    assert expected_reference_updates <= updates
    assert 'UPDATE users SET username=%s WHERE id=%s' in updates


def test_rename_user_exactly_replaces_json_and_legacy_matched_usernames(monkeypatch):
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=_complete_rename_schema_rows(),
        plagiarism_rows=[
            {'id': 1, 'matched_usernames': json.dumps(['alice', 'bob', 'alice'])},
            {'id': 2, 'matched_usernames': 'carol, alice'},
            {'id': 3, 'matched_usernames': 'malice,bob'},
        ],
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    db_services.rename_user(9, 'alice-new')

    matched_updates = [
        params
        for sql, params in cursor.calls
        if sql == 'UPDATE plagiarism_records SET matched_usernames=%s WHERE id=%s'
    ]
    assert len(matched_updates) == 2
    assert json.loads(matched_updates[0][0]) == ['alice-new', 'bob']
    assert matched_updates[0][1] == 1
    assert matched_updates[1] == ('carol,alice-new', 2)
    assert conn.commit_count == 1


def test_rename_user_skips_matched_usernames_when_optional_table_absent(monkeypatch):
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=_complete_rename_schema_rows(excluded_tables={'plagiarism_records'}),
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    db_services.rename_user(9, 'alice-new')

    assert not any(
        sql.startswith('SELECT id, matched_usernames FROM plagiarism_records')
        for sql, _params in cursor.calls
    )
    assert conn.commit_count == 1


def test_rename_user_rejects_present_optional_table_with_missing_column(monkeypatch):
    schema_rows = _complete_rename_schema_rows()
    schema_rows = [
        row for row in schema_rows
        if not (
            row['TABLE_NAME'] == 'ranking_appeals'
            and row['COLUMN_NAME'] == 'admin_username'
        )
    ]
    # 该表仍有 username 列，因此它是“表存在但 schema 不完整”，而不是可选表未安装。
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=schema_rows,
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='ranking_appeals.admin_username'):
        db_services.rename_user(9, 'alice-new')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(sql.startswith('UPDATE') for sql, _params in cursor.calls)


def test_rename_user_rejects_missing_required_table(monkeypatch):
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=_complete_rename_schema_rows(excluded_tables={'submission_limits'}),
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='submission_limits.username'):
        db_services.rename_user(9, 'alice-new')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert not any(sql.startswith('UPDATE') for sql, _params in cursor.calls)


def test_rename_user_rolls_back_every_table_when_any_update_fails(monkeypatch):
    cursor = _FakeCursor(
        user={'id': 9, 'username': 'alice'},
        schema_rows=_complete_rename_schema_rows(),
        fail_when='UPDATE `ranking_submissions`',
    )
    conn = _FakeConnection(cursor)
    monkeypatch.setattr(db_services, 'get_db_connection', lambda: conn)

    with pytest.raises(RuntimeError, match='模拟写入失败'):
        db_services.rename_user(9, 'alice-new')

    assert conn.commit_count == 0
    assert conn.rollback_count == 1
    assert conn.closed is True


def _admin_user_test_app():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY='test-secret')
    app.register_blueprint(admin_user_routes.admin_user_bp)
    return app


def test_edit_username_route_uses_service_and_keeps_self_session(monkeypatch):
    app = _admin_user_test_app()
    rename_calls = []
    invalidations = []
    monkeypatch.setattr(
        admin_user_routes,
        'current_user',
        lambda: {'id': 9, 'username': 'admin-old', 'is_admin': 1},
    )
    monkeypatch.setattr(admin_user_routes, 'is_admin', lambda _user: True)
    monkeypatch.setattr(
        admin_user_routes,
        'rename_user',
        lambda user_id, username: rename_calls.append((user_id, username)) or 'admin-old',
    )
    monkeypatch.setattr(
        admin_user_routes,
        '_invalidate_problem_list_cache_for_user',
        lambda **kwargs: invalidations.append(kwargs),
    )

    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session['username'] = 'admin-old'

    response = client.post(
        '/admin/edit_username_ajax',
        data={'user_id': '9', 'new_username': 'admin-new'},
    )

    assert response.status_code == 200
    assert rename_calls == [(9, 'admin-new')]
    assert invalidations == [
        {'user_id': 9, 'username': 'admin-old'},
        {'username': 'admin-new'},
    ]
    with client.session_transaction() as user_session:
        assert user_session['username'] == 'admin-new'


@pytest.mark.parametrize(
    ('error', 'expected_status', 'expected_message'),
    [
        (LookupError('用户不存在'), 404, '用户不存在'),
        (ValueError('用户名已存在'), 400, '用户名已存在'),
        (RuntimeError('schema drift'), 500, '数据库操作失败，请稍后再试'),
    ],
)
def test_edit_username_route_maps_service_failures(
        monkeypatch, error, expected_status, expected_message):
    app = _admin_user_test_app()
    monkeypatch.setattr(
        admin_user_routes,
        'current_user',
        lambda: {'id': 1, 'username': 'admin', 'is_admin': 1},
    )
    monkeypatch.setattr(admin_user_routes, 'is_admin', lambda _user: True)

    def _raise_error(_user_id, _new_username):
        raise error

    monkeypatch.setattr(admin_user_routes, 'rename_user', _raise_error)

    response = app.test_client().post(
        '/admin/edit_username_ajax',
        data={'user_id': '9', 'new_username': 'alice-new'},
    )

    assert response.status_code == expected_status
    assert response.get_json()['message'] == expected_message


def _submission_status_test_app():
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY='test-secret')
    app.register_blueprint(submission_routes.submission_bp)
    return app


@pytest.mark.parametrize(
    ('path', 'expected_body'),
    [
        ('/submission_status/42', None),
        ('/submission_status_stream/42', 'event: done'),
    ],
)
def test_submission_status_refreshes_stale_username_cache_once(
        monkeypatch, path, expected_body):
    calls = []
    cached_snapshot = {
        'id': 42,
        'username': 'alice-old',
        'problem_type': 1,
        'status': 'Accepted',
        'score': 100,
        'test_points': [],
    }
    database_snapshot = {**cached_snapshot, 'username': 'alice-new'}

    def get_snapshot(submission_id, prefer_cache=True):
        calls.append((submission_id, prefer_cache))
        return cached_snapshot if prefer_cache else database_snapshot

    monkeypatch.setattr(
        submission_routes,
        'current_user',
        lambda: {'id': 9, 'username': 'alice-new', 'is_admin': 0},
    )
    monkeypatch.setattr(submission_routes, 'is_admin', lambda _user: False)
    monkeypatch.setattr(
        submission_routes,
        'get_submission_status_snapshot',
        get_snapshot,
    )

    response = _submission_status_test_app().test_client().get(path)

    assert response.status_code == 200
    assert calls == [(42, True), (42, False)]
    if expected_body is None:
        assert response.get_json()['status'] == 'Accepted'
    else:
        assert expected_body in response.get_data(as_text=True)
