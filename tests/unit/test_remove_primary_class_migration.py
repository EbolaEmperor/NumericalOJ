# -*- coding: utf-8 -*-

from pathlib import Path
import subprocess
import sys

import pytest

from scripts import migrate_remove_primary_class as migration


class _FakeCursor:
    def __init__(
            self,
            *,
            users_columns=None,
            map_columns=None,
            map_indexes=None,
            admin_table_exists=True,
            admin_table_rows=0,
            legacy_ghosts=None,
            mapping_ghosts=None,
            zero_students=None,
            count_mismatches=None,
            known_orphan_table_exists=True,
            known_orphan_table_rows=0,
            valid_membership_count=2,
            known_delete_rowcount=1,
            fail_once_when=None,
    ):
        self.users_columns = set(users_columns or {
            'id', 'username', 'password_hash', 'is_admin', 'email',
            'class', 'class_cn',
        })
        self.map_columns = set(map_columns or {
            'id', 'user_id', 'class_en', 'is_primary',
        })
        self.map_indexes = set(map_indexes or {
            'PRIMARY', 'idx_user_id', 'idx_class_en', 'idx_primary',
        })
        self.admin_table_exists = admin_table_exists
        self.admin_table_rows = admin_table_rows
        self.legacy_ghosts = list(legacy_ghosts or [])
        self.mapping_ghosts = list(mapping_ghosts or [])
        self.zero_students = list(zero_students or [])
        self.count_mismatches = list(count_mismatches or [])
        self.known_orphan_table_exists = known_orphan_table_exists
        self.known_orphan_table_rows = known_orphan_table_rows
        self.valid_membership_count = valid_membership_count
        self.known_delete_rowcount = known_delete_rowcount
        self.fail_once_when = fail_once_when
        self.calls = []
        self._fetchone_result = None
        self._fetchall_result = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=()):
        normalized = ' '.join(str(sql).split())
        self.calls.append((normalized, params))
        self._fetchone_result = None
        self._fetchall_result = []
        self.rowcount = 0
        if self.fail_once_when and self.fail_once_when in normalized:
            self.fail_once_when = None
            raise RuntimeError('模拟 DDL 部分失败')

        if normalized == 'SHOW COLUMNS FROM `users`':
            self._fetchall_result = [
                {'Field': name} for name in sorted(self.users_columns)
            ]
        elif normalized == 'SHOW COLUMNS FROM `user_class_map`':
            self._fetchall_result = [
                {'Field': name} for name in sorted(self.map_columns)
            ]
        elif normalized == 'SHOW INDEX FROM `user_class_map`':
            self._fetchall_result = [
                {'Key_name': name} for name in sorted(self.map_indexes)
            ]
        elif normalized == 'SHOW TABLES LIKE %s':
            table = params[0]
            if table == 'Cadmin':
                exists = self.admin_table_exists
            else:
                exists = False
            self._fetchone_result = {'table': table} if exists else None
        elif normalized.startswith(
            'SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES'
        ):
            self._fetchone_result = (
                {'TABLE_NAME': migration.KNOWN_ORPHAN_CLASS}
                if (
                    params[0] == migration.KNOWN_ORPHAN_CLASS
                    and self.known_orphan_table_exists
                )
                else None
            )
        elif normalized == 'SELECT COUNT(*) AS row_count FROM `Cadmin`':
            self._fetchone_result = {'row_count': self.admin_table_rows}
        elif normalized == (
            'SELECT COUNT(*) AS row_count '
            'FROM `CNumAnl_25_26_AutWin`'
        ):
            self._fetchone_result = {
                'row_count': self.known_orphan_table_rows,
            }
        elif normalized.startswith('SELECT GET_LOCK'):
            self._fetchone_result = {'locked': 1}
        elif normalized.startswith('SELECT RELEASE_LOCK'):
            self._fetchone_result = {'released': 1}
        elif (
            'FROM users u LEFT JOIN class_table ct'
            in normalized
        ):
            self._fetchall_result = self.legacy_ghosts
        elif (
            'FROM user_class_map m LEFT JOIN users u'
            in normalized
        ):
            self._fetchall_result = self.mapping_ghosts
        elif normalized.startswith(
            'SELECT id, user_id, class_en, is_primary '
            'FROM user_class_map'
        ):
            self._fetchall_result = [
                {
                    'id': row.get('id'),
                    'user_id': row.get('user_id'),
                    'class_en': row.get('class_en'),
                    'is_primary': row.get('is_primary'),
                }
                for row in self.mapping_ghosts
                if row.get('user_id') == params[0]
                and row.get('class_en') == params[1]
            ]
        elif normalized.startswith(
            'SELECT COUNT(*) AS valid_count '
            'FROM user_class_map m JOIN class_table ct'
        ):
            self._fetchall_result = [{
                'valid_count': self.valid_membership_count,
            }]
        elif (
            'FROM users u WHERE u.is_admin = 0'
            in normalized
        ):
            self._fetchall_result = self.zero_students
        elif normalized.startswith(
            "SELECT 'class_table' AS source"
        ):
            self._fetchall_result = []
        elif normalized.startswith(
            'SELECT ct.class_en, ct.class_cnt, COUNT(m.user_id)'
        ):
            self._fetchall_result = self.count_mismatches
        elif normalized == 'DROP TABLE `Cadmin`':
            self.admin_table_exists = False
        elif normalized.startswith(
            'DELETE FROM user_class_map WHERE id=%s'
        ):
            self.rowcount = self.known_delete_rowcount
            if self.rowcount == 1:
                self.mapping_ghosts = [
                    row for row in self.mapping_ghosts
                    if not (
                        row.get('id') == params[0]
                        and row.get('user_id') == params[1]
                        and row.get('class_en') == params[2]
                        and row.get('is_primary') == params[3]
                    )
                ]
        elif normalized == (
            'ALTER TABLE user_class_map DROP INDEX idx_primary'
        ):
            self.map_indexes.discard('idx_primary')
        elif normalized == (
            'ALTER TABLE user_class_map DROP COLUMN is_primary'
        ):
            self.map_columns.discard('is_primary')
        elif normalized == 'ALTER TABLE users DROP COLUMN `class`':
            self.users_columns.discard('class')
        elif normalized == 'ALTER TABLE users DROP COLUMN class_cn':
            self.users_columns.discard('class_cn')

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
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def _operation_sql(plan):
    return [' '.join(operation.sql.split()) for operation in plan]


def _known_orphan_row(**overrides):
    row = {
        'id': migration.KNOWN_ORPHAN_MEMBERSHIP_ID,
        'user_id': migration.KNOWN_ORPHAN_USER_ID,
        'class_en': migration.KNOWN_ORPHAN_CLASS,
        'is_primary': migration.KNOWN_ORPHAN_IS_PRIMARY,
        'matched_user_id': migration.KNOWN_ORPHAN_USER_ID,
        'matched_class_en': None,
    }
    row.update(overrides)
    return row


def test_legacy_plan_backfills_then_recounts_and_contracts():
    cursor = _FakeCursor()

    plan = migration.build_plan(cursor)
    sqls = _operation_sql(plan)

    assert sqls[0].startswith(
        'INSERT IGNORE INTO user_class_map '
        '(user_id, class_en, is_primary)'
    )
    assert plan[0].params == ('Cadmin',)
    assert "TRIM(u.`class`) <> %s" in plan[0].sql
    assert sqls[1] == 'DELETE FROM user_class_map WHERE class_en=%s'
    assert sqls[2].startswith('UPDATE class_table ct LEFT JOIN')
    assert sqls[3] == 'DELETE FROM class_table WHERE class_en=%s'
    assert sqls[4] == 'DROP TABLE `Cadmin`'
    assert sqls[5:] == [
        'ALTER TABLE user_class_map DROP INDEX idx_primary',
        'ALTER TABLE user_class_map DROP COLUMN is_primary',
        'ALTER TABLE users DROP COLUMN `class`',
        'ALTER TABLE users DROP COLUMN class_cn',
    ]


def test_contracted_plan_is_a_complete_noop():
    cursor = _FakeCursor(
        users_columns={'id', 'username', 'password_hash', 'is_admin', 'email'},
        map_columns={'user_id', 'class_en'},
        map_indexes={'PRIMARY', 'idx_user_id', 'idx_class_en'},
        admin_table_exists=False,
    )

    assert migration.build_plan(cursor) == []


def test_contracted_schema_never_touches_a_later_legitimate_cadmin_class():
    cursor = _FakeCursor(
        users_columns={'id', 'username', 'password_hash', 'is_admin', 'email'},
        map_columns={'user_id', 'class_en'},
        map_indexes={'PRIMARY', 'idx_user_id', 'idx_class_en'},
        admin_table_exists=True,
        admin_table_rows=3,
    )
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection, apply=True)

    executed_sql = [sql for sql, _params in cursor.calls]
    assert plan == []
    assert 'DELETE FROM user_class_map WHERE class_en=%s' not in executed_sql
    assert 'DELETE FROM class_table WHERE class_en=%s' not in executed_sql
    assert 'DROP TABLE `Cadmin`' not in executed_sql
    assert 'SELECT COUNT(*) AS row_count FROM `Cadmin`' not in executed_sql
    assert cursor.admin_table_exists is True


def test_partially_contracted_plan_backfills_without_primary_column():
    cursor = _FakeCursor(
        map_columns={'user_id', 'class_en'},
        map_indexes={'PRIMARY', 'idx_user_id', 'idx_class_en'},
        admin_table_exists=False,
    )

    plan = migration.build_plan(cursor)

    assert '(user_id, class_en)' in plan[0].sql
    assert 'is_primary' not in plan[0].sql


def test_plan_blocks_legacy_snapshot_ghost_class():
    cursor = _FakeCursor(legacy_ghosts=[{
        'id': 7,
        'username': 'student',
        'class_en': 'Cmissing',
    }])

    with pytest.raises(
        migration.MigrationBlockedError,
        match='users.class 含不存在',
    ):
        migration.build_plan(cursor)


def test_plan_blocks_mapping_ghosts():
    cursor = _FakeCursor(mapping_ghosts=[{
        'user_id': 7,
        'class_en': 'Cmissing',
    }])

    with pytest.raises(
        migration.MigrationBlockedError,
        match='user_class_map 含孤儿用户或幽灵班级',
    ):
        migration.build_plan(cursor)


def test_plan_deletes_only_the_exact_authorized_orphan_before_recount():
    cursor = _FakeCursor(mapping_ghosts=[_known_orphan_row()])

    plan = migration.build_plan(cursor)
    sqls = _operation_sql(plan)

    assert sqls[0].startswith('DELETE FROM user_class_map WHERE id=%s')
    assert plan[0].params == (
        migration.KNOWN_ORPHAN_MEMBERSHIP_ID,
        migration.KNOWN_ORPHAN_USER_ID,
        migration.KNOWN_ORPHAN_CLASS,
        migration.KNOWN_ORPHAN_IS_PRIMARY,
    )
    assert plan[0].expected_rowcount == 1
    assert sqls.index(sqls[0]) < next(
        index for index, sql in enumerate(sqls)
        if sql.startswith('UPDATE class_table ct LEFT JOIN')
    )


def test_plan_blocks_an_extra_mapping_ghost_beside_the_authorized_one():
    cursor = _FakeCursor(mapping_ghosts=[
        _known_orphan_row(),
        {
            'user_id': 7,
            'class_en': 'Cmissing',
            'matched_user_id': 7,
            'matched_class_en': None,
        },
    ])

    with pytest.raises(
        migration.MigrationBlockedError,
        match='user_class_map 含孤儿用户或幽灵班级',
    ):
        migration.build_plan(cursor)


def test_plan_blocks_when_the_authorized_orphan_user_is_missing():
    cursor = _FakeCursor(mapping_ghosts=[
        _known_orphan_row(matched_user_id=None),
    ])

    with pytest.raises(
        migration.MigrationBlockedError,
        match='user_class_map 含孤儿用户或幽灵班级',
    ):
        migration.build_plan(cursor)


def test_plan_blocks_when_authorized_orphan_has_no_valid_memberships():
    cursor = _FakeCursor(
        mapping_ghosts=[_known_orphan_row()],
        valid_membership_count=0,
    )

    with pytest.raises(
        migration.MigrationBlockedError,
        match='有效班级数量发生变化',
    ):
        migration.build_plan(cursor)


def test_plan_blocks_when_authorized_orphan_homework_table_is_not_empty():
    cursor = _FakeCursor(
        mapping_ghosts=[_known_orphan_row()],
        known_orphan_table_rows=1,
    )

    with pytest.raises(
        migration.MigrationBlockedError,
        match='作业表已有 1 行',
    ):
        migration.build_plan(cursor)


def test_plan_blocks_when_authorized_orphan_homework_table_is_missing():
    cursor = _FakeCursor(
        mapping_ghosts=[_known_orphan_row()],
        known_orphan_table_exists=False,
    )

    with pytest.raises(
        migration.MigrationBlockedError,
        match='空作业表已不存在',
    ):
        migration.build_plan(cursor)


def test_apply_deletes_authorized_orphan_then_contracts_and_verifies():
    cursor = _FakeCursor(mapping_ghosts=[_known_orphan_row()])
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection, apply=True)

    assert plan[0].expected_rowcount == 1
    assert cursor.mapping_ghosts == []
    assert 'class' not in cursor.users_columns
    assert 'class_cn' not in cursor.users_columns
    assert 'is_primary' not in cursor.map_columns
    assert 'idx_primary' not in cursor.map_indexes


def test_apply_blocks_and_rolls_back_when_authorized_delete_misses():
    cursor = _FakeCursor(
        mapping_ghosts=[_known_orphan_row()],
        known_delete_rowcount=0,
    )
    connection = _FakeConnection(cursor)

    with pytest.raises(
        migration.MigrationBlockedError,
        match='影响行数不符合预期',
    ):
        migration.migrate(connection, apply=True)

    assert connection.rollbacks >= 1


def test_plan_blocks_student_with_no_real_membership():
    cursor = _FakeCursor(zero_students=[{
        'id': 7,
        'username': 'student',
    }])

    with pytest.raises(
        migration.MigrationBlockedError,
        match='非管理员用户在迁移后将没有任何班级',
    ):
        migration.build_plan(cursor)


def test_zero_membership_guard_only_targets_users_with_a_legacy_source():
    cursor = _FakeCursor()

    migration.build_plan(cursor)

    zero_membership_query = next(
        sql for sql, _params in cursor.calls
        if 'FROM users u WHERE u.is_admin = 0' in sql
    )
    assert (
        'FROM user_class_map source_membership '
        'WHERE source_membership.user_id = u.id'
        in zero_membership_query
    )
    assert "u.`class` IS NOT NULL" in zero_membership_query
    assert "TRIM(u.`class`) <> ''" in zero_membership_query


def test_plan_allows_admin_with_zero_memberships():
    cursor = _FakeCursor(zero_students=[])

    assert migration.build_plan(cursor)


def test_plan_blocks_nonempty_admin_homework_table():
    cursor = _FakeCursor(admin_table_rows=3)

    with pytest.raises(
        migration.MigrationBlockedError,
        match='仍有 3 行',
    ):
        migration.build_plan(cursor)


def test_default_migrate_is_dry_run_and_executes_no_plan_operations():
    cursor = _FakeCursor()
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection)

    plan_sql = set(_operation_sql(plan))
    executed_sql = {sql for sql, _params in cursor.calls}
    assert not plan_sql.intersection(executed_sql)
    assert connection.rollbacks == 1
    assert 'SELECT GET_LOCK(%s, %s) AS locked' in executed_sql
    assert 'SELECT RELEASE_LOCK(%s)' in executed_sql


def test_apply_contracts_schema_and_can_be_replanned_idempotently():
    cursor = _FakeCursor()
    connection = _FakeConnection(cursor)

    first_plan = migration.migrate(connection, apply=True)
    second_plan = migration.migrate(connection, apply=True)

    assert any(op.kind == 'ddl' for op in first_plan)
    assert second_plan == []
    assert 'class' not in cursor.users_columns
    assert 'class_cn' not in cursor.users_columns
    assert 'is_primary' not in cursor.map_columns
    assert 'idx_primary' not in cursor.map_indexes
    assert cursor.admin_table_exists is False


def test_apply_can_resume_after_partial_ddl_failure_while_marker_remains():
    cursor = _FakeCursor(
        fail_once_when='ALTER TABLE users DROP COLUMN class_cn',
    )
    connection = _FakeConnection(cursor)

    with pytest.raises(RuntimeError, match='模拟 DDL 部分失败'):
        migration.migrate(connection, apply=True)

    assert 'class' not in cursor.users_columns
    assert 'class_cn' in cursor.users_columns
    assert 'is_primary' not in cursor.map_columns
    assert cursor.admin_table_exists is False

    resumed = migration.migrate(connection, apply=True)

    assert any(
        'DROP COLUMN class_cn' in operation.sql
        for operation in resumed
    )
    assert 'class_cn' not in cursor.users_columns


def test_apply_fails_closed_when_recount_verification_disagrees():
    cursor = _FakeCursor(count_mismatches=[{
        'class_en': 'C1',
        'class_cnt': 1,
        'expected_count': 2,
    }])
    connection = _FakeConnection(cursor)

    with pytest.raises(
        migration.MigrationBlockedError,
        match='class_cnt 重算后仍不一致',
    ):
        migration.migrate(connection, apply=True)

    assert connection.rollbacks >= 1


def test_cli_help_imports_from_an_arbitrary_working_directory(tmp_path):
    script = (
        Path(__file__).resolve().parents[2]
        / 'scripts'
        / 'migrate_remove_primary_class.py'
    )

    result = subprocess.run(
        [sys.executable, str(script), '--help'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert '--confirm-app-writers-stopped' in result.stdout
    assert '--confirm-backup-verified' in result.stdout


def test_cli_apply_requires_both_safety_confirmations(tmp_path):
    script = (
        Path(__file__).resolve().parents[2]
        / 'scripts'
        / 'migrate_remove_primary_class.py'
    )

    result = subprocess.run(
        [sys.executable, str(script), '--apply'],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert '--apply requires' in result.stderr
