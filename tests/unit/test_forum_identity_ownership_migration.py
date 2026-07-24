# -*- coding: utf-8 -*-

from types import SimpleNamespace

import pytest

from scripts.migrations import (
    m20260725_forum_anonymous_identity_ownership as migration,
)


class _FetchAllSequenceCursor:
    def __init__(self, responses):
        self.responses = list(responses)
        self.current = None
        self.executed = []

    def execute(self, statement, params=None):
        self.executed.append((statement, params))
        self.current = self.responses.pop(0)

    def fetchall(self):
        return self.current


class _FetchOneCursor:
    def __init__(self, row):
        self.row = row
        self.executed = []

    def execute(self, statement, params=None):
        self.executed.append((statement, params))

    def fetchone(self):
        return self.row


def _complete_presence():
    return {
        (step.kind, step.object_name): True
        for step in migration.DDL_STEPS
    }


def _zero_anti_join_counts():
    return {
        reference.table: 0
        for reference in migration.OWNERSHIP_REFERENCES
    }


def test_migration_ddl_has_forward_only_dependency_order_and_never_disables_fk():
    steps = migration.DDL_STEPS

    assert steps[0] == migration.PARENT_INDEX_STEP
    assert steps[1:5] == migration.CHILD_INDEX_STEPS
    assert steps[5:] == migration.CHILD_FOREIGN_KEY_STEPS
    assert all(
        "FOREIGN_KEY_CHECKS" not in step.sql.upper()
        for step in steps
    )
    assert all(
        "ON DELETE RESTRICT ON UPDATE RESTRICT" in step.sql
        for step in migration.CHILD_FOREIGN_KEY_STEPS
    )


def test_apply_requires_explicit_writers_stopped_confirmation(monkeypatch):
    monkeypatch.setattr(
        migration,
        "load_config",
        lambda: (_ for _ in ()).throw(
            AssertionError("must fail before loading database config")
        ),
    )

    with pytest.raises(
        migration.MigrationError,
        match="应用写入者",
    ):
        migration.execute_migration(apply=True)

    with pytest.raises(SystemExit):
        migration._parse_args(["--apply"])
    with pytest.raises(SystemExit):
        migration._parse_args(
            ["--check", "--confirm-app-writers-stopped"]
        )


def test_source_schema_rejects_unsigned_or_incompatible_participant_column():
    table_rows = [
        {"table_name": table, "engine": "InnoDB"}
        for table in migration.REQUIRED_TABLES
    ]
    column_rows = []
    for (table, column), shape in migration.EXPECTED_COLUMNS.items():
        column_rows.append(
            {
                "table_name": table,
                "column_name": column,
                "data_type": shape.data_type,
                "column_type": (
                    f"{shape.data_type} unsigned"
                    if shape.unsigned
                    else shape.data_type
                ),
                "is_nullable": "YES" if shape.nullable else "NO",
            }
        )
    next(
        row
        for row in column_rows
        if row["table_name"] == "forum_threads"
        and row["column_name"] == "anonymous_identity_id"
    )["column_type"] = "bigint unsigned"
    cursor = _FetchAllSequenceCursor([table_rows, column_rows])

    with pytest.raises(migration.MigrationError, match="列定义不匹配"):
        migration._assert_source_schema(cursor, "oj_test")


def test_migration_requires_enabled_foreign_key_checks():
    cursor = _FetchOneCursor({"foreign_key_checks": 0})

    with pytest.raises(
        migration.MigrationError,
        match="FOREIGN_KEY_CHECKS",
    ):
        migration._assert_foreign_key_checks_enabled(cursor)


def test_source_schema_requires_every_participating_table_to_be_innodb():
    table_rows = [
        {
            "table_name": table,
            "engine": (
                "MyISAM"
                if table == "forum_replies"
                else "InnoDB"
            ),
        }
        for table in migration.REQUIRED_TABLES
    ]
    cursor = _FetchAllSequenceCursor([table_rows])

    with pytest.raises(
        migration.MigrationError,
        match=r"forum_replies",
    ):
        migration._assert_source_schema(cursor, "oj_test")


def test_anti_join_counts_all_four_sources_and_fails_closed_on_bad_owner():
    rows = [
        {
            "source_table": reference.table,
            "invalid_rows": (
                2 if reference.table == "forum_replies" else 0
            ),
        }
        for reference in migration.OWNERSHIP_REFERENCES
    ]
    cursor = _FetchAllSequenceCursor([rows])

    with pytest.raises(
        migration.MigrationError,
        match=r"forum_replies=2",
    ):
        migration._audit_identity_ownership(cursor)

    sql = cursor.executed[0][0]
    for reference in migration.OWNERSHIP_REFERENCES:
        assert f"FROM `{reference.table}` AS child" in sql
    assert sql.count("COUNT(*) AS invalid_rows") == 4
    assert "LEFT JOIN `forum_anonymous_identities`" in sql


def test_named_foreign_key_definition_must_match_owner_columns_and_rules():
    reference = migration.OWNERSHIP_REFERENCES[0]
    rows = [
        {
            "ordinal_position": 1,
            "column_name": "user_id",
            "referenced_table_schema": "oj_test",
            "referenced_table_name": migration.PARENT_TABLE,
            "referenced_column_name": "user_id",
            "position_in_unique_constraint": 1,
            "unique_constraint_name": migration.PARENT_UNIQUE_NAME,
            "match_option": "NONE",
            "update_rule": "CASCADE",
            "delete_rule": "RESTRICT",
        },
        {
            "ordinal_position": 2,
            "column_name": reference.identity_column,
            "referenced_table_schema": "oj_test",
            "referenced_table_name": migration.PARENT_TABLE,
            "referenced_column_name": "id",
            "position_in_unique_constraint": 2,
            "unique_constraint_name": migration.PARENT_UNIQUE_NAME,
            "match_option": "NONE",
            "update_rule": "CASCADE",
            "delete_rule": "RESTRICT",
        },
    ]
    cursor = _FetchAllSequenceCursor([rows])

    with pytest.raises(
        migration.MigrationError,
        match="同名外键定义不匹配",
    ):
        migration._foreign_key_present_and_exact(
            cursor,
            "oj_test",
            reference,
        )


def test_check_reports_missing_objects_without_executing_ddl(monkeypatch):
    presence = _complete_presence()
    presence[("index", migration.PARENT_UNIQUE_NAME)] = False
    cursor = SimpleNamespace(execute=lambda *_args, **_kwargs: None)

    monkeypatch.setattr(
        migration,
        "_assert_foreign_key_checks_enabled",
        lambda _cursor: None,
    )
    monkeypatch.setattr(
        migration,
        "_assert_source_schema",
        lambda _cursor, _database: None,
    )
    monkeypatch.setattr(
        migration,
        "_audit_identity_ownership",
        lambda _cursor: _zero_anti_join_counts(),
    )
    monkeypatch.setattr(
        migration,
        "_inspect_expected_objects",
        lambda _cursor, _database: presence,
    )

    report = migration.migrate(
        cursor,
        database="oj_test",
        apply=False,
    )

    assert report.complete is False
    assert report.applied_statements == ()
    assert report.missing_objects == (
        "index:forum_anonymous_identities."
        "uq_forum_anonymous_identity_owner",
    )


def test_apply_idempotently_fills_partial_state_in_dependency_order(monkeypatch):
    initial_presence = _complete_presence()
    initial_presence[
        ("index", migration.OWNERSHIP_REFERENCES[0].index_name)
    ] = False
    initial_presence[
        (
            "foreign_key",
            migration.OWNERSHIP_REFERENCES[0].constraint_name,
        )
    ] = False
    final_presence = _complete_presence()
    inspections = iter((initial_presence, final_presence))
    executed = []
    cursor = SimpleNamespace(
        execute=lambda statement, *_args, **_kwargs: executed.append(
            statement
        )
    )

    monkeypatch.setattr(
        migration,
        "_assert_foreign_key_checks_enabled",
        lambda _cursor: None,
    )
    monkeypatch.setattr(
        migration,
        "_assert_source_schema",
        lambda _cursor, _database: None,
    )
    monkeypatch.setattr(
        migration,
        "_audit_identity_ownership",
        lambda _cursor: _zero_anti_join_counts(),
    )
    monkeypatch.setattr(
        migration,
        "_inspect_expected_objects",
        lambda _cursor, _database: next(inspections),
    )
    verified = []
    monkeypatch.setattr(
        migration,
        "_verify_step",
        lambda _cursor, _database, step: verified.append(step),
    )

    report = migration.migrate(
        cursor,
        database="oj_test",
        apply=True,
    )

    expected_steps = (
        migration.CHILD_INDEX_STEPS[0],
        migration.CHILD_FOREIGN_KEY_STEPS[0],
    )
    assert tuple(verified) == expected_steps
    assert tuple(executed) == tuple(step.sql for step in expected_steps)
    assert report.applied_statements == tuple(executed)
    assert report.complete is True


def test_apply_is_noop_when_every_expected_object_is_already_exact(monkeypatch):
    presence = _complete_presence()
    executed = []
    cursor = SimpleNamespace(
        execute=lambda statement, *_args, **_kwargs: executed.append(
            statement
        )
    )

    monkeypatch.setattr(
        migration,
        "_assert_foreign_key_checks_enabled",
        lambda _cursor: None,
    )
    monkeypatch.setattr(
        migration,
        "_assert_source_schema",
        lambda _cursor, _database: None,
    )
    monkeypatch.setattr(
        migration,
        "_audit_identity_ownership",
        lambda _cursor: _zero_anti_join_counts(),
    )
    monkeypatch.setattr(
        migration,
        "_inspect_expected_objects",
        lambda _cursor, _database: presence,
    )

    report = migration.migrate(
        cursor,
        database="oj_test",
        apply=True,
    )

    assert executed == []
    assert report.complete is True
    assert report.applied_statements == ()


def test_execute_check_holds_advisory_lock_and_rolls_back_read_only(
    monkeypatch,
):
    report = migration.MigrationReport(
        complete=True,
        invalid_reference_counts=_zero_anti_join_counts(),
        missing_objects=(),
        applied_statements=(),
    )

    class Cursor:
        def __init__(self):
            self.executed = []
            self.result = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement, params=None):
            self.executed.append((statement, params))
            if "GET_LOCK" in statement:
                self.result = {"locked": 1}
            elif "RELEASE_LOCK" in statement:
                self.result = {"released": 1}

        def fetchone(self):
            return self.result

    class Connection:
        def __init__(self):
            self.cursor_instance = Cursor()
            self.commits = 0
            self.rollbacks = 0
            self.closed = False

        def cursor(self):
            return self.cursor_instance

        def commit(self):
            self.commits += 1

        def rollback(self):
            self.rollbacks += 1

        def close(self):
            self.closed = True

    connection = Connection()
    settings = SimpleNamespace(database="oj_test")
    monkeypatch.setattr(migration, "load_config", lambda: object())
    monkeypatch.setattr(
        migration,
        "settings_from_config",
        lambda _config: settings,
    )
    monkeypatch.setattr(
        migration,
        "connect_mysql",
        lambda *_args, **_kwargs: connection,
    )
    monkeypatch.setattr(
        migration,
        "migrate",
        lambda _cursor, *, database, apply: report,
    )

    actual = migration.execute_migration(apply=False)

    assert actual is report
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert connection.closed is True
    statements = [
        statement
        for statement, _params in connection.cursor_instance.executed
    ]
    assert statements == [
        "SELECT GET_LOCK(%s, %s) AS locked",
        "SELECT RELEASE_LOCK(%s) AS released",
    ]
