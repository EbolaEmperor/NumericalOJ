# -*- coding: utf-8 -*-

from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import migrate_llm_endpoint_model_identity as migration


class _FakeCursor:
    def __init__(
        self,
        *,
        table_exists=True,
        has_name=True,
        model_nullable=False,
        name_nullable=False,
        empty_models=None,
        duplicate_models=None,
        empty_names=None,
        duplicate_names=None,
        oversized_models=None,
        nullable_name_conflicts=None,
        nullable_name_has_null=False,
        wrong_model_index=False,
        fail_once_when=None,
    ):
        self.table_exists = table_exists
        self.columns = {
            "id": {"Field": "id", "Type": "bigint", "Null": "NO"},
            "model": {
                "Field": "model",
                "Type": "varchar(255)",
                "Null": "YES" if model_nullable else "NO",
            },
        }
        if has_name:
            self.columns["name"] = {
                "Field": "name",
                "Type": "varchar(120)",
                "Null": "YES" if name_nullable else "NO",
            }
        self.indexes = {
            "PRIMARY": migration.IndexDefinition(
                unique=True,
                columns=("id",),
                sub_parts=(None,),
            ),
        }
        if has_name:
            self.indexes[migration.LEGACY_NAME_INDEX_NAME] = (
                migration.IndexDefinition(
                    unique=True,
                    columns=("name",),
                    sub_parts=(None,),
                )
            )
        if wrong_model_index:
            self.indexes[migration.MODEL_INDEX_NAME] = (
                migration.IndexDefinition(
                    unique=False,
                    columns=("model",),
                    sub_parts=(None,),
                )
            )
        elif not has_name:
            self.indexes[migration.MODEL_INDEX_NAME] = (
                migration.IndexDefinition(
                    unique=True,
                    columns=("model",),
                    sub_parts=(None,),
                )
            )

        self.empty_models = list(empty_models or [])
        self.duplicate_models = list(duplicate_models or [])
        self.empty_names = list(empty_names or [])
        self.duplicate_names = list(duplicate_names or [])
        self.oversized_models = list(oversized_models or [])
        self.nullable_name_conflicts = list(nullable_name_conflicts or [])
        self.nullable_name_has_null = nullable_name_has_null
        self.fail_once_when = fail_once_when
        self.calls = []
        self._fetchone_result = None
        self._fetchall_result = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.calls.append((normalized, params))
        self._fetchone_result = None
        self._fetchall_result = []
        if self.fail_once_when and self.fail_once_when in normalized:
            self.fail_once_when = None
            raise RuntimeError("模拟 DDL 中断")

        if normalized == "SHOW TABLES LIKE %s":
            self._fetchone_result = (
                {"table": migration.TABLE_NAME}
                if self.table_exists
                else None
            )
        elif normalized == "SHOW COLUMNS FROM `llm_endpoints`":
            self._fetchall_result = list(self.columns.values())
        elif normalized == "SHOW INDEX FROM `llm_endpoints`":
            rows = []
            for name, definition in self.indexes.items():
                for position, (column, sub_part) in enumerate(
                    zip(definition.columns, definition.sub_parts),
                    start=1,
                ):
                    rows.append({
                        "Key_name": name,
                        "Non_unique": 0 if definition.unique else 1,
                        "Seq_in_index": position,
                        "Column_name": column,
                        "Sub_part": sub_part,
                    })
            self._fetchall_result = rows
        elif normalized.startswith("SELECT GET_LOCK"):
            self._fetchone_result = {"locked": 1}
        elif normalized.startswith("SELECT RELEASE_LOCK"):
            self._fetchone_result = {"released": 1}
        elif "WHERE model IS NULL OR TRIM(model) = ''" in normalized:
            self._fetchall_result = self.empty_models
        elif "GROUP BY model HAVING COUNT(*) > 1" in normalized:
            self._fetchall_result = self.duplicate_models
        elif "WHERE name IS NULL OR TRIM(name) = ''" in normalized:
            self._fetchall_result = self.empty_names
        elif "GROUP BY name HAVING COUNT(*) > 1" in normalized:
            self._fetchall_result = self.duplicate_names
        elif "WHERE CHAR_LENGTH(model) > %s" in normalized:
            self._fetchall_result = self.oversized_models
        elif "WHERE name IS NOT NULL AND name <> model" in normalized:
            self._fetchall_result = self.nullable_name_conflicts
        elif normalized == (
            "SELECT id FROM llm_endpoints WHERE name IS NULL LIMIT 1"
        ):
            self._fetchone_result = (
                {"id": 1} if self.nullable_name_has_null else None
            )
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN model varchar(255) NOT NULL"
        ):
            self.columns["model"]["Null"] = "NO"
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "ADD UNIQUE KEY uq_llm_endpoint_model (model)"
        ):
            self.indexes[migration.MODEL_INDEX_NAME] = (
                migration.IndexDefinition(True, ("model",), (None,))
            )
        elif normalized == (
            "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_name"
        ):
            self.indexes.pop(migration.LEGACY_NAME_INDEX_NAME, None)
        elif normalized == (
            "ALTER TABLE llm_endpoints DROP COLUMN name"
        ):
            self.columns.pop("name", None)
            for name in list(self.indexes):
                if "name" in self.indexes[name].columns:
                    self.indexes.pop(name)
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "ADD COLUMN name varchar(120) NULL AFTER id"
        ):
            self.columns["name"] = {
                "Field": "name",
                "Type": "varchar(120)",
                "Null": "YES",
            }
            self.nullable_name_has_null = True
        elif normalized in {
            "UPDATE llm_endpoints SET name = model",
            "UPDATE llm_endpoints SET name = model WHERE name IS NULL",
        }:
            self.nullable_name_has_null = False
            self.empty_names = []
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN name varchar(120) NOT NULL"
        ):
            self.columns["name"]["Null"] = "NO"
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "ADD UNIQUE KEY uq_llm_endpoint_name (name)"
        ):
            self.indexes[migration.LEGACY_NAME_INDEX_NAME] = (
                migration.IndexDefinition(True, ("name",), (None,))
            )
        elif normalized == (
            "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_model"
        ):
            self.indexes.pop(migration.MODEL_INDEX_NAME, None)

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


def _sqls(plan):
    return [" ".join(operation.sql.split()) for operation in plan]


def test_forward_plan_adds_model_uniqueness_before_dropping_name():
    cursor = _FakeCursor()

    sqls = _sqls(migration.build_forward_plan(cursor))

    assert sqls == [
        "ALTER TABLE llm_endpoints "
        "ADD UNIQUE KEY uq_llm_endpoint_model (model)",
        "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_name",
        "ALTER TABLE llm_endpoints DROP COLUMN name",
    ]


def test_forward_plan_is_noop_for_current_schema():
    cursor = _FakeCursor(has_name=False)

    assert migration.build_forward_plan(cursor) == []


def test_forward_plan_is_noop_before_fresh_database_bootstrap():
    cursor = _FakeCursor(table_exists=False)

    assert migration.build_forward_plan(cursor) == []


def test_connect_treats_an_absent_database_as_a_fresh_install(monkeypatch):
    settings = SimpleNamespace(database="fresh_db")
    server_connection = _FakeConnection(_FakeCursor())
    calls = []

    monkeypatch.setattr(migration, "load_config", lambda: object())
    monkeypatch.setattr(
        migration,
        "settings_from_config",
        lambda _config: settings,
    )
    monkeypatch.setattr(
        migration,
        "database_exists",
        lambda _cursor, _database: False,
    )

    def fake_connect(received_settings, *, with_database, dict_rows):
        calls.append((received_settings, with_database, dict_rows))
        if with_database:
            raise AssertionError("fresh install must not select an absent db")
        return server_connection

    monkeypatch.setattr(migration, "connect_mysql", fake_connect)
    assert migration._connect() is None
    assert calls == [(settings, False, True)]
    assert server_connection.closed is True


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"empty_models": [{"id": 7, "model": ""}]},
            "存在空 model",
        ),
        (
            {
                "duplicate_models": [{
                    "model": "qwen",
                    "endpoint_count": 2,
                    "endpoint_ids": "7,8",
                }],
            },
            "存在重复 model",
        ),
        ({"wrong_model_index": True}, "定义与预期不一致"),
    ],
)
def test_forward_plan_fails_closed_on_unsafe_data_or_schema(kwargs, message):
    cursor = _FakeCursor(**kwargs)

    with pytest.raises(migration.MigrationBlockedError, match=message):
        migration.build_forward_plan(cursor)


def test_default_migrate_is_read_only_but_holds_advisory_lock():
    cursor = _FakeCursor()
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection)

    planned_sql = set(_sqls(plan))
    executed_sql = {sql for sql, _params in cursor.calls}
    assert not planned_sql.intersection(executed_sql)
    assert "SELECT GET_LOCK(%s, %s) AS locked" in executed_sql
    assert "SELECT RELEASE_LOCK(%s)" in executed_sql
    assert connection.rollbacks == 1


def test_forward_apply_is_idempotent_and_resumes_after_partial_ddl():
    cursor = _FakeCursor(
        fail_once_when="DROP INDEX uq_llm_endpoint_name",
    )
    connection = _FakeConnection(cursor)

    with pytest.raises(RuntimeError, match="模拟 DDL 中断"):
        migration.migrate(connection, apply=True)

    assert migration.MODEL_INDEX_NAME in cursor.indexes
    assert "name" in cursor.columns

    resumed = migration.migrate(connection, apply=True)
    repeated = migration.migrate(connection, apply=True)

    assert _sqls(resumed) == [
        "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_name",
        "ALTER TABLE llm_endpoints DROP COLUMN name",
    ]
    assert repeated == []
    assert "name" not in cursor.columns


def test_rollback_recreates_name_from_model_then_removes_model_uniqueness():
    cursor = _FakeCursor(has_name=False)

    sqls = _sqls(migration.build_rollback_plan(cursor))

    assert sqls == [
        "ALTER TABLE llm_endpoints ADD COLUMN name varchar(120) NULL AFTER id",
        "UPDATE llm_endpoints SET name = model",
        "ALTER TABLE llm_endpoints "
        "MODIFY COLUMN name varchar(120) NOT NULL",
        "ALTER TABLE llm_endpoints "
        "ADD UNIQUE KEY uq_llm_endpoint_name (name)",
        "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_model",
    ]


def test_rollback_apply_is_idempotent():
    cursor = _FakeCursor(has_name=False)
    connection = _FakeConnection(cursor)

    first = migration.migrate(connection, apply=True, rollback=True)
    second = migration.migrate(connection, apply=True, rollback=True)

    assert first
    assert second == []
    assert "name" in cursor.columns
    assert migration.LEGACY_NAME_INDEX_NAME in cursor.indexes
    assert migration.MODEL_INDEX_NAME not in cursor.indexes


def test_rollback_resumes_after_only_nullable_name_was_added():
    cursor = _FakeCursor(
        has_name=True,
        name_nullable=True,
        nullable_name_has_null=True,
    )
    cursor.indexes.pop(migration.LEGACY_NAME_INDEX_NAME)
    cursor.indexes[migration.MODEL_INDEX_NAME] = (
        migration.IndexDefinition(True, ("model",), (None,))
    )

    sqls = _sqls(migration.build_rollback_plan(cursor))

    assert sqls[0] == (
        "UPDATE llm_endpoints SET name = model WHERE name IS NULL"
    )
    assert sqls[-1] == (
        "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_model"
    )


def test_rollback_blocks_model_that_cannot_fit_legacy_name():
    cursor = _FakeCursor(
        has_name=False,
        oversized_models=[{
            "id": 9,
            "model": "x" * 121,
            "model_length": 121,
        }],
    )

    with pytest.raises(
        migration.MigrationBlockedError,
        match="超过旧 name",
    ):
        migration.build_rollback_plan(cursor)


def test_cli_help_imports_from_an_arbitrary_working_directory(tmp_path):
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "migrate_llm_endpoint_model_identity.py"
    )

    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--rollback" in result.stdout
    assert "--confirm-app-writers-stopped" in result.stdout
    assert "--confirm-backup-verified" in result.stdout


def test_cli_apply_requires_both_safety_confirmations(tmp_path):
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "migrate_llm_endpoint_model_identity.py"
    )

    result = subprocess.run(
        [sys.executable, str(script), "--apply"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--apply requires" in result.stderr
