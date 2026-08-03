# -*- coding: utf-8 -*-

from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import migrate_llm_endpoint_model_identity as migration


_PRIMARY_INDEX = migration.IndexDefinition(
    unique=True,
    columns=("id",),
    sub_parts=(None,),
)
_UNIQUE_MODEL_INDEX = migration.IndexDefinition(
    unique=True,
    columns=("model",),
    sub_parts=(None,),
)
_LOOKUP_MODEL_INDEX = migration.IndexDefinition(
    unique=False,
    columns=("model",),
    sub_parts=(None,),
)
_UNIQUE_NAME_INDEX = migration.IndexDefinition(
    unique=True,
    columns=("name",),
    sub_parts=(None,),
)


class _FakeCursor:
    def __init__(
        self,
        *,
        table_exists=True,
        has_name=False,
        model_nullable=False,
        model_index="lookup",
        empty_models=None,
        duplicate_models=None,
        unexpected_model_unique_index=None,
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
                "Null": "NO",
            }

        self.indexes = {"PRIMARY": _PRIMARY_INDEX}
        if has_name:
            self.indexes[migration.LEGACY_NAME_INDEX_NAME] = (
                _UNIQUE_NAME_INDEX
            )
        if model_index in {"unique", "both"}:
            self.indexes[migration.MODEL_INDEX_NAME] = _UNIQUE_MODEL_INDEX
        if model_index in {"lookup", "both"}:
            self.indexes[migration.MODEL_LOOKUP_INDEX_NAME] = (
                _LOOKUP_MODEL_INDEX
            )
        if model_index == "wrong_unique":
            self.indexes[migration.MODEL_INDEX_NAME] = _LOOKUP_MODEL_INDEX
        elif model_index == "wrong_lookup":
            self.indexes[migration.MODEL_LOOKUP_INDEX_NAME] = (
                _UNIQUE_MODEL_INDEX
            )
        elif model_index not in {
            "none",
            "unique",
            "lookup",
            "both",
            "wrong_unique",
            "wrong_lookup",
        }:
            raise ValueError(f"未知 model_index 测试状态：{model_index}")
        if unexpected_model_unique_index:
            self.indexes[unexpected_model_unique_index] = _UNIQUE_MODEL_INDEX

        self.empty_models = list(empty_models or [])
        self.duplicate_models = list(duplicate_models or [])
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
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN model varchar(255) NOT NULL"
        ):
            self.columns["model"]["Null"] = "NO"
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "DROP INDEX uq_llm_endpoint_name"
        ):
            self.indexes.pop(migration.LEGACY_NAME_INDEX_NAME, None)
        elif normalized == "ALTER TABLE llm_endpoints DROP COLUMN name":
            self.columns.pop("name", None)
            for name in list(self.indexes):
                if "name" in self.indexes[name].columns:
                    self.indexes.pop(name)
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "DROP INDEX uq_llm_endpoint_model, "
            "ADD KEY idx_llm_endpoint_model (model)"
        ):
            self.indexes.pop(migration.MODEL_INDEX_NAME, None)
            self.indexes[migration.MODEL_LOOKUP_INDEX_NAME] = (
                _LOOKUP_MODEL_INDEX
            )
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "DROP INDEX uq_llm_endpoint_model"
        ):
            self.indexes.pop(migration.MODEL_INDEX_NAME, None)
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "ADD KEY idx_llm_endpoint_model (model)"
        ):
            self.indexes[migration.MODEL_LOOKUP_INDEX_NAME] = (
                _LOOKUP_MODEL_INDEX
            )
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "DROP INDEX idx_llm_endpoint_model, "
            "ADD UNIQUE KEY uq_llm_endpoint_model (model)"
        ):
            self.indexes.pop(migration.MODEL_LOOKUP_INDEX_NAME, None)
            self.indexes[migration.MODEL_INDEX_NAME] = _UNIQUE_MODEL_INDEX
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "ADD UNIQUE KEY uq_llm_endpoint_model (model)"
        ):
            self.indexes[migration.MODEL_INDEX_NAME] = _UNIQUE_MODEL_INDEX
        elif normalized == (
            "ALTER TABLE llm_endpoints "
            "DROP INDEX idx_llm_endpoint_model"
        ):
            self.indexes.pop(migration.MODEL_LOOKUP_INDEX_NAME, None)

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


def _duplicate_models():
    return [{
        "model": "qwen",
        "endpoint_count": 2,
        "endpoint_ids": "7,8",
    }]


def test_forward_plan_replaces_unique_model_index_with_lookup_index():
    cursor = _FakeCursor(model_index="unique")

    assert _sqls(migration.build_forward_plan(cursor)) == [
        "ALTER TABLE llm_endpoints "
        "DROP INDEX uq_llm_endpoint_model, "
        "ADD KEY idx_llm_endpoint_model (model)",
    ]


def test_forward_apply_accepts_duplicate_models_in_legacy_name_schema():
    cursor = _FakeCursor(
        has_name=True,
        model_index="none",
        duplicate_models=_duplicate_models(),
    )
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection, apply=True)

    assert _sqls(plan) == [
        "ALTER TABLE llm_endpoints DROP INDEX uq_llm_endpoint_name",
        "ALTER TABLE llm_endpoints DROP COLUMN name",
        "ALTER TABLE llm_endpoints ADD KEY idx_llm_endpoint_model (model)",
    ]
    assert "name" not in cursor.columns
    assert migration.LEGACY_NAME_INDEX_NAME not in cursor.indexes
    assert cursor.indexes[migration.MODEL_LOOKUP_INDEX_NAME] == (
        _LOOKUP_MODEL_INDEX
    )
    assert not any(
        "GROUP BY model HAVING COUNT(*) > 1" in sql
        for sql, _params in cursor.calls
    )


def test_forward_plan_is_noop_for_target_schema_even_with_duplicates():
    cursor = _FakeCursor(
        model_index="lookup",
        duplicate_models=_duplicate_models(),
    )

    assert migration.build_forward_plan(cursor) == []
    assert not any(
        "GROUP BY model HAVING COUNT(*) > 1" in sql
        for sql, _params in cursor.calls
    )


def test_forward_plan_is_noop_before_fresh_database_bootstrap():
    cursor = _FakeCursor(table_exists=False, model_index="none")

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
        ({"model_index": "wrong_unique"}, "定义与预期不一致"),
        ({"model_index": "wrong_lookup"}, "定义与预期不一致"),
        (
            {
                "model_index": "lookup",
                "unexpected_model_unique_index": "uq_custom_model",
            },
            "非标准唯一索引",
        ),
    ],
)
def test_forward_plan_fails_closed_on_unsafe_data_or_model_indexes(
    kwargs,
    message,
):
    cursor = _FakeCursor(**kwargs)

    with pytest.raises(migration.MigrationBlockedError, match=message):
        migration.build_forward_plan(cursor)


def test_default_migrate_is_read_only_but_holds_advisory_lock():
    cursor = _FakeCursor(model_index="unique")
    connection = _FakeConnection(cursor)

    plan = migration.migrate(connection)

    planned_sql = set(_sqls(plan))
    executed_sql = {sql for sql, _params in cursor.calls}
    assert not planned_sql.intersection(executed_sql)
    assert "SELECT GET_LOCK(%s, %s) AS locked" in executed_sql
    assert "SELECT RELEASE_LOCK(%s)" in executed_sql
    assert connection.rollbacks == 1
    assert migration.MODEL_INDEX_NAME in cursor.indexes
    assert migration.MODEL_LOOKUP_INDEX_NAME not in cursor.indexes


def test_forward_apply_is_idempotent_and_resumes_after_partial_ddl():
    cursor = _FakeCursor(
        has_name=True,
        model_index="none",
        duplicate_models=_duplicate_models(),
        fail_once_when="ADD KEY idx_llm_endpoint_model",
    )
    connection = _FakeConnection(cursor)

    with pytest.raises(RuntimeError, match="模拟 DDL 中断"):
        migration.migrate(connection, apply=True)

    assert "name" not in cursor.columns
    assert migration.LEGACY_NAME_INDEX_NAME not in cursor.indexes
    assert migration.MODEL_LOOKUP_INDEX_NAME not in cursor.indexes

    resumed = migration.migrate(connection, apply=True)
    repeated = migration.migrate(connection, apply=True)

    assert _sqls(resumed) == [
        "ALTER TABLE llm_endpoints ADD KEY idx_llm_endpoint_model (model)",
    ]
    assert repeated == []
    assert cursor.indexes[migration.MODEL_LOOKUP_INDEX_NAME] == (
        _LOOKUP_MODEL_INDEX
    )


def test_rollback_replaces_lookup_index_with_unique_model_index():
    cursor = _FakeCursor(model_index="lookup")

    assert _sqls(migration.build_rollback_plan(cursor)) == [
        "ALTER TABLE llm_endpoints "
        "DROP INDEX idx_llm_endpoint_model, "
        "ADD UNIQUE KEY uq_llm_endpoint_model (model)",
    ]


def test_rollback_apply_is_idempotent():
    cursor = _FakeCursor(model_index="lookup")
    connection = _FakeConnection(cursor)

    first = migration.migrate(connection, apply=True, rollback=True)
    second = migration.migrate(connection, apply=True, rollback=True)

    assert first
    assert second == []
    assert cursor.indexes[migration.MODEL_INDEX_NAME] == (
        _UNIQUE_MODEL_INDEX
    )
    assert migration.MODEL_LOOKUP_INDEX_NAME not in cursor.indexes
    assert "name" not in cursor.columns


def test_rollback_blocks_duplicate_models_before_executing_ddl():
    cursor = _FakeCursor(
        model_index="lookup",
        duplicate_models=_duplicate_models(),
    )
    connection = _FakeConnection(cursor)

    with pytest.raises(
        migration.MigrationBlockedError,
        match="无法恢复旧的唯一约束",
    ):
        migration.migrate(connection, apply=True, rollback=True)

    assert not any(sql.startswith("ALTER TABLE") for sql, _ in cursor.calls)
    assert migration.MODEL_LOOKUP_INDEX_NAME in cursor.indexes
    assert migration.MODEL_INDEX_NAME not in cursor.indexes


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


@pytest.mark.parametrize(
    "arguments",
    [
        ["--apply"],
        ["--apply", "--confirm-app-writers-stopped"],
        ["--apply", "--confirm-backup-verified"],
        ["--rollback", "--apply", "--confirm-app-writers-stopped"],
        ["--rollback", "--apply", "--confirm-backup-verified"],
    ],
)
def test_cli_apply_requires_both_safety_confirmations(tmp_path, arguments):
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "migrate_llm_endpoint_model_identity.py"
    )

    result = subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--apply requires" in result.stderr
