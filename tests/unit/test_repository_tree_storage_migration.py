#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from contextlib import contextmanager
import hashlib
import json

import pytest

from scripts.migrations import m20260725_repository_tree_storage as migration


def _normalized_row(row_id, path, content, *, user_id=3):
    encoded = content.encode("utf-8")
    return {
        "id": row_id,
        "user_id": user_id,
        "filename": path,
        "file_content": content,
        "file_size": len(encoded),
        "created_at": None,
        "updated_at": None,
        "relative_path": path,
        "normalized_content": content,
        "normalized_size": len(encoded),
        "normalized_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def test_interrupted_tree_correct_subset_returns_only_missing_rows(monkeypatch):
    rows = [
        _normalized_row(1, "include/a.h", "a\n"),
        _normalized_row(2, "src/b.cpp", "b\n"),
    ]
    monkeypatch.setattr(
        migration,
        "get_repository_tree_snapshot",
        lambda *_args, **_kwargs: {
            "structure_version": 8,
            "entries": [
                {"kind": "directory", "relative_path": "include"},
                {"kind": "directory", "relative_path": "src"},
                {
                    "kind": "file",
                    "relative_path": "include/a.h",
                    "file_size": rows[0]["normalized_size"],
                    "sha256": rows[0]["normalized_sha256"],
                },
            ],
        },
    )

    snapshot, missing = migration._inspect_authoritative_user_tree(3, rows)

    assert snapshot["structure_version"] == 8
    assert [row["relative_path"] for row in missing] == ["src/b.cpp"]


@pytest.mark.parametrize(
    "entries",
    (
        [
            {
                "kind": "file",
                "relative_path": "extra.h",
                "file_size": 1,
                "sha256": "0" * 64,
            }
        ],
        [
            {"kind": "directory", "relative_path": "extra"},
        ],
        [
            {
                "kind": "file",
                "relative_path": "a.h",
                "file_size": 99,
                "sha256": "f" * 64,
            }
        ],
    ),
)
def test_interrupted_tree_rejects_extra_or_digest_drift(monkeypatch, entries):
    rows = [_normalized_row(1, "a.h", "a\n")]
    monkeypatch.setattr(
        migration,
        "get_repository_tree_snapshot",
        lambda *_args, **_kwargs: {
            "structure_version": 2,
            "entries": entries,
        },
    )

    with pytest.raises(migration.MigrationError):
        migration._inspect_authoritative_user_tree(3, rows)


class _MigrationCursor:
    def __init__(self, *, delete_count=0):
        self.delete_count = delete_count
        self.rowcount = 0
        self._one = None
        self.executed = []

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append((normalized, params))
        if normalized.startswith("SELECT source_file_count"):
            self._one = None
            self.rowcount = 0
        elif normalized.startswith("DELETE FROM user_code_repository"):
            self.rowcount = self.delete_count
            self._one = None
        else:
            self.rowcount = 1
            self._one = None

    def fetchone(self):
        return self._one


class _MigrationConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.commits = 0

    @contextmanager
    def cursor(self):
        yield self.cursor_value

    def commit(self):
        self.commits += 1


def test_migrate_user_resumes_only_missing_file(monkeypatch):
    rows = [
        _normalized_row(1, "a.h", "a\n"),
        _normalized_row(2, "b.h", "b\n"),
    ]
    plan = migration.UserPlan(
        user_id=3,
        file_count=2,
        total_size=sum(row["normalized_size"] for row in rows),
        manifest_sha256="a" * 64,
    )
    monkeypatch.setattr(
        migration,
        "_inspect_authoritative_user_tree",
        lambda *_args, **_kwargs: (
            {"structure_version": 6},
            [rows[1]],
        ),
    )
    monkeypatch.setattr(
        migration,
        "_verify_authoritative_user_tree",
        lambda *_args, **_kwargs: {"entries": []},
    )
    upserts = []
    monkeypatch.setattr(
        migration,
        "upsert_repository_file_by_path",
        lambda user_id, path, content, **kwargs: (
            upserts.append((user_id, path, content, kwargs))
            or {"structure_version": 7}
        ),
    )
    cursor = _MigrationCursor(delete_count=2)
    connection = _MigrationConnection(cursor)

    migration._migrate_user(connection, 3, rows, plan)

    assert [(item[0], item[1]) for item in upserts] == [(3, "b.h")]
    assert upserts[0][3] == {
        "expected_structure_version": 6,
        "overwrite": False,
    }
    assert connection.commits == 1


class _DryRunCursor:
    def __init__(self, legacy_rows, *, include_legacy=True):
        self.legacy_rows = legacy_rows
        self.include_legacy = include_legacy
        self._one = None
        self._many = []

    def execute(self, sql, _params=()):
        normalized = " ".join(str(sql).split())
        if normalized.startswith("SELECT GET_LOCK"):
            self._one = {"locked": 1}
            self._many = []
        elif "FROM INFORMATION_SCHEMA.TABLES" in normalized:
            self._one = None
            tables = set(migration.REQUIRED_TABLES)
            if self.include_legacy:
                tables.add(migration.LEGACY_TABLE)
            self._many = [
                {"table_name": table}
                for table in sorted(tables)
            ]
        elif normalized.startswith("SELECT COALESCE(MAX(id), 0)"):
            self._one = {"high_water": 42}
            self._many = []
        elif "FROM user_code_repository" in normalized:
            self._one = None
            self._many = list(self.legacy_rows)
        elif normalized.startswith("SELECT RELEASE_LOCK"):
            self._one = {"released": 1}
            self._many = []
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return list(self._many)


class _DryRunConnection:
    def __init__(self, legacy_rows, *, include_legacy=True):
        self.cursor_value = _DryRunCursor(
            legacy_rows,
            include_legacy=include_legacy,
        )
        self.rolled_back = False

    @contextmanager
    def cursor(self):
        yield self.cursor_value

    def rollback(self):
        self.rolled_back = True

    def commit(self):
        return None

    def close(self):
        return None


def test_dry_run_never_writes_storage_or_database(monkeypatch):
    legacy = {
        "id": 1,
        "user_id": 3,
        "filename": "a.h",
        "file_content": "a\r\n",
        "file_size": 3,
        "created_at": None,
        "updated_at": None,
    }
    connection = _DryRunConnection([legacy])
    monkeypatch.setattr(migration, "load_config", lambda: object())
    monkeypatch.setattr(
        migration,
        "settings_from_config",
        lambda _config: type("Settings", (), {"database": "test"})(),
    )
    monkeypatch.setattr(
        migration,
        "connect_mysql",
        lambda *_args, **_kwargs: connection,
    )
    monkeypatch.setattr(
        migration,
        "_ensure_rollback_backup",
        lambda *_args, **_kwargs: pytest.fail("dry-run must not create backup"),
    )
    monkeypatch.setattr(
        migration,
        "_migrate_user",
        lambda *_args, **_kwargs: pytest.fail("dry-run must not migrate"),
    )

    report = migration.execute_migration(apply=False)

    assert report.apply is False
    assert report.legacy_high_water == 42
    assert report.legacy_file_count == 1
    assert report.users[0].file_count == 1
    assert connection.rolled_back is True


def test_rollback_backup_digest_detects_tampering():
    unsigned = {
        "schema_version": migration.ROLLBACK_BACKUP_SCHEMA_VERSION,
        "migration_id": migration.MIGRATION_ID,
        "legacy_high_water": 9,
        "rows": [],
    }
    payload = {
        **unsigned,
        "payload_sha256": migration._backup_payload_digest(unsigned),
    }
    assert migration._decode_rollback_backup(json.dumps(payload))["legacy_high_water"] == 9
    payload["legacy_high_water"] = 10
    with pytest.raises(migration.MigrationError, match="摘要"):
        migration._decode_rollback_backup(json.dumps(payload))


def test_fresh_install_without_legacy_body_table_is_safe_noop(monkeypatch):
    connection = _DryRunConnection([], include_legacy=False)
    monkeypatch.setattr(migration, "load_config", lambda: object())
    monkeypatch.setattr(
        migration,
        "settings_from_config",
        lambda _config: type("Settings", (), {"database": "test"})(),
    )
    monkeypatch.setattr(
        migration,
        "connect_mysql",
        lambda *_args, **_kwargs: connection,
    )

    report = migration.execute_migration(apply=False)

    assert report.legacy_file_count == 0
    assert report.users == ()
