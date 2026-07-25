#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from scripts.migrations import m20260725_repository_index_generations as migration


class _AuditCursor:
    def __init__(self, columns_by_table, negative_count=0):
        self.columns_by_table = columns_by_table
        self.negative_count = int(negative_count)
        self.executed = []
        self._rows = []
        self._one = None

    def execute(self, sql, _params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append(normalized)
        if normalized.startswith("SHOW FULL COLUMNS FROM"):
            table = normalized.rsplit("`", 2)[1]
            self._rows = [
                {"Field": name}
                for name in self.columns_by_table.get(table, ())
            ]
            self._one = None
        elif "WHERE repo_file_id IS NOT NULL" in normalized:
            self._rows = []
            self._one = {"n": self.negative_count}
        elif "HAVING COUNT(*) > 1" in normalized:
            self._rows = []
            self._one = {"n": 0}
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._one


def test_audit_accepts_legacy_schema_before_repo_file_id_is_added():
    cursor = _AuditCursor({
        "repository_function_chunks": ("id", "user_id", "chunk_id"),
        "repository_class_metadata": ("id", "user_id", "class_id"),
    })

    migration._audit_data(cursor)

    assert not any(
        "WHERE repo_file_id IS NOT NULL" in sql
        for sql in cursor.executed
    )


def test_audit_still_rejects_negative_repo_file_id_when_column_exists():
    cursor = _AuditCursor({
        "repository_function_chunks": ("id", "user_id", "chunk_id", "repo_file_id"),
        "repository_class_metadata": ("id", "user_id", "class_id", "repo_file_id"),
    }, negative_count=1)

    with pytest.raises(migration.IndexSchemaMigrationError, match="含负数"):
        migration._audit_data(cursor)
