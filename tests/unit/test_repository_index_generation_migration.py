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


class _IndexCursor:
    def __init__(self, indexes):
        self.indexes = dict(indexes)
        self.executed = []
        self._rows = []

    def execute(self, sql, _params=()):
        normalized = " ".join(str(sql).split())
        self.executed.append(normalized)
        if normalized.startswith("SHOW INDEX FROM"):
            table = normalized.rsplit("`", 2)[1]
            self._rows = []
            for name, (unique, columns) in self.indexes.get(table, {}).items():
                for position, column in enumerate(columns, start=1):
                    self._rows.append({
                        "Key_name": name,
                        "Non_unique": 0 if unique else 1,
                        "Column_name": column,
                        "Seq_in_index": position,
                    })
            return
        raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchall(self):
        return list(self._rows)


@pytest.mark.parametrize(
    "indexes",
    [
        {
            "uk_repository_chunk_embeddings_user_chunk": (
                True,
                ("user_id", "chunk_id"),
            ),
            "idx_repository_chunk_embeddings_user_chunk": (
                False,
                ("user_id", "chunk_id"),
            ),
        },
        {
            # 覆盖首次发布在删除普通索引后被 MySQL 中止的可重入现场。
            "uk_repository_chunk_embeddings_user_chunk": (
                True,
                ("user_id", "chunk_id"),
            ),
        },
    ],
)
def test_embedding_index_replacement_plans_temporary_fk_support(indexes):
    cursor = _IndexCursor({"repository_chunk_embeddings": indexes})
    actions = []

    active = migration._prepare_temporary_fk_indexes(
        cursor,
        apply=False,
        actions=actions,
    )
    migration._remove_temporary_fk_indexes(
        cursor,
        active,
        apply=False,
        actions=actions,
    )

    assert active == {
        (
            "repository_chunk_embeddings",
            "idx_repository_chunk_embeddings_migration_user_fk",
        )
    }
    assert actions == [
        "ALTER TABLE `repository_chunk_embeddings` "
        "ADD KEY `idx_repository_chunk_embeddings_migration_user_fk` (`user_id`)",
        "ALTER TABLE `repository_chunk_embeddings` "
        "DROP INDEX `idx_repository_chunk_embeddings_migration_user_fk`",
    ]


def test_completed_embedding_schema_does_not_plan_temporary_index():
    cursor = _IndexCursor({
        "repository_chunk_embeddings": {
            "uk_repository_chunk_embeddings_generation_chunk": (
                True,
                ("user_id", "index_generation", "chunk_id"),
            ),
            "idx_repository_chunk_embeddings_user_chunk": (
                False,
                ("user_id", "index_generation", "chunk_id"),
            ),
        },
    })
    actions = []

    active = migration._prepare_temporary_fk_indexes(
        cursor,
        apply=False,
        actions=actions,
    )

    assert active == set()
    assert actions == []


def test_completed_embedding_schema_cleans_up_residual_temporary_index():
    temporary_name = "idx_repository_chunk_embeddings_migration_user_fk"
    cursor = _IndexCursor({
        "repository_chunk_embeddings": {
            "uk_repository_chunk_embeddings_generation_chunk": (
                True,
                ("user_id", "index_generation", "chunk_id"),
            ),
            "idx_repository_chunk_embeddings_user_chunk": (
                False,
                ("user_id", "index_generation", "chunk_id"),
            ),
            temporary_name: (False, ("user_id",)),
        },
    })
    actions = []

    active = migration._prepare_temporary_fk_indexes(
        cursor,
        apply=False,
        actions=actions,
    )
    migration._remove_temporary_fk_indexes(
        cursor,
        active,
        apply=False,
        actions=actions,
    )

    assert actions == [
        "ALTER TABLE `repository_chunk_embeddings` "
        f"DROP INDEX `{temporary_name}`",
    ]


def test_temporary_embedding_fk_index_with_wrong_definition_fails_closed():
    cursor = _IndexCursor({
        "repository_chunk_embeddings": {
            "idx_repository_chunk_embeddings_migration_user_fk": (
                False,
                ("chunk_id",),
            ),
        },
    })

    with pytest.raises(
        migration.IndexSchemaMigrationError,
        match="迁移临时索引定义不匹配",
    ):
        migration._prepare_temporary_fk_indexes(
            cursor,
            apply=False,
            actions=[],
        )
