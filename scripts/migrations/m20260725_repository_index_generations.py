#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""显式迁移代码仓库索引表到 generation-aware schema。

此迁移必须在 ``scripts/init_db_schema.py`` 之前执行，因为旧
``idx_repository_function_chunks_user_file(user_id, filename)`` 会阻挡 filename
扩到 1024，而非破坏性 schema 同步也不会替换同名旧索引或删除旧 UNIQUE。默认只输出
计划；实际 DDL 要求全部应用写入者已停止且已有可验证数据库回滚点。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    load_config,
    settings_from_config,
)


MIGRATION_ID = "m20260725_repository_index_generations"
LOCK_NAME = "numericaloj:m20260725:repository_index_generations"
LOCK_TIMEOUT_SECONDS = 120
TABLES = {
    "repository_index_jobs",
    "repository_function_chunks",
    "repository_class_metadata",
    "repository_chunk_embeddings",
}

COLUMN_SPECS = {
    "repository_index_jobs": [
        (
            "base_repository_generation",
            "bigint unsigned NOT NULL DEFAULT '0' AFTER `user_id`",
            ("bigint unsigned", "NO", None, "0"),
        ),
    ],
    "repository_function_chunks": [
        (
            "index_generation",
            "bigint unsigned NOT NULL DEFAULT '0' AFTER `user_id`",
            ("bigint unsigned", "NO", None, "0"),
        ),
        (
            "repo_file_id",
            "bigint unsigned DEFAULT NULL",
            ("bigint unsigned", "YES", None, None),
        ),
        (
            "filename",
            "varchar(1024) CHARACTER SET utf8mb4 "
            "COLLATE utf8mb4_0900_as_cs NOT NULL",
            ("varchar(1024)", "NO", "utf8mb4_0900_as_cs", None),
        ),
        (
            "embedding_input_hash",
            "char(64) CHARACTER SET ascii COLLATE ascii_bin "
            "NOT NULL DEFAULT '' AFTER `source_hash`",
            ("char(64)", "NO", "ascii_bin", ""),
        ),
        (
            "parser_version",
            "varchar(64) CHARACTER SET ascii COLLATE ascii_bin "
            "NOT NULL DEFAULT '' AFTER `embedding_input_hash`",
            ("varchar(64)", "NO", "ascii_bin", ""),
        ),
        (
            "structured_model",
            "varchar(191) NOT NULL DEFAULT '' AFTER `parser_version`",
            ("varchar(191)", "NO", "utf8mb4_0900_ai_ci", ""),
        ),
    ],
    "repository_class_metadata": [
        (
            "index_generation",
            "bigint unsigned NOT NULL DEFAULT '0' AFTER `user_id`",
            ("bigint unsigned", "NO", None, "0"),
        ),
        (
            "repo_file_id",
            "bigint unsigned DEFAULT NULL",
            ("bigint unsigned", "YES", None, None),
        ),
        (
            "filename",
            "varchar(1024) CHARACTER SET utf8mb4 "
            "COLLATE utf8mb4_0900_as_cs NOT NULL",
            ("varchar(1024)", "NO", "utf8mb4_0900_as_cs", None),
        ),
    ],
    "repository_chunk_embeddings": [
        (
            "index_generation",
            "bigint unsigned NOT NULL DEFAULT '0' AFTER `user_id`",
            ("bigint unsigned", "NO", None, "0"),
        ),
    ],
}

LEGACY_INDEXES = {
    "repository_function_chunks": {
        "uk_repository_function_chunks_chunk_id",
    },
    "repository_class_metadata": {
        "uk_repository_class_metadata_class_id",
    },
    "repository_chunk_embeddings": {
        "uk_repository_chunk_embeddings_user_chunk",
    },
}

DESIRED_INDEXES = {
    "repository_function_chunks": {
        "uk_repository_function_chunks_generation_chunk": (
            True,
            ("user_id", "index_generation", "chunk_id"),
            "UNIQUE KEY `uk_repository_function_chunks_generation_chunk` "
            "(`user_id`,`index_generation`,`chunk_id`)",
        ),
        "idx_repository_function_chunks_user_file": (
            False,
            ("user_id", "repo_file_id"),
            "KEY `idx_repository_function_chunks_user_file` "
            "(`user_id`,`repo_file_id`)",
        ),
    },
    "repository_class_metadata": {
        "uk_repository_class_metadata_generation_class": (
            True,
            ("user_id", "index_generation", "class_id"),
            "UNIQUE KEY `uk_repository_class_metadata_generation_class` "
            "(`user_id`,`index_generation`,`class_id`)",
        ),
        "idx_repository_class_metadata_user_file": (
            False,
            ("user_id", "repo_file_id"),
            "KEY `idx_repository_class_metadata_user_file` "
            "(`user_id`,`repo_file_id`)",
        ),
    },
    "repository_chunk_embeddings": {
        "uk_repository_chunk_embeddings_generation_chunk": (
            True,
            ("user_id", "index_generation", "chunk_id"),
            "UNIQUE KEY `uk_repository_chunk_embeddings_generation_chunk` "
            "(`user_id`,`index_generation`,`chunk_id`)",
        ),
        "idx_repository_chunk_embeddings_user_chunk": (
            False,
            ("user_id", "index_generation", "chunk_id"),
            "KEY `idx_repository_chunk_embeddings_user_chunk` "
            "(`user_id`,`index_generation`,`chunk_id`)",
        ),
    },
}


class IndexSchemaMigrationError(RuntimeError):
    pass


def _quote(name):
    if not str(name).replace("_", "").isalnum():
        raise IndexSchemaMigrationError(f"非法固定标识符：{name}")
    return f"`{name}`"


def _acquire_lock(cursor):
    cursor.execute("SELECT GET_LOCK(%s, %s) AS locked", (LOCK_NAME, LOCK_TIMEOUT_SECONDS))
    if int((cursor.fetchone() or {}).get("locked") or 0) != 1:
        raise IndexSchemaMigrationError("无法取得仓库索引 schema 迁移锁")


def _release_lock(cursor):
    cursor.execute("SELECT RELEASE_LOCK(%s)", (LOCK_NAME,))


def _assert_tables(cursor, database):
    placeholders = ",".join(["%s"] * len(TABLES))
    cursor.execute(
        "SELECT TABLE_NAME AS table_name, ENGINE AS engine "
        "FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN ({placeholders})",
        (database, *sorted(TABLES)),
    )
    rows = cursor.fetchall() or []
    found = {row["table_name"]: str(row.get("engine") or "").upper() for row in rows}
    if not found:
        # 首次安装在 init_db_schema 之前尚无旧索引表；随后会直接按新定义创建。
        return False
    missing = sorted(TABLES - set(found))
    if missing:
        raise IndexSchemaMigrationError("缺少索引表：" + "、".join(missing))
    wrong_engine = sorted(name for name, engine in found.items() if engine != "INNODB")
    if wrong_engine:
        raise IndexSchemaMigrationError("索引表不是 InnoDB：" + "、".join(wrong_engine))
    return True


def _columns(cursor, table):
    cursor.execute(f"SHOW FULL COLUMNS FROM {_quote(table)}")
    return {row["Field"]: row for row in cursor.fetchall() or []}


def _indexes(cursor, table):
    cursor.execute(f"SHOW INDEX FROM {_quote(table)}")
    grouped = {}
    for row in cursor.fetchall() or []:
        grouped.setdefault(row["Key_name"], []).append(row)
    return {
        name: (
            int(rows[0]["Non_unique"]) == 0,
            tuple(
                row["Column_name"]
                for row in sorted(rows, key=lambda item: int(item["Seq_in_index"]))
            ),
        )
        for name, rows in grouped.items()
    }


def _column_matches(row, expected):
    expected_type, nullable, collation, default = expected
    return (
        str(row.get("Type") or "").lower() == expected_type
        and str(row.get("Null") or "").upper() == nullable
        and (collation is None or str(row.get("Collation") or "") == collation)
        and (
            default is None
            or str(row.get("Default") if row.get("Default") is not None else "")
            == str(default)
        )
    )


def _audit_data(cursor):
    for table in ("repository_function_chunks", "repository_class_metadata"):
        # 部分真实旧环境早于 repo_file_id 列，迁移本身稍后才会 ADD COLUMN。
        # 数据审计必须先按现有 schema 分支，不能因缺少待新增列而在 DDL 前失败。
        if "repo_file_id" not in _columns(cursor, table):
            continue
        cursor.execute(
            f"SELECT COUNT(*) AS n FROM {_quote(table)} "
            "WHERE repo_file_id IS NOT NULL AND repo_file_id < 0"
        )
        if int((cursor.fetchone() or {}).get("n") or 0):
            raise IndexSchemaMigrationError(
                f"{table}.repo_file_id 含负数，不能转为 bigint unsigned"
            )
    checks = (
        (
            "repository_function_chunks",
            "user_id, chunk_id",
            "function chunk",
        ),
        (
            "repository_class_metadata",
            "user_id, class_id",
            "class metadata",
        ),
        (
            "repository_chunk_embeddings",
            "user_id, chunk_id",
            "embedding",
        ),
    )
    for table, group_columns, label in checks:
        cursor.execute(
            f"SELECT COUNT(*) AS n FROM ("
            f"SELECT 1 FROM {_quote(table)} GROUP BY {group_columns} "
            "HAVING COUNT(*) > 1 LIMIT 1"
            ") AS duplicates"
        )
        if int((cursor.fetchone() or {}).get("n") or 0):
            raise IndexSchemaMigrationError(
                f"现有 {label} 数据在 generation=0 下存在重复键"
            )


def _execute_or_plan(cursor, sql, *, apply, actions):
    actions.append(sql)
    if apply:
        cursor.execute(sql)


def migrate_index_generation_schema(*, apply=False, writers_stopped_confirmed=False):
    if apply and not writers_stopped_confirmed:
        raise IndexSchemaMigrationError("拒绝迁移：未确认全部应用写入者已经停止")
    settings = settings_from_config(load_config())
    connection = connect_mysql(settings, with_database=True, dict_rows=True)
    actions = []
    locked = False
    try:
        with connection.cursor() as cursor:
            _acquire_lock(cursor)
            locked = True
            has_legacy_tables = _assert_tables(cursor, settings.database)
            if not has_legacy_tables:
                return {
                    "migration": MIGRATION_ID,
                    "apply": bool(apply),
                    "actions": [],
                    "fresh_install_noop": True,
                }
            _audit_data(cursor)

            # 先移除会阻挡 filename 扩列、或会让后续 generation 继续互相冲突的索引。
            for table in sorted(TABLES):
                existing = _indexes(cursor, table)
                names_to_drop = set(LEGACY_INDEXES.get(table, set()))
                for name, (unique, columns, _definition) in DESIRED_INDEXES.get(
                    table, {}
                ).items():
                    if name in existing and existing[name] != (unique, columns):
                        names_to_drop.add(name)
                for name in sorted(names_to_drop):
                    if name in existing:
                        _execute_or_plan(
                            cursor,
                            f"ALTER TABLE {_quote(table)} DROP INDEX {_quote(name)}",
                            apply=apply,
                            actions=actions,
                        )

            for table, specs in COLUMN_SPECS.items():
                existing_columns = _columns(cursor, table)
                for name, definition, expected in specs:
                    existing = existing_columns.get(name)
                    if existing is not None and _column_matches(existing, expected):
                        continue
                    action = "ADD COLUMN" if existing is None else "MODIFY COLUMN"
                    _execute_or_plan(
                        cursor,
                        f"ALTER TABLE {_quote(table)} {action} {_quote(name)} {definition}",
                        apply=apply,
                        actions=actions,
                    )

            for table, desired in DESIRED_INDEXES.items():
                existing = _indexes(cursor, table) if apply else _indexes(cursor, table)
                for name, (unique, columns, definition) in desired.items():
                    if existing.get(name) == (unique, columns):
                        continue
                    _execute_or_plan(
                        cursor,
                        f"ALTER TABLE {_quote(table)} ADD {definition}",
                        apply=apply,
                        actions=actions,
                    )
            if apply:
                # DDL 会隐式提交；这里做最终定义核验，异常时由部署前数据库备份回滚。
                for table, desired in DESIRED_INDEXES.items():
                    existing = _indexes(cursor, table)
                    for name, (unique, columns, _definition) in desired.items():
                        if existing.get(name) != (unique, columns):
                            raise IndexSchemaMigrationError(
                                f"索引迁移后定义不匹配：{table}.{name}"
                            )
                    for legacy_name in LEGACY_INDEXES.get(table, set()):
                        if legacy_name in existing:
                            raise IndexSchemaMigrationError(
                                f"旧唯一索引仍存在：{table}.{legacy_name}"
                            )
        if apply:
            connection.commit()
        else:
            connection.rollback()
        return {"migration": MIGRATION_ID, "apply": bool(apply), "actions": actions}
    finally:
        if locked:
            try:
                with connection.cursor() as cursor:
                    _release_lock(cursor)
                connection.commit()
            except Exception:
                pass
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="执行 DDL；默认只输出计划")
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )
    args = parser.parse_args()
    report = migrate_index_generation_schema(
        apply=args.apply,
        writers_stopped_confirmed=args.confirm_app_writers_stopped,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
