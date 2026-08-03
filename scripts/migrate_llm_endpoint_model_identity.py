#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Make ``llm_endpoints.id`` the sole endpoint identity.

The command is a read-only forward check by default. Applying either the
forward migration or its operational rollback requires explicit confirmation
that every application writer is stopped and a verified database backup is
available. The forward migration removes the former uniqueness constraint from
``model`` so the same provider model can be configured through multiple
endpoints. MySQL DDL auto-commits, so every step is independently detectable and
the plan can be rerun after an interruption.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    database_exists,
    load_config,
    settings_from_config,
)


MIGRATION_LOCK_NAME = "numericaloj:migrate:llm-endpoint-model-identity:v1"
MIGRATION_LOCK_TIMEOUT_SECONDS = 120
TABLE_NAME = "llm_endpoints"
MODEL_INDEX_NAME = "uq_llm_endpoint_model"
MODEL_LOOKUP_INDEX_NAME = "idx_llm_endpoint_model"
LEGACY_NAME_INDEX_NAME = "uq_llm_endpoint_name"


class MigrationBlockedError(RuntimeError):
    """The schema or data requires manual repair before migration."""


@dataclass(frozen=True)
class MigrationOperation:
    sql: str
    params: tuple = ()
    kind: str = "ddl"

    def display(self) -> str:
        suffix = f"  params={self.params!r}" if self.params else ""
        return self.sql.rstrip(";") + ";" + suffix


@dataclass(frozen=True)
class IndexDefinition:
    unique: bool
    columns: tuple[str, ...]
    sub_parts: tuple[int | None, ...]


def _table_exists(cursor) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (TABLE_NAME,))
    return cursor.fetchone() is not None


def _columns(cursor) -> dict[str, dict]:
    cursor.execute(f"SHOW COLUMNS FROM `{TABLE_NAME}`")
    return {
        str(row["Field"]): row
        for row in (cursor.fetchall() or [])
    }


def _indexes(cursor) -> dict[str, IndexDefinition]:
    cursor.execute(f"SHOW INDEX FROM `{TABLE_NAME}`")
    grouped: dict[str, list[dict]] = {}
    for row in cursor.fetchall() or []:
        grouped.setdefault(str(row["Key_name"]), []).append(row)

    definitions = {}
    for name, rows in grouped.items():
        ordered = sorted(rows, key=lambda row: int(row["Seq_in_index"]))
        definitions[name] = IndexDefinition(
            unique=all(int(row["Non_unique"]) == 0 for row in ordered),
            columns=tuple(str(row["Column_name"]) for row in ordered),
            sub_parts=tuple(
                int(row["Sub_part"])
                if row.get("Sub_part") is not None
                else None
                for row in ordered
            ),
        )
    return definitions


def _normalized_column_type(value) -> str:
    return re.sub(r"\s+", "", str(value or "").lower())


def _require_model_column(columns: dict[str, dict]) -> dict:
    model = columns.get("model")
    if model is None:
        raise MigrationBlockedError(
            f"{TABLE_NAME} 缺少迁移所需字段 model"
        )
    if _normalized_column_type(model.get("Type")) != "varchar(255)":
        raise MigrationBlockedError(
            "llm_endpoints.model 不是预期的 varchar(255)，拒绝自动改型"
        )
    return model


def _require_exact_index(
    indexes: dict[str, IndexDefinition],
    name: str,
    columns: tuple[str, ...],
    *,
    unique: bool = True,
) -> None:
    definition = indexes.get(name)
    if definition is None:
        return
    if (
        definition.unique != unique
        or definition.columns != columns
        or any(part is not None for part in definition.sub_parts)
    ):
        raise MigrationBlockedError(
            f"索引 {name} 的定义与预期不一致，拒绝自动覆盖"
        )


def _sample_text(rows, fields: tuple[str, ...]) -> str:
    samples = [
        "/".join(str(row.get(field, "")) for field in fields)
        for row in rows[:5]
    ]
    return "、".join(samples)


def _audit_models(cursor) -> None:
    cursor.execute(
        """
        SELECT id, model
        FROM llm_endpoints
        WHERE model IS NULL OR TRIM(model) = ''
        ORDER BY id ASC
        LIMIT 5
        """
    )
    empty_models = cursor.fetchall() or []
    if empty_models:
        raise MigrationBlockedError(
            "存在空 model，需先人工修复端点："
            + _sample_text(empty_models, ("id", "model"))
        )


def _audit_unique_models_for_rollback(cursor) -> None:
    cursor.execute(
        """
        SELECT model, COUNT(*) AS endpoint_count,
               GROUP_CONCAT(id ORDER BY id SEPARATOR ',') AS endpoint_ids
        FROM llm_endpoints
        GROUP BY model
        HAVING COUNT(*) > 1
        ORDER BY model ASC
        LIMIT 5
        """
    )
    duplicates = cursor.fetchall() or []
    if duplicates:
        raise MigrationBlockedError(
            "存在重复 model，无法恢复旧的唯一约束；"
            "请恢复迁移前备份或先人工处理："
            + _sample_text(
                duplicates,
                ("model", "endpoint_count", "endpoint_ids"),
            )
        )


def _fail_on_unexpected_name_indexes(
    indexes: dict[str, IndexDefinition],
) -> None:
    unexpected = sorted(
        name
        for name, definition in indexes.items()
        if "name" in definition.columns
        and name != LEGACY_NAME_INDEX_NAME
    )
    if unexpected:
        raise MigrationBlockedError(
            "name 字段仍被非标准索引引用，拒绝隐式删除："
            + "、".join(unexpected)
        )


def _fail_on_unexpected_model_unique_indexes(
    indexes: dict[str, IndexDefinition],
) -> None:
    unexpected = sorted(
        name
        for name, definition in indexes.items()
        if definition.unique
        and definition.columns == ("model",)
        and name != MODEL_INDEX_NAME
    )
    if unexpected:
        raise MigrationBlockedError(
            "model 字段仍被非标准唯一索引约束，拒绝隐式删除："
            + "、".join(unexpected)
        )


def build_forward_plan(cursor) -> list[MigrationOperation]:
    """Return an idempotent plan that makes endpoint IDs the identity."""
    if not _table_exists(cursor):
        return []

    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    _require_exact_index(
        indexes,
        MODEL_LOOKUP_INDEX_NAME,
        ("model",),
        unique=False,
    )
    _require_exact_index(indexes, LEGACY_NAME_INDEX_NAME, ("name",))
    _fail_on_unexpected_model_unique_indexes(indexes)
    _audit_models(cursor)

    operations: list[MigrationOperation] = []
    if str(model_column.get("Null") or "").upper() != "NO":
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN model varchar(255) NOT NULL",
        ))

    if "name" in columns:
        _fail_on_unexpected_name_indexes(indexes)
        if LEGACY_NAME_INDEX_NAME in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "DROP INDEX uq_llm_endpoint_name",
            ))
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints DROP COLUMN name",
        ))
    elif LEGACY_NAME_INDEX_NAME in indexes:
        raise MigrationBlockedError(
            "索引 uq_llm_endpoint_name 存在，但 name 字段不存在"
        )

    if MODEL_INDEX_NAME in indexes and MODEL_LOOKUP_INDEX_NAME not in indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "DROP INDEX uq_llm_endpoint_model, "
            "ADD KEY idx_llm_endpoint_model (model)",
        ))
    else:
        if MODEL_INDEX_NAME in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "DROP INDEX uq_llm_endpoint_model",
            ))
        if MODEL_LOOKUP_INDEX_NAME not in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "ADD KEY idx_llm_endpoint_model (model)",
            ))
    return operations


def build_rollback_plan(cursor) -> list[MigrationOperation]:
    """Restore the previous release's unique-model schema, if lossless."""
    if not _table_exists(cursor):
        return []

    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    _require_exact_index(
        indexes,
        MODEL_LOOKUP_INDEX_NAME,
        ("model",),
        unique=False,
    )
    _require_exact_index(indexes, LEGACY_NAME_INDEX_NAME, ("name",))
    _fail_on_unexpected_model_unique_indexes(indexes)
    _audit_models(cursor)
    _audit_unique_models_for_rollback(cursor)

    operations: list[MigrationOperation] = []
    if str(model_column.get("Null") or "").upper() != "NO":
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN model varchar(255) NOT NULL",
        ))

    if MODEL_INDEX_NAME not in indexes and MODEL_LOOKUP_INDEX_NAME in indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "DROP INDEX idx_llm_endpoint_model, "
            "ADD UNIQUE KEY uq_llm_endpoint_model (model)",
        ))
    else:
        if MODEL_INDEX_NAME not in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "ADD UNIQUE KEY uq_llm_endpoint_model (model)",
            ))
        if MODEL_LOOKUP_INDEX_NAME in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "DROP INDEX idx_llm_endpoint_model",
            ))

    if "name" in columns:
        _fail_on_unexpected_name_indexes(indexes)
        if LEGACY_NAME_INDEX_NAME in indexes:
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "DROP INDEX uq_llm_endpoint_name",
            ))
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints DROP COLUMN name",
        ))
    elif LEGACY_NAME_INDEX_NAME in indexes:
        raise MigrationBlockedError(
            "索引 uq_llm_endpoint_name 存在，但 name 字段不存在"
        )
    return operations


def _verify_forward(cursor) -> None:
    if not _table_exists(cursor):
        return
    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(
        indexes,
        MODEL_LOOKUP_INDEX_NAME,
        ("model",),
        unique=False,
    )
    _fail_on_unexpected_model_unique_indexes(indexes)
    if "name" in columns or LEGACY_NAME_INDEX_NAME in indexes:
        raise MigrationBlockedError("迁移后仍存在独立端点 name 结构")
    if MODEL_INDEX_NAME in indexes:
        raise MigrationBlockedError("迁移后仍存在 model 唯一约束")
    if MODEL_LOOKUP_INDEX_NAME not in indexes:
        raise MigrationBlockedError("迁移后缺少 model 普通索引")
    if str(model_column.get("Null") or "").upper() != "NO":
        raise MigrationBlockedError("迁移后 model 仍允许 NULL")
    _audit_models(cursor)


def _verify_rollback(cursor) -> None:
    if not _table_exists(cursor):
        return
    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    _fail_on_unexpected_model_unique_indexes(indexes)
    if "name" in columns or LEGACY_NAME_INDEX_NAME in indexes:
        raise MigrationBlockedError("回滚后仍存在独立端点 name 结构")
    if MODEL_INDEX_NAME not in indexes:
        raise MigrationBlockedError("回滚后缺少 model 唯一索引")
    if MODEL_LOOKUP_INDEX_NAME in indexes:
        raise MigrationBlockedError("回滚后仍存在冗余 model 普通索引")
    if str(model_column.get("Null") or "").upper() != "NO":
        raise MigrationBlockedError("回滚后 model 仍允许 NULL")
    _audit_models(cursor)
    _audit_unique_models_for_rollback(cursor)


def migrate(
    connection,
    *,
    apply: bool = False,
    rollback: bool = False,
) -> list[MigrationOperation]:
    """Plan or apply the forward migration or operational rollback."""
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT GET_LOCK(%s, %s) AS locked",
                (MIGRATION_LOCK_NAME, MIGRATION_LOCK_TIMEOUT_SECONDS),
            )
            lock_row = cursor.fetchone() or {}
            if int(lock_row.get("locked") or 0) != 1:
                raise MigrationBlockedError("无法取得 LLM 端点结构迁移锁")
            locked = True

            plan_builder = (
                build_rollback_plan if rollback else build_forward_plan
            )
            operations = plan_builder(cursor)
            if not apply:
                connection.rollback()
                return operations

            for operation in operations:
                cursor.execute(operation.sql, operation.params)
            connection.commit()
            if rollback:
                _verify_rollback(cursor)
            else:
                _verify_forward(cursor)
            connection.commit()
            return operations
    except Exception:
        connection.rollback()
        raise
    finally:
        if locked:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT RELEASE_LOCK(%s)",
                        (MIGRATION_LOCK_NAME,),
                    )
                connection.commit()
            except Exception:
                connection.rollback()


def _connect():
    settings = settings_from_config(load_config())
    server_connection = connect_mysql(
        settings,
        with_database=False,
        dict_rows=True,
    )
    try:
        with server_connection.cursor() as cursor:
            exists = database_exists(cursor, settings.database)
    finally:
        server_connection.close()
    if not exists:
        return None
    return connect_mysql(
        settings,
        with_database=True,
        dict_rows=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="执行结构变更；省略时只做检查并打印计划",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="恢复上一版的 model 唯一约束；默认规划前向迁移",
    )
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web 和全部 Celery 写入者已经停止",
    )
    parser.add_argument(
        "--confirm-backup-verified",
        action="store_true",
        help="确认迁移前数据库备份已经验证",
    )
    args = parser.parse_args()

    if args.apply and not (
        args.confirm_app_writers_stopped
        and args.confirm_backup_verified
    ):
        parser.error(
            "--apply requires --confirm-app-writers-stopped "
            "and --confirm-backup-verified"
        )

    connection = None
    try:
        connection = _connect()
        operations = (
            migrate(
                connection,
                apply=args.apply,
                rollback=args.rollback,
            )
            if connection is not None
            else []
        )
    except Exception as exc:
        print(f"[llm-endpoint-id-identity] blocked: {exc}", file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()

    direction = "rollback" if args.rollback else "forward"
    mode = "apply" if args.apply else "dry-run"
    print(
        f"[llm-endpoint-id-identity] {direction} {mode}: "
        f"{len(operations)} operations"
    )
    for operation in operations:
        print(operation.display())
    if not args.apply:
        print("[llm-endpoint-id-identity] no changes were applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
