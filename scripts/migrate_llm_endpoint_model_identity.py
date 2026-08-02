#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Make ``llm_endpoints.model`` the sole endpoint identity.

The command is a read-only forward check by default. Applying either the
forward migration or its operational rollback requires explicit confirmation
that every application writer is stopped and a verified database backup is
available. MySQL DDL auto-commits, so every step is independently detectable
and the plan can be rerun after an interruption.
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
LEGACY_NAME_INDEX_NAME = "uq_llm_endpoint_name"
LEGACY_NAME_MAX_LENGTH = 120


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
) -> None:
    definition = indexes.get(name)
    if definition is None:
        return
    if (
        not definition.unique
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
            "存在重复 model，需先人工合并或改名："
            + _sample_text(
                duplicates,
                ("model", "endpoint_count", "endpoint_ids"),
            )
        )


def _audit_legacy_names(cursor) -> None:
    cursor.execute(
        """
        SELECT id, name
        FROM llm_endpoints
        WHERE name IS NULL OR TRIM(name) = ''
        ORDER BY id ASC
        LIMIT 5
        """
    )
    empty_names = cursor.fetchall() or []
    if empty_names:
        raise MigrationBlockedError(
            "现有 name 含空值，无法恢复旧结构："
            + _sample_text(empty_names, ("id", "name"))
        )

    cursor.execute(
        """
        SELECT name, COUNT(*) AS endpoint_count,
               GROUP_CONCAT(id ORDER BY id SEPARATOR ',') AS endpoint_ids
        FROM llm_endpoints
        GROUP BY name
        HAVING COUNT(*) > 1
        ORDER BY name ASC
        LIMIT 5
        """
    )
    duplicates = cursor.fetchall() or []
    if duplicates:
        raise MigrationBlockedError(
            "现有 name 含重复值，无法恢复唯一约束："
            + _sample_text(
                duplicates,
                ("name", "endpoint_count", "endpoint_ids"),
            )
        )


def _audit_model_lengths_for_rollback(cursor) -> None:
    cursor.execute(
        """
        SELECT id, model, CHAR_LENGTH(model) AS model_length
        FROM llm_endpoints
        WHERE CHAR_LENGTH(model) > %s
        ORDER BY id ASC
        LIMIT 5
        """,
        (LEGACY_NAME_MAX_LENGTH,),
    )
    oversized = cursor.fetchall() or []
    if oversized:
        raise MigrationBlockedError(
            f"model 超过旧 name 的 {LEGACY_NAME_MAX_LENGTH} 字符上限，"
            "无法无损恢复旧结构："
            + _sample_text(oversized, ("id", "model_length", "model"))
        )


def _nullable_name_can_resume_from_model(cursor) -> bool:
    """Return whether a nullable name column is our interrupted rollback."""
    cursor.execute(
        """
        SELECT id, name, model
        FROM llm_endpoints
        WHERE name IS NOT NULL AND name <> model
        ORDER BY id ASC
        LIMIT 5
        """
    )
    conflicts = cursor.fetchall() or []
    if conflicts:
        raise MigrationBlockedError(
            "nullable name 含有与 model 不同的既有值，拒绝猜测恢复："
            + _sample_text(conflicts, ("id", "name", "model"))
        )
    cursor.execute(
        "SELECT id FROM llm_endpoints WHERE name IS NULL LIMIT 1"
    )
    return cursor.fetchone() is not None


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


def build_forward_plan(cursor) -> list[MigrationOperation]:
    """Return an idempotent model-identity migration plan."""
    if not _table_exists(cursor):
        return []

    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    _require_exact_index(indexes, LEGACY_NAME_INDEX_NAME, ("name",))
    _audit_models(cursor)

    operations: list[MigrationOperation] = []
    if str(model_column.get("Null") or "").upper() != "NO":
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "MODIFY COLUMN model varchar(255) NOT NULL",
        ))
    if MODEL_INDEX_NAME not in indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "ADD UNIQUE KEY uq_llm_endpoint_model (model)",
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


def build_rollback_plan(cursor) -> list[MigrationOperation]:
    """Return an operational rollback plan for the former name schema."""
    if not _table_exists(cursor):
        return []

    columns = _columns(cursor)
    _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    _require_exact_index(indexes, LEGACY_NAME_INDEX_NAME, ("name",))
    _audit_models(cursor)

    operations: list[MigrationOperation] = []
    name_column = columns.get("name")
    if name_column is None:
        _audit_model_lengths_for_rollback(cursor)
        operations.extend([
            MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "ADD COLUMN name varchar(120) NULL AFTER id",
            ),
            MigrationOperation(
                "UPDATE llm_endpoints SET name = model",
                kind="dml",
            ),
            MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "MODIFY COLUMN name varchar(120) NOT NULL",
            ),
        ])
    else:
        if _normalized_column_type(name_column.get("Type")) != "varchar(120)":
            raise MigrationBlockedError(
                "llm_endpoints.name 不是预期的 varchar(120)，拒绝自动改型"
            )
        if str(name_column.get("Null") or "").upper() != "NO":
            has_null_names = _nullable_name_can_resume_from_model(cursor)
            if has_null_names:
                _audit_model_lengths_for_rollback(cursor)
                operations.append(MigrationOperation(
                    "UPDATE llm_endpoints "
                    "SET name = model WHERE name IS NULL",
                    kind="dml",
                ))
            else:
                _audit_legacy_names(cursor)
            operations.append(MigrationOperation(
                "ALTER TABLE llm_endpoints "
                "MODIFY COLUMN name varchar(120) NOT NULL",
            ))
        else:
            _audit_legacy_names(cursor)

    if LEGACY_NAME_INDEX_NAME not in indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "ADD UNIQUE KEY uq_llm_endpoint_name (name)",
        ))
    if MODEL_INDEX_NAME in indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE llm_endpoints "
            "DROP INDEX uq_llm_endpoint_model",
        ))
    return operations


def _verify_forward(cursor) -> None:
    if not _table_exists(cursor):
        return
    columns = _columns(cursor)
    model_column = _require_model_column(columns)
    indexes = _indexes(cursor)
    _require_exact_index(indexes, MODEL_INDEX_NAME, ("model",))
    if "name" in columns or LEGACY_NAME_INDEX_NAME in indexes:
        raise MigrationBlockedError("迁移后仍存在独立端点 name 结构")
    if MODEL_INDEX_NAME not in indexes:
        raise MigrationBlockedError("迁移后缺少 model 唯一索引")
    if str(model_column.get("Null") or "").upper() != "NO":
        raise MigrationBlockedError("迁移后 model 仍允许 NULL")
    _audit_models(cursor)


def _verify_rollback(cursor) -> None:
    if not _table_exists(cursor):
        return
    columns = _columns(cursor)
    indexes = _indexes(cursor)
    name_column = columns.get("name")
    if name_column is None:
        raise MigrationBlockedError("回滚后仍缺少 name 字段")
    if str(name_column.get("Null") or "").upper() != "NO":
        raise MigrationBlockedError("回滚后 name 仍允许 NULL")
    _require_exact_index(indexes, LEGACY_NAME_INDEX_NAME, ("name",))
    if LEGACY_NAME_INDEX_NAME not in indexes:
        raise MigrationBlockedError("回滚后缺少 name 唯一索引")
    if MODEL_INDEX_NAME in indexes:
        raise MigrationBlockedError("回滚后仍存在 model 唯一索引")
    _audit_legacy_names(cursor)


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
        help="恢复旧 name 字段及唯一约束；默认规划前向迁移",
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
        print(f"[llm-endpoint-model-identity] blocked: {exc}", file=sys.stderr)
        return 1
    finally:
        if connection is not None:
            connection.close()

    direction = "rollback" if args.rollback else "forward"
    mode = "apply" if args.apply else "dry-run"
    print(
        f"[llm-endpoint-model-identity] {direction} {mode}: "
        f"{len(operations)} operations"
    )
    for operation in operations:
        print(operation.display())
    if not args.apply:
        print("[llm-endpoint-model-identity] no changes were applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
