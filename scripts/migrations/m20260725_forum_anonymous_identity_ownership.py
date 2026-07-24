#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""为讨论区匿名身份引用补齐“用户 + 身份”复合属主约束。

该迁移只增加索引和外键，不删除、改名或回填业务数据。MySQL DDL 会隐式提交，
因此迁移按“父表唯一索引 -> 全部子表索引 -> 全部子表外键”的顺序幂等向前补齐；
若中途失败，修复原因后重新运行同一命令即可继续。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    load_config,
    settings_from_config,
)


MIGRATION_ID = "m20260725_forum_anonymous_identity_ownership"
MIGRATION_LOCK_NAME = "numericaloj:m20260725:forum_identity_owner"
MIGRATION_LOCK_TIMEOUT_SECONDS = 120
PARENT_TABLE = "forum_anonymous_identities"
PARENT_UNIQUE_NAME = "uq_forum_anonymous_identity_owner"


class MigrationError(RuntimeError):
    """迁移前置条件、元数据或数据审计不满足。"""


@dataclass(frozen=True)
class OwnershipReference:
    table: str
    identity_column: str
    index_name: str
    constraint_name: str


@dataclass(frozen=True)
class ColumnShape:
    data_type: str
    unsigned: bool
    nullable: bool


@dataclass(frozen=True)
class DDLStep:
    kind: str
    table: str
    object_name: str
    sql: str


@dataclass(frozen=True)
class MigrationReport:
    complete: bool
    invalid_reference_counts: dict[str, int]
    missing_objects: tuple[str, ...]
    applied_statements: tuple[str, ...]


OWNERSHIP_REFERENCES = (
    OwnershipReference(
        table="forum_threads",
        identity_column="anonymous_identity_id",
        index_name="idx_forum_threads_identity_owner",
        constraint_name="fk_forum_threads_identity_owner",
    ),
    OwnershipReference(
        table="forum_replies",
        identity_column="anonymous_identity_id",
        index_name="idx_forum_replies_identity_owner",
        constraint_name="fk_forum_replies_identity_owner",
    ),
    OwnershipReference(
        table="forum_user_identity_settings",
        identity_column="current_anonymous_identity_id",
        index_name="idx_forum_settings_identity_owner",
        constraint_name="fk_forum_settings_identity_owner",
    ),
    OwnershipReference(
        table="forum_identity_operation_receipts",
        identity_column="anonymous_identity_id",
        index_name="idx_forum_identity_operation_owner",
        constraint_name="fk_forum_identity_operation_owner",
    ),
)

EXPECTED_COLUMNS = {
    (PARENT_TABLE, "user_id"): ColumnShape("int", False, False),
    (PARENT_TABLE, "id"): ColumnShape("bigint", False, False),
    ("forum_threads", "user_id"): ColumnShape("int", False, False),
    ("forum_threads", "anonymous_identity_id"): ColumnShape(
        "bigint", False, True
    ),
    ("forum_replies", "user_id"): ColumnShape("int", False, False),
    ("forum_replies", "anonymous_identity_id"): ColumnShape(
        "bigint", False, True
    ),
    ("forum_user_identity_settings", "user_id"): ColumnShape(
        "int", False, False
    ),
    (
        "forum_user_identity_settings",
        "current_anonymous_identity_id",
    ): ColumnShape("bigint", False, True),
    ("forum_identity_operation_receipts", "user_id"): ColumnShape(
        "int", False, False
    ),
    (
        "forum_identity_operation_receipts",
        "anonymous_identity_id",
    ): ColumnShape("bigint", False, False),
}

REQUIRED_TABLES = (
    PARENT_TABLE,
    *(reference.table for reference in OWNERSHIP_REFERENCES),
)

PARENT_INDEX_STEP = DDLStep(
    kind="index",
    table=PARENT_TABLE,
    object_name=PARENT_UNIQUE_NAME,
    sql=(
        "ALTER TABLE `forum_anonymous_identities` "
        "ADD UNIQUE KEY `uq_forum_anonymous_identity_owner` (`user_id`,`id`)"
    ),
)

CHILD_INDEX_STEPS = tuple(
    DDLStep(
        kind="index",
        table=reference.table,
        object_name=reference.index_name,
        sql=(
            f"ALTER TABLE `{reference.table}` "
            f"ADD KEY `{reference.index_name}` "
            f"(`user_id`,`{reference.identity_column}`)"
        ),
    )
    for reference in OWNERSHIP_REFERENCES
)

CHILD_FOREIGN_KEY_STEPS = tuple(
    DDLStep(
        kind="foreign_key",
        table=reference.table,
        object_name=reference.constraint_name,
        sql=(
            f"ALTER TABLE `{reference.table}` "
            f"ADD CONSTRAINT `{reference.constraint_name}` "
            f"FOREIGN KEY (`user_id`,`{reference.identity_column}`) "
            "REFERENCES `forum_anonymous_identities` (`user_id`,`id`) "
            "ON DELETE RESTRICT ON UPDATE RESTRICT"
        ),
    )
    for reference in OWNERSHIP_REFERENCES
)

DDL_STEPS = (
    PARENT_INDEX_STEP,
    *CHILD_INDEX_STEPS,
    *CHILD_FOREIGN_KEY_STEPS,
)


def _placeholders(values: Iterable[object]) -> str:
    values = tuple(values)
    return ",".join("%s" for _value in values)


def _acquire_migration_lock(cursor) -> None:
    cursor.execute(
        "SELECT GET_LOCK(%s, %s) AS locked",
        (MIGRATION_LOCK_NAME, MIGRATION_LOCK_TIMEOUT_SECONDS),
    )
    row = cursor.fetchone() or {}
    if int(row.get("locked") or 0) != 1:
        raise MigrationError(
            f"无法取得迁移 advisory lock：{MIGRATION_LOCK_NAME}"
        )


def _release_migration_lock(cursor) -> None:
    cursor.execute(
        "SELECT RELEASE_LOCK(%s) AS released",
        (MIGRATION_LOCK_NAME,),
    )
    row = cursor.fetchone() or {}
    if int(row.get("released") or 0) != 1:
        raise MigrationError(
            f"无法释放迁移 advisory lock：{MIGRATION_LOCK_NAME}"
        )


def _assert_foreign_key_checks_enabled(cursor) -> None:
    cursor.execute(
        "SELECT @@SESSION.FOREIGN_KEY_CHECKS AS foreign_key_checks"
    )
    row = cursor.fetchone() or {}
    if int(row.get("foreign_key_checks") or 0) != 1:
        raise MigrationError(
            "拒绝迁移：当前会话 FOREIGN_KEY_CHECKS 不是 1；"
            "本迁移禁止关闭外键检查。"
        )


def _assert_source_schema(cursor, database: str) -> None:
    cursor.execute(
        "SELECT TABLE_NAME AS table_name, ENGINE AS engine "
        "FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN ({_placeholders(REQUIRED_TABLES)})",
        (database, *REQUIRED_TABLES),
    )
    table_rows = cursor.fetchall() or []
    engines = {
        str(row.get("table_name")): str(row.get("engine") or "").lower()
        for row in table_rows
    }
    missing_tables = sorted(set(REQUIRED_TABLES) - set(engines))
    if missing_tables:
        raise MigrationError(
            "缺少迁移前置表：" + "、".join(missing_tables)
        )
    wrong_engines = sorted(
        table for table, engine in engines.items() if engine != "innodb"
    )
    if wrong_engines:
        raise MigrationError(
            "以下表不是 InnoDB，拒绝添加外键："
            + "、".join(wrong_engines)
        )

    cursor.execute(
        "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, "
        "DATA_TYPE AS data_type, COLUMN_TYPE AS column_type, "
        "IS_NULLABLE AS is_nullable "
        "FROM INFORMATION_SCHEMA.COLUMNS "
        f"WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN ({_placeholders(REQUIRED_TABLES)})",
        (database, *REQUIRED_TABLES),
    )
    column_rows = cursor.fetchall() or []
    columns = {
        (str(row.get("table_name")), str(row.get("column_name"))): row
        for row in column_rows
    }
    for key, expected in EXPECTED_COLUMNS.items():
        row = columns.get(key)
        if row is None:
            raise MigrationError(
                f"缺少迁移前置列：{key[0]}.{key[1]}"
            )
        column_type = str(row.get("column_type") or "").lower()
        actual = ColumnShape(
            data_type=str(row.get("data_type") or "").lower(),
            unsigned="unsigned" in column_type.split(),
            nullable=str(row.get("is_nullable") or "").upper() == "YES",
        )
        if actual != expected:
            expected_sign = " unsigned" if expected.unsigned else " signed"
            expected_null = " NULL" if expected.nullable else " NOT NULL"
            raise MigrationError(
                f"列定义不匹配：{key[0]}.{key[1]}，"
                f"期望 {expected.data_type}{expected_sign}{expected_null}，"
                f"实际 {column_type or actual.data_type} "
                f"{row.get('is_nullable') or 'UNKNOWN'}"
            )


def _anti_join_sql() -> str:
    selects = []
    for reference in OWNERSHIP_REFERENCES:
        selects.append(
            f"SELECT '{reference.table}' AS source_table, "
            "COUNT(*) AS invalid_rows "
            f"FROM `{reference.table}` AS child "
            "LEFT JOIN `forum_anonymous_identities` AS identity_row "
            "ON identity_row.`user_id`=child.`user_id` "
            f"AND identity_row.`id`=child.`{reference.identity_column}` "
            f"WHERE child.`{reference.identity_column}` IS NOT NULL "
            "AND identity_row.`id` IS NULL"
        )
    return " UNION ALL ".join(selects)


def _audit_identity_ownership(cursor) -> dict[str, int]:
    cursor.execute(_anti_join_sql())
    rows = cursor.fetchall() or []
    expected_tables = {
        reference.table for reference in OWNERSHIP_REFERENCES
    }
    counts: dict[str, int] = {}
    for row in rows:
        table = str(row.get("source_table") or "")
        if table in counts or table not in expected_tables:
            raise MigrationError(
                "匿名身份属主 anti-join 返回了异常表标识，拒绝继续。"
            )
        try:
            count = int(row.get("invalid_rows"))
        except (TypeError, ValueError) as exc:
            raise MigrationError(
                f"无法解析 {table or 'unknown'} 的 anti-join 计数。"
            ) from exc
        if count < 0:
            raise MigrationError(
                f"{table} 的 anti-join 计数为负数，拒绝继续。"
            )
        counts[table] = count

    if set(counts) != expected_tables:
        missing = sorted(expected_tables - set(counts))
        raise MigrationError(
            "匿名身份属主 anti-join 结果不完整："
            + "、".join(missing or ["unexpected result"])
        )

    invalid = {table: count for table, count in counts.items() if count}
    if invalid:
        details = "，".join(
            f"{table}={count}" for table, count in sorted(invalid.items())
        )
        raise MigrationError(
            "发现悬空或跨属主匿名身份引用，拒绝自动修复或添加外键："
            + details
        )
    return counts


def _index_present_and_exact(
    cursor,
    database: str,
    *,
    table: str,
    index_name: str,
    columns: tuple[str, ...],
    unique: bool,
) -> bool:
    cursor.execute(
        "SELECT SEQ_IN_INDEX AS seq_in_index, COLUMN_NAME AS column_name, "
        "NON_UNIQUE AS non_unique, SUB_PART AS sub_part, "
        "INDEX_TYPE AS index_type "
        "FROM INFORMATION_SCHEMA.STATISTICS "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s AND INDEX_NAME=%s "
        "ORDER BY SEQ_IN_INDEX",
        (database, table, index_name),
    )
    rows = cursor.fetchall() or []
    if not rows:
        return False
    actual = tuple(
        (
            int(row.get("seq_in_index") or 0),
            str(row.get("column_name") or ""),
            int(row.get("non_unique") or 0),
            row.get("sub_part"),
            str(row.get("index_type") or "").upper(),
        )
        for row in rows
    )
    expected_non_unique = 0 if unique else 1
    expected = tuple(
        (position, column, expected_non_unique, None, "BTREE")
        for position, column in enumerate(columns, start=1)
    )
    if actual != expected:
        raise MigrationError(
            f"同名索引定义不匹配：{table}.{index_name}，"
            f"期望列 {columns!r}、unique={unique}，实际 {actual!r}"
        )
    return True


def _foreign_key_present_and_exact(
    cursor,
    database: str,
    reference: OwnershipReference,
) -> bool:
    cursor.execute(
        "SELECT k.ORDINAL_POSITION AS ordinal_position, "
        "k.COLUMN_NAME AS column_name, "
        "k.REFERENCED_TABLE_SCHEMA AS referenced_table_schema, "
        "k.REFERENCED_TABLE_NAME AS referenced_table_name, "
        "k.REFERENCED_COLUMN_NAME AS referenced_column_name, "
        "k.POSITION_IN_UNIQUE_CONSTRAINT AS position_in_unique_constraint, "
        "r.UNIQUE_CONSTRAINT_NAME AS unique_constraint_name, "
        "r.MATCH_OPTION AS match_option, "
        "r.UPDATE_RULE AS update_rule, r.DELETE_RULE AS delete_rule "
        "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS k "
        "JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS AS r "
        "ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA "
        "AND r.TABLE_NAME=k.TABLE_NAME "
        "AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME "
        "WHERE k.CONSTRAINT_SCHEMA=%s AND k.TABLE_NAME=%s "
        "AND k.CONSTRAINT_NAME=%s "
        "ORDER BY k.ORDINAL_POSITION",
        (database, reference.table, reference.constraint_name),
    )
    rows = cursor.fetchall() or []
    if not rows:
        return False
    actual = tuple(
        (
            int(row.get("ordinal_position") or 0),
            str(row.get("column_name") or ""),
            str(row.get("referenced_table_schema") or ""),
            str(row.get("referenced_table_name") or ""),
            str(row.get("referenced_column_name") or ""),
            int(row.get("position_in_unique_constraint") or 0),
            str(row.get("unique_constraint_name") or ""),
            str(row.get("match_option") or "").upper(),
            str(row.get("update_rule") or "").upper(),
            str(row.get("delete_rule") or "").upper(),
        )
        for row in rows
    )
    expected = (
        (
            1,
            "user_id",
            database,
            PARENT_TABLE,
            "user_id",
            1,
            PARENT_UNIQUE_NAME,
            "NONE",
            "RESTRICT",
            "RESTRICT",
        ),
        (
            2,
            reference.identity_column,
            database,
            PARENT_TABLE,
            "id",
            2,
            PARENT_UNIQUE_NAME,
            "NONE",
            "RESTRICT",
            "RESTRICT",
        ),
    )
    if actual != expected:
        raise MigrationError(
            f"同名外键定义不匹配："
            f"{reference.table}.{reference.constraint_name}，实际 {actual!r}"
        )
    return True


def _inspect_expected_objects(
    cursor,
    database: str,
) -> dict[tuple[str, str], bool]:
    presence: dict[tuple[str, str], bool] = {}
    presence[("index", PARENT_UNIQUE_NAME)] = _index_present_and_exact(
        cursor,
        database,
        table=PARENT_TABLE,
        index_name=PARENT_UNIQUE_NAME,
        columns=("user_id", "id"),
        unique=True,
    )
    for reference in OWNERSHIP_REFERENCES:
        presence[("index", reference.index_name)] = (
            _index_present_and_exact(
                cursor,
                database,
                table=reference.table,
                index_name=reference.index_name,
                columns=("user_id", reference.identity_column),
                unique=False,
            )
        )
    for reference in OWNERSHIP_REFERENCES:
        presence[("foreign_key", reference.constraint_name)] = (
            _foreign_key_present_and_exact(cursor, database, reference)
        )
    return presence


def _missing_descriptions(
    presence: dict[tuple[str, str], bool],
) -> tuple[str, ...]:
    return tuple(
        f"{step.kind}:{step.table}.{step.object_name}"
        for step in DDL_STEPS
        if not presence[(step.kind, step.object_name)]
    )


def _verify_step(cursor, database: str, step: DDLStep) -> None:
    if step.kind == "index":
        if step.object_name == PARENT_UNIQUE_NAME:
            present = _index_present_and_exact(
                cursor,
                database,
                table=PARENT_TABLE,
                index_name=PARENT_UNIQUE_NAME,
                columns=("user_id", "id"),
                unique=True,
            )
        else:
            reference = next(
                item
                for item in OWNERSHIP_REFERENCES
                if item.index_name == step.object_name
            )
            present = _index_present_and_exact(
                cursor,
                database,
                table=reference.table,
                index_name=reference.index_name,
                columns=("user_id", reference.identity_column),
                unique=False,
            )
    else:
        reference = next(
            item
            for item in OWNERSHIP_REFERENCES
            if item.constraint_name == step.object_name
        )
        present = _foreign_key_present_and_exact(
            cursor, database, reference
        )
    if not present:
        raise MigrationError(
            f"DDL 执行后未发现预期对象：{step.table}.{step.object_name}"
        )


def migrate(
    cursor,
    *,
    database: str,
    apply: bool,
) -> MigrationReport:
    """在已持有迁移锁的连接中审计或执行迁移。"""

    _assert_foreign_key_checks_enabled(cursor)
    _assert_source_schema(cursor, database)
    counts = _audit_identity_ownership(cursor)
    presence = _inspect_expected_objects(cursor, database)
    missing_before = _missing_descriptions(presence)

    if not apply:
        return MigrationReport(
            complete=not missing_before,
            invalid_reference_counts=counts,
            missing_objects=missing_before,
            applied_statements=(),
        )

    applied: list[str] = []
    for step in DDL_STEPS:
        if presence[(step.kind, step.object_name)]:
            continue
        _assert_foreign_key_checks_enabled(cursor)
        cursor.execute(step.sql)
        _verify_step(cursor, database, step)
        presence[(step.kind, step.object_name)] = True
        applied.append(step.sql)

    _assert_foreign_key_checks_enabled(cursor)
    _assert_source_schema(cursor, database)
    counts = _audit_identity_ownership(cursor)
    final_presence = _inspect_expected_objects(cursor, database)
    missing_after = _missing_descriptions(final_presence)
    if missing_after:
        raise MigrationError(
            "迁移完成审计仍缺少对象：" + "、".join(missing_after)
        )
    return MigrationReport(
        complete=True,
        invalid_reference_counts=counts,
        missing_objects=(),
        applied_statements=tuple(applied),
    )


def execute_migration(
    *,
    apply: bool,
    app_writers_stopped_confirmed: bool = False,
) -> MigrationReport:
    if apply and not app_writers_stopped_confirmed:
        raise MigrationError(
            "拒绝执行 DDL：未确认全部应用写入者已经停止。"
        )
    config = load_config()
    settings = settings_from_config(config)
    connection = connect_mysql(
        settings,
        with_database=True,
        dict_rows=True,
    )
    locked = False
    primary_error: BaseException | None = None
    try:
        with connection.cursor() as cursor:
            _acquire_migration_lock(cursor)
            locked = True
            try:
                report = migrate(
                    cursor,
                    database=settings.database,
                    apply=apply,
                )
                if apply:
                    connection.commit()
                else:
                    connection.rollback()
                return report
            except BaseException as exc:
                primary_error = exc
                connection.rollback()
                raise
            finally:
                if locked:
                    try:
                        _release_migration_lock(cursor)
                    except BaseException:
                        if primary_error is None:
                            raise
    finally:
        connection.close()


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="只审计数据、元数据和迁移完成状态，不执行 DDL",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="幂等补齐缺失索引和外键",
    )
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web、Celery 及其他 NumericalOJ 数据库写入者均已停止",
    )
    args = parser.parse_args(argv)
    if args.apply and not args.confirm_app_writers_stopped:
        parser.error(
            "--apply 必须同时传入 --confirm-app-writers-stopped"
        )
    if args.check and args.confirm_app_writers_stopped:
        parser.error(
            "--check 不接受 --confirm-app-writers-stopped"
        )
    return args


def main(argv=None) -> int:
    args = _parse_args(argv)
    try:
        report = execute_migration(
            apply=args.apply,
            app_writers_stopped_confirmed=(
                args.confirm_app_writers_stopped
            ),
        )
    except Exception as exc:
        print(f"[{MIGRATION_ID}] failed: {exc}", file=sys.stderr)
        return 1

    counts = "，".join(
        f"{table}={count}"
        for table, count in sorted(
            report.invalid_reference_counts.items()
        )
    )
    if args.check:
        if not report.complete:
            print(
                f"[{MIGRATION_ID}] incomplete: "
                + "，".join(report.missing_objects),
                file=sys.stderr,
            )
            return 1
        print(f"[{MIGRATION_ID}] check passed; anti-join: {counts}")
        return 0

    for statement in report.applied_statements:
        print(f"[{MIGRATION_ID}] applied: {statement};")
    print(
        f"[{MIGRATION_ID}] complete; "
        f"{len(report.applied_statements)} DDL statements applied; "
        f"anti-join: {counts}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
