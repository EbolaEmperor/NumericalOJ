#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remove the legacy primary-class data model.

The command is dry-run by default. Applying it is an explicit, destructive
expand-contract step and requires confirmation that application writers are
stopped and a verified database backup exists.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import connect_mysql, load_config, settings_from_config


MIGRATION_LOCK_NAME = "numericaloj:migrate:remove-primary-class:v1"
MIGRATION_LOCK_TIMEOUT_SECONDS = 120
LEGACY_ADMIN_CLASS = "Cadmin"
KNOWN_ORPHAN_MEMBERSHIP_ID = 634
KNOWN_ORPHAN_USER_ID = 369
KNOWN_ORPHAN_CLASS = "CNumAnl_25_26_AutWin"
KNOWN_ORPHAN_IS_PRIMARY = 0
KNOWN_ORPHAN_VALID_MEMBERSHIP_COUNT = 2


class MigrationBlockedError(RuntimeError):
    """The legacy data cannot be contracted without manual repair."""


@dataclass(frozen=True)
class MigrationOperation:
    sql: str
    params: tuple = ()
    kind: str = "dml"
    expected_rowcount: int | None = None

    def display(self) -> str:
        suffix = f"  params={self.params!r}" if self.params else ""
        return self.sql.rstrip(";") + ";" + suffix


def _column_names(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW COLUMNS FROM `{table}`")
    return {str(row["Field"]) for row in (cursor.fetchall() or [])}


def _index_names(cursor, table: str) -> set[str]:
    cursor.execute(f"SHOW INDEX FROM `{table}`")
    return {str(row["Key_name"]) for row in (cursor.fetchall() or [])}


def _table_exists(cursor, table: str) -> bool:
    cursor.execute("SHOW TABLES LIKE %s", (table,))
    return cursor.fetchone() is not None


def _table_exists_exact(cursor, table: str) -> bool:
    cursor.execute(
        """
        SELECT TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s
        """,
        (table,),
    )
    return cursor.fetchone() is not None


def _rows(cursor, sql: str, params=()):
    cursor.execute(sql, params)
    return cursor.fetchall() or []


def _require_columns(actual: set[str], required: set[str], table: str) -> None:
    missing = sorted(required - actual)
    if missing:
        raise MigrationBlockedError(
            f"{table} 缺少迁移所需字段: {', '.join(missing)}"
        )


def _summarize_rows(rows, keys) -> str:
    samples = []
    for row in rows[:5]:
        samples.append(
            "/".join(str(row.get(key, "")) for key in keys)
        )
    suffix = " ..." if len(rows) > 5 else ""
    return ", ".join(samples) + suffix


def _fail_on_legacy_ghost_classes(cursor) -> None:
    ghosts = _rows(
        cursor,
        """
        SELECT u.id, u.username, u.`class` AS class_en
        FROM users u
        LEFT JOIN class_table ct ON ct.class_en = TRIM(u.`class`)
        WHERE u.`class` IS NOT NULL
          AND TRIM(u.`class`) <> ''
          AND TRIM(u.`class`) <> %s
          AND ct.class_en IS NULL
        ORDER BY u.id
        """,
        (LEGACY_ADMIN_CLASS,),
    )
    if ghosts:
        raise MigrationBlockedError(
            "users.class 含不存在于 class_table 的幽灵班级: "
            + _summarize_rows(ghosts, ("id", "username", "class_en"))
        )


def _fail_on_mapping_ghosts(
        cursor,
        *,
        allow_legacy_admin_class: bool,
        allow_known_orphan_mapping: bool,
        map_columns: set[str],
) -> bool:
    admin_exception = ""
    params = ()
    if allow_legacy_admin_class:
        admin_exception = "AND m.class_en <> %s"
        params = (LEGACY_ADMIN_CLASS,)
    ghosts = _rows(
        cursor,
        f"""
        SELECT m.user_id, m.class_en,
               u.id AS matched_user_id,
               ct.class_en AS matched_class_en
        FROM user_class_map m
        LEFT JOIN users u ON u.id = m.user_id
        LEFT JOIN class_table ct ON ct.class_en = m.class_en
        WHERE u.id IS NULL
           OR (ct.class_en IS NULL {admin_exception})
        ORDER BY m.user_id, m.class_en
        """,
        params,
    )
    if not ghosts:
        return False

    known_pair = (
        len(ghosts) == 1
        and int(ghosts[0].get("user_id") or 0) == KNOWN_ORPHAN_USER_ID
        and str(ghosts[0].get("class_en") or "") == KNOWN_ORPHAN_CLASS
        and int(ghosts[0].get("matched_user_id") or 0)
        == KNOWN_ORPHAN_USER_ID
        and ghosts[0].get("matched_class_en") is None
    )
    if not (allow_known_orphan_mapping and known_pair):
        raise MigrationBlockedError(
            "user_class_map 含孤儿用户或幽灵班级: "
            + _summarize_rows(ghosts, ("user_id", "class_en"))
        )

    _require_columns(
        map_columns,
        {"id", "user_id", "class_en", "is_primary"},
        "user_class_map",
    )
    target_rows = _rows(
        cursor,
        """
        SELECT id, user_id, class_en, is_primary
        FROM user_class_map
        WHERE user_id=%s AND class_en=%s
        ORDER BY id
        """,
        (KNOWN_ORPHAN_USER_ID, KNOWN_ORPHAN_CLASS),
    )
    target_signature = [
        (
            int(row.get("id") or 0),
            int(row.get("user_id") or 0),
            str(row.get("class_en") or ""),
            int(row.get("is_primary") or 0),
        )
        for row in target_rows
    ]
    expected_signature = [(
        KNOWN_ORPHAN_MEMBERSHIP_ID,
        KNOWN_ORPHAN_USER_ID,
        KNOWN_ORPHAN_CLASS,
        KNOWN_ORPHAN_IS_PRIMARY,
    )]
    if target_signature != expected_signature:
        raise MigrationBlockedError(
            "已授权孤儿班级关系的行身份发生变化，拒绝自动删除"
        )

    valid_membership_rows = _rows(
        cursor,
        """
        SELECT COUNT(*) AS valid_count
        FROM user_class_map m
        JOIN class_table ct ON ct.class_en = m.class_en
        WHERE m.user_id=%s AND m.id<>%s
        """,
        (KNOWN_ORPHAN_USER_ID, KNOWN_ORPHAN_MEMBERSHIP_ID),
    )
    valid_membership_count = int(
        (valid_membership_rows[0] if valid_membership_rows else {}).get(
            "valid_count",
        ) or 0
    )
    if valid_membership_count != KNOWN_ORPHAN_VALID_MEMBERSHIP_COUNT:
        raise MigrationBlockedError(
            "已授权孤儿班级关系所属用户的有效班级数量发生变化，拒绝自动删除"
        )

    if not _table_exists_exact(cursor, KNOWN_ORPHAN_CLASS):
        raise MigrationBlockedError(
            "已授权孤儿班级关系对应的空作业表已不存在，拒绝自动删除"
        )
    cursor.execute(
        f"SELECT COUNT(*) AS row_count FROM `{KNOWN_ORPHAN_CLASS}`"
    )
    row_count = int((cursor.fetchone() or {}).get("row_count") or 0)
    if row_count:
        raise MigrationBlockedError(
            f"已授权孤儿班级的作业表已有 {row_count} 行，拒绝自动删除关系"
        )
    return True


def _fail_on_zero_membership_students(
        cursor,
        *,
        has_legacy_class: bool,
        remove_legacy_admin_class: bool,
) -> None:
    legacy_fallback = ""
    legacy_membership_source = ""
    membership_exception = ""
    params = []
    if remove_legacy_admin_class:
        membership_exception = "AND m.class_en <> %s"
        params.append(LEGACY_ADMIN_CLASS)
    if has_legacy_class:
        legacy_fallback = """
          AND NOT EXISTS (
              SELECT 1
              FROM class_table legacy_class
              WHERE legacy_class.class_en = TRIM(u.`class`)
                AND legacy_class.class_en <> %s
          )
        """
        params.append(LEGACY_ADMIN_CLASS)
        legacy_membership_source = """
          OR (
              u.`class` IS NOT NULL
              AND TRIM(u.`class`) <> ''
          )
        """

    rows = _rows(
        cursor,
        f"""
        SELECT u.id, u.username
        FROM users u
        WHERE u.is_admin = 0
          AND NOT EXISTS (
              SELECT 1
              FROM user_class_map m
              WHERE m.user_id = u.id
                {membership_exception}
          )
          {legacy_fallback}
          AND (
              EXISTS (
                  SELECT 1
                  FROM user_class_map source_membership
                  WHERE source_membership.user_id = u.id
              )
              {legacy_membership_source}
          )
        ORDER BY u.id
        """,
        tuple(params),
    )
    if rows:
        raise MigrationBlockedError(
            "以下非管理员用户在迁移后将没有任何班级: "
            + _summarize_rows(rows, ("id", "username"))
        )


def _fail_on_nonempty_admin_homework_table(cursor) -> None:
    cursor.execute("SELECT COUNT(*) AS row_count FROM `Cadmin`")
    row = cursor.fetchone() or {}
    row_count = int(row.get("row_count") or 0)
    if row_count:
        raise MigrationBlockedError(
            f"Cadmin 伪班级作业表仍有 {row_count} 行，拒绝自动删除"
        )


def _preflight(
        cursor,
        users_columns: set[str],
        map_columns: set[str],
        *,
        remove_legacy_admin_class: bool,
        allow_known_orphan_mapping: bool = False,
) -> bool:
    _require_columns(
        users_columns,
        {"id", "username", "is_admin"},
        "users",
    )
    _require_columns(
        map_columns,
        {"user_id", "class_en"},
        "user_class_map",
    )
    if "class" in users_columns:
        _fail_on_legacy_ghost_classes(cursor)
    known_orphan_present = _fail_on_mapping_ghosts(
        cursor,
        allow_legacy_admin_class=remove_legacy_admin_class,
        allow_known_orphan_mapping=allow_known_orphan_mapping,
        map_columns=map_columns,
    )
    _fail_on_zero_membership_students(
        cursor,
        has_legacy_class="class" in users_columns,
        remove_legacy_admin_class=remove_legacy_admin_class,
    )
    return known_orphan_present


def _has_legacy_primary_schema(
        users_columns: set[str],
        map_columns: set[str],
        map_indexes: set[str],
) -> bool:
    return bool(
        {"class", "class_cn"} & users_columns
        or "is_primary" in map_columns
        or "idx_primary" in map_indexes
    )


def build_plan(cursor) -> list[MigrationOperation]:
    """Build and validate an idempotent migration plan using read-only checks."""
    users_columns = _column_names(cursor, "users")
    map_columns = _column_names(cursor, "user_class_map")
    map_indexes = _index_names(cursor, "user_class_map")
    has_legacy_primary_schema = _has_legacy_primary_schema(
        users_columns,
        map_columns,
        map_indexes,
    )
    known_orphan_present = _preflight(
        cursor,
        users_columns,
        map_columns,
        remove_legacy_admin_class=has_legacy_primary_schema,
        allow_known_orphan_mapping=has_legacy_primary_schema,
    )
    if not has_legacy_primary_schema:
        return []

    has_admin_homework_table = _table_exists(cursor, LEGACY_ADMIN_CLASS)
    if has_admin_homework_table:
        _fail_on_nonempty_admin_homework_table(cursor)

    operations: list[MigrationOperation] = []
    if known_orphan_present:
        operations.append(MigrationOperation(
            """
            DELETE FROM user_class_map
            WHERE id=%s
              AND user_id=%s
              AND class_en=%s
              AND is_primary=%s
            """.strip(),
            (
                KNOWN_ORPHAN_MEMBERSHIP_ID,
                KNOWN_ORPHAN_USER_ID,
                KNOWN_ORPHAN_CLASS,
                KNOWN_ORPHAN_IS_PRIMARY,
            ),
            expected_rowcount=1,
        ))
    if "class" in users_columns:
        if "is_primary" in map_columns:
            insert_columns = "(user_id, class_en, is_primary)"
            select_values = "u.id, TRIM(u.`class`), 0"
        else:
            insert_columns = "(user_id, class_en)"
            select_values = "u.id, TRIM(u.`class`)"
        operations.append(MigrationOperation(
            f"""
            INSERT IGNORE INTO user_class_map {insert_columns}
            SELECT {select_values}
            FROM users u
            JOIN class_table ct ON ct.class_en = TRIM(u.`class`)
            WHERE u.`class` IS NOT NULL
              AND TRIM(u.`class`) <> ''
              AND TRIM(u.`class`) <> %s
            """.strip(),
            (LEGACY_ADMIN_CLASS,),
        ))

    operations.extend([
        MigrationOperation(
            "DELETE FROM user_class_map WHERE class_en=%s",
            (LEGACY_ADMIN_CLASS,),
        ),
        MigrationOperation(
            """
            UPDATE class_table ct
            LEFT JOIN (
                SELECT class_en, COUNT(*) AS member_count
                FROM user_class_map
                GROUP BY class_en
            ) counts ON counts.class_en = ct.class_en
            SET ct.class_cnt = COALESCE(counts.member_count, 0)
            """.strip(),
        ),
        MigrationOperation(
            "DELETE FROM class_table WHERE class_en=%s",
            (LEGACY_ADMIN_CLASS,),
        ),
    ])

    if has_admin_homework_table:
        operations.append(MigrationOperation(
            "DROP TABLE `Cadmin`",
            kind="ddl",
        ))
    if "idx_primary" in map_indexes:
        operations.append(MigrationOperation(
            "ALTER TABLE user_class_map DROP INDEX idx_primary",
            kind="ddl",
        ))
    if "is_primary" in map_columns:
        operations.append(MigrationOperation(
            "ALTER TABLE user_class_map DROP COLUMN is_primary",
            kind="ddl",
        ))
    if "class" in users_columns:
        operations.append(MigrationOperation(
            "ALTER TABLE users DROP COLUMN `class`",
            kind="ddl",
        ))
    if "class_cn" in users_columns:
        operations.append(MigrationOperation(
            "ALTER TABLE users DROP COLUMN class_cn",
            kind="ddl",
        ))
    return operations


def _verify_contracted_schema(
        cursor,
        *,
        require_legacy_admin_removed: bool,
) -> None:
    users_columns = _column_names(cursor, "users")
    map_columns = _column_names(cursor, "user_class_map")
    map_indexes = _index_names(cursor, "user_class_map")
    leftovers = []
    for column in ("class", "class_cn"):
        if column in users_columns:
            leftovers.append(f"users.{column}")
    if "is_primary" in map_columns:
        leftovers.append("user_class_map.is_primary")
    if "idx_primary" in map_indexes:
        leftovers.append("user_class_map.idx_primary")
    if leftovers:
        raise MigrationBlockedError(
            "迁移后仍存在主班级结构: " + ", ".join(leftovers)
        )

    _preflight(
        cursor,
        users_columns,
        map_columns,
        remove_legacy_admin_class=False,
    )

    if require_legacy_admin_removed:
        admin_class_rows = _rows(
            cursor,
            """
            SELECT 'class_table' AS source, class_en
            FROM class_table WHERE class_en=%s
            UNION ALL
            SELECT 'user_class_map' AS source, class_en
            FROM user_class_map WHERE class_en=%s
            """,
            (LEGACY_ADMIN_CLASS, LEGACY_ADMIN_CLASS),
        )
        if admin_class_rows:
            raise MigrationBlockedError(
                "Cadmin 伪班级或成员关系清理不完整"
            )
        if _table_exists(cursor, LEGACY_ADMIN_CLASS):
            raise MigrationBlockedError("Cadmin 伪班级作业表清理不完整")

    mismatches = _rows(
        cursor,
        """
        SELECT ct.class_en, ct.class_cnt, COUNT(m.user_id) AS expected_count
        FROM class_table ct
        LEFT JOIN user_class_map m ON m.class_en = ct.class_en
        GROUP BY ct.class_en, ct.class_cnt
        HAVING COALESCE(ct.class_cnt, 0) <> COUNT(m.user_id)
        ORDER BY ct.class_en
        """,
    )
    if mismatches:
        raise MigrationBlockedError(
            "class_cnt 重算后仍不一致: "
            + _summarize_rows(
                mismatches,
                ("class_en", "class_cnt", "expected_count"),
            )
        )


def migrate(connection, *, apply: bool = False) -> list[MigrationOperation]:
    """Plan or apply the migration on an existing database connection."""
    locked = False
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT GET_LOCK(%s, %s) AS locked",
                (MIGRATION_LOCK_NAME, MIGRATION_LOCK_TIMEOUT_SECONDS),
            )
            lock_row = cursor.fetchone() or {}
            if int(lock_row.get("locked") or 0) != 1:
                raise MigrationBlockedError("无法取得主班级迁移锁")
            locked = True

            users_columns = _column_names(cursor, "users")
            map_columns = _column_names(cursor, "user_class_map")
            map_indexes = _index_names(cursor, "user_class_map")
            legacy_admin_cleanup_expected = _has_legacy_primary_schema(
                users_columns,
                map_columns,
                map_indexes,
            )
            operations = build_plan(cursor)
            if not apply:
                connection.rollback()
                return operations

            for operation in operations:
                cursor.execute(operation.sql, operation.params)
                if (
                    operation.expected_rowcount is not None
                    and cursor.rowcount != operation.expected_rowcount
                ):
                    raise MigrationBlockedError(
                        "迁移操作影响行数不符合预期: "
                        f"expected={operation.expected_rowcount}, "
                        f"actual={cursor.rowcount}"
                    )
            connection.commit()
            _verify_contracted_schema(
                cursor,
                require_legacy_admin_removed=(
                    legacy_admin_cleanup_expected
                ),
            )
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
    config = load_config()
    return connect_mysql(
        settings_from_config(config),
        with_database=True,
        dict_rows=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove NumericalOJ's legacy primary-class schema.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the destructive migration; omitted means read-only dry-run.",
    )
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="Confirm Web and all Celery writers are stopped.",
    )
    parser.add_argument(
        "--confirm-backup-verified",
        action="store_true",
        help="Confirm the pre-migration database backup was verified.",
    )
    args = parser.parse_args()

    if args.apply and not (
        args.confirm_app_writers_stopped and args.confirm_backup_verified
    ):
        parser.error(
            "--apply requires --confirm-app-writers-stopped "
            "and --confirm-backup-verified"
        )

    connection = _connect()
    try:
        operations = migrate(connection, apply=args.apply)
    except Exception as exc:
        print(f"[remove-primary-class] blocked: {exc}", file=sys.stderr)
        return 1
    finally:
        connection.close()

    mode = "apply" if args.apply else "dry-run"
    print(f"[remove-primary-class] {mode}: {len(operations)} operations")
    for operation in operations:
        print(operation.display())
    if not args.apply:
        print("[remove-primary-class] no data or schema changes were applied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
