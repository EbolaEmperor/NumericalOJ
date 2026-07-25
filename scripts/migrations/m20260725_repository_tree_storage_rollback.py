#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""把已迁走的 legacy 代码仓库行从受校验备份恢复到旧表。

默认只审计。实际恢复必须在全部 Web/Celery 写入者停止后显式传入
``--apply --confirm-app-writers-stopped``。脚本只恢复
``user_code_repository`` 原始行并把迁移回执标记为 ``rolled_back``；新目录树与
high-water 会保留，便于调查及之后重新迁移，旧版本应用会忽略它们。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.migrations.m20260725_repository_tree_storage import (  # noqa: E402
    MIGRATION_ID,
    MIGRATION_LOCK_NAME,
    MigrationError,
    ROLLBACK_BACKUP_PATH,
    _acquire_lock,
    _assert_required_schema,
    _release_lock,
    _serialize_legacy_row,
    load_rollback_backup,
)
from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    load_config,
    settings_from_config,
)


ROLLBACK_ID = f"{MIGRATION_ID}_rollback"


@dataclass(frozen=True)
class RollbackUserPlan:
    user_id: int
    source_file_count: int
    already_restored: int
    rows_to_restore: int
    receipt_status: str


@dataclass(frozen=True)
class RollbackReport:
    apply: bool
    backup_path: str
    users: tuple[RollbackUserPlan, ...]


def _rows_by_user(rows):
    grouped = {}
    for row in rows:
        grouped.setdefault(int(row["user_id"]), []).append(row)
    return grouped


def _load_existing_legacy_rows(cursor, user_id):
    cursor.execute(
        """
        SELECT id, user_id, filename, file_content, file_size, created_at, updated_at
        FROM user_code_repository
        WHERE user_id = %s
        ORDER BY id ASC
        """,
        (int(user_id),),
    )
    return cursor.fetchall() or []


def _plan_user_restore(user_id, backup_rows, existing_rows, receipt_status):
    expected_by_id = {int(row["id"]): row for row in backup_rows}
    expected_by_name = {
        (int(row["user_id"]), str(row["filename"])): row for row in backup_rows
    }
    existing_by_id = {
        int(row["id"]): _serialize_legacy_row(row) for row in existing_rows
    }
    existing_by_name = {
        (int(row["user_id"]), str(row["filename"])): _serialize_legacy_row(row)
        for row in existing_rows
    }
    unexpected = [
        row for row in existing_rows
        if int(row["id"]) not in expected_by_id
        or (int(row["user_id"]), str(row["filename"])) not in expected_by_name
    ]
    if unexpected:
        raise MigrationError(
            f"用户 {user_id} 的 legacy 表已有备份之外的数据，拒绝覆盖"
        )

    missing = []
    already_restored = 0
    for expected in backup_rows:
        row_id = int(expected["id"])
        name_key = (int(expected["user_id"]), str(expected["filename"]))
        by_id = existing_by_id.get(row_id)
        by_name = existing_by_name.get(name_key)
        if by_id is None and by_name is None:
            missing.append(expected)
            continue
        if by_id != expected or by_name != expected:
            raise MigrationError(
                f"用户 {user_id} 的 legacy 行 {row_id} 与回滚备份冲突"
            )
        already_restored += 1
    return RollbackUserPlan(
        user_id=int(user_id),
        source_file_count=len(backup_rows),
        already_restored=already_restored,
        rows_to_restore=len(missing),
        receipt_status=str(receipt_status),
    ), missing


def _restore_user(connection, user_id, backup_rows):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT status
            FROM repository_legacy_migrations
            WHERE user_id = %s
            FOR UPDATE
            """,
            (int(user_id),),
        )
        receipt = cursor.fetchone()
        if not receipt or receipt["status"] not in {"complete", "rolled_back"}:
            raise MigrationError(
                f"用户 {user_id} 没有可回滚的 complete 迁移回执"
            )
        existing_rows = _load_existing_legacy_rows(cursor, user_id)
        _plan, missing = _plan_user_restore(
            user_id, backup_rows, existing_rows, receipt["status"]
        )
        for row in missing:
            cursor.execute(
                """
                INSERT INTO user_code_repository (
                    id, user_id, filename, file_content, file_size,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    int(row["id"]),
                    int(row["user_id"]),
                    row["filename"],
                    row["file_content"],
                    int(row["file_size"]),
                    row.get("created_at"),
                    row.get("updated_at"),
                ),
            )
        if receipt["status"] == "complete":
            cursor.execute(
                """
                UPDATE repository_legacy_migrations
                SET status = 'rolled_back'
                WHERE user_id = %s AND status = 'complete'
                """,
                (int(user_id),),
            )
            if int(cursor.rowcount) != 1:
                raise MigrationError(f"用户 {user_id} 的迁移回执状态并发变化")
    connection.commit()


def execute_rollback(*, apply=False, app_writers_stopped_confirmed=False):
    if apply and not app_writers_stopped_confirmed:
        raise MigrationError("拒绝回滚：未确认全部应用写入者已经停止")
    backup = load_rollback_backup()
    grouped = _rows_by_user(backup["rows"])
    settings = settings_from_config(load_config())
    connection = connect_mysql(settings, with_database=True, dict_rows=True)
    locked = False
    try:
        with connection.cursor() as cursor:
            _acquire_lock(cursor)
            locked = True
            if not _assert_required_schema(cursor, settings.database):
                raise MigrationError(
                    "当前数据库没有 legacy user_code_repository 表；"
                    "精细回滚只能用于确实从旧表迁移过的部署"
                )
            cursor.execute(
                """
                SELECT user_id, status
                FROM repository_legacy_migrations
                WHERE status IN ('complete', 'rolled_back')
                ORDER BY user_id ASC
                """
            )
            receipts = {
                int(row["user_id"]): str(row["status"])
                for row in cursor.fetchall() or []
            }
            plans = []
            for user_id, receipt_status in sorted(receipts.items()):
                backup_rows = grouped.get(user_id)
                if backup_rows is None:
                    raise MigrationError(
                        f"用户 {user_id} 的迁移回执不在回滚备份中"
                    )
                existing_rows = _load_existing_legacy_rows(cursor, user_id)
                plan, _missing = _plan_user_restore(
                    user_id, backup_rows, existing_rows, receipt_status
                )
                plans.append(plan)
        report = RollbackReport(
            apply=bool(apply),
            backup_path=str(ROLLBACK_BACKUP_PATH),
            users=tuple(plans),
        )
        if not apply:
            connection.rollback()
            return report
        for plan in plans:
            _restore_user(connection, plan.user_id, grouped[plan.user_id])
        return report
    except Exception:
        connection.rollback()
        raise
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
    parser.add_argument("--apply", action="store_true", help="执行回滚；默认只审计")
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )
    args = parser.parse_args()
    report = execute_rollback(
        apply=args.apply,
        app_writers_stopped_confirmed=args.confirm_app_writers_stopped,
    )
    print(
        json.dumps(
            {
                "rollback": ROLLBACK_ID,
                "apply": report.apply,
                "backup_path": report.backup_path,
                "users": [plan.__dict__ for plan in report.users],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
