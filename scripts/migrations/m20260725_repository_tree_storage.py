#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""把旧平铺 ``user_code_repository`` 正文迁入受管真实目录树。

默认只审计。实际执行必须在全部 Web/Celery 写入者停止、数据库完成可验证备份后显式
传入 ``--apply --confirm-app-writers-stopped``。迁移先固定提交快照的历史 high-water
mark，再逐用户写入文件系统、核验内容，最后在单个数据库事务内写迁移回执并删除对应
legacy 正文。文件系统步骤中断可幂等重跑；发现部分但不一致的新树时会失败关闭。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.repository.storage import (  # noqa: E402
    MAX_ENTRIES,
    MAX_TOTAL_BYTES,
    STORAGE_ROOT,
    ensure_repository_storage_ready,
    normalize_source_bytes,
    validate_relative_path,
)
from oj_modules.repository.tree import (  # noqa: E402
    get_repository_tree_snapshot,
    upsert_repository_file_by_path,
)
from scripts.mysql_admin import (  # noqa: E402
    connect_mysql,
    load_config,
    settings_from_config,
)


MIGRATION_ID = "m20260725_repository_tree_storage"
MIGRATION_LOCK_NAME = "numericaloj:m20260725:repository_tree_storage"
MIGRATION_LOCK_TIMEOUT_SECONDS = 120
LEGACY_HIGH_WATER_KEY = "repository_snapshot_legacy_max_submission_id"
ROLLBACK_BACKUP_SCHEMA_VERSION = 1
ROLLBACK_BACKUP_DIRECTORY = (
    STORAGE_ROOT / "migration-backups" / MIGRATION_ID
)
ROLLBACK_BACKUP_PATH = ROLLBACK_BACKUP_DIRECTORY / "legacy_rows.json"
REQUIRED_TABLES = {
    "users",
    "submissions",
    "site_settings",
    "repository_states",
    "repository_entries",
    "repository_legacy_migrations",
}
LEGACY_TABLE = "user_code_repository"


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class UserPlan:
    user_id: int
    file_count: int
    total_size: int
    manifest_sha256: str


@dataclass(frozen=True)
class MigrationReport:
    apply: bool
    legacy_high_water: int
    users: tuple[UserPlan, ...]
    legacy_file_count: int
    normalized_total_size: int


def _acquire_lock(cursor):
    cursor.execute(
        "SELECT GET_LOCK(%s, %s) AS locked",
        (MIGRATION_LOCK_NAME, MIGRATION_LOCK_TIMEOUT_SECONDS),
    )
    if int((cursor.fetchone() or {}).get("locked") or 0) != 1:
        raise MigrationError("无法取得代码仓库迁移锁")


def _release_lock(cursor):
    cursor.execute("SELECT RELEASE_LOCK(%s) AS released", (MIGRATION_LOCK_NAME,))


def _assert_required_schema(cursor, database):
    inspected_tables = REQUIRED_TABLES | {LEGACY_TABLE}
    placeholders = ",".join(["%s"] * len(inspected_tables))
    cursor.execute(
        "SELECT TABLE_NAME AS table_name FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN ({placeholders})",
        (database, *sorted(inspected_tables)),
    )
    found = {row["table_name"] for row in cursor.fetchall() or []}
    missing = sorted(REQUIRED_TABLES - found)
    if missing:
        raise MigrationError(
            "缺少新仓库 schema，请先完成受控 schema 同步：" + "、".join(missing)
        )
    return LEGACY_TABLE in found


def _legacy_rows(cursor):
    cursor.execute(
        """
        SELECT id, user_id, filename, file_content, file_size, created_at, updated_at
        FROM user_code_repository
        ORDER BY user_id ASC, id ASC
        """
    )
    return cursor.fetchall() or []


def _normalize_legacy_rows(rows):
    grouped = {}
    for row in rows:
        user_id = int(row["user_id"])
        relative_path = validate_relative_path(row["filename"])
        normalized = normalize_source_bytes(str(row.get("file_content") or "").encode("utf-8"))
        grouped.setdefault(user_id, []).append(
            {
                **row,
                "relative_path": relative_path,
                "normalized_content": normalized.text,
                "normalized_size": len(normalized.data),
                "normalized_sha256": normalized.sha256,
            }
        )
    plans = []
    for user_id, user_rows in sorted(grouped.items()):
        if len(user_rows) > MAX_ENTRIES:
            raise MigrationError(f"用户 {user_id} 的 legacy 文件数超过 {MAX_ENTRIES}")
        total_size = sum(item["normalized_size"] for item in user_rows)
        if total_size > MAX_TOTAL_BYTES:
            raise MigrationError(
                f"用户 {user_id} 的规范化仓库大小超过 {MAX_TOTAL_BYTES} 字节"
            )
        paths = [item["relative_path"] for item in user_rows]
        if len(paths) != len(set(paths)):
            raise MigrationError(f"用户 {user_id} 存在重复 legacy 路径")
        path_set = set(paths)
        for path in paths:
            parent_parts = path.split("/")[:-1]
            for depth in range(1, len(parent_parts) + 1):
                prefix = "/".join(parent_parts[:depth])
                if prefix in path_set:
                    raise MigrationError(
                        f"用户 {user_id} 的 legacy 路径同时被用作文件和目录：{prefix}"
                    )
        manifest = [
            {
                "legacy_id": int(item["id"]),
                "path": item["relative_path"],
                "size": item["normalized_size"],
                "sha256": item["normalized_sha256"],
            }
            for item in user_rows
        ]
        digest = hashlib.sha256(
            json.dumps(
                manifest,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        plans.append(
            UserPlan(
                user_id=user_id,
                file_count=len(user_rows),
                total_size=total_size,
                manifest_sha256=digest,
            )
        )
    return grouped, tuple(plans)


def _expected_directory_paths(legacy_rows):
    expected = set()
    for item in legacy_rows:
        parts = item["relative_path"].split("/")
        for depth in range(1, len(parts)):
            expected.add("/".join(parts[:depth]))
    return expected


def _inspect_authoritative_user_tree(user_id, legacy_rows):
    """验证当前树是目标 manifest 的正确子集，并返回尚未迁入的行。

    迁移按单文件原子写入；进程可能在任意两个文件之间中断。这里允许正确子集续写，
    但任何额外路径、类型冲突或摘要漂移都会失败关闭。
    """
    snapshot = get_repository_tree_snapshot(user_id, include_content=False)
    actual_files = {
        item["relative_path"]: item
        for item in snapshot["entries"]
        if item["kind"] == "file"
    }
    actual_directories = {
        item["relative_path"]: item
        for item in snapshot["entries"]
        if item["kind"] == "directory"
    }
    expected = {item["relative_path"]: item for item in legacy_rows}
    expected_directories = _expected_directory_paths(legacy_rows)
    unexpected_files = sorted(set(actual_files) - set(expected))
    unexpected_directories = sorted(set(actual_directories) - expected_directories)
    if unexpected_files or unexpected_directories:
        raise MigrationError(
            f"用户 {user_id} 的新仓库包含 legacy manifest 之外的路径，拒绝合并猜测："
            f"files={unexpected_files[:3]} dirs={unexpected_directories[:3]}"
        )
    for path, actual in actual_files.items():
        expected_item = expected[path]
        if (
            int(actual["file_size"]) != int(expected_item["normalized_size"])
            or actual["sha256"] != expected_item["normalized_sha256"]
        ):
            raise MigrationError(f"用户 {user_id} 的迁移文件核验失败：{path}")
    missing = [
        item for item in legacy_rows
        if item["relative_path"] not in actual_files
    ]
    return snapshot, missing


def _verify_authoritative_user_tree(user_id, legacy_rows):
    snapshot, missing = _inspect_authoritative_user_tree(user_id, legacy_rows)
    if missing:
        raise MigrationError(
            f"用户 {user_id} 的新仓库缺少 {len(missing)} 个 legacy 文件"
        )
    actual_directories = {
        item["relative_path"]
        for item in snapshot["entries"]
        if item["kind"] == "directory"
    }
    expected_directories = _expected_directory_paths(legacy_rows)
    if actual_directories != expected_directories:
        raise MigrationError(
            f"用户 {user_id} 的目录树不是 legacy manifest 的精确镜像"
        )
    return snapshot


def _migrate_user(connection, user_id, rows, plan):
    snapshot, missing = _inspect_authoritative_user_tree(user_id, rows)
    structure_version = int(snapshot["structure_version"])
    for row in missing:
        result = upsert_repository_file_by_path(
            user_id,
            row["relative_path"],
            row["normalized_content"],
            expected_structure_version=structure_version,
            overwrite=False,
        )
        structure_version = int(result["structure_version"])
    _verify_authoritative_user_tree(user_id, rows)

    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT source_file_count, source_total_size, source_manifest_sha256,
                   status
            FROM repository_legacy_migrations
            WHERE user_id = %s
            FOR UPDATE
            """,
            (int(user_id),),
        )
        existing = cursor.fetchone()
        if existing and (
            int(existing["source_file_count"]) != plan.file_count
            or int(existing["source_total_size"]) != plan.total_size
            or existing["source_manifest_sha256"] != plan.manifest_sha256
        ):
            raise MigrationError(
                f"用户 {user_id} 已有不同 manifest 的迁移回执，拒绝覆盖"
            )
        cursor.execute(
            """
            INSERT INTO repository_legacy_migrations (
                user_id, source_file_count, source_total_size,
                source_manifest_sha256, status, completed_at
            ) VALUES (%s, %s, %s, %s, 'complete', NOW())
            ON DUPLICATE KEY UPDATE
                source_file_count = VALUES(source_file_count),
                source_total_size = VALUES(source_total_size),
                source_manifest_sha256 = VALUES(source_manifest_sha256),
                status = 'complete',
                completed_at = COALESCE(completed_at, NOW())
            """,
            (
                int(user_id),
                plan.file_count,
                plan.total_size,
                plan.manifest_sha256,
            ),
        )
        cursor.execute(
            "DELETE FROM user_code_repository WHERE user_id = %s",
            (int(user_id),),
        )
        if int(cursor.rowcount) != plan.file_count:
            raise MigrationError(
                f"用户 {user_id} 的 legacy 删除数量变化，事务已回滚"
            )
    connection.commit()


def _json_scalar(value):
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, date):
        return value.isoformat()
    return value


def _serialize_legacy_row(row):
    return {
        "id": int(row["id"]),
        "user_id": int(row["user_id"]),
        "filename": str(row["filename"]),
        "file_content": str(row.get("file_content") or ""),
        "file_size": int(row.get("file_size") or 0),
        "created_at": _json_scalar(row.get("created_at")),
        "updated_at": _json_scalar(row.get("updated_at")),
    }


def _backup_payload_digest(payload_without_digest):
    return hashlib.sha256(
        json.dumps(
            payload_without_digest,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _decode_rollback_backup(raw_text):
    try:
        payload = json.loads(raw_text)
    except (TypeError, ValueError) as exc:
        raise MigrationError("仓库 legacy 回滚备份不是有效 JSON") from exc
    if (
        not isinstance(payload, dict)
        or int(payload.get("schema_version") or 0)
        != ROLLBACK_BACKUP_SCHEMA_VERSION
        or payload.get("migration_id") != MIGRATION_ID
        or not isinstance(payload.get("rows"), list)
    ):
        raise MigrationError("仓库 legacy 回滚备份格式或版本不匹配")
    expected_digest = str(payload.get("payload_sha256") or "")
    unsigned = dict(payload)
    unsigned.pop("payload_sha256", None)
    actual_digest = _backup_payload_digest(unsigned)
    if expected_digest != actual_digest:
        raise MigrationError("仓库 legacy 回滚备份摘要校验失败")
    return payload


def load_rollback_backup():
    try:
        raw_text = ROLLBACK_BACKUP_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise MigrationError(
            f"缺少可执行回滚备份：{ROLLBACK_BACKUP_PATH}"
        ) from exc
    return _decode_rollback_backup(raw_text)


def _assert_current_rows_match_backup(rows, backup):
    backup_by_id = {
        int(item["id"]): item for item in backup.get("rows") or []
    }
    for row in rows:
        serialized = _serialize_legacy_row(row)
        if backup_by_id.get(serialized["id"]) != serialized:
            raise MigrationError(
                f"legacy 行 {serialized['id']} 与首次迁移回滚备份不一致"
            )


def _ensure_rollback_backup(rows, high_water):
    """首次 apply 原子保存 legacy 原文；续跑只接受其正确子集。"""
    ensure_repository_storage_ready()
    ROLLBACK_BACKUP_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(ROLLBACK_BACKUP_DIRECTORY, 0o700)
    except OSError:
        pass
    if ROLLBACK_BACKUP_PATH.exists():
        backup = load_rollback_backup()
        _assert_current_rows_match_backup(rows, backup)
        return backup

    unsigned = {
        "schema_version": ROLLBACK_BACKUP_SCHEMA_VERSION,
        "migration_id": MIGRATION_ID,
        "legacy_high_water": int(high_water),
        "rows": [_serialize_legacy_row(row) for row in rows],
    }
    payload = {
        **unsigned,
        "payload_sha256": _backup_payload_digest(unsigned),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    temporary = ROLLBACK_BACKUP_DIRECTORY / f".legacy_rows-{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, ROLLBACK_BACKUP_PATH)
        os.chmod(ROLLBACK_BACKUP_PATH, 0o600)
        directory_fd = os.open(
            ROLLBACK_BACKUP_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return payload


def execute_migration(*, apply=False, app_writers_stopped_confirmed=False):
    if apply and not app_writers_stopped_confirmed:
        raise MigrationError("拒绝迁移：未确认全部应用写入者已经停止")
    settings = settings_from_config(load_config())
    connection = connect_mysql(
        settings, with_database=True, dict_rows=True
    )
    locked = False
    try:
        with connection.cursor() as cursor:
            _acquire_lock(cursor)
            locked = True
            has_legacy_table = _assert_required_schema(cursor, settings.database)
            cursor.execute("SELECT COALESCE(MAX(id), 0) AS high_water FROM submissions")
            high_water = int((cursor.fetchone() or {}).get("high_water") or 0)
            rows = _legacy_rows(cursor) if has_legacy_table else []
        grouped, plans = _normalize_legacy_rows(rows)
        report = MigrationReport(
            apply=bool(apply),
            legacy_high_water=high_water,
            users=plans,
            legacy_file_count=len(rows),
            normalized_total_size=sum(plan.total_size for plan in plans),
        )
        if not apply:
            connection.rollback()
            return report

        rollback_backup = _ensure_rollback_backup(rows, high_water)
        fixed_high_water = int(rollback_backup["legacy_high_water"])
        # INSERT IGNORE 固定首次值；重跑绝不把“历史”边界向后推进。
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT IGNORE INTO site_settings (k, v) VALUES (%s, %s)",
                (LEGACY_HIGH_WATER_KEY, str(fixed_high_water)),
            )
            cursor.execute(
                "SELECT v FROM site_settings WHERE k = %s",
                (LEGACY_HIGH_WATER_KEY,),
            )
            persisted = cursor.fetchone()
            if int((persisted or {}).get("v") or -1) != fixed_high_water:
                raise MigrationError(
                    "提交快照 legacy high-water 与首次迁移备份不一致"
                )
        connection.commit()

        plan_by_user = {plan.user_id: plan for plan in plans}
        for user_id, user_rows in sorted(grouped.items()):
            _migrate_user(connection, user_id, user_rows, plan_by_user[user_id])
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
    parser.add_argument("--apply", action="store_true", help="执行迁移；默认只审计")
    parser.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )
    args = parser.parse_args()
    report = execute_migration(
        apply=args.apply,
        app_writers_stopped_confirmed=args.confirm_app_writers_stopped,
    )
    print(
        json.dumps(
            {
                "migration": MIGRATION_ID,
                "apply": report.apply,
                "legacy_high_water": report.legacy_high_water,
                "legacy_file_count": report.legacy_file_count,
                "normalized_total_size": report.normalized_total_size,
                "users": [plan.__dict__ for plan in report.users],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
