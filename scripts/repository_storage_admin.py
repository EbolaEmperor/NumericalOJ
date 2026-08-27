#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""代码仓库存储 doctor、journal 恢复、过期上传清理与孤儿隔离入口。

除 ``doctor`` 外的命令默认也只读。恢复、清理或隔离必须显式传入 ``--apply`` 和
对应确认参数；本脚本不会在导入时连接数据库或修改文件系统。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj_modules.db_services import get_db_connection  # noqa: E402
from oj_modules.repository.admin import (  # noqa: E402
    doctor_repository_storage,
    quarantine_repository_orphans,
    quarantine_repository_snapshot_orphans,
)
from oj_modules.repository.tree import (  # noqa: E402
    cleanup_expired_repository_upload_sessions,
    repository_user_lock,
)


def _active_journal_report():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT operation_id, user_id, operation_type, status,
                       structure_version_before, structure_version_after,
                       created_at, updated_at
                FROM repository_fs_journal
                WHERE status IN ('prepared', 'fs_applied', 'committed')
                ORDER BY user_id ASC, created_at ASC
                """
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    return [
        {
            "operation_id": row["operation_id"],
            "user_id": int(row["user_id"]),
            "operation_type": row["operation_type"],
            "status": row["status"],
            "structure_version_before": int(row["structure_version_before"]),
            "structure_version_after": (
                int(row["structure_version_after"])
                if row.get("structure_version_after") is not None
                else None
            ),
            "created_at": str(row.get("created_at") or ""),
            "updated_at": str(row.get("updated_at") or ""),
        }
        for row in rows
    ]


def recover_repository_journals(*, apply=False, writers_stopped_confirmed=False):
    if apply and not writers_stopped_confirmed:
        raise RuntimeError("拒绝恢复：未确认全部应用写入者已经停止")
    before = _active_journal_report()
    if apply:
        for user_id in sorted({item["user_id"] for item in before}):
            with repository_user_lock(user_id, exclusive=True):
                pass
    return {
        "apply": bool(apply),
        "before": before,
        "remaining": _active_journal_report() if apply else before,
    }


def _print(payload):
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="只读核验 metadata 与文件系统")

    recover = subparsers.add_parser(
        "recover-journal",
        help="审计或恢复未完成文件系统 journal",
    )
    recover.add_argument("--apply", action="store_true")
    recover.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )

    cleanup = subparsers.add_parser(
        "cleanup-expired-uploads",
        help="审计或清理过期上传 staging",
    )
    cleanup.add_argument("--apply", action="store_true")
    cleanup.add_argument(
        "--confirm-expired-staging-delete",
        action="store_true",
        help="确认删除已过期上传暂存内容",
    )
    quarantine = subparsers.add_parser(
        "quarantine-orphans",
        help="审计或把孤儿路径原子隔离到受管 quarantine（不删除）",
    )
    quarantine.add_argument("--apply", action="store_true")
    quarantine.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )
    snapshot_quarantine = subparsers.add_parser(
        "quarantine-orphan-snapshots",
        help="审计或隔离没有 metadata 的提交快照（不删除）",
    )
    snapshot_quarantine.add_argument("--apply", action="store_true")
    snapshot_quarantine.add_argument(
        "--confirm-app-writers-stopped",
        action="store_true",
        help="确认 Web/Celery 等全部应用写入者已停止",
    )

    args = parser.parse_args()
    if args.command == "doctor":
        report = doctor_repository_storage()
        _print(report)
        return 0 if report["ok"] else 1
    if args.command == "recover-journal":
        report = recover_repository_journals(
            apply=args.apply,
            writers_stopped_confirmed=args.confirm_app_writers_stopped,
        )
        _print(report)
        return 0
    if args.command == "quarantine-orphans":
        report = quarantine_repository_orphans(
            apply=args.apply,
            writers_stopped_confirmed=args.confirm_app_writers_stopped,
        )
        _print(report)
        return 0
    if args.command == "quarantine-orphan-snapshots":
        report = quarantine_repository_snapshot_orphans(
            apply=args.apply,
            writers_stopped_confirmed=args.confirm_app_writers_stopped,
        )
        _print(report)
        return 0
    if args.apply and not args.confirm_expired_staging_delete:
        parser.error("--apply 必须同时传入 --confirm-expired-staging-delete")
    report = cleanup_expired_repository_upload_sessions(apply=args.apply)
    _print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
