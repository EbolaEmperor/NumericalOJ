#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""在完整停止 NumericalOJ Celery worker 后显式恢复未完成任务。"""

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _local_numoj_celery_processes():
    """返回仍在本机运行的 NumericalOJ Celery worker 进程描述。"""
    completed = subprocess.run(
        ["ps", "-axo", "pid=,command="],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return [
        line.strip()
        for line in completed.stdout.splitlines()
        if "celery" in line and "-A oj.celery" in line and " worker" in line
    ]


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--confirm-celery-stopped",
        action="store_true",
        help="确认所有本机和远端 NumericalOJ Celery worker 均已停止",
    )
    return parser.parse_args(argv)


def _repair_known_agent_cleanup_sessions():
    """延迟导入一次性修复，确保 worker 存活检查先于任何数据访问。"""

    from scripts.repair_agent_cleanup_sessions_20260829 import (
        repair_agent_cleanup_sessions_20260829,
    )

    return repair_agent_cleanup_sessions_20260829()


def main(argv=None):
    args = _parse_args(argv)
    if not args.confirm_celery_stopped:
        raise SystemExit(
            "拒绝恢复：请先停止全部 Celery worker，再传入 "
            "--confirm-celery-stopped。"
        )

    try:
        local_workers = _local_numoj_celery_processes()
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"拒绝恢复：无法检查本机 Celery 进程：{exc}") from exc
    if local_workers:
        details = "\n".join(f"  {line}" for line in local_workers)
        raise SystemExit(f"拒绝恢复：检测到本机 Celery worker 仍在运行：\n{details}")

    # 延迟导入，确保在本机进程检查通过前不创建应用对象或连接 broker。
    from oj import celery, recover_pending_after_all_workers_stopped

    try:
        remote_workers = celery.control.ping(timeout=1.5) or []
    except Exception as exc:
        raise SystemExit(f"拒绝恢复：无法确认 Celery worker 状态：{exc}") from exc
    if remote_workers:
        names = ", ".join(
            next(iter(reply), "unknown")
            for reply in remote_workers
            if isinstance(reply, dict)
        ) or "unknown"
        raise SystemExit(f"拒绝恢复：仍有 Celery worker 响应 ping：{names}")

    repaired_agent_sessions = _repair_known_agent_cleanup_sessions()
    recover_pending_after_all_workers_stopped()
    print(
        f"指定 Agent 清理异常会话已修复 {repaired_agent_sessions} 个；"
        "未完成任务恢复与后台调度链重建已完成。"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
