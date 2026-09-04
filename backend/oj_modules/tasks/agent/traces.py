#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Problem Agent 的任务级轨迹目录与 Reverse Judge 同步适配。"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import tempfile

from backend.oj_modules.problems.agent_runs import agent_run_trace_dir
from backend.oj_modules.ranking.reverse_judge.trace_sync import (
    sync_claude_project_jsonl,
    sync_pi_agent_sessions,
)


AGENT_TRACE_SYNC_INTERVAL_SECONDS = 2.0
_CLAUDE_SESSION_DIR = "/workspace/.runtime/home/.claude/projects/-workspace"
_PI_SESSION_DIR = "/workspace/.runtime/pi/agent/sessions"
CANONICAL_AGENT_TRACE_FILENAME = "numoj_trace_v1.jsonl"
CANONICAL_AGENT_TRACE_MAX_BYTES = 64 * 1024 * 1024


def _sync_canonical_agent_journal(source_path, trace_dir):
    """原子发布宿主已过滤、已脱敏的 append-only 规范 journal。"""

    source_path = Path(source_path)
    try:
        before = source_path.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > CANONICAL_AGENT_TRACE_MAX_BYTES
    ):
        return False
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source_path, flags)
    temporary = ""
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size < before.st_size
        ):
            return False
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination = trace_dir / CANONICAL_AGENT_TRACE_FILENAME
        temp_descriptor, temporary = tempfile.mkstemp(
            dir=trace_dir,
            prefix=f".{CANONICAL_AGENT_TRACE_FILENAME}.",
            suffix=".tmp",
        )
        remaining = int(before.st_size)
        with os.fdopen(temp_descriptor, "wb") as target:
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    return False
                target.write(chunk)
                remaining -= len(chunk)
        os.replace(temporary, destination)
        temporary = ""
        return True
    finally:
        os.close(descriptor)
        if temporary:
            try:
                os.remove(temporary)
            except OSError:
                pass


def prepare_agent_trace_dir(task_id):
    """清空并重建一次任务的持久轨迹目录。"""

    trace_dir = agent_run_trace_dir(task_id)
    trace_dir.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = trace_dir.lstat()
    except FileNotFoundError:
        current = None
    if current is not None:
        if stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode):
            shutil.rmtree(trace_dir)
        else:
            trace_dir.unlink()
    trace_dir.mkdir(mode=0o700)
    return trace_dir


def ensure_agent_trace_dir(task_id):
    trace_dir = agent_run_trace_dir(task_id)
    trace_dir.parent.mkdir(parents=True, exist_ok=True)
    trace_dir.mkdir(mode=0o700, exist_ok=True)
    return trace_dir


def sync_agent_trace(
    container_name,
    trace_dir,
    harness,
    stdout_path,
    *,
    secrets=(),
    canonical=False,
):
    """使用 Reverse Judge 的同步实现发布当前 harness 轨迹。"""

    normalized = str(harness or "").strip().lower()
    trace_dir = str(Path(trace_dir))
    if canonical:
        # 交互 adapter 已把各 CLI 的通知归一化为 NumOJ v1 journal；宿主
        # 只会把成功 steer 回执转换为不含 Prompt 的时间线锚点，其它
        # 控制帧均不入盘。该文件不受 stdout 结果尾部的 8 MiB 截断
        # 影响，因此早期 usage 也会保留。
        return _sync_canonical_agent_journal(stdout_path, trace_dir)
    if normalized == "claude_code":
        return sync_claude_project_jsonl(
            container_name,
            trace_dir,
            container_project_dir=_CLAUDE_SESSION_DIR,
            secrets=secrets,
        )
    if normalized == "pi":
        return sync_pi_agent_sessions(
            container_name,
            trace_dir,
            container_session_dir=_PI_SESSION_DIR,
            runtime_user="",
            secrets=secrets,
        )
    return False


__all__ = [
    "AGENT_TRACE_SYNC_INTERVAL_SECONDS",
    "CANONICAL_AGENT_TRACE_FILENAME",
    "CANONICAL_AGENT_TRACE_MAX_BYTES",
    "ensure_agent_trace_dir",
    "prepare_agent_trace_dir",
    "sync_agent_trace",
]
