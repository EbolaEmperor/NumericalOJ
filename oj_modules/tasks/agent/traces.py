#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Problem Agent 的任务级轨迹目录与 Reverse Judge 同步适配。"""

from __future__ import annotations

from pathlib import Path
import shutil
import stat

from oj_modules.problems.agent_runs import agent_run_trace_dir
from oj_modules.ranking.reverse_judge.trace_sync import (
    sync_claude_project_jsonl,
    sync_pi_agent_sessions,
    sync_stdout_jsonl,
)


AGENT_TRACE_SYNC_INTERVAL_SECONDS = 2.0
_CLAUDE_SESSION_DIR = "/workspace/.runtime/home/.claude/projects/-workspace"
_PI_SESSION_DIR = "/workspace/.runtime/pi/agent/sessions"


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
):
    """使用 Reverse Judge 的同步实现发布当前 harness 轨迹。"""

    normalized = str(harness or "").strip().lower()
    trace_dir = str(Path(trace_dir))
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
    if normalized == "opencode":
        return sync_stdout_jsonl(
            stdout_path,
            trace_dir,
            "opencode_agent_judge.jsonl",
            secrets=secrets,
        )
    return sync_stdout_jsonl(
        stdout_path,
        trace_dir,
        "codex_reverse_solve.jsonl",
        secrets=secrets,
    )


__all__ = [
    "AGENT_TRACE_SYNC_INTERVAL_SECONDS",
    "ensure_agent_trace_dir",
    "prepare_agent_trace_dir",
    "sync_agent_trace",
]
