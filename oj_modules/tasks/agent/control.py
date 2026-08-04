#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent 任务的持久化终止与运行时清理。"""

from __future__ import annotations

import subprocess

from oj_modules.problems.agent_runs import (
    agent_run_container_name,
    normalize_agent_task_id,
)
from oj_modules.tasks.agent.shared import cancel_agent_run


def _force_remove_agent_container(task_id):
    container_name = agent_run_container_name(task_id)
    last_error = ""
    for _attempt in range(2):
        try:
            completed = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:
            last_error = str(exc)
            continue
        detail = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
        if completed.returncode == 0 or "no such container" in detail.lower():
            return None
        last_error = detail or f"docker rm exited {completed.returncode}"
    return f"强制清理 Agent 容器失败：{last_error[:500]}"


def build_agent_run_terminator(celery_app):
    """构造供 HTTP 适配层注入的任务终止操作。"""

    def terminate_agent_run(task_id):
        normalized_task_id = normalize_agent_task_id(task_id)
        # 持久标记必须先于 Celery revoke 和容器清理。即使 worker 被 late-ack
        # 重投，任务入场 guard 也会据此直接退出。
        result = cancel_agent_run(normalized_task_id)
        if not result.get("exists") or not result.get("canceled"):
            result["errors"] = []
            return result

        errors = []
        try:
            celery_app.control.revoke(
                normalized_task_id,
                terminate=True,
                signal="SIGTERM",
            )
        except Exception as exc:
            errors.append(f"撤销 Celery 任务失败：{str(exc)[:500]}")

        container_error = _force_remove_agent_container(normalized_task_id)
        if container_error:
            errors.append(container_error)
        result["errors"] = errors
        return result

    return terminate_agent_run


__all__ = ["build_agent_run_terminator"]
