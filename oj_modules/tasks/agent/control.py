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


def _project_session_cleanup_status(
    task_id,
    status,
    message,
    *,
    native_session_id="",
):
    from oj_modules.agents.sessions import (
        get_agent_session_by_task_id,
        sync_agent_session_state,
    )

    session = get_agent_session_by_task_id(task_id)
    if not isinstance(session, dict) or session.get("is_legacy"):
        return False
    return sync_agent_session_state({
        "task_id": task_id,
        "session_id": session.get("session_id"),
        "status": status,
        "message": message,
        "native_session_id": native_session_id,
        "_preserve_conclusion": True,
    })


def _read_native_session_id_for_task(task_id):
    """在容器移除后读取 CLI 已经原子落盘的恢复点。"""

    from oj_modules.agents.sessions import get_agent_session_by_task_id
    from oj_modules.tasks.agent.harness_runtime import read_agent_native_session_id

    session = get_agent_session_by_task_id(task_id)
    if not isinstance(session, dict) or session.get("is_legacy"):
        return ""
    return read_agent_native_session_id(
        session.get("session_id"),
        session.get("harness"),
    )


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
        native_session_id = ""
        try:
            native_session_id = _read_native_session_id_for_task(
                normalized_task_id
            )
        except Exception as exc:
            errors.append(f"读取 Agent 原生恢复点失败：{str(exc)[:500]}")
        projection_status = "CleanupFailed" if errors else "Canceled"
        projection_message = (
            "；".join(errors)
            if errors
            else str(
                (result.get("state") or {}).get("message")
                or "任务已由管理员终止"
            )
        )
        try:
            _project_session_cleanup_status(
                normalized_task_id,
                projection_status,
                projection_message,
                native_session_id=native_session_id,
            )
        except Exception as exc:
            errors.append(f"更新 Agent 会话清理状态失败：{str(exc)[:500]}")
        if errors:
            projection_status = "CleanupFailed"
            projection_message = "；".join(errors)
        state = dict(result.get("state") or {})
        state.update(
            status=projection_status,
            message=projection_message,
            stage="finished",
            harness_status=(
                "cleanup_failed"
                if projection_status == "CleanupFailed"
                else "canceled"
            ),
            native_session_id=native_session_id,
        )
        result["state"] = state
        result["errors"] = errors
        return result

    return terminate_agent_run


__all__ = ["build_agent_run_terminator"]
