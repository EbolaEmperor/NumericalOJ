#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent 任务的持久化终止与运行时清理。"""

from __future__ import annotations

import subprocess
import time

from backend.oj_modules.problems.agent_runs import (
    agent_run_container_name,
    normalize_agent_task_id,
)
from backend.oj_modules.tasks.agent.shared import cancel_agent_run


_PROTOCOL_INTERRUPT_GRACE_SECONDS = 10.0
_PROTOCOL_INTERRUPT_POLL_SECONDS = 0.25


def _harbor_runtime_for_task(task_id):
    from backend.oj_modules.agents.sessions import (
        get_agent_session_by_task_id, get_agent_session_runtime_config,
    )

    session = get_agent_session_by_task_id(task_id)
    if not session or session.get("judge_kind") != "reverse_answer":
        return None
    return get_agent_session_runtime_config(session["session_id"], task_id).get("harbor_runtime")


def _project_session_cleanup_status(
    task_id,
    status,
    message,
    *,
    native_session_id="",
    cleanup_confirmed=False,
):
    from backend.oj_modules.agents.sessions import (
        get_agent_session_by_task_id,
        sync_agent_session_state,
    )

    session = get_agent_session_by_task_id(task_id)
    if not isinstance(session, dict) or session.get("is_legacy"):
        return False
    options = {"cleanup_confirmed": True} if cleanup_confirmed else {}
    return sync_agent_session_state({
        "task_id": task_id,
        "session_id": session.get("session_id"),
        "status": status,
        "message": message,
        "native_session_id": native_session_id,
        "_preserve_conclusion": True,
    }, **options)


def _cleanup_retry_target(task_id, state):
    """只为当前 Harbor 清理失败轮次修复终态投影。"""
    terminal = {
        "completed": "Completed", "passed": "Completed",
        "failed": "Failed", "error": "Failed",
        "canceled": "Canceled", "cancelled": "Canceled",
        "cleanupfailed": "Canceled", "cleanup_failed": "Canceled",
    }.get(str((state or {}).get("status") or "").strip().lower())
    if terminal is None:
        return None
    from backend.oj_modules.agents.sessions import get_agent_session_by_task_id

    session = get_agent_session_by_task_id(task_id)
    if (not session or session.get("is_legacy")
            or session.get("current_task_id") != task_id
            or str(session.get("status") or "").strip().lower() not in {"cleanupfailed", "cleanup_failed"}
            or session.get("judge_kind") != "reverse_answer"
            or not _harbor_runtime_for_task(task_id)):
        return None
    return terminal


def _read_native_session_id_for_task(task_id):
    """在容器移除后读取 CLI 已经原子落盘的恢复点。"""

    from backend.oj_modules.agents.sessions import get_agent_session_by_task_id
    from backend.oj_modules.tasks.agent.harness_runtime import read_agent_native_session_id

    session = get_agent_session_by_task_id(task_id)
    if not isinstance(session, dict) or session.get("is_legacy"):
        return ""
    if session.get("judge_kind") == "reverse_answer":
        from backend.oj_modules.agents.sessions import get_agent_session_runtime_config

        if get_agent_session_runtime_config(session["session_id"], task_id).get("harbor_runtime"):
            return str(session.get("native_session_id") or "")
    return read_agent_native_session_id(
        session.get("session_id"),
        session.get("harness"),
    )


def _force_remove_agent_container(task_id):
    from backend.oj_modules.tasks.agent.harness_runtime import _remove_agent_container

    try:
        harbor_runtime = _harbor_runtime_for_task(task_id)
        if harbor_runtime:
            from backend.oj_modules.integrations.harbor_runtime import stop_harbor_trial

            stop_harbor_trial(harbor_runtime)
            return None
        container_name = agent_run_container_name(task_id)
        _remove_agent_container(container_name)
    except Exception as exc:
        return f"强制清理 Agent 容器失败：{str(exc)[:500]}"
    return None


def _agent_container_running(task_id):
    """探测任务容器；Docker 状态未知时返回 None 并进入强制兜底。"""

    try:
        harbor_runtime = _harbor_runtime_for_task(task_id)
        if harbor_runtime:
            from backend.oj_modules.integrations.harbor_runtime import harbor_trial_running

            return harbor_trial_running(harbor_runtime)
        container_name = agent_run_container_name(task_id)
        completed = subprocess.run(
            [
                "docker",
                "container",
                "inspect",
                "--format",
                "{{.State.Running}}",
                container_name,
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    detail = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
    if completed.returncode != 0:
        if "no such" in detail.lower():
            return False
        return None
    normalized = str(completed.stdout or "").strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _wait_for_protocol_interrupt(task_id):
    """给活动 worker 时间读取持久取消标记并发送 Harness interrupt。"""

    running = _agent_container_running(task_id)
    if running is False:
        return True
    if running is None:
        return False
    deadline = time.monotonic() + _PROTOCOL_INTERRUPT_GRACE_SECONDS
    while time.monotonic() < deadline:
        time.sleep(_PROTOCOL_INTERRUPT_POLL_SECONDS)
        running = _agent_container_running(task_id)
        if running is False:
            return True
        if running is None:
            return False
    return False


def build_agent_run_terminator(celery_app):
    """构造供 HTTP 适配层注入的任务终止操作。"""

    def terminate_agent_run(task_id):
        normalized_task_id = normalize_agent_task_id(task_id)
        # 持久标记必须先于 Celery revoke 和容器清理。即使 worker 被 late-ack
        # 重投，任务入场 guard 也会据此直接退出。
        result = cancel_agent_run(normalized_task_id)
        retry_target = (_cleanup_retry_target(normalized_task_id, result.get("state"))
                        if result.get("exists") else None)
        if not result.get("exists") or not result.get("canceled") and not retry_target:
            result["errors"] = []
            return result

        errors = []
        if retry_target:
            container_error = _force_remove_agent_container(normalized_task_id)
            if container_error:
                errors.append(container_error)
            elif _agent_container_running(normalized_task_id) is not False:
                errors.append("Harbor 执行进程或容器停止状态尚未确认")
        elif not _wait_for_protocol_interrupt(normalized_task_id):
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
        projection_status = "CleanupFailed" if errors else retry_target or "Canceled"
        projection_message = (
            "；".join(errors)
            if errors
            else str(
                (result.get("state") or {}).get("message")
                or "任务已被手动终止"
            )
        )
        try:
            options = {"cleanup_confirmed": True} if retry_target and not errors else {}
            projected = _project_session_cleanup_status(
                normalized_task_id,
                projection_status,
                projection_message,
                native_session_id=native_session_id,
                **options,
            )
            if retry_target and not errors and not projected:
                errors.append("Agent 清理已完成，但当前轮次终态投影尚未确认")
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
                else projection_status.lower()
            ),
            native_session_id=native_session_id,
        )
        result["state"] = state
        result["errors"] = errors
        return result

    return terminate_agent_run


__all__ = ["build_agent_run_terminator"]
