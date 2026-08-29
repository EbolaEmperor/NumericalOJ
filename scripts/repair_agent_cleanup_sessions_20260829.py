#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""一次性修复 2026-08-29 被密钥代理关闭竞态误报阻断的两个 Agent 会话。

本模块只能由 ``recover_pending_tasks.py`` 在确认全部 Celery worker 停止后调用。
它不提供独立 CLI，避免绕过停机恢复入口的本机进程与远端 worker 检查。
"""

from dataclasses import dataclass
import subprocess

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.infrastructure.redis import create_text_redis_client
from oj_modules.problems.agent_runs import agent_run_container_name


_FAILED_STATUS = "CleanupFailed"
_COMPLETED_STATUS = "Completed"
_FAILED_MESSAGE = "外部服务密钥代理未能彻底关闭"
_COMPLETED_MESSAGE = "Agent 已完成本轮任务"


@dataclass(frozen=True, slots=True)
class _RepairTarget:
    session_id: str
    task_id: str
    native_session_id: str


_TARGETS = (
    _RepairTarget(
        session_id="msgmtdt1drlr9cqglwfntq",
        task_id="msgmtdt1drlr9cqglwfntq",
        native_session_id="9e5e047b-79fb-4e30-a7fc-3f71e7cec2e3",
    ),
    _RepairTarget(
        session_id="msgmtdsecbop9c8lwfwqg",
        task_id="msgmtdsecbop9c8lwfwqg",
        native_session_id="0c271f38-f1ae-4853-b51f-67e24e483dd0",
    ),
)


def _assert_target_containers_absent():
    for target in _TARGETS:
        container_name = agent_run_container_name(target.task_id)
        try:
            completed = subprocess.run(
                ["docker", "container", "inspect", container_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：无法确认 Agent 容器不存在"
            ) from exc
        if completed.returncode == 0:
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：Agent 容器仍然存在"
            )
        detail = f"{completed.stdout or ''}\n{completed.stderr or ''}".lower()
        if "no such container" not in detail and "no such object" not in detail:
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：Docker 未能确认容器不存在"
            )


def _load_locked_target(cursor, target):
    cursor.execute(
        """
        SELECT s.session_id,
               s.current_task_id,
               s.requested_by AS session_requested_by,
               s.native_session_id,
               s.status AS session_status,
               s.message AS session_message,
               s.turn_count,
               s.queue_paused,
               s.queue_pause_reason,
               s.fresh_native_session_pending,
               r.requested_by AS run_requested_by,
               r.status AS run_status,
               r.message AS run_message,
               t.turn_index,
               t.status AS turn_status,
               t.conclusion
        FROM agent_sessions AS s
        JOIN agent_task_runs AS r
          ON r.task_id=s.current_task_id
        JOIN agent_session_turns AS t
          ON t.session_id=s.session_id
         AND t.task_id=s.current_task_id
        WHERE s.session_id=%s
        FOR UPDATE
        """,
        (target.session_id,),
    )
    rows = cursor.fetchall()
    if len(rows) != 1:
        raise RuntimeError(
            f"拒绝修复 {target.session_id}：预期恰好一个会话/任务/轮次绑定，"
            f"实际为 {len(rows)} 个"
        )
    cursor.execute(
        """
        SELECT message_id, status
        FROM agent_session_messages
        WHERE session_id=%s
          AND status IN ('queued', 'dispatching', 'unknown')
        FOR UPDATE
        """,
        (target.session_id,),
    )
    pending_messages = cursor.fetchall()
    if pending_messages:
        raise RuntimeError(
            f"拒绝修复 {target.session_id}：仍有未收束的排队或派发消息"
        )
    return rows[0]


def _classify_target(row, target):
    expected_identity = {
        "session_id": target.session_id,
        "current_task_id": target.task_id,
        "session_requested_by": "admin",
        "run_requested_by": "admin",
        "native_session_id": target.native_session_id,
        "turn_count": 1,
        "turn_index": 1,
        "fresh_native_session_pending": 0,
    }
    for field, expected in expected_identity.items():
        if row.get(field) != expected:
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：字段 {field} 与预期不符"
            )
    if not str(row.get("conclusion") or "").strip():
        raise RuntimeError(
            f"拒绝修复 {target.session_id}：任务结论为空"
        )

    statuses = (
        row.get("session_status"),
        row.get("run_status"),
        row.get("turn_status"),
    )
    if statuses == (_FAILED_STATUS,) * 3:
        if (
            row.get("session_message") != _FAILED_MESSAGE
            or row.get("run_message") != _FAILED_MESSAGE
            or row.get("queue_paused") != 1
            or row.get("queue_pause_reason") != _FAILED_MESSAGE
        ):
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：清理失败状态字段与预期不符"
            )
        return "repair"
    if statuses == (_COMPLETED_STATUS,) * 3:
        if (
            row.get("session_message") != _COMPLETED_MESSAGE
            or row.get("run_message") != _COMPLETED_MESSAGE
            or row.get("queue_paused") != 0
            or row.get("queue_pause_reason") is not None
        ):
            raise RuntimeError(
                f"拒绝修复 {target.session_id}：已完成状态字段与预期不符"
            )
        return "complete"
    raise RuntimeError(
        f"拒绝修复 {target.session_id}：三层终态不一致或不再是目标状态"
    )


def _repair_target(cursor, target):
    updates = (
        (
            """
            UPDATE agent_task_runs
            SET status=%s, message=%s
            WHERE task_id=%s AND status=%s AND message=%s
            """,
            (
                _COMPLETED_STATUS,
                _COMPLETED_MESSAGE,
                target.task_id,
                _FAILED_STATUS,
                _FAILED_MESSAGE,
            ),
        ),
        (
            """
            UPDATE agent_session_turns
            SET status=%s
            WHERE session_id=%s AND task_id=%s AND turn_index=1 AND status=%s
            """,
            (
                _COMPLETED_STATUS,
                target.session_id,
                target.task_id,
                _FAILED_STATUS,
            ),
        ),
        (
            """
            UPDATE agent_sessions
            SET status=%s,
                message=%s,
                queue_paused=0,
                queue_pause_reason=NULL
            WHERE session_id=%s
              AND current_task_id=%s
              AND status=%s
              AND message=%s
              AND queue_paused=1
              AND queue_pause_reason=%s
            """,
            (
                _COMPLETED_STATUS,
                _COMPLETED_MESSAGE,
                target.session_id,
                target.task_id,
                _FAILED_STATUS,
                _FAILED_MESSAGE,
                _FAILED_MESSAGE,
            ),
        ),
    )
    for statement, parameters in updates:
        cursor.execute(statement, parameters)
        if cursor.rowcount != 1:
            raise RuntimeError(
                f"修复 {target.session_id} 时更新行数异常：{cursor.rowcount}"
            )


def repair_agent_cleanup_sessions_20260829():
    """修复目标会话并返回本次实际更新的会话数量。"""

    _assert_target_containers_absent()
    redis_client = create_text_redis_client()
    redis_client.ping()

    conn = get_db_connection()
    repaired = 0
    try:
        with conn.cursor() as cursor:
            for target in _TARGETS:
                row = _load_locked_target(cursor, target)
                if _classify_target(row, target) == "repair":
                    _repair_target(cursor, target)
                    repaired += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    cache_keys = []
    for target in _TARGETS:
        cache_keys.extend((
            f"agent_run:{target.task_id}",
            f"agent_run_cancel:{target.task_id}",
        ))
    redis_client.delete(*cache_keys)
    return repaired


__all__ = ["repair_agent_cleanup_sessions_20260829"]
