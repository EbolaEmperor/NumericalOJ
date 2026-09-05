"""通用 Agent 会话、轮次与旧任务兼容查询。"""

from __future__ import annotations

import json
import re

from backend.oj_modules.agents.messages import (
    AgentSessionMessageConflictError,
    AgentSessionMessageError,
    AgentSessionMessageNotFoundError,
    cancel_queued_agent_session_message,
    claim_next_agent_session_message,
    claim_next_agent_session_steer,
    continue_agent_session_queue,
    enqueue_agent_session_message,
    finish_agent_session_message_delivery,
    get_agent_session_message,
    get_agent_session_queue_snapshot,
    insert_turn_message_in_transaction,
    list_agent_session_messages,
    list_agent_session_queue_recovery_candidates,
    mark_agent_session_message_broker_enqueued,
    mark_agent_session_steers_unknown_for_task,
    normalize_agent_message_id,
    pause_agent_session_queue,
    reorder_queued_agent_session_messages,
    release_agent_session_message_dispatch_attempt,
    set_agent_session_queue_paused,
    steer_queued_agent_session_message,
    sync_agent_message_state_in_transaction,
    update_queued_agent_session_message,
)
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.agent_launch import (
    normalize_agent_reasoning_effort,
    normalize_agent_task_kind,
    normalize_launch_harness,
)


AGENT_EMPTY_CONCLUSION_MESSAGE = "Agent 已结束，但没有返回可展示的结论"


_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_TERMINAL_STATUSES = frozenset({"completed", "failed", "canceled", "cancelled"})
_ACCESS_ROLES = frozenset({"user", "admin"})


class AgentSessionError(RuntimeError):
    """Agent 会话操作失败。"""


class AgentSessionNotFoundError(AgentSessionError):
    """会话不存在。"""


class AgentSessionBusyError(AgentSessionError):
    """上一轮仍在运行，暂时不能续发。"""


def normalize_agent_session_id(value):
    normalized = str(value or "").strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError("Agent session_id 无效")
    return normalized


def normalize_agent_access_role(value):
    normalized = str(value or "").strip().lower()
    if normalized not in _ACCESS_ROLES:
        raise ValueError("Agent 执行身份无效")
    return normalized


def agent_status_is_terminal(value):
    return str(value or "").strip().lower() in _TERMINAL_STATUSES


def _json_text(value, fallback):
    try:
        return json.dumps(value if value is not None else fallback, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(fallback, ensure_ascii=False)


def _json_value(value, fallback):
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed is not None else fallback


def _format_time(value):
    if value is None:
        return None
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


def _normalize_optional_identifier(
    value,
    *,
    max_length,
    label,
    safe_id=False,
):
    normalized = str(value or "").strip()
    if (
        len(normalized) > max_length
        or (
            normalized
            and safe_id
            and (
                not _ID_RE.fullmatch(normalized)
                or normalized in {".", ".."}
            )
        )
    ):
        raise ValueError(f"{label} 无效")
    return normalized


def _session_from_row(row):
    if not row:
        return None
    endpoint_source = str(row.get("endpoint_source") or "global")
    return {
        "session_id": row.get("session_id"),
        "current_task_id": row.get("current_task_id"),
        "title": str(row.get("title") or "").strip(),
        "task_kind": str(row.get("task_kind") or "custom"),
        "category": "judge" if row.get("task_kind") == "judge" else "agent",
        "judge_kind": row.get("judge_kind"),
        "submission_id": row.get("submission_id"),
        "attempt_id": row.get("attempt_id"),
        "competition_id": row.get("competition_id"),
        "problem_id": row.get("problem_id"),
        "problem_title": row.get("problem_title"),
        "requested_by": row.get("requested_by"),
        "access_role": str(row.get("access_role") or "user"),
        "harness": row.get("harness"),
        "reasoning_effort": str(
            row.get("reasoning_effort") or "default"
        ).strip().lower(),
        "endpoint_source": endpoint_source,
        "uses_personal_endpoint": endpoint_source == "user",
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": row.get("endpoint_model"),
        "native_session_id": str(row.get("native_session_id") or "").strip(),
        "status": str(row.get("status") or "Pending"),
        "message": row.get("message"),
        "turn_count": max(1, int(row.get("turn_count") or 1)),
        "queue_paused": bool(row.get("queue_paused")),
        "queue_pause_reason": str(row.get("queue_pause_reason") or ""),
        "fresh_native_session_pending": bool(
            row.get("fresh_native_session_pending")
        ),
        "created_at": _format_time(row.get("created_at")),
        "updated_at": _format_time(row.get("updated_at")),
        "is_legacy": bool(row.get("is_legacy")),
    }


def _turn_from_row(row):
    attachments = _json_value(row.get("attachments_json"), [])
    return {
        "task_id": row.get("task_id"),
        "turn_index": int(row.get("turn_index") or 1),
        "user_message": str(row.get("user_message") or ""),
        "attachments": attachments if isinstance(attachments, list) else [],
        "base_runtime_checkpoint_id": str(
            row.get("base_runtime_checkpoint_id") or ""
        ).strip(),
        "base_native_session_id": str(
            row.get("base_native_session_id") or ""
        ).strip(),
        "retry_of_task_id": str(row.get("retry_of_task_id") or "").strip(),
        "superseded_by_task_id": str(
            row.get("superseded_by_task_id") or ""
        ).strip(),
        "superseded_at": _format_time(row.get("superseded_at")),
        "harness": row.get("harness"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_model": row.get("endpoint_model"),
        "status": str(row.get("status") or "Pending"),
        "conclusion": str(row.get("conclusion") or ""),
        "created_at": _format_time(row.get("created_at")),
        "updated_at": _format_time(row.get("updated_at")),
    }


def _turn_message_response(
    *,
    session_id,
    task_id,
    created_by,
    user_message,
    attachments,
):
    """用事务内已知值构造新 turn 的 outbox 响应，避免提交后再读库。"""

    return {
        "message_id": task_id,
        "session_id": session_id,
        "created_by": str(created_by or ""),
        "user_message": user_message,
        "attachments": attachments if isinstance(attachments, list) else [],
        "delivery_mode": "turn",
        "status": "dispatching",
        "target_task_id": task_id,
        "final_task_id": task_id,
        "queue_position": 0,
        "error_message": "",
        "delivered_at": None,
        "created_at": None,
        "updated_at": None,
    }


def create_agent_session(
    *,
    session_id,
    task_id,
    requested_by,
    harness,
    reasoning_effort="default",
    endpoint_id,
    endpoint_revision,
    endpoint_model,
    endpoint_source="global",
    user_message,
    attachments=None,
    base_runtime_checkpoint_id="",
    base_native_session_id="",
    dispatch_payload=None,
    task_kind="custom",
    access_role="user",
    problem_id=None,
    problem_title=None,
    title="",
    judge_kind=None,
    submission_id=None,
    attempt_id=None,
    competition_id=None,
    runtime_config=None,
):
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    access_role = normalize_agent_access_role(access_role)
    task_kind = normalize_agent_task_kind(task_kind)
    harness = normalize_launch_harness(harness)
    reasoning_effort = normalize_agent_reasoning_effort(
        reasoning_effort,
        harness,
    )
    endpoint_source = str(endpoint_source or "global").strip().lower()
    if endpoint_source not in {"global", "user"}:
        raise ValueError("Agent LLM 节点来源无效")
    if isinstance(endpoint_revision, bool):
        raise ValueError("Agent LLM 节点版本无效")
    try:
        endpoint_revision = int(endpoint_revision)
    except (TypeError, ValueError):
        raise ValueError("Agent LLM 节点版本无效") from None
    if endpoint_revision <= 0:
        raise ValueError("Agent LLM 节点版本无效")
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")
    base_runtime_checkpoint_id = _normalize_optional_identifier(
        base_runtime_checkpoint_id,
        max_length=64,
        label="Agent 运行时 checkpoint_id",
        safe_id=True,
    )
    base_native_session_id = _normalize_optional_identifier(
        base_native_session_id,
        max_length=128,
        label="Agent 原生会话基线",
    )

    if task_kind == "judge":
        if judge_kind not in {"agent_judge", "reverse_quality", "reverse_answer"}:
            raise ValueError("Judge 会话类别无效")
        if access_role != "user":
            raise ValueError("Judge 会话只能使用 user 身份")
        historical = isinstance(runtime_config, dict) and runtime_config.get("historical_import") is True
        if not submission_id or not competition_id or (not historical and not str(attempt_id or "").strip()):
            raise ValueError("Judge 会话必须关联评测提交和轮次")
    elif judge_kind or submission_id or attempt_id or competition_id or runtime_config:
        raise ValueError("普通 Agent 会话不能指定 Judge 参数")

    session = {
        "session_id": session_id,
        "current_task_id": task_id,
        "title": str(title or "").strip()[:64],
        "task_kind": str(task_kind or "custom").strip().lower()[:32],
        "category": "judge" if task_kind == "judge" else "agent",
        "judge_kind": judge_kind,
        "submission_id": submission_id,
        "attempt_id": attempt_id,
        "competition_id": competition_id,
        "problem_id": problem_id,
        "problem_title": (
            str(problem_title or "")[:255]
            if problem_title is not None
            else None
        ),
        "requested_by": str(requested_by or "").strip()[:50],
        "access_role": access_role,
        "harness": harness,
        "reasoning_effort": reasoning_effort,
        "endpoint_source": endpoint_source,
        "uses_personal_endpoint": endpoint_source == "user",
        "endpoint_id": endpoint_id,
        "endpoint_revision": endpoint_revision,
        "endpoint_model": str(endpoint_model or "").strip()[:255],
        "native_session_id": "",
        "status": "Pending",
        "message": "任务排队中",
        "turn_count": 1,
        "queue_paused": False,
        "queue_pause_reason": "",
        "fresh_native_session_pending": False,
        "created_at": None,
        "updated_at": None,
        "is_legacy": False,
    }

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_sessions (
                    session_id, current_task_id, title, task_kind,
                    problem_id, problem_title, requested_by, access_role,
                    harness, reasoning_effort, endpoint_source, endpoint_id,
                    endpoint_revision, endpoint_model,
                    judge_kind, submission_id, attempt_id, competition_id, runtime_config_json,
                    status, message,
                    turn_count
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, 'Pending', '任务排队中',
                    1
                )
                """,
                (
                    session_id,
                    task_id,
                    session["title"] or None,
                    session["task_kind"],
                    session["problem_id"],
                    session["problem_title"],
                    session["requested_by"],
                    access_role,
                    session["harness"],
                    session["reasoning_effort"],
                    session["endpoint_source"],
                    endpoint_id,
                    session["endpoint_revision"],
                    session["endpoint_model"],
                    judge_kind, submission_id, attempt_id, competition_id,
                    _json_text(runtime_config, {}) if runtime_config else None,
                ),
            )
            cursor.execute(
                """
                INSERT INTO agent_session_turns (
                    session_id, task_id, turn_index, user_message,
                    attachments_json, base_runtime_checkpoint_id,
                    base_native_session_id, status
                ) VALUES (%s, %s, 1, %s, %s, NULLIF(%s, ''),
                          NULLIF(%s, ''), 'Pending')
                """,
                (
                    session_id,
                    task_id,
                    message,
                    _json_text(attachments, []),
                    base_runtime_checkpoint_id,
                    base_native_session_id,
                ),
            )
            insert_turn_message_in_transaction(
                cursor,
                session_id=session_id,
                task_id=task_id,
                created_by=session["requested_by"],
                user_message=message,
                attachments=attachments,
                dispatch_payload=dispatch_payload,
                queue_position=1024,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    # INSERT 已经提交后不能再用一次额外查询决定本操作是否“成功”；否则瞬时
    # 读取故障会让调用方误以为创建失败，却在库中遗留不可恢复的 Pending 会话。
    return session


def begin_agent_session_turn(
    session_id,
    *,
    task_id,
    user_message,
    attachments=None,
    base_runtime_checkpoint_id="",
    base_native_session_id="",
    internal_judge=False,
    dispatch_payload=None,
):
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")
    base_runtime_checkpoint_id = _normalize_optional_identifier(
        base_runtime_checkpoint_id,
        max_length=64,
        label="Agent 运行时 checkpoint_id",
        safe_id=True,
    )
    base_native_session_id = _normalize_optional_identifier(
        base_native_session_id,
        max_length=128,
        label="Agent 原生会话基线",
    )

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.status, s.turn_count, s.task_kind, s.problem_id,
                       s.requested_by, s.access_role, s.harness,
                       s.reasoning_effort,
                       s.endpoint_source, s.endpoint_id,
                       s.endpoint_revision, s.endpoint_model,
                       s.native_session_id,
                       previous.base_runtime_checkpoint_id AS
                           previous_base_runtime_checkpoint_id,
                       EXISTS(
                           SELECT 1
                           FROM agent_session_messages AS queued_message
                           WHERE queued_message.session_id=s.session_id
                             AND queued_message.delivery_mode='queue'
                             AND queued_message.status IN ('queued','dispatching')
                       ) AS has_pending_queue
                FROM agent_sessions AS s
                LEFT JOIN agent_session_turns AS previous
                  ON previous.session_id=s.session_id
                 AND previous.task_id=s.current_task_id
                WHERE s.session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionNotFoundError("Agent 会话不存在")
            if row.get("task_kind") == "judge" and not internal_judge:
                raise PermissionError("Judge 会话仅允许评测流程内部续聊")
            if not agent_status_is_terminal(row.get("status")):
                raise AgentSessionBusyError("上一轮 Agent 任务尚未结束")
            if bool(row.get("has_pending_queue")):
                raise AgentSessionBusyError("会话已有排队消息，请等待队列依次执行")
            frozen_native_session_id = str(
                row.get("native_session_id") or ""
            ).strip()
            if (
                base_native_session_id
                and base_native_session_id != frozen_native_session_id
            ):
                raise AgentSessionBusyError(
                    "Agent 原生会话基线已变化，请刷新后重试"
                )
            # 原生会话基线必须取自同一行锁内的权威值。参数仅用于让调用方
            # 声明其创建 checkpoint 时看到的值，并协助检测过期请求。
            base_native_session_id = frozen_native_session_id
            turn_index = max(1, int(row.get("turn_count") or 1)) + 1
            cursor.execute(
                """
                INSERT INTO agent_session_turns (
                    session_id, task_id, turn_index, user_message,
                    attachments_json, base_runtime_checkpoint_id,
                    base_native_session_id, status
                ) VALUES (%s, %s, %s, %s, %s, NULLIF(%s, ''),
                          NULLIF(%s, ''), 'Pending')
                """,
                (
                    session_id,
                    task_id,
                    turn_index,
                    message,
                    _json_text(attachments, []),
                    base_runtime_checkpoint_id,
                    base_native_session_id,
                ),
            )
            insert_turn_message_in_transaction(
                cursor,
                session_id=session_id,
                task_id=task_id,
                created_by=row.get("requested_by"),
                user_message=message,
                attachments=attachments,
                dispatch_payload=dispatch_payload,
            )
            cursor.execute(
                """
                UPDATE agent_sessions
                SET current_task_id=%s, status='Pending', message='任务排队中',
                    turn_count=%s, queue_paused=0, queue_pause_reason=NULL,
                    fresh_native_session_pending=0
                WHERE session_id=%s
                """,
                (task_id, turn_index, session_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "turn_index": turn_index,
        "task_kind": str(row.get("task_kind") or "custom"),
        "problem_id": row.get("problem_id"),
        "requested_by": row.get("requested_by"),
        "access_role": str(row.get("access_role") or "user"),
        "harness": row.get("harness"),
        "reasoning_effort": str(
            row.get("reasoning_effort") or "default"
        ).strip().lower(),
        "endpoint_source": str(row.get("endpoint_source") or "global"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": row.get("endpoint_model"),
        "native_session_id": base_native_session_id,
        "user_message": message,
        "attachments": attachments if isinstance(attachments, list) else [],
        "base_runtime_checkpoint_id": base_runtime_checkpoint_id,
        "previous_base_runtime_checkpoint_id": str(
            row.get("previous_base_runtime_checkpoint_id") or ""
        ).strip(),
        "base_native_session_id": base_native_session_id,
        "retry_of_task_id": "",
        "replaced_task_id": "",
        "agent_message": _turn_message_response(
            session_id=session_id,
            task_id=task_id,
            created_by=row.get("requested_by"),
            user_message=message,
            attachments=attachments,
        ),
    }


def begin_agent_session_retry(
    session_id,
    task_id,
    expected_task_id,
    fallback_base_checkpoint_id="",
):
    """在当前终态轮次的执行基线上创建一次新的物理重试。"""

    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    expected_task_id = normalize_agent_session_id(expected_task_id)
    if task_id == expected_task_id:
        raise ValueError("Agent 重试 task_id 不能与原轮次相同")
    fallback_base_checkpoint_id = _normalize_optional_identifier(
        fallback_base_checkpoint_id,
        max_length=64,
        label="Agent 运行时 checkpoint_id",
        safe_id=True,
    )

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT current_task_id, status, turn_count, task_kind,
                       problem_id, requested_by, access_role, harness,
                       reasoning_effort,
                       endpoint_source,
                       endpoint_id, endpoint_revision, endpoint_model,
                       native_session_id,
                       EXISTS(
                           SELECT 1
                           FROM agent_session_messages AS queued_message
                           WHERE queued_message.session_id=agent_sessions.session_id
                             AND queued_message.delivery_mode='queue'
                             AND queued_message.status IN ('queued','dispatching')
                       ) AS has_pending_queue
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionNotFoundError("Agent 会话不存在")
            if agent_session_is_judge(row):
                raise PermissionError("Judge 会话禁止人工重试")
            status = str(row.get("status") or "").strip().lower()
            if status in {"cleanupfailed", "cleanup_failed"}:
                raise AgentSessionBusyError(
                    "Agent 运行环境清理失败，暂时不能重试"
                )
            if not agent_status_is_terminal(status):
                raise AgentSessionBusyError("当前 Agent 任务尚未结束")
            current_task_id = str(row.get("current_task_id") or "").strip()
            if current_task_id != expected_task_id:
                raise AgentSessionBusyError("Agent 当前轮次已变化，请刷新后重试")
            if bool(row.get("has_pending_queue")):
                raise AgentSessionBusyError("会话已有排队消息，请等待队列依次执行")

            cursor.execute(
                """
                SELECT task_id, turn_index, user_message, attachments_json,
                       base_runtime_checkpoint_id, base_native_session_id,
                       superseded_by_task_id, superseded_at
                FROM agent_session_turns
                WHERE session_id=%s AND task_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id, expected_task_id),
            )
            source = cursor.fetchone()
            if not source:
                raise AgentSessionNotFoundError("Agent 当前轮次不存在")
            if (
                source.get("superseded_at") is not None
                or str(source.get("superseded_by_task_id") or "").strip()
            ):
                raise AgentSessionBusyError("Agent 当前轮次已被其它重试替代")

            try:
                base_runtime_checkpoint_id = _normalize_optional_identifier(
                    source.get("base_runtime_checkpoint_id"),
                    max_length=64,
                    label="Agent 运行时 checkpoint_id",
                    safe_id=True,
                )
                base_native_session_id = _normalize_optional_identifier(
                    source.get("base_native_session_id"),
                    max_length=128,
                    label="Agent 原生会话基线",
                )
            except ValueError:
                raise AgentSessionBusyError(
                    "待重试轮次缺少可恢复的运行时基线"
                ) from None
            source_turn_index = max(1, int(source.get("turn_index") or 1))
            if (
                str(row.get("task_kind") or "").strip().lower() == "testdata"
                and str(row.get("access_role") or "").strip().lower() == "user"
                and source_turn_index == 1
            ):
                # 升级前的造数据首轮把标准程序保存在 message 私有 payload，
                # 而非普通附件；重试无法按通用契约复原它。新版 admin 会话
                # 使用附件，不受这个迁移限制。
                raise AgentSessionBusyError("升级前造数据 Agent 的首轮不支持重试")
            if not base_runtime_checkpoint_id:
                if source_turn_index != 1 or not fallback_base_checkpoint_id:
                    raise AgentSessionBusyError(
                        "待重试轮次缺少可恢复的运行时基线"
                    )
                # 旧 schema 创建的首轮没有记录执行前的 checkpoint；调用方
                # 可为它提供初始 checkpoint，而原生会话基线必然为空。
                base_runtime_checkpoint_id = fallback_base_checkpoint_id
                base_native_session_id = ""

            message = str(source.get("user_message") or "").strip()
            if not message:
                raise AgentSessionBusyError("待重试轮次缺少原始消息")
            attachments = _json_value(source.get("attachments_json"), [])
            if not isinstance(attachments, list):
                attachments = []
            turn_index = max(1, int(row.get("turn_count") or 1)) + 1

            cursor.execute(
                """
                UPDATE agent_session_turns
                SET superseded_by_task_id=%s,
                    superseded_at=CURRENT_TIMESTAMP
                WHERE session_id=%s AND task_id=%s
                  AND superseded_at IS NULL
                  AND superseded_by_task_id IS NULL
                """,
                (task_id, session_id, expected_task_id),
            )
            if cursor.rowcount != 1:
                raise AgentSessionBusyError("Agent 当前轮次已被其它重试替代")
            cursor.execute(
                """
                INSERT INTO agent_session_turns (
                    session_id, task_id, turn_index, user_message,
                    attachments_json, base_runtime_checkpoint_id,
                    base_native_session_id, retry_of_task_id, status
                ) VALUES (%s, %s, %s, %s, %s, %s, NULLIF(%s, ''),
                          %s, 'Pending')
                """,
                (
                    session_id,
                    task_id,
                    turn_index,
                    message,
                    _json_text(attachments, []),
                    base_runtime_checkpoint_id,
                    base_native_session_id,
                    expected_task_id,
                ),
            )
            # retry 也是一条可恢复的当前轮 outbox。它必须和 supersede
            # lineage、新 turn 以及 current_task_id 在同一事务内提交；否则
            # Web 在 broker 唤醒前崩溃会留下无法由恢复扫描重新投递的 Pending。
            insert_turn_message_in_transaction(
                cursor,
                session_id=session_id,
                task_id=task_id,
                created_by=row.get("requested_by"),
                user_message=message,
                attachments=attachments,
            )
            cursor.execute(
                """
                UPDATE agent_sessions
                SET current_task_id=%s, status='Pending', message='任务排队中',
                    native_session_id=NULLIF(%s, ''), turn_count=%s,
                    fresh_native_session_pending=0
                WHERE session_id=%s AND current_task_id=%s
                """,
                (
                    task_id,
                    base_native_session_id,
                    turn_index,
                    session_id,
                    expected_task_id,
                ),
            )
            if cursor.rowcount != 1:
                raise AgentSessionBusyError("Agent 当前轮次已变化，请刷新后重试")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return {
        "turn_index": turn_index,
        "task_kind": str(row.get("task_kind") or "custom"),
        "problem_id": row.get("problem_id"),
        "requested_by": row.get("requested_by"),
        "access_role": str(row.get("access_role") or "user"),
        "harness": row.get("harness"),
        "reasoning_effort": str(
            row.get("reasoning_effort") or "default"
        ).strip().lower(),
        "endpoint_source": str(row.get("endpoint_source") or "global"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": row.get("endpoint_model"),
        "native_session_id": base_native_session_id,
        "user_message": message,
        "attachments": attachments,
        "base_runtime_checkpoint_id": base_runtime_checkpoint_id,
        "previous_base_runtime_checkpoint_id": base_runtime_checkpoint_id,
        "base_native_session_id": base_native_session_id,
        "retry_of_task_id": expected_task_id,
        "replaced_task_id": expected_task_id,
        "agent_message": _turn_message_response(
            session_id=session_id,
            task_id=task_id,
            created_by=row.get("requested_by"),
            user_message=message,
            attachments=attachments,
        ),
    }


def mark_agent_turn_enqueue_failed(session_id, task_id, message):
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    error = str(message or "任务入队失败")[:1000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_turns
                SET status='Failed', conclusion=%s
                WHERE session_id=%s AND task_id=%s
                """,
                (error, session_id, task_id),
            )
            cursor.execute(
                """
                UPDATE agent_sessions
                SET status='Failed', message=%s,
                    queue_paused=1, queue_pause_reason=%s
                WHERE session_id=%s AND current_task_id=%s
                """,
                (error, error, session_id, task_id),
            )
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET status='failed', error_message=%s
                WHERE session_id=%s AND final_task_id=%s
                  AND delivery_mode IN ('turn','queue')
                  AND status='dispatching'
                """,
                (error, session_id, task_id),
            )
        conn.commit()
    finally:
        conn.close()


def mark_agent_turn_runtime_restore_failed(session_id, task_id, message):
    """把无法确定 runtime 一致性的重试收束为不可续聊状态。"""

    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    error = str(message or "Agent 运行时恢复失败")[:1000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_turns
                SET status='CleanupFailed', conclusion=%s
                WHERE session_id=%s AND task_id=%s
                """,
                (error, session_id, task_id),
            )
            cursor.execute(
                """
                UPDATE agent_sessions
                SET status='CleanupFailed', message=%s,
                    queue_paused=1, queue_pause_reason=%s
                WHERE session_id=%s AND current_task_id=%s
                """,
                (error, error, session_id, task_id),
            )
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET status='failed', error_message=%s
                WHERE session_id=%s AND final_task_id=%s
                  AND delivery_mode IN ('turn','queue')
                  AND status='dispatching'
                """,
                (error, session_id, task_id),
            )
        conn.commit()
    finally:
        conn.close()


def set_agent_turn_attachments(session_id, task_id, attachments):
    """在轮次已独占会话后持久化附件元数据。"""

    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    attachments_json = _json_text(attachments, [])
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_turns AS t
                JOIN agent_sessions AS s ON s.session_id=t.session_id
                SET t.attachments_json=%s
                WHERE t.session_id=%s AND t.task_id=%s
                  AND s.current_task_id=%s AND LOWER(s.status)='pending'
                """,
                (attachments_json, session_id, task_id, task_id),
            )
            if cursor.rowcount <= 0:
                # MySQL 默认返回“实际改变的行数”；当续聊没有附件时，
                # begin_agent_session_turn 已写入 []，此处的 [] -> [] 会得到 0。
                # 用相同 CAS 条件做当前读并加锁，同时核对附件值；既能
                # 确认“命中但未改值”，也不会放行已被换轮或开始执行的会话。
                cursor.execute(
                    """
                    SELECT t.attachments_json
                    FROM agent_session_turns AS t
                    JOIN agent_sessions AS s ON s.session_id=t.session_id
                    WHERE t.session_id=%s AND t.task_id=%s
                      AND s.current_task_id=%s AND LOWER(s.status)='pending'
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (session_id, task_id, task_id),
                )
                row = cursor.fetchone()
                if (
                    not row
                    or str(row.get("attachments_json") or "") != attachments_json
                ):
                    raise AgentSessionBusyError("Agent 轮次附件状态已变化")
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET attachments_json=%s
                WHERE session_id=%s AND final_task_id=%s
                  AND delivery_mode='turn' AND status='dispatching'
                """,
                (attachments_json, session_id, task_id),
            )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def sync_agent_session_state_in_transaction(cursor, state):
    """在调用方事务内投影会话状态；run 与 session 可据此原子提交。"""

    if not isinstance(state, dict):
        return False
    raw_task_id = str(state.get("task_id") or "").strip()
    raw_session_id = str(state.get("session_id") or raw_task_id).strip()
    if not _ID_RE.fullmatch(raw_task_id) or not _ID_RE.fullmatch(raw_session_id):
        return False
    status = str(state.get("status") or "Pending")[:32]
    message = str(state.get("message") or "")[:4000]
    title = str(state.get("title") or "").strip()[:64]
    native_session_id = str(state.get("native_session_id") or "").strip()[:128]
    conclusion = str(state.get("conclusion") or "")
    if (
        not bool(state.get("_preserve_conclusion"))
        and not conclusion.strip()
        and status.strip().lower()
        in _TERMINAL_STATUSES | {"cleanupfailed", "cleanup_failed"}
    ):
        # 失败、取消或清理失败未必产生 assistant 结论；仍需把本轮终态原因
        # 固化到历史中，不能在进入下一轮后只剩一个空白响应块。
        conclusion = message

    cursor.execute(
        """
        SELECT status
        FROM agent_sessions
        WHERE session_id=%s AND current_task_id=%s
        LIMIT 1
        FOR UPDATE
        """,
        (raw_session_id, raw_task_id),
    )
    current = cursor.fetchone()
    if not current:
        return False
    # 已提交的 Completed/Failed 以及取消、清理失败都必须保持 sticky，
    # 避免 late-ack 或异常收束的迟到快照重开或改写会话。CleanupFailed
    # 仍允许从 Canceled 升级，以表达 revoke 或容器清理失败。
    current_status = str(current.get("status") or "").strip().lower()
    incoming_status = status.strip().lower()
    if (
        current_status
        in {"completed", "failed", "cleanupfailed", "cleanup_failed"}
        or (
            current_status in {"canceled", "cancelled"}
            and incoming_status not in {"cleanupfailed", "cleanup_failed"}
        )
    ):
        if native_session_id:
            # 终态本身保持 sticky，但容器退出边界可能比取消/失败事务更晚
            # 才观察到原生 session 摘要。只允许同一 current task 补齐空恢复
            # 点，不能借迟到 worker 改写状态或替换已有会话。
            cursor.execute(
                """
                UPDATE agent_sessions
                SET native_session_id=COALESCE(
                        NULLIF(native_session_id, ''), %s
                    ),
                    fresh_native_session_pending=0
                WHERE session_id=%s AND current_task_id=%s
                """,
                (native_session_id, raw_session_id, raw_task_id),
            )
            return cursor.rowcount > 0
        return False
    should_check_queue = incoming_status in {"canceled", "cancelled"} or (
        incoming_status == "failed" and message == AGENT_EMPTY_CONCLUSION_MESSAGE
    )
    has_queued_messages = False
    if should_check_queue:
        # 手动终止和“无可展示结论”都只有在仍有待发送的 FIFO 消息时才暂停。
        # enqueue 同样先锁会话行，因此这里在会话行锁内读取，避免把“空队列”
        # 误判成需要暂停，导致下一条即时消息被降级为 queue。
        cursor.execute(
            """
            SELECT 1
            FROM agent_session_messages
            WHERE session_id=%s AND delivery_mode='queue' AND status='queued'
            LIMIT 1
            """,
            (raw_session_id,),
        )
        has_queued_messages = bool(cursor.fetchone())

    pause_queue = incoming_status in {"cleanupfailed", "cleanup_failed"} or (
        incoming_status == "failed"
        and message != AGENT_EMPTY_CONCLUSION_MESSAGE
    ) or (should_check_queue and has_queued_messages)
    clear_queue_pause = should_check_queue and not has_queued_messages
    queue_pause_reason = message or "上一轮任务未正常完成"
    cursor.execute(
        """
        UPDATE agent_sessions
        SET status=%s, message=%s,
            title=COALESCE(NULLIF(%s, ''), title),
            native_session_id=COALESCE(NULLIF(%s, ''), native_session_id),
            fresh_native_session_pending=CASE
                WHEN %s <> '' THEN 0
                ELSE fresh_native_session_pending
            END,
            queue_paused=CASE
                WHEN %s THEN 1
                WHEN %s THEN 0
                ELSE queue_paused
            END,
            queue_pause_reason=CASE
                WHEN %s THEN %s
                WHEN %s THEN NULL
                ELSE queue_pause_reason
            END
        WHERE session_id=%s AND current_task_id=%s
        """,
        (
            status,
            message,
            title,
            native_session_id,
            native_session_id,
            1 if pause_queue else 0,
            1 if clear_queue_pause else 0,
            1 if pause_queue else 0,
            queue_pause_reason,
            1 if clear_queue_pause else 0,
            raw_session_id,
            raw_task_id,
        ),
    )
    cursor.execute(
        """
        UPDATE agent_session_turns
        SET status=%s,
            conclusion=CASE
                WHEN %s <> '' THEN %s
                ELSE conclusion
            END
        WHERE session_id=%s AND task_id=%s
        """,
        (
            status,
            conclusion,
            conclusion,
            raw_session_id,
            raw_task_id,
        ),
    )
    sync_agent_message_state_in_transaction(
        cursor,
        task_id=raw_task_id,
        status=status,
        reason=message,
    )
    return True


def sync_agent_session_state(state):
    """把单轮执行状态投影到当前会话；迟到的旧轮次不能覆盖新一轮。"""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            changed = sync_agent_session_state_in_transaction(cursor, state)
        if not changed:
            return False
        conn.commit()
        return True
    finally:
        conn.close()


def update_agent_session_title(session_id, title):
    session_id = normalize_agent_session_id(session_id)
    normalized = str(title or "").strip()[:64]
    if not normalized:
        return False
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_sessions
                SET title=%s
                WHERE session_id=%s AND (title IS NULL OR title='')
                """,
                (normalized, session_id),
            )
            changed = cursor.rowcount > 0
        conn.commit()
        return changed
    finally:
        conn.close()


def rename_agent_session_title(session_id, title):
    """显式重命名会话；与只填充空标题的生成写入分开。"""

    session_id = normalize_agent_session_id(session_id)
    normalized = str(title or "").replace("\x00", " ").strip()
    if not normalized:
        raise ValueError("Agent 会话标题不能为空")
    if len(normalized) > 64:
        raise ValueError("Agent 会话标题不能超过 64 个字符")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE agent_sessions SET title=%s WHERE session_id=%s",
                (normalized, session_id),
            )
            changed = cursor.rowcount > 0
        conn.commit()
        return changed
    finally:
        conn.close()


def claim_agent_session_title_generation(session_id, fallback_title):
    """用确定性回退标题原子占位，保证 late-ack 重投不会重复调用 LLM。"""

    session_id = normalize_agent_session_id(session_id)
    fallback = str(fallback_title or "Agent 任务").strip()[:64] or "Agent 任务"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_sessions
                SET title=%s
                WHERE session_id=%s AND (title IS NULL OR title='')
                """,
                (fallback, session_id),
            )
            claimed = cursor.rowcount > 0
        conn.commit()
        return claimed
    finally:
        conn.close()


def get_agent_session(session_id):
    session_id = normalize_agent_session_id(session_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT session_id, current_task_id, title, task_kind,
                       judge_kind, submission_id, attempt_id, competition_id,
                       problem_id, problem_title, requested_by, access_role,
                       harness, reasoning_effort, endpoint_source, endpoint_id,
                       endpoint_revision, endpoint_model,
                       native_session_id, status, message, turn_count,
                       queue_paused, queue_pause_reason,
                       fresh_native_session_pending,
                       created_at, updated_at, 0 AS is_legacy
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            if row:
                return _session_from_row(row)
            cursor.execute(
                """
                SELECT task_id AS session_id, task_id AS current_task_id,
                       problem_title AS title, 'legacy' AS task_kind,
                       problem_id, problem_title, requested_by,
                       'user' AS access_role, harness,
                       'default' AS reasoning_effort,
                       'global' AS endpoint_source, endpoint_id,
                       NULL AS endpoint_revision, endpoint_model,
                       NULL AS native_session_id,
                       status, message, 1 AS turn_count,
                       0 AS queue_paused, NULL AS queue_pause_reason,
                       0 AS fresh_native_session_pending,
                       created_at, updated_at, 1 AS is_legacy
                FROM agent_task_runs
                WHERE task_id=%s
                LIMIT 1
                """,
                (session_id,),
            )
            return _session_from_row(cursor.fetchone())
    finally:
        conn.close()


def get_agent_session_by_task_id(task_id):
    task_id = normalize_agent_session_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.session_id, s.current_task_id, s.title, s.task_kind,
                       s.judge_kind, s.submission_id, s.attempt_id, s.competition_id,
                       s.problem_id, s.problem_title, s.requested_by,
                       s.access_role, s.harness, s.reasoning_effort,
                       s.endpoint_source,
                       s.endpoint_id,
                       s.endpoint_revision, s.endpoint_model,
                       s.native_session_id, s.status,
                       s.message, s.turn_count,
                       s.queue_paused, s.queue_pause_reason,
                       s.fresh_native_session_pending,
                       s.created_at, s.updated_at,
                       0 AS is_legacy
                FROM agent_sessions AS s
                LEFT JOIN agent_session_turns AS t
                  ON t.session_id=s.session_id
                WHERE s.current_task_id=%s OR t.task_id=%s
                ORDER BY (s.current_task_id=%s) DESC
                LIMIT 1
                """,
                (task_id, task_id, task_id),
            )
            return _session_from_row(cursor.fetchone())
    finally:
        conn.close()


def get_agent_session_turns(session_id, include_superseded=False):
    session_id = normalize_agent_session_id(session_id)
    superseded_filter = (
        "" if bool(include_superseded) else "AND t.superseded_at IS NULL"
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT t.task_id, t.turn_index, t.user_message,
                       t.attachments_json, t.base_runtime_checkpoint_id,
                       t.base_native_session_id, t.retry_of_task_id,
                       t.superseded_by_task_id, t.superseded_at,
                       t.status, t.conclusion,
                       r.harness, r.endpoint_id, r.endpoint_model,
                       t.created_at, t.updated_at
                FROM agent_session_turns AS t
                LEFT JOIN agent_task_runs AS r ON r.task_id=t.task_id
                WHERE t.session_id=%s
                  {superseded_filter}
                ORDER BY t.turn_index ASC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()
            if rows:
                return [_turn_from_row(row) for row in rows]
            cursor.execute(
                """
                SELECT task_id, problem_id, problem_title, harness,
                       endpoint_id, endpoint_model, status, message,
                       created_at, updated_at
                FROM agent_task_runs
                WHERE task_id=%s
                LIMIT 1
                """,
                (session_id,),
            )
            legacy = cursor.fetchone()
    finally:
        conn.close()
    if not legacy:
        return []
    problem_label = str(legacy.get("problem_title") or "").strip()
    if legacy.get("problem_id"):
        user_message = f"处理题目 #{legacy['problem_id']} {problem_label}".strip()
    else:
        user_message = problem_label or "执行 Agent 任务"
    return [{
        "task_id": legacy.get("task_id"),
        "turn_index": 1,
        "user_message": user_message,
        "attachments": [],
        "base_runtime_checkpoint_id": "",
        "base_native_session_id": "",
        "retry_of_task_id": "",
        "superseded_by_task_id": "",
        "superseded_at": None,
        "harness": legacy.get("harness"),
        "endpoint_id": legacy.get("endpoint_id"),
        "endpoint_model": legacy.get("endpoint_model"),
        "status": str(legacy.get("status") or "Pending"),
        "conclusion": str(legacy.get("message") or ""),
        "created_at": _format_time(legacy.get("created_at")),
        "updated_at": _format_time(legacy.get("updated_at")),
    }]


def get_agent_sessions_paginated(page=1, per_page=20, requested_by=None, *, judge_only=False):
    page = max(1, int(page))
    per_page = max(1, min(100, int(per_page)))
    owner = str(requested_by or "").strip() or None
    session_filter = "WHERE s.task_kind='judge'" if judge_only else "WHERE s.task_kind<>'judge'"
    if owner:
        session_filter += " AND s.requested_by=%s"
    legacy_filter = (
        "WHERE r.requested_by=%s AND NOT EXISTS"
        if owner
        else "WHERE NOT EXISTS"
    )
    if judge_only:
        legacy_filter = legacy_filter.replace("WHERE ", "WHERE 1=0 AND ")
    count_params = (owner, owner) if owner else ()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    (SELECT COUNT(*) FROM agent_sessions AS s
                     {session_filter})
                    +
                    (SELECT COUNT(*)
                     FROM agent_task_runs AS r
                     {legacy_filter} (
                         SELECT 1 FROM agent_session_turns AS t
                         WHERE t.task_id=r.task_id
                     )) AS total
                """,
                count_params,
            )
            total = int((cursor.fetchone() or {}).get("total") or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(page, total_pages)
            list_params = (
                (owner, owner, per_page, (page - 1) * per_page)
                if owner
                else (per_page, (page - 1) * per_page)
            )
            cursor.execute(
                f"""
                SELECT *
                FROM (
                    SELECT s.id AS source_id, s.session_id,
                           s.current_task_id, s.title, s.task_kind,
                           s.judge_kind, s.submission_id, s.attempt_id, s.competition_id,
                           s.problem_id, s.problem_title, s.requested_by,
                           s.access_role, s.harness, s.reasoning_effort,
                           s.endpoint_source,
                           s.endpoint_id,
                           s.endpoint_revision, s.endpoint_model,
                           s.native_session_id, s.status,
                           s.message, s.turn_count,
                           s.queue_paused, s.queue_pause_reason,
                           s.fresh_native_session_pending,
                           s.created_at, s.updated_at,
                           0 AS is_legacy
                    FROM agent_sessions AS s
                    {session_filter}
                    UNION ALL
                    SELECT r.id AS source_id, r.task_id AS session_id,
                           r.task_id AS current_task_id,
                           r.problem_title AS title, 'legacy' AS task_kind,
                           NULL AS judge_kind, NULL AS submission_id,
                           NULL AS attempt_id, NULL AS competition_id,
                           r.problem_id, r.problem_title, r.requested_by,
                           'user' AS access_role, r.harness,
                           'default' AS reasoning_effort,
                           'global' AS endpoint_source, r.endpoint_id,
                           NULL AS endpoint_revision, r.endpoint_model,
                           NULL AS native_session_id,
                           r.status, r.message, 1 AS turn_count,
                           0 AS queue_paused, NULL AS queue_pause_reason,
                           0 AS fresh_native_session_pending,
                           r.created_at, r.updated_at, 1 AS is_legacy
                    FROM agent_task_runs AS r
                    {legacy_filter} (
                        SELECT 1 FROM agent_session_turns AS t
                        WHERE t.task_id=r.task_id
                    )
                ) AS sessions
                ORDER BY updated_at DESC, is_legacy ASC,
                         source_id DESC, session_id DESC
                LIMIT %s OFFSET %s
                """,
                list_params,
            )
            rows = cursor.fetchall()
    finally:
        conn.close()
    return [_session_from_row(row) for row in rows], page, total_pages



def agent_session_is_judge(session):
    return bool(session and session.get("task_kind") == "judge")


def can_view_agent_session(session, *, username, is_admin=False):
    """网页、轨迹和 workspace 共用的会话查看边界。"""
    if not session:
        return False
    if is_admin:
        return True
    if str(session.get("requested_by") or "") != str(username or ""):
        return False
    return not agent_session_is_judge(session) or session.get("judge_kind") == "reverse_answer"


def get_judge_session_for_attempt(submission_id, attempt_id, judge_kind):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT session_id FROM agent_sessions WHERE task_kind='judge' "
                "AND submission_id=%s AND COALESCE(attempt_id, '')=%s AND judge_kind=%s "
                "ORDER BY (session_id LIKE '%%-history') ASC, id DESC LIMIT 1",
                (submission_id, str(attempt_id or ""), judge_kind),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    return get_agent_session(row["session_id"]) if row else None


def get_agent_session_runtime_config(session_id, task_id=None):
    """内部运行配置永不包含在公开会话序列化结果中。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT runtime_config_json FROM agent_sessions WHERE session_id=%s", (normalize_agent_session_id(session_id),))
            row = cursor.fetchone() or {}
            result = _json_value(row.get("runtime_config_json"), {})
            result = result if isinstance(result, dict) else {}
            if task_id:
                cursor.execute("SELECT dispatch_payload_json FROM agent_session_messages WHERE session_id=%s AND final_task_id=%s LIMIT 1", (session_id, task_id))
                payload = _json_value((cursor.fetchone() or {}).get("dispatch_payload_json"), {})
                if isinstance(payload, dict) and "timeout_seconds" in payload:
                    result["timeout_seconds"] = payload["timeout_seconds"]
            return result
    finally:
        conn.close()


__all__ = [
    "agent_session_is_judge",
    "can_view_agent_session",
    "get_judge_session_for_attempt",
    "get_agent_session_runtime_config",
    "AgentSessionMessageConflictError",
    "AgentSessionMessageError",
    "AgentSessionMessageNotFoundError",
    "AgentSessionBusyError",
    "AgentSessionError",
    "AgentSessionNotFoundError",
    "agent_status_is_terminal",
    "begin_agent_session_retry",
    "begin_agent_session_turn",
    "cancel_queued_agent_session_message",
    "claim_next_agent_session_message",
    "claim_next_agent_session_steer",
    "claim_agent_session_title_generation",
    "create_agent_session",
    "continue_agent_session_queue",
    "enqueue_agent_session_message",
    "finish_agent_session_message_delivery",
    "get_agent_session_message",
    "get_agent_session_queue_snapshot",
    "get_agent_session",
    "get_agent_session_by_task_id",
    "get_agent_session_turns",
    "get_agent_sessions_paginated",
    "list_agent_session_messages",
    "list_agent_session_queue_recovery_candidates",
    "mark_agent_session_message_broker_enqueued",
    "mark_agent_session_steers_unknown_for_task",
    "rename_agent_session_title",
    "mark_agent_turn_enqueue_failed",
    "mark_agent_turn_runtime_restore_failed",
    "normalize_agent_access_role",
    "normalize_agent_message_id",
    "normalize_agent_session_id",
    "pause_agent_session_queue",
    "reorder_queued_agent_session_messages",
    "release_agent_session_message_dispatch_attempt",
    "set_agent_turn_attachments",
    "set_agent_session_queue_paused",
    "steer_queued_agent_session_message",
    "sync_agent_session_state",
    "sync_agent_session_state_in_transaction",
    "update_agent_session_title",
    "update_queued_agent_session_message",
]
