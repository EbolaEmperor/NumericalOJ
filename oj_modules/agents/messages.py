"""通用 Agent 会话消息、持久队列与投递状态。"""

from __future__ import annotations

import json
import re
import uuid

from oj_modules.infrastructure.mysql import get_db_connection


_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_DELIVERY_MODES = frozenset({"turn", "queue", "steer"})
_MESSAGE_STATUSES = frozenset(
    {"queued", "dispatching", "sent", "canceled", "failed", "unknown"}
)
_FINAL_DELIVERY_STATUSES = frozenset({"sent", "failed", "unknown"})
_TERMINAL_SESSION_STATUSES = frozenset(
    {"completed", "failed", "canceled", "cancelled", "cleanupfailed", "cleanup_failed"}
)
_START_FRESH_NATIVE_SESSION_KEY = "start_fresh_native_session"
_DISPATCH_ATTEMPT_LEASE_SECONDS = 60
_EXPECTED_ATTACHMENTS_UNSET = object()


class AgentSessionMessageError(RuntimeError):
    """会话消息操作失败。"""


class AgentSessionMessageNotFoundError(AgentSessionMessageError):
    """会话或消息不存在。"""


class AgentSessionMessageConflictError(AgentSessionMessageError):
    """消息状态、顺序或目标任务发生冲突。"""


def normalize_agent_message_id(value):
    normalized = str(value or "").strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError("Agent message_id 无效")
    return normalized


def _normalize_session_id(value):
    normalized = str(value or "").strip()
    if not _ID_RE.fullmatch(normalized):
        raise ValueError("Agent session_id 无效")
    return normalized


def _normalize_task_id(value, *, required=True):
    normalized = str(value or "").strip()
    if not normalized and not required:
        return ""
    if not _ID_RE.fullmatch(normalized):
        raise ValueError("Agent task_id 无效")
    return normalized


def _normalize_mode(value):
    normalized = str(value or "").strip().lower()
    if normalized not in _DELIVERY_MODES:
        raise ValueError("Agent 消息投递模式无效")
    return normalized


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


def _message_from_row(row):
    if not row:
        return None
    attachments = _json_value(row.get("attachments_json"), [])
    return {
        "message_id": row.get("message_id"),
        "session_id": row.get("session_id"),
        "created_by": str(row.get("created_by") or ""),
        "user_message": str(row.get("user_message") or ""),
        "attachments": attachments if isinstance(attachments, list) else [],
        "delivery_mode": str(row.get("delivery_mode") or "queue"),
        "status": str(row.get("status") or "queued"),
        "target_task_id": row.get("target_task_id"),
        "final_task_id": row.get("final_task_id"),
        "queue_position": int(row.get("queue_position") or 0),
        "error_message": str(row.get("error_message") or ""),
        "delivered_at": _format_time(row.get("delivered_at")),
        "created_at": _format_time(row.get("created_at")),
        "updated_at": _format_time(row.get("updated_at")),
    }


def _dispatch_payload_from_row(row):
    payload = _json_value((row or {}).get("dispatch_payload_json"), {})
    return payload if isinstance(payload, dict) else {}


def _attachment_list(value, *, label):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label}必须是列表")
    return value


def _next_message_position(cursor, session_id):
    cursor.execute(
        """
        SELECT COALESCE(MAX(queue_position), 0) AS max_position
        FROM agent_session_messages
        WHERE session_id=%s
        """,
        (session_id,),
    )
    row = cursor.fetchone() or {}
    return max(0, int(row.get("max_position") or 0)) + 1024


def insert_turn_message_in_transaction(
    cursor,
    *,
    session_id,
    task_id,
    created_by,
    user_message,
    attachments=None,
    dispatch_payload=None,
    message_id=None,
    queue_position=None,
):
    """随新执行轮次写入其首条消息；调用方负责事务与会话行锁。"""

    session_id = _normalize_session_id(session_id)
    task_id = _normalize_task_id(task_id)
    message_id = normalize_agent_message_id(message_id or task_id)
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")
    creator = str(created_by or "").strip()[:50]
    if not creator:
        raise ValueError("Agent 消息创建者不能为空")
    position = int(queue_position or 0)
    if position <= 0:
        position = _next_message_position(cursor, session_id)
    cursor.execute(
        """
        INSERT INTO agent_session_messages (
            message_id, session_id, created_by, user_message,
            attachments_json, dispatch_payload_json, delivery_mode, status,
            target_task_id, final_task_id, queue_position
        ) VALUES (%s, %s, %s, %s, %s, %s, 'turn', 'dispatching',
                  %s, %s, %s)
        """,
        (
            message_id,
            session_id,
            creator,
            message,
            _json_text(attachments, []),
            _json_text(dispatch_payload, {}) if dispatch_payload else None,
            task_id,
            task_id,
            position,
        ),
    )
    return message_id


def enqueue_agent_session_message(
    session_id,
    *,
    message_id,
    created_by,
    user_message,
    attachments=None,
    delivery_mode="queue",
    target_task_id=None,
):
    """持久化排队消息或指向当前运行任务的软插话。

    相同 ``message_id`` 和相同内容的重试是幂等的；复用 ID 提交不同内容会
    显式报冲突。插话必须带客户端所见的当前 task_id，绝不降级为排队消息。
    """

    session_id = _normalize_session_id(session_id)
    message_id = normalize_agent_message_id(message_id)
    mode = _normalize_mode(delivery_mode)
    if mode not in {"queue", "steer"}:
        raise ValueError("只能将 queue 或 steer 消息加入会话")
    creator = str(created_by or "").strip()[:50]
    if not creator:
        raise ValueError("Agent 消息创建者不能为空")
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")
    attachments_json = _json_text(attachments, [])
    target_task_id = _normalize_task_id(
        target_task_id,
        required=(mode == "steer"),
    )
    if mode == "queue":
        target_task_id = ""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT current_task_id, status
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")
            cursor.execute(
                """
                SELECT message_id, session_id, created_by, user_message,
                       attachments_json, delivery_mode, status,
                       target_task_id, final_task_id, queue_position,
                       error_message, delivered_at, created_at, updated_at
                FROM agent_session_messages
                WHERE message_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (message_id,),
            )
            existing = cursor.fetchone()
            if existing:
                same_request = (
                    str(existing.get("session_id") or "") == session_id
                    and str(existing.get("created_by") or "") == creator
                    and str(existing.get("user_message") or "") == message
                    and str(existing.get("attachments_json") or "") == attachments_json
                    and str(existing.get("delivery_mode") or "") == mode
                    and str(existing.get("target_task_id") or "") == target_task_id
                )
                if not same_request:
                    raise AgentSessionMessageConflictError("Agent message_id 已被其它消息使用")
                result = _message_from_row(existing)
            else:
                if mode == "steer":
                    current_task_id = str(session.get("current_task_id") or "")
                    session_status = str(session.get("status") or "").strip().lower()
                    if current_task_id != target_task_id:
                        raise AgentSessionMessageConflictError(
                            "Agent 当前任务已变化，请重新发送"
                        )
                    if session_status in _TERMINAL_SESSION_STATUSES:
                        raise AgentSessionMessageConflictError("Agent 当前任务已经结束")
                position = _next_message_position(cursor, session_id)
                cursor.execute(
                    """
                    INSERT INTO agent_session_messages (
                        message_id, session_id, created_by, user_message,
                        attachments_json, delivery_mode, status,
                        target_task_id, queue_position
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'queued', %s, %s)
                    """,
                    (
                        message_id,
                        session_id,
                        creator,
                        message,
                        attachments_json,
                        mode,
                        target_task_id or None,
                        position,
                    ),
                )
                result = {
                    "message_id": message_id,
                    "session_id": session_id,
                    "created_by": creator,
                    "user_message": message,
                    "attachments": _json_value(attachments_json, []),
                    "delivery_mode": mode,
                    "status": "queued",
                    "target_task_id": target_task_id or None,
                    "final_task_id": None,
                    "queue_position": position,
                    "error_message": "",
                    "delivered_at": None,
                    "created_at": None,
                    "updated_at": None,
                }
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_agent_session_messages(session_id, *, delivery_modes=None, statuses=None):
    session_id = _normalize_session_id(session_id)
    clauses = ["session_id=%s"]
    params = [session_id]
    if delivery_modes is not None:
        if isinstance(delivery_modes, str):
            delivery_modes = (delivery_modes,)
        modes = tuple(dict.fromkeys(_normalize_mode(value) for value in delivery_modes))
        if not modes:
            return []
        clauses.append(f"delivery_mode IN ({','.join(['%s'] * len(modes))})")
        params.extend(modes)
    if statuses is not None:
        if isinstance(statuses, str):
            statuses = (statuses,)
        normalized_statuses = tuple(
            dict.fromkeys(str(value or "").strip().lower() for value in statuses)
        )
        if not normalized_statuses:
            return []
        if any(value not in _MESSAGE_STATUSES for value in normalized_statuses):
            raise ValueError("Agent 消息状态无效")
        clauses.append(f"status IN ({','.join(['%s'] * len(normalized_statuses))})")
        params.extend(normalized_statuses)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT message_id, session_id, created_by, user_message,
                       attachments_json, delivery_mode, status,
                       target_task_id, final_task_id, queue_position,
                       error_message, delivered_at, created_at, updated_at
                FROM agent_session_messages
                WHERE {' AND '.join(clauses)}
                ORDER BY queue_position ASC, id ASC
                """,
                tuple(params),
            )
            rows = cursor.fetchall()
        return [_message_from_row(row) for row in rows]
    finally:
        conn.close()


def get_agent_session_message(message_id):
    """按幂等键读取消息；不向调用方暴露内部 dispatch payload。"""

    message_id = normalize_agent_message_id(message_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT message_id, session_id, created_by, user_message,
                       attachments_json, delivery_mode, status,
                       target_task_id, final_task_id, queue_position,
                       error_message, delivered_at, created_at, updated_at
                FROM agent_session_messages
                WHERE message_id=%s
                LIMIT 1
                """,
                (message_id,),
            )
            return _message_from_row(cursor.fetchone())
    finally:
        conn.close()


def get_agent_session_queue_snapshot(session_id):
    """读取页面/SSE 可直接使用的会话队列快照。"""

    session_id = _normalize_session_id(session_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT current_task_id, status, queue_paused, queue_pause_reason
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                """,
                (session_id,),
            )
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")
            cursor.execute(
                """
                SELECT message_id, session_id, created_by, user_message,
                       attachments_json, delivery_mode, status,
                       target_task_id, final_task_id, queue_position,
                       error_message, delivered_at, created_at, updated_at
                FROM agent_session_messages
                WHERE session_id=%s
                  AND (
                    (delivery_mode='queue' AND status IN ('queued','dispatching'))
                    OR
                    (delivery_mode='queue' AND status='sent'
                     AND final_task_id=%s)
                    OR
                    (delivery_mode='steer' AND status IN ('queued','dispatching','sent','failed','unknown'))
                  )
                ORDER BY queue_position ASC, id ASC
                """,
                (
                    session_id,
                    str(session.get("current_task_id") or ""),
                ),
            )
            messages = [_message_from_row(row) for row in cursor.fetchall()]
        status = str(session.get("status") or "Pending")
        return {
            "session_id": session_id,
            "current_task_id": session.get("current_task_id"),
            "status": status,
            "running": status.strip().lower() not in _TERMINAL_SESSION_STATUSES,
            "queue_paused": bool(session.get("queue_paused")),
            "queue_pause_reason": str(session.get("queue_pause_reason") or ""),
            "messages": messages,
        }
    finally:
        conn.close()


def list_agent_session_queue_recovery_candidates(*, limit=100):
    """列出需要补投当前轮 outbox 或继续空闲 FIFO 的会话。"""

    limit = max(1, min(1000, int(limit)))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.session_id
                FROM agent_sessions AS s
                JOIN agent_session_messages AS m ON m.session_id=s.session_id
                WHERE (
                    (m.delivery_mode IN ('turn','queue')
                     AND m.status='dispatching'
                     AND m.final_task_id=s.current_task_id
                     AND (
                         m.dispatch_attempt_id IS NULL
                         OR m.dispatch_attempted_at IS NULL
                         OR TIMESTAMPDIFF(
                             SECOND,
                             m.dispatch_attempted_at,
                             CURRENT_TIMESTAMP
                         ) >= %s
                     ))
                    OR
                    (m.delivery_mode='queue' AND m.status='queued'
                     AND s.queue_paused=0
                     AND LOWER(s.status) IN (
                         'completed','failed','canceled','cancelled'
                     ))
                )
                GROUP BY s.session_id
                ORDER BY MIN(s.updated_at) ASC, s.session_id ASC
                LIMIT %s
                """,
                (_DISPATCH_ATTEMPT_LEASE_SECONDS, limit),
            )
            return [str(row.get("session_id") or "") for row in cursor.fetchall()]
    finally:
        conn.close()


def mark_agent_session_message_broker_enqueued(
    message_id,
    *,
    dispatch_attempt_id,
    task_id,
):
    """记录当前派发尝试已被 broker 接收；同一回执可幂等重放。"""

    message_id = normalize_agent_message_id(message_id)
    dispatch_attempt_id = _normalize_task_id(dispatch_attempt_id)
    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT status, final_task_id, dispatch_attempt_id,
                       broker_enqueued_at
                FROM agent_session_messages
                WHERE message_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (message_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionMessageNotFoundError("Agent 消息不存在")
            if str(row.get("final_task_id") or "") != task_id:
                raise AgentSessionMessageConflictError("Agent 消息目标任务已变化")
            if str(row.get("dispatch_attempt_id") or "") != dispatch_attempt_id:
                raise AgentSessionMessageConflictError("Agent 消息派发租约已变化")
            if row.get("broker_enqueued_at") is not None:
                return True
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET broker_enqueued_at=CURRENT_TIMESTAMP
                WHERE message_id=%s AND final_task_id=%s
                  AND dispatch_attempt_id=%s
                  AND broker_enqueued_at IS NULL
                """,
                (message_id, task_id, dispatch_attempt_id),
            )
            if cursor.rowcount <= 0:
                raise AgentSessionMessageConflictError("Agent 消息派发回执已变化")
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def release_agent_session_message_dispatch_attempt(
    message_id,
    *,
    dispatch_attempt_id,
    task_id,
):
    """broker 未接收时释放本次短租约，让同一 outbox 可以立即重试。"""

    message_id = normalize_agent_message_id(message_id)
    dispatch_attempt_id = _normalize_task_id(dispatch_attempt_id)
    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET dispatch_attempt_id=NULL, dispatch_attempted_at=NULL
                WHERE message_id=%s AND final_task_id=%s
                  AND status='dispatching'
                  AND broker_enqueued_at IS NULL
                  AND dispatch_attempt_id=%s
                """,
                (message_id, task_id, dispatch_attempt_id),
            )
            if cursor.rowcount > 0:
                released = True
            else:
                cursor.execute(
                    """
                    SELECT final_task_id, dispatch_attempt_id,
                           broker_enqueued_at
                    FROM agent_session_messages
                    WHERE message_id=%s
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (message_id,),
                )
                row = cursor.fetchone()
                if not row:
                    raise AgentSessionMessageNotFoundError("Agent 消息不存在")
                if str(row.get("final_task_id") or "") != task_id:
                    raise AgentSessionMessageConflictError("Agent 消息目标任务已变化")
                # 已由当前尝试释放是幂等成功；broker 已接收或租约已被新的
                # 派发者接管时不能清掉对方状态。
                released = (
                    row.get("broker_enqueued_at") is None
                    and not str(row.get("dispatch_attempt_id") or "")
                )
        conn.commit()
        return released
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_agent_session_steers_unknown_for_task(
    task_id,
    reason="Agent worker 已退出，无法确认插话是否送达",
):
    """worker/控制通道异常退出时，收束已领取但未确认的插话。"""

    task_id = _normalize_task_id(task_id)
    error = str(reason or "Agent 插话投递状态未知").strip()[:4000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET status='unknown', error_message=%s
                WHERE target_task_id=%s AND delivery_mode='steer'
                  AND status='dispatching'
                """,
                (error, task_id),
            )
            changed = cursor.rowcount
        conn.commit()
        return max(0, int(changed or 0))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_queued_agent_session_message(
    session_id,
    message_id,
    *,
    user_message,
    attachments=None,
    expected_attachments=_EXPECTED_ATTACHMENTS_UNSET,
):
    """CAS 编辑尚未提升的排队消息，并返回锁内确认的移除附件。"""

    session_id = _normalize_session_id(session_id)
    message_id = normalize_agent_message_id(message_id)
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")
    desired_attachments = _attachment_list(
        attachments,
        label="Agent 消息附件",
    )
    attachments_json = _json_text(desired_attachments, [])
    expected = (
        _EXPECTED_ATTACHMENTS_UNSET
        if expected_attachments is _EXPECTED_ATTACHMENTS_UNSET
        else _attachment_list(
            expected_attachments,
            label="Agent 消息预期附件",
        )
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT delivery_mode, status, attachments_json
                FROM agent_session_messages
                WHERE session_id=%s AND message_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id, message_id),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionMessageNotFoundError("Agent 排队消息不存在")
            if row.get("delivery_mode") != "queue" or row.get("status") != "queued":
                raise AgentSessionMessageConflictError("Agent 消息已开始投递，无法编辑")
            current_attachments = _json_value(row.get("attachments_json"), [])
            if not isinstance(current_attachments, list):
                raise AgentSessionMessageConflictError("Agent 排队消息附件状态无效")
            if (
                expected is not _EXPECTED_ATTACHMENTS_UNSET
                and current_attachments != expected
            ):
                raise AgentSessionMessageConflictError(
                    "Agent 排队消息已变化，请刷新后重试"
                )
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET user_message=%s, attachments_json=%s, error_message=NULL
                WHERE session_id=%s AND message_id=%s
                """,
                (message, attachments_json, session_id, message_id),
            )
            removed_attachments = [
                item for item in current_attachments
                if item not in desired_attachments
            ]
        conn.commit()
        return removed_attachments
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cancel_queued_agent_session_message(
    session_id,
    message_id,
    *,
    expected_attachments=_EXPECTED_ATTACHMENTS_UNSET,
):
    """CAS 取消排队消息，并返回锁内确认的待清理附件。"""

    session_id = _normalize_session_id(session_id)
    message_id = normalize_agent_message_id(message_id)
    expected = (
        _EXPECTED_ATTACHMENTS_UNSET
        if expected_attachments is _EXPECTED_ATTACHMENTS_UNSET
        else _attachment_list(
            expected_attachments,
            label="Agent 消息预期附件",
        )
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT delivery_mode, status, attachments_json
                FROM agent_session_messages
                WHERE session_id=%s AND message_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id, message_id),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionMessageNotFoundError("Agent 排队消息不存在")
            if row.get("delivery_mode") != "queue":
                raise AgentSessionMessageConflictError("只能删除排队消息")
            current_attachments = _json_value(row.get("attachments_json"), [])
            if not isinstance(current_attachments, list):
                raise AgentSessionMessageConflictError("Agent 排队消息附件状态无效")
            if (
                expected is not _EXPECTED_ATTACHMENTS_UNSET
                and current_attachments != expected
            ):
                raise AgentSessionMessageConflictError(
                    "Agent 排队消息已变化，请刷新后重试"
                )
            if row.get("status") not in {"queued", "canceled"}:
                raise AgentSessionMessageConflictError("Agent 消息已开始投递，无法删除")
            if row.get("status") == "queued":
                cursor.execute(
                    """
                    UPDATE agent_session_messages
                    SET status='canceled', error_message=NULL
                    WHERE session_id=%s AND message_id=%s
                    """,
                    (session_id, message_id),
                )
        conn.commit()
        return current_attachments
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def reorder_queued_agent_session_messages(session_id, message_ids):
    """按完整 ID 列表重排当前 FIFO；集合变化会拒绝，防止并发覆盖。"""

    session_id = _normalize_session_id(session_id)
    normalized_ids = [normalize_agent_message_id(value) for value in message_ids]
    if len(normalized_ids) != len(set(normalized_ids)):
        raise ValueError("Agent 排队消息顺序包含重复 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT session_id
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            if not cursor.fetchone():
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")
            cursor.execute(
                """
                SELECT message_id
                FROM agent_session_messages
                WHERE session_id=%s AND delivery_mode='queue' AND status='queued'
                ORDER BY queue_position ASC, id ASC
                FOR UPDATE
                """,
                (session_id,),
            )
            current_ids = [str(row.get("message_id") or "") for row in cursor.fetchall()]
            if set(current_ids) != set(normalized_ids) or len(current_ids) != len(normalized_ids):
                raise AgentSessionMessageConflictError("Agent 排队消息已变化，请刷新后重试")
            for index, current_id in enumerate(normalized_ids, start=1):
                cursor.execute(
                    """
                    UPDATE agent_session_messages
                    SET queue_position=%s
                    WHERE session_id=%s AND message_id=%s
                      AND delivery_mode='queue' AND status='queued'
                    """,
                    (index * 1024, session_id, current_id),
                )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def set_agent_session_queue_paused(session_id, paused, reason=""):
    if not bool(paused):
        return continue_agent_session_queue(session_id)

    session_id = _normalize_session_id(session_id)
    normalized_reason = str(reason or "").strip()[:4000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT session_id
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")
            cursor.execute(
                """
                UPDATE agent_sessions
                SET queue_paused=%s, queue_pause_reason=%s
                WHERE session_id=%s
                """,
                (1, normalized_reason or None, session_id),
            )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def pause_agent_session_queue(session_id, reason="队列已暂停"):
    return set_agent_session_queue_paused(session_id, True, reason)


def continue_agent_session_queue(session_id):
    """显式继续已暂停的 FIFO；必要时让队首从空原生会话启动。

    首轮在原生 session id 落盘前被停止时，持久 workspace 仍然可用，但
    无法恢复模型上下文。只有这条显式操作会在会话行上写入一次性授权；
    实际领取时再把授权绑定到当时的队首，因此中间的重排或删除不会丢失授权。
    """

    session_id = _normalize_session_id(session_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT session_id, status, native_session_id
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")

            session_status = str(session.get("status") or "").strip().lower()
            if session_status in {"cleanupfailed", "cleanup_failed"}:
                raise AgentSessionMessageConflictError(
                    "上一轮 Agent 容器尚未完成清理，不能继续队列"
                )
            if session_status not in _TERMINAL_SESSION_STATUSES:
                raise AgentSessionMessageConflictError(
                    "当前 Agent 任务尚未结束，不能继续队列"
                )

            start_fresh_native_session = not str(
                session.get("native_session_id") or ""
            ).strip()
            if start_fresh_native_session:
                cursor.execute(
                    """
                    SELECT message_id
                    FROM agent_session_messages
                    WHERE session_id=%s AND delivery_mode='queue'
                      AND status='queued'
                    ORDER BY queue_position ASC, id ASC
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (session_id,),
                )
                head = cursor.fetchone()
                if not head:
                    raise AgentSessionMessageConflictError(
                        "当前没有可继续的排队消息"
                    )

            cursor.execute(
                """
                UPDATE agent_sessions
                SET queue_paused=0, queue_pause_reason=NULL,
                    fresh_native_session_pending=%s
                WHERE session_id=%s
                """,
                (1 if start_fresh_native_session else 0, session_id),
            )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _claim_payload(session, message, turn_index, *, newly_promoted=False):
    result = _message_from_row(message)
    result.update({
        "task_id": message.get("final_task_id"),
        "turn_index": int(turn_index),
        "task_kind": str(session.get("task_kind") or "custom"),
        "problem_id": session.get("problem_id"),
        "requested_by": session.get("requested_by"),
        "access_role": str(session.get("access_role") or "user"),
        "harness": session.get("harness"),
        "endpoint_id": session.get("endpoint_id"),
        "endpoint_revision": session.get("endpoint_revision"),
        "endpoint_model": session.get("endpoint_model"),
        "native_session_id": str(session.get("native_session_id") or "").strip(),
        "base_runtime_checkpoint_id": str(
            message.get("base_runtime_checkpoint_id") or ""
        ).strip(),
        "previous_base_runtime_checkpoint_id": str(
            message.get("previous_base_runtime_checkpoint_id") or ""
        ).strip(),
        "base_native_session_id": str(
            message.get("base_native_session_id") or ""
        ).strip(),
        "retry_of_task_id": str(message.get("retry_of_task_id") or "").strip(),
        "newly_promoted": bool(newly_promoted),
        "dispatch_attempt_id": str(
            message.get("dispatch_attempt_id") or ""
        ).strip(),
        "dispatch_payload": _dispatch_payload_from_row(message),
    })
    return result


def claim_next_agent_session_message(
    session_id,
    *,
    task_id=None,
    prepare_runtime_checkpoint=None,
):
    """原子领取 FIFO 队首并创建下一执行轮次。

    当前 ``dispatching`` 消息只会在上一派发租约已经过期时以相同 task_id
    重新领取；broker 回执不代表 worker 已经接收，因此不能永久阻止崩溃恢复。
    恢复不会越过当前消息领取下一条。
    """

    session_id = _normalize_session_id(session_id)
    supplied_task_id = _normalize_task_id(task_id, required=False)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.current_task_id, s.status, s.turn_count, s.queue_paused,
                       s.fresh_native_session_pending,
                       s.task_kind, s.problem_id, s.requested_by, s.access_role,
                       s.harness, s.endpoint_id, s.endpoint_revision,
                       s.endpoint_model, s.native_session_id,
                       previous.base_runtime_checkpoint_id AS
                           previous_base_runtime_checkpoint_id
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
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")

            cursor.execute(
                """
                SELECT m.message_id, m.session_id, m.created_by, m.user_message,
                       m.attachments_json, m.delivery_mode, m.status,
                       m.target_task_id, m.final_task_id, m.queue_position,
                       m.error_message, m.delivered_at, m.created_at, m.updated_at,
                       m.dispatch_payload_json, m.dispatch_attempt_id,
                       m.dispatch_attempted_at, m.broker_enqueued_at,
                       t.turn_index, t.base_runtime_checkpoint_id,
                       t.base_native_session_id, t.retry_of_task_id,
                       previous.base_runtime_checkpoint_id AS
                           previous_base_runtime_checkpoint_id
                FROM agent_session_messages AS m
                JOIN agent_session_turns AS t
                  ON t.session_id=m.session_id AND t.task_id=m.final_task_id
                LEFT JOIN agent_session_turns AS previous
                  ON previous.session_id=t.session_id
                 AND previous.turn_index=t.turn_index - 1
                WHERE m.session_id=%s AND m.delivery_mode IN ('turn','queue')
                  AND m.status='dispatching'
                  AND m.final_task_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id, session.get("current_task_id")),
            )
            existing = cursor.fetchone()
            if existing:
                if supplied_task_id and supplied_task_id != existing.get("final_task_id"):
                    raise AgentSessionMessageConflictError("Agent 队首已由其它任务领取")
                dispatch_attempt_id = uuid.uuid4().hex
                cursor.execute(
                    """
                    UPDATE agent_session_messages
                    SET dispatch_attempt_id=%s,
                        dispatch_attempted_at=CURRENT_TIMESTAMP,
                        broker_enqueued_at=NULL
                    WHERE message_id=%s AND status='dispatching'
                      AND (
                          dispatch_attempt_id IS NULL
                          OR dispatch_attempted_at IS NULL
                          OR TIMESTAMPDIFF(
                              SECOND,
                              dispatch_attempted_at,
                              CURRENT_TIMESTAMP
                          ) >= %s
                      )
                    """,
                    (
                        dispatch_attempt_id,
                        existing.get("message_id"),
                        _DISPATCH_ATTEMPT_LEASE_SECONDS,
                    ),
                )
                if cursor.rowcount <= 0:
                    return None
                existing = dict(existing)
                existing["dispatch_attempt_id"] = dispatch_attempt_id
                result = _claim_payload(
                    session,
                    existing,
                    existing.get("turn_index") or 1,
                )
            else:
                if bool(session.get("queue_paused")):
                    return None
                if str(session.get("status") or "").strip().lower() not in (
                    _TERMINAL_SESSION_STATUSES - {"cleanupfailed", "cleanup_failed"}
                ):
                    return None
                cursor.execute(
                    """
                    SELECT message_id, session_id, created_by, user_message,
                           attachments_json, delivery_mode, status,
                           target_task_id, final_task_id, queue_position,
                           error_message, delivered_at, created_at, updated_at,
                           dispatch_payload_json, dispatch_attempt_id,
                           dispatch_attempted_at, broker_enqueued_at
                    FROM agent_session_messages
                    WHERE session_id=%s AND delivery_mode='queue' AND status='queued'
                    ORDER BY queue_position ASC, id ASC
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (session_id,),
                )
                message = cursor.fetchone()
                if not message:
                    return None
                claimed_task_id = supplied_task_id or uuid.uuid4().hex
                dispatch_attempt_id = uuid.uuid4().hex
                turn_index = max(1, int(session.get("turn_count") or 1)) + 1
                base_runtime_checkpoint_id = claimed_task_id
                base_native_session_id = str(
                    session.get("native_session_id") or ""
                ).strip()
                if callable(prepare_runtime_checkpoint):
                    # 运行时 checkpoint 必须在持有会话行锁、尚未发布新 turn
                    # 时创建。只有创建成功才写入同名 baseline；恢复扫描看到
                    # dispatching turn 时便可确信该 checkpoint 已经发布。
                    prepare_runtime_checkpoint(session_id, claimed_task_id)
                dispatch_payload = _dispatch_payload_from_row(message)
                if bool(session.get("fresh_native_session_pending")):
                    dispatch_payload[_START_FRESH_NATIVE_SESSION_KEY] = True
                dispatch_payload_json = (
                    _json_text(dispatch_payload, {}) if dispatch_payload else None
                )
                cursor.execute(
                    """
                    INSERT INTO agent_session_turns (
                        session_id, task_id, turn_index, user_message,
                        attachments_json, base_runtime_checkpoint_id,
                        base_native_session_id, status
                    ) VALUES (%s, %s, %s, %s, %s, %s,
                              NULLIF(%s, ''), 'Pending')
                    """,
                    (
                        session_id,
                        claimed_task_id,
                        turn_index,
                        message.get("user_message"),
                        message.get("attachments_json") or "[]",
                        base_runtime_checkpoint_id,
                        base_native_session_id,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE agent_session_messages
                    SET status='dispatching', final_task_id=%s,
                        dispatch_payload_json=%s,
                        dispatch_attempt_id=%s,
                        dispatch_attempted_at=CURRENT_TIMESTAMP,
                        broker_enqueued_at=NULL,
                        error_message=NULL
                    WHERE session_id=%s AND message_id=%s
                      AND delivery_mode='queue' AND status='queued'
                    """,
                    (
                        claimed_task_id,
                        dispatch_payload_json,
                        dispatch_attempt_id,
                        session_id,
                        message.get("message_id"),
                    ),
                )
                if cursor.rowcount <= 0:
                    raise AgentSessionMessageConflictError("Agent 队首已被其它任务领取")
                cursor.execute(
                    """
                    UPDATE agent_sessions
                    SET current_task_id=%s, status='Pending', message='任务排队中',
                        turn_count=%s, fresh_native_session_pending=0
                    WHERE session_id=%s
                    """,
                    (claimed_task_id, turn_index, session_id),
                )
                message = dict(message)
                message["status"] = "dispatching"
                message["final_task_id"] = claimed_task_id
                message["dispatch_payload_json"] = dispatch_payload_json
                message["dispatch_attempt_id"] = dispatch_attempt_id
                message["base_runtime_checkpoint_id"] = (
                    base_runtime_checkpoint_id
                )
                message["previous_base_runtime_checkpoint_id"] = str(
                    session.get("previous_base_runtime_checkpoint_id") or ""
                ).strip()
                message["base_native_session_id"] = base_native_session_id
                message["retry_of_task_id"] = ""
                result = _claim_payload(
                    session,
                    message,
                    turn_index,
                    newly_promoted=True,
                )
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def claim_next_agent_session_steer(session_id, *, task_id):
    """原子领取当前任务的一条软插话，供持有 harness 控制通道的 worker 投递。"""

    session_id = _normalize_session_id(session_id)
    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT current_task_id, status
                FROM agent_sessions
                WHERE session_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (session_id,),
            )
            session = cursor.fetchone()
            if not session:
                raise AgentSessionMessageNotFoundError("Agent 会话不存在")
            if str(session.get("current_task_id") or "") != task_id:
                raise AgentSessionMessageConflictError("Agent 当前任务已变化")
            if str(session.get("status") or "").strip().lower() in _TERMINAL_SESSION_STATUSES:
                raise AgentSessionMessageConflictError("Agent 当前任务已经结束")
            cursor.execute(
                """
                SELECT message_id, session_id, created_by, user_message,
                       attachments_json, delivery_mode, status,
                       target_task_id, final_task_id, queue_position,
                       error_message, delivered_at, created_at, updated_at
                FROM agent_session_messages
                WHERE session_id=%s AND delivery_mode='steer'
                  AND status='queued' AND target_task_id=%s
                ORDER BY queue_position ASC, id ASC
                LIMIT 1
                FOR UPDATE
                """,
                (session_id, task_id),
            )
            message = cursor.fetchone()
            if not message:
                return None
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET status='dispatching', error_message=NULL
                WHERE message_id=%s AND status='queued'
                """,
                (message.get("message_id"),),
            )
            if cursor.rowcount <= 0:
                raise AgentSessionMessageConflictError("Agent 插话已被其它 worker 领取")
            message = dict(message)
            message["status"] = "dispatching"
            result = _message_from_row(message)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finish_agent_session_message_delivery(
    message_id,
    *,
    status,
    task_id=None,
    error_message="",
):
    """确认一次 harness 消息投递终态；相同终态重复确认是幂等的。"""

    message_id = normalize_agent_message_id(message_id)
    normalized_status = str(status or "").strip().lower()
    if normalized_status not in _FINAL_DELIVERY_STATUSES:
        raise ValueError("Agent 消息投递终态无效")
    expected_task_id = _normalize_task_id(task_id, required=False)
    error = str(error_message or "").strip()[:4000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT status, target_task_id, final_task_id
                FROM agent_session_messages
                WHERE message_id=%s
                LIMIT 1
                FOR UPDATE
                """,
                (message_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise AgentSessionMessageNotFoundError("Agent 消息不存在")
            linked_task_id = str(row.get("final_task_id") or row.get("target_task_id") or "")
            if expected_task_id and linked_task_id != expected_task_id:
                raise AgentSessionMessageConflictError("Agent 消息目标任务已变化")
            current_status = str(row.get("status") or "").lower()
            if current_status == normalized_status:
                return True
            if current_status != "dispatching":
                raise AgentSessionMessageConflictError("Agent 消息不在投递中")
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET status=%s, error_message=%s,
                    delivered_at=CASE WHEN %s='sent' THEN CURRENT_TIMESTAMP ELSE delivered_at END
                WHERE message_id=%s AND status='dispatching'
                """,
                (normalized_status, error or None, normalized_status, message_id),
            )
            if cursor.rowcount <= 0:
                raise AgentSessionMessageConflictError("Agent 消息投递状态已变化")
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def sync_agent_message_state_in_transaction(cursor, *, task_id, status, reason=""):
    """在会话快照事务内收束首消息与尚未确认的插话。"""

    task_id = _normalize_task_id(task_id)
    normalized_status = str(status or "").strip().lower()
    if normalized_status in {
        "running",
        "completed",
        "failed",
        "cleanupfailed",
        "cleanup_failed",
    }:
        cursor.execute(
            """
            UPDATE agent_session_messages
            SET status='sent', delivered_at=COALESCE(delivered_at, CURRENT_TIMESTAMP),
                error_message=NULL
            WHERE final_task_id=%s AND delivery_mode IN ('turn','queue')
              AND status='dispatching'
            """,
            (task_id,),
        )
    elif normalized_status in {"canceled", "cancelled"}:
        # 若 worker 已进入 Running，同一事务早已把消息标成 sent；仍为
        # dispatching 说明取消发生在 broker/worker 确认之前。保留 canceled
        # 才能准确表达“已提升为 turn，但实际未投递”，且该轮成本自然为零。
        cursor.execute(
            """
            UPDATE agent_session_messages
            SET status='canceled', error_message=%s
            WHERE final_task_id=%s AND delivery_mode IN ('turn','queue')
              AND status='dispatching'
            """,
            (str(reason or "Agent 当前任务已取消")[:4000], task_id),
        )
    if normalized_status in _TERMINAL_SESSION_STATUSES:
        terminal_reason = str(reason or "Agent 当前任务已经结束")[:4000]
        cursor.execute(
            """
            UPDATE agent_session_messages
            SET status='failed', error_message=%s
            WHERE target_task_id=%s AND delivery_mode='steer' AND status='queued'
            """,
            (terminal_reason, task_id),
        )
        cursor.execute(
            """
            UPDATE agent_session_messages
            SET status='unknown', error_message=%s
            WHERE target_task_id=%s AND delivery_mode='steer' AND status='dispatching'
            """,
            (terminal_reason, task_id),
        )


__all__ = [
    "AgentSessionMessageConflictError",
    "AgentSessionMessageError",
    "AgentSessionMessageNotFoundError",
    "cancel_queued_agent_session_message",
    "claim_next_agent_session_message",
    "claim_next_agent_session_steer",
    "continue_agent_session_queue",
    "enqueue_agent_session_message",
    "finish_agent_session_message_delivery",
    "get_agent_session_message",
    "get_agent_session_queue_snapshot",
    "insert_turn_message_in_transaction",
    "list_agent_session_messages",
    "list_agent_session_queue_recovery_candidates",
    "mark_agent_session_message_broker_enqueued",
    "mark_agent_session_steers_unknown_for_task",
    "normalize_agent_message_id",
    "pause_agent_session_queue",
    "reorder_queued_agent_session_messages",
    "release_agent_session_message_dispatch_attempt",
    "set_agent_session_queue_paused",
    "sync_agent_message_state_in_transaction",
    "update_queued_agent_session_message",
]
