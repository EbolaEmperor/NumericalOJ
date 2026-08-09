"""通用 Agent 会话、轮次与旧任务兼容查询。"""

from __future__ import annotations

import json
import re

from oj_modules.infrastructure.mysql import get_db_connection


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


def _session_from_row(row):
    if not row:
        return None
    return {
        "session_id": row.get("session_id"),
        "current_task_id": row.get("current_task_id"),
        "title": str(row.get("title") or "").strip(),
        "task_kind": str(row.get("task_kind") or "custom"),
        "problem_id": row.get("problem_id"),
        "problem_title": row.get("problem_title"),
        "requested_by": row.get("requested_by"),
        "access_role": str(row.get("access_role") or "user"),
        "harness": row.get("harness"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": row.get("endpoint_model"),
        "native_session_id": str(row.get("native_session_id") or "").strip(),
        "status": str(row.get("status") or "Pending"),
        "message": row.get("message"),
        "turn_count": max(1, int(row.get("turn_count") or 1)),
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
        "harness": row.get("harness"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_model": row.get("endpoint_model"),
        "status": str(row.get("status") or "Pending"),
        "conclusion": str(row.get("conclusion") or ""),
        "created_at": _format_time(row.get("created_at")),
        "updated_at": _format_time(row.get("updated_at")),
    }


def create_agent_session(
    *,
    session_id,
    task_id,
    requested_by,
    harness,
    endpoint_id,
    endpoint_revision,
    endpoint_model,
    user_message,
    attachments=None,
    task_kind="custom",
    access_role="user",
    problem_id=None,
    problem_title=None,
    title="",
):
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    access_role = normalize_agent_access_role(access_role)
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

    session = {
        "session_id": session_id,
        "current_task_id": task_id,
        "title": str(title or "").strip()[:64],
        "task_kind": str(task_kind or "custom").strip().lower()[:32],
        "problem_id": problem_id,
        "problem_title": (
            str(problem_title or "")[:255]
            if problem_title is not None
            else None
        ),
        "requested_by": str(requested_by or "").strip()[:50],
        "access_role": access_role,
        "harness": str(harness or "").strip()[:32],
        "endpoint_id": endpoint_id,
        "endpoint_revision": endpoint_revision,
        "endpoint_model": str(endpoint_model or "").strip()[:255],
        "native_session_id": "",
        "status": "Pending",
        "message": "任务排队中",
        "turn_count": 1,
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
                    harness, endpoint_id, endpoint_revision, endpoint_model,
                    status, message,
                    turn_count
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, 'Pending', '任务排队中',
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
                    endpoint_id,
                    session["endpoint_revision"],
                    session["endpoint_model"],
                ),
            )
            cursor.execute(
                """
                INSERT INTO agent_session_turns (
                    session_id, task_id, turn_index, user_message,
                    attachments_json, status
                ) VALUES (%s, %s, 1, %s, %s, 'Pending')
                """,
                (session_id, task_id, message, _json_text(attachments, [])),
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
):
    session_id = normalize_agent_session_id(session_id)
    task_id = normalize_agent_session_id(task_id)
    message = str(user_message or "").strip()
    if not message:
        raise ValueError("Agent 消息不能为空")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT status, turn_count, task_kind, problem_id,
                       requested_by, access_role, harness, endpoint_id,
                       endpoint_revision, endpoint_model, native_session_id
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
            if not agent_status_is_terminal(row.get("status")):
                raise AgentSessionBusyError("上一轮 Agent 任务尚未结束")
            turn_index = max(1, int(row.get("turn_count") or 1)) + 1
            cursor.execute(
                """
                INSERT INTO agent_session_turns (
                    session_id, task_id, turn_index, user_message,
                    attachments_json, status
                ) VALUES (%s, %s, %s, %s, %s, 'Pending')
                """,
                (
                    session_id,
                    task_id,
                    turn_index,
                    message,
                    _json_text(attachments, []),
                ),
            )
            cursor.execute(
                """
                UPDATE agent_sessions
                SET current_task_id=%s, status='Pending', message='任务排队中',
                    turn_count=%s
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
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": row.get("endpoint_model"),
        "native_session_id": str(row.get("native_session_id") or "").strip(),
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
                SET status='Failed', message=%s
                WHERE session_id=%s AND current_task_id=%s
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
        return False
    cursor.execute(
        """
        UPDATE agent_sessions
        SET status=%s, message=%s,
            title=COALESCE(NULLIF(%s, ''), title),
            native_session_id=COALESCE(NULLIF(%s, ''), native_session_id)
        WHERE session_id=%s AND current_task_id=%s
        """,
        (
            status,
            message,
            title,
            native_session_id,
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
                       problem_id, problem_title, requested_by, access_role,
                       harness, endpoint_id, endpoint_revision, endpoint_model,
                       native_session_id, status, message, turn_count,
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
                       'user' AS access_role, harness, endpoint_id,
                       NULL AS endpoint_revision, endpoint_model,
                       NULL AS native_session_id,
                       status, message, 1 AS turn_count,
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
                       s.problem_id, s.problem_title, s.requested_by,
                       s.access_role, s.harness, s.endpoint_id,
                       s.endpoint_revision, s.endpoint_model,
                       s.native_session_id, s.status,
                       s.message, s.turn_count, s.created_at, s.updated_at,
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


def get_agent_session_turns(session_id):
    session_id = normalize_agent_session_id(session_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT t.task_id, t.turn_index, t.user_message,
                       t.attachments_json, t.status, t.conclusion,
                       r.harness, r.endpoint_id, r.endpoint_model,
                       t.created_at, t.updated_at
                FROM agent_session_turns AS t
                LEFT JOIN agent_task_runs AS r ON r.task_id=t.task_id
                WHERE t.session_id=%s
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
        "harness": legacy.get("harness"),
        "endpoint_id": legacy.get("endpoint_id"),
        "endpoint_model": legacy.get("endpoint_model"),
        "status": str(legacy.get("status") or "Pending"),
        "conclusion": str(legacy.get("message") or ""),
        "created_at": _format_time(legacy.get("created_at")),
        "updated_at": _format_time(legacy.get("updated_at")),
    }]


def get_agent_sessions_paginated(page=1, per_page=20):
    page = max(1, int(page))
    per_page = max(1, min(100, int(per_page)))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM agent_sessions)
                    +
                    (SELECT COUNT(*)
                     FROM agent_task_runs AS r
                     WHERE NOT EXISTS (
                         SELECT 1 FROM agent_session_turns AS t
                         WHERE t.task_id=r.task_id
                     )) AS total
                """
            )
            total = int((cursor.fetchone() or {}).get("total") or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(page, total_pages)
            cursor.execute(
                """
                SELECT *
                FROM (
                    SELECT s.id AS source_id, s.session_id,
                           s.current_task_id, s.title, s.task_kind,
                           s.problem_id, s.problem_title, s.requested_by,
                           s.access_role, s.harness, s.endpoint_id,
                           s.endpoint_revision, s.endpoint_model,
                           s.native_session_id, s.status,
                           s.message, s.turn_count, s.created_at, s.updated_at,
                           0 AS is_legacy
                    FROM agent_sessions AS s
                    UNION ALL
                    SELECT r.id AS source_id, r.task_id AS session_id,
                           r.task_id AS current_task_id,
                           r.problem_title AS title, 'legacy' AS task_kind,
                           r.problem_id, r.problem_title, r.requested_by,
                           'user' AS access_role, r.harness, r.endpoint_id,
                           NULL AS endpoint_revision, r.endpoint_model,
                           NULL AS native_session_id,
                           r.status, r.message, 1 AS turn_count,
                           r.created_at, r.updated_at, 1 AS is_legacy
                    FROM agent_task_runs AS r
                    WHERE NOT EXISTS (
                        SELECT 1 FROM agent_session_turns AS t
                        WHERE t.task_id=r.task_id
                    )
                ) AS sessions
                ORDER BY updated_at DESC, is_legacy ASC,
                         source_id DESC, session_id DESC
                LIMIT %s OFFSET %s
                """,
                (per_page, (page - 1) * per_page),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()
    return [_session_from_row(row) for row in rows], page, total_pages


__all__ = [
    "AgentSessionBusyError",
    "AgentSessionError",
    "AgentSessionNotFoundError",
    "agent_status_is_terminal",
    "begin_agent_session_turn",
    "claim_agent_session_title_generation",
    "create_agent_session",
    "get_agent_session",
    "get_agent_session_by_task_id",
    "get_agent_session_turns",
    "get_agent_sessions_paginated",
    "mark_agent_turn_enqueue_failed",
    "normalize_agent_access_role",
    "normalize_agent_session_id",
    "set_agent_turn_attachments",
    "sync_agent_session_state",
    "sync_agent_session_state_in_transaction",
    "update_agent_session_title",
]
