"""Agent v2 轨迹事件的持久化、公开时间线与工作块查询。"""

from __future__ import annotations

import hashlib
import json
import re

from oj_modules.infrastructure.mysql import get_db_connection


AGENT_TRACE_SCHEMA_VERSION = 2

_TASK_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_BLOCK_ID_RE = re.compile(r"work-[0-9a-f]{16}")
_TRACE_KINDS = frozenset({
    "assistant", "thinking", "reasoning", "tool", "tool_call",
    "tool_result", "tool-result", "subagent",
})
_TERMINAL_STATUSES = frozenset({
    "completed", "failed", "canceled", "cancelled", "cleanupfailed",
    "cleanup_failed",
})
_MAX_PUBLIC_TEXT = 64 * 1024
_MAX_INTERNAL_TEXT = 1200
_TOKEN_USAGE_COUNTER_FIELDS = (
    "request_count",
    "input_uncached_tokens",
    "input_cached_tokens",
    "input_cache_write_tokens",
    "input_total_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "cached_fallback_request_count",
    "cached_fallback_input_tokens",
    "last_input_total_tokens",
    "last_output_tokens",
)


class AgentTraceStoreError(RuntimeError):
    """Agent v2 轨迹无法持久化或读取。"""


def _normalize_task_id(value):
    task_id = str(value or "").strip()
    if not _TASK_ID_RE.fullmatch(task_id):
        raise ValueError("Agent task_id 无效")
    return task_id


def _normalize_block_id(value):
    block_id = str(value or "").strip()
    if not _BLOCK_ID_RE.fullmatch(block_id):
        raise ValueError("Agent 工作块 ID 无效")
    return block_id


def _event_storage_id(task_id, source_id):
    digest = hashlib.sha256(
        f"{task_id}\0{source_id}".encode("utf-8", "replace")
    ).hexdigest()[:24]
    return f"event-{digest}"


def _work_block_id(task_id, event_id):
    digest = hashlib.sha256(
        f"{task_id}\0{event_id}".encode("utf-8", "replace")
    ).hexdigest()[:16]
    return f"work-{digest}"


def _truncate_text(value, limit):
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:max(0, limit - 1)] + "…"


def _normalize_sequence(value):
    if isinstance(value, bool):
        raise ValueError("Agent 轨迹 sequence 无效")
    try:
        sequence = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Agent 轨迹 sequence 无效") from exc
    if sequence <= 0:
        raise ValueError("Agent 轨迹 sequence 无效")
    return sequence


def _normalize_canonical_record(task_id, record):
    if not isinstance(record, dict):
        return None
    try:
        version = int(record.get("version") or 0)
    except (TypeError, ValueError):
        return None
    if version != 1:
        return None
    sequence = _normalize_sequence(record.get("sequence"))
    record_type = str(record.get("type") or "").strip().lower()
    if record_type == "numoj_steer":
        message_id = str(record.get("message_id") or "").strip()
        if not _TASK_ID_RE.fullmatch(message_id):
            return None
        source_id = f"steer:{message_id}"
        return {
            "event_id": _event_storage_id(task_id, source_id),
            "event_order": sequence,
            "kind": "user",
            "title": "用户插话",
            "text": "",
            "meta": "",
            "format": "text",
            "is_error": False,
            "message_id": message_id,
        }
    if record_type != "numoj_trace":
        return None
    event = record.get("event")
    if not isinstance(event, dict):
        return None
    kind = str(event.get("kind") or "").strip().lower()
    if kind not in _TRACE_KINDS:
        return None
    source_id = str(event.get("id") or "").strip()
    if not source_id or len(source_id) > 512:
        return None
    text_limit = _MAX_PUBLIC_TEXT if kind == "assistant" else _MAX_INTERNAL_TEXT
    text = _truncate_text(event.get("text"), text_limit)
    if not text:
        return None
    return {
        "event_id": _event_storage_id(task_id, source_id),
        "event_order": sequence,
        "kind": kind,
        "title": _truncate_text(event.get("title"), 255),
        "text": text,
        "meta": _truncate_text(event.get("meta"), 255),
        "format": (
            str(event.get("format") or "text").strip().lower()
            if str(event.get("format") or "text").strip().lower()
            in {"text", "json"}
            else "text"
        ),
        "is_error": bool(event.get("is_error")),
        "message_id": None,
    }


def _ensure_sync_state(cursor, task_id):
    cursor.execute(
        """
        INSERT IGNORE INTO agent_trace_sync_state (
            task_id, schema_version, last_event_order, next_item_index
        ) VALUES (%s, %s, 0, 1)
        """,
        (task_id, AGENT_TRACE_SCHEMA_VERSION),
    )
    cursor.execute(
        """
        SELECT schema_version, last_event_order, next_item_index,
               active_block_id, active_item_index
        FROM agent_trace_sync_state
        WHERE task_id=%s
        LIMIT 1
        FOR UPDATE
        """,
        (task_id,),
    )
    state = cursor.fetchone()
    if not state:
        raise AgentTraceStoreError("无法创建 Agent 轨迹同步状态")
    if int(state.get("schema_version") or 0) != AGENT_TRACE_SCHEMA_VERSION:
        raise AgentTraceStoreError("Agent 轨迹存储版本不匹配")
    return state


def ingest_agent_trace_records(task_id, records, *, final=False):
    """幂等写入 adapter v1 事件，并建立 v2 时间线/工作块索引。"""

    task_id = _normalize_task_id(task_id)
    normalized = []
    for record in records or ():
        item = _normalize_canonical_record(task_id, record)
        if item is not None:
            normalized.append(item)
    normalized.sort(key=lambda item: item["event_order"])

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            state = _ensure_sync_state(cursor, task_id)
            last_order = max(0, int(state.get("last_event_order") or 0))
            next_item_index = max(1, int(state.get("next_item_index") or 1))
            active_block_id = str(state.get("active_block_id") or "").strip()
            active_item_index = state.get("active_item_index")
            active_item_index = (
                max(1, int(active_item_index))
                if active_item_index is not None
                else None
            )

            inserted = 0
            for event in normalized:
                event_order = int(event["event_order"])
                if event_order <= last_order:
                    continue
                kind = event["kind"]
                is_internal = kind not in {"assistant", "user"}
                if is_internal:
                    candidate_block_id = active_block_id or _work_block_id(
                        task_id, event["event_id"]
                    )
                    candidate_item_index = (
                        active_item_index
                        if active_item_index is not None
                        else next_item_index
                    )
                else:
                    candidate_block_id = None
                    candidate_item_index = next_item_index

                cursor.execute(
                    """
                    INSERT IGNORE INTO agent_trace_events (
                        task_id, event_id, event_order, item_index, block_id,
                        kind, title, text, meta, format, is_error, message_id
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        task_id,
                        event["event_id"],
                        event_order,
                        candidate_item_index,
                        candidate_block_id,
                        kind,
                        event["title"],
                        event["text"],
                        event["meta"],
                        event["format"],
                        1 if event["is_error"] else 0,
                        event["message_id"],
                    ),
                )
                last_order = event_order
                if cursor.rowcount <= 0:
                    continue
                inserted += 1
                if is_internal:
                    if not active_block_id:
                        active_block_id = candidate_block_id
                        active_item_index = candidate_item_index
                        next_item_index += 1
                else:
                    active_block_id = ""
                    active_item_index = None
                    next_item_index += 1

            if final:
                active_block_id = ""
                active_item_index = None
            cursor.execute(
                """
                UPDATE agent_trace_sync_state
                SET last_event_order=%s, next_item_index=%s,
                    active_block_id=%s, active_item_index=%s
                WHERE task_id=%s
                """,
                (
                    last_order,
                    next_item_index,
                    active_block_id or None,
                    active_item_index,
                    task_id,
                ),
            )
        conn.commit()
        return inserted
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _work_summary(thinking_count, tool_count, is_running):
    parts = []
    thinkings = int(thinking_count)
    calls = int(tool_count)
    if thinkings > 0:
        parts.append(f"{thinkings} thinking" + ("" if thinkings == 1 else "s"))
    if calls > 0:
        parts.append(f"{calls} tool call" + ("" if calls == 1 else "s"))
    prefix = "工作中…" if is_running else ""
    summary = ", ".join(parts)
    return f"{prefix}{summary}" if summary else prefix


def list_agent_trace_timeline(task_id, *, status="", steer_records=()):
    """只返回公开回复、用户插话锚点和工作块计数摘要。"""

    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT item_index, event_order, event_id, kind, text, message_id
                FROM agent_trace_events
                WHERE task_id=%s AND block_id IS NULL
                  AND kind IN ('assistant','user')
                ORDER BY item_index ASC, event_order ASC
                """,
                (task_id,),
            )
            public_rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT item_index, block_id, MIN(event_order) AS event_order,
                       SUM(kind IN ('thinking','reasoning')) AS thinking_count,
                       SUM(kind IN ('tool','tool_call','subagent')) AS tool_count,
                       MAX(is_error) AS has_error
                FROM agent_trace_events
                WHERE task_id=%s AND block_id IS NOT NULL
                GROUP BY item_index, block_id
                ORDER BY item_index ASC
                """,
                (task_id,),
            )
            block_rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT active_block_id
                FROM agent_trace_sync_state
                WHERE task_id=%s
                LIMIT 1
                """,
                (task_id,),
            )
            sync_state = cursor.fetchone() or {}
    finally:
        conn.close()

    steer_by_id = {
        str(record.get("message_id") or "").strip(): record
        for record in steer_records or ()
        if isinstance(record, dict)
        and str(record.get("message_id") or "").strip()
    }
    items = []
    for row in public_rows:
        kind = str(row.get("kind") or "")
        if kind not in {"assistant", "user"}:
            continue
        item = {
            "kind": kind,
            "item_id": str(row.get("event_id") or ""),
            "item_index": int(row.get("item_index") or 0),
            "event_order": int(row.get("event_order") or 0),
        }
        if kind == "assistant":
            item["text"] = str(row.get("text") or "")
        elif kind == "user":
            message_id = str(row.get("message_id") or "").strip()
            record = steer_by_id.get(message_id)
            if not record:
                continue
            item.update({
                "message_id": message_id,
                "text": str(
                    record.get("user_message") or record.get("message") or ""
                ),
                "attachments": list(record.get("attachments") or ()),
            })
        items.append(item)

    terminal = str(status or "").strip().lower() in _TERMINAL_STATUSES
    active_block_id = str(sync_state.get("active_block_id") or "").strip()
    for row in block_rows:
        block_id = str(row.get("block_id") or "")
        thinking_count = max(0, int(row.get("thinking_count") or 0))
        tool_count = max(0, int(row.get("tool_count") or 0))
        is_running = bool(not terminal and block_id == active_block_id)
        items.append({
            "kind": "work_summary",
            "item_id": block_id,
            "block_id": block_id,
            "item_index": int(row.get("item_index") or 0),
            "event_order": int(row.get("event_order") or 0),
            "thinking_count": thinking_count,
            "tool_count": tool_count,
            "is_running": is_running,
            "has_error": bool(row.get("has_error")),
            "summary": _work_summary(thinking_count, tool_count, is_running),
        })

    items.sort(key=lambda item: (item["item_index"], item["event_order"]))
    if str(status or "").strip().lower() == "completed":
        for index in range(len(items) - 1, -1, -1):
            if items[index].get("kind") == "assistant":
                del items[index]
                break
    return items


def get_agent_trace_work_block(task_id, block_id):
    task_id = _normalize_task_id(task_id)
    block_id = _normalize_block_id(block_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT kind, title, text, meta, format, is_error, event_order
                FROM agent_trace_events
                WHERE task_id=%s AND block_id=%s
                  AND kind NOT IN ('assistant','user')
                ORDER BY event_order ASC
                """,
                (task_id, block_id),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()
    if not rows:
        return None
    messages = []
    for row in rows:
        message = {
            "kind": str(row.get("kind") or ""),
            "title": str(row.get("title") or ""),
            "text": str(row.get("text") or ""),
            "meta": str(row.get("meta") or ""),
            "format": str(row.get("format") or "text"),
        }
        if bool(row.get("is_error")):
            message["is_error"] = True
        messages.append(message)
    return {"block_id": block_id, "messages": messages}


def get_last_agent_trace_assistant(task_id):
    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT text
                FROM agent_trace_events
                WHERE task_id=%s AND kind='assistant'
                ORDER BY event_order DESC
                LIMIT 1
                """,
                (task_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    return str((row or {}).get("text") or "").strip()


def _normalized_token_usage(usage):
    if not isinstance(usage, dict):
        return None
    normalized = {}
    for field in _TOKEN_USAGE_COUNTER_FIELDS:
        value = usage.get(field)
        if value is None and field.startswith("last_"):
            normalized[field] = None
            continue
        if isinstance(value, bool):
            value = 0
        try:
            normalized[field] = max(0, int(value or 0))
        except (TypeError, ValueError):
            normalized[field] = 0
    if normalized["request_count"] <= 0:
        return None
    normalized["input_total_tokens"] = sum(
        normalized[field]
        for field in (
            "input_uncached_tokens",
            "input_cached_tokens",
            "input_cache_write_tokens",
        )
    )
    normalized["source"] = _truncate_text(usage.get("source"), 32)
    if usage.get("incremental") is True:
        normalized["incremental"] = True
    return normalized


def save_agent_trace_token_usage(task_id, usage):
    """保存 worker 从当前规范 journal 汇总出的用量快照。"""

    task_id = _normalize_task_id(task_id)
    normalized = _normalized_token_usage(usage)
    if normalized is None:
        return False
    payload = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _ensure_sync_state(cursor, task_id)
            cursor.execute(
                """
                UPDATE agent_trace_sync_state
                SET token_usage_json=%s
                WHERE task_id=%s
                  AND NOT (token_usage_json <=> %s)
                """,
                (payload, task_id, payload),
            )
            changed = cursor.rowcount > 0
        conn.commit()
        return changed
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_agent_trace_token_usage(task_id):
    task_id = _normalize_task_id(task_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT token_usage_json
                FROM agent_trace_sync_state
                WHERE task_id=%s AND schema_version=%s
                LIMIT 1
                """,
                (task_id, AGENT_TRACE_SCHEMA_VERSION),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    try:
        usage = json.loads(str((row or {}).get("token_usage_json") or ""))
    except (TypeError, ValueError):
        return None
    return _normalized_token_usage(usage)


__all__ = [
    "AGENT_TRACE_SCHEMA_VERSION",
    "AgentTraceStoreError",
    "get_agent_trace_work_block",
    "get_agent_trace_token_usage",
    "get_last_agent_trace_assistant",
    "ingest_agent_trace_records",
    "list_agent_trace_timeline",
    "save_agent_trace_token_usage",
]
