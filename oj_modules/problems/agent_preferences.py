"""解题/造数据 Agent 启动选择的按用户持久化偏好。"""

from __future__ import annotations

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.problems.agent_launch import (
    AgentLaunchValidationError,
    normalize_launch_endpoint_ref,
    normalize_launch_harness,
)


def _positive_id(value, *, label, max_value):
    if isinstance(value, int) and not isinstance(value, bool):
        normalized = value
    elif isinstance(value, str):
        text = value.strip()
        if not text.isascii() or not text.isdigit():
            raise AgentLaunchValidationError(f"{label} 无效")
        normalized = int(text)
    else:
        raise AgentLaunchValidationError(f"{label} 无效")
    if normalized <= 0 or normalized > max_value:
        raise AgentLaunchValidationError(f"{label} 无效")
    return normalized


def _normalize_user_id(value):
    return _positive_id(value, label="用户 ID", max_value=2_147_483_647)


def _normalize_endpoint_id(value):
    return _positive_id(
        value,
        label="LLM 节点 ID",
        max_value=9_223_372_036_854_775_807,
    )


def _preference_from_row(row):
    if not row:
        return None
    preference = dict(row)
    preference["user_id"] = _normalize_user_id(preference["user_id"])
    preference["harness"] = normalize_launch_harness(preference["harness"])
    source = str(preference.get("endpoint_source") or "global").strip().lower()
    if source not in {"global", "user"}:
        raise AgentLaunchValidationError("LLM 节点来源无效")
    preference["endpoint_source"] = source
    preference["endpoint_id"] = _normalize_endpoint_id(
        preference["endpoint_id"]
    )
    preference["endpoint_ref"] = f"{source}:{preference['endpoint_id']}"
    return preference


def get_agent_launch_preference(user_id):
    """返回某用户上次选择的 harness 与节点；未保存时返回 None。"""

    user_id = _normalize_user_id(user_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    user_id,
                    harness,
                    endpoint_source,
                    endpoint_id,
                    created_at,
                    updated_at
                FROM agent_launch_preferences
                WHERE user_id=%s
                """,
                (user_id,),
            )
            return _preference_from_row(cursor.fetchone())
    finally:
        conn.close()


def save_agent_launch_preference(user_id, harness, endpoint_ref):
    """原子保存并返回某用户统一的 Agent 启动偏好。"""

    user_id = _normalize_user_id(user_id)
    harness = normalize_launch_harness(harness)
    try:
        endpoint_source, endpoint_id = normalize_launch_endpoint_ref(endpoint_ref)
    except AgentLaunchValidationError:
        raise AgentLaunchValidationError("LLM 节点 ID 无效") from None

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO agent_launch_preferences (
                    user_id,
                    harness,
                    endpoint_source,
                    endpoint_id
                ) VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    harness=VALUES(harness),
                    endpoint_source=VALUES(endpoint_source),
                    endpoint_id=VALUES(endpoint_id),
                    updated_at=CURRENT_TIMESTAMP
                """,
                (user_id, harness, endpoint_source, endpoint_id),
            )
            cursor.execute(
                """
                SELECT
                    user_id,
                    harness,
                    endpoint_source,
                    endpoint_id,
                    created_at,
                    updated_at
                FROM agent_launch_preferences
                WHERE user_id=%s
                """,
                (user_id,),
            )
            preference = _preference_from_row(cursor.fetchone())
            if preference is None:
                raise RuntimeError("Agent 启动偏好保存后无法读取")
        conn.commit()
        return preference
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


__all__ = [
    "get_agent_launch_preference",
    "save_agent_launch_preference",
]
