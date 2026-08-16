"""通用 Agent 的站点级运行参数。"""

from __future__ import annotations

from oj_modules.infrastructure.mysql import get_db_connection


AGENT_CONCURRENCY_SETTING_KEY = "AGENT_CONCURRENCY_LIMIT"
AGENT_CONCURRENCY_MIN = 1
AGENT_CONCURRENCY_MAX = 100
AGENT_CONCURRENCY_DEFAULT = 8


class AgentRuntimeSettingsError(RuntimeError):
    """Agent 运行参数的可预期业务错误。"""

    status_code = 400
    code = "agent_runtime_settings_error"


class AgentRuntimeSettingsValidationError(AgentRuntimeSettingsError):
    code = "agent_runtime_settings_validation_error"


def normalize_agent_concurrency_limit(value):
    """返回严格位于支持范围内的并发上限。"""

    if isinstance(value, bool):
        raise AgentRuntimeSettingsValidationError("Agent 并发上限必须是 1 到 100 的整数")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise AgentRuntimeSettingsValidationError(
            "Agent 并发上限必须是 1 到 100 的整数"
        ) from None
    if (
        str(value).strip() != str(parsed)
        or not AGENT_CONCURRENCY_MIN <= parsed <= AGENT_CONCURRENCY_MAX
    ):
        raise AgentRuntimeSettingsValidationError("Agent 并发上限必须是 1 到 100 的整数")
    return parsed


def get_agent_concurrency_limit():
    """读取全站 Agent 并发上限；未配置时返回兼容默认值。"""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT v FROM site_settings WHERE k=%s",
                (AGENT_CONCURRENCY_SETTING_KEY,),
            )
            row = cursor.fetchone()
        if not row:
            return AGENT_CONCURRENCY_DEFAULT
        return normalize_agent_concurrency_limit(row.get("v"))
    finally:
        conn.close()


def set_agent_concurrency_limit(limit):
    """持久化全站 Agent 并发上限并返回规范化后的值。"""

    normalized = normalize_agent_concurrency_limit(limit)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_settings (k, v) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE v=VALUES(v)
                """,
                (AGENT_CONCURRENCY_SETTING_KEY, str(normalized)),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return normalized


__all__ = [
    "AGENT_CONCURRENCY_DEFAULT",
    "AGENT_CONCURRENCY_MAX",
    "AGENT_CONCURRENCY_MIN",
    "AGENT_CONCURRENCY_SETTING_KEY",
    "AgentRuntimeSettingsError",
    "AgentRuntimeSettingsValidationError",
    "get_agent_concurrency_limit",
    "normalize_agent_concurrency_limit",
    "set_agent_concurrency_limit",
]
