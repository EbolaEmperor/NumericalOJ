#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""普通用户自有 Agent 模型端点。"""

from __future__ import annotations

from datetime import datetime

from oj_modules.agents.endpoint_egress import (
    AgentEndpointEgressError,
    pinned_requests_session,
    resolve_public_endpoint_url,
)
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.site_config import services as config_service


def _positive_id(value, label):
    if isinstance(value, bool):
        raise config_service.DynamicConfigValidationError(f"{label}无效")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise config_service.DynamicConfigValidationError(f"{label}无效") from None
    if parsed <= 0:
        raise config_service.DynamicConfigValidationError(f"{label}无效")
    return parsed


def _candidate_from_row(row):
    if not row:
        return None
    return {
        "protocol": row.get("protocol"),
        "category": "text",
        "base_url": row.get("base_url"),
        "api_key": row.get("api_key"),
        "model": row.get("model"),
        "thinking_enabled": bool(row.get("thinking_enabled")),
        "thinking_format": row.get("thinking_format") or "none",
        # 自有端点不参与额度扣减；零价只用于复用全站端点的协议校验器。
        "input_price_per_million": "0",
        "cached_input_price_per_million": "0",
        "output_price_per_million": "0",
    }


def normalize_user_agent_endpoint_payload(payload, *, existing=None):
    raw = dict(payload or {})
    name = str(raw.get("name", (existing or {}).get("name") or "")).strip()
    if not name:
        raise config_service.DynamicConfigValidationError("端点名称不能为空")
    if len(name) > 100:
        raise config_service.DynamicConfigValidationError("端点名称不能超过 100 个字符")
    raw["category"] = "text"
    raw["input_price_per_million"] = "0"
    raw["cached_input_price_per_million"] = "0"
    raw["output_price_per_million"] = "0"
    candidate = config_service.normalize_llm_endpoint_payload(
        raw,
        existing=_candidate_from_row(existing),
    )
    return {
        "name": name,
        **{
            key: candidate[key]
            for key in (
            "protocol",
            "category",
            "base_url",
            "api_key",
            "model",
            "thinking_enabled",
            "thinking_format",
            )
        },
    }


def test_user_agent_endpoint(candidate, *, egress_target, timeout_seconds=30):
    """通过冻结公网 IP 的连接测试普通用户端点。"""

    from oj_modules.ai.endpoints import test_endpoint_candidate

    with pinned_requests_session(egress_target) as session:
        return test_endpoint_candidate(
            candidate,
            timeout=timeout_seconds,
            request_post=session.post,
        )


def _public_endpoint(row, *, include_secret=False):
    if not row:
        return None
    secret = str(row.get("api_key") or "")
    endpoint_id = int(row["id"])
    result = {
        "id": endpoint_id,
        "ref": f"user:{endpoint_id}",
        "source": "user",
        "name": str(row.get("name") or row.get("model") or ""),
        "protocol": str(row.get("protocol") or ""),
        "category": "text",
        "base_url": str(row.get("base_url") or ""),
        "model": str(row.get("model") or ""),
        "thinking_enabled": bool(row.get("thinking_enabled")),
        "thinking_format": str(row.get("thinking_format") or "none"),
        "revision": int(row.get("revision") or 1),
        "test_status": str(row.get("test_status") or "untested"),
        "test_message": str(row.get("test_message") or ""),
        "test_latency_ms": row.get("test_latency_ms"),
        "tested_at": row.get("tested_at"),
        "api_key_configured": bool(secret),
        "api_key": secret if include_secret else "",
        "is_personal": True,
        "metered": False,
    }
    return result


def list_user_agent_endpoints(user_id, *, include_secrets=False):
    user_id = _positive_id(user_id, "用户 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT * FROM agent_user_endpoints
                WHERE user_id=%s
                ORDER BY model ASC, id ASC
                """,
                (user_id,),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()
    return [
        _public_endpoint(row, include_secret=include_secrets)
        for row in rows
    ]


def get_user_agent_endpoint(
    endpoint_id,
    user_id,
    *,
    include_secret=False,
):
    endpoint_id = _positive_id(endpoint_id, "端点 ID")
    user_id = _positive_id(user_id, "用户 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM agent_user_endpoints WHERE id=%s AND user_id=%s",
                (endpoint_id, user_id),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        raise config_service.DynamicConfigNotFoundError("自有 Agent 端点不存在")
    return _public_endpoint(row, include_secret=include_secret)


def save_user_agent_endpoint(
    payload,
    *,
    user_id,
    tester,
    endpoint_id=None,
):
    """真实测试成功后创建或更新当前用户的端点。"""

    user_id = _positive_id(user_id, "用户 ID")
    endpoint_id = (
        _positive_id(endpoint_id, "端点 ID")
        if endpoint_id is not None
        else None
    )
    existing = None
    if endpoint_id is not None:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM agent_user_endpoints WHERE id=%s AND user_id=%s",
                    (endpoint_id, user_id),
                )
                existing = cursor.fetchone()
        finally:
            conn.close()
        if not existing:
            raise config_service.DynamicConfigNotFoundError("自有 Agent 端点不存在")

    candidate = normalize_user_agent_endpoint_payload(payload, existing=existing)
    try:
        egress_target = resolve_public_endpoint_url(candidate["base_url"])
    except AgentEndpointEgressError as exc:
        raise config_service.DynamicConfigValidationError(str(exc)) from None
    result = config_service.run_dynamic_config_tester(
        lambda tested: tester(tested, egress_target=egress_target),
        candidate,
    )
    if not result["passed"]:
        raise config_service.DynamicConfigTestFailedError(
            result["message"],
            result=result,
        )

    now = datetime.utcnow()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            values = (
                candidate["name"],
                candidate["protocol"],
                candidate["base_url"],
                candidate["api_key"],
                candidate["model"],
                int(candidate["thinking_enabled"]),
                candidate["thinking_format"],
                result["status"],
                result["message"],
                result["latency_ms"],
                now,
            )
            if endpoint_id is None:
                cursor.execute(
                    """
                    INSERT INTO agent_user_endpoints
                        (user_id, name, protocol, base_url, api_key, model,
                         thinking_enabled, thinking_format, test_status,
                         test_message, test_latency_ms, tested_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (user_id, *values),
                )
                endpoint_id = cursor.lastrowid
            else:
                cursor.execute(
                    """
                    UPDATE agent_user_endpoints
                    SET name=%s, protocol=%s, base_url=%s, api_key=%s, model=%s,
                        thinking_enabled=%s, thinking_format=%s,
                        test_status=%s, test_message=%s, test_latency_ms=%s,
                        tested_at=%s, revision=revision+1
                    WHERE id=%s AND user_id=%s AND revision=%s
                    """,
                    (*values, endpoint_id, user_id, int(existing["revision"])),
                )
                if cursor.rowcount != 1:
                    raise config_service.DynamicConfigConflictError(
                        "自有端点已被其它请求修改，请刷新后重试"
                    )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_user_agent_endpoint(endpoint_id, user_id)


def delete_user_agent_endpoint(endpoint_id, user_id):
    endpoint_id = _positive_id(endpoint_id, "端点 ID")
    user_id = _positive_id(user_id, "用户 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM agent_user_endpoints WHERE id=%s AND user_id=%s",
                (endpoint_id, user_id),
            )
            if cursor.rowcount != 1:
                raise config_service.DynamicConfigNotFoundError(
                    "自有 Agent 端点不存在"
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


__all__ = [
    "delete_user_agent_endpoint",
    "get_user_agent_endpoint",
    "list_user_agent_endpoints",
    "normalize_user_agent_endpoint_payload",
    "save_user_agent_endpoint",
    "test_user_agent_endpoint",
]
