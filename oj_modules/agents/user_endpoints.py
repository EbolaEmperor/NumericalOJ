#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""普通用户自有 Agent 模型端点。"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta

from oj_modules.agents.endpoint_egress import (
    AgentEndpointEgressError,
    pinned_requests_session,
    resolve_public_endpoint_url,
)
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.site_config import services as config_service


USER_ENDPOINT_TEST_GRANT_KIND = "user_agent_endpoint"
USER_ENDPOINT_TEST_GRANT_TTL_SECONDS = 10 * 60


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
        "category": row.get("category") or "text",
        "base_url": row.get("base_url"),
        "api_key": row.get("api_key"),
        "model": row.get("model"),
        "context_window_tokens": int(
            row.get("context_window_tokens")
            or config_service.DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
        ),
        "max_output_tokens": int(
            row.get("max_output_tokens")
            or config_service.DEFAULT_LLM_MAX_OUTPUT_TOKENS
        ),
        "thinking_enabled": bool(row.get("thinking_enabled")),
        "thinking_format": row.get("thinking_format") or "none",
        # 个人端点不参与平台计费，价格只用于复用全站端点校验器。
        **{field: "0" for field in config_service.LLM_PRICE_FIELDS},
    }


def normalize_user_agent_endpoint_payload(payload, *, existing=None):
    raw = dict(payload or {})
    # 用户自带密钥不扣平台额度，也不记录展示价格。
    for field in config_service.LLM_PRICE_FIELDS:
        raw[field] = "0"
    candidate = config_service.normalize_llm_endpoint_payload(
        raw,
        existing=_candidate_from_row(existing),
    )
    # name 是个人端点旧版 UI 的兼容字段。新版与全站端点共用同一套字段，
    # 未显式提供显示名称时直接使用模型名，避免继续维护额外表单分支。
    name = str(raw.get("name") or candidate["model"]).strip()
    if len(name) > 255:
        raise config_service.DynamicConfigValidationError("端点名称不能超过 255 个字符")
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
                "context_window_tokens",
                "max_output_tokens",
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
            request_get=session.get,
            request_post=session.post,
        )


def _owned_endpoint_row(endpoint_id, user_id):
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
    return row


def _test_candidate(candidate, tester):
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
    return result


def _candidate_fingerprint(candidate):
    encoded = json.dumps(
        candidate,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _validate_test_grant(
    cursor,
    *,
    token,
    endpoint_id,
    base_revision,
    fingerprint,
    user_id,
):
    if not str(token or "").strip():
        raise config_service.DynamicConfigValidationError(
            "保存前必须先通过真实连接测试"
        )
    cursor.execute(
        "SELECT * FROM dynamic_config_test_grants WHERE token_hash=%s FOR UPDATE",
        (_token_hash(token),),
    )
    grant = cursor.fetchone()
    if not grant:
        raise config_service.DynamicConfigValidationError(
            "测试凭证无效，请重新测试"
        )
    target_matches = (
        (endpoint_id is None and grant.get("target_id") is None)
        or int(grant.get("target_id") or 0) == int(endpoint_id or 0)
    )
    if (
        grant.get("config_kind") != USER_ENDPOINT_TEST_GRANT_KIND
        or not target_matches
        or int(grant.get("base_revision") or 0) != int(base_revision)
        or grant.get("payload_fingerprint") != fingerprint
        or int(grant.get("created_by_user_id") or 0) != int(user_id)
        or grant.get("status") != "passed"
    ):
        raise config_service.DynamicConfigConflictError(
            "配置已变化或测试凭证不匹配，请重新测试"
        )
    if grant.get("consumed_at") is not None:
        raise config_service.DynamicConfigConflictError(
            "测试凭证已使用，请重新测试"
        )
    expires_at = grant.get("expires_at")
    if not expires_at or expires_at < datetime.utcnow():
        raise config_service.DynamicConfigConflictError(
            "测试凭证已过期，请重新测试"
        )
    return grant


def test_user_agent_endpoint_payload(
    payload,
    *,
    user_id,
    tester,
    endpoint_id=None,
):
    """测试与当前用户已有端点合并后的完整候选配置。"""

    user_id = _positive_id(user_id, "用户 ID")
    endpoint_id = (
        _positive_id(endpoint_id, "端点 ID")
        if endpoint_id is not None
        else None
    )
    existing = (
        _owned_endpoint_row(endpoint_id, user_id)
        if endpoint_id is not None
        else None
    )
    candidate = normalize_user_agent_endpoint_payload(payload, existing=existing)
    result = _test_candidate(candidate, tester)
    effective_candidate = config_service.apply_llm_endpoint_test_limits(
        candidate,
        result,
    )
    result["context_window_tokens"] = effective_candidate[
        "context_window_tokens"
    ]
    result["max_output_tokens"] = effective_candidate["max_output_tokens"]
    result["limits_adjusted"] = any(
        effective_candidate[field] != candidate[field]
        for field in config_service.LLM_CAPACITY_FIELDS
    )
    token = secrets.token_urlsafe(32)
    now = datetime.utcnow()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO dynamic_config_test_grants
                    (token_hash, config_kind, target_id, base_revision,
                     payload_fingerprint, status, test_message, test_latency_ms,
                     created_by_user_id, created_at, expires_at)
                VALUES (%s, %s, %s, %s, %s, 'passed', %s, %s, %s, %s, %s)
                """,
                (
                    _token_hash(token),
                    USER_ENDPOINT_TEST_GRANT_KIND,
                    endpoint_id,
                    int((existing or {}).get("revision") or 0),
                    _candidate_fingerprint(effective_candidate),
                    result["message"],
                    result["latency_ms"],
                    user_id,
                    now,
                    now + timedelta(seconds=USER_ENDPOINT_TEST_GRANT_TTL_SECONDS),
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    result["test_token"] = token
    result["expires_in_seconds"] = USER_ENDPOINT_TEST_GRANT_TTL_SECONDS
    return result


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
        "category": str(row.get("category") or "text"),
        "base_url": str(row.get("base_url") or ""),
        "model": str(row.get("model") or ""),
        "context_window_tokens": int(
            row.get("context_window_tokens")
            or config_service.DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
        ),
        "max_output_tokens": int(
            row.get("max_output_tokens")
            or config_service.DEFAULT_LLM_MAX_OUTPUT_TOKENS
        ),
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
    test_token,
    endpoint_id=None,
):
    """消费与候选配置完全匹配的一次性测试凭证后保存端点。"""

    user_id = _positive_id(user_id, "用户 ID")
    endpoint_id = (
        _positive_id(endpoint_id, "端点 ID")
        if endpoint_id is not None
        else None
    )
    existing = None
    if endpoint_id is not None:
        existing = _owned_endpoint_row(endpoint_id, user_id)

    candidate = normalize_user_agent_endpoint_payload(payload, existing=existing)
    fingerprint = _candidate_fingerprint(candidate)
    base_revision = int((existing or {}).get("revision") or 0)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            grant = _validate_test_grant(
                cursor,
                token=test_token,
                endpoint_id=endpoint_id,
                base_revision=base_revision,
                fingerprint=fingerprint,
                user_id=user_id,
            )
            tested_at = grant.get("created_at") or datetime.utcnow()
            values = (
                candidate["name"],
                candidate["protocol"],
                candidate["category"],
                candidate["base_url"],
                candidate["api_key"],
                candidate["model"],
                candidate["context_window_tokens"],
                candidate["max_output_tokens"],
                int(candidate["thinking_enabled"]),
                candidate["thinking_format"],
                grant["test_message"],
                grant["test_latency_ms"],
                tested_at,
            )
            if endpoint_id is None:
                cursor.execute(
                    """
                    INSERT INTO agent_user_endpoints
                        (user_id, name, protocol, category, base_url, api_key,
                         model, context_window_tokens, max_output_tokens,
                         thinking_enabled, thinking_format, test_status,
                         test_message, test_latency_ms, tested_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            'passed', %s, %s, %s)
                    """,
                    (user_id, *values),
                )
                endpoint_id = cursor.lastrowid
            else:
                cursor.execute(
                    """
                    UPDATE agent_user_endpoints
                    SET name=%s, protocol=%s, category=%s, base_url=%s,
                        api_key=%s, model=%s, context_window_tokens=%s,
                        max_output_tokens=%s, thinking_enabled=%s,
                        thinking_format=%s, test_status='passed',
                        test_message=%s, test_latency_ms=%s,
                        tested_at=%s, revision=revision+1
                    WHERE id=%s AND user_id=%s AND revision=%s
                    """,
                    (*values, endpoint_id, user_id, base_revision),
                )
                if cursor.rowcount != 1:
                    raise config_service.DynamicConfigConflictError(
                        "自有端点已被其它请求修改，请刷新后重试"
                    )
            cursor.execute(
                "UPDATE dynamic_config_test_grants SET consumed_at=%s WHERE id=%s",
                (datetime.utcnow(), grant["id"]),
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
    "test_user_agent_endpoint_payload",
]
