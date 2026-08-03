#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""站点级动态配置的数据、校验与事务边界。

该模块只负责持久化和一致性，不直接依赖任何具体 LLM、邮件或搜索 SDK。管理端在
测试配置时注入独立 tester；LLM 端点只有取得一次性测试凭证后才能保存，避免把
“测试过 A、实际保存 B”变成配置绕过。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

import pymysql

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.security.credentials import verify_password


MASKED_SECRET = "********"
LLM_TEST_GRANT_TTL_SECONDS = 10 * 60
UNLOCK_CONFIRMATION = "我已阅读上述内容，我清楚后果，我坚持要解锁"
ENDPOINT_UNLOCK_CONFIRMATION = UNLOCK_CONFIRMATION
EMBEDDING_UNLOCK_CONFIRMATION = UNLOCK_CONFIRMATION

LLM_PROTOCOLS = ("openai", "anthropic")
LLM_CATEGORIES = ("omni", "text", "vision", "embedding")
THINKING_FORMATS = ("enable_thinking", "thinking_type", "none")

FEATURE_SPECS = {
    "ai_code_annotation": {
        "label": "AI 代码标注",
        "accepted_categories": ("text", "omni"),
    },
    "code_image_analysis": {
        "label": "代码图片分析",
        "accepted_categories": ("vision", "omni"),
    },
    "repository_structuring": {
        "label": "仓库结构化",
        "accepted_categories": ("text", "omni"),
    },
    "repository_embedding": {
        "label": "Embedding",
        "accepted_categories": ("embedding",),
        "locked_binding": True,
    },
}


class DynamicConfigError(RuntimeError):
    """动态配置的可预期业务错误。"""

    status_code = 400


class DynamicConfigValidationError(DynamicConfigError):
    status_code = 400


class DynamicConfigNotFoundError(DynamicConfigError):
    status_code = 404


class DynamicConfigConflictError(DynamicConfigError):
    status_code = 409


class DynamicConfigLockedError(DynamicConfigError):
    status_code = 423


class DynamicConfigTestFailedError(DynamicConfigError):
    status_code = 422

    def __init__(self, message, *, result=None):
        super().__init__(message)
        self.result = result


class DynamicConfigTesterUnavailableError(DynamicConfigError):
    status_code = 503


def _clean_string(value, field, *, required=True, max_length=None):
    cleaned = str(value or "").strip()
    if required and not cleaned:
        raise DynamicConfigValidationError(f"{field} 不能为空")
    if max_length is not None and len(cleaned) > max_length:
        raise DynamicConfigValidationError(f"{field} 不能超过 {max_length} 个字符")
    return cleaned


def _parse_bool(value, field, *, default=False):
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off", ""}:
            return False
    raise DynamicConfigValidationError(f"{field} 必须是布尔值")


def _parse_optional_positive_id(value, field="ID"):
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DynamicConfigValidationError(f"{field} 必须是正整数") from exc
    if parsed <= 0:
        raise DynamicConfigValidationError(f"{field} 必须是正整数")
    return parsed


def _normalize_http_url(value, field):
    cleaned = _clean_string(value, field, max_length=1024)
    if any(character.isspace() or ord(character) < 32 for character in cleaned):
        raise DynamicConfigValidationError(f"{field} 不能包含空白或控制字符")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DynamicConfigValidationError(f"{field} 必须是完整的 HTTP(S) URL")
    try:
        parsed.port
    except ValueError as exc:
        raise DynamicConfigValidationError(f"{field} 端口无效") from exc
    if parsed.username is not None or parsed.password is not None:
        raise DynamicConfigValidationError(f"{field} 不能包含用户信息")
    if parsed.query or parsed.fragment:
        raise DynamicConfigValidationError(f"{field} 不能包含查询参数或片段")
    request_path = (parsed.path or "").rstrip("/").lower()
    if any(
        request_path.endswith(suffix)
        for suffix in (
            "/chat/completions",
            "/responses",
            "/embeddings",
            "/messages",
        )
    ):
        raise DynamicConfigValidationError(
            f"{field} 应填写 SDK Base URL，不能填写完整请求端点"
        )
    return cleaned.rstrip("/")


def _json_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def _serialize_row(row):
    return {key: _json_value(value) for key, value in (row or {}).items()}


def _canonical_fingerprint(payload):
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _secret_is_omitted(value):
    return value is None or not str(value).strip() or str(value).strip() == MASKED_SECRET


def normalize_llm_endpoint_payload(payload, *, existing=None):
    """校验并返回可用于测试/保存的 LLM 端点候选配置。"""
    if not isinstance(payload, dict):
        raise DynamicConfigValidationError("端点配置必须是 JSON 对象")
    existing = existing or {}

    protocol = _clean_string(
        payload.get("protocol", existing.get("protocol")),
        "协议",
        max_length=16,
    ).lower()
    if protocol not in LLM_PROTOCOLS:
        raise DynamicConfigValidationError("协议仅支持 openai 或 anthropic")

    category = _clean_string(
        payload.get("category", existing.get("category")),
        "类别",
        max_length=16,
    ).lower()
    if category not in LLM_CATEGORIES:
        raise DynamicConfigValidationError("类别仅支持 omni、text、vision 或 embedding")

    raw_secret = payload.get("api_key")
    api_key = existing.get("api_key") if _secret_is_omitted(raw_secret) else str(raw_secret).strip()
    api_key = _clean_string(api_key, "API Key", max_length=65535)

    thinking_enabled = _parse_bool(
        payload.get("thinking_enabled"),
        "thinking_enabled",
        default=existing.get("thinking_enabled", False),
    )
    format_was_provided = "thinking_format" in payload
    requested_format = str(
        payload.get("thinking_format", existing.get("thinking_format") or "none") or "none"
    ).strip().lower()
    if requested_format not in THINKING_FORMATS:
        raise DynamicConfigValidationError(
            "thinking_format 仅支持 enable_thinking、thinking_type 或 none"
        )
    if category == "embedding":
        thinking_enabled = False
        requested_format = "none"
    elif requested_format == "none":
        if thinking_enabled and not format_was_provided and not existing:
            requested_format = (
                "thinking_type" if protocol == "anthropic" else "enable_thinking"
            )
        else:
            thinking_enabled = False
    elif protocol == "anthropic":
        requested_format = "thinking_type"

    return {
        "protocol": protocol,
        "category": category,
        "base_url": _normalize_http_url(
            payload.get("base_url", existing.get("base_url")),
            "Base URL",
        ),
        "api_key": api_key,
        "model": _clean_string(
            payload.get("model", existing.get("model")),
            "模型名称",
            max_length=255,
        ),
        "thinking_enabled": thinking_enabled,
        "thinking_format": requested_format,
    }


def _endpoint_candidate_from_row(row):
    return {
        "protocol": row["protocol"],
        "category": row["category"],
        "base_url": row["base_url"],
        "api_key": row["api_key"],
        "model": row["model"],
        "thinking_enabled": bool(row.get("thinking_enabled")),
        "thinking_format": row.get("thinking_format") or "none",
    }


def _public_endpoint(row, *, include_secret=False, actor_user_id=None):
    if not row:
        return None
    result = _serialize_row(row)
    secret = str(result.pop("api_key", "") or "")
    result["api_key_configured"] = bool(secret)
    result["api_key"] = secret if include_secret else ""
    result["thinking_enabled"] = bool(result.get("thinking_enabled"))
    result["is_locked"] = bool(result.get("is_locked"))
    result["can_unlock"] = bool(
        result["is_locked"]
        and actor_user_id is not None
        and int(result.get("locked_by_user_id") or 0) == int(actor_user_id)
    )
    return result


def get_llm_endpoint(endpoint_id, *, include_secret=False, actor_user_id=None):
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    if endpoint_id is None:
        raise DynamicConfigValidationError("端点 ID 不能为空")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM llm_endpoints WHERE id=%s", (endpoint_id,))
            row = cursor.fetchone()
        if not row:
            raise DynamicConfigNotFoundError("LLM 端点不存在")
        return _public_endpoint(
            row, include_secret=include_secret, actor_user_id=actor_user_id
        )
    finally:
        conn.close()


def list_llm_endpoints(*, include_secrets=False, actor_user_id=None):
    sql = "SELECT * FROM llm_endpoints ORDER BY model ASC, id ASC"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()
        return [
            _public_endpoint(
                row,
                include_secret=include_secrets,
                actor_user_id=actor_user_id,
            )
            for row in rows
        ]
    finally:
        conn.close()


def _fetch_endpoint_for_update(cursor, endpoint_id):
    cursor.execute("SELECT * FROM llm_endpoints WHERE id=%s FOR UPDATE", (endpoint_id,))
    row = cursor.fetchone()
    if not row:
        raise DynamicConfigNotFoundError("LLM 端点不存在")
    return row


def _sanitize_test_message(message, candidate):
    text = str(message or "").strip()
    for field in ("api_key", "smtp_password", "authorization"):
        secret_value = str(candidate.get(field) or "")
        if secret_value:
            text = text.replace(secret_value, "[已脱敏]")
    return text[:1000] or "测试完成"


def run_dynamic_config_tester(tester, candidate):
    """运行注入的同步 tester，并把常见返回形式统一为稳定结果。"""
    if tester is None:
        raise DynamicConfigTesterUnavailableError("当前未配置该类型的测试适配器")
    started = time.monotonic()
    try:
        raw_result = tester(dict(candidate))
    except Exception as exc:  # tester 异常属于测试失败，不泄露堆栈或密钥
        raw_result = {"passed": False, "message": f"连接测试失败：{exc}"}
    measured_latency = max(0, int((time.monotonic() - started) * 1000))

    if isinstance(raw_result, bool):
        passed = raw_result
        message = "测试通过" if passed else "测试未通过"
        latency_ms = measured_latency
    elif isinstance(raw_result, tuple):
        passed = bool(raw_result[0]) if raw_result else False
        message = raw_result[1] if len(raw_result) > 1 else None
        latency_ms = raw_result[2] if len(raw_result) > 2 else measured_latency
    elif isinstance(raw_result, dict):
        passed = bool(raw_result.get("passed", raw_result.get("success", False)))
        message = raw_result.get("message") or raw_result.get("detail")
        latency_ms = raw_result.get("latency_ms", measured_latency)
    else:
        passed = False
        message = "测试适配器返回了无法识别的结果"
        latency_ms = measured_latency

    try:
        latency_ms = max(0, min(int(latency_ms), 2_147_483_647))
    except (TypeError, ValueError):
        latency_ms = measured_latency
    if not message:
        message = "测试通过" if passed else "测试未通过"
    return {
        "passed": passed,
        "status": "passed" if passed else "failed",
        "message": _sanitize_test_message(message, candidate),
        "latency_ms": latency_ms,
    }


def test_llm_endpoint(payload, *, user_id, tester, endpoint_id=None):
    """真实测试候选配置；通过时签发短期、单次、绑定内容与 revision 的凭证。"""
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    existing = None
    base_revision = 0
    if endpoint_id is not None:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM llm_endpoints WHERE id=%s", (endpoint_id,))
                existing = cursor.fetchone()
            if not existing:
                raise DynamicConfigNotFoundError("LLM 端点不存在")
        finally:
            conn.close()
        base_revision = int(existing.get("revision") or 0)

    if existing and bool(existing.get("is_locked")):
        raise DynamicConfigLockedError("端点已锁定，不能测试")
    candidate = normalize_llm_endpoint_payload(payload, existing=existing)
    fingerprint = _canonical_fingerprint(candidate)
    candidate_matches_existing = bool(
        existing
        and fingerprint
        == _canonical_fingerprint(_endpoint_candidate_from_row(existing))
    )

    result = run_dynamic_config_tester(tester, candidate)
    now = datetime.utcnow()
    conn = get_db_connection()
    token = None
    try:
        with conn.cursor() as cursor:
            if endpoint_id is not None and candidate_matches_existing:
                cursor.execute(
                    """
                    UPDATE llm_endpoints
                    SET test_status=%s, test_message=%s, test_latency_ms=%s,
                        tested_at=%s, tested_by_user_id=%s
                    WHERE id=%s AND revision=%s
                    """,
                    (
                        result["status"], result["message"], result["latency_ms"],
                        now, user_id, endpoint_id, base_revision,
                    ),
                )
            if result["passed"]:
                token = secrets.token_urlsafe(32)
                cursor.execute(
                    """
                    INSERT INTO dynamic_config_test_grants
                        (token_hash, config_kind, target_id, base_revision,
                         payload_fingerprint, status, test_message, test_latency_ms,
                         created_by_user_id, created_at, expires_at)
                    VALUES (%s, 'llm_endpoint', %s, %s, %s, 'passed', %s, %s, %s, %s, %s)
                    """,
                    (
                        _token_hash(token), endpoint_id, base_revision, fingerprint,
                        result["message"], result["latency_ms"], user_id, now,
                        now + timedelta(seconds=LLM_TEST_GRANT_TTL_SECONDS),
                    ),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    result["test_token"] = token
    result["expires_in_seconds"] = LLM_TEST_GRANT_TTL_SECONDS if token else 0
    if not result["passed"]:
        raise DynamicConfigTestFailedError(result["message"], result=result)
    return result


def _validate_test_grant(cursor, *, token, endpoint_id, base_revision, fingerprint, user_id):
    if not str(token or "").strip():
        raise DynamicConfigValidationError("保存前必须先通过真实连接测试")
    cursor.execute(
        "SELECT * FROM dynamic_config_test_grants WHERE token_hash=%s FOR UPDATE",
        (_token_hash(token),),
    )
    grant = cursor.fetchone()
    if not grant:
        raise DynamicConfigValidationError("测试凭证无效，请重新测试")
    target_matches = (
        (endpoint_id is None and grant.get("target_id") is None)
        or int(grant.get("target_id") or 0) == int(endpoint_id or 0)
    )
    if (
        grant.get("config_kind") != "llm_endpoint"
        or not target_matches
        or int(grant.get("base_revision") or 0) != int(base_revision)
        or grant.get("payload_fingerprint") != fingerprint
        or int(grant.get("created_by_user_id") or 0) != int(user_id)
        or grant.get("status") != "passed"
    ):
        raise DynamicConfigConflictError("配置已变化或测试凭证不匹配，请重新测试")
    if grant.get("consumed_at") is not None:
        raise DynamicConfigConflictError("测试凭证已使用，请重新测试")
    expires_at = grant.get("expires_at")
    if not expires_at or expires_at < datetime.utcnow():
        raise DynamicConfigConflictError("测试凭证已过期，请重新测试")
    return grant


def save_llm_endpoint(payload, *, user_id, test_token, endpoint_id=None):
    """创建或更新端点；每次保存都必须消费与候选配置完全匹配的测试凭证。"""
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            existing = None
            base_revision = 0
            if endpoint_id is not None:
                existing = _fetch_endpoint_for_update(cursor, endpoint_id)
                if bool(existing.get("is_locked")):
                    raise DynamicConfigLockedError("端点已锁定，不能修改")
                base_revision = int(existing.get("revision") or 0)

            candidate = normalize_llm_endpoint_payload(payload, existing=existing)
            grant = _validate_test_grant(
                cursor,
                token=test_token,
                endpoint_id=endpoint_id,
                base_revision=base_revision,
                fingerprint=_canonical_fingerprint(candidate),
                user_id=user_id,
            )
            tested_at = grant.get("created_at") or datetime.utcnow()
            values = (
                candidate["protocol"], candidate["category"], candidate["base_url"],
                candidate["api_key"], candidate["model"],
                int(candidate["thinking_enabled"]), candidate["thinking_format"],
                grant.get("test_message"), grant.get("test_latency_ms"), tested_at, user_id,
            )
            if endpoint_id is None:
                cursor.execute(
                    """
                    INSERT INTO llm_endpoints
                        (protocol, category, base_url, api_key, model,
                         thinking_enabled, thinking_format, test_status, test_message,
                         test_latency_ms, tested_at, tested_by_user_id,
                         created_by_user_id, updated_by_user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'passed', %s, %s, %s, %s, %s, %s)
                    """,
                    values + (user_id, user_id),
                )
                endpoint_id = cursor.lastrowid
            else:
                cursor.execute(
                    """
                    UPDATE llm_endpoints
                    SET protocol=%s, category=%s, base_url=%s, api_key=%s,
                        model=%s, thinking_enabled=%s, thinking_format=%s,
                        test_status='passed', test_message=%s, test_latency_ms=%s,
                        tested_at=%s, tested_by_user_id=%s,
                        revision=revision+1, updated_by_user_id=%s
                    WHERE id=%s
                    """,
                    values + (user_id, endpoint_id),
                )
            cursor.execute(
                "UPDATE dynamic_config_test_grants SET consumed_at=%s WHERE id=%s",
                (datetime.utcnow(), grant["id"]),
            )
        conn.commit()
    except pymysql.err.IntegrityError as exc:
        conn.rollback()
        if exc.args and int(exc.args[0]) == 1062:
            raise DynamicConfigConflictError("模型名称已存在") from exc
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_llm_endpoint(endpoint_id, actor_user_id=user_id)


def delete_llm_endpoint(endpoint_id):
    """删除未锁定端点；故意不清理绑定，以保留可诊断的悬空端点 ID。"""
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_endpoint_for_update(cursor, endpoint_id)
            if bool(row.get("is_locked")):
                raise DynamicConfigLockedError("端点已锁定，不能删除")
            cursor.execute("DELETE FROM llm_endpoints WHERE id=%s", (endpoint_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def lock_llm_endpoint(endpoint_id, *, user_id, reason):
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    reason = _clean_string(reason, "锁定原因", max_length=1000)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_endpoint_for_update(cursor, endpoint_id)
            if bool(row.get("is_locked")):
                raise DynamicConfigConflictError("端点已经锁定")
            cursor.execute(
                """
                UPDATE llm_endpoints
                SET is_locked=1, lock_reason=%s, locked_by_user_id=%s, locked_at=%s,
                    revision=revision+1, updated_by_user_id=%s
                WHERE id=%s
                """,
                (reason, user_id, datetime.utcnow(), user_id, endpoint_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_llm_endpoint(endpoint_id, actor_user_id=user_id)


def _verify_unlock_authority(user, password, confirmation, expected_confirmation):
    if not user or int(user.get("is_admin") or 0) != 1:
        raise DynamicConfigValidationError("只有管理员可以解锁")
    if str(confirmation or "") != expected_confirmation:
        raise DynamicConfigValidationError("确认短语不正确")
    verified, _ = verify_password(user.get("password_hash"), password)
    if not verified:
        raise DynamicConfigValidationError("当前管理员密码不正确")
    return _parse_optional_positive_id(user.get("id"), "用户 ID")


def unlock_llm_endpoint(endpoint_id, *, user, password, confirmation):
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    user_id = _verify_unlock_authority(
        user, password, confirmation, ENDPOINT_UNLOCK_CONFIRMATION
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_endpoint_for_update(cursor, endpoint_id)
            if not bool(row.get("is_locked")):
                raise DynamicConfigConflictError("端点当前未锁定")
            if int(row.get("locked_by_user_id") or 0) != int(user_id):
                raise DynamicConfigLockedError("只有执行锁定的管理员可以解锁该端点")
            cursor.execute(
                """
                UPDATE llm_endpoints
                SET is_locked=0, lock_reason=NULL, locked_by_user_id=NULL, locked_at=NULL,
                    revision=revision+1, updated_by_user_id=%s
                WHERE id=%s
                """,
                (user_id, endpoint_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_llm_endpoint(endpoint_id, actor_user_id=user_id)


def _binding_from_joined_row(row, *, actor_user_id=None):
    feature_key = row["feature_key"]
    spec = FEATURE_SPECS[feature_key]
    endpoint_id = row.get("endpoint_id")
    endpoint = None
    endpoint_missing = False
    if endpoint_id is not None:
        if row.get("endpoint_row_id") is None:
            endpoint_missing = True
        else:
            endpoint_row = {
                key[len("endpoint_"):]: value
                for key, value in row.items()
                if key.startswith("endpoint_") and key != "endpoint_row_id"
            }
            endpoint_row["id"] = row["endpoint_row_id"]
            endpoint = _public_endpoint(
                endpoint_row, actor_user_id=actor_user_id
            )
    return {
        "feature_key": feature_key,
        "label": spec["label"],
        "allowed_categories": list(spec["accepted_categories"]),
        "endpoint_id": endpoint_id,
        "endpoint_missing": endpoint_missing,
        "is_locked": bool(row.get("is_locked")),
        "lock_reason": row.get("lock_reason"),
        "locked_by_user_id": row.get("locked_by_user_id"),
        "locked_at": _json_value(row.get("locked_at")),
        "can_unlock": bool(
            row.get("is_locked")
            and actor_user_id is not None
            and int(row.get("locked_by_user_id") or 0) == int(actor_user_id)
        ),
        "revision": int(row.get("revision") or 0),
        "updated_by_user_id": row.get("updated_by_user_id"),
        "updated_at": _json_value(row.get("updated_at")),
        "endpoint": endpoint,
    }


_BINDING_ENDPOINT_SELECT = """
    SELECT b.feature_key, b.endpoint_id, b.is_locked, b.lock_reason,
           b.locked_by_user_id, b.locked_at, b.revision,
           b.updated_by_user_id, b.updated_at,
           e.id AS endpoint_row_id,
           e.protocol AS endpoint_protocol, e.category AS endpoint_category,
           e.base_url AS endpoint_base_url,
           e.api_key AS endpoint_api_key, e.model AS endpoint_model,
           e.thinking_enabled AS endpoint_thinking_enabled,
           e.thinking_format AS endpoint_thinking_format,
           e.test_status AS endpoint_test_status,
           e.test_message AS endpoint_test_message,
           e.test_latency_ms AS endpoint_test_latency_ms,
           e.tested_at AS endpoint_tested_at,
           e.tested_by_user_id AS endpoint_tested_by_user_id,
           e.is_locked AS endpoint_is_locked, e.lock_reason AS endpoint_lock_reason,
           e.locked_by_user_id AS endpoint_locked_by_user_id,
           e.locked_at AS endpoint_locked_at, e.revision AS endpoint_revision,
           e.created_by_user_id AS endpoint_created_by_user_id,
           e.updated_by_user_id AS endpoint_updated_by_user_id,
           e.created_at AS endpoint_created_at, e.updated_at AS endpoint_updated_at
    FROM llm_feature_bindings b
    LEFT JOIN llm_endpoints e ON e.id=b.endpoint_id
"""


def _empty_feature_binding(feature_key):
    spec = FEATURE_SPECS[feature_key]
    return {
        "feature_key": feature_key,
        "label": spec["label"],
        "allowed_categories": list(spec["accepted_categories"]),
        "endpoint_id": None,
        "endpoint_missing": False,
        "is_locked": False,
        "lock_reason": None,
        "locked_by_user_id": None,
        "locked_at": None,
        "can_unlock": False,
        "revision": 0,
        "updated_by_user_id": None,
        "updated_at": None,
        "endpoint": None,
    }


def get_feature_binding(feature_key, *, actor_user_id=None):
    feature_key = str(feature_key or "").strip()
    if feature_key not in FEATURE_SPECS:
        raise DynamicConfigValidationError("未知的功能绑定")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                _BINDING_ENDPOINT_SELECT + " WHERE b.feature_key=%s",
                (feature_key,),
            )
            row = cursor.fetchone()
        if row:
            return _binding_from_joined_row(row, actor_user_id=actor_user_id)
        return _empty_feature_binding(feature_key)
    finally:
        conn.close()


def list_feature_bindings(*, actor_user_id=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(_BINDING_ENDPOINT_SELECT + " ORDER BY b.feature_key ASC")
            rows = cursor.fetchall()
    finally:
        conn.close()
    by_key = {
        row["feature_key"]: _binding_from_joined_row(
            row, actor_user_id=actor_user_id
        )
        for row in rows
        if row.get("feature_key") in FEATURE_SPECS
    }
    return [
        by_key.get(feature_key)
        or _empty_feature_binding(feature_key)
        for feature_key in FEATURE_SPECS
    ]


def _validate_binding_endpoint(cursor, feature_key, endpoint_id):
    if endpoint_id is None:
        return
    cursor.execute("SELECT * FROM llm_endpoints WHERE id=%s", (endpoint_id,))
    endpoint = cursor.fetchone()
    if not endpoint:
        raise DynamicConfigNotFoundError("要绑定的 LLM 端点不存在")
    accepted = FEATURE_SPECS[feature_key]["accepted_categories"]
    if endpoint.get("category") not in accepted:
        raise DynamicConfigValidationError(
            f"该功能仅允许绑定类别：{', '.join(accepted)}"
        )


def set_feature_binding(feature_key, endpoint_id, *, user_id, lock_reason=None):
    feature_key = str(feature_key or "").strip()
    if feature_key not in FEATURE_SPECS:
        raise DynamicConfigValidationError("未知的功能绑定")
    endpoint_id = _parse_optional_positive_id(endpoint_id, "端点 ID")
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM llm_feature_bindings WHERE feature_key=%s FOR UPDATE",
                (feature_key,),
            )
            existing = cursor.fetchone()
            if existing and bool(existing.get("is_locked")):
                raise DynamicConfigLockedError("Embedding 绑定已锁定，请先解锁")
            _validate_binding_endpoint(cursor, feature_key, endpoint_id)
            if existing:
                cursor.execute(
                    """
                    UPDATE llm_feature_bindings
                    SET endpoint_id=%s, is_locked=%s, lock_reason=%s,
                        locked_by_user_id=%s, locked_at=%s,
                        revision=revision+1, updated_by_user_id=%s
                    WHERE feature_key=%s
                    """,
                    (
                        endpoint_id, 0, None,
                        None, None,
                        user_id, feature_key,
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO llm_feature_bindings
                        (feature_key, endpoint_id, is_locked, lock_reason,
                         locked_by_user_id, locked_at, updated_by_user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        feature_key, endpoint_id, 0,
                        None, None, None,
                        user_id,
                    ),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_feature_binding(feature_key)


def lock_embedding_binding(*, user_id, reason):
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    reason = _clean_string(reason, "锁定原因", max_length=1000)
    feature_key = "repository_embedding"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM llm_feature_bindings WHERE feature_key=%s FOR UPDATE",
                (feature_key,),
            )
            row = cursor.fetchone()
            if row and bool(row.get("is_locked")):
                raise DynamicConfigConflictError("Embedding 绑定已经锁定")
            if not row:
                now = datetime.utcnow()
                cursor.execute(
                    """
                    INSERT INTO llm_feature_bindings
                        (feature_key, endpoint_id, is_locked, lock_reason,
                         locked_by_user_id, locked_at, updated_by_user_id)
                    VALUES (%s, NULL, 1, %s, %s, %s, %s)
                    """,
                    (feature_key, reason, user_id, now, user_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE llm_feature_bindings
                    SET is_locked=1, lock_reason=%s, locked_by_user_id=%s,
                        locked_at=%s, revision=revision+1, updated_by_user_id=%s
                    WHERE feature_key=%s
                    """,
                    (reason, user_id, datetime.utcnow(), user_id, feature_key),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_feature_binding(feature_key, actor_user_id=user_id)


def unlock_embedding_binding(*, user, password, confirmation):
    user_id = _verify_unlock_authority(
        user, password, confirmation, EMBEDDING_UNLOCK_CONFIRMATION
    )
    feature_key = "repository_embedding"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM llm_feature_bindings WHERE feature_key=%s FOR UPDATE",
                (feature_key,),
            )
            row = cursor.fetchone()
            if not row:
                raise DynamicConfigNotFoundError("Embedding 绑定尚未配置")
            if not bool(row.get("is_locked")):
                raise DynamicConfigConflictError("Embedding 绑定当前未锁定")
            if int(row.get("locked_by_user_id") or 0) != int(user_id):
                raise DynamicConfigLockedError("只有执行锁定的管理员可以解锁该绑定")
            cursor.execute(
                """
                UPDATE llm_feature_bindings
                SET is_locked=0, lock_reason=NULL, locked_by_user_id=NULL,
                    locked_at=NULL, revision=revision+1, updated_by_user_id=%s
                WHERE feature_key=%s
                """,
                (user_id, feature_key),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_feature_binding(feature_key, actor_user_id=user_id)


def resolve_feature_endpoint(feature_key):
    """返回业务调用所需的完整端点（含密钥），未配置或悬空时 fail-closed。"""
    feature_key = str(feature_key or "").strip()
    if feature_key not in FEATURE_SPECS:
        raise DynamicConfigValidationError("未知的功能绑定")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT b.endpoint_id AS bound_endpoint_id, e.*
                FROM llm_feature_bindings b
                LEFT JOIN llm_endpoints e ON e.id=b.endpoint_id
                WHERE b.feature_key=%s
                """,
                (feature_key,),
            )
            row = cursor.fetchone()
        if not row or row.get("bound_endpoint_id") is None:
            raise DynamicConfigNotFoundError("该功能尚未绑定 LLM 端点")
        if row.get("id") is None:
            raise DynamicConfigNotFoundError(
                f"该功能绑定的 LLM 端点不存在（ID: {int(row['bound_endpoint_id'])}）"
            )
        accepted = FEATURE_SPECS[feature_key]["accepted_categories"]
        if row.get("category") not in accepted:
            raise DynamicConfigConflictError("该功能绑定的 LLM 端点类别不兼容")
        return _public_endpoint(row, include_secret=True)
    finally:
        conn.close()


def normalize_mail_settings_payload(payload, *, existing=None):
    if not isinstance(payload, dict):
        raise DynamicConfigValidationError("邮件配置必须是 JSON 对象")
    existing = existing or {}
    raw_password = payload.get("smtp_password")
    smtp_password = (
        existing.get("smtp_password")
        if _secret_is_omitted(raw_password)
        else str(raw_password).strip()
    )
    try:
        smtp_port = int(payload.get("smtp_port", existing.get("smtp_port")))
    except (TypeError, ValueError) as exc:
        raise DynamicConfigValidationError("SMTP 端口必须是整数") from exc
    if not 1 <= smtp_port <= 65535:
        raise DynamicConfigValidationError("SMTP 端口必须在 1 到 65535 之间")
    return {
        "smtp_server": _clean_string(
            payload.get("smtp_server", existing.get("smtp_server")),
            "SMTP 服务器", max_length=512,
        ),
        "smtp_port": smtp_port,
        "smtp_username": _clean_string(
            payload.get("smtp_username", existing.get("smtp_username")),
            "SMTP 用户名", max_length=512,
        ),
        "smtp_password": _clean_string(smtp_password, "SMTP 密码", max_length=65535),
    }


def _public_mail_settings(row, *, include_secret=False):
    if not row:
        return None
    result = _serialize_row(row)
    secret = str(result.pop("smtp_password", "") or "")
    result["smtp_password_configured"] = bool(secret)
    result["smtp_password"] = secret if include_secret else ""
    result.pop("id", None)
    return result


def get_mail_settings(*, include_secret=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM site_mail_settings WHERE id=1")
            row = cursor.fetchone()
        return _public_mail_settings(row, include_secret=include_secret)
    finally:
        conn.close()


def save_mail_settings(payload, *, user_id):
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    existing = get_mail_settings(include_secret=True)
    candidate = normalize_mail_settings_payload(payload, existing=existing)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_mail_settings
                    (id, smtp_server, smtp_port, smtp_username, smtp_password,
                     test_status, test_message, test_latency_ms, tested_at,
                     tested_by_user_id, revision, updated_by_user_id)
                VALUES (1, %s, %s, %s, %s, 'untested', NULL, NULL, NULL, NULL, 1, %s)
                ON DUPLICATE KEY UPDATE
                    smtp_server=VALUES(smtp_server), smtp_port=VALUES(smtp_port),
                    smtp_username=VALUES(smtp_username), smtp_password=VALUES(smtp_password),
                    test_status='untested', test_message=NULL, test_latency_ms=NULL,
                    tested_at=NULL, tested_by_user_id=NULL,
                    revision=revision+1, updated_by_user_id=VALUES(updated_by_user_id)
                """,
                (
                    candidate["smtp_server"], candidate["smtp_port"],
                    candidate["smtp_username"], candidate["smtp_password"], user_id,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_mail_settings()


def test_mail_settings(payload, *, user_id, recipient_email, tester):
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    recipient_email = _clean_string(
        recipient_email, "当前管理员邮箱", max_length=320
    )
    if "@" not in recipient_email or recipient_email.startswith("@"):
        raise DynamicConfigValidationError("当前管理员邮箱无效，无法发送测试邮件")
    existing = get_mail_settings(include_secret=True)
    candidate = normalize_mail_settings_payload(payload, existing=existing)
    result = run_dynamic_config_tester(
        tester,
        {**candidate, "recipient_email": recipient_email},
    )
    if existing and all(existing.get(key) == value for key, value in candidate.items()):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE site_mail_settings
                    SET test_status=%s, test_message=%s, test_latency_ms=%s,
                        tested_at=%s, tested_by_user_id=%s
                    WHERE id=1
                    """,
                    (
                        result["status"], result["message"], result["latency_ms"],
                        datetime.utcnow(), user_id,
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    if not result["passed"]:
        raise DynamicConfigTestFailedError(result["message"], result=result)
    return result


def clear_mail_settings():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM site_mail_settings WHERE id=1")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def normalize_web_search_settings_payload(payload, *, existing=None):
    if not isinstance(payload, dict):
        raise DynamicConfigValidationError("WebSearch 配置必须是 JSON 对象")
    existing = existing or {}
    raw_authorization = payload.get("authorization")
    authorization = (
        existing.get("authorization")
        if _secret_is_omitted(raw_authorization)
        else str(raw_authorization).strip()
    )
    return {
        "base_url": _normalize_http_url(
            payload.get("base_url", existing.get("base_url")),
            "Base URL",
        ),
        "authorization": _clean_string(
            authorization, "Authorization", max_length=65535
        ),
    }


def _public_web_search_settings(row, *, include_secret=False):
    if not row:
        return None
    result = _serialize_row(row)
    secret = str(result.pop("authorization", "") or "")
    result["authorization_configured"] = bool(secret)
    result["authorization"] = secret if include_secret else ""
    result.pop("id", None)
    return result


def get_web_search_settings(*, include_secret=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM site_web_search_settings WHERE id=1")
            row = cursor.fetchone()
        return _public_web_search_settings(row, include_secret=include_secret)
    finally:
        conn.close()


def save_web_search_settings(payload, *, user_id):
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    existing = get_web_search_settings(include_secret=True)
    candidate = normalize_web_search_settings_payload(payload, existing=existing)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_web_search_settings
                    (id, base_url, authorization, test_status, test_message,
                     test_latency_ms, tested_at, tested_by_user_id, revision,
                     updated_by_user_id)
                VALUES (1, %s, %s, 'untested', NULL, NULL, NULL, NULL, 1, %s)
                ON DUPLICATE KEY UPDATE
                    base_url=VALUES(base_url), authorization=VALUES(authorization),
                    test_status='untested', test_message=NULL, test_latency_ms=NULL,
                    tested_at=NULL, tested_by_user_id=NULL,
                    revision=revision+1, updated_by_user_id=VALUES(updated_by_user_id)
                """,
                (candidate["base_url"], candidate["authorization"], user_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return get_web_search_settings()


def test_web_search_settings(payload, *, user_id, tester):
    user_id = _parse_optional_positive_id(user_id, "用户 ID")
    existing = get_web_search_settings(include_secret=True)
    candidate = normalize_web_search_settings_payload(payload, existing=existing)
    result = run_dynamic_config_tester(tester, candidate)
    if existing and all(existing.get(key) == value for key, value in candidate.items()):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE site_web_search_settings
                    SET test_status=%s, test_message=%s, test_latency_ms=%s,
                        tested_at=%s, tested_by_user_id=%s
                    WHERE id=1
                    """,
                    (
                        result["status"], result["message"], result["latency_ms"],
                        datetime.utcnow(), user_id,
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    if not result["passed"]:
        raise DynamicConfigTestFailedError(result["message"], result=result)
    return result


def clear_web_search_settings():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM site_web_search_settings WHERE id=1")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_dynamic_config_meta():
    return {
        "protocols": list(LLM_PROTOCOLS),
        "categories": list(LLM_CATEGORIES),
        "thinking_formats": list(THINKING_FORMATS),
        "features": [
            {
                "key": key,
                "label": spec["label"],
                "allowed_categories": list(spec["accepted_categories"]),
                "lockable": bool(spec.get("locked_binding")),
            }
            for key, spec in FEATURE_SPECS.items()
        ],
        "unlock_confirmations": {
            "endpoint": ENDPOINT_UNLOCK_CONFIRMATION,
            "embedding_binding": EMBEDDING_UNLOCK_CONFIRMATION,
        },
        "llm_test_grant_ttl_seconds": LLM_TEST_GRANT_TTL_SECONDS,
    }
