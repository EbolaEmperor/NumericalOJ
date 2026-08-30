"""通用 Agent 的额度账户、申请与逐请求计费领域服务。"""

from __future__ import annotations

import re
import uuid
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext

from backend.oj_modules.classroom.logos import class_logo_presentation
from backend.oj_modules.infrastructure.mysql import get_db_connection


AGENT_PUBLIC_ENABLED_SETTING_KEY = "AGENT_PUBLIC_ENABLED"
AGENT_QUOTA_HARD_STOP_AMOUNT = Decimal("-5")
_MONEY_QUANTUM = Decimal("0.00000000000001")
_MONEY_LIMIT = Decimal("10000000000000000")
_MAX_TOKEN_COUNT = 18_446_744_073_709_551_615
_SAFE_SOURCE_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}")
_USAGE_COUNT_FIELDS = (
    "input_uncached_tokens",
    "input_cached_tokens",
    "input_cache_write_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)
_USAGE_PRICE_FIELDS = (
    "input_price_per_million",
    "cached_input_price_per_million",
    "output_price_per_million",
)
class AgentQuotaError(RuntimeError):
    """可预期的 Agent 额度领域错误。"""

    status_code = 400
    code = "agent_quota_error"


class AgentQuotaValidationError(AgentQuotaError):
    code = "agent_quota_validation_error"


class AgentQuotaNotFoundError(AgentQuotaError):
    status_code = 404
    code = "agent_quota_not_found"


class AgentQuotaConflictError(AgentQuotaError):
    status_code = 409
    code = "agent_quota_conflict"


class AgentQuotaAccessDeniedError(AgentQuotaError):
    status_code = 403

    def __init__(self, message, *, decision):
        super().__init__(message)
        self.decision = dict(decision)
        self.code = str(decision.get("reason_code") or "agent_quota_denied")


def _positive_int(value, label):
    if isinstance(value, bool):
        raise AgentQuotaValidationError(f"{label} 无效")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise AgentQuotaValidationError(f"{label} 无效") from None
    if parsed <= 0 or str(value).strip() != str(parsed):
        raise AgentQuotaValidationError(f"{label} 无效")
    return parsed


def _money(value, label, *, positive=False, nonzero=False):
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, TypeError, ValueError):
        raise AgentQuotaValidationError(f"{label} 必须是有效金额") from None
    if not amount.is_finite():
        raise AgentQuotaValidationError(f"{label} 必须是有效金额")
    with localcontext() as context:
        context.prec = 60
        amount = amount.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    if abs(amount) >= _MONEY_LIMIT:
        raise AgentQuotaValidationError(f"{label} 超出数据库可存储范围")
    if positive and amount <= 0:
        raise AgentQuotaValidationError(f"{label} 必须大于 0")
    if nonzero and amount == 0:
        raise AgentQuotaValidationError(f"{label} 不能为 0")
    return amount


def _decimal_from_row(value):
    try:
        parsed = Decimal(str(value if value is not None else "0"))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal("0")
    return parsed if parsed.is_finite() else Decimal("0")


def _money_text(value):
    amount = _decimal_from_row(value)
    if amount == 0:
        return "0"
    text = format(amount, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _time_text(value):
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    return str(value)


def _token_count(value, label):
    if isinstance(value, bool):
        raise AgentQuotaValidationError(f"{label} 无效")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise AgentQuotaValidationError(f"{label} 无效") from None
    if parsed < 0 or parsed > _MAX_TOKEN_COUNT or str(value).strip() != str(parsed):
        raise AgentQuotaValidationError(f"{label} 无效")
    return parsed


def _optional_token_count(value, label):
    """读取可选计数字段；无法识别时按 0 处理。"""

    try:
        return _token_count(value, label)
    except AgentQuotaValidationError:
        return 0


def _cached_fallback_metadata(usage):
    """校验并读取 cached 字段回退计费的审计信息。"""

    request_count = _token_count(
        usage.get("cached_fallback_request_count", 0),
        "cached 回退调用次数",
    )
    input_tokens = _token_count(
        usage.get("cached_fallback_input_tokens", 0),
        "cached 回退输入 Token",
    )
    if request_count > 1:
        raise AgentQuotaValidationError("cached 回退调用次数无效")
    if request_count == 0 and input_tokens != 0:
        raise AgentQuotaValidationError("cached 回退输入 Token 无效")
    if request_count == 1 and input_tokens <= 0:
        raise AgentQuotaValidationError("cached 回退输入 Token 无效")
    return request_count, input_tokens


def _setting_enabled(value):
    return str(value if value is not None else "1").strip().lower() not in {
        "0",
        "false",
        "off",
        "no",
    }


def _read_public_enabled(cursor):
    cursor.execute(
        "SELECT v FROM site_settings WHERE k=%s",
        (AGENT_PUBLIC_ENABLED_SETTING_KEY,),
    )
    row = cursor.fetchone()
    return _setting_enabled(row.get("v") if row else "1")


def _account_from_row(row):
    if not row:
        return None
    granted = _decimal_from_row(row.get("granted_amount"))
    used = _decimal_from_row(row.get("used_amount"))
    return {
        "user_id": int(row.get("user_id") or 0),
        "total_amount": _money_text(granted),
        "used_amount": _money_text(used),
        "remaining_amount": _money_text(granted - used),
        "updated_by_user_id": row.get("updated_by_user_id"),
        "adjustment_note": str(row.get("adjustment_note") or ""),
        "created_at": _time_text(row.get("created_at")),
        "updated_at": _time_text(row.get("updated_at")),
    }


def _request_from_row(row):
    if not row:
        return None
    return {
        "id": int(row.get("id") or 0),
        "user_id": int(row.get("user_id") or 0),
        "username": str(row.get("username") or ""),
        "requested_amount": (
            _money_text(row.get("requested_amount"))
            if row.get("requested_amount") is not None
            else None
        ),
        "approved_amount": (
            _money_text(row.get("approved_amount"))
            if row.get("approved_amount") is not None
            else None
        ),
        "reason": str(row.get("reason") or ""),
        "status": str(row.get("status") or "pending"),
        "review_note": str(row.get("review_note") or ""),
        "reviewed_by_user_id": row.get("reviewed_by_user_id"),
        "reviewed_at": _time_text(row.get("reviewed_at")),
        "created_at": _time_text(row.get("created_at")),
        "updated_at": _time_text(row.get("updated_at")),
    }


def _ledger_from_row(row, *, applied):
    if not row:
        return None
    remaining = _decimal_from_row(row.get("remaining_after"))
    return {
        "id": int(row.get("id") or 0),
        "user_id": row.get("user_id"),
        "session_id": str(row.get("session_id") or ""),
        "task_id": str(row.get("task_id") or ""),
        "source": str(row.get("source") or ""),
        "usage_event_id": str(row.get("usage_event_id") or ""),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_revision": row.get("endpoint_revision"),
        "endpoint_model": str(row.get("endpoint_model") or ""),
        "charged_amount": _money_text(row.get("charged_amount")),
        "remaining_amount": _money_text(remaining),
        "cached_fallback_request_count": int(
            row.get("cached_fallback_request_count") or 0
        ),
        "cached_fallback_input_tokens": int(
            row.get("cached_fallback_input_tokens") or 0
        ),
        "hard_stop": remaining <= AGENT_QUOTA_HARD_STOP_AMOUNT,
        "applied": bool(applied),
        "created_at": _time_text(row.get("created_at")),
    }


def _require_user(cursor, user_id, *, admin=False, for_update=False):
    cursor.execute(
        "SELECT id, is_admin FROM users WHERE id=%s "
        + ("FOR UPDATE" if for_update else "FOR SHARE"),
        (user_id,),
    )
    row = cursor.fetchone()
    if not row:
        raise AgentQuotaNotFoundError("用户不存在")
    if admin and not bool(row.get("is_admin")):
        raise AgentQuotaAccessDeniedError(
            "只有管理员可以执行此操作",
            decision={
                "allowed": False,
                "reason_code": "admin_required",
                "message": "只有管理员可以执行此操作",
            },
        )
    return row


def get_agent_public_enabled():
    """读取普通用户 Agent 总开关；未配置时默认开启。"""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            return _read_public_enabled(cursor)
    finally:
        conn.close()


def set_agent_public_enabled(enabled):
    """设置普通用户 Agent 总开关。"""

    if not isinstance(enabled, bool):
        raise AgentQuotaValidationError("Agent 开关必须是布尔值")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_settings (k, v) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE v=VALUES(v)
                """,
                (AGENT_PUBLIC_ENABLED_SETTING_KEY, "1" if enabled else "0"),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return enabled


def get_agent_quota_summary(user_id, *, is_admin=False):
    """返回额度账户、待审核申请与当前普通端点启动资格。"""

    user_id = _positive_int(user_id, "用户 ID")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            public_enabled = _read_public_enabled(cursor)
            cursor.execute(
                "SELECT * FROM agent_quota_accounts WHERE user_id=%s",
                (user_id,),
            )
            account = _account_from_row(cursor.fetchone())
            cursor.execute(
                """
                SELECT * FROM agent_quota_requests
                WHERE user_id=%s AND status='pending'
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            )
            pending_request = _request_from_row(cursor.fetchone())
    finally:
        conn.close()

    has_account = account is not None
    if not has_account:
        account = {
            "user_id": user_id,
            "total_amount": "0",
            "used_amount": "0",
            "remaining_amount": "0",
            "updated_by_user_id": None,
            "adjustment_note": "",
            "created_at": None,
            "updated_at": None,
        }
    remaining = _decimal_from_row(account["remaining_amount"])
    can_use_shared_endpoint = bool(
        is_admin or (public_enabled and has_account and remaining >= 0)
    )
    return {
        **account,
        "has_account": has_account,
        "pending_request": pending_request,
        "public_enabled": public_enabled,
        "can_start": can_use_shared_endpoint,
        "can_continue": can_use_shared_endpoint,
        "hard_stop": bool(has_account and remaining <= AGENT_QUOTA_HARD_STOP_AMOUNT),
    }


def get_agent_runtime_quota_summary(user_id, *, is_admin=False):
    """用一次查询返回会话控件所需的实时额度状态。"""

    user_id = _positive_int(user_id, "用户 ID")
    if is_admin:
        return {
            "user_id": user_id,
            "has_account": True,
            "total_amount": "0",
            "used_amount": "0",
            "remaining_amount": "0",
            "public_enabled": True,
            "can_start": True,
            "can_continue": True,
            "hard_stop": False,
        }
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT a.user_id AS account_user_id,
                       a.granted_amount, a.used_amount,
                       (
                           SELECT v FROM site_settings WHERE k=%s
                       ) AS public_setting
                FROM (SELECT %s AS user_id) AS requested
                LEFT JOIN agent_quota_accounts AS a
                  ON a.user_id=requested.user_id
                """,
                (AGENT_PUBLIC_ENABLED_SETTING_KEY, user_id),
            )
            row = cursor.fetchone() or {}
    finally:
        conn.close()

    public_enabled = _setting_enabled(row.get("public_setting"))
    has_account = row.get("account_user_id") is not None
    granted = _decimal_from_row(row.get("granted_amount"))
    used = _decimal_from_row(row.get("used_amount"))
    remaining = granted - used
    can_use_shared = bool(
        is_admin or (public_enabled and has_account and remaining >= 0)
    )
    return {
        "user_id": user_id,
        "has_account": has_account,
        "total_amount": _money_text(granted),
        "used_amount": _money_text(used),
        "remaining_amount": _money_text(remaining),
        "public_enabled": public_enabled,
        "can_start": can_use_shared,
        "can_continue": can_use_shared,
        "hard_stop": bool(has_account and remaining <= AGENT_QUOTA_HARD_STOP_AMOUNT),
    }


def get_agent_session_usage_cost(session_id):
    """返回会话账本中的历史总费用；没有 usage 记录时返回 ``None``。"""

    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id or len(normalized_session_id) > 64:
        raise AgentQuotaValidationError("Agent session_id 无效")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT SUM(charged_amount) AS charged_amount
                FROM agent_usage_ledger
                WHERE session_id=%s
                """,
                (normalized_session_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    if not row or row.get("charged_amount") is None:
        return None
    return _money_text(row["charged_amount"])


def get_agent_session_token_usage(session_id):
    """从计费账本返回会话累计 Token 与冻结后的实际费用。"""

    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id or len(normalized_session_id) > 64:
        raise AgentQuotaValidationError("Agent session_id 无效")
    conn = get_db_connection()
    latest_context = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT task_id, COUNT(*) AS request_count,
                       SUM(input_uncached_tokens) AS input_uncached_tokens,
                       SUM(input_cached_tokens) AS input_cached_tokens,
                       SUM(input_cache_write_tokens) AS input_cache_write_tokens,
                       SUM(output_tokens) AS output_tokens,
                       SUM(reasoning_output_tokens) AS reasoning_output_tokens,
                       SUM(cached_fallback_request_count)
                           AS cached_fallback_request_count,
                       SUM(cached_fallback_input_tokens)
                           AS cached_fallback_input_tokens,
                       SUM(charged_amount) AS charged_amount
                FROM agent_usage_ledger
                WHERE session_id=%s
                GROUP BY task_id
                """,
                (normalized_session_id,),
            )
            rows = cursor.fetchall()
            if rows:
                cursor.execute(
                    """
                    SELECT task_id, input_uncached_tokens,
                           input_cached_tokens, input_cache_write_tokens,
                           output_tokens
                    FROM agent_usage_ledger
                    WHERE session_id=%s
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (normalized_session_id,),
                )
                latest_context = cursor.fetchone()
    finally:
        conn.close()
    if not rows:
        return None
    usage = {
        "source": "session",
        "request_count": sum(int(row.get("request_count") or 0) for row in rows),
        "turn_count": len(rows),
        "input_uncached_tokens": sum(
            int(row.get("input_uncached_tokens") or 0) for row in rows
        ),
        "input_cached_tokens": sum(
            int(row.get("input_cached_tokens") or 0) for row in rows
        ),
        "input_cache_write_tokens": sum(
            int(row.get("input_cache_write_tokens") or 0) for row in rows
        ),
        "output_tokens": sum(
            int(row.get("output_tokens") or 0) for row in rows
        ),
        "reasoning_output_tokens": sum(
            int(row.get("reasoning_output_tokens") or 0) for row in rows
        ),
        "cached_fallback_request_count": sum(
            int(row.get("cached_fallback_request_count") or 0)
            for row in rows
        ),
        "cached_fallback_input_tokens": sum(
            int(row.get("cached_fallback_input_tokens") or 0)
            for row in rows
        ),
        "cost_rmb": _money_text(sum(
            (_decimal_from_row(row.get("charged_amount")) for row in rows),
            start=Decimal("0"),
        )),
        "cost_complete": True,
        "_task_ids": [str(row.get("task_id") or "") for row in rows],
    }
    if usage["cached_fallback_request_count"] <= 0:
        usage.pop("cached_fallback_request_count")
        usage.pop("cached_fallback_input_tokens")
    usage["input_total_tokens"] = (
        usage["input_uncached_tokens"]
        + usage["input_cached_tokens"]
        + usage["input_cache_write_tokens"]
    )
    if latest_context:
        latest_task_id = str(latest_context.get("task_id") or "").strip()
        usage["_latest_context_task_id"] = latest_task_id
        usage["_latest_context_tokens"] = sum(
            int(latest_context.get(field) or 0)
            for field in (
                "input_uncached_tokens",
                "input_cached_tokens",
                "input_cache_write_tokens",
                "output_tokens",
            )
        )
        usage["_latest_context_request_count"] = next(
            (
                int(row.get("request_count") or 0)
                for row in rows
                if str(row.get("task_id") or "").strip() == latest_task_id
            ),
            0,
        )
    return usage


def list_agent_quota_requests(user_id, *, limit=20):
    user_id = _positive_int(user_id, "用户 ID")
    limit = min(_positive_int(limit, "查询数量"), 100)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT * FROM agent_quota_requests
                WHERE user_id=%s ORDER BY id DESC LIMIT %s
                """,
                (user_id, limit),
            )
            return [_request_from_row(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def create_agent_quota_request(user_id, reason):
    """创建额度申请；同一用户同时只能有一条待审核申请。"""

    user_id = _positive_int(user_id, "用户 ID")
    reason = str(reason or "").strip()
    if not reason:
        raise AgentQuotaValidationError("申请理由不能为空")
    if len(reason) > 2000:
        raise AgentQuotaValidationError("申请理由不能超过 2000 个字符")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if not _read_public_enabled(cursor):
                raise AgentQuotaAccessDeniedError(
                    "当前未开放普通用户使用 Agent",
                    decision={
                        "allowed": False,
                        "reason_code": "agent_public_disabled",
                        "message": "当前未开放普通用户使用 Agent",
                    },
                )
            _require_user(cursor, user_id, for_update=True)
            cursor.execute(
                """
                SELECT id FROM agent_quota_requests
                WHERE user_id=%s AND status='pending'
                ORDER BY id DESC LIMIT 1 FOR UPDATE
                """,
                (user_id,),
            )
            if cursor.fetchone():
                raise AgentQuotaConflictError("已有待审核的额度申请")
            cursor.execute(
                """
                INSERT INTO agent_quota_requests
                    (user_id, reason, status)
                VALUES (%s, %s, 'pending')
                """,
                (user_id, reason),
            )
            request_id = cursor.lastrowid
            cursor.execute(
                "SELECT * FROM agent_quota_requests WHERE id=%s",
                (request_id,),
            )
            result = _request_from_row(cursor.fetchone())
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return result


def list_pending_agent_quota_requests(reviewer_user_id, *, limit=100):
    reviewer_user_id = _positive_int(reviewer_user_id, "管理员用户 ID")
    limit = min(_positive_int(limit, "查询数量"), 500)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _require_user(cursor, reviewer_user_id, admin=True)
            cursor.execute(
                """
                SELECT r.*, u.username
                FROM agent_quota_requests AS r
                JOIN users AS u ON u.id=r.user_id
                WHERE r.status='pending'
                ORDER BY r.created_at ASC, r.id ASC LIMIT %s
                """,
                (limit,),
            )
            return [_request_from_row(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def list_agent_quota_grant_classes():
    """返回管理员批量赠送额度所需的班级和普通用户 ID。"""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT c.class_en, c.class_cn, c.logo_seed, u.id AS user_id
                FROM class_table AS c
                LEFT JOIN user_class_map AS m ON m.class_en=c.class_en
                LEFT JOIN users AS u ON u.id=m.user_id AND u.is_admin=0
                ORDER BY c.class_cn ASC, c.class_en ASC, u.id ASC
                """
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    classes = []
    by_class = {}
    for row in rows:
        class_en = str(row.get("class_en") or "")
        item = by_class.get(class_en)
        if item is None:
            item = {
                "class_en": class_en,
                "label": str(row.get("class_cn") or class_en),
                "logo": class_logo_presentation(
                    row.get("logo_seed"),
                    fallback=class_en,
                ),
                "user_ids": [],
            }
            by_class[class_en] = item
            classes.append(item)
        if row.get("user_id") is not None:
            user_id = int(row["user_id"])
            if user_id not in item["user_ids"]:
                item["user_ids"].append(user_id)
    return classes


def review_agent_quota_request(
    request_id,
    *,
    reviewer_user_id,
    approved,
    approved_amount=None,
    review_note="",
):
    """管理员审核申请；通过时在同一事务中增加账户总额度。"""

    request_id = _positive_int(request_id, "额度申请 ID")
    reviewer_user_id = _positive_int(reviewer_user_id, "管理员用户 ID")
    if not isinstance(approved, bool):
        raise AgentQuotaValidationError("审核结果必须是布尔值")
    granted = (
        _money(approved_amount, "批准额度", positive=True)
        if approved
        else None
    )
    review_note = str(review_note or "").strip()
    if len(review_note) > 2000:
        raise AgentQuotaValidationError("审核意见不能超过 2000 个字符")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _require_user(cursor, reviewer_user_id, admin=True)
            cursor.execute(
                "SELECT * FROM agent_quota_requests WHERE id=%s FOR UPDATE",
                (request_id,),
            )
            request_row = cursor.fetchone()
            if not request_row:
                raise AgentQuotaNotFoundError("额度申请不存在")
            if str(request_row.get("status")) != "pending":
                raise AgentQuotaConflictError("额度申请已经审核")

            status = "rejected"
            if approved:
                status = "approved"
                cursor.execute(
                    """
                    INSERT INTO agent_quota_accounts
                        (user_id, granted_amount, used_amount,
                         updated_by_user_id, adjustment_note)
                    VALUES (%s, %s, 0, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        granted_amount=granted_amount+VALUES(granted_amount),
                        updated_by_user_id=VALUES(updated_by_user_id),
                        adjustment_note=VALUES(adjustment_note)
                    """,
                    (
                        request_row["user_id"],
                        granted,
                        reviewer_user_id,
                        review_note or f"批准额度申请 #{request_id}",
                    ),
                )
                cursor.execute(
                    """
                    INSERT INTO agent_quota_grants
                        (user_id, amount, kind, request_id,
                         granted_by_user_id, note)
                    VALUES (%s, %s, 'request_approval', %s, %s, %s)
                    """,
                    (
                        request_row["user_id"],
                        granted,
                        request_id,
                        reviewer_user_id,
                        review_note,
                    ),
                )
            cursor.execute(
                """
                UPDATE agent_quota_requests
                SET status=%s, approved_amount=%s, review_note=%s,
                    reviewed_by_user_id=%s, reviewed_at=CURRENT_TIMESTAMP
                WHERE id=%s
                """,
                (status, granted, review_note, reviewer_user_id, request_id),
            )
            cursor.execute(
                "SELECT * FROM agent_quota_requests WHERE id=%s",
                (request_id,),
            )
            result = _request_from_row(cursor.fetchone())
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return result


def adjust_agent_quota(
    user_id,
    amount_delta,
    *,
    adjusted_by_user_id,
    note="",
):
    """管理员直接增减用户的总额度，已用金额不随调整变化。"""

    user_id = _positive_int(user_id, "用户 ID")
    adjusted_by_user_id = _positive_int(adjusted_by_user_id, "管理员用户 ID")
    delta = _money(amount_delta, "额度调整金额", nonzero=True)
    note = str(note or "").strip()
    if len(note) > 2000:
        raise AgentQuotaValidationError("调整备注不能超过 2000 个字符")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _require_user(cursor, adjusted_by_user_id, admin=True)
            _require_user(cursor, user_id)
            cursor.execute(
                """
                INSERT INTO agent_quota_accounts
                    (user_id, granted_amount, used_amount,
                     updated_by_user_id, adjustment_note)
                VALUES (%s, 0, 0, %s, %s)
                ON DUPLICATE KEY UPDATE user_id=VALUES(user_id)
                """,
                (user_id, adjusted_by_user_id, note),
            )
            cursor.execute(
                "SELECT * FROM agent_quota_accounts WHERE user_id=%s FOR UPDATE",
                (user_id,),
            )
            account = cursor.fetchone()
            next_granted = _decimal_from_row(account.get("granted_amount")) + delta
            if next_granted < 0:
                raise AgentQuotaValidationError("调整后总额度不能小于 0")
            if next_granted >= _MONEY_LIMIT:
                raise AgentQuotaValidationError("调整后总额度超出数据库可存储范围")
            cursor.execute(
                """
                UPDATE agent_quota_accounts
                SET granted_amount=%s, updated_by_user_id=%s,
                    adjustment_note=%s
                WHERE user_id=%s
                """,
                (next_granted, adjusted_by_user_id, note, user_id),
            )
            cursor.execute(
                """
                INSERT INTO agent_quota_grants
                    (user_id, amount, kind, granted_by_user_id, note)
                VALUES (%s, %s, 'manual_adjustment', %s, %s)
                """,
                (user_id, delta, adjusted_by_user_id, note),
            )
            cursor.execute(
                "SELECT * FROM agent_quota_accounts WHERE user_id=%s",
                (user_id,),
            )
            result = _account_from_row(cursor.fetchone())
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return result


def batch_grant_quota_by_classes(
    class_en_values,
    amount_rmb,
    granted_by_user_id,
):
    """按班级给普通用户批量赠送额度，同一用户在批次内只入账一次。"""

    if not isinstance(class_en_values, (list, tuple, set)):
        raise AgentQuotaValidationError("班级列表无效")
    class_names = []
    seen = set()
    for value in class_en_values:
        class_en = str(value or "").strip()
        if not class_en or len(class_en) > 255:
            raise AgentQuotaValidationError("班级标识无效")
        if class_en not in seen:
            seen.add(class_en)
            class_names.append(class_en)
    if not class_names:
        raise AgentQuotaValidationError("请至少选择一个班级")
    if len(class_names) > 100:
        raise AgentQuotaValidationError("一次最多选择 100 个班级")
    amount = _money(amount_rmb, "赠送额度", positive=True)
    granted_by_user_id = _positive_int(granted_by_user_id, "管理员用户 ID")
    batch_id = uuid.uuid4().hex

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            _require_user(cursor, granted_by_user_id, admin=True)
            placeholders = ",".join(["%s"] * len(class_names))
            cursor.execute(
                f"""
                SELECT DISTINCT u.id
                FROM users AS u
                JOIN user_class_map AS m ON m.user_id=u.id
                WHERE m.class_en IN ({placeholders}) AND u.is_admin=0
                ORDER BY u.id ASC
                """,
                tuple(class_names),
            )
            selected_ids = [int(row["id"]) for row in cursor.fetchall()]
            user_ids = []
            if selected_ids:
                user_placeholders = ",".join(["%s"] * len(selected_ids))
                cursor.execute(
                    f"""
                    SELECT id FROM users
                    WHERE id IN ({user_placeholders}) AND is_admin=0
                    ORDER BY id ASC FOR UPDATE
                    """,
                    tuple(selected_ids),
                )
                user_ids = [int(row["id"]) for row in cursor.fetchall()]

            if user_ids:
                cursor.executemany(
                    """
                    INSERT INTO agent_quota_accounts
                        (user_id, granted_amount, used_amount,
                         updated_by_user_id, adjustment_note)
                    VALUES (%s, %s, 0, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        granted_amount=granted_amount+VALUES(granted_amount),
                        updated_by_user_id=VALUES(updated_by_user_id),
                        adjustment_note=VALUES(adjustment_note)
                    """,
                    [
                        (
                            user_id,
                            amount,
                            granted_by_user_id,
                            f"班级批量赠送 {batch_id}",
                        )
                        for user_id in user_ids
                    ],
                )
                cursor.executemany(
                    """
                    INSERT INTO agent_quota_grants
                        (user_id, amount, kind, batch_id,
                         granted_by_user_id, note)
                    VALUES (%s, %s, 'class_batch', %s, %s, %s)
                    """,
                    [
                        (
                            user_id,
                            amount,
                            batch_id,
                            granted_by_user_id,
                            "班级：" + "、".join(class_names),
                        )
                        for user_id in user_ids
                    ],
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    total = amount * len(user_ids)
    return {
        "batch_id": batch_id,
        "affected_users": len(user_ids),
        "user_ids": user_ids,
        "amount_per_user": _money_text(amount),
        "total_rmb": _money_text(total),
    }


def check_agent_start_eligibility(
    user_id,
    *,
    is_admin=False,
    uses_personal_endpoint=False,
):
    """检查能否新建任务或继续会话；自有端点只受全站开关约束。"""

    user_id = _positive_int(user_id, "用户 ID")
    if is_admin:
        return {
            "allowed": True,
            "reason_code": "admin_bypass",
            "message": "管理员不受 Agent 额度限制",
            "quota_bypassed": True,
            "remaining_amount": None,
            "hard_stop": False,
        }
    if not get_agent_public_enabled():
        return {
            "allowed": False,
            "reason_code": "agent_public_disabled",
            "message": "当前未开放普通用户使用 Agent",
            "quota_bypassed": False,
            "remaining_amount": None,
            "hard_stop": False,
        }
    if uses_personal_endpoint:
        return {
            "allowed": True,
            "reason_code": "personal_endpoint_bypass",
            "message": "使用自有端点，不消耗站内额度",
            "quota_bypassed": True,
            "remaining_amount": None,
            "hard_stop": False,
        }

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM agent_quota_accounts WHERE user_id=%s",
                (user_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        return {
            "allowed": False,
            "reason_code": "quota_account_required",
            "message": "请先申请 Agent 额度",
            "quota_bypassed": False,
            "remaining_amount": None,
            "hard_stop": False,
        }
    remaining = _decimal_from_row(row.get("granted_amount")) - _decimal_from_row(
        row.get("used_amount")
    )
    hard_stop = remaining <= AGENT_QUOTA_HARD_STOP_AMOUNT
    if remaining < 0:
        return {
            "allowed": False,
            "reason_code": "quota_negative",
            "message": "Agent 额度已用完，请先申请额度",
            "quota_bypassed": False,
            "remaining_amount": _money_text(remaining),
            "hard_stop": hard_stop,
        }
    return {
        "allowed": True,
        "reason_code": "ok",
        "message": "可以使用 Agent",
        "quota_bypassed": False,
        "remaining_amount": _money_text(remaining),
        "hard_stop": hard_stop,
    }


def require_agent_start_eligibility(*args, **kwargs):
    decision = check_agent_start_eligibility(*args, **kwargs)
    if not decision["allowed"]:
        raise AgentQuotaAccessDeniedError(decision["message"], decision=decision)
    return decision


def calculate_agent_usage_charge(usage, pricing):
    """按每百万 Token 的价格快照计算单次 LLM 请求费用。"""

    if not isinstance(usage, dict) or not isinstance(pricing, dict):
        raise AgentQuotaValidationError("Usage 与价格快照必须是对象")
    _cached_fallback_metadata(usage)
    missing_usage_fields = [
        field for field in _USAGE_COUNT_FIELDS if field not in usage
    ]
    if missing_usage_fields:
        raise AgentQuotaValidationError("Usage 缺少完整的 Token 计数字段")
    counts = {
        "input_uncached_tokens": _token_count(
            usage.get("input_uncached_tokens"), "非缓存输入 Token"
        ),
        "input_cached_tokens": _token_count(
            usage.get("input_cached_tokens"), "缓存输入 Token"
        ),
        "input_cache_write_tokens": _optional_token_count(
            usage.get("input_cache_write_tokens"), "缓存写入 Token"
        ),
        "output_tokens": _token_count(usage.get("output_tokens"), "输出 Token"),
        "reasoning_output_tokens": _token_count(
            usage.get("reasoning_output_tokens"), "推理输出 Token"
        ),
    }
    if not any(counts.values()):
        raise AgentQuotaValidationError("Usage 的 Token 计数不能全部为 0")
    missing_price_fields = [
        field for field in _USAGE_PRICE_FIELDS if field not in pricing
    ]
    if missing_price_fields:
        raise AgentQuotaValidationError("价格快照缺少完整的 Token 单价字段")
    prices = {
        field: _money(pricing.get(field), "Token 单价")
        for field in _USAGE_PRICE_FIELDS
    }
    if any(price < 0 for price in prices.values()):
        raise AgentQuotaValidationError("Token 单价不能为负数")
    with localcontext() as context:
        context.prec = 60
        raw_charge = (
            Decimal(
                counts["input_uncached_tokens"]
                + counts["input_cache_write_tokens"]
            )
            * prices["input_price_per_million"]
            + Decimal(counts["input_cached_tokens"])
            * prices["cached_input_price_per_million"]
            + Decimal(counts["output_tokens"])
            * prices["output_price_per_million"]
        ) / Decimal(1_000_000)
        charge = raw_charge.quantize(_MONEY_QUANTUM, rounding=ROUND_HALF_UP)
    if charge >= _MONEY_LIMIT:
        raise AgentQuotaValidationError("本次 LLM 请求费用超出数据库可存储范围")
    return counts, prices, charge


def _ledger_matches_usage(
    row,
    *,
    user_id,
    session_id,
    endpoint_id,
    endpoint_revision,
    endpoint_model,
    counts,
    prices,
    charge,
    cached_fallback_request_count,
    cached_fallback_input_tokens,
):
    """校验同一幂等键确实是同一条 usage，而非冲突重放。"""

    required_fields = {
        "user_id",
        "session_id",
        "endpoint_id",
        "endpoint_revision",
        "endpoint_model",
        "charged_amount",
        *_USAGE_COUNT_FIELDS,
        *_USAGE_PRICE_FIELDS,
    }
    if not isinstance(row, dict) or any(
        field not in row or row.get(field) is None
        for field in required_fields
    ):
        return False
    try:
        if (
            int(row["user_id"]) != user_id
            or str(row["session_id"]) != session_id
            or int(row["endpoint_id"]) != endpoint_id
            or int(row["endpoint_revision"]) != endpoint_revision
            or str(row["endpoint_model"]) != endpoint_model
        ):
            return False
        if any(
            int(row[field]) != counts[field]
            for field in _USAGE_COUNT_FIELDS
        ):
            return False
        if (
            int(row.get("cached_fallback_request_count") or 0)
            != cached_fallback_request_count
            or int(row.get("cached_fallback_input_tokens") or 0)
            != cached_fallback_input_tokens
        ):
            return False
        if any(
            _money(row[field], "既有 Token 单价") != prices[field]
            for field in _USAGE_PRICE_FIELDS
        ):
            return False
        return _money(row["charged_amount"], "既有请求费用") == charge
    except (AgentQuotaValidationError, TypeError, ValueError):
        return False


def charge_agent_usage(
    *,
    user_id,
    session_id,
    task_id,
    source,
    usage_event_id,
    endpoint_id,
    endpoint_revision,
    endpoint_model,
    usage,
    pricing,
    is_admin=False,
    uses_personal_endpoint=False,
):
    """幂等、原子地记录一条全站 LLM usage。

    普通用户的记录会同步扣减站内额度；管理员也需要保留逐请求、价格冻结
    的成本记录，但不占用额度账户。自有端点的费用由用户自行承担，不进入
    平台账本。
    """

    user_id = _positive_int(user_id, "用户 ID")
    if uses_personal_endpoint:
        return {
            "applied": False,
            "skipped_reason": "personal_endpoint",
            "charged_amount": "0",
            "remaining_amount": None,
            "hard_stop": False,
        }
    session_id = str(session_id or "").strip()
    task_id = str(task_id or "").strip()
    source = str(source or "").strip().lower()
    usage_event_id = str(usage_event_id or "").strip()
    endpoint_model = str(endpoint_model or "").strip()
    if not session_id or len(session_id) > 64:
        raise AgentQuotaValidationError("Agent session_id 无效")
    if not task_id or len(task_id) > 64:
        raise AgentQuotaValidationError("Agent task_id 无效")
    if not _SAFE_SOURCE_RE.fullmatch(source):
        raise AgentQuotaValidationError("Usage 来源无效")
    if not usage_event_id or len(usage_event_id) > 191:
        raise AgentQuotaValidationError("Usage 事件 ID 无效")
    if not endpoint_model or len(endpoint_model) > 255:
        raise AgentQuotaValidationError("LLM 模型名称无效")
    endpoint_id = _positive_int(endpoint_id, "LLM 端点 ID")
    endpoint_revision = _positive_int(endpoint_revision, "LLM 端点版本")
    counts, prices, charge = calculate_agent_usage_charge(usage, pricing)
    (
        cached_fallback_request_count,
        cached_fallback_input_tokens,
    ) = _cached_fallback_metadata(usage)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            account = None
            if is_admin:
                # 管理员没有额度账户。仍锁定用户行，保证同一个 usage 事件
                # 并发重放时可以可靠地走账本幂等分支。
                _require_user(cursor, user_id, admin=True, for_update=True)
            else:
                cursor.execute(
                    "SELECT * FROM agent_quota_accounts WHERE user_id=%s FOR UPDATE",
                    (user_id,),
                )
                account = cursor.fetchone()
                if not account:
                    raise AgentQuotaAccessDeniedError(
                        "请先申请 Agent 额度",
                        decision={
                            "allowed": False,
                            "reason_code": "quota_account_required",
                            "message": "请先申请 Agent 额度",
                        },
                    )
            cursor.execute(
                """
                SELECT * FROM agent_usage_ledger
                WHERE task_id=%s AND source=%s AND usage_event_id=%s
                """,
                (task_id, source, usage_event_id),
            )
            existing = cursor.fetchone()
            if existing:
                if not _ledger_matches_usage(
                    existing,
                    user_id=user_id,
                    session_id=session_id,
                    endpoint_id=endpoint_id,
                    endpoint_revision=endpoint_revision,
                    endpoint_model=endpoint_model,
                    counts=counts,
                    prices=prices,
                    charge=charge,
                    cached_fallback_request_count=cached_fallback_request_count,
                    cached_fallback_input_tokens=cached_fallback_input_tokens,
                ):
                    raise AgentQuotaConflictError(
                        "Usage 事件幂等键与既有记账内容冲突"
                    )
                result = _ledger_from_row(existing, applied=False)
            else:
                if is_admin:
                    # remaining_after 仍为 NOT NULL，管理员账本以 0 作为
                    # 不适用的稳定占位；对外结果会恢复为 None。
                    remaining = Decimal("0")
                    next_used = None
                else:
                    granted = _decimal_from_row(account.get("granted_amount"))
                    used = _decimal_from_row(account.get("used_amount"))
                    next_used = used + charge
                    remaining = granted - next_used
                cursor.execute(
                    """
                    INSERT INTO agent_usage_ledger
                        (user_id, session_id, task_id, source, usage_event_id,
                         endpoint_id, endpoint_revision, endpoint_model,
                         input_uncached_tokens, input_cached_tokens,
                         input_cache_write_tokens, output_tokens,
                         reasoning_output_tokens,
                         input_price_per_million,
                         cached_input_price_per_million,
                         output_price_per_million, charged_amount,
                         remaining_after, cached_fallback_request_count,
                         cached_fallback_input_tokens)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        session_id,
                        task_id,
                        source,
                        usage_event_id,
                        endpoint_id,
                        endpoint_revision,
                        endpoint_model,
                        counts["input_uncached_tokens"],
                        counts["input_cached_tokens"],
                        counts["input_cache_write_tokens"],
                        counts["output_tokens"],
                        counts["reasoning_output_tokens"],
                        prices["input_price_per_million"],
                        prices["cached_input_price_per_million"],
                        prices["output_price_per_million"],
                        charge,
                        remaining,
                        cached_fallback_request_count,
                        cached_fallback_input_tokens,
                    ),
                )
                ledger_id = cursor.lastrowid
                if next_used is not None:
                    cursor.execute(
                        """
                        UPDATE agent_quota_accounts
                        SET used_amount=%s WHERE user_id=%s
                        """,
                        (next_used, user_id),
                    )
                cursor.execute(
                    "SELECT * FROM agent_usage_ledger WHERE id=%s",
                    (ledger_id,),
                )
                result = _ledger_from_row(cursor.fetchone(), applied=True)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    if is_admin:
        # 管理员账本用于成本展示而非配额治理，保持调用方原有的余额语义。
        return {
            **result,
            "remaining_amount": None,
            "hard_stop": False,
        }
    return result


__all__ = [
    "AGENT_PUBLIC_ENABLED_SETTING_KEY",
    "AGENT_QUOTA_HARD_STOP_AMOUNT",
    "AgentQuotaAccessDeniedError",
    "AgentQuotaConflictError",
    "AgentQuotaError",
    "AgentQuotaNotFoundError",
    "AgentQuotaValidationError",
    "adjust_agent_quota",
    "batch_grant_quota_by_classes",
    "calculate_agent_usage_charge",
    "charge_agent_usage",
    "check_agent_start_eligibility",
    "create_agent_quota_request",
    "get_agent_public_enabled",
    "get_agent_quota_summary",
    "get_agent_runtime_quota_summary",
    "get_agent_session_token_usage",
    "get_agent_session_usage_cost",
    "list_agent_quota_grant_classes",
    "list_agent_quota_requests",
    "list_pending_agent_quota_requests",
    "require_agent_start_eligibility",
    "review_agent_quota_request",
    "set_agent_public_enabled",
]
