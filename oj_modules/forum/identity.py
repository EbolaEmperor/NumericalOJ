#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""讨论区实名/匿名身份的领域规则与事务边界。

匿名只改变公开展示身份：帖子和回复仍保存真实 ``user_id``，同时可选保存一条
不可变的匿名身份记录。匿名名的历史记录永不复用；实名用户名与所有历史匿名名
通过同一个 MySQL advisory lock 串行检查，避免跨表唯一性竞态。
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Callable, TypeVar

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.shared.identicon import text_identicon_presentation
from oj_modules.shared.idempotency import (
    InvalidClientRequestId,
    normalize_client_request_id,
)


logger = logging.getLogger(__name__)

ANONYMOUS_NAME_MAX_WEIGHT = 10
ANONYMOUS_IDENTITY_COOLDOWN = timedelta(hours=24)
IDENTITY_NAMESPACE_LOCK_NAME = "numericaloj:forum_identity_namespace"
IDENTITY_NAMESPACE_LOCK_TIMEOUT_SECONDS = 10

# NFKC 与 ASCII 大小写折叠后比较。既保留明确的系统账号名称，也阻止匿名身份
# 冒充常见的系统/管理角色；已有 bootstrap 管理员不需要任何数据回填。
_RESERVED_NORMALIZED_NAMES = frozenset(
    {
        "admin",
        "administrator",
        "moderator",
        "numericaloj",
        "official",
        "root",
        "system",
        "官方",
        "管理员",
        "系统",
    }
)

_HAN_RANGES = (
    (0x3400, 0x4DBF),   # CJK Unified Ideographs Extension A
    (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    (0xF900, 0xFAFF),   # CJK Compatibility Ideographs
    (0x20000, 0x2A6DF), # Extensions B
    (0x2A700, 0x2B73F), # Extension C
    (0x2B740, 0x2B81F), # Extension D
    (0x2B820, 0x2CEAF), # Extensions E/F
    (0x2CEB0, 0x2EBEF), # Extension F supplement
    (0x2F800, 0x2FA1F), # Compatibility supplement
    (0x30000, 0x3134F), # Extension G
    (0x31350, 0x323AF), # Extension H
)

_T = TypeVar("_T")


class ForumIdentityError(RuntimeError):
    """讨论身份领域错误基类，可由 HTTP 层按 ``code`` 稳定映射。"""

    code = "forum_identity_error"


class AnonymousNameValidationError(ForumIdentityError, ValueError):
    code = "invalid_anonymous_name"


class IdentityNameReservedError(AnonymousNameValidationError):
    code = "reserved_identity_name"


class IdentityNameConflictError(ForumIdentityError, ValueError):
    code = "identity_name_conflict"


# 兼容 HTTP 适配层使用更具体的匿名名异常名称。
AnonymousNameConflictError = IdentityNameConflictError


class AnonymousIdentityRequiredError(ForumIdentityError):
    code = "anonymous_identity_required"


class AnonymousIdentityCooldownError(ForumIdentityError):
    code = "anonymous_identity_cooldown"

    def __init__(self, retry_after_seconds: int, available_at: datetime):
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        self.available_at = _as_utc_naive(available_at)
        super().__init__(f"匿名身份暂不可更换，请在 {self.retry_after_seconds} 秒后重试")


class ForumIdentityStateError(ForumIdentityError):
    code = "forum_identity_state_invalid"


class ForumIdentityUserNotFoundError(ForumIdentityError, LookupError):
    code = "forum_identity_user_not_found"


class IdentityNamespaceLockError(ForumIdentityError):
    code = "identity_namespace_busy"


class ForumIdentityRequestValidationError(ForumIdentityError, ValueError):
    code = "invalid_client_request_id"


class IdentityOperationConflictError(ForumIdentityError):
    code = "identity_operation_conflict"


class PostingIdentityConflictError(ForumIdentityError):
    code = "posting_identity_changed"


def _ascii_casefold(value: str) -> str:
    return "".join(
        chr(ord(char) + 32) if "A" <= char <= "Z" else char
        for char in value
    )


def clean_identity_name(value) -> str:
    """执行统一的 NFKC 与首尾空白清理，但保留展示用 ASCII 大小写。"""
    return unicodedata.normalize("NFKC", str(value or "")).strip()


def normalize_identity_name(value) -> str:
    """生成实名/匿名统一命名空间的比较键。"""
    return _ascii_casefold(clean_identity_name(value))


def _is_han_character(char: str) -> bool:
    codepoint = ord(char)
    return any(start <= codepoint <= end for start, end in _HAN_RANGES)


def _is_allowed_ascii_alias_character(char: str) -> bool:
    return (
        "A" <= char <= "Z"
        or "a" <= char <= "z"
        or "0" <= char <= "9"
        or char in "_-"
    )


def anonymous_name_weight(value) -> int:
    """返回匿名名权重；汉字计 2，其余（经白名单允许的 ASCII）计 1。"""
    return sum(2 if _is_han_character(char) else 1 for char in str(value or ""))


def validate_anonymous_name(value) -> str:
    """校验并返回可持久化的匿名显示名，失败时抛出明确领域异常。"""
    cleaned = clean_identity_name(value)
    if not cleaned:
        raise AnonymousNameValidationError("匿名用户名不能为空")

    for char in cleaned:
        if not (_is_han_character(char) or _is_allowed_ascii_alias_character(char)):
            raise AnonymousNameValidationError(
                "匿名用户名只能包含中文汉字、英文字母、数字、下划线和连字符"
            )

    if normalize_identity_name(cleaned) in _RESERVED_NORMALIZED_NAMES:
        raise IdentityNameReservedError("该名称为系统保留名称")

    weight = anonymous_name_weight(cleaned)
    if weight > ANONYMOUS_NAME_MAX_WEIGHT:
        raise AnonymousNameValidationError(
            "匿名用户名总长度不能超过 10（中文汉字计 2，其他字符计 1）"
        )
    return cleaned


def avatar_presentation(display_name) -> dict:
    """将显示名稳定映射为浏览器可复刻的 8×8 左右对称头像。

    算法固定为 UTF-8 FNV-1a 32-bit 加 xorshift32。``cells`` 使用
    ``row * 8 + column`` 的一维下标，便于模板和 JSON 客户端直接消费。
    """
    return text_identicon_presentation(display_name)


def _secret_bytes(secret_key) -> bytes:
    if isinstance(secret_key, bytes):
        value = secret_key
    else:
        value = str(secret_key or "").encode("utf-8")
    if not value:
        raise ForumIdentityStateError("身份令牌密钥未配置")
    return value


def draft_namespace_token(user_id: int, secret_key) -> str:
    digest = hmac.new(
        _secret_bytes(secret_key),
        f"forum-draft-namespace:v1:{int(user_id)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"d1_{digest}"


def posting_identity_token(
    *,
    user_id: int,
    real_username,
    use_anonymous: bool,
    anonymous_identity_id,
    anonymous_display_name,
    secret_key,
) -> str:
    if use_anonymous:
        if anonymous_identity_id is None or anonymous_display_name is None:
            raise ForumIdentityStateError("匿名身份状态不完整")
        identity_material = (
            f"anonymous:{int(anonymous_identity_id)}:{anonymous_display_name}"
        )
    else:
        identity_material = f"real:{str(real_username or '')}"
    digest = hmac.new(
        _secret_bytes(secret_key),
        (
            f"forum-posting-identity:v1:{int(user_id)}:"
            f"{identity_material}"
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"p1_{digest}"


def posting_identity_token_from_state(state: dict, secret_key) -> str:
    anonymous = state.get("anonymous_identity") or {}
    return posting_identity_token(
        user_id=int(state["user_id"]),
        real_username=state.get("real_username"),
        use_anonymous=bool(state.get("use_anonymous")),
        anonymous_identity_id=anonymous.get("id"),
        anonymous_display_name=anonymous.get("display_name"),
        secret_key=secret_key,
    )


def _posting_identity_token_from_row(row: dict, secret_key) -> str:
    return posting_identity_token(
        user_id=int(row["user_id"]),
        real_username=row.get("real_username"),
        use_anonymous=bool(row.get("use_anonymous")),
        anonymous_identity_id=row.get("anonymous_identity_id"),
        anonymous_display_name=row.get("anonymous_display_name"),
        secret_key=secret_key,
    )


def _result_scalar(row, *preferred_keys):
    if isinstance(row, dict):
        for key in preferred_keys:
            if key in row:
                return row[key]
        return next(iter(row.values()), None)
    if isinstance(row, (tuple, list)):
        return row[0] if row else None
    return row


def acquire_identity_namespace_lock(
    cursor,
    *,
    timeout_seconds: int = IDENTITY_NAMESPACE_LOCK_TIMEOUT_SECONDS,
) -> None:
    """取得实名/匿名跨表命名空间锁；锁属于当前 MySQL 连接而非事务。"""
    cursor.execute(
        "SELECT GET_LOCK(%s, %s) AS identity_namespace_locked",
        (IDENTITY_NAMESPACE_LOCK_NAME, int(timeout_seconds)),
    )
    acquired = _result_scalar(cursor.fetchone(), "identity_namespace_locked")
    if int(acquired or 0) != 1:
        raise IdentityNamespaceLockError("身份命名空间正忙，请稍后重试")


def release_identity_namespace_lock(cursor) -> None:
    """释放当前连接持有的身份命名空间锁，防止锁随连接返回池后泄露。"""
    cursor.execute(
        "SELECT RELEASE_LOCK(%s) AS identity_namespace_released",
        (IDENTITY_NAMESPACE_LOCK_NAME,),
    )
    released = _result_scalar(cursor.fetchone(), "identity_namespace_released")
    if int(released or 0) != 1:
        raise IdentityNamespaceLockError("身份命名空间锁释放失败")


def assert_identity_name_available(
    cursor,
    display_name,
    *,
    exclude_user_id: int | None = None,
) -> str:
    """在已持有 namespace lock 时检查实名与所有匿名历史名，返回规范名。

    现有 ``users`` 表没有规范名列，且结构同步器不能安全回填。用户名本身受 ASCII
    白名单约束，因此这里在锁内读取用户名并用同一 Python 规范化函数比较，既兼容
    历史账号，也无需引入一次性数据迁移。
    """
    normalized_name = normalize_identity_name(display_name)
    if not normalized_name:
        raise AnonymousNameValidationError("身份名称不能为空")
    if normalized_name in _RESERVED_NORMALIZED_NAMES:
        raise IdentityNameReservedError("该名称为系统保留名称")

    cursor.execute("SELECT id, username FROM users")
    for row in cursor.fetchall() or ():
        row_id = int(row["id"])
        if exclude_user_id is not None and row_id == int(exclude_user_id):
            continue
        if normalize_identity_name(row.get("username")) == normalized_name:
            raise IdentityNameConflictError("该名称已被其他身份使用")

    cursor.execute(
        """
        SELECT id
        FROM forum_anonymous_identities
        WHERE normalized_name=%s
        LIMIT 1
        """,
        (normalized_name,),
    )
    if cursor.fetchone():
        raise IdentityNameConflictError("该名称已被其他身份使用")
    return normalized_name


def _as_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _coerce_datetime(value) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return _as_utc_naive(value)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return _as_utc_naive(datetime.fromisoformat(text))
    except ValueError as exc:
        raise ForumIdentityStateError("匿名身份更换时间无效") from exc


def _utc_now(now: datetime | None = None) -> datetime:
    if now is None:
        now = datetime.now(timezone.utc)
    return _as_utc_naive(now)


def _cooldown_status(changed_at, *, now: datetime) -> tuple[int, datetime | None]:
    changed = _coerce_datetime(changed_at)
    if changed is None:
        return 0, None
    available_at = changed + ANONYMOUS_IDENTITY_COOLDOWN
    remaining = max(0, math.ceil((available_at - now).total_seconds()))
    return remaining, available_at


def _iso_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _as_utc_naive(value).replace(tzinfo=timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _fetch_identity_row(cursor, user_id: int, *, for_update: bool) -> dict:
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        f"""
        SELECT
          u.id AS user_id,
          u.username AS real_username,
          s.user_id AS settings_user_id,
          s.use_anonymous,
          s.current_anonymous_identity_id,
          s.identity_changed_at,
          a.id AS anonymous_identity_id,
          a.display_name AS anonymous_display_name
        FROM users u
        LEFT JOIN forum_user_identity_settings s ON s.user_id=u.id
        LEFT JOIN forum_anonymous_identities a
          ON a.id=s.current_anonymous_identity_id
         AND a.user_id=u.id
        WHERE u.id=%s{suffix}
        """,
        (int(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        raise ForumIdentityUserNotFoundError("用户不存在")

    current_id = row.get("current_anonymous_identity_id")
    anonymous_id = row.get("anonymous_identity_id")
    if current_id is not None and anonymous_id is None:
        raise ForumIdentityStateError("当前匿名身份不属于该用户或已损坏")
    return row


def _serialize_identity_state(row: dict, *, now: datetime) -> dict:
    current_id = row.get("anonymous_identity_id")
    anonymous_name = row.get("anonymous_display_name")
    use_anonymous = bool(row.get("use_anonymous"))
    if use_anonymous and current_id is None:
        raise ForumIdentityStateError("匿名开关已开启，但尚未设置匿名身份")

    changed_at = _coerce_datetime(row.get("identity_changed_at"))
    retry_after, available_at = _cooldown_status(changed_at, now=now)
    anonymous_identity = None
    if current_id is not None:
        anonymous_identity = {
            "id": int(current_id),
            "display_name": str(anonymous_name),
            "avatar": avatar_presentation(anonymous_name),
        }

    real_username = str(row.get("real_username") or "")
    if use_anonymous:
        effective_identity = {
            "kind": "anonymous",
            "display_name": str(anonymous_name),
            "anonymous_identity_id": int(current_id),
            "avatar": avatar_presentation(anonymous_name),
        }
    else:
        effective_identity = {
            "kind": "real",
            "display_name": real_username,
            "anonymous_identity_id": None,
            "avatar": avatar_presentation(real_username),
        }

    return {
        "user_id": int(row["user_id"]),
        "real_username": real_username,
        "use_anonymous": use_anonymous,
        "anonymous_identity": anonymous_identity,
        "effective_identity": effective_identity,
        "identity_changed_at": _iso_utc(changed_at),
        "can_refresh": current_id is None or retry_after == 0,
        "refresh_available_at": _iso_utc(available_at),
        "refresh_retry_after_seconds": retry_after,
    }


def get_identity_state(user_id: int, *, now: datetime | None = None) -> dict:
    """读取当前用户自己的实名/匿名设置，返回可直接 JSON 序列化的状态。"""
    current_time = _utc_now(now)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_identity_row(cursor, int(user_id), for_update=False)
            return _serialize_identity_state(row, now=current_time)
    finally:
        conn.close()


def set_anonymous_mode(
    user_id: int,
    enabled: bool,
    *,
    now: datetime | None = None,
) -> dict:
    """启停匿名模式；首次开启前必须已经成功创建匿名身份。"""
    current_time = _utc_now(now)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            row = _fetch_identity_row(cursor, int(user_id), for_update=True)
            if enabled and row.get("anonymous_identity_id") is None:
                raise AnonymousIdentityRequiredError("首次开启匿名身份前必须先设置匿名用户名")

            if row.get("settings_user_id") is None:
                # 缺少设置行时只能是关闭状态；数据库默认语义已经是关闭，无需写空行。
                result = _serialize_identity_state(row, now=current_time)
            else:
                cursor.execute(
                    """
                    UPDATE forum_user_identity_settings
                    SET use_anonymous=%s
                    WHERE user_id=%s
                    """,
                    (1 if enabled else 0, int(user_id)),
                )
                row["use_anonymous"] = 1 if enabled else 0
                result = _serialize_identity_state(row, now=current_time)
        conn.commit()
        return result
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def run_identity_namespace_transaction(
    operation: Callable[[object], _T],
    *,
    connection_factory: Callable[[], object] | None = None,
) -> _T:
    """在统一命名空间锁内执行并提交一个数据库回调。

    advisory lock 在事务提交后才释放，因此另一个注册、改名或匿名名更换操作
    不会在前一事务尚不可见时通过跨表检查。
    ``connection_factory`` 供兼容调用方沿用自身可替换的事务连接入口。
    """
    factory = get_db_connection if connection_factory is None else connection_factory
    conn = factory()
    lock_acquired = False
    result: _T
    try:
        with conn.cursor() as cursor:
            acquire_identity_namespace_lock(cursor)
            lock_acquired = True
            result = operation(cursor)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        release_error = None
        if lock_acquired:
            try:
                with conn.cursor() as cursor:
                    release_identity_namespace_lock(cursor)
            except Exception as exc:  # pragma: no cover - 仅连接级灾难故障
                release_error = exc
                logger.exception("释放身份命名空间锁失败")
        if release_error is None:
            conn.close()
        else:
            # 事务一旦提交便不能再向调用方报“失败”，否则客户端重试会得到重名/
            # 冷却冲突。池代理的 close() 只会归还连接，无法释放遗留的 named lock，
            # 因此必须物理丢弃；非池连接则由 close() 直接断开并释放连接级锁。
            discard = getattr(conn, "discard", None)
            try:
                if callable(discard):
                    discard()
                else:
                    conn.close()
            except Exception:  # pragma: no cover - 双重连接故障
                logger.exception("丢弃持有身份命名空间锁的连接失败")
    return result


def rotate_anonymous_identity(
    user_id: int,
    display_name,
    *,
    enable: bool | None = None,
    client_request_id=None,
    now: datetime | None = None,
) -> dict:
    """首次设置或更换匿名身份。

    首次设置可立即进行；一旦成功，每次后续更换必须与上次成功操作间隔 24 小时。
    校验失败、重名或数据库回滚都不会推进冷却时间。``enable=None`` 保留当前开关；
    首次从匿名开关触发设置时传 ``enable=True``。
    """
    cleaned_name = validate_anonymous_name(display_name)
    normalized_name = normalize_identity_name(cleaned_name)
    try:
        request_id = normalize_client_request_id(client_request_id)
    except InvalidClientRequestId as exc:
        raise ForumIdentityRequestValidationError(str(exc)) from exc
    current_time = _utc_now(now)
    requested_enable = None if enable is None else (1 if bool(enable) else 0)

    def operation(cursor):
        cursor.execute(
            """
            SELECT
              display_name,
              normalized_name,
              requested_enable
            FROM forum_identity_operation_receipts
            WHERE user_id=%s AND client_request_id=%s
            LIMIT 1
            FOR UPDATE
            """,
            (int(user_id), request_id),
        )
        receipt = cursor.fetchone()
        if receipt:
            if (
                receipt.get("display_name") != cleaned_name
                or receipt.get("normalized_name") != normalized_name
                or receipt.get("requested_enable") != requested_enable
            ):
                raise IdentityOperationConflictError(
                    "该幂等键已用于另一项匿名身份更换"
                )
            # 成功响应丢失后的重试只确认原操作已经成功，绝不能把设置重新指回
            # 旧匿名身份；否则迟到的重试可能覆盖用户后来主动切换的身份。
            current_row = _fetch_identity_row(cursor, int(user_id), for_update=True)
            return _serialize_identity_state(current_row, now=current_time)

        row = _fetch_identity_row(cursor, int(user_id), for_update=True)
        current_identity_id = row.get("anonymous_identity_id")
        retry_after, available_at = _cooldown_status(
            row.get("identity_changed_at"),
            now=current_time,
        )
        if current_identity_id is not None and retry_after:
            raise AnonymousIdentityCooldownError(retry_after, available_at)

        checked_normalized_name = assert_identity_name_available(
            cursor,
            cleaned_name,
        )
        # 防止未来改动让校验键和入库键产生分歧。
        if checked_normalized_name != normalized_name:
            raise ForumIdentityStateError("匿名身份规范化结果不一致")

        cursor.execute(
            """
            INSERT INTO forum_anonymous_identities
              (user_id, display_name, normalized_name, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (
                int(user_id),
                cleaned_name,
                normalized_name,
                current_time,
            ),
        )
        new_identity_id = int(cursor.lastrowid)
        next_enabled = bool(row.get("use_anonymous")) if enable is None else bool(enable)

        if row.get("settings_user_id") is None:
            cursor.execute(
                """
                INSERT INTO forum_user_identity_settings
                  (user_id, use_anonymous, current_anonymous_identity_id,
                   identity_changed_at)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    int(user_id),
                    1 if next_enabled else 0,
                    new_identity_id,
                    current_time,
                ),
            )
        else:
            cursor.execute(
                """
                UPDATE forum_user_identity_settings
                SET use_anonymous=%s,
                    current_anonymous_identity_id=%s,
                    identity_changed_at=%s
                WHERE user_id=%s
                """,
                (
                    1 if next_enabled else 0,
                    new_identity_id,
                    current_time,
                    int(user_id),
                ),
            )

        row.update(
            {
                "settings_user_id": int(user_id),
                "use_anonymous": 1 if next_enabled else 0,
                "current_anonymous_identity_id": new_identity_id,
                "anonymous_identity_id": new_identity_id,
                "anonymous_display_name": cleaned_name,
                "identity_changed_at": current_time,
            }
        )
        cursor.execute(
            """
            INSERT INTO forum_identity_operation_receipts (
              user_id,
              client_request_id,
              display_name,
              normalized_name,
              requested_enable,
              anonymous_identity_id,
              result_use_anonymous,
              created_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                int(user_id),
                request_id,
                cleaned_name,
                normalized_name,
                requested_enable,
                new_identity_id,
                1 if next_enabled else 0,
                current_time,
            ),
        )
        return _serialize_identity_state(row, now=current_time)

    return run_identity_namespace_transaction(operation)


def resolve_posting_identity(
    cursor,
    user_id: int,
    *,
    expected_identity_token=None,
    token_secret=None,
) -> int | None:
    """在发帖/回复事务内锁定并返回匿名身份 id；实名状态返回 ``None``。"""
    row = _fetch_identity_row(cursor, int(user_id), for_update=True)
    if expected_identity_token is not None or token_secret is not None:
        if not expected_identity_token or token_secret is None:
            raise PostingIdentityConflictError("发布身份凭据缺失，请刷新身份后重试")
        current_token = _posting_identity_token_from_row(row, token_secret)
        if not hmac.compare_digest(str(expected_identity_token), current_token):
            raise PostingIdentityConflictError(
                "发布身份已在其他页面更改，请确认当前身份后重试"
            )
    if not bool(row.get("use_anonymous")):
        return None
    identity_id = row.get("anonymous_identity_id")
    if identity_id is None:
        raise AnonymousIdentityRequiredError("匿名身份尚未设置")
    return int(identity_id)


__all__ = [
    "ANONYMOUS_IDENTITY_COOLDOWN",
    "ANONYMOUS_NAME_MAX_WEIGHT",
    "AnonymousIdentityCooldownError",
    "AnonymousIdentityRequiredError",
    "AnonymousNameConflictError",
    "AnonymousNameValidationError",
    "ForumIdentityError",
    "ForumIdentityRequestValidationError",
    "ForumIdentityStateError",
    "ForumIdentityUserNotFoundError",
    "IdentityNameConflictError",
    "IdentityNameReservedError",
    "IdentityNamespaceLockError",
    "IdentityOperationConflictError",
    "PostingIdentityConflictError",
    "acquire_identity_namespace_lock",
    "anonymous_name_weight",
    "assert_identity_name_available",
    "avatar_presentation",
    "clean_identity_name",
    "draft_namespace_token",
    "get_identity_state",
    "normalize_identity_name",
    "posting_identity_token",
    "posting_identity_token_from_state",
    "release_identity_namespace_lock",
    "resolve_posting_identity",
    "rotate_anonymous_identity",
    "run_identity_namespace_transaction",
    "set_anonymous_mode",
    "validate_anonymous_name",
]
