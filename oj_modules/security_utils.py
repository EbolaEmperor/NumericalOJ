#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""安全相关公共工具：口令哈希（带盐慢哈希 + 兼容历史 sha256）、用户名校验与限流。

历史版本用无盐 sha256 存口令。这里改用 werkzeug 的带盐慢哈希（pbkdf2/scrypt），
登录时若发现是历史 sha256 哈希且校验通过，则透明地重新哈希为新算法（verify-then-rehash），
无需一次性迁移全表。
"""

import hashlib
import re

from werkzeug.security import check_password_hash, generate_password_hash

# 历史无盐 sha256：64 位十六进制
_SHA256_HEX_RE = re.compile(r'^[0-9a-f]{64}$')
# 用户名会出现在 URL、Git 仓库命名、管理员页面和会话键里；只允许稳定的 ASCII 标识符字符。
_USERNAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,49}$')


def validate_username(username):
    """校验并返回规范化用户名。

    返回 ``(ok, cleaned, message)``。用户名作为权限边界字段，不允许 HTML/JS/路径/空白字符。
    """
    cleaned = str(username or '').strip()
    if not cleaned:
        return False, cleaned, '用户名不能为空'
    if not _USERNAME_RE.fullmatch(cleaned):
        return (
            False,
            cleaned,
            '用户名只能包含字母、数字、下划线、点和连字符，长度不超过 50，且必须以字母、数字或下划线开头',
        )
    return True, cleaned, ''


def hash_password(password):
    """返回带盐慢哈希。"""
    return generate_password_hash(str(password or ''))


def verify_password(stored_hash, password):
    """校验口令。返回 (是否正确, 是否需要升级重哈希)。

    - 历史 sha256（无盐）：用 sha256 比对；若通过则标记需要重哈希为新算法。
    - werkzeug 哈希（pbkdf2:/scrypt:/...）：用 check_password_hash 校验。
    """
    if not stored_hash:
        return False, False
    stored = str(stored_hash)
    pw = str(password or '')
    if _SHA256_HEX_RE.match(stored):
        ok = hashlib.sha256(pw.encode()).hexdigest() == stored
        return ok, ok  # 历史哈希校验通过即应升级
    try:
        ok = check_password_hash(stored, pw)
    except Exception:
        ok = False
    return ok, False


def rate_limit_hit(redis_client, key, max_hits, window_seconds):
    """固定窗口计数限流。返回 (是否允许, 距窗口结束的秒数)。

    Redis 不可用或异常时「放行」（fail-open），避免因缓存故障把全站登录/注册卡死。
    """
    if redis_client is None:
        return True, 0
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, int(window_seconds))
        if count > max_hits:
            ttl = redis_client.ttl(key)
            return False, (int(ttl) if ttl and ttl > 0 else int(window_seconds))
        return True, 0
    except Exception:
        return True, 0


def seconds_until_allowed(redis_client, key):
    """返回某限流键距离过期的剩余秒数（用于「请 N 秒后再试」提示）；无则 0。"""
    if redis_client is None:
        return 0
    try:
        ttl = redis_client.ttl(key)
        return int(ttl) if ttl and ttl > 0 else 0
    except Exception:
        return 0


def cooldown_active(redis_client, key, window_seconds):
    """冷却闸：若 key 不存在则置位并放行，存在则拒绝。返回 (是否放行, 剩余秒数)。

    用于「同一邮箱 N 秒内只能发一次验证码」这种节流。
    """
    if redis_client is None:
        return True, 0
    try:
        # SET key 1 NX EX window —— 仅当不存在时置位
        ok = redis_client.set(key, '1', nx=True, ex=int(window_seconds))
        if ok:
            return True, 0
        ttl = redis_client.ttl(key)
        return False, (int(ttl) if ttl and ttl > 0 else int(window_seconds))
    except Exception:
        return True, 0
