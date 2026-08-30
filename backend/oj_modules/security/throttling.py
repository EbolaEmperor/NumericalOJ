"""依赖调用方 Redis 客户端的限流与冷却原语。"""


def rate_limit_hit(redis_client, key, max_hits, window_seconds):
    """固定窗口计数限流，Redis 异常时按既有契约 fail-open。"""
    if redis_client is None:
        return True, 0
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, int(window_seconds))
        if count > max_hits:
            ttl = redis_client.ttl(key)
            return False, int(ttl) if ttl and ttl > 0 else int(window_seconds)
        return True, 0
    except Exception:
        return True, 0


def seconds_until_allowed(redis_client, key):
    """返回限流键的剩余秒数，无键或 Redis 异常时返回 0。"""
    if redis_client is None:
        return 0
    try:
        ttl = redis_client.ttl(key)
        return int(ttl) if ttl and ttl > 0 else 0
    except Exception:
        return 0


def cooldown_active(redis_client, key, window_seconds):
    """原子设置冷却键并返回 ``(是否放行, 剩余秒数)``。"""
    if redis_client is None:
        return True, 0
    try:
        ok = redis_client.set(key, "1", nx=True, ex=int(window_seconds))
        if ok:
            return True, 0
        ttl = redis_client.ttl(key)
        return False, int(ttl) if ttl and ttl > 0 else int(window_seconds)
    except Exception:
        return True, 0


__all__ = ["cooldown_active", "rate_limit_hit", "seconds_until_allowed"]
