#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Redis 客户端的统一构造入口。

本模块负责读取连接配置并构造客户端，不在导入时连接 Redis。严格构造函数不执行
I/O；显式的 ``create_optional_redis_client`` 则为可降级场景集中执行连通性检查。
普通命令、二进制值和可能阻塞的 Pub/Sub 读取使用不同 profile，避免短请求和长轮询
互相继承不合适的超时设置。
"""

from enum import Enum
import math

import config as _config

try:
    import redis as _redis
except Exception:  # pragma: no cover - 允许不需要 Redis 的纯单元测试导入业务模块
    _redis = None


DEFAULT_SOCKET_TIMEOUT_SECONDS = 3.0
DEFAULT_BLOCKING_SOCKET_TIMEOUT_SECONDS = 30.0
DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS = 30


class RedisClientProfile(str, Enum):
    """不同 Redis 使用场景的连接参数集合。"""

    TEXT = "text"
    BINARY = "binary"
    BLOCKING = "blocking"


class RedisClientUnavailable(RuntimeError):
    """当前环境没有可用的 redis-py 客户端。"""


def _positive_seconds(config_module, name, default):
    raw_value = getattr(config_module, name, default)
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} 必须是正数秒值") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} 必须是正数秒值")
    return value


def redis_client_options(profile=RedisClientProfile.TEXT, *, config_module=None):
    """返回指定 profile 的 redis-py 构造参数，不创建网络连接。"""

    config_module = config_module or _config
    try:
        profile = RedisClientProfile(profile)
    except ValueError as exc:
        raise ValueError(f"未知 Redis client profile: {profile!r}") from exc

    socket_timeout = _positive_seconds(
        config_module,
        "REDIS_SOCKET_TIMEOUT_SECONDS",
        DEFAULT_SOCKET_TIMEOUT_SECONDS,
    )
    connect_timeout = _positive_seconds(
        config_module,
        "REDIS_CONNECT_TIMEOUT_SECONDS",
        socket_timeout,
    )
    if profile is RedisClientProfile.BLOCKING:
        socket_timeout = _positive_seconds(
            config_module,
            "REDIS_BLOCKING_SOCKET_TIMEOUT_SECONDS",
            DEFAULT_BLOCKING_SOCKET_TIMEOUT_SECONDS,
        )

    return {
        "host": getattr(config_module, "REDIS_HOST", "127.0.0.1"),
        "port": int(getattr(config_module, "REDIS_PORT", 6379)),
        "db": int(getattr(config_module, "REDIS_DB", 0)),
        "decode_responses": profile is not RedisClientProfile.BINARY,
        "socket_connect_timeout": connect_timeout,
        "socket_timeout": socket_timeout,
        "health_check_interval": DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS,
    }


def create_redis_client(
    profile=RedisClientProfile.TEXT,
    *,
    config_module=None,
    redis_module=None,
):
    """构造指定 profile 的客户端；构造本身不执行 Redis I/O。"""

    backend = _redis if redis_module is None else redis_module
    if backend is None:
        raise RedisClientUnavailable("未安装 redis-py，无法创建 Redis 客户端")
    return backend.StrictRedis(
        **redis_client_options(profile, config_module=config_module),
    )


def create_text_redis_client(*, config_module=None, redis_module=None):
    return create_redis_client(
        RedisClientProfile.TEXT,
        config_module=config_module,
        redis_module=redis_module,
    )


def create_binary_redis_client(*, config_module=None, redis_module=None):
    return create_redis_client(
        RedisClientProfile.BINARY,
        config_module=config_module,
        redis_module=redis_module,
    )


def create_blocking_redis_client(*, config_module=None, redis_module=None):
    return create_redis_client(
        RedisClientProfile.BLOCKING,
        config_module=config_module,
        redis_module=redis_module,
    )


def create_optional_redis_client(
    profile=RedisClientProfile.TEXT,
    *,
    verify_connection=True,
    config_module=None,
    redis_module=None,
):
    """按 fail-open 语义构造可选客户端，不可用时返回 ``None``。

    只有 Redis 明确是缓存、通知或分布式锁的可降级依赖时才应使用本函数；应用组合根
    等强依赖场景继续调用 ``create_*_redis_client`` 并让错误直接暴露。默认执行一次
    ``PING``，把散落在各业务模块的宽泛异常处理和连通性探测收口到这里。
    """

    try:
        client = create_redis_client(
            profile,
            config_module=config_module,
            redis_module=redis_module,
        )
        if verify_connection:
            client.ping()
        return client
    except Exception:
        return None
