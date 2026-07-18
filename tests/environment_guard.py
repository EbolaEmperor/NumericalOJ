# -*- coding: utf-8 -*-
"""破坏性测试的环境安全判定。

本模块只接收显式参数，不读取环境变量、配置文件、主机名或文件系统，便于在不连接
MySQL/Redis 的情况下完整测试安全策略。调用方负责收集运行时信息，并在任何建库、
清库、删表或 ``FLUSHDB`` 之前调用 :func:`assert_disposable_test_target`。
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import posixpath


PRODUCTION_CHECKOUT = "/home/ebola/oj"
_PRODUCTION_HOSTS = frozenset({"computing", "why-server"})
_LOCAL_HOST_NAMES = frozenset({"localhost"})
_MYSQL_CONTAINER_HOSTS = frozenset({"mysql"})
_REDIS_CONTAINER_HOSTS = frozenset({"redis"})


@dataclass(frozen=True)
class DestructiveTestTarget:
    """执行破坏性测试所需的全部环境事实。"""

    test_env: str | None
    hostname: str
    checkout_path: str
    mysql_host: str
    mysql_db: str
    redis_host: str
    redis_db: int | str


class UnsafeTestEnvironmentError(RuntimeError):
    """测试目标不能被证明为一次性环境。"""


def _normalized_host(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _is_loopback_host(value: str) -> bool:
    host = _normalized_host(value)
    if host in _LOCAL_HOST_NAMES:
        return True
    # IPv6 URL 常把地址写成 [::1]；配置项本身通常不带括号，但这里一并兼容。
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _is_allowed_service_host(value: str, container_hosts: frozenset[str]) -> bool:
    host = _normalized_host(value)
    return _is_loopback_host(host) or host in container_hosts


def _normalized_checkout(value: str) -> str:
    # 调用方传入 resolve() 后的路径；这里仍做纯字符串归一化，避免尾斜杠绕过。
    return posixpath.normpath(str(value or "").replace("\\", "/"))


def _looks_like_test_database(value: str) -> bool:
    name = str(value or "").strip().lower()
    return name.startswith("test_") or name.endswith("_test") or "_test_" in name


def unsafe_environment_reasons(target: DestructiveTestTarget) -> tuple[str, ...]:
    """返回所有不安全原因；空元组表示目标满足 fail-closed 策略。"""

    reasons: list[str] = []

    if str(target.test_env or "").strip() != "1":
        reasons.append("必须显式设置 NUMOJ_TEST_ENV=1")

    hostname = _normalized_host(target.hostname)
    short_hostname = hostname.split(".", 1)[0]
    if not hostname:
        reasons.append("无法确认当前主机名，按 fail-closed 策略拒绝运行")
    elif short_hostname in _PRODUCTION_HOSTS:
        reasons.append(f"禁止在生产主机 {target.hostname!r} 上运行破坏性测试")

    checkout = _normalized_checkout(target.checkout_path)
    if not posixpath.isabs(checkout):
        reasons.append(f"检出目录 {target.checkout_path!r} 不是可验证的绝对路径")
    elif checkout == PRODUCTION_CHECKOUT or checkout.startswith(f"{PRODUCTION_CHECKOUT}/"):
        reasons.append(f"禁止在生产检出目录 {checkout!r} 中运行测试")

    if not _is_allowed_service_host(target.mysql_host, _MYSQL_CONTAINER_HOSTS):
        reasons.append(
            f"MYSQL_HOST={target.mysql_host!r} 不是 loopback 或容器服务名 'mysql'"
        )

    mysql_db = str(target.mysql_db or "").strip()
    if mysql_db.lower() == "myojdb":
        reasons.append("禁止使用默认/生产数据库 MYSQL_DB='myojdb'")
    elif not _looks_like_test_database(mysql_db):
        reasons.append(
            f"MYSQL_DB={mysql_db!r} 未使用专用测试库命名（例如 'myojdb_test'）"
        )

    if not _is_allowed_service_host(target.redis_host, _REDIS_CONTAINER_HOSTS):
        reasons.append(
            f"REDIS_HOST={target.redis_host!r} 不是 loopback 或容器服务名 'redis'"
        )

    try:
        redis_db = int(target.redis_db)
    except (TypeError, ValueError):
        reasons.append(f"REDIS_DB={target.redis_db!r} 不是有效整数")
    else:
        if redis_db <= 0:
            reasons.append("REDIS_DB 必须是大于 0 的专用测试 DB，禁止使用默认 DB 0")

    return tuple(reasons)


def assert_disposable_test_target(target: DestructiveTestTarget) -> None:
    """目标不安全时一次性报告全部原因。"""

    reasons = unsafe_environment_reasons(target)
    if reasons:
        details = "\n".join(f"- {reason}" for reason in reasons)
        raise UnsafeTestEnvironmentError(
            "拒绝执行可能清空 MySQL/Redis 的测试：\n" + details
        )
