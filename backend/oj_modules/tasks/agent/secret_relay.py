#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent 外部服务密钥的短生命周期宿主转发代理。

容器只获得每个 relay 独立生成的临时凭据及宿主转发地址。模型端点 API Key
和 WebSearch MCP Authorization 始终只保存在宿主进程内存中；代理验证临时
凭据后剥离全部来访凭据，并向冻结的同源、同 base path 上游注入真实凭据。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, replace
import errno
import hmac
import http.client
import http.server
import json
import logging
import os
import re
import secrets
import select
import socket
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from backend.oj_modules.security.outbound import (
    PublicOutboundTargetError,
    resolve_public_http_target,
)
from backend.oj_modules.tasks.agent.identity_relay import (
    _BoundedIdentityRelayServer,
    _RequestRejected,
    _canonical_request_path,
    _read_response_chunk,
    _relay_bind_host,
    _request_parts,
    _single_header,
)


logger = logging.getLogger(__name__)

_CONTAINER_HOST = "host.docker.internal"
_TEMPORARY_SECRET_BYTES = 32
_MAX_REQUESTS_PER_RELAY = 2048
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_UPSTREAM_TIMEOUT_SECONDS = 600
_CONNECT_POLL_INTERVAL_SECONDS = 0.2
_CLIENT_TIMEOUT_SECONDS = 30
# handler 可能正阻塞在受 _CLIENT_TIMEOUT_SECONDS 约束的客户端读写中。
# 清理等待必须覆盖该边界并留出线程 finally 收束时间；否则正常的连接关闭
# 会在 5 秒后被误判为凭据代理泄漏。
_HANDLER_SHUTDOWN_TIMEOUT_SECONDS = _CLIENT_TIMEOUT_SECONDS + 5
_HANDLER_SHUTDOWN_POLL_SECONDS = 0.2
_ENDPOINT_USAGE_DRAIN_SECONDS = _UPSTREAM_TIMEOUT_SECONDS + 5
# Claude Code workflow 会让多个 subagent 同时请求模型和 MCP。身份 relay 仍
# 保持 4 条连接的窄能力边界；密钥 relay 需要覆盖一轮正常 workflow 的并发，
# 同时继续由逐 relay 请求次数、请求体总量和响应大小限制资源消耗。
_MAX_SECRET_RELAY_CONNECTIONS = 128
_DEFAULT_CACHED_HIT_RATE_PERCENT = 90
_REDACTION = b"[REDACTED]"
_EMPTY_ASSISTANT_CONTENT_ERROR = (
    "Provider returned error: empty assistant content; retry the request"
)
_ALLOWED_METHODS = {
    "openai": frozenset({"POST"}),
    "anthropic": frozenset({"POST"}),
    "mcp": frozenset({"GET", "POST", "DELETE"}),
}
_MAX_REQUEST_BYTES = {
    "openai": 16 * 1024 * 1024,
    "anthropic": 16 * 1024 * 1024,
    "mcp": 2 * 1024 * 1024,
}
_MAX_INFLIGHT_REQUEST_BYTES = {
    "openai": 32 * 1024 * 1024,
    "anthropic": 32 * 1024 * 1024,
    "mcp": 4 * 1024 * 1024,
}
_ALLOWED_RELATIVE_ROUTES = {
    "openai": {
        "POST": frozenset({
            "/chat/completions",
            "/responses",
            "/responses/compact",
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/responses/compact",
        }),
    },
    "anthropic": {
        "POST": frozenset({
            "/messages",
            "/messages/count_tokens",
            "/v1/messages",
            "/v1/messages/count_tokens",
        }),
    },
}
_FORWARDED_REQUEST_HEADERS = {
    "openai": {
        "accept": "Accept",
        "content-type": "Content-Type",
        "openai-beta": "OpenAI-Beta",
        "user-agent": "User-Agent",
    },
    "anthropic": {
        "accept": "Accept",
        "anthropic-beta": "Anthropic-Beta",
        "anthropic-version": "Anthropic-Version",
        "content-type": "Content-Type",
        "user-agent": "User-Agent",
    },
    "mcp": {
        "accept": "Accept",
        "content-type": "Content-Type",
        "last-event-id": "Last-Event-ID",
        "mcp-protocol-version": "MCP-Protocol-Version",
        "mcp-session-id": "MCP-Session-Id",
        "user-agent": "User-Agent",
    },
}

_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "expect",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})
_CREDENTIAL_HEADERS = frozenset({
    "api-key",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
})
_SENSITIVE_RESPONSE_HEADERS = frozenset({
    "location",
    "proxy-authenticate",
    "refresh",
    "server",
    "set-cookie",
    "set-cookie2",
})


class AgentSecretRelayError(RuntimeError):
    """外部服务密钥代理配置或运行失败。"""


class AgentSecretRelayCleanupError(AgentSecretRelayError):
    """外部服务密钥代理关闭状态未知。"""


class AgentSecretRelayUsageError(AgentSecretRelayError):
    """模型响应 usage 缺失、无效或未能完成记账。"""


class AgentSecretRelayUsageHardStopError(AgentSecretRelayUsageError):
    """模型请求完成记账后触发用户额度硬停。"""


def _open_interruptible_stream_connection(
    host,
    port,
    timeout,
    source_address,
    handle,
):
    """替代 socket.create_connection，使上游建连可被 relay close() 中断。

    未连接的 socket 先登记到中断句柄；relay 关闭后最多一个轮询周期即放弃建连，
    避免 handler 在凭据已被丢弃后仍长时间停留在建连阶段，导致关闭等待超时。
    DNS 解析本身不可中断，由操作系统限时；每次地址尝试沿用原有整体超时。
    """

    if handle is not None and handle.is_closed():
        raise OSError("secret relay is closing")
    per_attempt_timeout = (
        None
        if timeout is None or timeout is socket._GLOBAL_DEFAULT_TIMEOUT
        else timeout
    )
    last_error = None
    for _family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(
        host,
        port,
        0,
        socket.SOCK_STREAM,
    ):
        if handle is not None and handle.is_closed():
            raise OSError("secret relay is closing")
        sock = socket.socket(_family, _type, _proto)
        try:
            if source_address:
                sock.bind(source_address)
            if handle is not None and not handle.remember_socket(sock):
                raise OSError("secret relay is closing")
            sock.setblocking(False)
            error = sock.connect_ex(sockaddr)
            deadline = (
                None
                if per_attempt_timeout is None
                else time.monotonic() + float(per_attempt_timeout)
            )
            while error in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                wait = _CONNECT_POLL_INTERVAL_SECONDS
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout("Connection timed out")
                    wait = min(wait, remaining)
                try:
                    select.select([], [sock], [], wait)
                except (InterruptedError, OSError, ValueError):
                    pass
                if handle is not None and handle.is_closed():
                    raise OSError("secret relay is closing")
                error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error == 0:
                    break
            if error:
                raise OSError(error, os.strerror(error), sockaddr)
            sock.setblocking(True)
            if per_attempt_timeout is not None:
                sock.settimeout(per_attempt_timeout)
            return sock
        except OSError as exc:
            try:
                sock.close()
            except OSError:
                pass
            if str(exc) == "secret relay is closing":
                raise
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo 未返回可用地址")


class _RelayConnectionMixin:
    """让 relay 能在 HTTPConnection 懒连接完成时立即取得底层 socket。"""

    def __init__(self, *args, connect_host="", **kwargs):
        self._relay_connect_host = str(connect_host or "").strip()
        super().__init__(*args, **kwargs)

    def connect(self):
        original_create_connection = getattr(self, "_create_connection", None)
        handle = getattr(self, "_relay_interrupt_handle", None)
        pinned_host = self._relay_connect_host
        # 新版 Python 的 HTTPConnection.__init__ 会把默认的
        # socket.create_connection 写进实例属性；只有与之不同的可调用对象
        # 才是调用方（如测试）显式注入的连接工厂。
        injected = (
            original_create_connection is not None
            and original_create_connection is not socket.create_connection
        )
        managed = handle is not None and not injected
        if managed:
            def create_managed_connection(
                address,
                timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                source_address=None,
            ):
                target_host = pinned_host or address[0]
                return _open_interruptible_stream_connection(
                    target_host,
                    address[1],
                    timeout,
                    source_address,
                    handle,
                )

            self._create_connection = create_managed_connection
        elif pinned_host and original_create_connection is not None:
            def create_pinned_connection(address, *args, **kwargs):
                return original_create_connection(
                    (pinned_host, address[1]),
                    *args,
                    **kwargs,
                )

            self._create_connection = create_pinned_connection
        try:
            # HTTPSConnection 仍以 self.host 执行 SNI 与证书校验；只有底层
            # 如需固定解析结果，调用方可以提供 connect_host；默认按主机名连接。
            super().connect()
        finally:
            if original_create_connection is not None:
                self._create_connection = original_create_connection
        if handle is not None and not handle.remember_socket(self.sock):
            raise OSError("secret relay is closing")


class _RelayHTTPConnection(_RelayConnectionMixin, http.client.HTTPConnection):
    pass


class _RelayHTTPSConnection(_RelayConnectionMixin, http.client.HTTPSConnection):
    pass


class _InterruptibleHTTPConnection:
    """先 shutdown 底层 socket，再关闭可能仍被 HTTPResponse 引用的连接。"""

    def __init__(self, connection):
        self.connection = connection
        self._lock = threading.Lock()
        self._socket = None
        self._closed = False
        self._close_event = threading.Event()
        connection._relay_interrupt_handle = self

    def is_closed(self):
        return self._close_event.is_set()

    @staticmethod
    def _shutdown_socket(upstream_socket):
        if upstream_socket is None:
            return
        try:
            upstream_socket.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass

    def remember_socket(self, upstream_socket=None):
        current_socket = (
            upstream_socket
            if upstream_socket is not None
            else getattr(self.connection, "sock", None)
        )
        with self._lock:
            if not self._closed:
                if current_socket is not None:
                    self._socket = current_socket
                return True
        # close() 可能发生在 HTTPConnection 的懒连接建立之前。连接一旦
        # 出现就立即中断，不能让已进入 closing 的 relay 再发送请求头。
        self._shutdown_socket(current_socket)
        try:
            self.connection.close()
        except Exception:
            pass
        return False

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            upstream_socket = self._socket or getattr(
                self.connection,
                "sock",
                None,
            )
        # 先通知仍停留在建连轮询中的调用方，再中断已建立的 socket。
        self._close_event.set()
        # socket.makefile() 可能仍被 HTTPResponse.read1() 持有。仅调用
        # HTTPConnection.close() 不能可靠唤醒另一个线程里的阻塞读取。
        self._shutdown_socket(upstream_socket)
        self.connection.close()


def _validate_header_value(value, label):
    normalized = str(value or "").strip()
    if (
        not normalized
        or len(normalized.encode("utf-8")) > 65_535
        or any(not 0x20 <= ord(char) <= 0x7E for char in normalized)
    ):
        raise AgentSecretRelayError(f"{label} 无效")
    return normalized


@dataclass(frozen=True, slots=True)
class _FrozenUpstream:
    scheme: str
    host: str
    port: int
    connect_host: str
    origin_url: str
    base_path: str
    base_query: str
    container_base_path: str

    def open_connection(self):
        connection_type = (
            _RelayHTTPSConnection
            if self.scheme == "https"
            else _RelayHTTPConnection
        )
        return connection_type(
            self.host,
            self.port,
            timeout=_UPSTREAM_TIMEOUT_SECONDS,
            connect_host=self.connect_host,
        )

    def target_path(self, canonical_target):
        parts = urlsplit(str(canonical_target or ""))
        query = "&".join(
            item for item in (self.base_query, parts.query) if item
        )
        return urlunsplit(("", "", parts.path, query, ""))

    def target_url(self, canonical_target):
        return self.origin_url + self.target_path(canonical_target)


def _normalize_upstream_base_url(
    value,
    *,
    preserve_trailing_slash=False,
):
    raw = str(value or "").strip()
    if (
        not raw
        or "\\" in raw
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw)
    ):
        raise AgentSecretRelayError("外部服务 Base URL 无效")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise AgentSecretRelayError("外部服务 Base URL 无效") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise AgentSecretRelayError(
            "外部服务 Base URL 必须是无凭据的 HTTP(S) 地址"
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise AgentSecretRelayError("外部服务 Base URL 端口无效") from exc

    raw_path = parts.path or "/"
    if raw_path != "/" and not preserve_trailing_slash:
        raw_path = raw_path.rstrip("/") or "/"
    try:
        decoded_path, canonical_path = _canonical_request_path(
            raw_path,
            allow_trailing_slash=preserve_trailing_slash,
        )
    except _RequestRejected as exc:
        raise AgentSecretRelayError("外部服务 Base URL 路径无效") from exc
    host = str(parts.hostname).lower().rstrip(".")
    use_port = int(port or (443 if parts.scheme.lower() == "https" else 80))
    if host == _CONTAINER_HOST:
        host = "127.0.0.1"
    rendered_host = f"[{host}]" if ":" in host else host
    netloc = rendered_host
    if port is not None:
        netloc += f":{port}"
    origin_url = urlunsplit((parts.scheme.lower(), netloc, "", "", ""))
    return _FrozenUpstream(
        scheme=parts.scheme.lower(),
        host=host,
        port=use_port,
        connect_host="",
        origin_url=origin_url,
        base_path=decoded_path,
        base_query=parts.query,
        container_base_path="" if canonical_path == "/" else canonical_path,
    )


def _path_within_base(path, base_path):
    if base_path == "/":
        return str(path or "").startswith("/")
    return path == base_path or path.startswith(base_path + "/")


def _relative_request_path(path, base_path):
    if not _path_within_base(path, base_path):
        return ""
    if base_path == "/":
        return path
    relative = path[len(base_path):]
    return relative or "/"


def _route_allowed(mode, method, path, query, base_path):
    del query
    if method not in _ALLOWED_METHODS[mode]:
        return False
    if mode == "mcp":
        # WebSearch 配置的是完整 Streamable HTTP MCP 端点；session 通过
        # MCP-Session-Id 传递，不能让 Agent 借此凭据访问相邻路径。
        return path == base_path
    relative = _relative_request_path(path, base_path)
    # Query 只携带 provider 的版本、beta、路由等参数，不会改变已经冻结的
    # origin、方法和请求路径，因此不再把它当作路由权限的一部分。
    return relative in _ALLOWED_RELATIVE_ROUTES[mode].get(method, ())


def _route_requires_usage_ack(mode, path, base_path):
    if mode == "mcp":
        return False
    relative = _relative_request_path(path, base_path)
    # Anthropic count_tokens 只做确定性的计数，不产生可计费模型输出；让它
    # 占据闸门会在真正的 /messages 请求前自锁。
    return relative not in {"/messages/count_tokens", "/v1/messages/count_tokens"}


def _usage_count(value, label):
    """严格读取 provider usage；不能把缺失或小数静默当成 0。"""

    if isinstance(value, bool):
        raise AgentSecretRelayUsageError(f"{label} 无效")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        parsed = int(value.strip())
    else:
        raise AgentSecretRelayUsageError(f"{label} 无效")
    if parsed < 0:
        raise AgentSecretRelayUsageError(f"{label} 无效")
    return parsed


def _first_usage_count(mapping, names, label, *, required=False, default=0):
    source = mapping if isinstance(mapping, dict) else {}
    for name in names:
        if name in source:
            return _usage_count(source[name], label), True
    if required:
        raise AgentSecretRelayUsageError(f"模型响应缺少 {label}")
    return int(default), False


def _first_optional_usage_count(mapping, names, label):
    """读取可选 usage；字段缺失或非法时按 0 处理。"""

    source = mapping if isinstance(mapping, dict) else {}
    for name in names:
        if name not in source:
            continue
        try:
            return _usage_count(source[name], label), True
        except AgentSecretRelayUsageError:
            return 0, True
    return 0, False


def _default_cached_input_split(total_input_tokens, cache_write_tokens=0):
    """在 provider 没有可识别 cached 字段时按 90% 命中率估算。"""

    total_input_tokens = max(0, int(total_input_tokens))
    cache_write_tokens = max(0, int(cache_write_tokens))
    effective_input_tokens = max(total_input_tokens, cache_write_tokens)
    hit_candidate = max(0, effective_input_tokens - cache_write_tokens)
    cached_tokens = (
        hit_candidate * _DEFAULT_CACHED_HIT_RATE_PERCENT + 50
    ) // 100
    uncached_tokens = hit_candidate - cached_tokens
    return {
        "input_uncached_tokens": uncached_tokens,
        "input_cached_tokens": cached_tokens,
        "input_cache_write_tokens": cache_write_tokens,
        "cached_fallback_request_count": 1,
        "cached_fallback_input_tokens": effective_input_tokens,
    }


def _cached_input_count_with_fallback(
    mapping,
    names,
    details,
    detail_names,
    *,
    total_input_tokens,
    cache_write_tokens=0,
    label,
):
    """读取 cached 字段；缺少或非法时返回 90% 命中率的估算值。"""

    source = mapping if isinstance(mapping, dict) else {}
    detail_source = details if isinstance(details, dict) else {}
    for candidate_source, candidate_names in (
        (source, names),
        (detail_source, detail_names),
    ):
        for name in candidate_names:
            if name not in candidate_source:
                continue
            try:
                return {
                    "input_cached_tokens": _usage_count(
                        candidate_source[name], label
                    ),
                    "cached_fallback_request_count": 0,
                    "cached_fallback_input_tokens": 0,
                }
            except AgentSecretRelayUsageError:
                return _default_cached_input_split(
                    total_input_tokens,
                    cache_write_tokens,
                )
    return _default_cached_input_split(
        total_input_tokens,
        cache_write_tokens,
    )


def _usage_details(usage, *names):
    for name in names:
        value = usage.get(name) if isinstance(usage, dict) else None
        if isinstance(value, dict):
            return value
    return {}


def _normalize_openai_usage(usage):
    """投影 OpenAI/兼容端点 usage，与容器 adapter 的五字段口径一致。"""

    if not isinstance(usage, dict):
        raise AgentSecretRelayUsageError("模型响应 usage 必须是对象")
    total_input, _ = _first_usage_count(
        usage,
        ("prompt_tokens", "input_tokens"),
        "输入 Token",
        required=True,
    )
    output_tokens, _ = _first_usage_count(
        usage,
        ("completion_tokens", "output_tokens"),
        "输出 Token",
        required=True,
    )
    input_details = _usage_details(
        usage,
        "prompt_tokens_details",
        "input_tokens_details",
    )
    output_details = _usage_details(
        usage,
        "completion_tokens_details",
        "output_tokens_details",
    )
    cache_write_tokens, cache_write_present = _first_optional_usage_count(
        usage,
        ("input_cache_write_tokens", "cache_creation_input_tokens"),
        "缓存写入 Token",
    )
    if not cache_write_present:
        cache_write_tokens, _ = _first_optional_usage_count(
            input_details,
            ("cache_write_tokens", "cache_creation_tokens"),
            "缓存写入 Token",
        )
    cached_split = _cached_input_count_with_fallback(
        usage,
        (
            "prompt_cache_hit_tokens",
            "input_cached_tokens",
            "cache_read_input_tokens",
        ),
        input_details,
        ("cached_tokens", "cache_read_tokens"),
        total_input_tokens=total_input,
        cache_write_tokens=cache_write_tokens if cache_write_present else 0,
        label="缓存输入 Token",
    )
    cached_tokens = cached_split["input_cached_tokens"]
    fallback_meta = {
        key: cached_split[key]
        for key in (
            "cached_fallback_request_count",
            "cached_fallback_input_tokens",
        )
    }
    if fallback_meta["cached_fallback_request_count"]:
        cache_write_tokens = cached_split["input_cache_write_tokens"]
    uncached_tokens, uncached_present = _first_usage_count(
        usage,
        ("prompt_cache_miss_tokens", "input_uncached_tokens"),
        "非缓存输入 Token",
    )
    if not uncached_present:
        cached_total = cached_tokens + cache_write_tokens
        if cached_total > total_input:
            raise AgentSecretRelayUsageError("缓存输入 Token 超过总输入 Token")
        uncached_tokens = total_input - cached_total
    if fallback_meta["cached_fallback_request_count"]:
        uncached_tokens = cached_split["input_uncached_tokens"]
    reasoning_tokens, reasoning_present = _first_usage_count(
        usage,
        ("reasoning_output_tokens", "reasoning_tokens"),
        "推理输出 Token",
    )
    if not reasoning_present:
        reasoning_tokens, _ = _first_usage_count(
            output_details,
            ("reasoning_tokens",),
            "推理输出 Token",
        )
    if reasoning_tokens > output_tokens:
        raise AgentSecretRelayUsageError("推理输出 Token 超过总输出 Token")
    normalized = {
        "input_uncached_tokens": uncached_tokens,
        "input_cached_tokens": cached_tokens,
        "input_cache_write_tokens": cache_write_tokens,
        "output_tokens": output_tokens,
        "reasoning_output_tokens": reasoning_tokens,
    }
    if fallback_meta["cached_fallback_request_count"]:
        normalized.update(fallback_meta)
    return normalized


def _normalize_anthropic_usage(usages):
    """合并 Anthropic message_start/message_delta 的累计 usage。"""

    records = [item for item in usages if isinstance(item, dict)]
    if not records:
        raise AgentSecretRelayUsageError("模型响应缺少 usage")
    maxima = {}
    aliases = {
        "input_uncached_tokens": ("input_tokens", "input"),
        "input_cached_tokens": ("cache_read_input_tokens", "cacheRead"),
        "input_cache_write_tokens": (
            "cache_creation_input_tokens",
            "cacheWrite",
        ),
        "output_tokens": ("output_tokens", "output"),
        "reasoning_output_tokens": (
            "reasoning_output_tokens",
            "reasoning_tokens",
            "reasoning",
        ),
    }
    present = set()
    cached_field_invalid = False
    for record in records:
        cache_creation = record.get("cache_creation")
        if (
            "cache_creation_input_tokens" not in record
            and isinstance(cache_creation, dict)
        ):
            five_minutes, _ = _first_optional_usage_count(
                cache_creation,
                ("ephemeral_5m_input_tokens",),
                "5 分钟缓存写入 Token",
            )
            one_hour, _ = _first_optional_usage_count(
                cache_creation,
                ("ephemeral_1h_input_tokens",),
                "1 小时缓存写入 Token",
            )
            record = {
                **record,
                "cache_creation_input_tokens": five_minutes + one_hour,
            }
        for target, names in aliases.items():
            if target == "input_cached_tokens":
                value = 0
                found = False
                for name in names:
                    if name not in record:
                        continue
                    if record[name] is None:
                        continue
                    found = True
                    try:
                        value = _usage_count(record[name], target)
                    except AgentSecretRelayUsageError:
                        cached_field_invalid = True
                        found = False
                    break
            elif target == "input_cache_write_tokens":
                value, found = _first_optional_usage_count(
                    record,
                    names,
                    target,
                )
            else:
                value, found = _first_usage_count(
                    record,
                    names,
                    target,
                )
            if found:
                present.add(target)
                maxima[target] = max(maxima.get(target, 0), value)
    if "input_uncached_tokens" not in present:
        raise AgentSecretRelayUsageError("模型响应缺少输入 Token")
    if "output_tokens" not in present:
        raise AgentSecretRelayUsageError("模型响应缺少输出 Token")
    normalized = {field: maxima.get(field, 0) for field in aliases}
    if cached_field_invalid or "input_cached_tokens" not in present:
        fallback = _default_cached_input_split(
            maxima.get("input_uncached_tokens", 0)
            + maxima.get("input_cache_write_tokens", 0),
            maxima.get("input_cache_write_tokens", 0),
        )
        normalized.update(fallback)
    return normalized


def _response_documents(payload):
    """读取完整 JSON 或 SSE data 帧；任何破损 data 帧都 fail closed。"""

    try:
        text = bytes(payload or b"").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentSecretRelayUsageError("模型响应不是有效 UTF-8") from exc
    if not text.strip():
        raise AgentSecretRelayUsageError("模型响应为空")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        return [document]
    if document is not None:
        raise AgentSecretRelayUsageError("模型 JSON 响应必须是对象")

    documents = []
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    for record in normalized.split("\n\n"):
        data_lines = []
        for line in record.split("\n"):
            if line == "data":
                data_lines.append("")
            elif line.startswith("data:"):
                value = line[5:]
                if value.startswith(" "):
                    value = value[1:]
                data_lines.append(value)
        if not data_lines:
            continue
        data = "\n".join(data_lines).strip()
        if not data or data == "[DONE]":
            continue
        try:
            document = json.loads(data)
        except json.JSONDecodeError as exc:
            raise AgentSecretRelayUsageError("模型 SSE usage 帧无效") from exc
        if not isinstance(document, dict):
            raise AgentSecretRelayUsageError("模型 SSE data 必须是对象")
        documents.append(document)
    if not documents:
        raise AgentSecretRelayUsageError("模型响应不是有效 JSON/SSE")
    return documents


def _extract_response_usage(mode, relative_route, payload):
    """从受支持生成路由的完整响应提取五类 Token。"""

    documents = _response_documents(payload)
    normalized_mode = str(mode or "").strip().lower()
    try:
        parsed_whole = json.loads(bytes(payload or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed_whole = None
    is_json = isinstance(parsed_whole, dict)
    if normalized_mode == "openai":
        if not is_json:
            route = str(relative_route or "")
            if route.endswith("/chat/completions"):
                normalized_payload = bytes(payload).replace(b"\r\n", b"\n")
                done = any(
                    line[5:].strip() == b"[DONE]"
                    for line in normalized_payload.split(b"\n")
                    if line.startswith(b"data:")
                )
                if not done:
                    raise AgentSecretRelayUsageError(
                        "Chat Completions SSE 未完整结束"
                    )
            elif route.endswith("/responses"):
                if not any(
                    str(document.get("type") or "") in {
                        "response.completed",
                        "response.failed",
                        "response.incomplete",
                    }
                    for document in documents
                ):
                    raise AgentSecretRelayUsageError("Responses SSE 未完整结束")
            elif route.endswith("/responses/compact"):
                raise AgentSecretRelayUsageError("Compact 响应必须是完整 JSON")
        usages = []
        for document in documents:
            if isinstance(document.get("usage"), dict):
                usages.append(document["usage"])
            response = document.get("response")
            if isinstance(response, dict) and isinstance(response.get("usage"), dict):
                usages.append(response["usage"])
        if not usages:
            raise AgentSecretRelayUsageError(
                f"模型响应缺少 usage：{relative_route}"
            )
        return _normalize_openai_usage(usages[-1])
    if normalized_mode == "anthropic":
        if not is_json and not any(
            str(document.get("type") or "") == "message_stop"
            for document in documents
        ):
            raise AgentSecretRelayUsageError("Anthropic SSE 未完整结束")
        usages = []
        for document in documents:
            if isinstance(document.get("usage"), dict):
                usages.append(document["usage"])
            message = document.get("message")
            if isinstance(message, dict) and isinstance(message.get("usage"), dict):
                usages.append(message["usage"])
        return _normalize_anthropic_usage(usages)
    raise AgentSecretRelayUsageError("当前 relay 模式不支持 usage 计费")


def _prepare_endpoint_request_body(mode, relative_route, body):
    """为流式 Chat 请求强制要求 usage，避免正常客户端拿不到计费帧。"""

    payload = bytes(body or b"")
    if (
        str(mode or "").lower() != "openai"
        or not str(relative_route or "").endswith("/chat/completions")
    ):
        return payload
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    if not isinstance(document, dict) or document.get("stream") is not True:
        return payload
    stream_options = document.get("stream_options")
    if stream_options is None:
        stream_options = {}
    if not isinstance(stream_options, dict):
        raise _RequestRejected(400, "invalid stream options")
    document["stream_options"] = {**stream_options, "include_usage": True}
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _request_content_length(headers, method, max_bytes):
    transfer_encoding = _single_header(headers, "Transfer-Encoding").strip().lower()
    if transfer_encoding not in {"", "identity"}:
        raise _RequestRejected(400, "unsupported transfer encoding")
    raw = _single_header(headers, "Content-Length").strip()
    if not raw:
        if str(method or "").upper() in {"POST", "PUT", "PATCH"}:
            raise _RequestRejected(411, "content length required")
        return 0
    if not re.fullmatch(r"[0-9]+", raw):
        raise _RequestRejected(400, "invalid content length")
    length = int(raw)
    if length > int(max_bytes):
        raise _RequestRejected(413, "request too large")
    return length


def _response_content_length(headers):
    try:
        raw = _single_header(headers, "Content-Length").strip()
    except _RequestRejected as exc:
        raise _RequestRejected(502, "multiple upstream content lengths") from exc
    if not raw:
        return None
    if not re.fullmatch(r"[0-9]+", raw):
        raise _RequestRejected(502, "invalid upstream content length")
    length = int(raw)
    if length > _MAX_RESPONSE_BYTES:
        raise _RequestRejected(502, "upstream response too large")
    return length


def _validate_response_content_encoding(headers):
    try:
        encoding = _single_header(headers, "Content-Encoding").strip().lower()
    except _RequestRejected as exc:
        raise _RequestRejected(502, "multiple upstream content encodings") from exc
    if encoding not in {"", "identity"}:
        # 只有明文流才能证明真实凭据已从响应中移除。
        raise _RequestRejected(502, "encoded upstream response refused")


def _redaction_secrets(*values):
    result = []
    for value in values:
        normalized = str(value or "")
        if not normalized:
            continue
        candidates = [normalized]
        if " " in normalized:
            _scheme, credential = normalized.split(" ", 1)
            if len(credential) >= 8:
                candidates.append(credential)
        for candidate in candidates:
            encoded = candidate.encode("utf-8")
            if encoded and encoded not in result:
                result.append(encoded)
    return tuple(sorted(result, key=len, reverse=True))


class _StreamingRedactor:
    """跨 chunk 脱敏，保留至多最长密钥减一字节的有界尾部。"""

    def __init__(self, secret_values):
        self.secrets = tuple(
            sorted(
                {bytes(value) for value in secret_values if bytes(value)},
                key=len,
                reverse=True,
            )
        )
        self._pending = b""
        self._tail_size = max((len(value) for value in self.secrets), default=1) - 1

    def feed(self, chunk=b"", *, final=False):
        pending = self._pending + bytes(chunk or b"")
        output = bytearray()
        while pending and self.secrets:
            matches = [
                (index, -len(secret), secret)
                for secret in self.secrets
                if (index := pending.find(secret)) >= 0
            ]
            if not matches:
                break
            index, _negative_length, secret = min(matches)
            output.extend(pending[:index])
            output.extend(_REDACTION)
            pending = pending[index + len(secret):]
        if final or not self.secrets:
            output.extend(pending)
            pending = b""
        elif len(pending) > self._tail_size:
            split_at = len(pending) - self._tail_size
            output.extend(pending[:split_at])
            pending = pending[split_at:]
        self._pending = pending
        return bytes(output)


class _OpenAIEmptyContentTransformer:
    """把 Chat Completions 的空成功响应转成标准流式错误。"""

    def __init__(self, *, event_stream):
        self._event_stream = bool(event_stream)
        self._pending = b""
        self._saw_output = False
        self._saw_error = False
        self._saw_nonretryable_finish = False

    @staticmethod
    def _error_document():
        return {
            "error": {
                "message": _EMPTY_ASSISTANT_CONTENT_ERROR,
                "type": "server_error",
                "code": "empty_assistant_content",
            },
        }

    @staticmethod
    def _payload_has_output(payload):
        if not isinstance(payload, dict):
            return False
        content = payload.get("content")
        if isinstance(content, str) and content.strip():
            return True
        if isinstance(content, list) and content:
            return True
        for key in (
            "tool_calls", "function_call", "refusal", "audio",
            "reasoning", "reasoning_content",
        ):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return True
            if isinstance(value, (list, dict)) and value:
                return True
        return False

    def _transform_document(self, document):
        if not isinstance(document, dict):
            return document
        if document.get("error"):
            self._saw_error = True
            return document
        choices = document.get("choices")
        if not isinstance(choices, list):
            return document
        finish_reasons = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            payload = choice.get("delta")
            if not isinstance(payload, dict):
                payload = choice.get("message")
            if self._payload_has_output(payload):
                self._saw_output = True
            reason = str(choice.get("finish_reason") or "").strip().lower()
            if reason:
                finish_reasons.append(reason)
                if reason != "stop":
                    self._saw_nonretryable_finish = True
        if (
            finish_reasons
            and all(reason == "stop" for reason in finish_reasons)
            and not self._saw_output
        ):
            self._saw_error = True
            return self._error_document()
        return document

    def _transform_sse_record(self, record):
        newline = b"\r\n" if b"\r\n" in record else b"\n"
        lines = record.split(newline)
        data_indexes = [
            index
            for index, line in enumerate(lines)
            if line == b"data" or line.startswith(b"data:")
        ]
        if not data_indexes:
            return record
        data_parts = []
        for index in data_indexes:
            line = lines[index]
            value = b"" if line == b"data" else line[5:]
            if value.startswith(b" "):
                value = value[1:]
            data_parts.append(value)
        raw_data = b"\n".join(data_parts)
        if raw_data.strip() == b"[DONE]":
            if (
                self._saw_output
                or self._saw_error
                or self._saw_nonretryable_finish
            ):
                return record
            document = self._error_document()
            self._saw_error = True
        else:
            try:
                document = json.loads(raw_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return record
            transformed = self._transform_document(document)
            if transformed is document:
                return record
            document = transformed
        first = data_indexes[0]
        lines[first] = b"data: " + json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        for index in reversed(data_indexes[1:]):
            del lines[index]
        return newline.join(lines)

    def _transform_json(self, payload):
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return payload
        if not isinstance(document, dict) or document.get("error"):
            return payload
        choices = document.get("choices")
        if not isinstance(choices, list):
            return payload
        has_output = any(
            isinstance(choice, dict)
            and self._payload_has_output(choice.get("message"))
            for choice in choices
        )
        finish_reasons = [
            str(choice.get("finish_reason") or "").strip().lower()
            for choice in choices
            if isinstance(choice, dict)
        ]
        if has_output or any(
            reason not in {"", "stop"} for reason in finish_reasons
        ):
            return payload
        return json.dumps(
            self._error_document(),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def feed(self, chunk=b"", *, final=False):
        self._pending += bytes(chunk or b"")
        if not self._event_stream:
            if not final:
                return b""
            payload, self._pending = self._pending, b""
            return self._transform_json(payload)

        output = bytearray()
        while True:
            separator = re.search(br"\r?\n\r?\n", self._pending)
            if separator is None:
                break
            record = self._pending[:separator.start()]
            delimiter = self._pending[separator.start():separator.end()]
            self._pending = self._pending[separator.end():]
            output.extend(self._transform_sse_record(record))
            output.extend(delimiter)
        if final and self._pending:
            output.extend(self._transform_sse_record(self._pending))
            self._pending = b""
        return bytes(output)


class _AnthropicEmptyContentTransformer:
    """把协议完整但无 content 的 Anthropic 成功响应转成可重试错误。

    Anthropic 协议没有 ``error`` stop_reason；使用合法的 ``refusal`` 并
    附带瞬时上游错误说明。支持的 CLI 会把它识别为失败，Pi 还会按
    瞬时错误执行内建重试。SSE 只缓存当前 record，非流式 JSON 才缓存
    完整响应。
    """

    def __init__(self, *, event_stream):
        self._event_stream = bool(event_stream)
        self._pending = b""
        self._saw_content = False

    @staticmethod
    def _mark_error(document):
        delta = document.get("delta")
        if not isinstance(delta, dict) or not delta.get("stop_reason"):
            return False
        if str(delta.get("stop_reason")) in {"refusal", "sensitive"}:
            # Provider 已经明确返回安全拒绝，CLI 本来就会映射为失败；
            # 不能把它伪装成瞬时空响应并诱发无意义重试。
            return False
        delta["stop_reason"] = "refusal"
        delta["stop_details"] = {
            "type": "refusal",
            "explanation": _EMPTY_ASSISTANT_CONTENT_ERROR,
        }
        return True

    def _transform_document(self, document):
        if not isinstance(document, dict):
            return False
        event_type = str(document.get("type") or "")
        if event_type == "message_start":
            message = document.get("message")
            if isinstance(message, dict) and message.get("content"):
                self._saw_content = True
            return False
        if event_type == "content_block_start":
            self._saw_content = True
            return False
        if event_type == "message_delta" and not self._saw_content:
            return self._mark_error(document)
        return False

    def _transform_sse_record(self, record):
        newline = b"\r\n" if b"\r\n" in record else b"\n"
        lines = record.split(newline)
        data_indexes = [
            index
            for index, line in enumerate(lines)
            if line == b"data" or line.startswith(b"data:")
        ]
        if not data_indexes:
            return record
        data_parts = []
        for index in data_indexes:
            line = lines[index]
            value = b"" if line == b"data" else line[5:]
            if value.startswith(b" "):
                value = value[1:]
            data_parts.append(value)
        try:
            document = json.loads(b"\n".join(data_parts).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return record
        if not self._transform_document(document):
            return record
        first = data_indexes[0]
        lines[first] = b"data: " + json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        for index in reversed(data_indexes[1:]):
            del lines[index]
        return newline.join(lines)

    def _transform_json(self, payload):
        try:
            document = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return payload
        if (
            not isinstance(document, dict)
            or str(document.get("type") or "") != "message"
            or document.get("content")
            or str(document.get("stop_reason") or "")
            in {"refusal", "sensitive"}
        ):
            return payload
        document["stop_reason"] = "refusal"
        document["stop_details"] = {
            "type": "refusal",
            "explanation": _EMPTY_ASSISTANT_CONTENT_ERROR,
        }
        return json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def feed(self, chunk=b"", *, final=False):
        self._pending += bytes(chunk or b"")
        if not self._event_stream:
            if not final:
                return b""
            payload, self._pending = self._pending, b""
            return self._transform_json(payload)

        output = bytearray()
        while True:
            separator = re.search(br"\r?\n\r?\n", self._pending)
            if separator is None:
                break
            record = self._pending[:separator.start()]
            delimiter = self._pending[separator.start():separator.end()]
            self._pending = self._pending[separator.end():]
            output.extend(self._transform_sse_record(record))
            output.extend(delimiter)
        if final and self._pending:
            output.extend(self._transform_sse_record(self._pending))
            self._pending = b""
        return bytes(output)


def _sanitize_text(value, secret_values):
    rendered = str(value or "")
    for secret in secret_values:
        rendered = rendered.replace(secret.decode("utf-8"), "[REDACTED]")
    return rendered


def _forward_headers(headers, upstream_headers, mode):
    forwarded = {}
    for source_name, target_name in _FORWARDED_REQUEST_HEADERS[mode].items():
        value = _single_header(headers, source_name).strip()
        if value:
            forwarded[target_name] = value
    forwarded["Accept-Encoding"] = "identity"
    forwarded.update(upstream_headers)
    return forwarded


def _response_headers(headers, secret_values):
    forwarded = []
    for name, value in (headers.items() if headers is not None else ()):
        lowered = str(name).lower()
        if (
            lowered in _HOP_BY_HOP_HEADERS
            or lowered in _SENSITIVE_RESPONSE_HEADERS
            or lowered in {"content-length", "date"}
        ):
            continue
        forwarded.append((
            str(name),
            _sanitize_text(value, secret_values),
        ))
    return forwarded


class _BoundedSecretRelayServer(_BoundedIdentityRelayServer):
    """在通用连接边界外额外追踪每个 handler 的完整生命周期。"""

    max_connections = _MAX_SECRET_RELAY_CONNECTIONS
    request_queue_size = _MAX_SECRET_RELAY_CONNECTIONS * 2

    def __init__(self, server_address, handler_class):
        self._handler_condition = threading.Condition()
        self._pending_handlers = set()
        super().__init__(server_address, handler_class)

    def process_request(self, request, client_address):
        try:
            request.settimeout(_CLIENT_TIMEOUT_SECONDS)
        except OSError:
            self.shutdown_request(request)
            return
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\n"
                    b"Content-Length: 4\r\nConnection: close\r\n\r\nbusy",
                )
            except OSError:
                pass
            self.shutdown_request(request)
            return
        with self._active_lock:
            if self._closing:
                self._slots.release()
                self.shutdown_request(request)
                return
            self._active_clients.add(request)
        marker = id(request)
        with self._handler_condition:
            self._pending_handlers.add(marker)
        try:
            # 直接调用 ThreadingHTTPServer，避免再次进入父类的连接门禁。
            http.server.ThreadingHTTPServer.process_request(
                self,
                request,
                client_address,
            )
        except Exception:
            with self._active_lock:
                self._active_clients.discard(request)
            self._slots.release()
            with self._handler_condition:
                self._pending_handlers.discard(marker)
                self._handler_condition.notify_all()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        marker = id(request)
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._handler_condition:
                self._pending_handlers.discard(marker)
                self._handler_condition.notify_all()

    def wait_for_handlers(self, timeout):
        """等待请求处理线程全部退出，返回截止时仍未退出的数量。"""

        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._handler_condition:
            while self._pending_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return len(self._pending_handlers)
                self._handler_condition.wait(timeout=remaining)
            return 0

    def drain_handlers(self, timeout):
        """持续中断已登记连接，并等待所有 handler 的 finally 完成。"""

        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            # close_active_requests() 保留登记项直到 handler 自己注销，因此
            # 可以安全地重复中断仍在客户端读写或上游响应读取中的连接。
            self.close_active_requests()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self.wait_for_handlers(0)
            pending = self.wait_for_handlers(
                min(_HANDLER_SHUTDOWN_POLL_SECONDS, remaining),
            )
            if not pending:
                return 0


class _AgentSecretRelay:
    def __init__(
        self,
        *,
        upstream_base_url,
        mode,
        real_credential,
        stop_event=None,
        require_usage_ack=False,
        usage_callback=None,
        require_public_target=False,
    ):
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode not in {"openai", "anthropic", "mcp"}:
            raise AgentSecretRelayError("外部服务密钥代理模式无效")
        self.mode = normalized_mode
        self.upstream = _normalize_upstream_base_url(
            upstream_base_url,
            preserve_trailing_slash=self.mode == "mcp",
        )
        if require_public_target:
            try:
                target = resolve_public_http_target(self.upstream.origin_url)
            except PublicOutboundTargetError as exc:
                raise AgentSecretRelayError(str(exc)) from None
            # HTTPConnection 保留 self.host 生成 Host；HTTPSConnection 也继续
            # 用该 hostname 完成 SNI 与证书校验，仅底层 TCP 连接固定到本次
            # 已校验的公网 IP，避免保存后 DNS rebinding。
            self.upstream = replace(
                self.upstream,
                connect_host=target.connect_host,
            )
        self.real_credential = _validate_header_value(
            real_credential,
            "外部服务长期凭据",
        )
        self.temporary_secret = secrets.token_urlsafe(_TEMPORARY_SECRET_BYTES)
        if self.mode == "openai":
            self.expected_headers = {
                "authorization": f"Bearer {self.temporary_secret}",
            }
            self.upstream_headers = {
                "Authorization": f"Bearer {self.real_credential}",
            }
        elif self.mode == "anthropic":
            self.expected_headers = {
                "authorization": f"Bearer {self.temporary_secret}",
                "x-api-key": self.temporary_secret,
            }
            self.upstream_headers = {"x-api-key": self.real_credential}
        else:
            self.expected_headers = {
                "authorization": f"Bearer {self.temporary_secret}",
            }
            self.upstream_headers = {"Authorization": self.real_credential}
        self.secret_values = _redaction_secrets(
            *self.upstream_headers.values(),
            self.real_credential,
            *self.expected_headers.values(),
            self.temporary_secret,
        )
        self.server = None
        self.thread = None
        self.container_base_url = ""
        self._state_lock = threading.Lock()
        self._active = False
        self._closed = False
        self._stop_event = stop_event or threading.Event()
        self._require_usage_ack = bool(require_usage_ack)
        self._usage_callback = usage_callback
        if self._require_usage_ack and not callable(self._usage_callback):
            raise AgentSecretRelayError("模型端点实时计费 callback 未配置")
        self._request_count = 0
        self._inflight_request_bytes = 0
        self._endpoint_request_claims = set()
        self._usage_failure = None
        self._usage_condition = threading.Condition(self._state_lock)
        # 模型请求必须并发到达上游；只有很短的数据库记账 callback 串行，
        # 让额度账户保持确定顺序，也避免一次 workflow 瞬间占满数据库连接。
        self._usage_callback_lock = threading.Lock()
        hard_stop_setter = getattr(
            self._usage_callback,
            "set_hard_stop_callback",
            None,
        )
        if callable(hard_stop_setter):
            hard_stop_setter(self._record_committed_hard_stop)

    @property
    def container_credential(self):
        if self.mode == "mcp":
            return f"Bearer {self.temporary_secret}"
        return self.temporary_secret

    def _authorize_request(self, headers):
        provided = {}
        for name in _CREDENTIAL_HEADERS:
            value = _single_header(headers, name).strip()
            if value:
                provided[name] = value
        allowed_names = set(self.expected_headers)
        if not provided or not set(provided).issubset(allowed_names):
            return False
        for name, value in provided.items():
            if not hmac.compare_digest(value, self.expected_headers[name]):
                return False
        if self.mode in {"openai", "mcp"}:
            return set(provided) == {"authorization"}
        # Claude Code 与 Pi 的 Anthropic 兼容层可能发送其中一种或同时发送；
        # 两种均必须是本 relay 的同一个临时 secret。
        return bool(set(provided) & {"authorization", "x-api-key"})

    def _claim_request(self):
        with self._state_lock:
            if (
                not self._active
                or self._closed
                or self._stop_event.is_set()
            ):
                return False
            if self._request_count >= _MAX_REQUESTS_PER_RELAY:
                return False
            self._request_count += 1
            return True

    def _claim_endpoint_request(self):
        """登记一条需计费的模型请求，不阻塞其他 subagent 并发转发。"""

        if not self._require_usage_ack:
            return True
        with self._usage_condition:
            if (
                not self._active
                or self._closed
                or self._stop_event.is_set()
            ):
                return False
            claim = object()
            self._endpoint_request_claims.add(claim)
            return claim

    def _abandon_endpoint_request(self, claim):
        if not self._require_usage_ack:
            return
        with self._usage_condition:
            if claim in self._endpoint_request_claims:
                self._endpoint_request_claims.discard(claim)
                self._usage_condition.notify_all()

    def _record_usage_failure(self, exc):
        failure = exc if isinstance(exc, Exception) else AgentSecretRelayUsageError(
            "模型 usage 记账失败"
        )
        with self._usage_condition:
            if self._usage_failure is None:
                self._usage_failure = failure
            self._usage_condition.notify_all()
        self.deny_new_requests()

    def _record_committed_hard_stop(self, result):
        remaining = str(
            (result or {}).get("remaining_rmb")
            or (result or {}).get("remaining_amount")
            or ""
        ).strip()
        detail = f"，剩余额度 {remaining} 元" if remaining else ""
        self._record_usage_failure(
            AgentSecretRelayUsageHardStopError(
                f"Agent 额度已达到硬停阈值{detail}"
            )
        )

    def _account_endpoint_response(
        self,
        claim,
        relative_route,
        payload,
        *,
        force_zero_usage=False,
    ):
        if not self._require_usage_ack:
            return None
        try:
            if force_zero_usage:
                usage = {
                    "input_uncached_tokens": 0,
                    "input_cached_tokens": 0,
                    "input_cache_write_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                }
            else:
                try:
                    usage = _extract_response_usage(
                        self.mode,
                        relative_route,
                        payload,
                    )
                except AgentSecretRelayUsageError:
                    # 响应已经实际发生，但第三方代理可能省略、截断或返回
                    # 非法 usage。没有完整可计费响应时按全 0 写一条账本
                    # 记录，不能因此封锁 relay 并终止 Agent。
                    usage = {
                        "input_uncached_tokens": 0,
                        "input_cached_tokens": 0,
                        "input_cache_write_tokens": 0,
                        "output_tokens": 0,
                        "reasoning_output_tokens": 0,
                    }
            event = {
                "type": "numoj_usage",
                "version": 1,
                "source": f"relay_{self.mode}",
                "id": "relay-" + secrets.token_urlsafe(24),
                "usage": usage,
            }
            try:
                with self._usage_callback_lock:
                    result = self._usage_callback(event)
            except Exception:
                # 计费是可恢复旁路。容错计费器会把事件留在宿主 outbox；即使
                # 自定义 callback 本身异常，也不得关闭 relay 或连带终止并发
                # subagent。
                logger.exception("模型 usage callback 异常；任务继续等待恢复结算")
                return {
                    "applied": False,
                    "acknowledged": True,
                    "deferred": True,
                    "hard_stop": False,
                }
            if not isinstance(result, dict):
                logger.error("模型 usage callback 未返回结算状态；任务继续运行")
                return {
                    "applied": False,
                    "acknowledged": True,
                    "deferred": True,
                    "hard_stop": False,
                }
            # applied=False 是账本已存在的正常幂等重放。只有已成功结算后
            # 明确返回 hard_stop，才允许计费链路终止任务。
            if bool(result.get("hard_stop")):
                remaining = str(
                    result.get("remaining_rmb")
                    or result.get("remaining_amount")
                    or ""
                ).strip()
                detail = f"，剩余额度 {remaining} 元" if remaining else ""
                raise AgentSecretRelayUsageHardStopError(
                    f"Agent 额度已达到硬停阈值{detail}"
                )
        except AgentSecretRelayUsageHardStopError as exc:
            self._record_usage_failure(exc)
            raise
        finally:
            self._abandon_endpoint_request(claim)
        return result

    def raise_if_usage_failed(self):
        with self._usage_condition:
            failure = self._usage_failure
        if failure is not None:
            raise failure

    def wait_for_endpoint_usage(self, timeout=_ENDPOINT_USAGE_DRAIN_SECONDS):
        """正常结束 harness 时等待全部已接受请求读完并完成记账。"""

        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._usage_condition:
            while self._endpoint_request_claims and self._usage_failure is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AgentSecretRelayUsageError("等待模型 usage 记账超时")
                self._usage_condition.wait(timeout=remaining)
            failure = self._usage_failure
        if failure is not None:
            raise failure

    def deny_new_requests(self):
        """立即封锁本轮 relay，并中断已进入转发链的模型请求。"""

        self._stop_event.set()
        with self._usage_condition:
            self._active = False
            server = self.server
            self._usage_condition.notify_all()
        if server is not None:
            # usage 记账完成时，harness 可能已经并发发起下一次模型请求。
            # 除了让 _claim_request fail closed，还要关闭已经进入 handler 的
            # client/upstream socket，确保硬停不会再产生一次未记账调用。
            server.close_active_requests()

    def _forwarding_snapshot(self):
        """原子复制请求注入与响应脱敏所需的同一组凭据。"""

        with self._state_lock:
            return dict(self.upstream_headers), tuple(self.secret_values)

    def _reserve_request_body(self, length):
        requested = int(length)
        with self._state_lock:
            limit = _MAX_INFLIGHT_REQUEST_BYTES[self.mode]
            if (
                not self._active
                or self._closed
                or self._stop_event.is_set()
                or requested < 0
                or self._inflight_request_bytes + requested > limit
            ):
                return False
            self._inflight_request_bytes += requested
            return True

    def _release_request_body(self, length):
        released = max(0, int(length))
        with self._state_lock:
            self._inflight_request_bytes = max(
                0,
                self._inflight_request_bytes - released,
            )

    def _forget_credentials(self):
        with self._state_lock:
            self.real_credential = ""
            self.temporary_secret = ""
            self.expected_headers = {}
            self.upstream_headers = {}
            self.secret_values = ()

    def _handler_class(self):
        relay = self

        class RelayHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            server_version = "NumOJAgentSecretRelay/1.0"
            sys_version = ""

            def log_message(self, _format, *_args):
                return

            def _send_plain(self, status, message):
                payload = str(message).encode("utf-8")[:1024]
                self.send_response(int(status))
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                self.close_connection = True

            def _proxy(self):
                response = None
                connection = None
                connection_handle = None
                connection_registered = False
                reserved_body_bytes = 0
                endpoint_request_claim = None
                endpoint_response_accepted = False
                endpoint_accounting_attempted = False
                endpoint_accounted = False
                response_started = False
                relative_route = ""

                def account_incomplete_response_as_zero():
                    nonlocal endpoint_accounting_attempted, endpoint_accounted
                    if (
                        not endpoint_response_accepted
                        or endpoint_accounting_attempted
                    ):
                        return
                    endpoint_accounting_attempted = True
                    try:
                        relay._account_endpoint_response(
                            endpoint_request_claim,
                            relative_route,
                            b"",
                            force_zero_usage=True,
                        )
                    except Exception:
                        # 只有这里的账本 callback 失败或返回硬停，才会由
                        # _account_endpoint_response 封锁 relay；handler 不能
                        # 再向已经开始的 HTTP 响应追加第二个错误。
                        return
                    endpoint_accounted = True

                try:
                    # 临时凭据验证和生命周期门禁必须早于路径、body 与上游 I/O。
                    if not relay._authorize_request(self.headers):
                        raise _RequestRejected(404, "not found")
                    if not relay._claim_request():
                        raise _RequestRejected(404, "not found")
                    method = str(self.command or "").upper()
                    if method not in _ALLOWED_METHODS[relay.mode]:
                        raise _RequestRejected(405, "method not allowed")
                    path, query, canonical_target = _request_parts(
                        self.path,
                        allow_trailing_slash=relay.mode == "mcp",
                    )
                    if not _route_allowed(
                        relay.mode,
                        method,
                        path,
                        query,
                        relay.upstream.base_path,
                    ):
                        raise _RequestRejected(404, "not found")
                    relative_route = _relative_request_path(
                        path,
                        relay.upstream.base_path,
                    )
                    content_length = _request_content_length(
                        self.headers,
                        method,
                        _MAX_REQUEST_BYTES[relay.mode],
                    )
                    if (
                        relay._require_usage_ack
                        and _route_requires_usage_ack(
                            relay.mode,
                            path,
                            relay.upstream.base_path,
                        )
                    ):
                        endpoint_request_claim = relay._claim_endpoint_request()
                        if not endpoint_request_claim:
                            raise _RequestRejected(
                                503,
                                "usage acknowledgement required",
                            )
                    upstream_headers, secret_values = (
                        relay._forwarding_snapshot()
                    )
                    headers = _forward_headers(
                        self.headers,
                        upstream_headers,
                        relay.mode,
                    )
                    if not relay._reserve_request_body(content_length):
                        raise _RequestRejected(503, "request budget exhausted")
                    reserved_body_bytes = content_length
                    body = self.rfile.read(content_length) if content_length else None
                    if content_length and (body is None or len(body) != content_length):
                        raise _RequestRejected(400, "incomplete request")
                    if endpoint_request_claim is not None:
                        body = _prepare_endpoint_request_body(
                            relay.mode,
                            relative_route,
                            body,
                        )
                    connection = relay.upstream.open_connection()
                    connection_handle = _InterruptibleHTTPConnection(connection)
                    # handle 在 request/connect 之前登记，并在懒连接建立后保存
                    # 原始 socket；即使 getresponse() 转移 socket 所有权，close()
                    # 仍能 shutdown 它并唤醒阻塞的 SSE/read1。
                    if not self.server.register_upstream(connection_handle):
                        return
                    connection_registered = True
                    try:
                        connection.request(
                            method,
                            relay.upstream.target_path(canonical_target),
                            body=body,
                            headers=headers,
                        )
                        if not connection_handle.remember_socket():
                            return
                        response = connection.getresponse()
                    except Exception as exc:
                        raise _RequestRejected(502, "upstream unavailable") from exc
                    status = int(getattr(response, "status", response.getcode()))
                    if 300 <= status < 400:
                        raise _RequestRejected(502, "upstream redirect refused")
                    endpoint_response_accepted = bool(
                        endpoint_request_claim is not None and 200 <= status < 300
                    )
                    _response_content_length(response.headers)
                    _validate_response_content_encoding(response.headers)
                    response_started = True
                    client_writable = True
                    try:
                        self.send_response(status)
                        for name, value in _response_headers(
                            response.headers,
                            secret_values,
                        ):
                            self.send_header(name, value)
                        # 脱敏可能改变长度，因此不转发 Content-Length；HTTP/1.0
                        # 以连接关闭定界，同时保持 SSE/流式输出。
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Connection", "close")
                        self.end_headers()
                    except (
                        BrokenPipeError,
                        ConnectionResetError,
                        OSError,
                        socket.timeout,
                    ):
                        # 客户端断开不等于上游请求没有发生。继续 drain 上游，
                        # 只有完整 usage 入账后才注销这条请求的计费 claim。
                        client_writable = False
                    transferred = 0
                    response_payload = bytearray()
                    redactor = _StreamingRedactor(secret_values)
                    response_transformer = None
                    if endpoint_response_accepted:
                        response_content_type = _single_header(
                            response.headers,
                            "Content-Type",
                        ).partition(";")[0].strip().lower()
                        event_stream = (
                            response_content_type == "text/event-stream"
                        )
                    if endpoint_response_accepted and relay.mode == "anthropic":
                        response_transformer = (
                            _AnthropicEmptyContentTransformer(
                                event_stream=event_stream,
                            )
                        )
                    elif (
                        endpoint_response_accepted
                        and relay.mode == "openai"
                        and relative_route.rstrip("/").endswith(
                            "/chat/completions"
                        )
                    ):
                        response_transformer = (
                            _OpenAIEmptyContentTransformer(
                                event_stream=event_stream,
                            )
                        )
                    while True:
                        chunk = _read_response_chunk(response)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        if transferred > _MAX_RESPONSE_BYTES:
                            raise AgentSecretRelayUsageError("模型响应过大")
                        if endpoint_response_accepted:
                            response_payload.extend(chunk)
                        forwarded = (
                            response_transformer.feed(chunk)
                            if response_transformer is not None
                            else chunk
                        )
                        rendered = redactor.feed(forwarded)
                        if rendered and client_writable:
                            try:
                                self.wfile.write(rendered)
                                self.wfile.flush()
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                OSError,
                                socket.timeout,
                            ):
                                client_writable = False
                    forwarded = (
                        response_transformer.feed(final=True)
                        if response_transformer is not None
                        else b""
                    )
                    rendered = redactor.feed(forwarded, final=True)
                    if rendered and client_writable:
                        try:
                            self.wfile.write(rendered)
                            self.wfile.flush()
                        except (
                            BrokenPipeError,
                            ConnectionResetError,
                            OSError,
                            socket.timeout,
                        ):
                            client_writable = False
                    if endpoint_response_accepted:
                        endpoint_accounting_attempted = True
                        relay._account_endpoint_response(
                            endpoint_request_claim,
                            relative_route,
                            bytes(response_payload),
                        )
                        endpoint_accounted = True
                except _RequestRejected as exc:
                    account_incomplete_response_as_zero()
                    if not response_started:
                        try:
                            self._send_plain(exc.status, exc.message)
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            pass
                except AgentSecretRelayUsageError:
                    # 响应处理失败按 0 cost 收束；若异常来自账本 callback，
                    # _account_endpoint_response 已记录权威失败并封锁 relay。
                    account_incomplete_response_as_zero()
                except (
                    BrokenPipeError,
                    ConnectionResetError,
                    http.client.HTTPException,
                    OSError,
                    socket.timeout,
                ):
                    # 上游断流没有完整可计费结果：本条写 0 cost，由 harness
                    # 决定是否重试，不得杀掉其他并发 subagent。
                    account_incomplete_response_as_zero()
                except Exception:
                    account_incomplete_response_as_zero()
                finally:
                    if (
                        endpoint_request_claim is not None
                        and not endpoint_accounted
                    ):
                        relay._abandon_endpoint_request(endpoint_request_claim)
                    if reserved_body_bytes:
                        relay._release_request_body(reserved_body_bytes)
                    if response is not None:
                        try:
                            response.close()
                        except Exception:
                            pass
                    if connection_registered:
                        self.server.unregister_upstream(connection_handle)
                    if connection_handle is not None:
                        try:
                            connection_handle.close()
                        except Exception:
                            pass
                    elif connection is not None:
                        try:
                            connection.close()
                        except Exception:
                            pass
                    self.close_connection = True

            def do_GET(self):
                self._proxy()

            def do_POST(self):
                self._proxy()

            def do_PUT(self):
                self._proxy()

            def do_PATCH(self):
                self._proxy()

            def do_DELETE(self):
                self._proxy()

            def do_HEAD(self):
                self._proxy()

            def do_OPTIONS(self):
                self._proxy()

            def do_CONNECT(self):
                self._proxy()

            def do_TRACE(self):
                self._proxy()

        return RelayHandler

    def start(self):
        with self._state_lock:
            if self.server is not None or self._closed:
                raise AgentSecretRelayError("外部服务密钥代理已启动或已关闭")
        try:
            server = _BoundedSecretRelayServer(
                (_relay_bind_host(), 0),
                self._handler_class(),
            )
        except Exception as exc:
            with self._state_lock:
                self._active = False
                self._closed = True
            self._forget_credentials()
            raise AgentSecretRelayError("外部服务密钥代理启动失败") from exc
        port = int(server.server_address[1])
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"numoj-agent-secret-relay-{port}",
            daemon=True,
        )
        with self._state_lock:
            self.server = server
            self.thread = thread
            self._active = True
            self.container_base_url = (
                f"http://{_CONTAINER_HOST}:{port}"
                f"{self.upstream.container_base_path}"
            )
        try:
            thread.start()
        except Exception as exc:
            with self._state_lock:
                self._active = False
                self._closed = True
            server.server_close()
            self._forget_credentials()
            raise AgentSecretRelayError(
                "外部服务密钥代理启动失败"
            ) from exc
        return self.container_base_url

    def close(self):
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._active = False
            # 唤醒 usage drain 等待者；它们必须立即观察 _closed
            # 并 fail-closed 退出，而不是睡到自己的 605 秒截止，把
            # close() 的限时等待拖成清理失败。
            self._usage_condition.notify_all()
            server = self.server
            thread = self.thread
        # relay 一进入 closing 就立即擦除对象上的长期及临时凭据。已经进入
        # handler 的局部快照只能由下方确认 handler 退出来完成生命周期收束。
        self._forget_credentials()
        if server is None:
            return
        cleanup_error = None
        pending_handlers = 0
        try:
            server.close_active_requests()
            server.shutdown()
        except Exception as exc:
            cleanup_error = exc
        try:
            server.server_close()
        except Exception as exc:
            cleanup_error = cleanup_error or exc
        try:
            pending_handlers = server.drain_handlers(
                _HANDLER_SHUTDOWN_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            cleanup_error = cleanup_error or exc
        if thread is not None:
            thread.join(timeout=_HANDLER_SHUTDOWN_TIMEOUT_SECONDS)
        thread_alive = thread is not None and thread.is_alive()
        if cleanup_error is not None or pending_handlers or thread_alive:
            reasons = []
            if cleanup_error is not None:
                reasons.append(
                    f"清理动作异常 {type(cleanup_error).__name__}: "
                    f"{cleanup_error}"
                )
            if pending_handlers:
                reasons.append(f"{pending_handlers} 个转发请求未在限时内退出")
            if thread_alive:
                reasons.append("转发服务线程未退出")
            raise AgentSecretRelayCleanupError(
                f"外部服务密钥代理（{self.mode}）未能彻底关闭："
                + "；".join(reasons)
            ) from cleanup_error


@dataclass(frozen=True, slots=True)
class AgentSecretRelaySession:
    endpoint_base_url: str
    endpoint_api_key: str = field(repr=False)
    web_search_base_url: str = ""
    web_search_authorization: str = field(default="", repr=False)
    temporary_secrets: tuple[str, ...] = field(default=(), repr=False)
    _deny_endpoint_requests: object = field(
        default=None,
        repr=False,
        compare=False,
    )
    _raise_if_usage_failed: object = field(
        default=None,
        repr=False,
        compare=False,
    )
    _wait_for_endpoint_usage: object = field(
        default=None,
        repr=False,
        compare=False,
    )

    def deny_endpoint_requests(self):
        callback = self._deny_endpoint_requests
        if callable(callback):
            callback()

    def raise_if_usage_failed(self):
        callback = self._raise_if_usage_failed
        if callable(callback):
            callback()

    def wait_for_endpoint_usage(self, timeout=_ENDPOINT_USAGE_DRAIN_SECONDS):
        callback = self._wait_for_endpoint_usage
        if callable(callback):
            callback(timeout)


@contextmanager
def run_agent_secret_relays(
    endpoint,
    web_search_settings=None,
    *,
    endpoint_stop_event=None,
    require_endpoint_usage_ack=False,
    endpoint_usage_callback=None,
):
    """启动一轮模型端点及可选 WebSearch MCP 密钥代理。"""

    endpoint_protocol = str(endpoint.get("protocol") or "").strip().lower()
    endpoint_source = str(endpoint.get("source") or "").strip().lower()
    require_public_target = (
        endpoint_source == "user" or endpoint.get("is_personal") is True
    )
    endpoint_relay = _AgentSecretRelay(
        upstream_base_url=endpoint.get("base_url"),
        mode=endpoint_protocol,
        real_credential=endpoint.get("api_key"),
        stop_event=endpoint_stop_event,
        require_usage_ack=require_endpoint_usage_ack,
        usage_callback=endpoint_usage_callback,
        require_public_target=require_public_target,
    )
    web_search_relay = None
    if web_search_settings:
        base_url = str(web_search_settings.get("base_url") or "").strip()
        authorization = str(
            web_search_settings.get("authorization") or ""
        ).strip()
        if not base_url or not authorization:
            raise AgentSecretRelayError("站点 Web Search MCP 配置不完整")
        web_search_relay = _AgentSecretRelay(
            upstream_base_url=base_url,
            mode="mcp",
            real_credential=authorization,
        )

    started = []
    try:
        endpoint_base_url = endpoint_relay.start()
        started.append(endpoint_relay)
        web_search_base_url = ""
        web_search_authorization = ""
        temporary_secrets = [endpoint_relay.temporary_secret]
        if web_search_relay is not None:
            web_search_base_url = web_search_relay.start()
            started.append(web_search_relay)
            web_search_authorization = web_search_relay.container_credential
            temporary_secrets.append(web_search_relay.temporary_secret)
        yield AgentSecretRelaySession(
            endpoint_base_url=endpoint_base_url,
            endpoint_api_key=endpoint_relay.container_credential,
            web_search_base_url=web_search_base_url,
            web_search_authorization=web_search_authorization,
            temporary_secrets=tuple(temporary_secrets),
            _deny_endpoint_requests=endpoint_relay.deny_new_requests,
            _raise_if_usage_failed=endpoint_relay.raise_if_usage_failed,
            _wait_for_endpoint_usage=endpoint_relay.wait_for_endpoint_usage,
        )
    finally:
        cleanup_errors = []
        for relay in reversed(started):
            try:
                relay.close()
            except Exception as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            first = cleanup_errors[0]
            if isinstance(first, AgentSecretRelayCleanupError):
                raise first
            raise AgentSecretRelayCleanupError(
                "外部服务密钥代理清理失败"
            ) from first


__all__ = [
    "AgentSecretRelayCleanupError",
    "AgentSecretRelayError",
    "AgentSecretRelayUsageError",
    "AgentSecretRelayUsageHardStopError",
    "AgentSecretRelaySession",
    "run_agent_secret_relays",
]
