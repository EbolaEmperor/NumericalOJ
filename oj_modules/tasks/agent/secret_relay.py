#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent 外部服务密钥的短生命周期宿主转发代理。

容器只获得每个 relay 独立生成的临时凭据及宿主转发地址。模型端点 API Key
和 WebSearch MCP Authorization 始终只保存在宿主进程内存中；代理验证临时
凭据后剥离全部来访凭据，并向冻结的同源、同 base path 上游注入真实凭据。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hmac
import http.client
import http.server
import json
import re
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from oj_modules.tasks.agent.identity_relay import (
    _BoundedIdentityRelayServer,
    _RequestRejected,
    _canonical_request_path,
    _read_response_chunk,
    _relay_bind_host,
    _request_parts,
    _single_header,
)


_CONTAINER_HOST = "host.docker.internal"
_TEMPORARY_SECRET_BYTES = 32
_MAX_REQUESTS_PER_RELAY = 2048
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_UPSTREAM_TIMEOUT_SECONDS = 600
_HANDLER_SHUTDOWN_TIMEOUT_SECONDS = 5
_CLIENT_TIMEOUT_SECONDS = 30
_ENDPOINT_USAGE_GATE_WAIT_SECONDS = 30
_ENDPOINT_USAGE_DRAIN_SECONDS = _UPSTREAM_TIMEOUT_SECONDS + 5
_REDACTION = b"[REDACTED]"
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


class _RelayConnectionMixin:
    """让 relay 能在 HTTPConnection 懒连接完成时立即取得底层 socket。"""

    def __init__(self, *args, connect_host="", **kwargs):
        self._relay_connect_host = str(connect_host or "").strip()
        super().__init__(*args, **kwargs)

    def connect(self):
        original_create_connection = getattr(self, "_create_connection", None)
        if self._relay_connect_host and original_create_connection is not None:
            pinned_host = self._relay_connect_host

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
        handle = getattr(self, "_relay_interrupt_handle", None)
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
        connection._relay_interrupt_handle = self

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
    cached_tokens, cached_present = _first_usage_count(
        usage,
        (
            "prompt_cache_hit_tokens",
            "input_cached_tokens",
            "cache_read_input_tokens",
        ),
        "缓存输入 Token",
    )
    if not cached_present:
        cached_tokens, _ = _first_usage_count(
            input_details,
            ("cached_tokens", "cache_read_tokens"),
            "缓存输入 Token",
        )
    cache_write_tokens, cache_write_present = _first_usage_count(
        usage,
        ("input_cache_write_tokens", "cache_creation_input_tokens"),
        "缓存写入 Token",
    )
    if not cache_write_present:
        cache_write_tokens, _ = _first_usage_count(
            input_details,
            ("cache_write_tokens", "cache_creation_tokens"),
            "缓存写入 Token",
        )
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
    return {
        "input_uncached_tokens": uncached_tokens,
        "input_cached_tokens": cached_tokens,
        "input_cache_write_tokens": cache_write_tokens,
        "output_tokens": output_tokens,
        "reasoning_output_tokens": reasoning_tokens,
    }


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
    for record in records:
        cache_creation = record.get("cache_creation")
        if (
            "cache_creation_input_tokens" not in record
            and isinstance(cache_creation, dict)
        ):
            five_minutes, _ = _first_usage_count(
                cache_creation,
                ("ephemeral_5m_input_tokens",),
                "5 分钟缓存写入 Token",
            )
            one_hour, _ = _first_usage_count(
                cache_creation,
                ("ephemeral_1h_input_tokens",),
                "1 小时缓存写入 Token",
            )
            record = {
                **record,
                "cache_creation_input_tokens": five_minutes + one_hour,
            }
        for target, names in aliases.items():
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
    return {field: maxima.get(field, 0) for field in aliases}


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
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._handler_condition:
            while self._pending_handlers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._handler_condition.wait(timeout=remaining)
            return True


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
    ):
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode not in {"openai", "anthropic", "mcp"}:
            raise AgentSecretRelayError("外部服务密钥代理模式无效")
        self.mode = normalized_mode
        self.upstream = _normalize_upstream_base_url(
            upstream_base_url,
            preserve_trailing_slash=self.mode == "mcp",
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
        self._endpoint_request_inflight = False
        self._usage_failure = None
        self._usage_condition = threading.Condition(self._state_lock)

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
        """串行放行一条需计费的模型请求。

        relay 临时凭据对容器内所有进程可见，因此必须以 relay 观察到的上游
        usage 为权威边界。上一条响应没有完整读取、解析并入账前，下一条生成
        请求不能到达上游；adapter stdout 只负责展示轨迹。
        """

        if not self._require_usage_ack:
            return True
        deadline = time.monotonic() + _ENDPOINT_USAGE_GATE_WAIT_SECONDS
        with self._usage_condition:
            while self._endpoint_request_inflight:
                if (
                    not self._active
                    or self._closed
                    or self._stop_event.is_set()
                ):
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._usage_condition.wait(timeout=remaining)
            if (
                not self._active
                or self._closed
                or self._stop_event.is_set()
            ):
                return False
            self._endpoint_request_inflight = True
            return True

    def _abandon_endpoint_request(self):
        if not self._require_usage_ack:
            return
        with self._usage_condition:
            self._endpoint_request_inflight = False
            self._usage_condition.notify_all()

    def _record_usage_failure(self, exc):
        failure = exc if isinstance(exc, Exception) else AgentSecretRelayUsageError(
            "模型 usage 记账失败"
        )
        with self._usage_condition:
            if self._usage_failure is None:
                self._usage_failure = failure
            self._endpoint_request_inflight = False
            self._usage_condition.notify_all()
        self.deny_new_requests()

    def _account_endpoint_response(self, relative_route, payload):
        if not self._require_usage_ack:
            return None
        try:
            usage = _extract_response_usage(self.mode, relative_route, payload)
            event = {
                "type": "numoj_usage",
                "version": 1,
                "source": f"relay_{self.mode}",
                "id": "relay-" + secrets.token_urlsafe(24),
                "usage": usage,
            }
            result = self._usage_callback(event)
            if not isinstance(result, dict) or result.get("applied") is not True:
                raise AgentSecretRelayUsageError("模型 usage 没有产生新的记账记录")
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
        except Exception as exc:
            self._record_usage_failure(exc)
            raise
        with self._usage_condition:
            self._endpoint_request_inflight = False
            self._usage_condition.notify_all()
        return result

    def raise_if_usage_failed(self):
        with self._usage_condition:
            failure = self._usage_failure
        if failure is not None:
            raise failure

    def wait_for_endpoint_usage(self, timeout=_ENDPOINT_USAGE_DRAIN_SECONDS):
        """正常结束 harness 时等最后一个已接受请求读完并完成记账。"""

        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._usage_condition:
            while self._endpoint_request_inflight and self._usage_failure is None:
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
                endpoint_request_claimed = False
                endpoint_response_accepted = False
                endpoint_accounting_attempted = False
                endpoint_accounted = False
                response_started = False
                relative_route = ""
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
                        if not relay._claim_endpoint_request():
                            raise _RequestRejected(
                                503,
                                "usage acknowledgement required",
                            )
                        endpoint_request_claimed = True
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
                    if endpoint_request_claimed:
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
                        endpoint_request_claimed and 200 <= status < 300
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
                        # 只有完整 usage 入账后才释放串行闸门。
                        client_writable = False
                    transferred = 0
                    response_payload = bytearray()
                    redactor = _StreamingRedactor(secret_values)
                    while True:
                        chunk = _read_response_chunk(response)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        if transferred > _MAX_RESPONSE_BYTES:
                            raise AgentSecretRelayUsageError("模型响应过大")
                        if endpoint_response_accepted:
                            response_payload.extend(chunk)
                        rendered = redactor.feed(chunk)
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
                    rendered = redactor.feed(final=True)
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
                            relative_route,
                            bytes(response_payload),
                        )
                        endpoint_accounted = True
                except _RequestRejected as exc:
                    if endpoint_response_accepted:
                        relay._record_usage_failure(
                            AgentSecretRelayUsageError(
                                "模型响应未能完整读取并记账"
                            )
                        )
                    if not response_started:
                        try:
                            self._send_plain(exc.status, exc.message)
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            pass
                except AgentSecretRelayUsageError:
                    # 解析/记账方法已经记录权威失败并封锁 relay；响应可能已经
                    # 流式交付，不能再向同一连接拼接另一个 HTTP 错误。
                    if endpoint_response_accepted and not endpoint_accounting_attempted:
                        relay._record_usage_failure(
                            AgentSecretRelayUsageError(
                                "模型响应未能完整读取并记账"
                            )
                        )
                except (
                    BrokenPipeError,
                    ConnectionResetError,
                    OSError,
                    socket.timeout,
                ) as exc:
                    if endpoint_response_accepted and not endpoint_accounting_attempted:
                        relay._record_usage_failure(
                            AgentSecretRelayUsageError(
                                "模型响应读取中断，无法确认 usage"
                            )
                        )
                except Exception as exc:
                    if endpoint_response_accepted and not endpoint_accounting_attempted:
                        relay._record_usage_failure(exc)
                finally:
                    if (
                        endpoint_request_claimed
                        and not endpoint_response_accepted
                        and not endpoint_accounted
                    ):
                        relay._abandon_endpoint_request()
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
            server = self.server
            thread = self.thread
        if server is None:
            self._forget_credentials()
            return
        cleanup_error = None
        handlers_stopped = False
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
            handlers_stopped = server.wait_for_handlers(
                _HANDLER_SHUTDOWN_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            cleanup_error = cleanup_error or exc
        if thread is not None:
            thread.join(timeout=_HANDLER_SHUTDOWN_TIMEOUT_SECONDS)
        # 关闭后立即丢弃 relay 内真实/临时凭据映射；即使调用方仍错误地
        # 持有对象，也无法再次完成认证或向上游注入长期密钥。
        self._forget_credentials()
        if (
            cleanup_error is not None
            or not handlers_stopped
            or (thread is not None and thread.is_alive())
        ):
            raise AgentSecretRelayCleanupError(
                "外部服务密钥代理未能彻底关闭"
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
    endpoint_relay = _AgentSecretRelay(
        upstream_base_url=endpoint.get("base_url"),
        mode=endpoint_protocol,
        real_credential=endpoint.get("api_key"),
        stop_event=endpoint_stop_event,
        require_usage_ack=require_endpoint_usage_ack,
        usage_callback=endpoint_usage_callback,
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
