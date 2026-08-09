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


class _RelayConnectionMixin:
    """让 relay 能在 HTTPConnection 懒连接完成时立即取得底层 socket。"""

    def connect(self):
        super().connect()
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
        )

    def target_path(self, canonical_target):
        parts = urlsplit(str(canonical_target or ""))
        query = "&".join(
            item for item in (self.base_query, parts.query) if item
        )
        return urlunsplit(("", "", parts.path, query, ""))

    def target_url(self, canonical_target):
        return self.origin_url + self.target_path(canonical_target)


def _normalize_upstream_base_url(value, *, preserve_trailing_slash=False):
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
        port=int(port or (443 if parts.scheme.lower() == "https" else 80)),
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
    def __init__(self, *, upstream_base_url, mode, real_credential):
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
        self._request_count = 0
        self._inflight_request_bytes = 0

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
            if not self._active or self._closed:
                return False
            if self._request_count >= _MAX_REQUESTS_PER_RELAY:
                return False
            self._request_count += 1
            return True

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
                response_started = False
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
                    content_length = _request_content_length(
                        self.headers,
                        method,
                        _MAX_REQUEST_BYTES[relay.mode],
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
                    _response_content_length(response.headers)
                    _validate_response_content_encoding(response.headers)
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
                    response_started = True
                    transferred = 0
                    redactor = _StreamingRedactor(secret_values)
                    while True:
                        chunk = _read_response_chunk(response)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        if transferred > _MAX_RESPONSE_BYTES:
                            break
                        rendered = redactor.feed(chunk)
                        if rendered:
                            self.wfile.write(rendered)
                            self.wfile.flush()
                    rendered = redactor.feed(final=True)
                    if rendered:
                        self.wfile.write(rendered)
                        self.wfile.flush()
                except _RequestRejected as exc:
                    if not response_started:
                        self._send_plain(exc.status, exc.message)
                except (
                    BrokenPipeError,
                    ConnectionResetError,
                    OSError,
                    socket.timeout,
                ):
                    pass
                finally:
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


@contextmanager
def run_agent_secret_relays(endpoint, web_search_settings=None):
    """启动一轮模型端点及可选 WebSearch MCP 密钥代理。"""

    endpoint_protocol = str(endpoint.get("protocol") or "").strip().lower()
    endpoint_relay = _AgentSecretRelay(
        upstream_base_url=endpoint.get("base_url"),
        mode=endpoint_protocol,
        real_credential=endpoint.get("api_key"),
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
    "AgentSecretRelaySession",
    "run_agent_secret_relays",
]
