#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""短生命周期 NumOJ 身份转发代理。

Agent 工作区只需要保存代理地址和一个无权限的固定 cookie 占位值。真实
Flask Session 仅由宿主进程内存持有；代理在严格的任务路由白名单内剥离来访
凭证并注入真实 Session，生命周期结束后立即关闭所有客户端与上游连接。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import http.server
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from oj_modules.problems.agent_launch import (
    AGENT_TASK_SOLVE,
    AGENT_TASK_TESTDATA,
    normalize_agent_task_kind,
)


_CONTAINER_HOST = "host.docker.internal"
_MAX_CONNECTIONS = 4
_MAX_REQUEST_TARGET_BYTES = 4096
_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_CLIENT_TIMEOUT_SECONDS = 30
_UPSTREAM_TIMEOUT_SECONDS = 60

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
_INBOUND_CREDENTIAL_HEADERS = frozenset({
    "api-key",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
})
_FORWARDING_HEADERS = frozenset({
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
})
_SENSITIVE_RESPONSE_HEADERS = frozenset({
    "proxy-authenticate",
    "refresh",
    "set-cookie",
    "set-cookie2",
})
_COOKIE_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}\Z")
_SUBMISSION_LOCATION_RE = re.compile(r"/submission_detail/([1-9][0-9]*)\Z")
_SUBMISSION_STATUS_RE = re.compile(r"/submission_status/([1-9][0-9]*)\Z")
_SUBMISSION_STREAM_RE = re.compile(
    r"/submission_status_stream/([1-9][0-9]*)\Z",
)
_SUBMISSION_API_DETAIL_RE = re.compile(r"/api/submissions/([1-9][0-9]*)\Z")


class IdentityRelayError(RuntimeError):
    """身份代理配置或运行失败。"""


def _relay_bind_host():
    """只监听容器可达的本机接口，不能把管理员 Session 暴露到站点网卡。"""

    if platform.system() == "Darwin":
        # Docker Desktop 会把 host.docker.internal 转发到 macOS loopback。
        return "127.0.0.1"
    if platform.system() != "Linux":
        raise IdentityRelayError("当前系统不支持安全启动 NumOJ 身份代理")
    try:
        completed = subprocess.run(
            [
                "docker",
                "network",
                "inspect",
                "bridge",
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        raise IdentityRelayError("无法解析 Docker bridge 网关") from exc
    raw = str(completed.stdout or "").strip()
    if completed.returncode != 0 or "\n" in raw:
        raise IdentityRelayError("无法解析 Docker bridge 网关")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise IdentityRelayError("Docker bridge 网关地址无效") from exc
    if address.version != 4 or not (address.is_private or address.is_loopback):
        raise IdentityRelayError("Docker bridge 网关不是安全的本机私有地址")
    return str(address)


class _RequestRejected(ValueError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = int(status)
        self.message = str(message)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """上游响应必须先经过同源检查，绝不自动跟随 Location。"""

    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


def _origin(parts):
    scheme = str(parts.scheme or "").lower()
    host = str(parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port
    except ValueError as exc:
        raise IdentityRelayError("NumOJ 站点地址端口无效") from exc
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, int(port)


def _normalize_site_url(site_url):
    raw = str(site_url or "").strip()
    if not raw or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw):
        raise IdentityRelayError("NumOJ 站点地址无效")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise IdentityRelayError("NumOJ 站点地址无效") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise IdentityRelayError("NumOJ 站点地址必须是无路径、无凭证的 HTTP(S) Origin")
    _origin(parts)
    host = str(parts.hostname).lower().rstrip(".")
    # AGENT_CONTAINER_SITE_URL 常使用容器专用别名；宿主回源时改为 loopback，
    # 避免依赖宿主 DNS 是否认识 host.docker.internal。
    upstream_host = "127.0.0.1" if host == _CONTAINER_HOST else host
    if ":" in upstream_host and not upstream_host.startswith("["):
        upstream_host = f"[{upstream_host}]"
    netloc = upstream_host
    if parts.port is not None:
        netloc += f":{parts.port}"
    upstream_url = urlunsplit((parts.scheme.lower(), netloc, "", "", ""))
    return upstream_url, _origin(urlsplit(upstream_url))


def _validate_identity(cookie_name, session_cookie):
    name = str(cookie_name or "").strip()
    value = str(session_cookie or "")
    if not _COOKIE_NAME_RE.fullmatch(name):
        raise IdentityRelayError("Session cookie 名称无效")
    if (
        not value
        or len(value.encode("utf-8")) > 8192
        or any(not 0x21 <= ord(char) <= 0x7E for char in value)
        or any(char in value for char in '\",;\\')
    ):
        raise IdentityRelayError("Session cookie 内容无效")
    return name, value


def _request_parts(raw_target):
    target = str(raw_target or "")
    if not target or len(target.encode("utf-8")) > _MAX_REQUEST_TARGET_BYTES:
        raise _RequestRejected(414, "request target too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in target):
        raise _RequestRejected(400, "invalid request target")
    try:
        parts = urlsplit(target)
    except ValueError as exc:
        raise _RequestRejected(400, "invalid request target") from exc
    if parts.scheme or parts.netloc or parts.fragment or not parts.path.startswith("/"):
        raise _RequestRejected(400, "invalid request target")
    try:
        query = parse_qsl(
            parts.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=8,
        ) if parts.query else []
    except ValueError as exc:
        raise _RequestRejected(400, "invalid query string") from exc
    return parts.path, query


def _single_header(headers, name):
    values = []
    getter = getattr(headers, "get_all", None)
    if callable(getter):
        values = getter(name) or []
    elif headers is not None:
        value = headers.get(name)
        values = [] if value is None else [value]
    if len(values) > 1:
        raise _RequestRejected(400, f"multiple {name} headers")
    return str(values[0]) if values else ""


def _request_content_length(headers, method):
    raw = _single_header(headers, "Content-Length").strip()
    if not raw:
        if str(method).upper() == "POST":
            raise _RequestRejected(411, "content length required")
        return 0
    if not re.fullmatch(r"[0-9]+", raw):
        raise _RequestRejected(400, "invalid content length")
    length = int(raw)
    if length > _MAX_REQUEST_BYTES:
        raise _RequestRejected(413, "request too large")
    return length


def _upstream_headers(headers, cookie_name, session_cookie):
    forwarded = {}
    for name, value in (headers.items() if headers is not None else ()):
        lowered = str(name).lower()
        if (
            lowered in _HOP_BY_HOP_HEADERS
            or lowered in _INBOUND_CREDENTIAL_HEADERS
            or lowered in _FORWARDING_HEADERS
            or lowered == "content-length"
        ):
            continue
        forwarded[str(name)] = str(value)
    forwarded["Cookie"] = f"{cookie_name}={session_cookie}"
    return forwarded


def _response_headers(headers, rewritten_location=""):
    forwarded = []
    for name, value in (headers.items() if headers is not None else ()):
        lowered = str(name).lower()
        if (
            lowered in _HOP_BY_HOP_HEADERS
            or lowered in _SENSITIVE_RESPONSE_HEADERS
            or lowered in {"content-length", "location", "server", "date"}
        ):
            continue
        forwarded.append((str(name), str(value)))
    if rewritten_location:
        forwarded.append(("Location", rewritten_location))
    return forwarded


def _response_content_length(headers):
    raw = str((headers.get("Content-Length") if headers is not None else "") or "").strip()
    if not raw:
        return None
    if not re.fullmatch(r"[0-9]+", raw):
        raise _RequestRejected(502, "invalid upstream content length")
    length = int(raw)
    if length > _MAX_RESPONSE_BYTES:
        raise _RequestRejected(502, "upstream response too large")
    return length


@dataclass(frozen=True, slots=True)
class _ForwardPlan:
    method: str
    raw_target: str
    path: str
    target_url: str


class _IdentityRelayPolicy:
    """任务路由白名单及本代理创建 submission 的状态机。"""

    def __init__(self, task_kind, problem_id, upstream_url):
        self.task_kind = normalize_agent_task_kind(task_kind)
        if type(problem_id) is not int or problem_id <= 0:
            raise IdentityRelayError("题号无效")
        self.problem_id = problem_id
        self.upstream_url, self.upstream_origin = _normalize_site_url(upstream_url)
        self._submission_ids = set()
        self._lock = threading.Lock()

    def _created_submission_allowed(self, path):
        for pattern in (
            _SUBMISSION_STATUS_RE,
            _SUBMISSION_STREAM_RE,
            _SUBMISSION_API_DETAIL_RE,
        ):
            match = pattern.fullmatch(path)
            if match:
                submission_id = int(match.group(1))
                with self._lock:
                    return submission_id in self._submission_ids
        return False

    def created_submission_ids(self):
        with self._lock:
            return tuple(sorted(self._submission_ids))

    def plan(self, method, raw_target):
        normalized_method = str(method or "").upper()
        path, query = _request_parts(raw_target)
        pid = self.problem_id
        allowed = False
        if self.task_kind == AGENT_TASK_SOLVE:
            if normalized_method == "GET" and not query:
                allowed = path in {
                    f"/api/problems/{pid}",
                    f"/api/problems/{pid}/submit-context",
                    "/me/classes",
                } or self._created_submission_allowed(path)
            elif normalized_method == "POST" and not query:
                allowed = path == f"/submit/{pid}"
        elif self.task_kind == AGENT_TASK_TESTDATA:
            if normalized_method == "GET" and not query:
                allowed = path in {
                    f"/api/problems/{pid}",
                    "/me/classes",
                }
        if not allowed:
            raise _RequestRejected(404, "not found")
        return _ForwardPlan(
            method=normalized_method,
            raw_target=str(raw_target),
            path=path,
            target_url=self.upstream_url + str(raw_target),
        )

    def inspect_redirect(self, plan, status, headers):
        if not 300 <= int(status) < 400:
            return ""
        location = str((headers.get("Location") if headers is not None else "") or "").strip()
        if not location:
            return ""
        if (
            len(location.encode("utf-8")) > _MAX_REQUEST_TARGET_BYTES
            or "\\" in location
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in location)
        ):
            raise _RequestRejected(502, "unsafe upstream redirect")
        try:
            joined = urljoin(plan.target_url, location)
            parts = urlsplit(joined)
        except ValueError as exc:
            raise _RequestRejected(502, "unsafe upstream redirect") from exc
        if (
            parts.scheme.lower() not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or _origin(parts) != self.upstream_origin
            # Location 以双斜杠开头时，写回响应后会被客户端重新解释为
            # network-path reference；即使 urljoin 曾把它视作同源路径也拒绝。
            or not (parts.path or "").startswith("/")
            or (parts.path or "").startswith("//")
        ):
            raise _RequestRejected(502, "cross-origin redirect refused")
        rewritten = urlunsplit(("", "", parts.path or "/", parts.query, parts.fragment))
        if plan.method == "POST" and plan.path == f"/submit/{self.problem_id}":
            match = _SUBMISSION_LOCATION_RE.fullmatch(parts.path or "")
            if match:
                submission_id = int(match.group(1))
                if submission_id <= 9_223_372_036_854_775_807:
                    with self._lock:
                        self._submission_ids.add(submission_id)
        return rewritten


def _read_response_chunk(response, size=64 * 1024):
    reader = getattr(response, "read1", None)
    if callable(reader):
        return reader(int(size))
    return response.read(int(size))


class _BoundedIdentityRelayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = _MAX_CONNECTIONS * 2

    def __init__(self, server_address, handler_class):
        self._slots = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        self._active_lock = threading.Lock()
        self._active_clients = set()
        self._active_upstreams = set()
        self._closing = False
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
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._active_lock:
                self._active_clients.discard(request)
            self._slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._active_lock:
                self._active_clients.discard(request)
            self._slots.release()

    def register_upstream(self, response):
        with self._active_lock:
            if self._closing:
                response.close()
                return False
            self._active_upstreams.add(response)
            return True

    def unregister_upstream(self, response):
        with self._active_lock:
            self._active_upstreams.discard(response)

    def close_active_requests(self):
        with self._active_lock:
            self._closing = True
            clients = list(self._active_clients)
            upstreams = list(self._active_upstreams)
            self._active_clients.clear()
            self._active_upstreams.clear()
        for response in upstreams:
            try:
                response.close()
            except Exception:
                pass
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass

    def handle_error(self, _request, _client_address):
        return


class _NumOJIdentityRelay:
    def __init__(self, task_kind, problem_id, site_url, cookie_name, session_cookie):
        upstream_url, _upstream_origin = _normalize_site_url(site_url)
        self.policy = _IdentityRelayPolicy(task_kind, problem_id, upstream_url)
        self.cookie_name, self.session_cookie = _validate_identity(
            cookie_name,
            session_cookie,
        )
        self.server = None
        self.thread = None
        self.container_base_url = ""
        self._closed = False

    def _handler_class(self):
        relay = self
        opener = urllib.request.build_opener(_NoRedirect())

        class RelayHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            server_version = "NumOJIdentityRelay/1.0"
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
                try:
                    plan = relay.policy.plan(self.command, self.path)
                    transfer_encoding = _single_header(
                        self.headers,
                        "Transfer-Encoding",
                    ).strip().lower()
                    if transfer_encoding not in {"", "identity"}:
                        raise _RequestRejected(400, "unsupported transfer encoding")
                    content_length = _request_content_length(
                        self.headers,
                        plan.method,
                    )
                    body = self.rfile.read(content_length) if content_length else None
                    if content_length and (body is None or len(body) != content_length):
                        raise _RequestRejected(400, "incomplete request")
                    headers = _upstream_headers(
                        self.headers,
                        relay.cookie_name,
                        relay.session_cookie,
                    )
                    request_obj = urllib.request.Request(
                        plan.target_url,
                        data=body,
                        headers=headers,
                        method=plan.method,
                    )
                    try:
                        response = opener.open(
                            request_obj,
                            timeout=_UPSTREAM_TIMEOUT_SECONDS,
                        )
                    except urllib.error.HTTPError as exc:
                        response = exc
                    except Exception as exc:
                        raise _RequestRejected(502, "upstream unavailable") from exc
                    if not self.server.register_upstream(response):
                        return
                    status = int(getattr(response, "status", response.getcode()))
                    rewritten_location = relay.policy.inspect_redirect(
                        plan,
                        status,
                        response.headers,
                    )
                    expected_length = _response_content_length(response.headers)
                    self.send_response(status)
                    for name, value in _response_headers(
                        response.headers,
                        rewritten_location,
                    ):
                        self.send_header(name, value)
                    if expected_length is not None:
                        self.send_header("Content-Length", str(expected_length))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    transferred = 0
                    while True:
                        chunk = _read_response_chunk(response)
                        if not chunk:
                            break
                        transferred += len(chunk)
                        if transferred > _MAX_RESPONSE_BYTES:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except _RequestRejected as exc:
                    if response is None:
                        self._send_plain(exc.status, exc.message)
                    else:
                        # 还未发送上游 headers 时可以安全替换为本地错误响应。
                        self._send_plain(exc.status, exc.message)
                except (BrokenPipeError, ConnectionResetError, socket.timeout):
                    pass
                finally:
                    if response is not None:
                        self.server.unregister_upstream(response)
                        try:
                            response.close()
                        except Exception:
                            pass
                    self.close_connection = True

            def do_GET(self):
                self._proxy()

            def do_POST(self):
                self._proxy()

            def do_HEAD(self):
                self._send_plain(405, "method not allowed")

            def do_PUT(self):
                self._send_plain(405, "method not allowed")

            def do_PATCH(self):
                self._send_plain(405, "method not allowed")

            def do_DELETE(self):
                self._send_plain(405, "method not allowed")

            def do_OPTIONS(self):
                self._send_plain(405, "method not allowed")

        return RelayHandler

    def start(self):
        if self.server is not None:
            raise IdentityRelayError("NumOJ 身份代理已启动")
        try:
            server = _BoundedIdentityRelayServer(
                (_relay_bind_host(), 0),
                self._handler_class(),
            )
        except OSError as exc:
            raise IdentityRelayError("NumOJ 身份代理启动失败") from exc
        port = int(server.server_address[1])
        thread = threading.Thread(
            target=server.serve_forever,
            name=f"numoj-identity-relay-{port}",
            daemon=True,
        )
        self.server = server
        self.thread = thread
        self.container_base_url = f"http://{_CONTAINER_HOST}:{port}"
        thread.start()
        return self.container_base_url

    @property
    def created_submission_ids(self):
        return self.policy.created_submission_ids()

    def close(self):
        if self._closed:
            return
        self._closed = True
        server = self.server
        thread = self.thread
        if server is None:
            return
        try:
            server.close_active_requests()
            server.shutdown()
        finally:
            server.server_close()
            if thread is not None:
                thread.join(timeout=5)
        if thread is not None and thread.is_alive():
            raise IdentityRelayError("NumOJ 身份代理未能彻底关闭")


@dataclass(frozen=True, slots=True)
class NumOJIdentityRelaySession:
    """调用方可读取代理地址及由该代理精确创建的提交编号。"""

    base_url: str
    _relay: _NumOJIdentityRelay

    @property
    def created_submission_ids(self):
        return self._relay.created_submission_ids


@contextmanager
def run_numoj_identity_relay(
    task_kind,
    problem_id,
    site_url,
    cookie_name,
    session_cookie,
):
    """启动任务级身份转发代理并返回容器可访问的 NumOJ base URL。

    这里的“任务级”仅描述进程生命周期；接口不创建、签发或校验任何任务
    token。调用方必须把真实 Session 留在宿主参数中，不能写入 Agent 工作区。
    """

    relay = _NumOJIdentityRelay(
        task_kind,
        problem_id,
        site_url,
        cookie_name,
        session_cookie,
    )
    base_url = relay.start()
    session = NumOJIdentityRelaySession(base_url=base_url, _relay=relay)
    try:
        yield session
    finally:
        relay.close()


__all__ = [
    "IdentityRelayError",
    "NumOJIdentityRelaySession",
    "run_numoj_identity_relay",
]
