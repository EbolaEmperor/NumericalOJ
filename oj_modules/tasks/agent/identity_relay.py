#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""短生命周期 NumOJ 身份转发代理。

Agent 工作区只保存带本轮高熵访问凭证的代理地址和一个无权限 cookie 占位值。
真实 Flask Session 仅由宿主进程内存持有；代理先验证本轮请求凭证，再在严格
任务路由边界内剥离来访凭证并注入真实 Session，结束后关闭所有连接。
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import hmac
import http.server
import ipaddress
import platform
import re
import secrets
import socket
import subprocess
import threading
import urllib.error
import urllib.request
from urllib.parse import (
    quote,
    unquote_to_bytes,
    urljoin,
    urlsplit,
    urlunsplit,
)

from oj_modules.problems.agent_launch import (
    AGENT_ACCESS_ROLE_USER,
    AGENT_TASK_CUSTOM,
    AGENT_TASK_SOLVE,
    AGENT_TASK_TESTDATA,
    normalize_agent_access_role,
    normalize_agent_task_kind,
)
from oj_modules.security.agent_identity import (
    AGENT_IDENTITY_HEADER,
    create_agent_identity_capability,
)


_CONTAINER_HOST = "host.docker.internal"
_MAX_CONNECTIONS = 4
_MAX_REQUEST_TARGET_BYTES = 4096
_MAX_REQUEST_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_CLIENT_TIMEOUT_SECONDS = 30
_UPSTREAM_TIMEOUT_SECONDS = 60
_RELAY_AUTH_USERNAME = "numoj-agent"
_RELAY_SECRET_BYTES = 32
_CANONICAL_PATH_SAFE = "/!$&'()*+,-.:;=@_~"

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
    AGENT_IDENTITY_HEADER.lower(),
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
_SUBMIT_RE = re.compile(r"/submit/([1-9][0-9]*)\Z")

_CUSTOM_BLOCKED_EXACT_ROUTES = frozenset({
    "/login",
    "/logout",
    "/register",
    "/send_code",
    "/forgot_password",
    "/send_password_code",
    "/change_password",
})
_CUSTOM_BLOCKED_ROUTE_PREFIXES = (
    "/admin/agent_tasks",
    "/admin/agent_solve_problem",
    "/admin/agent_generate_testdata",
    "/admin/agent_run_cancel",
    "/api/admin/agent-tasks",
)


class IdentityRelayError(RuntimeError):
    """身份代理配置或运行失败。"""


class IdentityRelayCleanupError(IdentityRelayError):
    """身份代理关闭状态未知，Agent 会话不得恢复。"""


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


def _validate_identity(cookie_name, session_cookie, *, allow_empty=False):
    name = str(cookie_name or "").strip()
    value = str(session_cookie or "")
    if not _COOKIE_NAME_RE.fullmatch(name):
        raise IdentityRelayError("Session cookie 名称无效")
    if (
        (not value and not allow_empty)
        or len(value.encode("utf-8")) > 8192
        or any(not 0x21 <= ord(char) <= 0x7E for char in value)
        or any(char in value for char in '\",;\\')
    ):
        raise IdentityRelayError("Session cookie 内容无效")
    return name, value


def _canonical_request_path(raw_path, *, allow_trailing_slash=False):
    """返回唯一语义路径与规范转发编码，拒绝会改变授权边界的歧义。"""

    raw = str(raw_path or "")
    if (
        not raw.startswith("/")
        or raw.startswith("//")
        or "\\" in raw
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in raw)
    ):
        raise _RequestRejected(400, "invalid request path")

    index = 0
    while index < len(raw):
        if raw[index] != "%":
            index += 1
            continue
        if index + 2 >= len(raw):
            raise _RequestRejected(400, "invalid percent escape")
        escaped = raw[index + 1:index + 3]
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", escaped):
            raise _RequestRejected(400, "invalid percent escape")
        # 这些字节会改变路径分段、制造二次解码或落入控制字符语义，必须
        # 拒绝；其它合法 escape 统一解码后再生成唯一转发编码。
        if int(escaped, 16) in {0x00, 0x25, 0x2F, 0x5C}:
            raise _RequestRejected(400, "ambiguous percent escape")
        index += 3

    try:
        decoded = unquote_to_bytes(raw).decode("utf-8", "strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise _RequestRejected(400, "invalid UTF-8 request path") from exc
    if (
        not decoded.startswith("/")
        or "\\" in decoded
        or "%" in decoded
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in decoded)
    ):
        raise _RequestRejected(400, "ambiguous decoded request path")
    if decoded != "/":
        segments = decoded.split("/")[1:]
        if allow_trailing_slash and decoded.endswith("/"):
            segments = segments[:-1]
        if any(segment in {"", ".", ".."} for segment in segments):
            raise _RequestRejected(400, "ambiguous request path segment")

    canonical = quote(
        decoded,
        safe=_CANONICAL_PATH_SAFE,
        encoding="utf-8",
        errors="strict",
    )
    return decoded, canonical


def _request_parts(raw_target, *, allow_trailing_slash=False):
    target = str(raw_target or "")
    if not target or len(target.encode("utf-8")) > _MAX_REQUEST_TARGET_BYTES:
        raise _RequestRejected(414, "request target too long")
    if (
        not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in target)
    ):
        raise _RequestRejected(400, "invalid request target")
    try:
        parts = urlsplit(target)
    except ValueError as exc:
        raise _RequestRejected(400, "invalid request target") from exc
    if parts.scheme or parts.netloc or parts.fragment or not parts.path.startswith("/"):
        raise _RequestRejected(400, "invalid request target")
    path, canonical_path = _canonical_request_path(
        parts.path,
        allow_trailing_slash=allow_trailing_slash,
    )
    # Query 对身份路由只需区分“有/无”，模型代理则原样转发给固定上游。
    # 不解析其键值可以兼容 provider 自定义语法，也避免人为限制参数数量。
    query = parts.query
    canonical_target = canonical_path
    if parts.query:
        canonical_target += "?" + parts.query
    return path, query, canonical_target


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


def _relay_authorization(secret):
    value = str(secret or "")
    if not value:
        raise IdentityRelayError("NumOJ 身份代理请求密钥无效")
    try:
        raw = f"{_RELAY_AUTH_USERNAME}:{value}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise IdentityRelayError("NumOJ 身份代理请求密钥无效") from exc
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _relay_request_authorized(headers, expected_authorization):
    provided = _single_header(headers, "Authorization").strip()
    expected = str(expected_authorization or "")
    return bool(
        provided
        and expected
        and hmac.compare_digest(provided, expected)
    )


def _relay_container_base_url(port, secret):
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise IdentityRelayError("NumOJ 身份代理端口无效") from exc
    if not 1 <= normalized_port <= 65535:
        raise IdentityRelayError("NumOJ 身份代理端口无效")
    encoded_secret = quote(str(secret or ""), safe="")
    if not encoded_secret:
        raise IdentityRelayError("NumOJ 身份代理请求密钥无效")
    return (
        f"http://{_RELAY_AUTH_USERNAME}:{encoded_secret}@"
        f"{_CONTAINER_HOST}:{normalized_port}"
    )


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


def _upstream_headers(
    headers,
    cookie_name,
    session_cookie,
    agent_identity_capability="",
):
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
    if session_cookie:
        forwarded["Cookie"] = f"{cookie_name}={session_cookie}"
    if agent_identity_capability:
        forwarded[AGENT_IDENTITY_HEADER] = str(agent_identity_capability)
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

    def __init__(
        self,
        task_kind,
        problem_id,
        upstream_url,
        access_role=AGENT_ACCESS_ROLE_USER,
    ):
        self.task_kind = normalize_agent_task_kind(task_kind)
        self.access_role = normalize_agent_access_role(
            access_role,
            task_kind=self.task_kind,
        )
        if self.task_kind == AGENT_TASK_CUSTOM:
            self.problem_id = None
        else:
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

    def _custom_route_allowed(self, method, path):
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return False
        if any(
            path == blocked or path.startswith(blocked + "/")
            for blocked in _CUSTOM_BLOCKED_EXACT_ROUTES
        ):
            return False
        return not any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in _CUSTOM_BLOCKED_ROUTE_PREFIXES
        )

    def plan(self, method, raw_target):
        normalized_method = str(method or "").upper()
        path, _query, canonical_target = _request_parts(raw_target)
        pid = self.problem_id
        allowed = False
        if self.task_kind == AGENT_TASK_SOLVE:
            if normalized_method == "GET":
                allowed = path in {
                    f"/api/problems/{pid}",
                    f"/api/problems/{pid}/submit-context",
                    "/me/classes",
                } or self._created_submission_allowed(path)
            elif normalized_method == "POST":
                allowed = path == f"/submit/{pid}"
        elif self.task_kind == AGENT_TASK_TESTDATA:
            if normalized_method == "GET":
                allowed = path in {
                    f"/api/problems/{pid}",
                    "/me/classes",
                }
        elif self.task_kind == AGENT_TASK_CUSTOM:
            allowed = self._custom_route_allowed(normalized_method, path)
        if not allowed:
            raise _RequestRejected(404, "not found")
        return _ForwardPlan(
            method=normalized_method,
            raw_target=canonical_target,
            path=path,
            target_url=self.upstream_url + canonical_target,
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
        try:
            redirect_path, canonical_redirect_path = _canonical_request_path(
                parts.path or "/",
            )
        except _RequestRejected as exc:
            raise _RequestRejected(502, "unsafe upstream redirect path") from exc
        rewritten = urlunsplit(
            ("", "", canonical_redirect_path, parts.query, parts.fragment),
        )
        submitted = _SUBMIT_RE.fullmatch(plan.path) if plan.method == "POST" else None
        if submitted and (
            self.task_kind == AGENT_TASK_CUSTOM
            or int(submitted.group(1)) == self.problem_id
        ):
            match = _SUBMISSION_LOCATION_RE.fullmatch(redirect_path)
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
    def __init__(
        self,
        task_kind,
        problem_id,
        site_url,
        cookie_name,
        session_cookie,
        requested_by="",
        access_role=AGENT_ACCESS_ROLE_USER,
        session_id="",
        task_id="",
    ):
        upstream_url, _upstream_origin = _normalize_site_url(site_url)
        self.policy = _IdentityRelayPolicy(
            task_kind,
            problem_id,
            upstream_url,
            access_role=access_role,
        )
        capability_username = str(requested_by or "").strip()
        capability_session_id = str(session_id or "").strip()
        capability_task_id = str(task_id or "").strip()
        has_task_binding = bool(
            capability_username and capability_session_id and capability_task_id
        )
        self.cookie_name, self.session_cookie = _validate_identity(
            cookie_name,
            session_cookie,
            allow_empty=has_task_binding,
        )
        self.agent_identity_capability = (
            create_agent_identity_capability(
                capability_username,
                self.policy.access_role,
                session_id=capability_session_id,
                task_id=capability_task_id,
            )
            if capability_username
            else ""
        )
        # 此密钥只通过本轮 identity config 中的 relay URL userinfo 交给目标
        # 容器。现有 requests/curl 客户端会自动生成 Authorization header；
        # 同 bridge 的其他容器无法仅凭端口借用真实 Flask Session。
        self.relay_request_secret = secrets.token_urlsafe(_RELAY_SECRET_BYTES)
        self.relay_authorization = _relay_authorization(
            self.relay_request_secret,
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
                    # 身份门禁必须先于路径 policy、请求体读取和任何上游 I/O。
                    if not _relay_request_authorized(
                        self.headers,
                        relay.relay_authorization,
                    ):
                        raise _RequestRejected(404, "not found")
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
                        relay.agent_identity_capability,
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
                self._proxy()

            def do_PATCH(self):
                self._proxy()

            def do_DELETE(self):
                self._proxy()

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
        self.container_base_url = _relay_container_base_url(
            port,
            self.relay_request_secret,
        )
        thread.start()
        return self.container_base_url

    @property
    def created_submission_ids(self):
        return self.policy.created_submission_ids()

    @property
    def temporary_secrets(self):
        """返回可能被 CLI 输出的本轮凭据表示，供宿主统一脱敏。"""

        base_url = str(self.container_base_url or "")
        authorization = str(self.relay_authorization or "")
        secret = str(self.relay_request_secret or "")
        basic_payload = authorization.partition(" ")[2]
        userinfo = f"{_RELAY_AUTH_USERNAME}:{secret}" if secret else ""
        candidates = (
            # URL 必须排在其中所含的 secret 前，避免只替换密码后仍把带
            # userinfo 的代理地址保留在轨迹里。
            base_url,
            base_url.replace("/", r"\/") if base_url else "",
            authorization,
            basic_payload,
            userinfo,
            secret,
        )
        return tuple(dict.fromkeys(value for value in candidates if value))

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
            raise IdentityRelayCleanupError("NumOJ 身份代理未能彻底关闭")


@dataclass(frozen=True, slots=True)
class NumOJIdentityRelaySession:
    """调用方可读取代理地址及由该代理精确创建的提交编号。"""

    base_url: str = field(repr=False)
    _relay: _NumOJIdentityRelay = field(repr=False)

    @property
    def temporary_secrets(self):
        return self._relay.temporary_secrets

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
    requested_by="",
    access_role=AGENT_ACCESS_ROLE_USER,
    session_id="",
    task_id="",
):
    """启动任务级身份转发代理并返回容器可访问的 NumOJ base URL。

    调用方必须把真实 Session 留在宿主参数中，不能写入 Agent 工作区。返回的
    base URL 内只含短生命周期 relay 请求密钥，退出上下文后即失效。
    """

    relay_args = (
        task_kind,
        problem_id,
        site_url,
        cookie_name,
        session_cookie,
        requested_by,
        access_role,
    )
    if str(session_id or "").strip() or str(task_id or "").strip():
        relay = _NumOJIdentityRelay(
            *relay_args,
            session_id=session_id,
            task_id=task_id,
        )
    else:
        relay = _NumOJIdentityRelay(*relay_args)
    base_url = relay.start()
    session = NumOJIdentityRelaySession(base_url=base_url, _relay=relay)
    try:
        yield session
    finally:
        try:
            relay.close()
        except IdentityRelayCleanupError:
            raise
        except Exception as exc:
            raise IdentityRelayCleanupError("NumOJ 身份代理清理失败") from exc


__all__ = [
    "IdentityRelayCleanupError",
    "IdentityRelayError",
    "NumOJIdentityRelaySession",
    "run_numoj_identity_relay",
]
