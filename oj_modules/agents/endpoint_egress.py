#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""普通用户 Agent 模型端点的公网出站约束。"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import BaseAdapter, HTTPAdapter


_BLOCKED_HOSTS = frozenset({
    "docker.for.mac.host.internal",
    "docker.for.win.localhost",
    "gateway.docker.internal",
    "host.docker.internal",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes.docker.internal",
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
})
_BLOCKED_SUFFIXES = (".home.arpa", ".internal", ".local", ".localhost")


class AgentEndpointEgressError(ValueError):
    """用户端点不能安全地从宿主机访问。"""


def _normalized_ip(value):
    try:
        address = ipaddress.ip_address(str(value or "").split("%", 1)[0])
    except ValueError as exc:
        raise AgentEndpointEgressError("模型端点解析结果无效") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address


def _require_global_ip(value):
    address = _normalized_ip(value)
    # is_global 同时排除 loopback/private/link-local/multicast/unspecified、
    # 文档保留地址和共享地址；比逐个网段黑名单更不易漏掉新保留范围。
    if (
        not address.is_global
        or address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise AgentEndpointEgressError("自有模型端点只能连接公网地址")
    return str(address)


def _normalize_hostname(value):
    host = str(value or "").strip().lower().rstrip(".")
    if not host or "%" in host:
        raise AgentEndpointEgressError("模型端点主机名无效")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise AgentEndpointEgressError("模型端点主机名无效") from exc
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_SUFFIXES):
        raise AgentEndpointEgressError("自有模型端点不能连接宿主机或内网地址")
    return host


def resolve_public_host(host, port):
    """解析一次并冻结一个公网目标；任一答案非公网时整体拒绝。"""

    normalized_host = _normalize_hostname(host)
    try:
        return _require_global_ip(normalized_host)
    except AgentEndpointEgressError:
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError:
            pass
        else:
            raise

    try:
        answers = socket.getaddrinfo(
            normalized_host,
            int(port),
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, OverflowError, ValueError) as exc:
        raise AgentEndpointEgressError("无法解析自有模型端点") from exc

    addresses = []
    for family, _socktype, _protocol, _canonical_name, sockaddr in answers:
        if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
            continue
        address = _require_global_ip(sockaddr[0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise AgentEndpointEgressError("无法解析自有模型端点")
    return addresses[0]


@dataclass(frozen=True, slots=True)
class PinnedEndpointTarget:
    scheme: str
    hostname: str
    port: int
    explicit_port: bool
    connect_ip: str

    @property
    def host_header(self):
        rendered = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{rendered}:{self.port}" if self.explicit_port else rendered

    def pinned_url(self, value):
        try:
            parts = urlsplit(str(value or ""))
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        except ValueError as exc:
            raise AgentEndpointEgressError("模型端点请求地址无效") from exc
        if (
            parts.scheme.lower() != self.scheme
            or _normalize_hostname(parts.hostname) != self.hostname
            or int(port) != self.port
            or parts.username is not None
            or parts.password is not None
        ):
            raise AgentEndpointEgressError("模型端点请求越过了已冻结的公网目标")
        rendered_ip = (
            f"[{self.connect_ip}]" if ":" in self.connect_ip else self.connect_ip
        )
        return urlunsplit((
            self.scheme,
            f"{rendered_ip}:{self.port}",
            parts.path,
            parts.query,
            "",
        ))


def resolve_public_endpoint_url(value):
    raw = str(value or "").strip()
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise AgentEndpointEgressError("模型端点 Base URL 无效") from exc
    scheme = parts.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise AgentEndpointEgressError("模型端点 Base URL 必须是无凭据的 HTTP(S) 地址")
    hostname = _normalize_hostname(parts.hostname)
    use_port = int(port or (443 if scheme == "https" else 80))
    return PinnedEndpointTarget(
        scheme=scheme,
        hostname=hostname,
        port=use_port,
        explicit_port=port is not None,
        connect_ip=resolve_public_host(hostname, use_port),
    )


class _RejectingAdapter(BaseAdapter):
    def send(self, request, **_kwargs):
        del request
        raise requests.RequestException("模型端点请求越过了已冻结的公网目标")

    def close(self):
        return None


class _PinnedAddressAdapter(HTTPAdapter):
    def __init__(self, target, *args, **kwargs):
        self.target = target
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        if self.target.scheme == "https":
            # URL 会改写为固定 IP；显式保留原 hostname 作为 TLS SNI 和证书
            # 匹配目标，不能通过关闭证书校验来实现固定解析。
            pool_kwargs["server_hostname"] = self.target.hostname
            pool_kwargs["assert_hostname"] = self.target.hostname
        return super().init_poolmanager(
            connections,
            maxsize,
            block=block,
            **pool_kwargs,
        )

    def send(self, request, **kwargs):
        request.url = self.target.pinned_url(request.url)
        request.headers["Host"] = self.target.host_header
        return super().send(request, **kwargs)


def pinned_requests_session(target):
    """构造不读取代理环境、且只能连接冻结地址的 requests Session。"""

    session = requests.Session()
    session.trust_env = False
    session.mount("http://", _RejectingAdapter())
    session.mount("https://", _RejectingAdapter())
    session.mount(f"{target.scheme}://", _PinnedAddressAdapter(target))
    return session


__all__ = [
    "AgentEndpointEgressError",
    "PinnedEndpointTarget",
    "pinned_requests_session",
    "resolve_public_endpoint_url",
    "resolve_public_host",
]
