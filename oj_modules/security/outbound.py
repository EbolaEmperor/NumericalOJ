#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""不受信任 HTTP 目标的公网解析与固定连接原语。"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
from urllib.parse import urlsplit

from requests.adapters import BaseAdapter, HTTPAdapter
from requests.exceptions import InvalidURL
from requests.utils import select_proxy


_BLOCKED_HOSTS = frozenset({
    "host.docker.internal",
    "kubernetes.default.svc",
    "metadata.google.internal",
    "metadata.google.internal.",
    "localhost",
})
_BLOCKED_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".local",
    ".localhost",
)
_NAT64_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


class PublicOutboundTargetError(ValueError):
    """用户提供的出站目标不是可安全固定的公网 HTTP(S) 地址。"""


def _canonical_hostname(value):
    hostname = str(value or "").strip().rstrip(".")
    if not hostname or "%" in hostname:
        raise PublicOutboundTargetError("个人端点地址无效")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            return hostname.encode("idna").decode("ascii").lower()
        except (UnicodeError, ValueError):
            raise PublicOutboundTargetError("个人端点地址无效") from None
    return address.compressed.lower()


def _public_unicast_address(value):
    try:
        address = ipaddress.ip_address(str(value or "").split("%", 1)[0])
    except ValueError:
        return None
    if (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
        or getattr(address, "is_site_local", False)
        or address.is_unspecified
    ):
        return None
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None and _public_unicast_address(mapped) is None:
            return None
        six_to_four = address.sixtofour
        if six_to_four is not None and _public_unicast_address(six_to_four) is None:
            return None
        # Teredo 与 NAT64 会让 URL 中的 IPv6 字面量最终连接另一个 IPv4
        # 目标；为避免嵌入式私网地址绕过，个人端点不接受这些转换前缀。
        if address.teredo is not None or any(
            address in network for network in _NAT64_NETWORKS
        ):
            return None
    return address


@dataclass(frozen=True, slots=True)
class ResolvedPublicTarget:
    scheme: str
    hostname: str
    port: int
    connect_host: str
    authority: str


def resolve_public_http_target(value, *, resolver=None):
    """解析并固定公网目标；任一 DNS 答案不安全时整体拒绝。"""

    try:
        parts = urlsplit(str(value or "").strip())
        explicit_port = parts.port
    except (TypeError, ValueError):
        raise PublicOutboundTargetError("个人端点地址无效") from None
    scheme = str(parts.scheme or "").lower()
    if (
        scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
    ):
        raise PublicOutboundTargetError("个人端点地址无效")
    hostname = _canonical_hostname(parts.hostname)
    if hostname in _BLOCKED_HOSTS or hostname.endswith(_BLOCKED_SUFFIXES):
        raise PublicOutboundTargetError("个人端点只能连接公开可路由的地址")
    if explicit_port is not None and not 1 <= explicit_port <= 65535:
        raise PublicOutboundTargetError("个人端点地址无效")
    port = int(
        explicit_port if explicit_port is not None else (
            443 if scheme == "https" else 80
        )
    )

    literal = _public_unicast_address(hostname)
    addresses = []
    if literal is not None:
        addresses.append(literal)
    else:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            lookup = resolver or socket.getaddrinfo
            try:
                answers = lookup(
                    hostname,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            except (OSError, socket.gaierror):
                raise PublicOutboundTargetError(
                    "个人端点域名无法解析为可用的公网地址"
                ) from None
            for family, _socktype, _protocol, _canonname, sockaddr in answers:
                if family not in {socket.AF_INET, socket.AF_INET6} or not sockaddr:
                    continue
                address = _public_unicast_address(sockaddr[0])
                if address is None:
                    raise PublicOutboundTargetError(
                        "个人端点只能连接公开可路由的地址"
                    )
                if address not in addresses:
                    addresses.append(address)
        else:
            # IP 字面量能够解析但不是公网单播地址。
            raise PublicOutboundTargetError(
                "个人端点只能连接公开可路由的地址"
            )
    if not addresses:
        raise PublicOutboundTargetError(
            "个人端点域名无法解析为可用的公网地址"
        )

    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = rendered_host
    if explicit_port is not None:
        authority += f":{explicit_port}"
    return ResolvedPublicTarget(
        scheme=scheme,
        hostname=hostname,
        port=port,
        connect_host=addresses[0].compressed,
        authority=authority,
    )


class PinnedHTTPAdapter(HTTPAdapter):
    """连接已验证 IP，同时保留原始 HTTP Host、TLS SNI 与证书校验名。"""

    def __init__(self, target, *args, **kwargs):
        if not isinstance(target, ResolvedPublicTarget):
            raise TypeError("target 必须是 ResolvedPublicTarget")
        self.target = target
        super().__init__(*args, **kwargs)

    def _validate_request(self, request):
        try:
            parts = urlsplit(str(request.url or ""))
            port = int(parts.port or (443 if parts.scheme.lower() == "https" else 80))
            hostname = _canonical_hostname(parts.hostname)
        except (AttributeError, TypeError, ValueError, PublicOutboundTargetError):
            raise InvalidURL("个人端点请求目标发生变化", request=request) from None
        if (
            parts.scheme.lower() != self.target.scheme
            or hostname != self.target.hostname
            or port != self.target.port
        ):
            raise InvalidURL("个人端点请求目标发生变化", request=request)

    def get_connection_with_tls_context(
        self,
        request,
        verify,
        proxies=None,
        cert=None,
    ):
        self._validate_request(request)
        if select_proxy(request.url, proxies or {}):
            raise InvalidURL("个人端点不允许使用转发代理", request=request)
        try:
            host_params, pool_kwargs = self.build_connection_pool_key_attributes(
                request,
                verify,
                cert,
            )
        except ValueError as exc:
            raise InvalidURL(exc, request=request) from exc
        host_params.update({
            "host": self.target.connect_host,
            "port": self.target.port,
            "scheme": self.target.scheme,
        })
        if self.target.scheme == "https":
            pool_kwargs.update({
                "assert_hostname": self.target.hostname,
                "server_hostname": self.target.hostname,
            })
        return self.poolmanager.connection_from_host(
            **host_params,
            pool_kwargs=pool_kwargs,
        )

    def send(self, request, *args, **kwargs):
        self._validate_request(request)
        request.headers["Host"] = self.target.authority
        return super().send(request, *args, **kwargs)


class _RejectingHTTPAdapter(BaseAdapter):
    """拒绝专用 Session 意外发往另一个 HTTP 协议。"""

    def send(self, request, *args, **kwargs):
        raise InvalidURL("个人端点请求目标发生变化", request=request)

    def close(self):
        return None


def pinned_public_session(session, target):
    """把专用 requests Session 的目标协议固定到已验证地址。"""

    if not isinstance(target, ResolvedPublicTarget):
        raise TypeError("target 必须是 ResolvedPublicTarget")
    session.trust_env = False
    session.mount("http://", _RejectingHTTPAdapter())
    session.mount("https://", _RejectingHTTPAdapter())
    session.mount(f"{target.scheme}://", PinnedHTTPAdapter(target))
    return session


__all__ = [
    "PinnedHTTPAdapter",
    "PublicOutboundTargetError",
    "ResolvedPublicTarget",
    "pinned_public_session",
    "resolve_public_http_target",
]
