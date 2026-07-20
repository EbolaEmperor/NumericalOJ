"""Flask 请求日志、可信客户端地址与认证审计上下文。"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any, Iterable
from uuid import uuid4

from flask import current_app, g, request, session

from .context import replace_context, reset_context
from .events import content_fingerprint, emit_event, redact_text


_EXTENSION_KEY = "numericaloj_observability"
_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_trusted_proxy_cidrs(values: Iterable[str]) -> tuple[_Network, ...]:
    networks = []
    for value in values or ():
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError as exc:
            raise ValueError(f"无效的可信代理 CIDR: {value!r}") from exc
        if network.prefixlen == 0:
            raise ValueError(f"可信代理 CIDR 不得覆盖全部地址: {value!r}")
        networks.append(network)
    return tuple(networks)


def _parse_ip(value: Any):
    try:
        return ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None


def _is_trusted(address, networks) -> bool:
    return bool(address) and any(address in network for network in networks)


def _configured_networks() -> tuple[_Network, ...]:
    try:
        extension = current_app.extensions.get(_EXTENSION_KEY, {})
    except RuntimeError:
        return ()
    return tuple(extension.get("trusted_proxy_networks") or ())


def client_source(req=None, *, trusted_proxy_networks=None) -> dict[str, Any]:
    """解析来源地址；只有直连 peer 可信时才接受 X-Forwarded-For。"""
    req = req or request
    networks = (
        tuple(trusted_proxy_networks)
        if trusted_proxy_networks is not None
        else _configured_networks()
    )
    peer = _parse_ip(getattr(req, "remote_addr", None))
    result: dict[str, Any] = {
        "ip": str(peer) if peer else "unknown",
        "peer_ip": str(peer) if peer else "unknown",
        "forwarded": False,
    }
    forwarded_value = req.headers.get("X-Forwarded-For", "")
    if not forwarded_value or not _is_trusted(peer, networks):
        return result

    forwarded = [_parse_ip(item) for item in forwarded_value.split(",")]
    if not forwarded or any(address is None for address in forwarded):
        result["forwarded_valid"] = False
        return result

    chain = [*forwarded, peer]
    client = None
    for address in reversed(chain):
        if _is_trusted(address, networks):
            continue
        client = address
        break
    if client is None:
        client = forwarded[0]

    result.update({
        "ip": str(client),
        "forwarded": True,
        "forwarded_valid": True,
        "forwarded_for": [str(address) for address in forwarded],
    })
    return result


def client_ip(req=None) -> str:
    return str(client_source(req).get("ip") or "unknown")


def user_agent_metadata(req=None) -> dict[str, Any]:
    req = req or request
    return {
        "original": redact_text(req.headers.get("User-Agent", ""), max_chars=1_024),
        "client_hints": {
            "brands": redact_text(req.headers.get("Sec-CH-UA", ""), max_chars=256),
            "platform": redact_text(
                req.headers.get("Sec-CH-UA-Platform", ""),
                max_chars=128,
            ),
            "mobile": redact_text(
                req.headers.get("Sec-CH-UA-Mobile", ""),
                max_chars=32,
            ),
        },
    }


def request_audit_fields(req=None) -> dict[str, Any]:
    req = req or request
    request_id = getattr(g, "numoj_request_id", None)
    return {
        "request": {
            "id": request_id,
            "method": req.method,
            "route": str(req.url_rule) if req.url_rule is not None else None,
            "endpoint": req.endpoint,
        },
        "source": client_source(req),
        "user_agent": user_agent_metadata(req),
    }


def _unmatched_path_metadata(path: str) -> dict[str, Any]:
    fingerprint = content_fingerprint(path or "")
    return {
        "bytes": fingerprint["bytes"],
        "sha256": fingerprint["sha256"],
    }


def install_flask_observability(app, *, trusted_proxy_cidrs=()) -> None:
    """安装一次请求生命周期钩子；不记录请求体、查询串或任意请求头。"""
    if app.extensions.get(_EXTENSION_KEY):
        return
    networks = parse_trusted_proxy_cidrs(trusted_proxy_cidrs)
    app.extensions[_EXTENSION_KEY] = {"trusted_proxy_networks": networks}

    @app.before_request
    def _begin_observed_request():
        request_id = uuid4().hex
        g.numoj_request_id = request_id
        g.numoj_request_started = time.monotonic()
        g.numoj_context_token = replace_context(
            request_id=request_id,
            trace_id=request_id,
            username=session.get("username"),
        )

    @app.after_request
    def _finish_observed_request(response):
        request_id = getattr(g, "numoj_request_id", None)
        if not request_id:
            request_id = uuid4().hex
        response.headers.setdefault("X-Request-ID", request_id)
        route = str(request.url_rule) if request.url_rule is not None else None
        status_code = int(response.status_code)
        level = (
            logging.DEBUG
            if route in ("/health/live", "/health/ready") and status_code < 400
            else logging.INFO
        )
        if level == logging.DEBUG and not logging.getLogger(
            "numoj.access.http"
        ).isEnabledFor(logging.DEBUG):
            return response

        started = getattr(g, "numoj_request_started", None)
        duration_ms = (
            round((time.monotonic() - started) * 1000, 3)
            if started is not None
            else None
        )
        content_length = response.headers.get("Content-Length")
        try:
            response_bytes = int(content_length) if content_length is not None else None
        except (TypeError, ValueError):
            response_bytes = None
        http = {
            "request": {"method": request.method},
            "route": route,
            "response": {
                "status_code": status_code,
                "body_bytes": response_bytes,
                "streaming": bool(response.is_streamed),
            },
        }
        if route is None:
            http["unmatched_path"] = _unmatched_path_metadata(request.path)
        emit_event(
            "access.http",
            action="request.completed",
            outcome="success" if status_code < 400 else "failure",
            message="HTTP 请求已完成",
            level=level,
            http=http,
            source=client_source(request, trusted_proxy_networks=networks),
            user_agent=user_agent_metadata(request),
            duration={"milliseconds": duration_ms},
        )
        return response

    @app.teardown_request
    def _clear_observed_request(_error=None):
        token = getattr(g, "numoj_context_token", None)
        if token is not None:
            try:
                reset_context(token)
            except (LookupError, RuntimeError, ValueError):
                pass
            g.numoj_context_token = None
