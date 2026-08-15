from __future__ import annotations

import socket

import pytest
import requests
from requests.adapters import HTTPAdapter

from oj_modules.agents import endpoint_egress
from oj_modules.agents import user_endpoints
from oj_modules.site_config import services as config_service


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/v1",
    "http://10.0.0.8/v1",
    "http://169.254.169.254/latest",
    "http://224.0.0.1/v1",
    "http://0.0.0.0/v1",
    "http://192.0.2.1/v1",
    "http://[::1]/v1",
    "http://[ff02::1]/v1",
    "http://[::]/v1",
])
def test_personal_endpoint_rejects_every_non_public_address_class(url):
    with pytest.raises(endpoint_egress.AgentEndpointEgressError):
        endpoint_egress.resolve_public_endpoint_url(url)


@pytest.mark.parametrize("host", [
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
    "api.service.internal",
    "printer.local",
])
def test_personal_endpoint_rejects_obvious_host_and_internal_names(
    monkeypatch,
    host,
):
    monkeypatch.setattr(
        endpoint_egress.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("内网名称不应进入 DNS 解析"),
    )

    with pytest.raises(endpoint_egress.AgentEndpointEgressError):
        endpoint_egress.resolve_public_endpoint_url(f"https://{host}/v1")


def test_dns_answer_set_is_rejected_if_any_address_is_not_public(monkeypatch):
    monkeypatch.setattr(
        endpoint_egress.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 443),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("10.72.190.121", 443),
            ),
        ],
    )

    with pytest.raises(endpoint_egress.AgentEndpointEgressError):
        endpoint_egress.resolve_public_endpoint_url(
            "https://api.example.test/v1"
        )


def test_public_dns_result_is_resolved_once_and_frozen(monkeypatch):
    calls = []

    def resolve(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", port),
            )
        ]

    monkeypatch.setattr(endpoint_egress.socket, "getaddrinfo", resolve)

    target = endpoint_egress.resolve_public_endpoint_url(
        "https://API.Example.Test:8443/v1"
    )

    assert calls == [(
        "api.example.test",
        8443,
        {
            "family": socket.AF_UNSPEC,
            "type": socket.SOCK_STREAM,
            "proto": socket.IPPROTO_TCP,
        },
    )]
    assert target.hostname == "api.example.test"
    assert target.port == 8443
    assert target.connect_ip == "93.184.216.34"


def test_pinned_https_transport_keeps_host_sni_and_certificate_name(
    monkeypatch,
):
    target = endpoint_egress.PinnedEndpointTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        explicit_port=False,
        connect_ip="93.184.216.34",
    )
    session = endpoint_egress.pinned_requests_session(target)
    assert session.verify is True
    assert session.trust_env is False
    adapter = session.get_adapter("https://api.example.test/v1")
    observed = {}

    def fake_send(self, request, **kwargs):
        observed.update(url=request.url, headers=dict(request.headers), kwargs=kwargs)
        return object()

    monkeypatch.setattr(HTTPAdapter, "send", fake_send)
    prepared = requests.Request(
        "POST",
        "https://api.example.test/v1/chat/completions",
    ).prepare()
    try:
        adapter.send(prepared, timeout=3)
        pool_options = adapter.poolmanager.connection_pool_kw
    finally:
        session.close()

    assert observed["url"] == (
        "https://93.184.216.34:443/v1/chat/completions"
    )
    assert observed["headers"]["Host"] == "api.example.test"
    assert pool_options["server_hostname"] == "api.example.test"
    assert pool_options["assert_hostname"] == "api.example.test"


def test_pinned_transport_refuses_redirect_to_another_origin():
    target = endpoint_egress.PinnedEndpointTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        explicit_port=False,
        connect_ip="93.184.216.34",
    )
    session = endpoint_egress.pinned_requests_session(target)
    adapter = session.get_adapter("https://evil.example/v1")
    prepared = requests.Request("POST", "https://evil.example/v1").prepare()
    try:
        with pytest.raises(endpoint_egress.AgentEndpointEgressError):
            adapter.send(prepared, timeout=3)
    finally:
        session.close()


def test_user_endpoint_probe_uses_the_pinned_request_transport(monkeypatch):
    from oj_modules.ai import endpoints as llm_endpoints

    target = endpoint_egress.PinnedEndpointTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        explicit_port=False,
        connect_ip="93.184.216.34",
    )
    observed = {}

    def probe(candidate, *, timeout, request_get, request_post):
        observed.update(
            candidate=candidate,
            timeout=timeout,
            get_session=request_get.__self__,
            session=request_post.__self__,
        )
        return {"passed": True, "message": "ok", "latency_ms": 1}

    monkeypatch.setattr(llm_endpoints, "test_endpoint_candidate", probe)
    candidate = {"base_url": "https://api.example.test/v1"}
    result = user_endpoints.test_user_agent_endpoint(
        candidate,
        egress_target=target,
    )

    assert result["passed"] is True
    assert observed["candidate"] is candidate
    assert observed["session"].trust_env is False
    assert observed["get_session"] is observed["session"]


def test_llm_probe_sends_through_injected_pinned_transport():
    from oj_modules.ai import endpoints as llm_endpoints

    calls = []

    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def json(self):
            return {
                "choices": [{"message": {"content": "OK"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            }

        def close(self):
            return None

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    result = llm_endpoints.test_endpoint_candidate(
        {
            "protocol": "openai",
            "category": "text",
            "base_url": "https://api.example.test/v1",
            "api_key": "secret",
            "model": "private-model",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        request_post=post,
    )

    assert result["passed"] is True
    assert calls[0][0] == "https://api.example.test/v1/chat/completions"
    assert calls[0][1]["stream"] is False


def test_user_endpoint_probe_rejects_unsafe_target_before_tester_or_write(
    monkeypatch,
):
    tester_called = []
    monkeypatch.setattr(
        user_endpoints,
        "resolve_public_endpoint_url",
        lambda _value: (_ for _ in ()).throw(
            endpoint_egress.AgentEndpointEgressError(
                "自有模型端点只能连接公网地址"
            )
        ),
    )

    with pytest.raises(
        config_service.DynamicConfigValidationError,
        match="只能连接公网地址",
    ):
        user_endpoints.test_user_agent_endpoint_payload(
            {
                "protocol": "openai",
                "category": "text",
                "name": "危险节点",
                "base_url": "http://127.0.0.1/v1",
                "api_key": "secret",
                "model": "private-model",
                "thinking_enabled": False,
                "thinking_format": "none",
            },
            user_id=7,
            tester=lambda *_args, **_kwargs: tester_called.append(True),
        )

    assert tester_called == []
