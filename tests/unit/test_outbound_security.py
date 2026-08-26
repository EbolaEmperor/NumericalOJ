import socket
from types import SimpleNamespace

import pytest
import requests

from oj_modules.security import outbound


def _answer(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/v1",
        "http://10.0.0.1/v1",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0/v1",
        "http://224.0.0.1/v1",
        "http://[::1]/v1",
        "http://[fc00::1]/v1",
        "http://[fe80::1]/v1",
        "http://[fec0::1]/v1",
        "https://[feff::1234]:8443/v1",
        "http://[::ffff:127.0.0.1]/v1",
        "http://[64:ff9b::7f00:1]/v1",
    ],
)
def test_public_target_rejects_non_public_ip_literals(url):
    with pytest.raises(
        outbound.PublicOutboundTargetError,
        match="公开可路由",
    ):
        outbound.resolve_public_http_target(url)


def test_public_target_rejects_mixed_public_and_private_dns_answers():
    answers = [
        _answer("93.184.216.34"),
        _answer("127.0.0.1"),
    ]

    with pytest.raises(
        outbound.PublicOutboundTargetError,
        match="公开可路由",
    ):
        outbound.resolve_public_http_target(
            "https://api.example.test/v1",
            resolver=lambda *_args, **_kwargs: answers,
        )


@pytest.mark.parametrize(
    "hostname",
    ["127.1", "0177.0.0.1", "0x7f000001", "2130706433"],
)
def test_public_target_rejects_legacy_numeric_loopback_representation(hostname):
    with pytest.raises(
        outbound.PublicOutboundTargetError,
        match="公开可路由",
    ):
        outbound.resolve_public_http_target(
            f"http://{hostname}/v1",
            resolver=lambda *_args, **_kwargs: [_answer("127.0.0.1")],
        )


@pytest.mark.parametrize(
    "hostname",
    [
        "localhost",
        "service.internal",
        "printer.local",
        "host.docker.internal",
        "metadata.google.internal",
    ],
)
def test_public_target_rejects_internal_hostnames_without_dns(hostname):
    def unexpected_resolver(*_args, **_kwargs):
        pytest.fail("内部主机名不应进入 DNS 解析")

    with pytest.raises(
        outbound.PublicOutboundTargetError,
        match="公开可路由",
    ):
        outbound.resolve_public_http_target(
            f"http://{hostname}/v1",
            resolver=unexpected_resolver,
        )


@pytest.mark.parametrize("answers", [[], None])
def test_public_target_fails_closed_when_dns_has_no_usable_answers(answers):
    def resolver(*_args, **_kwargs):
        if answers is None:
            raise socket.gaierror("lookup failed")
        return answers

    with pytest.raises(
        outbound.PublicOutboundTargetError,
        match="无法解析",
    ):
        outbound.resolve_public_http_target(
            "https://api.example.test/v1",
            resolver=resolver,
        )


@pytest.mark.parametrize(
    "url",
    ["http://example.test:0/v1", "http://[fe80::1%25en0]/v1"],
)
def test_public_target_rejects_invalid_port_and_scoped_ip(url):
    with pytest.raises(outbound.PublicOutboundTargetError, match="地址无效"):
        outbound.resolve_public_http_target(url)


def test_public_target_pins_one_address_only_after_all_answers_are_safe():
    target = outbound.resolve_public_http_target(
        "https://API.Example.Test:8443/tenant/v1",
        resolver=lambda *_args, **_kwargs: [
            _answer("93.184.216.34"),
            _answer("2606:2800:220:1:248:1893:25c8:1946"),
        ],
    )

    assert target == outbound.ResolvedPublicTarget(
        scheme="https",
        hostname="api.example.test",
        port=8443,
        connect_host="93.184.216.34",
        authority="api.example.test:8443",
    )


def test_pinned_adapter_dials_ip_but_preserves_host_sni_and_certificate_name(
        monkeypatch):
    target = outbound.ResolvedPublicTarget(
        scheme="https",
        hostname="api.example.test",
        port=8443,
        connect_host="93.184.216.34",
        authority="api.example.test:8443",
    )
    adapter = outbound.PinnedHTTPAdapter(target)
    prepared = requests.Request(
        "POST",
        "https://api.example.test:8443/v1/chat/completions",
    ).prepare()
    observed = {}

    def connection_from_host(**kwargs):
        observed.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(
        adapter.poolmanager,
        "connection_from_host",
        connection_from_host,
    )

    adapter.get_connection_with_tls_context(
        prepared,
        verify=True,
        proxies={},
        cert=None,
    )

    assert observed["host"] == "93.184.216.34"
    assert observed["port"] == 8443
    assert observed["scheme"] == "https"
    assert observed["pool_kwargs"]["assert_hostname"] == "api.example.test"
    assert observed["pool_kwargs"]["server_hostname"] == "api.example.test"


def test_pinned_adapter_rejects_changed_origin_and_proxy():
    target = outbound.ResolvedPublicTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        connect_host="93.184.216.34",
        authority="api.example.test",
    )
    adapter = outbound.PinnedHTTPAdapter(target)
    changed = requests.Request("POST", "https://other.example/v1").prepare()
    expected = requests.Request("POST", "https://api.example.test/v1").prepare()

    with pytest.raises(requests.exceptions.InvalidURL, match="目标发生变化"):
        adapter.get_connection_with_tls_context(
            changed,
            verify=True,
            proxies={},
            cert=None,
        )
    with pytest.raises(requests.exceptions.InvalidURL, match="转发代理"):
        adapter.get_connection_with_tls_context(
            expected,
            verify=True,
            proxies={"https": "http://proxy.example:3128"},
            cert=None,
        )


def test_pinned_session_disables_environment_proxies_and_sets_original_host(
        monkeypatch):
    target = outbound.ResolvedPublicTarget(
        scheme="http",
        hostname="api.example.test",
        port=8080,
        connect_host="93.184.216.34",
        authority="api.example.test:8080",
    )
    session = requests.Session()
    outbound.pinned_public_session(session, target)
    adapter = session.get_adapter("http://api.example.test:8080/v1")
    prepared = requests.Request(
        "POST",
        "http://api.example.test:8080/v1/chat/completions",
    ).prepare()

    def parent_send(_self, request, *args, **kwargs):
        return request

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", parent_send)
    sent = adapter.send(prepared)

    assert session.trust_env is False
    assert sent.headers["Host"] == "api.example.test:8080"


def test_pinned_session_rejects_the_other_http_scheme():
    target = outbound.ResolvedPublicTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        connect_host="93.184.216.34",
        authority="api.example.test",
    )
    session = requests.Session()
    outbound.pinned_public_session(session, target)
    prepared = requests.Request(
        "GET",
        "http://api.example.test/v1/models",
    ).prepare()

    with pytest.raises(requests.exceptions.InvalidURL, match="目标发生变化"):
        session.get_adapter(prepared.url).send(prepared)
