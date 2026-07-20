import hashlib
import ipaddress
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, Response, g, request, session

from oj_modules.observability import web
from oj_modules.observability.context import (
    current_context,
    replace_context,
    reset_context,
)


def _request(*, remote_addr="127.0.0.1", forwarded_for="", headers=None):
    request_headers = dict(headers or {})
    if forwarded_for:
        request_headers["X-Forwarded-For"] = forwarded_for
    return SimpleNamespace(remote_addr=remote_addr, headers=request_headers)


def _make_app(*, trusted_proxy_cidrs=()):
    app = Flask(__name__)
    app.secret_key = "test-only-secret"
    app.config.update(TESTING=True)

    @app.get("/items/<item_id>")
    def item(item_id):
        return f"item:{item_id}"

    @app.get("/health/live")
    def health_live():
        return "ok"

    @app.get("/stream")
    def stream():
        return Response((part for part in (b"first", b"second")))

    @app.get("/boom")
    def boom():
        raise RuntimeError("request failed")

    web.install_flask_observability(
        app,
        trusted_proxy_cidrs=trusted_proxy_cidrs,
    )
    return app


def test_parse_trusted_proxy_cidrs_supports_ipv4_ipv6_and_normalizes_hosts():
    networks = web.parse_trusted_proxy_cidrs(
        [" 10.20.30.40/8 ", "2001:db8::42/32"],
    )

    assert networks == (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    assert isinstance(networks, tuple)
    assert web.parse_trusted_proxy_cidrs(()) == ()


def test_parse_trusted_proxy_cidrs_rejects_invalid_value():
    with pytest.raises(ValueError, match="无效的可信代理 CIDR"):
        web.parse_trusted_proxy_cidrs(["not-a-network"])


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0", "192.0.2.7/0"])
def test_parse_trusted_proxy_cidrs_rejects_global_network(cidr):
    with pytest.raises(ValueError, match="不得覆盖全部地址"):
        web.parse_trusted_proxy_cidrs([cidr])


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (" 192.0.2.7 ", ipaddress.ip_address("192.0.2.7")),
        ("2001:db8::7", ipaddress.ip_address("2001:db8::7")),
        (None, None),
        ("", None),
        ("invalid", None),
    ],
)
def test_parse_ip_handles_valid_and_invalid_inputs(value, expected):
    assert web._parse_ip(value) == expected


def test_is_trusted_supports_ipv4_ipv6_and_fails_closed():
    networks = web.parse_trusted_proxy_cidrs(["10.0.0.0/8", "2001:db8::/32"])

    assert web._is_trusted(ipaddress.ip_address("10.2.3.4"), networks) is True
    assert web._is_trusted(ipaddress.ip_address("2001:db8::1"), networks) is True
    assert web._is_trusted(ipaddress.ip_address("192.0.2.1"), networks) is False
    assert web._is_trusted(None, networks) is False
    assert web._is_trusted(ipaddress.ip_address("10.2.3.4"), ()) is False


def test_configured_networks_reads_extension_and_is_safe_without_app_context():
    assert web._configured_networks() == ()

    app = Flask(__name__)
    configured = web.parse_trusted_proxy_cidrs(["10.0.0.0/8"])
    app.extensions[web._EXTENSION_KEY] = {
        "trusted_proxy_networks": configured,
    }
    with app.app_context():
        assert web._configured_networks() == configured
        app.extensions[web._EXTENSION_KEY] = {}
        assert web._configured_networks() == ()


def test_client_source_ignores_spoofed_forwarded_for_by_default():
    source = web.client_source(
        _request(
            remote_addr="203.0.113.8",
            forwarded_for="198.51.100.77",
        ),
        trusted_proxy_networks=(),
    )

    assert source == {
        "ip": "203.0.113.8",
        "peer_ip": "203.0.113.8",
        "forwarded": False,
    }


def test_client_source_strips_trusted_multihop_proxies_from_the_right():
    networks = web.parse_trusted_proxy_cidrs(
        ["10.0.0.0/8", "2001:db8::/32"],
    )
    source = web.client_source(
        _request(
            remote_addr="10.0.0.2",
            forwarded_for="198.51.100.17, 2001:db8::9, 10.0.0.3",
        ),
        trusted_proxy_networks=networks,
    )

    assert source == {
        "ip": "198.51.100.17",
        "peer_ip": "10.0.0.2",
        "forwarded": True,
        "forwarded_valid": True,
        "forwarded_for": ["198.51.100.17", "2001:db8::9", "10.0.0.3"],
    }


def test_client_source_accepts_ipv6_proxy_and_selects_ipv6_client():
    networks = web.parse_trusted_proxy_cidrs(["2001:db8:ffff::/48"])

    source = web.client_source(
        _request(
            remote_addr="2001:db8:ffff::2",
            forwarded_for="2001:db8:1234::9",
        ),
        trusted_proxy_networks=networks,
    )

    assert source["ip"] == "2001:db8:1234::9"
    assert source["peer_ip"] == "2001:db8:ffff::2"
    assert source["forwarded"] is True


def test_client_source_invalid_forwarded_for_fails_safe_to_peer():
    networks = web.parse_trusted_proxy_cidrs(["10.0.0.0/8"])

    source = web.client_source(
        _request(
            remote_addr="10.0.0.2",
            forwarded_for="198.51.100.7, invalid",
        ),
        trusted_proxy_networks=networks,
    )

    assert source == {
        "ip": "10.0.0.2",
        "peer_ip": "10.0.0.2",
        "forwarded": False,
        "forwarded_valid": False,
    }


def test_client_source_all_trusted_uses_leftmost_and_invalid_peer_is_unknown():
    networks = web.parse_trusted_proxy_cidrs(["10.0.0.0/8"])

    all_trusted = web.client_source(
        _request(remote_addr="10.0.0.2", forwarded_for="10.1.1.1, 10.2.2.2"),
        trusted_proxy_networks=networks,
    )
    invalid_peer = web.client_source(
        _request(remote_addr="not-an-ip", forwarded_for="198.51.100.1"),
        trusted_proxy_networks=networks,
    )

    assert all_trusted["ip"] == "10.1.1.1"
    assert invalid_peer == {
        "ip": "unknown",
        "peer_ip": "unknown",
        "forwarded": False,
    }


def test_client_ip_uses_installed_proxy_configuration_and_unknown_fallback():
    app = Flask(__name__)
    web.install_flask_observability(app, trusted_proxy_cidrs=["10.0.0.0/8"])

    with app.app_context():
        assert web.client_ip(
            _request(remote_addr="10.0.0.2", forwarded_for="198.51.100.3"),
        ) == "198.51.100.3"
        assert web.client_ip(_request(remote_addr=None)) == "unknown"


def test_user_agent_metadata_truncates_user_agent_and_client_hints():
    metadata = web.user_agent_metadata(
        _request(
            headers={
                "User-Agent": "u" * 1_030,
                "Sec-CH-UA": "b" * 260,
                "Sec-CH-UA-Platform": "p" * 130,
                "Sec-CH-UA-Mobile": "m" * 34,
            },
        ),
    )

    assert metadata["original"] == "u" * 1_024 + "…<truncated:6>"
    assert metadata["client_hints"] == {
        "brands": "b" * 256 + "…<truncated:4>",
        "platform": "p" * 128 + "…<truncated:2>",
        "mobile": "m" * 32 + "…<truncated:2>",
    }
    assert web.user_agent_metadata(_request())["client_hints"] == {
        "brands": "",
        "platform": "",
        "mobile": "",
    }


def test_request_audit_fields_records_route_not_query_or_concrete_path():
    app = Flask(__name__)

    @app.get("/accounts/<account_id>")
    def account(account_id):
        return account_id

    with app.test_request_context(
        "/accounts/private-account?token=top-secret",
        headers={"User-Agent": "Example Browser"},
        environ_base={"REMOTE_ADDR": "192.0.2.9"},
    ):
        g.numoj_request_id = "request-123"
        fields = web.request_audit_fields(request)

    assert fields["request"] == {
        "id": "request-123",
        "method": "GET",
        "route": "/accounts/<account_id>",
        "endpoint": "account",
    }
    assert fields["source"]["ip"] == "192.0.2.9"
    assert fields["user_agent"]["original"] == "Example Browser"
    assert "private-account" not in repr(fields)
    assert "top-secret" not in repr(fields)


def test_unmatched_path_metadata_uses_utf8_length_and_digest_only():
    path = "/不存在/private"

    with patch.object(
        web,
        "content_fingerprint",
        wraps=web.content_fingerprint,
    ) as fingerprint:
        metadata = web._unmatched_path_metadata(path)

    encoded = path.encode("utf-8")
    fingerprint.assert_called_once_with(path)
    assert metadata == {
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    assert path not in repr(metadata)


def test_install_flask_observability_sets_request_id_and_logs_route_privately():
    app = _make_app()
    observed = []

    def capture_event(*args, **kwargs):
        observed.append((args, kwargs, current_context()))

    outer_token = replace_context(trace_id="outer-trace")
    try:
        with patch.object(web, "emit_event", side_effect=capture_event):
            response = app.test_client().get(
                "/items/private-value?token=top-secret",
                headers={"User-Agent": "Test Browser"},
            )

        assert current_context() == {"trace_id": "outer-trace"}
    finally:
        reset_context(outer_token)

    assert response.status_code == 200
    assert len(response.headers["X-Request-ID"]) == 32
    assert len(observed) == 1
    event_args, event_fields, event_context = observed[0]
    assert event_args == ("access.http",)
    assert event_fields["action"] == "request.completed"
    assert event_fields["outcome"] == "success"
    assert event_fields["level"] == 20
    assert event_fields["http"] == {
        "request": {"method": "GET"},
        "route": "/items/<item_id>",
        "response": {
            "status_code": 200,
            "body_bytes": len(b"item:private-value"),
            "streaming": False,
        },
    }
    assert event_context["request_id"] == response.headers["X-Request-ID"]
    assert event_context["trace_id"] == response.headers["X-Request-ID"]
    assert "private-value" not in repr(event_fields)
    assert "top-secret" not in repr(event_fields)


def test_finish_observed_request_hashes_404_path_and_marks_failure():
    app = _make_app()
    emitter = MagicMock()
    path = "/not-found/private-404-value"

    with patch.object(web, "emit_event", emitter):
        response = app.test_client().get(path)

    fields = emitter.call_args.kwargs
    assert response.status_code == 404
    assert fields["outcome"] == "failure"
    assert fields["level"] == 20
    assert fields["http"]["route"] is None
    assert fields["http"]["unmatched_path"] == web._unmatched_path_metadata(path)
    assert path not in repr(fields)


def test_finish_observed_request_marks_streaming_and_health_level():
    app = _make_app()
    emitter = MagicMock()
    client = app.test_client()

    with (
        patch.object(web, "emit_event", emitter),
        patch.object(
            web.logging.getLogger("numoj.access.http"),
            "isEnabledFor",
            return_value=True,
        ),
    ):
        stream_response = client.get("/stream", buffered=False)
        stream_fields = emitter.call_args.kwargs
        health_response = client.get("/health/live")
        health_fields = emitter.call_args.kwargs

    assert stream_response.status_code == 200
    assert stream_fields["http"]["response"]["streaming"] is True
    assert stream_fields["level"] == 20
    assert health_response.status_code == 200
    assert health_fields["http"]["route"] == "/health/live"
    assert health_fields["level"] == 10


def test_successful_health_request_skips_expensive_metadata_when_debug_disabled():
    app = _make_app()
    emitter = MagicMock()

    with (
        patch.object(web, "emit_event", emitter),
        patch.object(web.logging, "getLogger") as get_logger,
        patch.object(web, "client_source") as source,
        patch.object(web, "user_agent_metadata") as user_agent,
    ):
        get_logger.return_value.isEnabledFor.return_value = False
        response = app.test_client().get("/health/live")

    assert response.status_code == 200
    assert len(response.headers["X-Request-ID"]) == 32
    get_logger.assert_called_once_with("numoj.access.http")
    emitter.assert_not_called()
    source.assert_not_called()
    user_agent.assert_not_called()


def test_finish_request_does_not_generate_fallback_id_when_one_already_exists():
    app = _make_app()
    finish_hook = app.after_request_funcs[None][-1]

    with app.test_request_context("/items/1"):
        g.numoj_request_id = "existing-request-id"
        with (
            patch.object(web, "uuid4") as make_uuid,
            patch.object(web, "emit_event"),
        ):
            response = finish_hook(Response("ok"))

    assert response.headers["X-Request-ID"] == "existing-request-id"
    make_uuid.assert_not_called()


def test_request_context_is_restored_after_success_and_exception_without_leakage():
    app = _make_app()
    app.config.update(TESTING=False, PROPAGATE_EXCEPTIONS=False)
    contexts = []

    def capture_context(*_args, **_kwargs):
        contexts.append(current_context())

    outer_token = replace_context(trace_id="outer")
    try:
        client = app.test_client()
        with client.session_transaction() as stored_session:
            stored_session["username"] = "alice"
        with patch.object(web, "emit_event", side_effect=capture_context):
            assert client.get("/items/1").status_code == 200
            assert current_context() == {"trace_id": "outer"}
            with client.session_transaction() as stored_session:
                stored_session.pop("username")
            assert client.get("/boom").status_code == 500
            assert current_context() == {"trace_id": "outer"}
    finally:
        reset_context(outer_token)

    assert contexts[0]["username"] == "alice"
    assert "username" not in contexts[1]
    assert contexts[0]["request_id"] != contexts[1]["request_id"]


def test_clear_observed_request_swallows_reset_errors_and_clears_token():
    app = _make_app()
    clear_hook = app.teardown_request_funcs[None][-1]

    with app.test_request_context("/items/1"):
        g.numoj_context_token = object()
        with patch.object(web, "reset_context", side_effect=ValueError("bad token")):
            clear_hook()
        assert g.numoj_context_token is None


def test_install_flask_observability_is_idempotent():
    app = _make_app(trusted_proxy_cidrs=["10.0.0.0/8"])
    hook_counts = (
        len(app.before_request_funcs.get(None, ())),
        len(app.after_request_funcs.get(None, ())),
        len(app.teardown_request_funcs.get(None, ())),
    )
    configured = app.extensions[web._EXTENSION_KEY]

    web.install_flask_observability(
        app,
        trusted_proxy_cidrs=["this-would-be-invalid-if-reparsed"],
    )

    assert (
        len(app.before_request_funcs.get(None, ())),
        len(app.after_request_funcs.get(None, ())),
        len(app.teardown_request_funcs.get(None, ())),
    ) == hook_counts
    assert app.extensions[web._EXTENSION_KEY] is configured
