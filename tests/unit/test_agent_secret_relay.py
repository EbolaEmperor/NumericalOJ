import io
import http.client
from email.message import Message
import json
import socket
import threading
from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import secret_relay as relay


def _headers(**values):
    headers = Message()
    for name, value in values.items():
        headers[name.replace("_", "-")] = str(value)
    return headers


@pytest.mark.parametrize(
    "base_url",
    [
        "ftp://llm.example/v1",
        "https://user:secret@llm.example/v1",
        "https://llm.example/v1/../admin",
        "https://llm.example/v1\\admin",
    ],
)
def test_upstream_base_url_is_strictly_frozen(base_url):
    with pytest.raises(relay.AgentSecretRelayError):
        relay._normalize_upstream_base_url(base_url)


def test_upstream_keeps_fixed_origin_and_base_path():
    upstream = relay._normalize_upstream_base_url(
        "https://LLM.example.test:8443/tenant/v1/"
        "?api-version=2026-08-01#dashboard"
    )

    assert upstream.origin_url == "https://llm.example.test:8443"
    assert upstream.base_path == "/tenant/v1"
    assert upstream.base_query == "api-version=2026-08-01"
    assert upstream.container_base_path == "/tenant/v1"
    assert upstream.target_url("/tenant/v1/chat/completions?stream=1") == (
        "https://llm.example.test:8443/tenant/v1/chat/completions"
        "?api-version=2026-08-01&stream=1"
    )
    assert relay._path_within_base("/tenant/v1", upstream.base_path)
    assert relay._path_within_base(
        "/tenant/v1/chat/completions",
        upstream.base_path,
    )
    assert not relay._path_within_base("/tenant/v10", upstream.base_path)
    assert not relay._path_within_base("/other", upstream.base_path)


def test_upstream_normalizes_safe_percent_escapes():
    upstream = relay._normalize_upstream_base_url(
        "https://llm.example/v1/%61dmin/%7etenant",
    )

    assert upstream.base_path == "/v1/admin/~tenant"
    assert upstream.container_base_path == "/v1/admin/~tenant"


def test_mcp_upstream_preserves_exact_trailing_slash_and_safe_escapes():
    instance = relay._AgentSecretRelay(
        upstream_base_url=(
            "https://search.example.test/mcp/acme%20search/"
            "?tenant=math#dashboard"
        ),
        mode="mcp",
        real_credential="Bearer search-secret",
    )

    assert instance.upstream.base_path == "/mcp/acme search/"
    assert instance.upstream.base_query == "tenant=math"
    assert instance.upstream.container_base_path == "/mcp/acme%20search/"
    path, query, canonical_target = relay._request_parts(
        "/mcp/acme%20search/?session=1",
        allow_trailing_slash=True,
    )
    assert path == "/mcp/acme search/"
    assert query == "session=1"
    assert canonical_target == "/mcp/acme%20search/?session=1"
    assert relay._route_allowed(
        "mcp",
        "POST",
        path,
        query,
        instance.upstream.base_path,
    )


def test_real_credentials_must_have_unambiguous_ascii_header_encoding():
    with pytest.raises(relay.AgentSecretRelayError, match="长期凭据"):
        relay._AgentSecretRelay(
            upstream_base_url="https://llm.example/v1",
            mode="openai",
            real_credential="密钥",
        )


def test_local_container_alias_is_only_rewritten_for_host_upstream():
    upstream = relay._normalize_upstream_base_url(
        "http://host.docker.internal:9000/v1"
    )

    assert upstream.origin_url == "http://127.0.0.1:9000"
    assert upstream.container_base_path == "/v1"
    assert upstream.connect_host == ""


def test_personal_upstream_allows_private_target():
    upstream = relay._normalize_upstream_base_url(
        "http://127.0.0.1:9000/v1"
    )

    assert upstream.host == "127.0.0.1"
    assert upstream.connect_host == ""


def test_personal_upstream_keeps_hostname_for_runtime_resolution():
    upstream = relay._normalize_upstream_base_url(
        "https://API.Example.Test:8443/tenant/v1",
    )

    assert upstream.host == "api.example.test"
    assert upstream.connect_host == ""
    assert upstream.origin_url == "https://api.example.test:8443"


def test_pinned_https_connection_dials_ip_but_keeps_hostname_for_sni():
    calls = []

    class FakeSocket:
        def setsockopt(self, *args):
            calls.append(("sockopt", args))

    class FakeContext:
        def wrap_socket(self, upstream_socket, *, server_hostname):
            calls.append(("sni", server_hostname, upstream_socket))
            return FakeSocket()

    connection = relay._RelayHTTPSConnection(
        "api.example.test",
        443,
        timeout=3,
        context=FakeContext(),
        connect_host="93.184.216.34",
    )
    connection._create_connection = (
        lambda address, *_args, **_kwargs: (
            calls.append(("connect", address)) or FakeSocket()
        )
    )

    connection.connect()

    assert calls[0] == ("connect", ("93.184.216.34", 443))
    assert any(call[:2] == ("sni", "api.example.test") for call in calls)


def test_personal_endpoint_source_allows_private_runtime_target(monkeypatch):
    started = []

    def fake_start(instance):
        started.append(instance)
        with instance._state_lock:
            instance._active = True
        instance.container_base_url = "http://host.docker.internal:43100/v1"
        return instance.container_base_url

    monkeypatch.setattr(relay._AgentSecretRelay, "start", fake_start)

    with relay.run_agent_secret_relays({
        "source": "user",
        "protocol": "openai",
        "base_url": "http://127.0.0.1:9000/v1",
        "api_key": "private-key",
    }):
        pass

    assert started[0].upstream.host == "127.0.0.1"
    assert started[0].upstream.connect_host == ""


def test_each_relay_has_an_independent_high_entropy_temporary_credential():
    first = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    second = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="another-long-lived-key",
    )
    first_headers = _headers(
        Authorization=f"Bearer {first.temporary_secret}",
    )

    assert first.temporary_secret != second.temporary_secret
    assert len(first.temporary_secret) >= 40
    assert first._authorize_request(first_headers) is True
    assert second._authorize_request(first_headers) is False
    assert "long-lived-model-key" not in repr(first)


def test_composite_context_exposes_only_distinct_temporary_credentials(
    monkeypatch,
):
    started = []
    closed = []
    original_close = relay._AgentSecretRelay.close

    def fake_start(instance):
        started.append(instance)
        with instance._state_lock:
            instance._active = True
        instance.container_base_url = (
            f"http://host.docker.internal:{43100 + len(started)}"
            f"{instance.upstream.container_base_path}"
        )
        return instance.container_base_url

    def recorded_close(instance):
        closed.append(instance.mode)
        return original_close(instance)

    monkeypatch.setattr(relay._AgentSecretRelay, "start", fake_start)
    monkeypatch.setattr(relay._AgentSecretRelay, "close", recorded_close)

    with relay.run_agent_secret_relays(
        {
            "protocol": "openai",
            "base_url": "https://llm.example/v1",
            "api_key": "long-lived-model-key",
        },
        {
            "base_url": "https://search.example/mcp",
            "authorization": "Bearer long-lived-search-key",
        },
    ) as session:
        endpoint_temporary = session.endpoint_api_key
        search_temporary = session.web_search_authorization.removeprefix(
            "Bearer "
        )
        assert endpoint_temporary != search_temporary
        assert session.temporary_secrets == (
            endpoint_temporary,
            search_temporary,
        )
        rendered = repr(session)
        assert "long-lived-model-key" not in rendered
        assert "long-lived-search-key" not in rendered
        assert endpoint_temporary not in rendered
        assert search_temporary not in rendered

    assert closed == ["mcp", "openai"]
    assert all(instance.real_credential == "" for instance in started)
    assert all(instance.temporary_secret == "" for instance in started)


def test_expired_relay_never_accepts_another_request(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    temporary_secret = instance.temporary_secret
    headers = _headers(
        Authorization=f"Bearer {temporary_secret}",
    )
    with instance._state_lock:
        instance._active = True

    assert instance._authorize_request(headers) is True
    assert instance._claim_request() is True
    instance.close()
    # 即使攻击者保留了本轮 token，关闭后生命周期门禁仍 fail closed。
    assert instance._authorize_request(headers) is False
    assert instance._claim_request() is False
    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: SimpleNamespace(
            request=lambda *_args, **_kwargs: pytest.fail(
                "expired token reached upstream"
            )
        ),
    )
    authorization = f"Bearer {temporary_secret}".encode("ascii")
    assert _send(
        instance,
        b"GET /v1/models HTTP/1.0\r\nAuthorization: "
        + authorization
        + b"\r\n\r\n",
    )[0] == 404


def test_usage_stop_event_rejects_subsequent_endpoint_requests():
    stop_event = threading.Event()
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
        stop_event=stop_event,
    )
    with instance._state_lock:
        instance._active = True

    assert instance._claim_request() is True
    stop_event.set()
    assert instance._claim_request() is False


@pytest.mark.parametrize(
    ("mode", "route", "payload", "expected"),
    [
        (
            "openai",
            "/v1/chat/completions",
            b'{"usage":{"prompt_tokens":10,"prompt_tokens_details":'
            b'{"cached_tokens":3,"cache_write_tokens":2},'
            b'"completion_tokens":5,"completion_tokens_details":'
            b'{"reasoning_tokens":2}}}',
            (5, 3, 2, 5, 2),
        ),
        (
            "openai",
            "/v1/chat/completions",
            b'data: {"choices":[],"usage":{"prompt_tokens":8,'
            b'"prompt_cache_hit_tokens":3,"prompt_cache_miss_tokens":5,'
            b'"completion_tokens":2}}\n\ndata: [DONE]\n\n',
            (5, 3, 0, 2, 0),
        ),
        (
            "openai",
            "/v1/responses",
            b'{"usage":{"input_tokens":7,"input_tokens_details":'
            b'{"cached_tokens":2},"output_tokens":4,'
            b'"output_tokens_details":{"reasoning_tokens":1}}}',
            (5, 2, 0, 4, 1),
        ),
        (
            "openai",
            "/v1/responses",
            b'data: {"type":"response.completed","response":{"usage":'
            b'{"input_tokens":6,"output_tokens":3}}}\n\n',
            (6, 0, 0, 3, 0),
        ),
        (
            "openai",
            "/v1/responses/compact",
            b'{"object":"response.compaction","usage":'
            b'{"input_tokens":9,"output_tokens":1}}',
            (9, 0, 0, 1, 0),
        ),
        (
            "anthropic",
            "/v1/messages",
            b'{"usage":{"input_tokens":5,"cache_read_input_tokens":2,'
            b'"cache_creation_input_tokens":1,"output_tokens":4}}',
            (5, 2, 1, 4, 0),
        ),
        (
            "anthropic",
            "/v1/messages",
            b'data: {"type":"message_start","message":{"usage":'
            b'{"input_tokens":5,"cache_creation":{"ephemeral_5m_input_tokens":2},'
            b'"cache_read_input_tokens":1,"output_tokens":0}}}\n\n'
            b'data: {"type":"message_delta","usage":{"output_tokens":4}}\n\n'
            b'data: {"type":"message_stop"}\n\n',
            (5, 1, 2, 4, 0),
        ),
    ],
)
def test_extracts_authoritative_usage_from_supported_json_and_sse(
    mode,
    route,
    payload,
    expected,
):
    usage = relay._extract_response_usage(mode, route, payload)

    assert tuple(usage.values()) == expected


@pytest.mark.parametrize(
    ("mode", "route", "payload", "message"),
    [
        ("openai", "/v1/chat/completions", b'{"choices":[]}', "缺少 usage"),
        (
            "openai",
            "/v1/chat/completions",
            b'data: {"usage":{"prompt_tokens":1,"completion_tokens":1}}\n\n',
            "未完整结束",
        ),
        (
            "anthropic",
            "/v1/messages",
            b'{"usage":{"input_tokens":true,"output_tokens":1}}',
            "无效",
        ),
    ],
)
def test_response_usage_missing_truncated_or_invalid_fails_closed(
    mode,
    route,
    payload,
    message,
):
    with pytest.raises(relay.AgentSecretRelayUsageError, match=message):
        relay._extract_response_usage(mode, route, payload)


def test_anthropic_count_tokens_does_not_consume_generation_usage_gate():
    assert relay._route_requires_usage_ack(
        "anthropic",
        "/tenant/v1/messages/count_tokens",
        "/tenant/v1",
    ) is False
    assert relay._route_requires_usage_ack(
        "anthropic",
        "/tenant/v1/messages",
        "/tenant/v1",
    ) is True


def test_deny_new_requests_sets_shared_stop_event_and_closes_inflight():
    stop_event = threading.Event()
    closed = []
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
        stop_event=stop_event,
    )
    instance.server = SimpleNamespace(
        close_active_requests=lambda: closed.append("closed")
    )
    with instance._state_lock:
        instance._active = True

    instance.deny_new_requests()

    assert stop_event.is_set()
    assert instance._claim_request() is False
    assert closed == ["closed"]


def test_start_failure_forgets_real_and_temporary_credentials(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    monkeypatch.setattr(relay, "_relay_bind_host", lambda: "127.0.0.1")
    monkeypatch.setattr(
        relay,
        "_BoundedSecretRelayServer",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("bind failed")),
    )

    with pytest.raises(relay.AgentSecretRelayError, match="启动失败"):
        instance.start()

    assert instance.real_credential == ""
    assert instance.temporary_secret == ""
    assert instance._closed is True


@pytest.mark.parametrize("mode", ["openai", "mcp"])
def test_openai_and_mcp_reject_inbound_credential_override(mode):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://service.example/v1",
        mode=mode,
        real_credential="long-lived-secret",
    )
    expected = f"Bearer {instance.temporary_secret}"

    assert instance._authorize_request(
        _headers(Authorization=expected),
    ) is True
    assert instance._authorize_request(
        _headers(Authorization=expected, X_Api_Key="attacker-key"),
    ) is False
    assert instance._authorize_request(
        _headers(Authorization=expected, Cookie="session=attacker"),
    ) is False
    assert instance._authorize_request(
        _headers(Authorization="Bearer wrong"),
    ) is False


def test_anthropic_accepts_only_matching_temporary_standard_headers():
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://anthropic.example/v1",
        mode="anthropic",
        real_credential="long-lived-anthropic-key",
    )
    bearer = f"Bearer {instance.temporary_secret}"

    assert instance._authorize_request(
        _headers(X_Api_Key=instance.temporary_secret),
    ) is True
    assert instance._authorize_request(
        _headers(Authorization=bearer),
    ) is True
    assert instance._authorize_request(_headers(
        Authorization=bearer,
        X_Api_Key=instance.temporary_secret,
    )) is True
    assert instance._authorize_request(_headers(
        Authorization=bearer,
        X_Api_Key="other-relay-token",
    )) is False


def test_upstream_headers_strip_all_inbound_credentials_and_forwarding_metadata():
    incoming = _headers(
        Authorization="Bearer temporary",
        X_Api_Key="attacker",
        Cookie="session=attacker",
        X_Forwarded_Host="internal.example",
        X_HTTP_Method_Override="DELETE",
        X_Original_URL="/v1/files",
        OpenAI_Organization="attacker-organization",
        OpenAI_Project="attacker-project",
        Content_Type="application/json",
    )
    forwarded = relay._forward_headers(
        incoming,
        {"Authorization": "Bearer real-model-key"},
        "openai",
    )

    assert forwarded == {
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
        "Authorization": "Bearer real-model-key",
    }


def test_protocol_route_whitelists_expose_only_inference_or_exact_mcp_endpoint():
    assert relay._route_allowed(
        "openai", "POST", "/tenant/v1/chat/completions", [], "/tenant/v1"
    )
    assert relay._route_allowed(
        "openai", "POST", "/tenant/v1/responses", [], "/tenant/v1"
    )
    assert not relay._route_allowed(
        "openai", "POST", "/tenant/v1/files", [], "/tenant/v1"
    )
    assert not relay._route_allowed(
        "openai", "POST", "/tenant/v1/batches", [], "/tenant/v1"
    )
    assert not relay._route_allowed(
        "openai", "DELETE", "/tenant/v1/responses", [], "/tenant/v1"
    )
    assert relay._route_allowed(
        "openai",
        "POST",
        "/tenant/v1/chat/completions",
        [("beta", "true")],
        "/tenant/v1",
    )
    assert relay._route_allowed("mcp", "POST", "/mcp", [], "/mcp")
    assert relay._route_allowed("mcp", "DELETE", "/mcp", [], "/mcp")
    assert not relay._route_allowed(
        "mcp", "POST", "/mcp/admin", [], "/mcp"
    )
    assert relay._route_allowed(
        "mcp", "POST", "/mcp", [("target", "admin")], "/mcp"
    )


@pytest.mark.parametrize(
    "relative_path",
    [
        "/messages",
        "/messages/count_tokens",
        "/v1/messages",
        "/v1/messages/count_tokens",
    ],
)
def test_anthropic_message_routes_accept_provider_queries_without_expanding_path(
        relative_path):
    base_path = "/tenant/anthropic"
    path = base_path + relative_path

    assert relay._route_allowed(
        "anthropic", "POST", path, [("beta", "true")], base_path,
    )
    for provider_query in (
        [("beta", "false")],
        [("beta", "true"), ("extra", "value")],
        [("beta", "true"), ("beta", "true")],
    ):
        assert relay._route_allowed(
            "anthropic", "POST", path, provider_query, base_path,
        )

    assert not relay._route_allowed(
        "anthropic", "GET", path, [("beta", "true")], base_path,
    )
    assert not relay._route_allowed(
        "anthropic",
        "POST",
        base_path + "/models",
        [("beta", "true")],
        base_path,
    )


def test_streaming_response_redaction_handles_chunk_boundaries():
    secret = b"long-lived-secret-value"
    redactor = relay._StreamingRedactor((secret,))

    rendered = b"".join([
        redactor.feed(b"prefix long-lived-"),
        redactor.feed(b"secret-value suffix long-"),
        redactor.feed(b"lived-secret-value end"),
        redactor.feed(final=True),
    ])

    assert rendered == b"prefix [REDACTED] suffix [REDACTED] end"
    assert secret not in rendered


def test_response_headers_are_sanitized_and_sensitive_headers_removed():
    headers = _headers(
        X_Upstream_Debug="key=long-lived-secret",
        Set_Cookie="token=long-lived-secret",
        Location="https://evil.example/long-lived-secret",
        Content_Length="99",
    )

    assert relay._response_headers(
        headers,
        relay._redaction_secrets("long-lived-secret"),
    ) == [("X-Upstream-Debug", "key=[REDACTED]")]


def test_request_limits_are_fail_closed():
    with pytest.raises(relay._RequestRejected) as missing:
        relay._request_content_length(
            _headers(),
            "POST",
            relay._MAX_REQUEST_BYTES["openai"],
        )
    assert missing.value.status == 411

    with pytest.raises(relay._RequestRejected) as too_large:
        relay._request_content_length(
            _headers(
                Content_Length=relay._MAX_REQUEST_BYTES["openai"] + 1,
            ),
            "POST",
            relay._MAX_REQUEST_BYTES["openai"],
        )
    assert too_large.value.status == 413

    with pytest.raises(relay._RequestRejected) as response_too_large:
        relay._response_content_length({
            "Content-Length": str(relay._MAX_RESPONSE_BYTES + 1),
        })
    assert response_too_large.value.status == 502

    with pytest.raises(relay._RequestRejected) as encoded_response:
        relay._validate_response_content_encoding({
            "Content-Encoding": "gzip",
        })
    assert encoded_response.value.status == 502

    duplicate_encoding = Message()
    duplicate_encoding["Content-Encoding"] = "identity"
    duplicate_encoding["Content-Encoding"] = "gzip"
    with pytest.raises(relay._RequestRejected) as ambiguous_encoding:
        relay._validate_response_content_encoding(duplicate_encoding)
    assert ambiguous_encoding.value.status == 502


def test_total_inflight_request_body_budget_is_bounded():
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    with instance._state_lock:
        instance._active = True
    one_request = relay._MAX_REQUEST_BYTES["openai"]

    assert instance._reserve_request_body(one_request) is True
    assert instance._reserve_request_body(one_request) is True
    assert instance._reserve_request_body(1) is False
    instance._release_request_body(one_request)
    assert instance._reserve_request_body(1) is True


def test_forwarding_snapshot_keeps_injection_and_redaction_credentials_together():
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )

    upstream_headers, secret_values = instance._forwarding_snapshot()
    instance._forget_credentials()

    assert upstream_headers == {
        "Authorization": "Bearer long-lived-model-key",
    }
    assert b"long-lived-model-key" in secret_values
    assert instance.upstream_headers == {}
    assert instance.secret_values == ()


def test_close_reports_cleanup_error_when_a_handler_does_not_exit():
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    lifecycle = []

    class FakeServer:
        def close_active_requests(self):
            lifecycle.append("close-active")

        def shutdown(self):
            lifecycle.append("shutdown")

        def server_close(self):
            lifecycle.append("server-close")

        def wait_for_handlers(self, timeout):
            lifecycle.append(("wait-handlers", timeout))
            return False

    class FakeThread:
        def join(self, timeout):
            lifecycle.append(("join", timeout))

        def is_alive(self):
            return False

    instance.server = FakeServer()
    instance.thread = FakeThread()
    with instance._state_lock:
        instance._active = True

    with pytest.raises(
        relay.AgentSecretRelayCleanupError,
        match="未能彻底关闭",
    ):
        instance.close()

    assert lifecycle == [
        "close-active",
        "shutdown",
        "server-close",
        ("wait-handlers", relay._HANDLER_SHUTDOWN_TIMEOUT_SECONDS),
        ("join", relay._HANDLER_SHUTDOWN_TIMEOUT_SECONDS),
    ]
    assert instance.real_credential == ""
    assert instance.temporary_secret == ""


def test_interruptible_connection_shutdowns_saved_socket_before_close():
    events = []

    class FakeUpstreamSocket:
        def shutdown(self, how):
            events.append(("shutdown", how))

    class FakeConnection:
        def __init__(self):
            self.sock = FakeUpstreamSocket()

        def close(self):
            events.append(("close", None))

    connection = FakeConnection()
    handle = relay._InterruptibleHTTPConnection(connection)

    assert handle.remember_socket() is True
    # HTTPConnection.getresponse() 对 close-delimited 响应可能清空 sock，
    # 但 HTTPResponse.fp 仍持有同一个文件描述符。
    connection.sock = None
    handle.close()
    handle.close()

    assert events == [
        ("shutdown", socket.SHUT_RDWR),
        ("close", None),
    ]


def test_interruptible_connection_aborts_socket_created_after_close():
    events = []

    class FakeUpstreamSocket:
        def shutdown(self, how):
            events.append(("shutdown", how))
            raise OSError("already interrupted")

    class FakeConnection:
        sock = None

        def close(self):
            events.append(("close", None))

    connection = FakeConnection()
    handle = relay._InterruptibleHTTPConnection(connection)

    handle.close()
    late_socket = FakeUpstreamSocket()
    connection.sock = late_socket

    assert handle.remember_socket(late_socket) is False
    assert events == [
        ("close", None),
        ("shutdown", socket.SHUT_RDWR),
        ("close", None),
    ]


def test_lazy_connection_is_aborted_before_request_can_resume():
    events = []

    class FakeUpstreamSocket:
        def shutdown(self, how):
            events.append(("shutdown", how))

    class LazyConnectionBase:
        sock = None

        def connect(self):
            self.sock = FakeUpstreamSocket()
            events.append(("connected", None))

        def close(self):
            events.append(("close", None))

    class LazyConnection(relay._RelayConnectionMixin, LazyConnectionBase):
        pass

    connection = LazyConnection()
    handle = relay._InterruptibleHTTPConnection(connection)
    handle.close()

    with pytest.raises(OSError, match="relay is closing"):
        connection.connect()

    assert events == [
        ("close", None),
        ("connected", None),
        ("shutdown", socket.SHUT_RDWR),
        ("close", None),
    ]


def test_close_interrupts_a_handler_blocked_on_streaming_upstream(monkeypatch):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("127.0.0.1", 0))
    except PermissionError:
        listener.close()
        pytest.skip("当前测试沙箱禁止绑定 loopback 端口")
    listener.listen(1)
    listener.settimeout(5)
    upstream_port = listener.getsockname()[1]
    release_upstream = threading.Event()
    upstream_done = threading.Event()

    def serve_upstream():
        accepted = None
        try:
            accepted, _address = listener.accept()
            request = bytearray()
            while b"\r\n\r\n" not in request:
                chunk = accepted.recv(4096)
                if not chunk:
                    return
                request.extend(chunk)
            accepted.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"Connection: keep-alive\r\n\r\n"
            )
            release_upstream.wait(timeout=5)
        finally:
            if accepted is not None:
                accepted.close()
            listener.close()
            upstream_done.set()

    upstream_thread = threading.Thread(target=serve_upstream, daemon=True)
    upstream_thread.start()

    read_started = threading.Event()
    original_read_chunk = relay._read_response_chunk

    def observed_read_chunk(response, size=64 * 1024):
        read_started.set()
        return original_read_chunk(response, size)

    monkeypatch.setattr(relay, "_relay_bind_host", lambda: "127.0.0.1")
    monkeypatch.setattr(relay, "_read_response_chunk", observed_read_chunk)
    instance = relay._AgentSecretRelay(
        upstream_base_url=f"http://127.0.0.1:{upstream_port}/mcp",
        mode="mcp",
        real_credential="Bearer long-lived-search-key",
    )
    instance.start()
    relay_port = instance.server.server_address[1]
    client_done = threading.Event()

    def call_relay():
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            relay_port,
            timeout=5,
        )
        try:
            connection.request(
                "POST",
                "/mcp",
                body=b"{}",
                headers={
                    "Authorization": f"Bearer {instance.temporary_secret}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            try:
                response.read()
            except (OSError, http.client.HTTPException):
                pass
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
            client_done.set()

    client_thread = threading.Thread(target=call_relay, daemon=True)
    client_thread.start()
    try:
        assert read_started.wait(timeout=2)
        instance.close()
        assert client_done.wait(timeout=2)
        assert not instance.server._pending_handlers
    finally:
        release_upstream.set()
        upstream_done.wait(timeout=2)
        if not instance._closed:
            instance.close()
        client_thread.join(timeout=2)
        upstream_thread.join(timeout=2)
        assert not client_thread.is_alive()
        assert not upstream_thread.is_alive()


class _FakeSocket:
    def __init__(self, payload):
        self.input = io.BytesIO(payload)
        self.output = bytearray()

    def makefile(self, mode, *_args, **_kwargs):
        assert mode == "rb"
        return self.input

    def sendall(self, payload):
        self.output.extend(payload)


class _FakeServer:
    def __init__(self):
        self.upstreams = []

    def register_upstream(self, response):
        try:
            getattr(response, "connection", response).registered = True
        except Exception:
            pass
        self.upstreams.append(response)
        return True

    def unregister_upstream(self, response):
        self.upstreams.remove(response)


def _send(instance, raw_request):
    request_socket = _FakeSocket(raw_request)
    server = _FakeServer()
    instance._handler_class()(
        request_socket,
        ("127.0.0.1", 12345),
        server,
    )
    head, payload = bytes(request_socket.output).split(b"\r\n\r\n", 1)
    status = int(head.splitlines()[0].split()[1])
    return status, head, payload


def test_direct_endpoint_requests_are_accounted_by_relay_and_reopen_gate(
    monkeypatch,
):
    charged = []
    request_bodies = []
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
        require_usage_ack=True,
        usage_callback=lambda event: charged.append(event) or {
            "applied": True,
            "hard_stop": False,
        },
    )
    with instance._state_lock:
        instance._active = True

    class SuccessfulResponse:
        status = 200
        headers = _headers(Content_Type="text/event-stream")

        def __init__(self):
            self.chunks = [
                b'data: {"choices":[],"usage":{"prompt_tokens":8,',
                b'"prompt_tokens_details":{"cached_tokens":3},'
                b'"completion_tokens":2}}\n\ndata: [DONE]\n\n',
            ]

        def getcode(self):
            return self.status

        def read1(self, _size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            return None

    class SuccessfulConnection:
        registered = False

        def request(self, _method, _target, *, body, headers):
            assert self.registered is True
            request_bodies.append(body)

        def getresponse(self):
            return SuccessfulResponse()

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: SuccessfulConnection(),
    )
    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")
    body = b'{"stream":true}'
    request = (
        b"POST /v1/chat/completions HTTP/1.0\r\nAuthorization: "
        + authorization
        + b"\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )

    assert _send(instance, request)[0] == 200
    assert _send(instance, request)[0] == 200

    assert len(charged) == 2
    assert charged[0]["source"] == "relay_openai"
    assert charged[0]["id"] != charged[1]["id"]
    assert charged[0]["usage"] == {
        "input_uncached_tokens": 5,
        "input_cached_tokens": 3,
        "input_cache_write_tokens": 0,
        "output_tokens": 2,
        "reasoning_output_tokens": 0,
    }
    assert all(
        json.loads(payload)["stream_options"]["include_usage"] is True
        for payload in request_bodies
    )


@pytest.mark.parametrize(
    ("payload", "callback_result", "error_type", "message"),
    [
        (b'{"choices":[]}', None, relay.AgentSecretRelayUsageError, "缺少 usage"),
        (
            b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}',
            {"applied": False, "hard_stop": False},
            relay.AgentSecretRelayUsageError,
            "新的记账记录",
        ),
        (
            b'{"usage":{"prompt_tokens":1,"completion_tokens":1}}',
            {"applied": True, "hard_stop": True, "remaining_rmb": "-5.2"},
            relay.AgentSecretRelayUsageHardStopError,
            "-5.2",
        ),
    ],
)
def test_usage_failure_replay_or_hard_stop_closes_relay(
    monkeypatch,
    payload,
    callback_result,
    error_type,
    message,
):
    callback_calls = []
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
        require_usage_ack=True,
        usage_callback=lambda event: callback_calls.append(event) or callback_result,
    )
    with instance._state_lock:
        instance._active = True

    class Response:
        status = 200
        headers = _headers(Content_Type="application/json")

        def __init__(self):
            self.chunks = [payload]

        def getcode(self):
            return self.status

        def read1(self, _size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            return None

    class Connection:
        registered = False

        def request(self, *_args, **_kwargs):
            return None

        def getresponse(self):
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: Connection(),
    )
    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")
    request = (
        b"POST /v1/chat/completions HTTP/1.0\r\nAuthorization: "
        + authorization
        + b"\r\nContent-Length: 2\r\n\r\n{}"
    )

    assert _send(instance, request)[0] == 200
    with pytest.raises(error_type, match=message):
        instance.raise_if_usage_failed()
    assert instance._stop_event.is_set()
    assert _send(instance, request)[0] == 404
    assert len(callback_calls) == (0 if callback_result is None else 1)


def test_client_disconnect_still_drains_and_accounts_upstream(monkeypatch):
    charged = []
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="anthropic",
        real_credential="long-lived-model-key",
        require_usage_ack=True,
        usage_callback=lambda event: charged.append(event) or {
            "applied": True,
            "hard_stop": False,
        },
    )
    with instance._state_lock:
        instance._active = True

    class Response:
        status = 200
        headers = _headers(Content_Type="text/event-stream")

        def __init__(self):
            self.chunks = [
                b'data: {"type":"message_start","message":{"usage":'
                b'{"input_tokens":3,"output_tokens":0}}}\n\n',
                b'data: {"type":"message_delta","usage":{"output_tokens":2}}\n\n'
                b'data: {"type":"message_stop"}\n\n',
            ]
            self.read_count = 0

        def getcode(self):
            return self.status

        def read1(self, _size):
            self.read_count += 1
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            return None

    response = Response()

    class Connection:
        registered = False

        def request(self, *_args, **_kwargs):
            return None

        def getresponse(self):
            return response

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: Connection(),
    )

    class DisconnectSocket(_FakeSocket):
        def sendall(self, _payload):
            raise BrokenPipeError("client disconnected")

    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")
    request_socket = DisconnectSocket(
        b"POST /v1/messages HTTP/1.0\r\nX-Api-Key: "
        + authorization.removeprefix(b"Bearer ")
        + b"\r\nContent-Length: 2\r\n\r\n{}"
    )
    instance._handler_class()(
        request_socket,
        ("127.0.0.1", 12345),
        _FakeServer(),
    )

    assert response.read_count == 3
    assert len(charged) == 1
    assert charged[0]["usage"]["output_tokens"] == 2


def test_anthropic_count_tokens_is_forwarded_without_billing(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="anthropic",
        real_credential="long-lived-model-key",
        require_usage_ack=True,
        usage_callback=lambda _event: pytest.fail("count_tokens 不应记账"),
    )
    with instance._state_lock:
        instance._active = True

    class Response:
        status = 200
        headers = _headers(Content_Type="application/json")

        def __init__(self):
            self.chunks = [b'{"input_tokens":42}']

        def getcode(self):
            return self.status

        def read1(self, _size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            return None

    class Connection:
        registered = False

        def request(self, *_args, **_kwargs):
            return None

        def getresponse(self):
            return Response()

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: Connection(),
    )
    secret = instance.temporary_secret.encode("ascii")
    status, _head, payload = _send(
        instance,
        b"POST /v1/messages/count_tokens HTTP/1.0\r\nX-Api-Key: "
        + secret
        + b"\r\nContent-Length: 2\r\n\r\n{}",
    )

    assert status == 200
    assert payload == b'{"input_tokens":42}'
    instance.raise_if_usage_failed()


def test_temporary_gate_precedes_path_body_and_upstream(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    with instance._state_lock:
        instance._active = True
    path_calls = []
    real_request_parts = relay._request_parts

    def counted_request_parts(target):
        path_calls.append(target)
        return real_request_parts(target)

    monkeypatch.setattr(relay, "_request_parts", counted_request_parts)
    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: SimpleNamespace(
            request=lambda *_args, **_kwargs: pytest.fail(
                "unauthorized request reached upstream"
            )
        ),
    )

    assert _send(
        instance,
        b"POST /v1/chat/completions HTTP/1.0\r\n\r\n",
    )[0] == 404
    assert path_calls == []

    duplicate = (
        f"Authorization: Bearer {instance.temporary_secret}\r\n"
        f"Authorization: Bearer {instance.temporary_secret}\r\n"
    ).encode("ascii")
    assert _send(
        instance,
        b"POST /v1/chat/completions HTTP/1.0\r\n" + duplicate + b"\r\n",
    )[0] == 400
    assert path_calls == []


def test_proxy_injects_real_key_into_frozen_upstream_and_scrubs_response(
    monkeypatch,
):
    real_key = "long-lived-model-key"
    instance = relay._AgentSecretRelay(
        upstream_base_url=(
            "https://llm.example/tenant/v1/?api-version=2026-08-01"
        ),
        mode="openai",
        real_credential=real_key,
    )
    with instance._state_lock:
        instance._active = True
    captured = {}

    class FakeResponse:
        status = 200

        def __init__(self):
            self.headers = _headers(
                Content_Type="text/event-stream",
                X_Debug=f"credential={real_key}",
            )
            self.chunks = [
                b"data: long-lived-",
                b"model-key\n\n",
            ]

        def getcode(self):
            return self.status

        def read1(self, _size):
            return self.chunks.pop(0) if self.chunks else b""

        def close(self):
            return None

    class FakeConnection:
        registered = False

        def request(self, method, target, *, body, headers):
            assert self.registered is True
            captured["method"] = method
            captured["target"] = target
            captured["headers"] = {
                name.lower(): value for name, value in headers.items()
            }
            captured["body"] = body

        def getresponse(self):
            return FakeResponse()

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: FakeConnection(),
    )
    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")
    status, head, payload = _send(
        instance,
        b"POST /tenant/v1/chat/completions?stream=1&vendor-flag HTTP/1.0\r\n"
        + b"Authorization: " + authorization + b"\r\n"
        + b"X-Api-Key: attacker-override\r\n"
        + b"Content-Type: application/json\r\n"
        + b"Content-Length: 2\r\n\r\n{}",
    )
    # 额外来访凭据导致 fail closed，不能借正确 token 覆盖真实 key。
    assert status == 404
    assert captured == {}

    status, head, payload = _send(
        instance,
        b"POST /tenant/v1/chat/completions?stream=1&vendor-flag HTTP/1.0\r\n"
        + b"Authorization: " + authorization + b"\r\n"
        + b"Content-Type: application/json\r\n"
        + b"X-HTTP-Method-Override: DELETE\r\n"
        + b"X-Original-URL: /tenant/v1/files\r\n"
        + b"OpenAI-Organization: attacker\r\n"
        + b"OpenAI-Project: attacker\r\n"
        + b"Content-Length: 2\r\n\r\n{}",
    )

    assert status == 200
    assert captured == {
        "method": "POST",
        "target": (
            "/tenant/v1/chat/completions"
            "?api-version=2026-08-01&stream=1&vendor-flag"
        ),
        "headers": {
            "content-type": "application/json",
            "accept-encoding": "identity",
            "authorization": f"Bearer {real_key}",
        },
        "body": b"{}",
    }
    assert real_key.encode() not in head + payload
    assert b"X-Debug: credential=[REDACTED]" in head
    assert payload == b"data: [REDACTED]\n\n"


def test_proxy_rejects_path_outside_frozen_base_before_upstream(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/tenant/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    with instance._state_lock:
        instance._active = True
    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: SimpleNamespace(
            request=lambda *_args, **_kwargs: pytest.fail(
                "outside-base request reached upstream"
            )
        ),
    )
    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")

    status, _head, _payload = _send(
        instance,
        b"POST /other/files HTTP/1.0\r\nAuthorization: "
        + authorization
        + b"\r\n\r\n",
    )

    assert status == 404


def test_proxy_refuses_upstream_redirect(monkeypatch):
    instance = relay._AgentSecretRelay(
        upstream_base_url="https://llm.example/v1",
        mode="openai",
        real_credential="long-lived-model-key",
    )
    with instance._state_lock:
        instance._active = True

    class RedirectResponse:
        status = 307
        headers = _headers(Location="https://evil.example/steal")

        def getcode(self):
            return self.status

        def close(self):
            return None

    class RedirectConnection:
        registered = False

        def request(self, *_args, **_kwargs):
            assert self.registered is True

        def getresponse(self):
            return RedirectResponse()

        def close(self):
            return None

    monkeypatch.setattr(
        relay._FrozenUpstream,
        "open_connection",
        lambda _self: RedirectConnection(),
    )
    authorization = f"Bearer {instance.temporary_secret}".encode("ascii")

    status, _head, payload = _send(
        instance,
        b"POST /v1/chat/completions HTTP/1.0\r\nAuthorization: "
        + authorization
        + b"\r\nContent-Length: 2\r\n\r\n{}",
    )

    assert status == 502
    assert payload == b"upstream redirect refused"
