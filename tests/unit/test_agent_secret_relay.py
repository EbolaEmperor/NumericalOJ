import io
from email.message import Message
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
        "https://llm.example/v1?target=other",
        "https://llm.example/v1?",
        "https://llm.example/v1#fragment",
        "https://llm.example/v1#",
        "https://llm.example/v1/",
        "https://llm.example/v1/../admin",
        "https://llm.example/v1/%61dmin",
        "https://llm.example/v1\\admin",
    ],
)
def test_upstream_base_url_is_strictly_frozen(base_url):
    with pytest.raises(relay.AgentSecretRelayError):
        relay._normalize_upstream_base_url(base_url)


def test_upstream_keeps_fixed_origin_and_base_path():
    upstream = relay._normalize_upstream_base_url(
        "https://LLM.example.test:8443/tenant/v1"
    )

    assert upstream.origin_url == "https://llm.example.test:8443"
    assert upstream.base_path == "/tenant/v1"
    assert upstream.container_base_path == "/tenant/v1"
    assert upstream.target_url("/tenant/v1/chat/completions?stream=1") == (
        "https://llm.example.test:8443/tenant/v1/chat/completions?stream=1"
    )
    assert relay._path_within_base("/tenant/v1", upstream.base_path)
    assert relay._path_within_base(
        "/tenant/v1/chat/completions",
        upstream.base_path,
    )
    assert not relay._path_within_base("/tenant/v10", upstream.base_path)
    assert not relay._path_within_base("/other", upstream.base_path)


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
    assert relay._route_allowed("mcp", "POST", "/mcp", [], "/mcp")
    assert relay._route_allowed("mcp", "DELETE", "/mcp", [], "/mcp")
    assert not relay._route_allowed(
        "mcp", "POST", "/mcp/admin", [], "/mcp"
    )
    assert not relay._route_allowed(
        "mcp", "POST", "/mcp", [("target", "admin")], "/mcp"
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
            response.registered = True
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
        upstream_base_url="https://llm.example/tenant/v1",
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
        b"POST /tenant/v1/chat/completions HTTP/1.0\r\n"
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
        b"POST /tenant/v1/chat/completions HTTP/1.0\r\n"
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
        "target": "/tenant/v1/chat/completions",
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
