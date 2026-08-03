from email.message import Message

import pytest

from oj_modules.tasks.agent import identity_relay as relay


def _headers(**values):
    headers = Message()
    for name, value in values.items():
        headers[name.replace("_", "-")] = str(value)
    return headers


def test_solve_policy_only_allows_current_problem_and_proxy_created_submissions():
    policy = relay._IdentityRelayPolicy(
        "solve",
        17,
        "http://host.docker.internal:2025",
    )

    assert policy.upstream_url == "http://127.0.0.1:2025"
    for path in (
        "/api/problems/17",
        "/api/problems/17/submit-context",
        "/me/classes",
    ):
        assert policy.plan("GET", path).target_url == (
            "http://127.0.0.1:2025" + path
        )
    submit = policy.plan("POST", "/submit/17")

    for path in (
        "/api/problems/18",
        "/api/problems",
        "/submit/18",
        "/api/admin/users?page=1",
        "/submission_status/91",
        "/submission_status_stream/91",
        "/api/submissions/91",
    ):
        with pytest.raises(relay._RequestRejected) as exc_info:
            policy.plan("GET" if not path.startswith("/submit/") else "POST", path)
        assert exc_info.value.status == 404

    location = policy.inspect_redirect(
        submit,
        302,
        _headers(Location="/submission_detail/91"),
    )
    assert location == "/submission_detail/91"
    assert policy.plan("GET", "/submission_status/91").path == (
        "/submission_status/91"
    )
    assert policy.plan("GET", "/submission_status_stream/91").path == (
        "/submission_status_stream/91"
    )
    assert policy.plan("GET", "/api/submissions/91").path == (
        "/api/submissions/91"
    )
    with pytest.raises(relay._RequestRejected):
        policy.plan("GET", "/api/submissions/92")


def test_solve_policy_rejects_query_absolute_form_and_unlisted_methods():
    policy = relay._IdentityRelayPolicy("solve", 3, "https://oj.example.test")

    for method, target, expected_status in (
        ("GET", "/api/problems/3?extra=1", 404),
        ("GET", "https://oj.example.test/api/problems/3", 400),
        ("GET", "//evil.example/api/problems/3", 400),
        ("DELETE", "/api/problems/3", 404),
        ("POST", "/submit/3?next=/", 404),
        ("GET", "/api/problems/3#fragment", 400),
    ):
        with pytest.raises(relay._RequestRejected) as exc_info:
            policy.plan(method, target)
        assert exc_info.value.status == expected_status


def test_testdata_policy_is_read_only_and_uses_user_skill_routes():
    policy = relay._IdentityRelayPolicy(
        "testdata",
        8,
        "http://127.0.0.1:2025",
    )

    assert policy.plan("GET", "/api/problems/8").path == "/api/problems/8"
    assert policy.plan("GET", "/me/classes").path == "/me/classes"
    for method, path in (
        ("GET", "/api/problems/8/submit-context"),
        ("GET", "/api/admin/users"),
        ("GET", "/api/admin/users?page=1"),
        ("GET", "/api/admin/users?page=2"),
        ("GET", "/api/admin/users?page=1&limit=1"),
        ("POST", "/admin/upload_testdata/8"),
        ("POST", "/submit/8"),
    ):
        with pytest.raises(relay._RequestRejected) as exc_info:
            policy.plan(method, path)
        assert exc_info.value.status == 404


def test_incoming_credentials_and_forwarding_claims_are_replaced():
    incoming = _headers(
        Cookie="session=workspace-placeholder; attacker=1",
        Authorization="Bearer attacker",
        Proxy_Authorization="Basic attacker",
        X_Api_Key="attacker",
        X_Forwarded_For="203.0.113.8",
        Host="evil.example",
        Content_Length="123",
        Content_Type="application/x-www-form-urlencoded",
        Accept="application/json",
    )

    forwarded = relay._upstream_headers(
        incoming,
        "numoj_session",
        "real-session-value",
    )

    lowered = {name.lower(): value for name, value in forwarded.items()}
    assert lowered == {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "cookie": "numoj_session=real-session-value",
    }
    assert "workspace-placeholder" not in repr(forwarded)


def test_response_headers_never_return_session_updates_to_agent():
    upstream = _headers(
        Set_Cookie="numoj_session=refreshed; HttpOnly",
        Server="secret-upstream",
        Content_Length="12",
        Content_Type="application/json",
        X_Request_Id="request-1",
        Location="https://ignored.example",
    )

    assert relay._response_headers(upstream, "/submission_detail/7") == [
        ("Content-Type", "application/json"),
        ("X-Request-Id", "request-1"),
        ("Location", "/submission_detail/7"),
    ]


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/submission_detail/91",
        "//evil.example/submission_detail/91",
        "https://user:password@oj.example.test/submission_detail/91",
        "javascript:alert(1)",
        "/submission_detail/91\\@evil.example",
        "////evil.example/submission_detail/91",
    ],
)
def test_redirect_to_another_origin_or_ambiguous_location_is_refused(location):
    policy = relay._IdentityRelayPolicy("solve", 17, "https://oj.example.test")
    plan = policy.plan("POST", "/submit/17")

    with pytest.raises(relay._RequestRejected) as exc_info:
        policy.inspect_redirect(plan, 302, _headers(Location=location))

    assert exc_info.value.status == 502
    with pytest.raises(relay._RequestRejected):
        policy.plan("GET", "/submission_status/91")


def test_same_origin_absolute_redirect_is_rewritten_and_records_submission():
    policy = relay._IdentityRelayPolicy("solve", 17, "https://oj.example.test")
    plan = policy.plan("POST", "/submit/17")

    rewritten = policy.inspect_redirect(
        plan,
        303,
        _headers(Location="https://oj.example.test/submission_detail/44"),
    )

    assert rewritten == "/submission_detail/44"
    assert policy.plan("GET", "/api/submissions/44").path == (
        "/api/submissions/44"
    )


def test_request_and_response_size_limits_fail_closed():
    with pytest.raises(relay._RequestRejected) as exc_info:
        relay._request_content_length(
            _headers(Content_Length=relay._MAX_REQUEST_BYTES + 1),
            "POST",
        )
    assert exc_info.value.status == 413

    with pytest.raises(relay._RequestRejected) as exc_info:
        relay._request_content_length(_headers(), "POST")
    assert exc_info.value.status == 411

    with pytest.raises(relay._RequestRejected) as exc_info:
        relay._response_content_length(
            _headers(Content_Length=relay._MAX_RESPONSE_BYTES + 1),
        )
    assert exc_info.value.status == 502


@pytest.mark.parametrize(
    ("site_url", "cookie_name", "cookie_value"),
    [
        ("file:///etc/passwd", "session", "value"),
        ("https://user:password@oj.example", "session", "value"),
        ("https://oj.example/prefix", "session", "value"),
        ("https://oj.example", "bad cookie", "value"),
        ("https://oj.example", "session", "line\nbreak"),
        ("https://oj.example", "session", "value; attacker=1"),
        ("https://oj.example", "session", "非 ASCII"),
    ],
)
def test_relay_configuration_rejects_unsafe_origin_or_cookie(
    site_url,
    cookie_name,
    cookie_value,
):
    with pytest.raises(relay.IdentityRelayError):
        relay._NumOJIdentityRelay(
            "solve",
            1,
            site_url,
            cookie_name,
            cookie_value,
        )


def test_relay_binds_loopback_on_docker_desktop(monkeypatch):
    monkeypatch.setattr(relay.platform, "system", lambda: "Darwin")

    assert relay._relay_bind_host() == "127.0.0.1"


def test_relay_binds_only_linux_docker_bridge_gateway(monkeypatch):
    monkeypatch.setattr(relay.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        relay.subprocess,
        "run",
        lambda *_args, **_kwargs: type("Result", (), {
            "returncode": 0,
            "stdout": "172.17.0.1\n",
        })(),
    )

    assert relay._relay_bind_host() == "172.17.0.1"


def test_relay_refuses_public_or_unresolved_linux_bind_address(monkeypatch):
    monkeypatch.setattr(relay.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        relay.subprocess,
        "run",
        lambda *_args, **_kwargs: type("Result", (), {
            "returncode": 0,
            "stdout": "8.8.8.8\n",
        })(),
    )

    with pytest.raises(relay.IdentityRelayError, match="私有地址"):
        relay._relay_bind_host()


def test_context_manager_always_closes_relay_without_creating_a_token(monkeypatch):
    calls = []

    class FakeRelay:
        def __init__(self, *args):
            calls.append(("init", args))

        def start(self):
            calls.append(("start",))
            return "http://host.docker.internal:43123"

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr(relay, "_NumOJIdentityRelay", FakeRelay)

    with pytest.raises(RuntimeError, match="stop"):
        with relay.run_numoj_identity_relay(
            "solve",
            5,
            "http://host.docker.internal:2025",
            "session",
            "real-cookie",
        ) as session:
            assert session.base_url == "http://host.docker.internal:43123"
            raise RuntimeError("stop")

    assert calls == [
        (
            "init",
            (
                "solve",
                5,
                "http://host.docker.internal:2025",
                "session",
                "real-cookie",
            ),
        ),
        ("start",),
        ("close",),
    ]
