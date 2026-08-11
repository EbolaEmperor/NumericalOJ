from email.message import Message
import io
from urllib.parse import urljoin

import pytest
import requests

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


def test_solve_policy_allows_query_but_rejects_absolute_form_and_unlisted_methods():
    policy = relay._IdentityRelayPolicy("solve", 3, "https://oj.example.test")

    assert policy.plan("GET", "/api/problems/3?extra=1").target_url == (
        "https://oj.example.test/api/problems/3?extra=1"
    )
    assert policy.plan("POST", "/submit/3?next=/").target_url == (
        "https://oj.example.test/submit/3?next=/"
    )
    for method, target, expected_status in (
        ("GET", "https://oj.example.test/api/problems/3", 400),
        ("GET", "//evil.example/api/problems/3", 400),
        ("DELETE", "/api/problems/3", 404),
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
    assert policy.plan("GET", "/api/problems/8?view=detail").target_url == (
        "http://127.0.0.1:2025/api/problems/8?view=detail"
    )
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


@pytest.mark.parametrize("access_role", ["user", "admin"])
def test_custom_policy_allows_same_origin_skill_routes_but_blocks_identity_and_agents(
    access_role,
):
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role=access_role,
    )

    for method, path in (
        ("GET", "/ask_ai_code_marks/7"),
        ("GET", "/submission_status/9"),
        ("GET", "/export_scores?class=C1"),
        ("POST", "/api/repository/file"),
        ("DELETE", "/api/repository/file/3"),
    ):
        assert policy.plan(method, path).target_url == (
            "http://127.0.0.1:2025" + path
        )

    for method, path in (
        ("POST", "/login"),
        ("POST", "/logout"),
        ("POST", "/send_code"),
        ("POST", "/change_password"),
        ("POST", "/admin/agent_tasks"),
        ("POST", "/admin/agent_run_cancel/task-1"),
        ("GET", "/api/admin/agent-tasks"),
    ):
        with pytest.raises(relay._RequestRejected) as exc_info:
            policy.plan(method, path)
        assert exc_info.value.status == 404

    with pytest.raises(relay._RequestRejected) as exc_info:
        policy.plan("POST", "/login/")
    assert exc_info.value.status == 400


def test_canonical_unicode_path_is_authorized_and_forwarded_in_one_representation():
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role="admin",
    )
    raw_target = "/api/admin/ai-detection/student/%E5%BC%A0%E4%B8%89?detail=1"

    plan = policy.plan("GET", raw_target)

    assert plan.path == "/api/admin/ai-detection/student/张三"
    assert plan.raw_target == raw_target
    assert plan.target_url == "http://127.0.0.1:2025" + raw_target


def test_safe_percent_escapes_are_normalized_before_authorization_and_forwarding():
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role="admin",
    )

    plan = policy.plan(
        "POST",
        "/api/student/%e5%bc%a0/%7etenant?detail=1",
    )

    assert plan.path == "/api/student/张/~tenant"
    assert plan.raw_target == "/api/student/%E5%BC%A0/~tenant?detail=1"
    assert plan.target_url == (
        "http://127.0.0.1:2025/api/student/%E5%BC%A0/~tenant?detail=1"
    )


def test_unicode_path_is_encoded_without_forcing_unicode_normalization():
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role="admin",
    )

    plan = policy.plan("GET", "/api/student/数学/e\u0301")

    assert plan.path == "/api/student/数学/e\u0301"
    assert plan.raw_target == "/api/student/%E6%95%B0%E5%AD%A6/e%CC%81"


@pytest.mark.parametrize(
    "raw_target",
    [
        "/%61dmin/agent_tasks",
        "/admin/%61gent_tasks",
    ],
)
def test_encoded_blocked_path_cannot_bypass_custom_policy(raw_target):
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role="admin",
    )

    with pytest.raises(relay._RequestRejected) as exc_info:
        policy.plan("POST", raw_target)

    assert exc_info.value.status == 404


@pytest.mark.parametrize(
    "raw_target",
    [
        "/admin/%2561gent_tasks",
        "/foo/%2Fadmin/agent_tasks",
        "/foo/%5Cadmin/agent_tasks",
        "/foo/%00admin/agent_tasks",
        "/foo/%2E%2E/admin/agent_tasks",
        "/foo/../admin/agent_tasks",
        "/foo/./admin/agent_tasks",
        "/foo//admin/agent_tasks",
        "///admin/agent_tasks",
        "/foo/",
        "/foo\\admin/agent_tasks",
        "/api/student/%GG",
        "/api/student/%E5%BC",
        "/api/student/%E5%BC%A0%",
    ],
)
def test_ambiguous_path_never_reaches_custom_policy(raw_target):
    policy = relay._IdentityRelayPolicy(
        "custom",
        None,
        "http://127.0.0.1:2025",
        access_role="admin",
    )

    with pytest.raises(relay._RequestRejected) as exc_info:
        policy.plan("POST", raw_target)

    assert exc_info.value.status == 400


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


def test_agent_identity_capability_replaces_forged_inbound_header():
    incoming = _headers(
        X_NumOJ_Agent_Identity="forged",
        Cookie="session=forged",
    )

    forwarded = relay._upstream_headers(
        incoming,
        "session",
        "real-session",
        "signed-capability",
    )

    lowered = {name.lower(): value for name, value in forwarded.items()}
    assert lowered["cookie"] == "session=real-session"
    assert lowered[relay.AGENT_IDENTITY_HEADER.lower()] == "signed-capability"
    assert "forged" not in repr(forwarded)


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


def test_relay_allows_cookieless_identity_only_with_task_binding():
    with pytest.raises(relay.IdentityRelayError):
        relay._NumOJIdentityRelay(
            "custom",
            None,
            "https://oj.example",
            "session",
            "",
            "admin",
            "admin",
        )

    instance = relay._NumOJIdentityRelay(
        "custom",
        None,
        "https://oj.example",
        "session",
        "",
        "admin",
        "admin",
        "session-1",
        "task-2",
    )
    forwarded = relay._upstream_headers(
        _headers(Accept="application/json"),
        instance.cookie_name,
        instance.session_cookie,
        instance.agent_identity_capability,
    )
    assert "Cookie" not in forwarded
    assert forwarded[relay.AGENT_IDENTITY_HEADER]


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


def test_relay_secret_is_unique_and_existing_cli_sends_authorization():
    first = relay._NumOJIdentityRelay(
        "solve",
        17,
        "http://127.0.0.1:2025",
        "session",
        "real-session-one",
    )
    second = relay._NumOJIdentityRelay(
        "solve",
        17,
        "http://127.0.0.1:2025",
        "session",
        "real-session-two",
    )
    assert first.relay_request_secret != second.relay_request_secret
    assert len(first.relay_request_secret) >= 40

    base_url = relay._relay_container_base_url(
        43123,
        first.relay_request_secret,
    )
    assert first.relay_request_secret in base_url
    assert first.session_cookie not in base_url
    request_url = urljoin(base_url + "/", "api/problems/17")
    prepared = requests.Request("GET", request_url).prepare()
    assert prepared.headers["Authorization"] == first.relay_authorization
    assert first.relay_request_secret not in prepared.headers["Authorization"]

    first.container_base_url = base_url
    basic_payload = first.relay_authorization.removeprefix("Basic ")
    userinfo = f"numoj-agent:{first.relay_request_secret}"
    assert first.temporary_secrets == (
        base_url,
        base_url.replace("/", r"\/"),
        first.relay_authorization,
        basic_payload,
        userinfo,
        first.relay_request_secret,
    )
    session = relay.NumOJIdentityRelaySession(base_url=base_url, _relay=first)
    assert session.temporary_secrets == first.temporary_secrets
    assert base_url not in repr(session)
    assert first.relay_request_secret not in repr(session)


def test_relay_authorization_gate_precedes_policy_and_body_read():
    instance = relay._NumOJIdentityRelay(
        "solve",
        17,
        "http://127.0.0.1:2025",
        "session",
        "real-session",
    )
    policy_calls = []
    original_plan = instance.policy.plan

    def counted_plan(method, raw_target):
        policy_calls.append((method, raw_target))
        return original_plan(method, raw_target)

    instance.policy.plan = counted_plan

    class FakeSocket:
        def __init__(self, payload):
            self.input = io.BytesIO(payload)
            self.output = bytearray()

        def makefile(self, mode, *_args, **_kwargs):
            assert mode == "rb"
            return self.input

        def sendall(self, payload):
            self.output.extend(payload)

    class FakeServer:
        pass

    def send(authorization_values=()):
        header_lines = b"".join(
            b"Authorization: " + value.encode("ascii") + b"\r\n"
            for value in authorization_values
        )
        request_socket = FakeSocket(
            b"POST /submit/17 HTTP/1.0\r\n"
            + header_lines
            + b"\r\n",
        )
        instance._handler_class()(
            request_socket,
            ("127.0.0.1", 12345),
            FakeServer(),
        )
        head, payload = bytes(request_socket.output).split(b"\r\n\r\n", 1)
        status = int(head.splitlines()[0].split()[1])
        return status, payload

    assert send() == (404, b"not found")
    assert send(("Basic wrong",)) == (404, b"not found")
    assert send(("Basic one", "Basic two"))[0] == 400
    assert policy_calls == []

    status, payload = send((instance.relay_authorization,))
    # 正确凭证通过 policy 后才因缺 Content-Length 被拒绝，证明身份门禁
    # 位于 policy 和请求体读取之前。
    assert status == 411
    assert payload == b"content length required"
    assert policy_calls == [("POST", "/submit/17")]
    assert instance.relay_request_secret.encode() not in payload


def test_relay_authorization_comparison_rejects_missing_wrong_and_duplicate():
    expected = relay._relay_authorization("A" * 43)

    assert relay._relay_request_authorized(_headers(), expected) is False
    assert relay._relay_request_authorized(
        _headers(Authorization="Basic wrong"),
        expected,
    ) is False
    assert relay._relay_request_authorized(
        _headers(Authorization=expected),
        expected,
    ) is True

    duplicate = Message()
    duplicate["Authorization"] = expected
    duplicate["Authorization"] = expected
    with pytest.raises(relay._RequestRejected) as exc_info:
        relay._relay_request_authorized(duplicate, expected)
    assert exc_info.value.status == 400


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
                "",
                "user",
            ),
        ),
        ("start",),
        ("close",),
    ]


def test_context_manager_classifies_relay_close_failure(monkeypatch):
    class FakeRelay:
        def __init__(self, *_args):
            pass

        def start(self):
            return "http://host.docker.internal:43123"

        def close(self):
            raise RuntimeError("thread still alive")

    monkeypatch.setattr(relay, "_NumOJIdentityRelay", FakeRelay)

    with pytest.raises(relay.IdentityRelayCleanupError, match="清理失败"):
        with relay.run_numoj_identity_relay(
            "custom",
            None,
            "http://host.docker.internal:2025",
            "session",
            "real-cookie",
            "admin",
            "user",
        ):
            pass
