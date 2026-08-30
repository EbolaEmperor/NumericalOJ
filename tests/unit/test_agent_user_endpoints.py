from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from backend.oj_modules.agents import user_endpoints


def test_agent_user_endpoint_schema_and_source_columns_are_declared():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    endpoint = specs["agent_user_endpoints"]

    assert endpoint.columns["user_id"].lower() == "int not null"
    assert endpoint.columns["name"].lower() == "varchar(255) not null"
    assert endpoint.columns["api_key"].lower() == "text not null"
    assert endpoint.columns["category"].lower() == "varchar(16) not null default 'text'"
    assert endpoint.columns["context_window_tokens"].lower() == (
        "int not null default '384000'"
    )
    assert endpoint.columns["max_output_tokens"].lower() == (
        "int not null default '32000'"
    )
    for field in (
        "input_price_per_million",
        "cached_input_price_per_million",
        "output_price_per_million",
    ):
        assert field not in endpoint.columns
    assert "idx_agent_user_endpoints_user_model" in endpoint.indexes
    assert (
        specs["agent_sessions"].columns["endpoint_source"].lower()
        == "varchar(16) not null default 'global'"
    )
    assert (
        specs["agent_launch_preferences"].columns["endpoint_source"].lower()
        == "varchar(16) not null default 'global'"
    )
    assert (
        specs["llm_endpoints"].columns["input_price_per_million"].lower()
        == "decimal(20,8) not null"
    )


def test_personal_endpoint_normalization_preserves_category_without_prices():
    normalized = user_endpoints.normalize_user_agent_endpoint_payload({
        "protocol": "openai",
        "base_url": "https://example.test/v1",
        "api_key": "secret",
        "model": "private-model",
        "thinking_enabled": False,
        "thinking_format": "none",
        "category": "vision",
        "input_price_per_million": "1.25",
        "cached_input_price_per_million": "0.125",
        "output_price_per_million": "5",
    })

    assert normalized["name"] == "private-model"
    assert normalized["category"] == "vision"
    assert normalized["context_window_tokens"] == 384_000
    assert normalized["max_output_tokens"] == 32_000
    assert "input_price_per_million" not in normalized
    assert "cached_input_price_per_million" not in normalized
    assert "output_price_per_million" not in normalized


def test_personal_endpoint_public_view_hides_secret_and_has_stable_ref():
    row = {
        "id": 8,
        "user_id": 4,
        "name": "我的 Claude",
        "protocol": "anthropic",
        "category": "omni",
        "base_url": "https://example.test",
        "api_key": "secret",
        "model": "private-model",
        "thinking_enabled": 1,
        "thinking_format": "thinking_type",
        "revision": 3,
        "test_status": "passed",
    }

    public = user_endpoints._public_endpoint(row)
    private = user_endpoints._public_endpoint(row, include_secret=True)

    assert public["ref"] == "user:8"
    assert public["name"] == "我的 Claude"
    assert public["category"] == "omni"
    assert public["context_window_tokens"] == 384_000
    assert public["max_output_tokens"] == 32_000
    assert "input_price_per_million" not in public
    assert "cached_input_price_per_million" not in public
    assert "output_price_per_million" not in public
    assert public["metered"] is False
    assert public["api_key"] == ""
    assert public["api_key_configured"] is True
    assert private["api_key"] == "secret"


def test_personal_endpoint_test_issues_scoped_one_time_grant(monkeypatch):
    executed = []
    observed = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params):
            executed.append((" ".join(sql.split()), params))

    class Connection:
        def cursor(self):
            return Cursor()

        def commit(self):
            return None

        def rollback(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(user_endpoints, "get_db_connection", Connection)
    monkeypatch.setattr(
        user_endpoints.secrets,
        "token_urlsafe",
        lambda _length: "personal-test-token",
    )

    result = user_endpoints.test_user_agent_endpoint_payload(
        {
            "protocol": "openai",
            "category": "text",
            "base_url": "https://93.184.216.34/v1",
            "api_key": "secret",
            "model": "private-model",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        user_id=7,
        tester=lambda candidate, **_kwargs: (
            observed.append(candidate)
            or {
                "passed": True,
                "message": "ok",
                "latency_ms": 2,
                "upstream_context_window_tokens": 128_000,
                "upstream_max_output_tokens": 16_000,
            }
        ),
    )

    assert result["test_token"] == "personal-test-token"
    assert result["expires_in_seconds"] == 600
    assert observed[0]["category"] == "text"
    assert observed[0]["context_window_tokens"] == 384_000
    assert result["context_window_tokens"] == 128_000
    assert result["max_output_tokens"] == 16_000
    assert result["limits_adjusted"] is True
    assert "input_price_per_million" not in observed[0]
    assert "INSERT INTO dynamic_config_test_grants" in executed[0][0]
    assert executed[0][1][1] == user_endpoints.USER_ENDPOINT_TEST_GRANT_KIND
    expected = dict(observed[0], context_window_tokens=128_000, max_output_tokens=16_000)
    assert executed[0][1][4] == user_endpoints._candidate_fingerprint(expected)


def test_personal_endpoint_test_rejects_private_target_before_custom_tester():
    called = []

    with pytest.raises(
        user_endpoints.config_service.DynamicConfigValidationError,
        match="公开可路由",
    ):
        user_endpoints.test_user_agent_endpoint_payload(
            {
                "protocol": "openai",
                "category": "text",
                "base_url": "http://127.0.0.1:9000/v1",
                "api_key": "secret",
                "model": "private-model",
                "thinking_enabled": False,
                "thinking_format": "none",
            },
            user_id=7,
            tester=lambda *_args, **_kwargs: called.append(True),
        )

    assert called == []


def test_default_personal_endpoint_tester_pins_target_and_refuses_redirects(
        monkeypatch):
    from backend.oj_modules.ai import endpoints as ai_endpoints
    from backend.oj_modules.security import outbound

    target = outbound.ResolvedPublicTarget(
        scheme="https",
        hostname="api.example.test",
        port=443,
        connect_host="93.184.216.34",
        authority="api.example.test",
    )
    events = []

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, **kwargs):
            events.append(("post", url, kwargs))
            return object()

        def get(self, url, **kwargs):
            events.append(("get", url, kwargs))
            return object()

    monkeypatch.setattr(
        user_endpoints,
        "resolve_public_http_target",
        lambda _url: target,
    )
    monkeypatch.setattr(user_endpoints.requests, "Session", Session)
    monkeypatch.setattr(
        user_endpoints,
        "pinned_public_session",
        lambda session, resolved: (
            events.append(("pin", resolved.connect_host)) or session
        ),
    )

    def fake_test(candidate, *, request_post, request_get, **_kwargs):
        request_post("https://api.example.test/v1/chat/completions", json={})
        request_get("https://api.example.test/v1/models")
        return {"passed": True, "message": "ok", "latency_ms": 1}

    monkeypatch.setattr(ai_endpoints, "test_endpoint_candidate", fake_test)

    result = user_endpoints.test_user_agent_endpoint({
        "protocol": "openai",
        "category": "text",
        "base_url": "https://api.example.test/v1",
        "api_key": "secret",
        "model": "model",
    })

    assert result["passed"] is True
    assert events[0] == ("pin", "93.184.216.34")
    assert events[1][2]["allow_redirects"] is False
    assert events[2][2]["allow_redirects"] is False


def test_personal_endpoint_create_persists_category_without_prices(monkeypatch):
    executed = []
    payload = {
        "protocol": "openai",
        "category": "omni",
        "base_url": "https://93.184.216.34/v1",
        "api_key": "secret",
        "model": "private-model",
        "thinking_enabled": False,
        "thinking_format": "none",
    }
    candidate = user_endpoints.normalize_user_agent_endpoint_payload(payload)
    grant = {
        "id": 23,
        "config_kind": user_endpoints.USER_ENDPOINT_TEST_GRANT_KIND,
        "target_id": None,
        "base_revision": 0,
        "payload_fingerprint": user_endpoints._candidate_fingerprint(candidate),
        "created_by_user_id": 7,
        "status": "passed",
        "test_message": "ok",
        "test_latency_ms": 2,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(minutes=5),
        "consumed_at": None,
    }

    class Cursor:
        lastrowid = 19

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, sql, params):
            executed.append((" ".join(sql.split()), params))

        def fetchone(self):
            return grant

    class Connection:
        def cursor(self):
            return Cursor()

        def commit(self):
            return None

        def rollback(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(user_endpoints, "get_db_connection", Connection)
    monkeypatch.setattr(
        user_endpoints,
        "get_user_agent_endpoint",
        lambda endpoint_id, user_id: {"id": endpoint_id, "user_id": user_id},
    )

    saved = user_endpoints.save_user_agent_endpoint(
        payload,
        user_id=7,
        test_token="valid-token",
    )

    sql, params = executed[1]
    assert "protocol, category, base_url" in sql
    assert "context_window_tokens, max_output_tokens" in sql
    assert "input_price_per_million" not in sql
    assert params[3] == "omni"
    assert "UPDATE dynamic_config_test_grants SET consumed_at" in executed[2][0]
    assert saved == {"id": 19, "user_id": 7}


def test_personal_endpoint_save_rechecks_target_before_consuming_old_grant(
        monkeypatch):
    monkeypatch.setattr(
        user_endpoints,
        "get_db_connection",
        lambda: pytest.fail("私网目标不得进入 grant 消费事务"),
    )

    with pytest.raises(
        user_endpoints.config_service.DynamicConfigValidationError,
        match="公开可路由",
    ):
        user_endpoints.save_user_agent_endpoint(
            {
                "protocol": "openai",
                "category": "text",
                "base_url": "http://169.254.169.254/v1",
                "api_key": "secret",
                "model": "private-model",
                "thinking_enabled": False,
                "thinking_format": "none",
            },
            user_id=7,
            test_token="pre-upgrade-grant",
        )
