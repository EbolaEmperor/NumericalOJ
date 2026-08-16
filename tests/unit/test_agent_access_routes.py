from __future__ import annotations

from flask import Flask

from oj_modules.routes import agent_access_routes as routes
from oj_modules.security import auth


def _app(monkeypatch, user, *, concurrency_runtime_applier=None):
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(
        routes.create_agent_access_blueprint(
            endpoint_tester=lambda _candidate, **_kwargs: {
                "passed": True,
                "message": "ok",
                "latency_ms": 1,
            },
            concurrency_runtime_applier=concurrency_runtime_applier,
        )
    )
    monkeypatch.setattr(auth, "current_user", lambda: user)
    monkeypatch.setattr(routes, "current_user", lambda: user)
    return app


def test_quota_and_price_apis_use_public_agent_paths(monkeypatch):
    app = _app(monkeypatch, {"id": 7, "username": "alice", "is_admin": 0})
    monkeypatch.setattr(
        routes.quota,
        "get_agent_quota_summary",
        lambda user_id, **_kwargs: {
            "user_id": user_id,
            "total_amount": "2",
            "used_amount": "0.75",
            "remaining_amount": "1.25",
            "public_enabled": True,
        },
    )
    monkeypatch.setattr(
        routes.config_service,
        "list_llm_endpoints",
        lambda **_kwargs: [
            {
                "id": 3,
                "model": "model-a",
                "protocol": "anthropic",
                "category": "text",
                "api_key_configured": True,
                "input_price_per_million": "1",
                "cached_input_price_per_million": "0.25",
                "output_price_per_million": "4.5",
            }
        ],
    )

    client = app.test_client()
    quota_payload = client.get("/api/agent/quota").get_json()
    prices_payload = client.get("/api/agent/endpoints/prices").get_json()

    assert quota_payload["summary"]["remaining_amount"] == "1.25"
    assert prices_payload["endpoints"] == [
        {
            "id": 3,
            "model": "model-a",
            "protocol": "anthropic",
            "input_price_per_million": "1",
            "cached_input_price_per_million": "0.25",
            "output_price_per_million": "4.5",
        }
    ]


def test_admin_pending_payload_includes_class_user_ids(monkeypatch):
    app = _app(monkeypatch, {"id": 1, "username": "admin", "is_admin": 1})
    monkeypatch.setattr(
        routes.quota,
        "list_pending_agent_quota_requests",
        lambda reviewer_id: [{"id": 9, "username": "alice"}],
    )
    monkeypatch.setattr(
        routes.quota,
        "list_agent_quota_grant_classes",
        lambda: [{"class_en": "math", "label": "数学班", "user_ids": [7, 8]}],
    )

    payload = app.test_client().get(
        "/api/agent/quota/requests/pending"
    ).get_json()

    assert payload["requests"][0]["id"] == 9
    assert payload["classes"][0]["user_ids"] == [7, 8]


def test_quota_request_only_submits_reason_and_ignores_legacy_amount(monkeypatch):
    app = _app(monkeypatch, {"id": 7, "username": "alice", "is_admin": 0})
    seen = []
    monkeypatch.setattr(
        routes.quota,
        "create_agent_quota_request",
        lambda user_id, reason: seen.append((user_id, reason)) or {"id": 9},
    )
    monkeypatch.setattr(
        routes.quota,
        "get_agent_quota_summary",
        lambda user_id: {"user_id": user_id},
    )

    response = app.test_client().post(
        "/api/agent/quota/requests",
        json={"requested_amount": "999", "reason": "课程项目"},
    )

    assert response.status_code == 201
    assert seen == [(7, "课程项目")]


def test_personal_endpoint_mutations_are_scoped_to_logged_in_user(monkeypatch):
    app = _app(monkeypatch, {"id": 7, "username": "alice", "is_admin": 0})
    seen = []

    def save(payload, *, user_id, test_token, endpoint_id=None):
        seen.append((payload, user_id, endpoint_id, test_token))
        return {"id": endpoint_id or 12, "name": payload["name"]}

    monkeypatch.setattr(routes.user_endpoints, "save_user_agent_endpoint", save)
    client = app.test_client()
    created = client.post(
        "/api/agent/endpoints",
        json={"name": "自己的节点", "test_token": "create-token"},
    )
    updated = client.put(
        "/api/agent/endpoints/12",
        json={"name": "改名后的节点", "test_token": "update-token"},
    )

    assert created.status_code == 201
    assert updated.status_code == 200
    assert [(item[1], item[2]) for item in seen] == [(7, None), (7, 12)]
    assert [item[3] for item in seen] == ["create-token", "update-token"]


def test_personal_endpoint_test_uses_same_user_scoped_payload(monkeypatch):
    app = _app(monkeypatch, {"id": 7, "username": "alice", "is_admin": 0})
    seen = []

    def test_payload(payload, *, user_id, endpoint_id, tester):
        seen.append((payload, user_id, endpoint_id, tester))
        return {
            "passed": True,
            "status": "passed",
            "message": "测试通过",
            "latency_ms": 12,
            "test_token": "test-token",
            "expires_in_seconds": 600,
        }

    monkeypatch.setattr(
        routes.user_endpoints,
        "test_user_agent_endpoint_payload",
        test_payload,
    )
    response = app.test_client().post(
        "/api/agent/endpoints/test",
        json={
            "endpoint_id": 12,
            "protocol": "openai",
            "category": "text",
            "model": "private-model",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["test"] == {
        "passed": True,
        "status": "passed",
        "message": "测试通过",
        "latency_ms": 12,
    }
    assert response.get_json()["test_token"] == "test-token"
    assert response.get_json()["expires_in_seconds"] == 600
    assert seen[0][1:3] == (7, 12)
    assert seen[0][0]["category"] == "text"


def test_admin_can_read_and_update_agent_concurrency_limit(monkeypatch):
    saved = []
    applied = []
    monkeypatch.setattr(
        routes.runtime_settings,
        "get_agent_concurrency_limit",
        lambda: 8,
    )
    monkeypatch.setattr(
        routes.runtime_settings,
        "set_agent_concurrency_limit",
        lambda limit: saved.append(limit) or int(limit),
    )
    app = _app(
        monkeypatch,
        {"id": 1, "username": "admin", "is_admin": 1},
        concurrency_runtime_applier=lambda limit: applied.append(limit) or True,
    )
    client = app.test_client()

    read = client.get("/api/admin/dynamic-config/agent-concurrency")
    updated = client.put(
        "/api/admin/dynamic-config/agent-concurrency",
        json={"limit": 24},
    )

    assert read.status_code == 200
    assert read.get_json() == {"success": True, "limit": 8}
    assert updated.status_code == 200
    assert updated.get_json() == {
        "success": True,
        "limit": 24,
        "applied": True,
    }
    assert saved == [24]
    assert applied == [24]


def test_agent_concurrency_runtime_apply_failure_does_not_undo_saved_limit(
    monkeypatch,
):
    saved = []

    def fail_to_apply(_limit):
        raise RuntimeError("worker control unavailable")

    monkeypatch.setattr(
        routes.runtime_settings,
        "set_agent_concurrency_limit",
        lambda limit: saved.append(limit) or int(limit),
    )
    app = _app(
        monkeypatch,
        {"id": 1, "username": "admin", "is_admin": 1},
        concurrency_runtime_applier=fail_to_apply,
    )

    response = app.test_client().put(
        "/api/admin/dynamic-config/agent-concurrency",
        json={"limit": 32},
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "success": True,
        "limit": 32,
        "applied": False,
    }
    assert saved == [32]


def test_agent_concurrency_runtime_apply_requires_explicit_success(monkeypatch):
    applied = []
    monkeypatch.setattr(
        routes.runtime_settings,
        "set_agent_concurrency_limit",
        lambda limit: int(limit),
    )
    app = _app(
        monkeypatch,
        {"id": 1, "username": "admin", "is_admin": 1},
        concurrency_runtime_applier=lambda limit: applied.append(limit),
    )

    response = app.test_client().put(
        "/api/admin/dynamic-config/agent-concurrency",
        json={"limit": 16},
    )

    assert response.get_json()["applied"] is False
    assert applied == [16]


def test_agent_concurrency_runtime_applier_can_be_configured_after_blueprint_creation(
    monkeypatch,
):
    applied = []
    monkeypatch.setattr(
        routes.runtime_settings,
        "set_agent_concurrency_limit",
        lambda limit: int(limit),
    )
    routes.configure_agent_concurrency_runtime_applier(
        lambda limit: applied.append(limit) or True
    )
    try:
        app = _app(
            monkeypatch,
            {"id": 1, "username": "admin", "is_admin": 1},
        )
        response = app.test_client().put(
            "/api/admin/dynamic-config/agent-concurrency",
            json={"limit": 12},
        )
    finally:
        routes.configure_agent_concurrency_runtime_applier(None)

    assert response.get_json()["applied"] is True
    assert applied == [12]


def test_agent_concurrency_limit_validation_is_exposed_as_bad_request(monkeypatch):
    app = _app(
        monkeypatch,
        {"id": 1, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes.runtime_settings,
        "get_db_connection",
        lambda: (_ for _ in ()).throw(
            AssertionError("invalid value must not reach DB")
        ),
    )

    response = app.test_client().put(
        "/api/admin/dynamic-config/agent-concurrency",
        json={"limit": 101},
    )

    assert response.status_code == 400
    assert response.get_json()["code"] == "agent_runtime_settings_validation_error"
