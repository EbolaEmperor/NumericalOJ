from __future__ import annotations

from flask import Flask

from oj_modules.routes import agent_access_routes as routes
from oj_modules.security import auth


def _app(monkeypatch, user):
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(
        routes.create_agent_access_blueprint(
            endpoint_tester=lambda _candidate: {
                "passed": True,
                "message": "ok",
                "latency_ms": 1,
            }
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


def test_personal_endpoint_mutations_are_scoped_to_logged_in_user(monkeypatch):
    app = _app(monkeypatch, {"id": 7, "username": "alice", "is_admin": 0})
    seen = []

    def save(payload, *, user_id, tester, endpoint_id=None):
        seen.append((payload, user_id, endpoint_id, tester({})["passed"]))
        return {"id": endpoint_id or 12, "name": payload["name"]}

    monkeypatch.setattr(routes.user_endpoints, "save_user_agent_endpoint", save)
    client = app.test_client()
    created = client.post(
        "/api/agent/endpoints",
        json={"name": "自己的节点"},
    )
    updated = client.put(
        "/api/agent/endpoints/12",
        json={"name": "改名后的节点"},
    )

    assert created.status_code == 201
    assert updated.status_code == 200
    assert [(item[1], item[2]) for item in seen] == [(7, None), (7, 12)]
