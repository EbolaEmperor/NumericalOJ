# -*- coding: utf-8 -*-

from flask import Flask

from oj_modules.security import auth as auth_helpers
from oj_modules.routes import admin_dynamic_config_routes as routes


ADMIN = {
    "id": 17,
    "username": "admin",
    "password_hash": "unused",
    "is_admin": 1,
    "email": "admin@example.test",
}


def make_client(monkeypatch, **factory_kwargs):
    monkeypatch.setattr(auth_helpers, "current_user", lambda: ADMIN)
    monkeypatch.setattr(routes, "current_user", lambda: ADMIN)
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(
        routes.create_admin_dynamic_config_blueprint(**factory_kwargs)
    )
    return app, app.test_client()


def test_site_config_endpoint_name_is_stable(monkeypatch):
    app, _client = make_client(monkeypatch)

    rule = next(rule for rule in app.url_map.iter_rules() if rule.rule == "/admin/site-config")
    assert rule.endpoint == "admin_dynamic_config.site_config"


def test_endpoint_list_passes_current_admin_for_unlock_permission(monkeypatch):
    captured = {}

    def fake_list(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr(routes.config_service, "list_llm_endpoints", fake_list)
    _app, client = make_client(monkeypatch)

    response = client.get(
        "/api/admin/dynamic-config/llm-endpoints?category=text",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 200
    assert response.get_json() == {"success": True, "endpoints": []}
    assert captured == {"category": "text", "actor_user_id": 17}


def test_llm_test_token_is_top_level(monkeypatch):
    injected_tester = object()
    captured = {}

    def fake_test(payload, **kwargs):
        captured["payload"] = payload
        captured.update(kwargs)
        return {
            "passed": True,
            "status": "passed",
            "message": "测试通过",
            "latency_ms": 12,
            "test_token": "one-use-token",
            "expires_in_seconds": 600,
        }

    monkeypatch.setattr(routes.config_service, "test_llm_endpoint", fake_test)
    _app, client = make_client(monkeypatch, llm_endpoint_tester=injected_tester)

    response = client.post(
        "/api/admin/dynamic-config/llm-endpoints/test",
        json={"id": 3, "name": "端点"},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["test_token"] == "one-use-token"
    assert body["expires_in_seconds"] == 600
    assert "test_token" not in body["test"]
    assert captured["endpoint_id"] == 3
    assert captured["user_id"] == 17
    assert captured["tester"] is injected_tester


def test_mail_test_targets_current_admin_email(monkeypatch):
    captured = {}

    def fake_test(payload, **kwargs):
        captured["payload"] = payload
        captured.update(kwargs)
        return {
            "passed": True,
            "status": "passed",
            "message": "已发送",
            "latency_ms": 8,
        }

    monkeypatch.setattr(routes.config_service, "test_mail_settings", fake_test)
    _app, client = make_client(monkeypatch, mail_tester="mail-adapter")

    response = client.post(
        "/api/admin/dynamic-config/mail/test",
        json={"smtp_server": "smtp.example.test"},
    )

    assert response.status_code == 200
    assert captured["recipient_email"] == "admin@example.test"
    assert captured["tester"] == "mail-adapter"


def test_mail_and_search_save_do_not_require_a_test(monkeypatch):
    saved = []

    def save_mail(payload, *, user_id):
        saved.append(("mail", payload, user_id))
        return {"smtp_server": payload["smtp_server"], "test_status": "untested"}

    def save_search(payload, *, user_id):
        saved.append(("web-search", payload, user_id))
        return {"base_url": payload["base_url"], "test_status": "untested"}

    monkeypatch.setattr(routes.config_service, "save_mail_settings", save_mail)
    monkeypatch.setattr(routes.config_service, "save_web_search_settings", save_search)
    _app, client = make_client(monkeypatch)

    mail_response = client.put(
        "/api/admin/dynamic-config/mail",
        json={"smtp_server": "smtp.example.test"},
    )
    search_response = client.put(
        "/api/admin/dynamic-config/web-search",
        json={"base_url": "https://search.example.test/mcp"},
    )

    assert mail_response.status_code == 200
    assert search_response.status_code == 200
    assert saved == [
        ("mail", {"smtp_server": "smtp.example.test"}, 17),
        ("web-search", {"base_url": "https://search.example.test/mcp"}, 17),
    ]


def test_expected_business_error_is_returned_as_json(monkeypatch):
    def locked(*_args, **_kwargs):
        raise routes.config_service.DynamicConfigLockedError("已经锁定")

    monkeypatch.setattr(routes.config_service, "delete_llm_endpoint", locked)
    _app, client = make_client(monkeypatch)

    response = client.delete("/api/admin/dynamic-config/llm-endpoints/4")

    assert response.status_code == 423
    assert response.get_json() == {"success": False, "message": "已经锁定"}


def test_every_dynamic_config_api_rejects_non_admin(monkeypatch):
    non_admin = {
        "id": 23,
        "username": "student",
        "is_admin": 0,
        "email": "student@example.test",
    }
    monkeypatch.setattr(auth_helpers, "current_user", lambda: non_admin)
    monkeypatch.setattr(routes, "current_user", lambda: non_admin)
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="test")
    app.register_blueprint(routes.create_admin_dynamic_config_blueprint())
    client = app.test_client()

    tested = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/admin/dynamic-config/"):
            continue
        path = (
            rule.rule
            .replace("<int:endpoint_id>", "1")
            .replace("<feature_key>", "ai_code_annotation")
        )
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = client.open(
                path,
                method=method,
                json={},
                headers={"Accept": "application/json"},
            )
            assert response.status_code == 403, (method, path, response.get_data(as_text=True))
            assert response.get_json() == {"success": False, "message": "无权限"}
            tested.append((method, path))

    assert len(tested) >= 20
