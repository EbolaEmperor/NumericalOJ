from unittest.mock import MagicMock

from flask import Flask

from backend.oj_modules.api import spa_api
from backend.oj_modules.api.helpers import public_problem


def _app():
    app = Flask(__name__)
    app.config.update(TESTING=True)
    app.register_blueprint(spa_api.spa_api_bp)
    return app


def test_public_problem_excludes_private_grading_configuration():
    problem = public_problem({
        "id": 7,
        "title": "公开题目",
        "programming_grading_mode": 2,
        "written_grading_mode": 4,
        "output_image_filename": "secret-output.png",
    })

    assert problem == {
        "id": 7,
        "title": "公开题目",
        "programming_grading_mode": 2,
    }


def test_session_bootstrap_is_public_and_minimal_when_logged_out(monkeypatch):
    monkeypatch.setattr(spa_api, "current_user", lambda: None)

    response = _app().test_client().get("/api/v1/session")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["success"] is True
    assert payload["api_version"] == "v1"
    assert payload["user"] is None
    assert payload["navigation"] == {
        "items": [],
        "counts": {},
        "agent_active": False,
    }


def test_session_bootstrap_exposes_spa_paths_and_admin_capability(monkeypatch):
    user = {"id": 7, "username": "root", "email": "root@example.test", "is_admin": 1}
    monkeypatch.setattr(spa_api, "current_user", lambda: user)
    monkeypatch.setattr(
        spa_api,
        "get_layout_navigation_context",
        lambda *_args, **_kwargs: {
            "counts": {"problems": 9, "submissions": 4},
            "agent_active": True,
        },
    )
    monkeypatch.setattr(spa_api, "is_class_adjust_enabled", lambda **_kwargs: True)
    monkeypatch.setattr(spa_api, "get_mail_settings", lambda **_kwargs: {"host": "smtp.example.test"})

    payload = _app().test_client().get("/api/v1/session").get_json()

    assert payload["user"] == user
    paths = {item["id"]: item["path"] for item in payload["navigation"]["items"]}
    assert paths["library"] == "/problems?view=library"
    assert paths["problems"] == "/problems"
    assert paths["repository"] == "/repository"
    assert paths["admin"] == "/admin"
    faithsieve = next(item for item in payload["navigation"]["items"] if item["id"] == "faithsieve")
    assert faithsieve["path"] == "/admin/faithsieve"
    assert faithsieve["group"] == "admin"
    assert payload["navigation"]["agent_active"] is True
    assert payload["capabilities"]["spa"] is True
    assert payload["capabilities"]["class_adjust_enabled"] is True
    assert payload["capabilities"]["mail_service_configured"] is True


def test_faithsieve_navigation_is_admin_only():
    assert all(item["id"] != "faithsieve" for item in spa_api._navigation_items({"is_admin": 0}))


def test_faithsieve_document_paths_do_not_match_other_resources():
    from backend.oj_modules.routes.spa_routes import is_spa_document_path

    assert is_spa_document_path("/admin/faithsieve")
    assert is_spa_document_path("/admin/faithsieve/" + "a" * 32)
    assert not is_spa_document_path("/admin/faithsieve/invalid")
    assert not is_spa_document_path("/api/admin/faithsieve/" + "a" * 32)
    assert not is_spa_document_path("/app/admin/faithsieve")


def test_session_navigation_uses_class_cookie_with_url_priority(monkeypatch):
    user = {"id": 7, "username": "root", "email": "root@example.test", "is_admin": 1}
    monkeypatch.setattr(spa_api, "current_user", lambda: user)
    navigation = MagicMock(side_effect=lambda _user, *, selected_class_en: {
        "counts": {},
        "agent_active": False,
        "selected_class_en": selected_class_en,
    })
    monkeypatch.setattr(spa_api, "get_layout_navigation_context", navigation)
    monkeypatch.setattr(spa_api, "is_class_adjust_enabled", lambda **_kwargs: False)
    monkeypatch.setattr(spa_api, "get_mail_settings", lambda **_kwargs: None)
    client = _app().test_client()
    client.set_cookie("numoj_problem_list_class", "C1")

    remembered = client.get("/api/v1/session")
    explicit = client.get("/api/v1/session?class_en=C2")

    assert remembered.status_code == 200
    assert explicit.status_code == 200
    assert remembered.get_json()["navigation"]["selected_class_en"] == "C1"
    assert explicit.get_json()["navigation"]["selected_class_en"] == "C2"
    assert navigation.call_args_list[0].kwargs == {"selected_class_en": "C1"}
    assert navigation.call_args_list[1].kwargs == {"selected_class_en": "C2"}
