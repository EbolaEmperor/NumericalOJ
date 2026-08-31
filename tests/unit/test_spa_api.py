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
    assert payload["navigation"]["agent_active"] is True
    assert payload["capabilities"]["spa"] is True
    assert payload["capabilities"]["class_adjust_enabled"] is True
    assert payload["capabilities"]["mail_service_configured"] is True
