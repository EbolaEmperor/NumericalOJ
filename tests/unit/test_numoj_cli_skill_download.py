from io import BytesIO
import zipfile

from flask import Flask

from oj_modules.problems import context as problem_context
from oj_modules.routes import problem_core_routes


def _archive_names(response):
    with zipfile.ZipFile(BytesIO(response.data)) as archive:
        return set(archive.namelist())


def test_cli_resource_copy_is_selected_in_backend_by_role():
    assert problem_context._numoj_cli_resource({"is_admin": 0}) == {
        "label": "numoj-user CLI",
        "description": "Download for agents to use NumOJ.",
    }
    assert problem_context._numoj_cli_resource({"is_admin": 1}) == {
        "label": "numoj-admin CLI",
        "description": "Download for agents to manage NumOJ",
    }


def test_numoj_cli_download_requires_login(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(problem_core_routes.problem_core_bp)
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: None)

    response = app.test_client().get("/downloads/numoj-cli.zip")

    assert response.status_code == 401


def test_regular_user_can_only_download_numoj_user_skill(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(problem_core_routes.problem_core_bp)
    monkeypatch.setattr(
        problem_core_routes,
        "current_user",
        lambda: {"id": 8, "is_admin": 0},
    )

    response = app.test_client().get(
        "/downloads/numoj-cli.zip?skill=numoj-admin"
    )

    assert response.status_code == 200
    assert "numoj-user.zip" in response.headers["Content-Disposition"]
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Vary"] == "Cookie"
    names = _archive_names(response)
    assert "numoj-user/SKILL.md" in names
    assert "numoj-user/scripts/numoj_user.py" in names
    assert all(name.startswith("numoj-user/") for name in names)


def test_admin_downloads_numoj_admin_skill(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(problem_core_routes.problem_core_bp)
    monkeypatch.setattr(
        problem_core_routes,
        "current_user",
        lambda: {"id": 1, "is_admin": 1},
    )

    response = app.test_client().get("/downloads/numoj-cli.zip")

    assert response.status_code == 200
    assert "numoj-admin.zip" in response.headers["Content-Disposition"]
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["Vary"] == "Cookie"
    names = _archive_names(response)
    assert "numoj-admin/SKILL.md" in names
    assert "numoj-admin/scripts/numoj_admin.py" in names
    assert all(name.startswith("numoj-admin/") for name in names)
