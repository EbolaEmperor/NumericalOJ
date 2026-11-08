"""默认 Harbor 附件的官方格式、只读下载及比赛可见性。"""

from io import BytesIO
import stat
import tomllib
from zipfile import ZipFile

from flask import Flask
import pytest

from backend.oj_modules.api import ranking_api
from backend.oj_modules.integrations.harbor_runtime import validate_harbor_task
from backend.oj_modules.ranking.reverse_judge import template
from backend.oj_modules.routes import ranking_routes


def test_generated_template_is_a_valid_official_harbor_task_with_executable_scripts(tmp_path):
    archive = template.build_harbor_template_archive()
    with ZipFile(archive) as package:
        assert set(package.namelist()) == {"task.toml", "instruction.md", "environment/Dockerfile",
                                          "solution/solve.sh", "tests/test.sh", "README.md"}
        for item in package.infolist():
            if item.filename.endswith(".sh"):
                assert stat.S_IMODE(item.external_attr >> 16) == 0o755
            target = tmp_path / item.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(package.read(item))
        config = tomllib.loads(package.read("task.toml").decode())
        assert config["artifacts"] == ["/app"]
        assert package.read("environment/Dockerfile").decode() == template.DEFAULT_HARBOR_DOCKERFILE
    assert validate_harbor_task(tmp_path) is not None


def _application(monkeypatch, user, competition):
    app = Flask(__name__)
    app.secret_key = "test"
    app.register_blueprint(ranking_api.ranking_api_bp)
    app.register_blueprint(ranking_routes.ranking_bp)
    monkeypatch.setattr(ranking_api, "current_user", lambda: user)
    monkeypatch.setattr(ranking_api, "get_competition", lambda _id: competition)
    monkeypatch.setattr(ranking_routes, "_require_user", lambda: (user, None))
    monkeypatch.setattr(ranking_routes, "get_competition", lambda _id: competition)
    return app


@pytest.mark.parametrize("admin,active,status", [(0, 1, 200), (0, 0, 403), (1, 0, 200)])
@pytest.mark.parametrize("path", ["/api/ranking/competitions/7/attachments/harbor-template/download",
                                  "/ranking/7/attachment/harbor-template/download"])
def test_builtin_download_obeys_competition_visibility(monkeypatch, admin, active, status, path):
    user = {"username": "reader", "is_admin": admin}
    comp = {"id": 7, "scoring_mode": "reverse_judge", "is_active": active}
    response = _application(monkeypatch, user, comp).test_client().get(path)
    assert response.status_code == status
    if status == 200:
        assert "harbor-template.zip" in response.headers["Content-Disposition"]
        assert response.headers["Cache-Control"] == "private, no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        with ZipFile(BytesIO(response.data)) as archive:
            assert "tests/test.sh" in archive.namelist()


def test_builtin_download_requires_login_and_reverse_judge_mode(monkeypatch):
    comp = {"id": 7, "scoring_mode": "absolute", "is_active": 1}
    app = _application(monkeypatch, None, comp)
    url = "/api/ranking/competitions/7/attachments/harbor-template/download"
    assert app.test_client().get(url).status_code == 401
    monkeypatch.setattr(ranking_api, "current_user", lambda: {"username": "reader", "is_admin": 0})
    assert app.test_client().get(url).status_code == 404
    monkeypatch.setattr(ranking_api, "get_competition", lambda _id: None)
    assert app.test_client().get(url).status_code == 404


def test_default_template_is_not_a_deletable_attachment_record(monkeypatch):
    app = _application(monkeypatch, {"username": "admin", "is_admin": 1},
                       {"id": 7, "scoring_mode": "reverse_judge", "is_active": 1})
    assert app.test_client().delete("/api/ranking/competitions/7/attachments/harbor-template").status_code == 404
    assert app.test_client().post("/ranking/7/attachment/harbor-template/delete").status_code == 404


@pytest.mark.parametrize("scoring", ["reverse_judge", "absolute"])
def test_competition_files_include_default_template_only_for_reverse_and_keep_uploads(monkeypatch, scoring):
    comp = {"id": 7, "scoring_mode": scoring, "is_active": 1, "description": "题面"}
    app = _application(monkeypatch, {"username": "student", "is_admin": 0}, comp)
    uploaded = {"id": 5, "competition_id": 7, "filename": "existing.zip", "file_size": 10}
    monkeypatch.setattr(ranking_api, "list_competition_files", lambda _id: [uploaded])
    monkeypatch.setattr(ranking_api, "get_ranking_navigation_state", lambda *_args: {})
    monkeypatch.setattr(ranking_api, "_agent_judge_endpoint_ready", lambda *_args: True)
    monkeypatch.setattr(ranking_api, "_reverse_quality_gate_ready", lambda *_args: True)
    monkeypatch.setattr(ranking_api, "list_agent_judge_endpoints", lambda *_args, **_kw: [])
    monkeypatch.setattr(ranking_api, "_render_description", lambda text: text)
    response = app.test_client().get("/api/ranking/competitions/7")
    assert response.status_code == 200
    files = response.get_json()["files"]
    assert files[-1]["id"] == 5 and files[-1]["filename"] == "existing.zip"
    assert "builtin" not in uploaded
    if scoring == "reverse_judge":
        assert files[0]["id"] == template.HARBOR_TEMPLATE_ID
        assert files[0]["builtin"] is True
        download = app.test_client().get(files[0]["download_url"])
        assert files[0]["file_size"] == len(download.data)
    else:
        assert len(files) == 1
