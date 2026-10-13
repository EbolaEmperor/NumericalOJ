"""题目评分开关的保存兼容与查询边界；不连接真实数据库。"""

import pytest
from flask import Flask

from backend.oj_modules import db_services
from backend.oj_modules.api import problem_api
from backend.oj_modules.routes import admin_problem_routes
from scripts import init_db_schema


@pytest.fixture
def setting_client(monkeypatch):
    app = Flask(__name__)
    app.config.update(TESTING=True, SECRET_KEY="unit-test")
    app.register_blueprint(admin_problem_routes.admin_problem_bp)
    monkeypatch.setattr(
        admin_problem_routes, "current_user",
        lambda: {"username": "admin", "is_admin": 1},
    )
    return app.test_client()


@pytest.mark.parametrize("value", ["0", "1"])
def test_create_problem_persists_explicit_visibility(setting_client, monkeypatch, value):
    calls = []
    monkeypatch.setattr(
        admin_problem_routes, "create_problem",
        lambda *args, **kwargs: calls.append(kwargs) or 7,
    )
    response = setting_client.post(
        "/api/admin/problems",
        data={"title": "书面题", "content": "论证", "type": "2", "written_score_public": value},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 200
    assert calls[0]["written_score_public"] == int(value)


@pytest.mark.parametrize("saved_value", [0, 1])
def test_old_cli_edit_keeps_visibility(setting_client, monkeypatch, saved_value):
    monkeypatch.setattr(admin_problem_routes, "get_problem", lambda _id: {
        "id": 7, "type": 2, "written_grading_mode": 1,
        "written_score_public": saved_value,
    })
    calls = []
    monkeypatch.setattr(
        admin_problem_routes, "update_problem",
        lambda *args, **kwargs: calls.append(kwargs),
    )
    response = setting_client.post(
        "/api/admin/problems/7",
        data={"title": "仅修改标题", "content": "论证"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 200
    # 缺失参数不进入 UPDATE，避免旧 CLI 与开关保存并发时恢复旧公开策略。
    assert "new_written_score_public" not in calls[0]


@pytest.mark.parametrize("value", ["0", "1"])
def test_edit_problem_saves_explicit_visibility(setting_client, monkeypatch, value):
    monkeypatch.setattr(admin_problem_routes, "get_problem", lambda _id: {
        "id": 7, "type": 2, "written_grading_mode": 1, "written_score_public": 1,
    })
    calls = []
    monkeypatch.setattr(admin_problem_routes, "update_problem", lambda *args, **kwargs: calls.append(kwargs))
    response = setting_client.post(
        "/api/admin/problems/7",
        data={"title": "书面题", "content": "论证", "written_score_public": value},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 200
    assert calls[0]["new_written_score_public"] == int(value)


def test_student_cannot_change_visibility(setting_client, monkeypatch):
    monkeypatch.setattr(
        admin_problem_routes, "current_user",
        lambda: {"username": "alice", "is_admin": 0},
    )
    monkeypatch.setattr(
        admin_problem_routes, "update_problem",
        lambda *args, **kwargs: pytest.fail("学生请求不能写题目"),
    )
    response = setting_client.post(
        "/api/admin/problems/7", data={"written_score_public": "1"},
    )
    assert response.status_code == 403


def test_invalid_visibility_does_not_create_problem(setting_client, monkeypatch):
    monkeypatch.setattr(
        admin_problem_routes, "create_problem",
        lambda *args, **kwargs: pytest.fail("无效公开设置不能写入"),
    )
    response = setting_client.post(
        "/api/admin/problems",
        data={"title": "书面题", "content": "论证", "type": "2", "written_score_public": "2"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 400


def test_edit_form_returns_closed_switch(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(problem_api.problem_api_bp)
    monkeypatch.setattr(problem_api, "current_user", lambda: {"is_admin": 1})
    monkeypatch.setattr(problem_api, "build_problem_detail_context", lambda *_args: (
        {"problem": {"id": 7, "type": 2, "written_score_public": 0}}, None,
    ))
    monkeypatch.setattr(problem_api, "_problem_form_options", lambda: {})
    response = app.test_client().get("/api/admin/problems/7/edit-form")
    assert response.status_code == 200
    assert response.json["form"]["written_score_public"] == 0
    assert response.headers["Cache-Control"] == "no-store"


def test_schema_keeps_old_problems_public_without_backfill():
    definition = init_db_schema._load_schema_specs()["problems"].columns["written_score_public"]
    assert definition.lower() == "tinyint not null default '1'"


def test_student_status_filter_uses_visible_state_and_admin_keeps_real_state():
    student_sql, student_params = db_services._build_submission_list_where(
        username="alice", status_filter="accepted", respect_grading_visibility=True,
    )
    assert "p.written_score_public=0" in student_sql
    assert "THEN '评分未公开' ELSE s.status END = %s" in student_sql
    assert student_params == ("alice", "Accepted")
    admin_sql, admin_params = db_services._build_submission_list_where(status_filter="accepted")
    assert "written_score_public" not in admin_sql
    assert "s.status = %s" in admin_sql
    assert admin_params == ("Accepted",)


def test_empty_visibility_lookup_never_connects(monkeypatch):
    monkeypatch.setattr(
        db_services, "get_db_connection", lambda: pytest.fail("空集合不应连接数据库"),
    )
    assert db_services.get_problem_visibility_map([]) == {}


class _Cursor:
    def __init__(self):
        self.calls = []
        self.lastrowid = 7

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))

    def fetchone(self):
        return {"lang": "matlab", "max_score": 5}


class _Connection:
    def __init__(self):
        self.current_cursor = _Cursor()

    def cursor(self):
        return self.current_cursor

    def commit(self):
        pass

    def close(self):
        pass


def test_database_save_keeps_closed_flag_when_omitted(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    db_services.update_problem(7, "标题", "题面")
    sql, _params = connection.current_cursor.calls[-1]
    assert "written_score_public" not in sql
    db_services.update_problem(7, "标题", "题面", new_written_score_public=0)
    sql, params = connection.current_cursor.calls[-1]
    assert "written_score_public=%s" in sql
    assert params[-2:] == (0, 7)


def test_database_create_stores_switch_value(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    assert db_services.create_problem("标题", "题面", type=2, written_score_public=0) == 7
    sql, params = connection.current_cursor.calls[-1]
    assert "written_score_public" in sql
    assert params[-1] == 0
    assert sql.count("%s") == len(params)
