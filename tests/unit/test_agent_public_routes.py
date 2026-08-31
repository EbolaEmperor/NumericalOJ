"""公开 Agent Tasks 路由与会话所有权边界。"""

from __future__ import annotations

from flask import Flask

from backend.oj_modules.routes import problem_core_routes as routes


ADMIN = {"id": 1, "username": "admin", "is_admin": 1}
STUDENT = {"id": 9, "username": "student", "is_admin": 0}


class _WakeTask:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args):
        self.calls.append(args)


def _app():
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", SESSION_COOKIE_NAME="session")
    return app


def test_agent_routes_expose_api_canonical_urls():
    app = _app()
    app.register_blueprint(routes.problem_core_bp)
    rules = {rule.endpoint: rule.rule for rule in app.url_map.iter_rules()}

    assert rules["problem_core.agent_tasks"] == "/api/agent/sessions"
    assert rules["problem_core.agent_task_detail"] == "/api/agent/sessions/<session_id>"
    assert rules["problem_core.agent_launch_options"] == "/agent/launch-options"
    assert rules["problem_core.agent_run_status"] == "/api/agent/runs/<task_id>"
    assert rules["problem_core.agent_run_cancel"] == "/agent/runs/<task_id>/cancel"
    assert rules["problem_core.agent_run_stream"] == "/api/agent/runs/<task_id>/events"


def test_ordinary_user_list_is_always_scoped_to_self(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(STUDENT))
    calls = []
    monkeypatch.setattr(
        routes,
        "get_agent_sessions_paginated",
        lambda **kwargs: calls.append(kwargs) or ([], 1, 1),
    )
    monkeypatch.setattr(routes, "_agent_launch_page_options", lambda _uid: {})

    app = _app()
    with app.test_request_context("/api/agent/sessions?scope=all"):
        assert routes.agent_tasks().get_json()["success"] is True

    assert calls == [{"page": 1, "per_page": 20, "requested_by": "student"}]


def test_admin_list_defaults_to_all_and_can_select_mine(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(ADMIN))
    calls = []
    monkeypatch.setattr(
        routes,
        "get_agent_sessions_paginated",
        lambda **kwargs: calls.append(kwargs) or ([], 1, 1),
    )
    monkeypatch.setattr(routes, "_agent_launch_page_options", lambda _uid: {})

    app = _app()
    with app.test_request_context("/api/agent/sessions"):
        assert routes.agent_tasks().get_json()["success"] is True
    with app.test_request_context("/api/agent/sessions?scope=mine"):
        assert routes.agent_tasks().get_json()["success"] is True

    assert calls == [
        {"page": 1, "per_page": 20, "requested_by": None},
        {"page": 1, "per_page": 20, "requested_by": "admin"},
    ]


def test_ordinary_user_creation_forces_user_access_role(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(STUDENT))
    monkeypatch.setattr(routes, "_agent_run_turn_task", object())
    wake = _WakeTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", wake)
    monkeypatch.setattr(routes, "_agent_message_from_request", lambda: "完成任务")
    monkeypatch.setattr(routes, "_agent_client_message_id", lambda **_kwargs: "session-1")
    monkeypatch.setattr(routes, "_agent_session_cookie", lambda: ("session", "signed"))
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(routes, "_agent_quota_gate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: {"id": 12, "revision": 3, "model": "m"},
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(
        routes,
        "initialize_agent_task_workspace",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(routes, "create_empty_agent_runtime_checkpoint", lambda *_args: None)
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [])
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    created = []
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: created.append(kwargs) or kwargs,
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: f"/agent/tasks/{kwargs['session_id']}",
    )

    app = _app()
    with app.test_request_context(
        "/agent/tasks",
        method="POST",
        data={"message": "完成任务", "harness": "pi", "endpoint_id": "12", "access_role": "admin"},
        content_type="multipart/form-data",
    ):
        response = routes.agent_tasks()

    assert response.get_json()["success"] is True
    assert created[0]["requested_by"] == "student"
    assert created[0]["access_role"] == "user"
    assert created[0]["reasoning_effort"] == "high"


def test_ordinary_user_cannot_read_another_users_session(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(STUDENT))
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _sid: {
            "session_id": "session-1",
            "requested_by": "other",
            "is_legacy": False,
        },
    )

    app = _app()
    with app.test_request_context("/agent/tasks/session-1"):
        response, status = routes.agent_task_detail("session-1")

    assert status == 403
    assert "无权查看" in response


def test_run_state_rejects_another_users_task(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(STUDENT))
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda _task_id: {"requested_by": "other", "is_legacy": False},
    )

    app = _app()
    with app.test_request_context("/agent/runs/task-1/state"):
        response, status = routes.agent_run_status("task-1")

    assert status == 403
    assert response.get_json()["success"] is False
