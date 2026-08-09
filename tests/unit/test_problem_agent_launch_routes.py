import io
import json
from types import SimpleNamespace

from flask import Flask
import pytest

from oj_modules.routes import problem_core_routes as routes


class _Task:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args, task_id):
        self.calls.append({"args": args, "task_id": task_id})


def _app(cookie_name="session"):
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", SESSION_COOKIE_NAME=cookie_name)
    return app


def test_launch_options_return_unified_user_preference_for_each_task_kind(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    endpoints = {
        "claude_code": [],
        "codex": [{"id": 12, "model": "m", "protocol": "openai", "category": "text"}],
        "opencode": [],
        "pi": [],
    }
    monkeypatch.setattr(routes, "list_launch_endpoints_by_harness", lambda: endpoints)
    monkeypatch.setattr(
        routes,
        "get_agent_launch_preference",
        lambda user_id: {
            "user_id": user_id,
            "harness": "codex",
            "endpoint_id": 12,
        },
    )

    app = _app()
    with app.test_request_context("/admin/agent_launch_options?task_kind=testdata"):
        response = routes.admin_agent_launch_options()

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["task_kind"] == "testdata"
    assert payload["preference"] == {"harness": "codex", "endpoint_id": 12}
    assert payload["endpoints_by_harness"]["codex"][0]["id"] == 12
    assert response.headers["Cache-Control"] == "private, no-store"


def test_launch_options_fall_back_when_remembered_endpoint_disappeared(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    endpoints = {
        "claude_code": [],
        "codex": [{"id": 22, "model": "new", "protocol": "openai", "category": "text"}],
        "opencode": [],
        "pi": [],
    }
    monkeypatch.setattr(routes, "list_launch_endpoints_by_harness", lambda: endpoints)
    monkeypatch.setattr(
        routes,
        "get_agent_launch_preference",
        lambda *_args: {"harness": "codex", "endpoint_id": 12},
    )

    app = _app()
    with app.test_request_context("/admin/agent_launch_options?task_kind=solve"):
        payload = routes.admin_agent_launch_options().get_json()

    assert payload["preference"] == {"harness": "codex", "endpoint_id": 22}


def test_solve_launch_passes_selected_values_and_current_session(monkeypatch):
    task = _Task()
    snapshots = []
    saved = []
    sessions = []
    url_calls = []
    monkeypatch.setattr(routes, "_agent_solve_problem_task", task)
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "get_problem", lambda _pid: {"id": 9, "title": "题", "type": 1})
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "revision": 6,
            "model": "selected-model",
            "protocol": "openai",
            "category": "text",
            "input_price_per_million": "2.00",
            "cached_input_price_per_million": "0.20",
            "output_price_per_million": "8.00",
        },
    )
    monkeypatch.setattr(
        routes,
        "save_agent_launch_preference",
        lambda *args: saved.append(args),
    )
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", snapshots.append)
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: sessions.append(kwargs),
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: (
            url_calls.append((endpoint, kwargs))
            or f"/admin/agent_tasks/{kwargs['session_id']}"
        ),
    )

    app = _app("numoj_session")
    with app.test_request_context(
        "/admin/agent_solve_problem/9",
        method="POST",
        json={"harness": "codex", "endpoint_id": 12},
        environ_overrides={"HTTP_COOKIE": "numoj_session=signed-session-value"},
    ):
        response = routes.admin_agent_solve_problem(9)

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["view_url"] == f"/admin/agent_tasks/{payload['task_id']}"
    assert url_calls[-1] == (
        "problem_core.admin_agent_task_detail",
        {"session_id": payload["task_id"]},
    )
    assert saved == [(7, "codex", 12)]
    assert sessions == [{
        "session_id": payload["task_id"],
        "task_id": payload["task_id"],
        "requested_by": "admin",
        "harness": "codex",
        "endpoint_id": 12,
        "endpoint_revision": 6,
        "endpoint_model": "selected-model",
        "user_message": "解决题目 #9：题",
        "task_kind": "solve",
        "access_role": "user",
        "problem_id": 9,
        "problem_title": "题",
    }]
    assert len(task.calls) == 1
    assert task.calls[0]["args"] == (
        9,
        "admin",
        "codex",
        12,
        "signed-session-value",
        "numoj_session",
        6,
    )
    assert snapshots[0]["harness"] == "codex"
    assert "token_pricing" not in snapshots[0]
    assert "signed-session-value" not in str(snapshots)


def test_solve_launch_rejects_non_object_json(monkeypatch):
    monkeypatch.setattr(routes, "_agent_solve_problem_task", _Task())
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {"id": 9, "title": "题", "type": 1},
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_solve_problem/9",
        method="POST",
        json=["codex", 12],
    ):
        response, status = routes.admin_agent_solve_problem(9)

    assert status == 400
    assert response.get_json()["message"] == "请求参数格式无效"


def test_testdata_launch_passes_skill_inputs_after_agent_selection(monkeypatch):
    task = _Task()
    requirement = "x" * 4001
    sessions = []
    url_calls = []
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", task)
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "get_problem", lambda _pid: {"id": 9, "title": "题", "type": 1})
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda _harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id), "revision": 7,
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: sessions.append(kwargs),
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: (
            url_calls.append((endpoint, kwargs))
            or f"/admin/agent_tasks/{kwargs['session_id']}"
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        data={
            "harness": "pi",
            "endpoint_id": "18",
            "test_point_count": "4",
            "data_requirement": requirement,
            "standard_solution": (
                io.BytesIO("print(1)\n".encode()),
                "正解.py",
            ),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-session-value"},
    ):
        response = routes.admin_agent_generate_testdata(9)

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["view_url"] == f"/admin/agent_tasks/{payload['task_id']}"
    assert url_calls[-1] == (
        "problem_core.admin_agent_task_detail",
        {"session_id": payload["task_id"]},
    )
    assert sessions == [{
        "session_id": payload["task_id"],
        "task_id": payload["task_id"],
        "requested_by": "admin",
        "harness": "pi",
        "endpoint_id": 18,
        "endpoint_revision": 7,
        "endpoint_model": "selected-model",
        "user_message": f"为题目 #9 生成 4 个测试点。\n\n{requirement}",
        "task_kind": "testdata",
        "access_role": "user",
        "problem_id": 9,
        "problem_title": "题",
    }]
    assert task.calls[0]["args"] == (
        9,
        "admin",
        4,
        "print(1)\n",
        requirement,
        "standard_solution.py",
        "pi",
        18,
        "signed-session-value",
        "session",
        7,
    )


def test_agent_task_list_redirects_existing_task_to_session_detail(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_agent_sessions_paginated",
        lambda **_kwargs: ([], 1, 1),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda task_id: (
            {"session_id": "session-1"} if task_id == "task-1" else None
        ),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _session_id: None,
    )
    monkeypatch.setattr(
        routes,
        "_agent_launch_page_options",
        lambda _user_id: {
            "harnesses": [],
            "endpoints_by_harness": {},
            "preference": {"harness": "", "endpoint_id": None},
        },
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: (
            f"/admin/agent_tasks/{kwargs['session_id']}"
            if endpoint == "problem_core.admin_agent_task_detail"
            else "/unexpected"
        ),
    )
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_template",
        lambda template, **context: rendered.append((template, context)) or "ok",
    )

    app = _app()
    with app.test_request_context("/admin/agent_tasks?task_id=task-1"):
        response = routes.admin_agent_tasks()
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/agent_tasks/session-1")
    assert rendered == []

    with app.test_request_context("/admin/agent_tasks?task_id=missing"):
        assert routes.admin_agent_tasks() == "ok"
    assert rendered[-1][0] == "admin/agent_tasks.html"
    assert rendered[-1][1]["agent_sessions"] == []
    assert rendered[-1][1]["current_page"] == 1
    assert rendered[-1][1]["total_pages"] == 1


def test_legacy_agent_run_page_route_is_removed():
    app = _app()
    app.register_blueprint(routes.problem_core_bp)
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/admin/agent_run/<task_id>" not in rules
    assert "/admin/agent_run_status/<task_id>" in rules
    assert "/admin/agent_run_stream/<task_id>" in rules
    assert "/admin/agent_run_cancel/<task_id>" in rules


def test_agent_run_cancel_returns_published_terminal_state(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    calls = []
    monkeypatch.setattr(
        routes,
        "_terminate_agent_run",
        lambda task_id: calls.append(task_id) or {
            "exists": True,
            "changed": True,
            "canceled": True,
            "errors": [],
            "state": {
                "task_id": task_id,
                "status": "Canceled",
                "message": "任务已由管理员终止",
            },
        },
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_run_cancel/task-1",
        method="POST",
    ):
        response = routes.admin_agent_run_cancel("task-1")

    assert calls == ["task-1"]
    assert response.get_json() == {
        "success": True,
        "message": "任务已终止",
        "state": {
            "task_id": "task-1",
            "status": "Canceled",
            "message": "任务已由管理员终止",
        },
    }


@pytest.mark.parametrize(
    ("result", "expected_status"),
    [
        ({"exists": False, "canceled": False}, 404),
        ({
            "exists": True,
            "changed": False,
            "canceled": False,
            "state": {"status": "Completed"},
        }, 409),
    ],
)
def test_agent_run_cancel_rejects_missing_or_finished_task(
    monkeypatch,
    result,
    expected_status,
):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_terminate_agent_run", lambda _task_id: result)

    app = _app()
    with app.test_request_context(
        "/admin/agent_run_cancel/task-1",
        method="POST",
    ):
        response, status = routes.admin_agent_run_cancel("task-1")

    assert status == expected_status
    assert response.get_json()["success"] is False


def test_agent_run_stream_subscribes_before_rechecking_terminal_state(monkeypatch):
    order = []
    states = iter([
        {"task_id": "task-1", "status": "Completed"},
    ])

    def get_state(_task_id):
        order.append("read")
        return next(states)

    class PubSub:
        closed = False

        def get_message(self, **_kwargs):
            raise AssertionError("订阅后的终态重读不应再等待消息")

        def close(self):
            self.closed = True

    pubsub = PubSub()
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", get_state)
    monkeypatch.setattr(
        routes,
        "_subscribe_agent_run_events",
        lambda _task_id: order.append("subscribe") or pubsub,
    )
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/task-1"):
        body = routes.admin_agent_run_stream("task-1").get_data(as_text=True)

    assert order == ["subscribe", "read"]
    assert "event: done" in body
    assert pubsub.closed is True


def test_agent_run_stream_rechecks_state_when_pubsub_has_no_message(monkeypatch):
    states = iter([
        {"task_id": "task-2", "status": "Running"},
        {"task_id": "task-2", "status": "Completed"},
    ])

    class PubSub:
        def get_message(self, **_kwargs):
            return None

        def close(self):
            pass

    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _task_id: next(states))
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _task_id: PubSub())
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/task-2"):
        body = routes.admin_agent_run_stream("task-2").get_data(as_text=True)

    assert "event: done" in body


def test_agent_run_stream_stays_open_past_the_previous_one_hour_cutoff(
    monkeypatch,
):
    states = iter([
        {"task_id": "task-long", "status": "Running"},
        {"task_id": "task-long", "status": "Running"},
        {"task_id": "task-long", "status": "Completed"},
    ])

    class PubSub:
        def get_message(self, **_kwargs):
            return None

        def close(self):
            pass

    clock = iter([0.0, 3601.0])
    monkeypatch.setattr(
        routes,
        "time",
        SimpleNamespace(time=lambda: next(clock), sleep=lambda _seconds: None),
    )
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _task_id: next(states))
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _task_id: PubSub())
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/task-long"):
        body = routes.admin_agent_run_stream("task-long").get_data(as_text=True)

    assert "event: done" in body
    assert "event: timeout" not in body


def test_agent_state_markdown_is_rebuilt_only_for_rich_trace_text(monkeypatch):
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: rendered.append(str(text)) or f"<safe>{text}</safe>",
    )
    raw = {
        "status": "Completed",
        "conclusion": "**最终结论**",
        "conclusion_html": "<script>unsafe()</script>",
        "execution_trace": {
            "conclusion_html": "<img src=x onerror=unsafe()>",
            "trace_messages": [
                {"kind": "assistant", "text": "**回答**", "html": "<b>伪造</b>"},
                {"kind": "thinking", "content": "$x$"},
                {"kind": "reasoning", "text": "推理"},
                {"kind": "tool", "input": "<b>命令</b>", "html": "<b>伪造</b>"},
                {"kind": "tool_result", "output": "<b>结果</b>"},
            ],
        },
    }

    state = routes._decorate_agent_state_markdown(raw)
    messages = state["execution_trace"]["trace_messages"]

    assert messages[0]["html"] == "<safe>**回答**</safe>"
    assert messages[1]["html"] == "<safe>$x$</safe>"
    assert messages[2]["html"] == "<safe>推理</safe>"
    assert "html" not in messages[3]
    assert "html" not in messages[4]
    assert state["conclusion_html"] == "<safe>**最终结论**</safe>"
    assert "conclusion_html" not in state["execution_trace"]
    assert raw["conclusion_html"] == "<script>unsafe()</script>"
    assert raw["execution_trace"]["trace_messages"][0]["html"] == "<b>伪造</b>"
    assert rendered == ["**回答**", "$x$", "推理", "**最终结论**"]


def test_agent_run_status_returns_server_rendered_markdown(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "markdown-task",
            "status": "Completed",
            "execution_trace": {
                "trace_messages": [
                    {"kind": "assistant", "text": "结论含公式 $x^2$"},
                ],
            },
        },
    )
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<safe>{text}</safe>",
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_status/markdown-task"):
        response = routes.admin_agent_run_status("markdown-task")

    state = response.get_json()["state"]
    message = state["execution_trace"]["trace_messages"][0]
    assert message["html"] == "<safe>结论含公式 $x^2$</safe>"
    assert state["conclusion_html"] == "<safe>结论含公式 $x^2$</safe>"


def test_agent_run_state_overlays_session_cleanup_failure_on_sticky_cancel(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "cleanup-task",
            "status": "Canceled",
            "message": "任务已由管理员终止",
            "execution_trace": {"trace_messages": []},
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda _task_id: {
            "session_id": "session-1",
            "current_task_id": "cleanup-task",
            "status": "CleanupFailed",
            "message": "容器状态未知",
        },
    )
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)

    state = routes._get_agent_run_state("cleanup-task")

    assert state["status"] == "CleanupFailed"
    assert state["message"] == "容器状态未知"
    assert state["harness_status"] == "cleanup_failed"


def test_agent_run_stream_overlays_cleanup_failure_on_pubsub_snapshot(monkeypatch):
    class PubSub:
        def get_message(self, **_kwargs):
            return {
                "type": "message",
                "data": json.dumps({
                    "task_id": "cleanup-stream",
                    "status": "Canceled",
                    "message": "任务已由管理员终止",
                    "execution_trace": {
                        "trace_messages": [
                            {"kind": "assistant", "text": "保留 **结论**"},
                        ],
                    },
                }),
            }

        def close(self):
            pass

    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: {"task_id": "cleanup-stream", "status": "Running"},
    )
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _task_id: PubSub())
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<safe>{text}</safe>",
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda _task_id: {
            "session_id": "session-1",
            "current_task_id": "cleanup-stream",
            "status": "CleanupFailed",
            "message": "relay 未能关闭",
        },
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/cleanup-stream"):
        body = routes.admin_agent_run_stream("cleanup-stream").get_data(as_text=True)

    assert '"status": "CleanupFailed"' in body
    assert "relay 未能关闭" in body
    assert "<safe>保留 **结论**</safe>" in body
    assert "event: done" in body


@pytest.mark.parametrize("invalid_count", [True, False, 1.0, "1.0", " 1", "01"])
def test_testdata_launch_rejects_non_strict_test_point_count(
    monkeypatch,
    invalid_count,
):
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", _Task())
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {"id": 9, "title": "题", "type": 1},
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        data={
            "harness": "pi",
            "endpoint_id": "18",
            "test_point_count": invalid_count,
            "standard_solution": (io.BytesIO(b"print(1)\n"), "answer.py"),
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 400
    assert response.get_json()["message"] == "测试点数量无效"


def test_testdata_launch_accepts_any_positive_test_point_count():
    assert routes._parse_agent_test_point_count("5001") == 5001


def test_testdata_launch_rejects_promptly_grading_problem(monkeypatch):
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", _Task())
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {
            "id": 9,
            "title": "Promptly 题",
            "type": 1,
            "programming_grading_mode": 3,
        },
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        json={},
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 400
    assert "Promptly" in response.get_json()["message"]


def test_testdata_launch_rejects_json_standard_code_contract(monkeypatch):
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", _Task())
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {"id": 9, "title": "题", "type": 1},
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        json={
            "harness": "pi",
            "endpoint_id": 18,
            "test_point_count": 4,
            "standard_code": "print(1)",
        },
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 415
    assert "multipart/form-data" in response.get_json()["message"]


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (b"", "不能为空"),
        (b"\xff\xfe", "UTF-8"),
        (b"print(1)\x00", "NUL"),
    ],
)
def test_testdata_launch_rejects_invalid_standard_solution_file(
    monkeypatch,
    payload,
    expected_message,
):
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", _Task())
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {"id": 9, "title": "题", "type": 1},
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        data={
            "harness": "pi",
            "endpoint_id": "18",
            "test_point_count": "4",
            "standard_solution": (io.BytesIO(payload), "answer.py"),
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 400
    assert expected_message in response.get_json()["message"]


def test_testdata_launch_reads_large_standard_solution_without_size_cap():
    payload = b"#" * (2 * 1024 * 1024 + 1)
    source, filename = routes._read_agent_standard_solution(SimpleNamespace(
        filename="answer.py",
        stream=io.BytesIO(payload),
    ))

    assert source.encode() == payload
    assert filename == "answer.py"


@pytest.mark.parametrize(
    ("celery_state", "result", "expected_status", "expected_message"),
    [
        ("FAILURE", RuntimeError("worker crashed"), "Failed", "worker crashed"),
        (
            "SUCCESS",
            {
                "success": True,
                "message": "已通过",
                "final_submission_id": 91,
                "latest_submission_id": 92,
                "attempts": [{"submission_id": 91}],
            },
            "Completed",
            "已通过",
        ),
    ],
)
def test_agent_run_state_overlays_celery_terminal_on_stale_snapshot(
    monkeypatch,
    celery_state,
    result,
    expected_status,
    expected_message,
):
    snapshot = {
        "task_id": "task-1",
        "status": "Running",
        "message": "仍在执行",
        "harness": "codex",
        "final_submission_id": None,
        "latest_submission_id": None,
        "attempts": [],
    }
    monkeypatch.setattr(routes, "_get_agent_run_snapshot", lambda _task_id: snapshot)
    monkeypatch.setattr(routes, "get_agent_run_by_task_id", lambda _task_id: None)
    monkeypatch.setattr(
        routes,
        "_agent_solve_problem_task",
        SimpleNamespace(
            AsyncResult=lambda _task_id: SimpleNamespace(
                state=celery_state,
                result=result,
            ),
        ),
    )

    state = routes._get_agent_run_state("task-1")

    assert state["status"] == expected_status
    assert state["message"] == expected_message
    assert state["harness"] == "codex"
    if celery_state == "SUCCESS":
        assert state["final_submission_id"] == 91
        assert state["latest_submission_id"] == 92


def test_agent_run_state_never_overlays_canceled_with_celery_failure(monkeypatch):
    snapshot = {
        "task_id": "task-canceled",
        "status": "Canceled",
        "message": "任务已由管理员终止",
        "attempts": [],
    }
    monkeypatch.setattr(routes, "_get_agent_run_snapshot", lambda _task_id: snapshot)
    monkeypatch.setattr(
        routes,
        "_agent_solve_problem_task",
        SimpleNamespace(
            AsyncResult=lambda _task_id: SimpleNamespace(
                state="FAILURE",
                result=RuntimeError("worker terminated"),
            ),
        ),
    )

    state = routes._get_agent_run_state("task-canceled")

    assert state["status"] == "Canceled"
    assert state["message"] == "任务已由管理员终止"


def test_agent_run_state_prefers_persisted_cancel_over_stale_running_cache(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "task-canceled",
            "status": "Running",
            "message": "旧缓存仍在运行",
            "harness": "codex",
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_run_by_task_id",
        lambda _task_id: {
            "task_id": "task-canceled",
            "status": "Canceled",
            "message": "任务已由管理员终止",
            "attempts": [],
        },
    )

    state = routes._get_agent_run_state("task-canceled")

    assert state["status"] == "Canceled"
    assert state["message"] == "任务已由管理员终止"
    assert state["harness"] == "codex"


def test_agent_run_state_prefers_persisted_completion_over_stale_cache_and_celery(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "task-completed",
            "status": "Running",
            "message": "旧缓存仍在发布",
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_run_by_task_id",
        lambda _task_id: {
            "task_id": "task-completed",
            "status": "Completed",
            "message": "测试数据已发布",
            "attempts": [],
        },
    )
    monkeypatch.setattr(
        routes,
        "_agent_solve_problem_task",
        SimpleNamespace(
            AsyncResult=lambda _task_id: SimpleNamespace(
                state="FAILURE",
                result=RuntimeError("worker died after commit"),
            ),
        ),
    )

    state = routes._get_agent_run_state("task-completed")

    assert state["status"] == "Completed"
    assert state["message"] == "测试数据已发布"
