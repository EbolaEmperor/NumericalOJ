import io
import json
from types import SimpleNamespace

from flask import Flask
import pytest

from backend.oj_modules.problems import agent_runs
from backend.oj_modules.routes import problem_core_routes as routes


class _Task:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args, task_id=None):
        self.calls.append({"args": args, "task_id": task_id})


def _app(cookie_name="session"):
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", SESSION_COOKIE_NAME=cookie_name)
    return app


@pytest.fixture(autouse=True)
def _patch_agent_runtime_checkpoint_io(monkeypatch):
    """启动路由单测不触碰真实会话 workspace/checkpoint。"""

    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(
        routes,
        "initialize_agent_task_workspace",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        routes,
        "create_empty_agent_runtime_checkpoint",
        lambda _session_id, _checkpoint_id: None,
    )
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda _session_id, _checkpoint_id, *, missing_ok=True: None,
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda session_id, message_id, uploads: [
            {
                "name": upload.filename,
                "path": f"attachments/{message_id}/{upload.filename}",
            }
            for upload in uploads
        ],
    )
    monkeypatch.setattr(routes, "remove_agent_attachments", lambda *_args: 0)
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_timeline",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        agent_runs,
        "get_agent_trace_token_usage",
        lambda _task_id: None,
    )
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_subagents",
        lambda _task_id: [],
    )
    monkeypatch.setattr(routes, "get_last_agent_trace_assistant", lambda _task_id: "")
    monkeypatch.setattr(routes, "get_agent_session_by_task_id", lambda _task_id: None)


@pytest.fixture(autouse=True)
def _queue_dispatcher(monkeypatch):
    task = _Task()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", task)
    return task


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


def test_custom_launch_options_include_current_users_personal_endpoints(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    calls = []

    def launch_options(user_id):
        calls.append(user_id)
        return {
            "harnesses": [{"value": "pi", "label": "Pi"}],
            "endpoints_by_harness": {
                "pi": [
                    {
                        "id": 3,
                        "ref": "user:3",
                        "source": "user",
                        "model": "deepseek-v4-flash",
                    }
                ]
            },
            "reasoning_efforts_by_harness": {},
            "preference": {"harness": "pi", "endpoint_id": "user:3"},
        }

    monkeypatch.setattr(routes, "_agent_launch_page_options", launch_options)

    app = _app()
    with app.test_request_context("/agent/launch-options?task_kind=custom"):
        response = routes.agent_launch_options()

    payload = response.get_json()
    assert calls == [7]
    assert payload["success"] is True
    assert payload["task_kind"] == "custom"
    assert payload["endpoints_by_harness"]["pi"][0]["ref"] == "user:3"
    assert payload["preference"] == {"harness": "pi", "endpoint_id": "user:3"}
    assert response.headers["Cache-Control"] == "private, no-store"


def test_solve_launch_persists_outbox_and_wakes_dispatcher(
    monkeypatch,
    _queue_dispatcher,
):
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
        lambda **kwargs: sessions.append(kwargs) or kwargs,
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: (
            url_calls.append((endpoint, kwargs))
            or f"/agent/tasks/{kwargs['session_id']}"
        ),
    )

    app = _app("numoj_session")
    with app.test_request_context(
        "/agent/problems/9/solve",
        method="POST",
        json={"harness": "codex", "endpoint_id": 12},
        environ_overrides={"HTTP_COOKIE": "numoj_session=signed-session-value"},
    ):
        response = routes.agent_solve_problem(9)

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["view_url"] == f"/agent/tasks/{payload['task_id']}"
    assert url_calls[-1] == (
        "problem_core.agent_task_detail",
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
        "user_message": routes.build_solution_agent_prompt(
            problem_id=9,
            problem_title="题",
        ),
        "task_kind": "solve",
        "access_role": "user",
        "problem_id": 9,
        "problem_title": "题",
        "base_runtime_checkpoint_id": payload["task_id"],
        "base_native_session_id": "",
    }]
    assert task.calls == []
    assert _queue_dispatcher.calls == [{
        "args": (payload["task_id"],),
        "task_id": None,
    }]
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


def test_testdata_launch_creates_admin_session_with_standard_solution_attachment(
    monkeypatch,
    _queue_dispatcher,
):
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
        lambda **kwargs: sessions.append(kwargs) or kwargs,
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda endpoint, **kwargs: (
            url_calls.append((endpoint, kwargs))
            or f"/agent/tasks/{kwargs['session_id']}"
        ),
    )

    app = _app()
    with app.test_request_context(
        "/agent/problems/9/generate-testdata",
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
        response = routes.agent_generate_testdata(9)

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["view_url"] == f"/agent/tasks/{payload['task_id']}"
    assert url_calls[-1] == (
        "problem_core.agent_task_detail",
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
        "user_message": routes.build_testdata_agent_prompt(
            problem_id=9,
            problem_title="题",
            test_point_count=4,
            data_requirement=requirement,
        ),
        "attachments": [{
            "name": "standard_solution.py",
            "path": (
                f"attachments/{payload['task_id']}/standard_solution.py"
            ),
        }],
        "task_kind": "testdata",
        "access_role": "admin",
        "problem_id": 9,
        "problem_title": "题",
        "base_runtime_checkpoint_id": payload["task_id"],
        "base_native_session_id": "",
    }]
    assert task.calls == []
    assert _queue_dispatcher.calls == [{
        "args": (payload["task_id"],),
        "task_id": None,
    }]


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
            f"/agent/tasks/{kwargs['session_id']}"
            if endpoint == "problem_core.agent_task_detail"
            else "/unexpected"
        ),
    )
    app = _app()
    with app.test_request_context("/admin/agent_tasks?task_id=task-1"):
        response = routes.admin_agent_tasks()
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/agent/tasks/session-1")

    with app.test_request_context("/api/agent/sessions?task_id=missing"):
        payload = routes.admin_agent_tasks().get_json()
    assert payload["agent_sessions"] == []
    assert payload["current_page"] == 1
    assert payload["total_pages"] == 1


def test_legacy_agent_run_page_route_is_removed():
    app = _app()
    app.register_blueprint(routes.problem_core_bp)
    rules = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/admin/agent_run/<task_id>" not in rules
    assert "/agent/runs/<task_id>/state" in rules
    assert "/agent/runs/<task_id>/stream" in rules
    assert "/agent/runs/<task_id>/cancel" in rules


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
                "message": "任务已被手动终止",
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
        "message": "任务已被手动终止",
        "state": {
            "task_id": "task-1",
            "status": "Canceled",
            "message": "任务已被手动终止",
            "session_token_usage": None,
            "context_usage": {
                "used_tokens": None,
                "window_tokens": routes.DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
            },
        },
        "session_state": None,
    }


def test_agent_run_cancel_returns_whole_session_token_usage(monkeypatch):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "_terminate_agent_run",
        lambda _task_id: {
            "exists": True,
            "changed": True,
            "canceled": True,
            "errors": [],
            "state": {
                "task_id": "turn-2",
                "session_id": "session-1",
                "harness": "codex",
                "status": "Canceled",
                "message": "任务已被手动终止",
                "execution_trace": {"token_usage": {
                    "source": "codex",
                    "request_count": 1,
                    "input_uncached_tokens": 60,
                    "input_cached_tokens": 15,
                    "input_cache_write_tokens": 0,
                    "output_tokens": 8,
                    "cost_rmb": "0.08",
                }},
            },
        },
    )
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda session_id, task_id: [("turn-1", {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 5,
            "output_tokens": 10,
            "cost_rmb": "0.10",
        })],
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_run_cancel/turn-2",
        method="POST",
    ):
        response = routes.admin_agent_run_cancel("turn-2")

    usage = response.get_json()["state"]["session_token_usage"]
    assert usage["request_count"] == 2
    assert usage["input_total_tokens"] == 200
    assert usage["input_cached_tokens"] == 35
    assert usage["output_tokens"] == 18
    assert usage["cost_rmb"] == "0.18"


def test_old_session_without_trace_usage_uses_ledger_summary(monkeypatch):
    ledger_usage = {
        "source": "session",
        "request_count": 3,
        "turn_count": 1,
        "input_uncached_tokens": 100,
        "input_cached_tokens": 80,
        "input_cache_write_tokens": 5,
        "input_total_tokens": 185,
        "output_tokens": 20,
        "reasoning_output_tokens": 4,
        "cost_rmb": "0.42",
        "cost_complete": True,
        "_latest_context_task_id": "turn-old",
        "_latest_context_tokens": 172,
        "_latest_context_request_count": 3,
    }
    monkeypatch.setattr(
        routes,
        "get_agent_session_token_usage",
        lambda _session_id: ledger_usage,
    )
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _session_id, _task_id: [],
    )

    projected = routes._agent_state_with_loaded_session_token_usage({
        "task_id": "turn-old",
        "session_id": "session-old",
        "status": "Completed",
        "execution_trace": {"token_usage": None},
    })

    assert projected["session_token_usage"]["input_total_tokens"] == 185
    assert projected["session_token_usage"]["input_cached_tokens"] == 80
    assert projected["session_token_usage"]["output_tokens"] == 20
    assert projected["session_token_usage"]["cost_rmb"] == "0.42"
    assert projected["session_charged_amount_rmb"] == "0.42"
    assert projected["context_usage"] == {
        "used_tokens": 172,
        "window_tokens": routes.DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
    }


def test_partial_ledger_coverage_keeps_unbilled_historical_trace_usage():
    ledger_usage = {
        "source": "session",
        "request_count": 2,
        "turn_count": 1,
        "input_uncached_tokens": 70,
        "input_cached_tokens": 30,
        "input_cache_write_tokens": 0,
        "input_total_tokens": 100,
        "output_tokens": 12,
        "reasoning_output_tokens": 0,
        "cost_rmb": "0.20",
        "cost_complete": True,
        "_task_ids": ["turn-2"],
    }
    historical = [("turn-1", {
        "source": "codex",
        "request_count": 1,
        "input_uncached_tokens": 40,
        "input_cached_tokens": 10,
        "input_cache_write_tokens": 0,
        "output_tokens": 8,
        "cost_rmb": "0.10",
        "incremental": True,
    })]

    projected = routes._agent_state_with_session_token_usage(
        {
            "task_id": "turn-2",
            "execution_trace": {"token_usage": {
                "source": "codex",
                "request_count": 99,
                "input_uncached_tokens": 999,
                "input_cached_tokens": 0,
                "input_cache_write_tokens": 0,
                "output_tokens": 999,
                "cost_rmb": "99",
                "incremental": True,
            }},
        },
        historical,
        ledger_usage=ledger_usage,
    )

    usage = projected["session_token_usage"]
    assert usage["request_count"] == 3
    assert usage["turn_count"] == 2
    assert usage["input_total_tokens"] == 150
    assert usage["output_tokens"] == 20
    assert usage["cost_rmb"] == "0.3"


def test_context_usage_prefers_fresh_current_trace_over_session_totals():
    projected = routes._agent_state_with_session_token_usage(
        {
            "task_id": "turn-current",
            "context_window_tokens": 200_000,
            "execution_trace": {"token_usage": {
                "source": "codex",
                "request_count": 3,
                "input_uncached_tokens": 180,
                "input_cached_tokens": 120,
                "input_cache_write_tokens": 0,
                "output_tokens": 30,
                "last_input_total_tokens": 92,
                "last_output_tokens": 11,
                "incremental": True,
            }},
        },
        ledger_usage={
            "source": "session",
            "request_count": 8,
            "turn_count": 2,
            "input_uncached_tokens": 900,
            "input_cached_tokens": 700,
            "input_cache_write_tokens": 20,
            "output_tokens": 100,
            "cost_rmb": "0.8",
            "cost_complete": True,
            "_task_ids": ["turn-earlier", "turn-current"],
            "_latest_context_task_id": "turn-current",
            "_latest_context_tokens": 81,
            "_latest_context_request_count": 2,
        },
    )

    assert projected["session_token_usage"]["input_total_tokens"] == 1620
    assert projected["context_usage"] == {
        "used_tokens": 103,
        "window_tokens": 200_000,
    }


@pytest.mark.parametrize(
    ("source", "earlier_values", "expected_input", "expected_requests"),
    [
        ("codex", (100, 40), 200, 3),
        ("claude_code", (100, 160), 320, 4),
    ],
)
def test_superseded_task_status_keeps_whole_session_usage(
    monkeypatch,
    source,
    earlier_values,
    expected_input,
    expected_requests,
):
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda _session_id, include_superseded=False: [
            {"task_id": "turn-1"},
            {"task_id": "turn-superseded"},
            {"task_id": "turn-replacement"},
        ],
    )
    historical_usages = {
        "turn-1": {
            "source": source,
            "request_count": 1,
            "input_uncached_tokens": earlier_values[0],
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 10,
            "cost_rmb": "0.10",
            "incremental": True,
        },
        "turn-replacement": {
            "source": source,
            "request_count": 2 if source == "claude_code" else 1,
            "input_uncached_tokens": earlier_values[1],
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 20,
            "cost_rmb": "0.20",
            "incremental": True,
        },
    }
    monkeypatch.setattr(
        routes,
        "get_agent_run_by_task_id",
        lambda task_id: {
            "task_id": task_id,
            "execution_trace": {"token_usage": historical_usages[task_id]},
        },
    )
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    superseded = {
        "task_id": "turn-superseded",
        "session_id": "session-1",
        "execution_trace": {"token_usage": {
            "source": source,
            "request_count": 1,
            "input_uncached_tokens": 60,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 15,
            "cost_rmb": "0.30",
            "incremental": True,
        }},
    }

    projected = routes._agent_state_with_loaded_session_token_usage(
        superseded
    )

    usage = projected["session_token_usage"]
    assert usage["input_uncached_tokens"] == expected_input
    assert usage["request_count"] == expected_requests
    assert usage["cost_rmb"] == "0.6"


@pytest.mark.parametrize(
    ("task_id", "session_current_task_id", "expected_cost"),
    [
        ("turn-superseded", "turn-replacement", "0.2"),
        ("turn-replacement", "turn-replacement", "0.2"),
    ],
)
def test_historical_usage_failure_keeps_requested_session_task_usage(
    monkeypatch,
    task_id,
    session_current_task_id,
    expected_cost,
):
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _session_id, _task_id: (_ for _ in ()).throw(
            RuntimeError("history unavailable")
        ),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda _task_id: {
            "session_id": "session-1",
            "current_task_id": session_current_task_id,
        },
    )
    state = {
        "task_id": task_id,
        "session_id": "session-1",
        "execution_trace": {"token_usage": {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 0,
            "output_tokens": 10,
            "cost_rmb": "0.20",
        }},
    }

    projected = routes._agent_state_with_loaded_session_token_usage(state)

    usage = projected["session_token_usage"]
    if expected_cost is None:
        assert usage is None
    else:
        assert usage["request_count"] == 1
        assert usage["input_total_tokens"] == 120
        assert usage["output_tokens"] == 10
        assert usage["cost_rmb"] == expected_cost


@pytest.mark.parametrize("operation", ["status", "cancel"])
def test_agent_status_and_cancel_keep_v2_task_local_public_timeline(
    monkeypatch,
    operation,
):
    current = [
        {"kind": "assistant", "text": "阶段进展"},
        {
            "kind": "work_summary",
            "block_id": "work-1234567890abcdef",
            "summary": "工作中…2 thinkings, 1 tool call",
        },
    ]
    token_usage = {"source": "pi", "request_count": 2}
    state = {
        "task_id": "turn-2",
        "session_id": "session-1",
        "harness": "pi",
        "status": "Canceled" if operation == "cancel" else "Running",
        "execution_trace": {
            "schema_version": 2,
            "status": "error" if operation == "cancel" else "running",
            "trace_messages": current,
            "token_usage": token_usage,
        },
    }
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _sid, _tid: [],
    )
    if operation == "status":
        monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: state)
    else:
        monkeypatch.setattr(
            routes,
            "_terminate_agent_run",
            lambda _tid: {
                "exists": True,
                "changed": True,
                "canceled": True,
                "errors": [],
                "state": state,
            },
        )

    app = _app()
    path = f"/admin/agent_run_{operation}/turn-2"
    with app.test_request_context(
        path,
        method="POST" if operation == "cancel" else "GET",
    ):
        response = (
            routes.admin_agent_run_cancel("turn-2")
            if operation == "cancel"
            else routes.admin_agent_run_status("turn-2")
        )

    projected = response.get_json()["state"]
    projected_messages = projected["execution_trace"]["trace_messages"]
    assert [message["kind"] for message in projected_messages] == [
        "assistant", "work_summary",
    ]
    assert projected_messages[0]["text"] == "阶段进展"
    assert projected_messages[1]["summary"].startswith("工作中…")
    assert projected["execution_trace"]["token_usage"] == token_usage


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


def test_agent_run_stream_includes_historical_and_current_session_usage(
    monkeypatch,
):
    current = {
        "task_id": "turn-2",
        "session_id": "session-1",
        "status": "Completed",
        "execution_trace": {"token_usage": {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 60,
            "input_cached_tokens": 15,
            "input_cache_write_tokens": 0,
            "output_tokens": 8,
            "cost_rmb": "0.08",
        }},
    }

    class PubSub:
        closed = False

        def get_message(self, **_kwargs):
            raise AssertionError("首个快照已经终止，不应继续等待")

        def close(self):
            self.closed = True

    pubsub = PubSub()
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: current)
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _tid: pubsub)
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda session_id, task_id: [("turn-1", {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 5,
            "output_tokens": 10,
            "cost_rmb": "0.10",
        })],
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/turn-2"):
        body = routes.admin_agent_run_stream("turn-2").get_data(as_text=True)

    status_data = next(
        line.removeprefix("data: ")
        for line in body.splitlines()
        if line.startswith("data: ")
    )
    state = json.loads(status_data)
    usage = state["session_token_usage"]
    assert usage["request_count"] == 2
    assert usage["input_total_tokens"] == 200
    assert usage["input_cached_tokens"] == 35
    assert usage["output_tokens"] == 18
    assert usage["cost_rmb"] == "0.18"
    assert pubsub.closed is True


def test_agent_run_stream_emits_live_usage_and_cost_updates(monkeypatch):
    initial_usage = {
        "source": "codex",
        "request_count": 1,
        "input_uncached_tokens": 80,
        "input_cached_tokens": 20,
        "input_cache_write_tokens": 0,
        "input_total_tokens": 100,
        "output_tokens": 10,
        "reasoning_output_tokens": 0,
        "cost_rmb": "0.10",
        "incremental": True,
    }
    updated_usage = {
        **initial_usage,
        "request_count": 2,
        "input_uncached_tokens": 140,
        "input_cached_tokens": 60,
        "input_total_tokens": 200,
        "output_tokens": 40,
    }
    initial = {
        "task_id": "turn-live-usage",
        "session_id": "session-live-usage",
        "harness": "codex",
        "status": "Running",
        "session_charged_amount_rmb": "0.10",
        "execution_trace": {
            "status": "running",
            "trace_id": "trace-live-usage",
            "trace_messages": [{"kind": "tool", "text": "working"}],
            "trace_files": [],
            "token_usage": initial_usage,
            "incremental": True,
        },
    }
    token_update = {
        **initial,
        "execution_trace": {
            **initial["execution_trace"],
            "token_usage": updated_usage,
        },
    }
    cost_update = {
        **token_update,
        "session_charged_amount_rmb": "0.25",
    }
    completed = {
        **cost_update,
        "status": "Completed",
        "execution_trace": {
            **cost_update["execution_trace"],
            "status": "passed",
        },
    }

    class PubSub:
        def __init__(self):
            self.snapshots = iter((token_update, cost_update, completed))

        def get_message(self, **_kwargs):
            return {
                "type": "message",
                "data": json.dumps(next(self.snapshots)),
            }

        def close(self):
            pass

    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: initial)
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _tid: PubSub())
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _session_id, _task_id: [],
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_token_usage",
        lambda _session_id: None,
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/turn-live-usage"):
        body = routes.admin_agent_run_stream("turn-live-usage").get_data(as_text=True)

    status_states = []
    for block in body.split("\n\n"):
        if not block.startswith("event: status\n"):
            continue
        data = next(
            line.removeprefix("data: ")
            for line in block.splitlines()
            if line.startswith("data: ")
        )
        status_states.append(json.loads(data))

    assert len(status_states) == 4
    assert status_states[1]["session_token_usage"]["input_total_tokens"] == 200
    assert status_states[1]["session_token_usage"]["input_cached_tokens"] == 60
    assert status_states[1]["session_token_usage"]["output_tokens"] == 40
    assert status_states[2]["session_token_usage"]["cost_rmb"] == "0.25"


@pytest.mark.parametrize(
    ("initial_cost", "updated_cost", "expected_ledger_calls"),
    [("0.10", "0.25", 2), ("0", "0", 3)],
)
def test_agent_run_stream_uses_live_ledger_when_trace_has_no_usage(
    monkeypatch,
    initial_cost,
    updated_cost,
    expected_ledger_calls,
):
    initial = {
        "task_id": "turn-ledger-live",
        "session_id": "session-ledger-live",
        "harness": "pi",
        "status": "Running",
        "session_charged_amount_rmb": initial_cost,
        "execution_trace": {
            "status": "running",
            "trace_id": "trace-ledger-live",
            "trace_messages": [{"kind": "tool", "text": "working"}],
            "trace_files": [],
            "token_usage": None,
        },
    }
    updated = {
        **initial,
        "session_charged_amount_rmb": updated_cost,
        "execution_trace": {
            **initial["execution_trace"],
            "trace_messages": [
                *initial["execution_trace"]["trace_messages"],
                {"kind": "tool_result", "text": "next"},
            ],
        },
    }
    completed = {
        **updated,
        "status": "Completed",
        "execution_trace": {
            **updated["execution_trace"],
            "status": "passed",
        },
    }
    usage_before = {
        "source": "session",
        "request_count": 1,
        "turn_count": 1,
        "input_uncached_tokens": 80,
        "input_cached_tokens": 20,
        "input_cache_write_tokens": 0,
        "input_total_tokens": 100,
        "output_tokens": 10,
        "reasoning_output_tokens": 0,
        "cost_rmb": initial_cost,
        "cost_complete": True,
    }
    usage_after = {
        **usage_before,
        "request_count": 2,
        "input_uncached_tokens": 140,
        "input_cached_tokens": 60,
        "input_total_tokens": 200,
        "output_tokens": 40,
        "cost_rmb": updated_cost,
    }

    class PubSub:
        def __init__(self):
            self.snapshots = iter((updated, completed))

        def get_message(self, **_kwargs):
            return {
                "type": "message",
                "data": json.dumps(next(self.snapshots)),
            }

        def close(self):
            pass

    ledger_usages = iter(
        (usage_before, usage_after, usage_after)[:expected_ledger_calls]
    )
    ledger_calls = []
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: initial)
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _tid: PubSub())
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _session_id, _task_id: [],
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_token_usage",
        lambda session_id: ledger_calls.append(session_id) or next(ledger_usages),
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/turn-ledger-live"):
        body = routes.admin_agent_run_stream("turn-ledger-live").get_data(
            as_text=True
        )

    states = [
        json.loads(line.removeprefix("data: "))
        for line in body.splitlines()
        if line.startswith("data: ")
    ]
    assert states[0]["session_token_usage"]["input_total_tokens"] == 100
    assert states[0]["session_token_usage"]["cost_rmb"] == (
        "0.1" if initial_cost == "0.10" else "0"
    )
    assert states[1]["session_token_usage"]["input_total_tokens"] == 200
    assert states[1]["session_token_usage"]["input_cached_tokens"] == 60
    assert states[1]["session_token_usage"]["output_tokens"] == 40
    assert states[-1]["session_token_usage"]["cost_rmb"] == (
        "0.25" if updated_cost == "0.25" else "0"
    )
    assert ledger_calls == ["session-ledger-live"] * expected_ledger_calls


def test_agent_run_stream_keeps_v2_public_timeline_task_local(monkeypatch):
    running_messages = [
        {"kind": "assistant", "text": "我正在检查数据"},
        {
            "kind": "work_summary",
            "block_id": "work-1234567890abcdef",
            "thinking_count": 2,
            "tool_count": 1,
            "is_running": True,
            "summary": "工作中…2 thinkings, 1 tool call",
        },
    ]
    completed_messages = [
        running_messages[0],
        {
            **running_messages[1],
            "thinking_count": 4,
            "tool_count": 3,
            "is_running": False,
            "summary": "4 thinkings, 3 tool calls",
        },
    ]
    token_usage = {
        "source": "pi",
        "request_count": 2,
        "input_uncached_tokens": 80,
        "input_cached_tokens": 10,
        "input_cache_write_tokens": 0,
        "output_tokens": 12,
    }
    initial = {
        "task_id": "turn-2",
        "session_id": "session-1",
        "harness": "pi",
        "status": "Running",
        "execution_trace": {
            "schema_version": 2,
            "status": "running",
            "trace_messages": running_messages,
            "token_usage": token_usage,
        },
    }
    completed = {
        **initial,
        "status": "Completed",
        "conclusion": "检查已经完成",
        "execution_trace": {
            "schema_version": 2,
            "status": "passed",
            "trace_messages": completed_messages,
            "token_usage": token_usage,
        },
    }

    class PubSub:
        closed = False

        def get_message(self, **_kwargs):
            return {"type": "message", "data": json.dumps(completed)}

        def close(self):
            self.closed = True

    pubsub = PubSub()
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: initial)
    monkeypatch.setattr(routes, "_subscribe_agent_run_events", lambda _tid: pubsub)
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(routes, "render_rich_markdown", lambda text: f"<p>{text}</p>")
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _sid, _tid: [],
    )

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/turn-2"):
        body = routes.admin_agent_run_stream("turn-2").get_data(as_text=True)

    snapshots = [
        json.loads(line.removeprefix("data: "))
        for line in body.splitlines()
        if line.startswith("data: ")
    ]
    assert [
        len(snapshot["execution_trace"]["trace_messages"])
        for snapshot in snapshots
    ] == [2, 2, 2]
    assert snapshots[1]["execution_trace"]["trace_messages"][1][
        "thinking_count"
    ] == 4
    assert snapshots[1]["execution_trace"]["token_usage"] == token_usage
    assert snapshots[1]["session_token_usage"]["request_count"] == 2
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


def test_agent_run_stream_detects_new_message_after_trace_reaches_cap(
    monkeypatch,
):
    prefix = [
        {"kind": "thinking", "text": f"step-{index}"}
        for index in range(239)
    ]
    first = {
        "task_id": "task-trace-cap",
        "status": "Running",
        "message": "Agent 正在工作",
        "updated_at": "2026-08-17 12:00:00",
        "execution_trace": {
            "status": "running",
            "trace_id": "trace-cap",
            "trace_messages": [
                *prefix,
                {"kind": "user", "message_id": "steer-old", "text": "旧插话"},
            ],
            "trace_files": [],
            "token_usage": None,
        },
    }
    second = {
        **first,
        "execution_trace": {
            **first["execution_trace"],
            "trace_messages": [
                *prefix,
                {"kind": "user", "message_id": "steer-new", "text": "新插话"},
            ],
        },
    }
    completed = {
        **second,
        "status": "Completed",
        "execution_trace": {**second["execution_trace"], "status": "passed"},
    }
    states = iter((first, second, completed))

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
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: next(states),
    )
    monkeypatch.setattr(
        routes,
        "_subscribe_agent_run_events",
        lambda _task_id: PubSub(),
    )
    monkeypatch.setattr(routes.time, "sleep", lambda _seconds: None)

    app = _app()
    with app.test_request_context("/admin/agent_run_stream/task-trace-cap"):
        body = routes.admin_agent_run_stream(
            "task-trace-cap"
        ).get_data(as_text=True)

    assert body.count("event: status") == 3
    assert "steer-new" in body
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


def test_agent_state_markdown_only_projects_public_v2_items(monkeypatch):
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
            "subagents": [
                {
                    "subagent_id": "worker-a",
                    "name": "核对官方文档",
                    "status": "completed",
                    "private_trace": "不应公开",
                },
                {
                    "subagent_id": "../escape",
                    "name": "非法",
                    "status": "running",
                },
            ],
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
    assert len(messages) == 1
    assert state["execution_trace"]["subagents"] == [{
        "subagent_id": "worker-a",
        "name": "核对官方文档",
        "status": "completed",
    }]
    assert state["conclusion"] == "**最终结论**"
    assert state["conclusion_html"] == "<safe>**最终结论**</safe>"
    assert "conclusion_html" not in state["execution_trace"]
    assert raw["conclusion_html"] == "<script>unsafe()</script>"
    assert raw["execution_trace"]["trace_messages"][0]["html"] == "<b>伪造</b>"
    assert rendered == ["**回答**", "**最终结论**"]


def test_failed_agent_state_keeps_failure_reason_over_trace_conclusion(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<safe>{text}</safe>",
    )

    state = routes._decorate_agent_state_markdown({
        "status": "Failed",
        "conclusion": "测试数据发布失败",
        "execution_trace": {
            "trace_messages": [
                {"kind": "assistant", "text": "候选数据已经生成。"},
            ],
        },
    })

    assert state["conclusion"] == "测试数据发布失败"
    assert state["conclusion_html"] == "<safe>测试数据发布失败</safe>"


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
        "get_last_agent_trace_assistant",
        lambda _task_id: "结论含公式 $x^2$",
    )
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


def test_agent_work_block_endpoint_returns_only_the_requested_internal_block(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    authorized = []
    monkeypatch.setattr(
        routes,
        "_agent_task_for_actor",
        lambda task_id, actor, **kwargs: authorized.append(
            (task_id, actor["username"], kwargs)
        ),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_trace_work_block",
        lambda task_id, block_id: {
            "block_id": block_id,
            "messages": [
                {"kind": "thinking", "text": "核对 $x^2$"},
                {"kind": "tool", "title": "已运行命令", "text": "rg trace"},
            ],
        },
    )
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<safe>{text}</safe>",
    )

    app = _app()
    with app.test_request_context(
        "/agent/runs/task-1/work-blocks/work-1234567890abcdef"
    ):
        response = routes.agent_run_work_block(
            "task-1", "work-1234567890abcdef"
        )

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["block"]["block_id"] == "work-1234567890abcdef"
    assert payload["block"]["messages"][0]["html"] == "<safe>核对 $x^2$</safe>"
    assert "html" not in payload["block"]["messages"][1]
    assert authorized == [(
        "task-1",
        "admin",
        {"allow_unknown_for_admin": True},
    )]


def test_agent_run_state_overlays_session_cleanup_failure_on_sticky_cancel(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "cleanup-task",
            "status": "Canceled",
            "message": "任务已被手动终止",
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
                    "message": "任务已被手动终止",
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
        "message": "任务已被手动终止",
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
    assert state["message"] == "任务已被手动终止"


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
            "message": "任务已被手动终止",
            "attempts": [],
        },
    )

    state = routes._get_agent_run_state("task-canceled")

    assert state["status"] == "Canceled"
    assert state["message"] == "任务已被手动终止"
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


def test_agent_run_state_reuses_worker_projected_redis_trace(monkeypatch):
    trace = {
        "schema_version": 2,
        "status": "running",
        "trace_messages": [{
            "kind": "work_summary",
            "block_id": "work-1234567890abcdef",
            "summary": "工作中…1 thinking",
        }],
        "trace_files": [],
        "token_usage": None,
    }
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "task-cached-trace",
            "status": "Running",
            "execution_trace": trace,
        },
    )
    monkeypatch.setattr(routes, "get_agent_run_by_task_id", lambda _task_id: None)
    monkeypatch.setattr(routes, "_agent_solve_problem_task", None)
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda _state: pytest.fail("Redis 已有 v2 公开轨迹时不应再次查询数据库"),
    )

    state = routes._get_agent_run_state("task-cached-trace")

    assert state["execution_trace"]["trace_messages"][0]["summary"].startswith(
        "工作中…"
    )


def test_agent_run_state_hydrates_empty_worker_trace_from_v2_store(monkeypatch):
    empty_trace = {
        "status": "running",
        "trace_messages": [],
        "trace_files": [],
        "token_usage": None,
    }
    journal_trace = {
        **empty_trace,
        "schema_version": 2,
        "trace_messages": [{
            "kind": "work_summary",
            "block_id": "work-1234567890abcdef",
            "summary": "工作中…1 thinking",
        }],
        "token_usage": {
            "source": "codex",
            "input_total_tokens": 120,
            "input_cached_tokens": 80,
            "output_tokens": 20,
        },
    }
    monkeypatch.setattr(
        routes,
        "_get_agent_run_snapshot",
        lambda _task_id: {
            "task_id": "task-empty-cached-trace",
            "status": "Running",
            "execution_trace": empty_trace,
        },
    )
    monkeypatch.setattr(routes, "get_agent_run_by_task_id", lambda _task_id: None)
    monkeypatch.setattr(routes, "_agent_solve_problem_task", None)
    hydrated = []
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda state: hydrated.append(state) or {
            **state,
            "execution_trace": journal_trace,
        },
    )

    state = routes._get_agent_run_state("task-empty-cached-trace")

    assert len(hydrated) == 1
    assert state["execution_trace"]["trace_messages"][0]["kind"] == "work_summary"
    assert state["execution_trace"]["token_usage"]["input_cached_tokens"] == 80


def test_agent_run_stream_skips_duplicate_snapshot_before_markdown(monkeypatch):
    running = {
        "task_id": "task-stream-dedup",
        "status": "Running",
        "execution_trace": {
            "status": "running",
            "trace_id": "trace-1",
            "trace_messages": [{"kind": "thinking", "text": "正在分析"}],
            "trace_files": [],
            "token_usage": None,
        },
    }
    completed = {
        **running,
        "status": "Completed",
        "execution_trace": {
            **running["execution_trace"],
            "status": "passed",
            "trace_messages": [{"kind": "assistant", "text": "已经完成"}],
        },
    }

    class PubSub:
        def __init__(self):
            self.snapshots = iter((running, completed))

        def get_message(self, **_kwargs):
            return {
                "type": "message",
                "data": json.dumps(next(self.snapshots)),
            }

        def close(self):
            pass

    rendered = []
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 7, "username": "admin", "is_admin": 1},
    )
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _task_id: running)
    monkeypatch.setattr(
        routes,
        "_subscribe_agent_run_events",
        lambda _task_id: PubSub(),
    )
    hydrated = []
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda state: hydrated.append(state) or state,
    )
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: rendered.append(text) or f"<p>{text}</p>",
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_run_stream/task-stream-dedup"
    ):
        body = routes.admin_agent_run_stream(
            "task-stream-dedup"
        ).get_data(as_text=True)

    assert body.count("event: status") == 2
    assert "event: done" in body
    assert [state["status"] for state in hydrated] == ["Completed"]
    assert rendered == ["已经完成"]
