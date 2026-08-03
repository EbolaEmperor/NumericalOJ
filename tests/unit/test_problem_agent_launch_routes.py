import io
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
            "model": "selected-model",
            "protocol": "openai",
            "category": "text",
        },
    )
    monkeypatch.setattr(
        routes,
        "save_agent_launch_preference",
        lambda *args: saved.append(args),
    )
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", snapshots.append)
    monkeypatch.setattr(routes, "url_for", lambda *_args, **kwargs: f"/run/{kwargs['task_id']}")

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
    assert saved == [(7, "codex", 12)]
    assert len(task.calls) == 1
    assert task.calls[0]["args"] == (
        9,
        "admin",
        "codex",
        12,
        "signed-session-value",
        "numoj_session",
    )
    assert snapshots[0]["harness"] == "codex"
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
            "id": int(endpoint_id), "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(routes, "url_for", lambda *_args, **kwargs: f"/run/{kwargs['task_id']}")

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        data={
            "harness": "pi",
            "endpoint_id": "18",
            "test_point_count": "4",
            "data_requirement": "覆盖边界",
            "standard_solution": (
                io.BytesIO("print(1)\n".encode()),
                "正解.py",
            ),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-session-value"},
    ):
        response = routes.admin_agent_generate_testdata(9)

    assert response.get_json()["success"] is True
    assert task.calls[0]["args"] == (
        9,
        "admin",
        4,
        "print(1)\n",
        "覆盖边界",
        "standard_solution.py",
        "pi",
        18,
        "signed-session-value",
        "session",
    )


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


def test_testdata_launch_rejects_oversized_requirement_without_truncating(
    monkeypatch,
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
            "data_requirement": "x" * 4001,
            "standard_solution": (io.BytesIO(b"print(1)\n"), "answer.py"),
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 400
    assert "4000" in response.get_json()["message"]


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


def test_testdata_launch_bounds_standard_solution_file_read(monkeypatch):
    monkeypatch.setattr(routes, "_AGENT_STANDARD_SOLUTION_MAX_BYTES", 4)
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
            "standard_solution": (io.BytesIO(b"12345"), "answer.py"),
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 400
    assert "2 MiB" in response.get_json()["message"]


def test_testdata_launch_rejects_oversized_multipart_before_parsing(monkeypatch):
    monkeypatch.setattr(routes, "_AGENT_TESTDATA_REQUEST_MAX_BYTES", 256)
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
            "standard_solution": (io.BytesIO(b"x" * 512), "answer.py"),
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_generate_testdata(9)

    assert status == 413
    assert "3 MiB" in response.get_json()["message"]


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
