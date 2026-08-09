"""通用 Agent HTML 路由的创建、续聊与附件补偿契约。"""

from __future__ import annotations

import io
from types import SimpleNamespace

from flask import Flask
import pytest

from oj_modules.agents.sessions import AgentSessionBusyError
from oj_modules.routes import problem_core_routes as routes


ADMIN = {"id": 7, "username": "admin", "is_admin": 1}


class _Task:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args, task_id):
        self.calls.append({"args": args, "task_id": task_id})


def _app(cookie_name="session"):
    app = Flask(__name__)
    app.config.update(SECRET_KEY="test", SESSION_COOKIE_NAME=cookie_name)
    return app


def _session(*, task_kind="custom", access_role="admin", status="Completed"):
    return {
        "session_id": "session-1",
        "current_task_id": "turn-1",
        "title": "验证数值算法",
        "task_kind": task_kind,
        "problem_id": 9 if task_kind != "custom" else None,
        "problem_title": "数值积分" if task_kind != "custom" else None,
        "requested_by": "admin",
        "access_role": access_role,
        "harness": "codex",
        "endpoint_id": 12,
        "endpoint_revision": 3,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-session-1",
        "status": status,
        "message": "上一轮已结束",
        "turn_count": 1,
        "is_legacy": False,
    }


def _patch_admin(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: dict(ADMIN))


def test_task_id_query_redirects_historical_turn_to_owning_session(monkeypatch):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(
        routes,
        "get_agent_sessions_paginated",
        lambda **_kwargs: ([], 1, 1),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_by_task_id",
        lambda task_id: (
            {"session_id": "session-1"} if task_id == "turn-historical" else None
        ),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _session_id: pytest.fail("task lookup 已命中，不应再次回退查询"),
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

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks?task_id=turn-historical",
    ):
        response = routes.admin_agent_tasks()

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/agent_tasks/session-1")


def test_custom_session_creation_binds_role_endpoint_workspace_and_title_turn(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    task = _Task()
    monkeypatch.setattr(routes, "_agent_run_turn_task", task)
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="session-new"))
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "revision": 3,
            "model": "selected-model",
        },
    )
    preference_calls = []
    workspace_calls = []
    create_calls = []
    snapshots = []
    monkeypatch.setattr(
        routes,
        "save_agent_launch_preference",
        lambda *args: preference_calls.append(args),
    )
    monkeypatch.setattr(
        routes,
        "ensure_agent_workspace",
        lambda session_id: workspace_calls.append(session_id),
    )
    attachments = [{
        "name": "notes.txt",
        "path": "attachments/session-new/notes.txt",
        "size": 4,
    }]
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda session_id, task_id, uploads: attachments,
    )
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: create_calls.append(kwargs) or {
            **_session(task_kind="custom", access_role="admin"),
            "session_id": "session-new",
            "current_task_id": "session-new",
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _session_id: {
            **_session(task_kind="custom", access_role="admin"),
            "session_id": "session-new",
            "current_task_id": "session-new",
        },
    )
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", snapshots.append)
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda _endpoint, **kwargs: f"/admin/agent_tasks/{kwargs['session_id']}",
    )

    app = _app("numoj_session")
    with app.test_request_context(
        "/admin/agent_tasks",
        method="POST",
        data={
            "message": "分析附件并给出验证程序",
            "harness": "codex",
            "endpoint_id": "12",
            "access_role": "admin",
            "attachments": (io.BytesIO(b"note"), "notes.txt"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "numoj_session=signed-cookie"},
    ):
        response = routes.admin_agent_tasks()

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["session_id"] == "session-new"
    assert payload["detail_url"] == "/admin/agent_tasks/session-new"
    assert preference_calls == [(7, "codex", 12)]
    assert workspace_calls == ["session-new"]
    assert create_calls[0]["task_kind"] == "custom"
    assert create_calls[0]["access_role"] == "admin"
    assert create_calls[0]["endpoint_revision"] == 3
    assert create_calls[0]["attachments"] == attachments
    assert task.calls == [{
        "task_id": "session-new",
        "args": (
            "session-new",
            "admin",
            "admin",
            "codex",
            12,
            "signed-cookie",
            (
                "分析附件并给出验证程序\n\n"
                "用户随本轮消息上传了以下附件，文件已经放入 workspace。"
                "请在需要时直接读取：\n"
                "- /workspace/attachments/session-new/notes.txt"
            ),
            "numoj_session",
            "",
            True,
        ),
    }]
    assert snapshots[0]["session_id"] == "session-new"
    assert "signed-cookie" not in str(snapshots)


def test_custom_creation_removes_published_attachments_when_db_create_fails(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="session-new"))
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda _harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "ensure_agent_workspace", lambda _session_id: None)
    attachments = [{"name": "input.dat", "path": "attachments/a/input.dat"}]
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: attachments,
    )
    def fail_session_create(**_kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(
        routes,
        "create_agent_session",
        fail_session_create,
    )
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, items: removed.append((session_id, items)),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks",
        method="POST",
        data={
            "message": "读取附件",
            "harness": "codex",
            "endpoint_id": "12",
            "access_role": "user",
            "attachments": (io.BytesIO(b"data"), "input.dat"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_tasks()

    assert status == 500
    assert response.get_json()["success"] is False
    assert removed == [("session-new", attachments)]


@pytest.mark.parametrize(
    ("task_kind", "access_role"),
    [("custom", "admin"), ("solve", "user"), ("testdata", "user")],
)
def test_all_session_kinds_resume_through_the_same_fixed_runtime_contract(
    monkeypatch,
    task_kind,
    access_role,
):
    _patch_admin(monkeypatch)
    task = _Task()
    monkeypatch.setattr(routes, "_agent_run_turn_task", task)
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    agent_session = _session(task_kind=task_kind, access_role=access_role)
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: dict(agent_session))
    attachments = [{
        "name": "follow-up.txt",
        "path": "attachments/turn-2/follow-up.txt",
    }]
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: attachments,
    )
    begin_calls = []
    monkeypatch.setattr(
        routes,
        "set_agent_turn_attachments",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        routes,
        "begin_agent_session_turn",
        lambda session_id, **kwargs: (
            begin_calls.append((session_id, kwargs))
            or {
                "turn_index": 2,
                "task_kind": task_kind,
                "access_role": access_role,
                "harness": "codex",
                "endpoint_id": 12,
                "native_session_id": "native-session-authoritative",
            }
        ),
    )
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(routes, "render_rich_markdown", lambda text: f"<p>{text}</p>")

    app = _app("numoj_session")
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "message": "继续，并核对新附件",
            # 即使客户端伪造这些字段，续聊也必须沿用会话固定值。
            "harness": "pi",
            "endpoint_id": "999",
            "access_role": "admin" if access_role == "user" else "user",
            "attachments": (io.BytesIO(b"next"), "follow-up.txt"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "numoj_session=signed-cookie"},
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["turn_index"] == 2
    assert begin_calls == [("session-1", {
        "task_id": "turn-2",
        "user_message": "继续，并核对新附件",
        "attachments": [],
    })]
    assert task.calls == [{
        "task_id": "turn-2",
        "args": (
            "session-1",
            "admin",
            access_role,
            "codex",
            12,
            "signed-cookie",
            (
                "继续，并核对新附件\n\n"
                "用户随本轮消息上传了以下附件，文件已经放入 workspace。"
                "请在需要时直接读取：\n"
                "- /workspace/attachments/turn-2/follow-up.txt"
            ),
            "numoj_session",
            "native-session-authoritative",
            False,
        ),
    }]


def test_resume_race_rejects_before_attachments_become_public(monkeypatch):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-racing"))
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: pytest.fail("CAS 失败前不得发布附件"),
    )
    monkeypatch.setattr(
        routes,
        "begin_agent_session_turn",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AgentSessionBusyError("上一轮 Agent 任务尚未结束")
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "message": "并发续聊",
            "attachments": (io.BytesIO(b"race"), "race.txt"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 409
    assert response.get_json()["message"] == "上一轮 Agent 任务尚未结束"


def test_cleanup_failed_session_is_blocked_before_accepting_attachments(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _sid: _session(status="CleanupFailed"),
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: pytest.fail("CleanupFailed 会话不应接收新附件"),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "继续"},
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 409
    assert "尚未结束" in response.get_json()["message"]


def test_session_without_native_resume_point_is_blocked_before_attachments(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    session = _session(status="Failed")
    session["native_session_id"] = ""
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: session)
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: pytest.fail("没有原生恢复点时不应接收新附件"),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "继续"},
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 409
    assert "未建立可恢复的原生会话" in response.get_json()["message"]


def test_specialized_solve_launch_creates_a_resumable_user_session(monkeypatch):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_solve_problem_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="solve-1"))
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {"id": 9, "title": "数值积分", "type": 1},
    )
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda _harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    create_calls = []
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: create_calls.append(kwargs),
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda _endpoint, **kwargs: f"/admin/agent_tasks/{kwargs['session_id']}",
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_solve_problem/9",
        method="POST",
        json={"harness": "codex", "endpoint_id": 12},
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response = routes.admin_agent_solve_problem(9)

    assert response.get_json()["view_url"] == "/admin/agent_tasks/solve-1"
    assert create_calls[0]["session_id"] == "solve-1"
    assert create_calls[0]["task_id"] == "solve-1"
    assert create_calls[0]["task_kind"] == "solve"
    assert create_calls[0]["access_role"] == "user"
    assert create_calls[0]["problem_id"] == 9


def test_specialized_testdata_launch_creates_a_resumable_user_session(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_generate_testdata_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="testdata-1"))
    monkeypatch.setattr(
        routes,
        "get_problem",
        lambda _pid: {
            "id": 9,
            "title": "数值积分",
            "type": 1,
            "programming_grading_mode": 1,
        },
    )
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda _harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    create_calls = []
    monkeypatch.setattr(
        routes,
        "create_agent_session",
        lambda **kwargs: create_calls.append(kwargs),
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda _endpoint, **kwargs: f"/admin/agent_tasks/{kwargs['session_id']}",
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_generate_testdata/9",
        method="POST",
        data={
            "harness": "codex",
            "endpoint_id": "12",
            "test_point_count": "4",
            "data_requirement": "覆盖病态输入",
            "standard_solution": (io.BytesIO(b"print(1)\n"), "answer.py"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response = routes.admin_agent_generate_testdata(9)

    assert response.get_json()["view_url"] == "/admin/agent_tasks/testdata-1"
    assert create_calls[0]["session_id"] == "testdata-1"
    assert create_calls[0]["task_id"] == "testdata-1"
    assert create_calls[0]["task_kind"] == "testdata"
    assert create_calls[0]["access_role"] == "user"
    assert create_calls[0]["problem_id"] == 9


def test_detail_get_renders_new_conversation_page_with_workspace(monkeypatch):
    _patch_admin(monkeypatch)
    agent_session = _session()
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda _sid: [{"task_id": "turn-1", "status": "Completed"}],
    )
    monkeypatch.setattr(routes, "_decorate_agent_turns", lambda turns: turns)
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: {"task_id": "turn-1", "status": "Completed"},
    )
    monkeypatch.setattr(
        routes,
        "build_agent_workspace_tree",
        lambda _sid: [{"name": "answer.py", "type": "file"}],
    )
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_template",
        lambda template, **context: rendered.append((template, context)) or "detail",
    )

    app = _app()
    with app.test_request_context("/admin/agent_tasks/session-1"):
        response = routes.admin_agent_task_detail("session-1")

    assert response.get_data(as_text=True) == "detail"
    assert response.headers["Cache-Control"] == "private, no-store"
    assert rendered[0][0] == "admin/agent_task_detail.html"
    assert rendered[0][1]["agent_session"] == agent_session
    assert rendered[0][1]["can_resume"] is True
    assert rendered[0][1]["workspace_tree"] == [
        {"name": "answer.py", "type": "file"},
    ]


def test_detail_get_exposes_cumulative_session_usage_without_pi_resume_double_count(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    agent_session = _session()
    agent_session.update(current_task_id="turn-2", turn_count=2)
    turns = [
        {
            "task_id": "turn-1",
            "status": "Completed",
            "execution_trace": {"token_usage": {
                "source": "pi",
                "request_count": 1,
                "input_uncached_tokens": 100,
                "input_cached_tokens": 20,
                "input_cache_write_tokens": 0,
                "output_tokens": 10,
                "cost_rmb": "0.10",
            }},
        },
        {"task_id": "turn-2", "status": "Running"},
    ]
    current_state = {
        "task_id": "turn-2",
        "session_id": "session-1",
        "status": "Running",
        # Pi 第二轮实时 trace 已包含首轮，不应与历史基线相加。
        "execution_trace": {"token_usage": {
            "source": "pi",
            "request_count": 2,
            "input_uncached_tokens": 180,
            "input_cached_tokens": 50,
            "input_cache_write_tokens": 5,
            "output_tokens": 25,
            "cost_rmb": "0.25",
        }},
    }
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(routes, "get_agent_session_turns", lambda _sid: turns)
    monkeypatch.setattr(routes, "_decorate_agent_turns", lambda values: values)
    monkeypatch.setattr(routes, "_get_agent_run_state", lambda _tid: current_state)
    monkeypatch.setattr(
        routes,
        "_load_agent_historical_token_usages",
        lambda _sid, _tid: [("turn-1", turns[0]["execution_trace"]["token_usage"])],
    )
    monkeypatch.setattr(routes, "build_agent_workspace_tree", lambda _sid: [])
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_template",
        lambda template, **context: rendered.append((template, context)) or "detail",
    )

    app = _app()
    with app.test_request_context("/admin/agent_tasks/session-1"):
        routes.admin_agent_task_detail("session-1")

    usage = rendered[0][1]["current_state"]["session_token_usage"]
    assert usage["request_count"] == 2
    assert usage["input_total_tokens"] == 235
    assert usage["input_cached_tokens"] == 50
    assert usage["output_tokens"] == 25
    assert usage["cost_rmb"] == "0.25"


def test_ordered_pi_turns_render_only_each_resume_trace_delta_and_keep_nonempty_baseline(
    monkeypatch,
):
    first_messages = [
        {
            "kind": "tool",
            "title": "运行命令",
            "text": f"command-{index}",
            "line": index + 1,
            "offset": index * 100,
            "source": "pi-first",
            "html": "<b>不可信</b>",
        }
        for index in range(39)
    ]
    copied_prefix = [
        {
            **message,
            # resume 后日志位置和服务端 HTML 可以变化，但不影响语义 LCP。
            "line": int(message["line"]) + 900,
            "offset": int(message["offset"]) + 100_000,
            "source": "pi-resume",
            "html": "<i>仍不可信</i>",
        }
        for message in first_messages
    ]
    second_messages = copied_prefix + [
        {
            "kind": "assistant",
            "title": "AI 回复",
            "text": f"second-{index}",
            "meta": "deepseek-v4-flash",
        }
        for index in range(24)
    ]
    fourth_messages = second_messages + [
        {"kind": "assistant", "title": "AI 回复", "text": "fourth-0"},
        {"kind": "assistant", "title": "AI 回复", "text": "fourth-1"},
    ]
    traces = {
        "turn-1": first_messages,
        "turn-2": second_messages,
        # 入队/运行失败且没有 trace 时不能把第二轮完整轨迹 baseline 清空。
        "turn-3": [],
        "turn-4": fourth_messages,
    }

    def hydrate(state):
        return {
            **state,
            "execution_trace": {
                "trace_messages": traces[state["task_id"]],
                "token_usage": {"source": "pi", "request_count": 4},
            },
        }

    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", hydrate)
    monkeypatch.setattr(routes, "render_rich_markdown", lambda text: f"<p>{text}</p>")
    turns = routes._decorate_agent_turns([
        {
            "task_id": f"turn-{index}",
            "turn_index": index,
            "harness": "pi",
            "status": "Completed" if index != 3 else "Failed",
            "user_message": f"message-{index}",
        }
        for index in range(1, 5)
    ])

    deltas = [
        turn["execution_trace"]["trace_messages"]
        for turn in turns
    ]
    assert [len(messages) for messages in deltas] == [39, 24, 0, 2]
    assert deltas[1][0]["text"] == "second-0"
    assert deltas[3][0]["text"] == "fourth-0"
    assert turns[1]["execution_trace"]["token_usage"] == {
        "source": "pi",
        "request_count": 4,
    }


@pytest.mark.parametrize("harness", ["codex", "opencode"])
def test_incremental_harness_trace_is_not_resume_filtered(harness):
    previous = [{"kind": "assistant", "text": "first"}]
    current = previous + [{"kind": "assistant", "text": "second"}]
    state = {
        "harness": harness,
        "execution_trace": {
            "trace_messages": current,
            "token_usage": {"source": harness, "request_count": 1},
        },
    }

    assert routes._agent_state_with_trace_delta(
        state,
        previous,
        harness,
    ) is state
    assert state["execution_trace"]["trace_messages"] == current


def test_detail_get_marks_another_admin_session_read_only(monkeypatch):
    _patch_admin(monkeypatch)
    agent_session = _session()
    agent_session["requested_by"] = "another-admin"
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(routes, "get_agent_session_turns", lambda _sid: [])
    monkeypatch.setattr(routes, "_decorate_agent_turns", lambda turns: turns)
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: {"task_id": "turn-1", "status": "Completed"},
    )
    monkeypatch.setattr(routes, "build_agent_workspace_tree", lambda _sid: [])
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_template",
        lambda template, **context: rendered.append((template, context)) or "detail",
    )

    app = _app()
    with app.test_request_context("/admin/agent_tasks/session-1"):
        response = routes.admin_agent_task_detail("session-1")

    assert response.get_data(as_text=True) == "detail"
    assert rendered[0][1]["can_resume"] is False


def test_detail_refresh_keeps_cleanup_failed_session_blocked_over_sticky_cancel(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    agent_session = _session(status="CleanupFailed")
    agent_session["message"] = "容器清理状态未知"
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(routes, "get_agent_session_turns", lambda _sid: [])
    monkeypatch.setattr(routes, "_decorate_agent_turns", lambda turns: turns)
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: {
            "task_id": "turn-1",
            "status": "Canceled",
            "message": "任务已由管理员终止",
            "execution_trace": {"trace_messages": []},
        },
    )
    monkeypatch.setattr(routes, "build_agent_workspace_tree", lambda _sid: [])
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_template",
        lambda template, **context: rendered.append((template, context)) or "detail",
    )

    app = _app()
    with app.test_request_context("/admin/agent_tasks/session-1"):
        response = routes.admin_agent_task_detail("session-1")

    assert response.get_data(as_text=True) == "detail"
    current_state = rendered[0][1]["current_state"]
    assert current_state["status"] == "CleanupFailed"
    assert current_state["message"] == "容器清理状态未知"
    assert current_state["harness_status"] == "cleanup_failed"
