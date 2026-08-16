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


class _WakeTask:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args):
        self.calls.append(args)


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
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", _WakeTask())
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())


def _patch_frozen_endpoint(monkeypatch, *, revision=3):
    calls = []

    def resolve(harness, endpoint_id, *, include_secret):
        calls.append((harness, endpoint_id, include_secret))
        return {
            "id": int(endpoint_id),
            "revision": revision,
            "model": "gpt-test",
        }

    monkeypatch.setattr(routes, "resolve_launch_endpoint", resolve)
    return calls


def test_agent_launch_page_options_exposes_harness_native_reasoning_efforts(
    monkeypatch,
):
    monkeypatch.setattr(
        routes,
        "list_launch_endpoints_by_harness",
        lambda *, user_id: {
            "pi": [{"ref": "global:1"}],
            "claude_code": [{"ref": "global:2"}],
            "codex": [],
            "opencode": [],
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_launch_preference",
        lambda _user_id: {"harness": "pi", "endpoint_ref": "global:1"},
    )

    options = routes._agent_launch_page_options(7)

    assert [
        item["value"]
        for item in options["reasoning_efforts_by_harness"]["pi"]
    ] == ["off", "minimal", "low", "medium", "high", "xhigh", "max"]
    assert [
        item["value"]
        for item in options["reasoning_efforts_by_harness"]["claude_code"]
    ] == ["low", "medium", "high", "xhigh", "max"]
    assert "codex" not in options["reasoning_efforts_by_harness"]


@pytest.fixture(autouse=True)
def _patch_runtime_checkpoints(monkeypatch):
    """路由单测只验证编排；checkpoint 文件语义由独立单测覆盖。"""

    monkeypatch.setattr(routes, "ensure_agent_workspace", lambda _sid: None)
    monkeypatch.setattr(
        routes,
        "create_agent_runtime_checkpoint",
        lambda _session_id, _checkpoint_id: None,
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
        "restore_agent_runtime_checkpoint",
        lambda _session_id, _checkpoint_id: None,
    )
    monkeypatch.setattr(
        routes,
        "clear_agent_session_state_file",
        lambda _session_id: False,
    )
    monkeypatch.setattr(
        routes,
        "mark_agent_turn_runtime_restore_failed",
        lambda _session_id, _task_id, _message: None,
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
            f"/agent/tasks/{kwargs['session_id']}"
            if endpoint == "problem_core.agent_task_detail"
            else "/unexpected"
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks?task_id=turn-historical",
    ):
        response = routes.admin_agent_tasks()

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/agent/tasks/session-1")


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
            "harness": "pi",
            "endpoint_id": "12",
            "reasoning_effort": "minimal",
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
    assert preference_calls == [(7, "pi", 12)]
    assert workspace_calls == ["session-new"]
    assert create_calls[0]["task_kind"] == "custom"
    assert create_calls[0]["access_role"] == "admin"
    assert create_calls[0]["reasoning_effort"] == "minimal"
    assert create_calls[0]["endpoint_revision"] == 3
    assert create_calls[0]["attachments"] == attachments
    assert create_calls[0]["base_runtime_checkpoint_id"] == (
        "session-new-session-new"
    )
    assert create_calls[0]["base_native_session_id"] == ""
    assert task.calls == []
    assert routes._agent_queue_dispatch_task.calls == [("session-new",)]
    assert snapshots[0]["session_id"] == "session-new"
    assert "signed-cookie" not in str(snapshots)


def test_custom_session_idempotency_rejects_different_reasoning_effort(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_message_from_request", lambda: "完成任务")
    monkeypatch.setattr(
        routes,
        "_agent_client_message_id",
        lambda **_kwargs: "same-message",
    )
    monkeypatch.setattr(routes, "_agent_session_cookie", lambda: ("session", "signed"))
    monkeypatch.setattr(routes, "_agent_quota_gate", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        routes,
        "_resolve_agent_endpoint_for_user",
        lambda *_args, **_kwargs: {
            "id": 12,
            "source": "global",
            "revision": 3,
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session_message",
        lambda _message_id: {
            "session_id": "same-message",
            "created_by": "admin",
            "user_message": "完成任务",
        },
    )
    monkeypatch.setattr(
        routes,
        "get_agent_session",
        lambda _session_id: {
            "session_id": "same-message",
            "harness": "pi",
            "reasoning_effort": "low",
            "endpoint_source": "global",
            "endpoint_id": 12,
            "access_role": "admin",
        },
    )

    app = _app()
    with app.test_request_context(
        "/agent/tasks",
        method="POST",
        data={
            "message": "完成任务",
            "message_id": "same-message",
            "harness": "pi",
            "endpoint_id": "12",
            "reasoning_effort": "high",
            "access_role": "admin",
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.agent_tasks()

    assert status == 409
    assert response.get_json()["message"] == "Agent message_id 已被其它消息使用"


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
    removed_checkpoints = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, items: removed.append((session_id, items)),
    )
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: (
            removed_checkpoints.append((session_id, checkpoint_id, missing_ok))
        ),
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
    assert removed_checkpoints == [(
        "session-new",
        "session-new-session-new",
        True,
    )]


def test_same_client_message_creation_conflict_keeps_winner_checkpoint(
    monkeypatch,
):
    """并发请求的败者只能补偿自己的 generation，不能删除胜者基线。"""

    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    generations = iter(("checkpoint-a", "checkpoint-b"))
    monkeypatch.setattr(
        routes,
        "uuid4",
        lambda: SimpleNamespace(hex=next(generations)),
    )
    monkeypatch.setattr(routes, "normalize_launch_harness", lambda value: value)
    monkeypatch.setattr(
        routes,
        "resolve_launch_endpoint",
        lambda _harness, endpoint_id, **_kwargs: {
            "id": int(endpoint_id),
            "revision": 3,
            "model": "selected-model",
        },
    )
    monkeypatch.setattr(routes, "save_agent_launch_preference", lambda *_args: None)
    monkeypatch.setattr(routes, "ensure_agent_workspace", lambda _session_id: None)
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [])
    # 模拟两个请求都在胜者提交前完成了幂等预读。
    monkeypatch.setattr(routes, "get_agent_session_message", lambda _mid: None)
    create_calls = []

    def create_session(**kwargs):
        create_calls.append(kwargs)
        if len(create_calls) == 2:
            raise RuntimeError("duplicate session")
        return {
            **_session(),
            "session_id": "same-message",
            "current_task_id": "same-message",
        }

    monkeypatch.setattr(routes, "create_agent_session", create_session)
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda _endpoint, **kwargs: f"/admin/agent_tasks/{kwargs['session_id']}",
    )
    created_checkpoints = []
    removed_checkpoints = []
    monkeypatch.setattr(
        routes,
        "create_empty_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: created_checkpoints.append(
            (session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: (
            removed_checkpoints.append((session_id, checkpoint_id, missing_ok))
        ),
    )

    app = _app()
    responses = []
    for _attempt in range(2):
        with app.test_request_context(
            "/admin/agent_tasks",
            method="POST",
            data={
                "message": "创建并发会话",
                "message_id": "same-message",
                "harness": "codex",
                "endpoint_id": "12",
                "access_role": "admin",
            },
            content_type="multipart/form-data",
            environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
        ):
            responses.append(routes.admin_agent_tasks())

    assert responses[0].get_json()["success"] is True
    assert responses[1][1] == 500
    assert created_checkpoints == [
        ("same-message", "same-message-checkpoint-a"),
        ("same-message", "same-message-checkpoint-b"),
    ]
    assert [item["base_runtime_checkpoint_id"] for item in create_calls] == [
        "same-message-checkpoint-a",
        "same-message-checkpoint-b",
    ]
    assert removed_checkpoints == [(
        "same-message",
        "same-message-checkpoint-b",
        True,
    )]


@pytest.mark.parametrize(
    ("task_kind", "access_role"),
    [("custom", "admin"), ("solve", "user"), ("testdata", "admin")],
)
def test_all_session_kinds_resume_through_the_same_fixed_runtime_contract(
    monkeypatch,
    task_kind,
    access_role,
):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
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
    removed_checkpoints = []
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: (
            removed_checkpoints.append((session_id, checkpoint_id, missing_ok))
        ),
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
                "previous_base_runtime_checkpoint_id": "turn-1-base",
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
        "attachments": attachments,
        "base_runtime_checkpoint_id": "turn-2-turn-2",
    })]
    assert removed_checkpoints == [("session-1", "turn-1-base", True)]
    assert task.calls == []
    assert routes._agent_queue_dispatch_task.calls == [("session-1",)]


def test_resume_race_removes_its_published_attachment_generation(monkeypatch):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-racing"))
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    attachments = [{
        "name": "race.txt",
        "path": "attachments/turn-racing-generation/race.txt",
    }]
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: attachments)
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, values: removed.append((session_id, values)),
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
    assert removed == [("session-1", attachments)]


def test_same_client_resume_conflict_keeps_winner_checkpoint(monkeypatch):
    """相同续聊幂等键竞争时，DB 败者不得清理胜者 checkpoint。"""

    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(routes, "get_agent_session_message", lambda _mid: None)
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [])
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    generations = iter(("checkpoint-a", "checkpoint-b"))
    monkeypatch.setattr(
        routes,
        "uuid4",
        lambda: SimpleNamespace(hex=next(generations)),
    )
    created_checkpoints = []
    removed_checkpoints = []
    monkeypatch.setattr(
        routes,
        "create_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: created_checkpoints.append(
            (session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: (
            removed_checkpoints.append((session_id, checkpoint_id, missing_ok))
        ),
    )
    begin_calls = []

    def begin_turn(session_id, **kwargs):
        begin_calls.append((session_id, kwargs))
        if len(begin_calls) == 2:
            raise AgentSessionBusyError("上一轮 Agent 任务尚未结束")
        return {
            "turn_index": 2,
            "task_kind": "custom",
            "access_role": "admin",
            "harness": "codex",
            "endpoint_id": 12,
            "native_session_id": "native-session-1",
            "previous_base_runtime_checkpoint_id": "",
        }

    monkeypatch.setattr(routes, "begin_agent_session_turn", begin_turn)

    app = _app()
    responses = []
    for _attempt in range(2):
        with app.test_request_context(
            "/admin/agent_tasks/session-1",
            method="POST",
            data={
                "message": "继续并发会话",
                "message_id": "same-turn",
                "delivery_mode": "turn",
            },
            content_type="multipart/form-data",
            environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
        ):
            responses.append(routes.admin_agent_task_detail("session-1"))

    assert responses[0].get_json()["success"] is True
    assert responses[1][1] == 409
    assert created_checkpoints == [
        ("session-1", "same-turn-checkpoint-a"),
        ("session-1", "same-turn-checkpoint-b"),
    ]
    assert [call[1]["base_runtime_checkpoint_id"] for call in begin_calls] == [
        "same-turn-checkpoint-a",
        "same-turn-checkpoint-b",
    ]
    assert removed_checkpoints == [(
        "session-1",
        "same-turn-checkpoint-b",
        True,
    )]


def test_resume_rejects_changed_frozen_endpoint_before_claiming_turn(monkeypatch):
    _patch_admin(monkeypatch)
    endpoint_calls = _patch_frozen_endpoint(monkeypatch, revision=4)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(
        routes,
        "uuid4",
        lambda: pytest.fail("节点版本校验失败时不得生成新轮次 ID"),
    )
    monkeypatch.setattr(
        routes,
        "begin_agent_session_turn",
        lambda *_args, **_kwargs: pytest.fail("节点版本校验失败时不得 claim 轮次"),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "继续"},
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert status == 409
    assert payload == {
        "success": False,
        "message": "该 Agent 会话使用的 LLM 节点配置已变化，请新建会话",
    }
    assert endpoint_calls == [("codex", 12, False)]


def test_resume_attachment_failure_does_not_publish_turn_outbox(monkeypatch):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    monkeypatch.setattr(
        routes,
        "begin_agent_session_turn",
        lambda *_args, **_kwargs: pytest.fail(
            "附件完整落盘前不得发布 turn/outbox"
        ),
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: (_ for _ in ()).throw(ValueError("附件过大")),
    )
    monkeypatch.setattr(routes, "remove_agent_attachments", lambda *_args: 0)
    removed_checkpoints = []
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: (
            removed_checkpoints.append((session_id, checkpoint_id, missing_ok))
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "继续", "attachments": (io.BytesIO(b"x"), "large.bin")},
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 400
    assert response.get_json() == {
        "success": False,
        "message": "附件过大",
    }
    assert removed_checkpoints == [(
        "session-1",
        "turn-2-turn-2",
        True,
    )]


def test_resume_no_longer_depends_on_direct_generic_broker_publish(monkeypatch):
    class FailingTask:
        def apply_async(self, **_kwargs):
            raise RuntimeError("broker unavailable")

    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", FailingTask())
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    monkeypatch.setattr(
        routes,
        "begin_agent_session_turn",
        lambda *_args, **_kwargs: {
            "turn_index": 2,
            "task_kind": "custom",
            "access_role": "admin",
            "harness": "codex",
            "endpoint_id": 12,
            "native_session_id": "native-session-1",
        },
    )
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [])
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    failures = []
    monkeypatch.setattr(
        routes,
        "_mark_agent_dispatch_failed",
        lambda *args: failures.append(args) or str(args[-1]),
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
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "继续"},
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response = routes.admin_agent_task_detail("session-1")

    assert response.get_json()["success"] is True
    assert response.get_json()["task_id"] == "turn-2"
    assert failures == []


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


@pytest.mark.parametrize(
    ("task_kind", "access_role"),
    [
        ("custom", "admin"),
        ("solve", "user"),
        ("testdata", "admin"),
    ],
)
def test_retry_first_turn_reuses_message_and_restores_empty_runtime(
    monkeypatch,
    task_kind,
    access_role,
):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    task = _Task()
    monkeypatch.setattr(routes, "_agent_run_turn_task", task)
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    session = _session(
        task_kind=task_kind,
        access_role=access_role,
        status="Failed",
    )
    session["native_session_id"] = ""
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: dict(session))

    checkpoint_calls = []
    runtime_calls = []
    monkeypatch.setattr(
        routes,
        "create_empty_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: checkpoint_calls.append(
            (session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(
        routes,
        "restore_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: runtime_calls.append(
            ("restore", session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(
        routes,
        "clear_agent_session_state_file",
        lambda session_id: runtime_calls.append(("clear", session_id)),
    )
    retry_calls = []
    attachments = [{
        "name": "需求.md",
        "path": "attachments/turn-1/需求.md",
    }]
    monkeypatch.setattr(
        routes,
        "begin_agent_session_retry",
        lambda session_id, **kwargs: (
            retry_calls.append((session_id, kwargs))
            or {
                "turn_index": 2,
                "task_kind": task_kind,
                "access_role": access_role,
                "harness": "codex",
                "endpoint_id": 12,
                "endpoint_revision": 3,
                "endpoint_model": "gpt-test",
                "native_session_id": "",
                "user_message": "造一道数值积分题",
                "attachments": attachments,
                "base_runtime_checkpoint_id": "turn-2-turn-2",
                "base_native_session_id": "",
                "retry_of_task_id": "turn-1",
                "replaced_task_id": "turn-1",
                "agent_message": {
                    "message_id": "turn-2",
                    "session_id": "session-1",
                    "created_by": "admin",
                    "user_message": "造一道数值积分题",
                    "attachments": attachments,
                    "delivery_mode": "turn",
                    "status": "dispatching",
                    "final_task_id": "turn-2",
                },
            }
        ),
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: pytest.fail("重试必须复用旧附件，不得再次保存"),
    )
    monkeypatch.setattr(routes, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(routes, "render_rich_markdown", lambda text: f"<p>{text}</p>")

    app = _app("numoj_session")
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"retry_last": "1", "expected_task_id": "turn-1"},
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "numoj_session=signed-cookie"},
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["task_id"] == "turn-2"
    assert payload["replaced_task_id"] == "turn-1"
    assert payload["user_message"] == "造一道数值积分题"
    assert payload["attachments"] == attachments
    assert payload["agent_message"]["message_id"] == "turn-2"
    assert payload["agent_message"]["status"] == "dispatching"
    assert checkpoint_calls == [("session-1", "turn-2-turn-2")]
    assert runtime_calls == [
        ("restore", "session-1", "turn-2-turn-2"),
        ("clear", "session-1"),
    ]
    assert retry_calls == [("session-1", {
        "task_id": "turn-2",
        "expected_task_id": "turn-1",
        "fallback_base_checkpoint_id": "turn-2-turn-2",
    })]
    assert task.calls == []
    assert routes._agent_queue_dispatch_task.calls == [("session-1",)]


def test_retry_runtime_restore_failure_blocks_dispatch_and_future_resume(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    task = _Task()
    monkeypatch.setattr(routes, "_agent_run_turn_task", task)
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session(status="Failed"))
    monkeypatch.setattr(
        routes,
        "begin_agent_session_retry",
        lambda *_args, **_kwargs: {
            "turn_index": 2,
            "task_kind": "custom",
            "access_role": "admin",
            "harness": "codex",
            "endpoint_id": 12,
            "endpoint_revision": 3,
            "endpoint_model": "gpt-test",
            "native_session_id": "native-before-turn-1",
            "user_message": "重试这条消息",
            "attachments": [],
            "base_runtime_checkpoint_id": "checkpoint-before-turn-1",
            "base_native_session_id": "native-before-turn-1",
            "retry_of_task_id": "turn-1",
            "replaced_task_id": "turn-1",
        },
    )
    monkeypatch.setattr(
        routes,
        "restore_agent_runtime_checkpoint",
        lambda *_args: (_ for _ in ()).throw(OSError("checkpoint damaged")),
    )
    marked = []
    monkeypatch.setattr(
        routes,
        "mark_agent_turn_runtime_restore_failed",
        lambda session_id, task_id, message: marked.append(
            (session_id, task_id, message)
        ),
    )
    snapshots = []
    monkeypatch.setattr(
        routes,
        "upsert_agent_run_snapshot",
        lambda state: snapshots.append(dict(state)),
    )
    monkeypatch.setattr(
        routes,
        "url_for",
        lambda _endpoint, **kwargs: f"/admin/agent_tasks/{kwargs['session_id']}",
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"retry_last": "1", "expected_task_id": "turn-1"},
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 500
    assert response.get_json()["message"] == (
        "Agent 运行时恢复失败，已阻止继续会话"
    )
    assert task.calls == []
    assert routes._agent_queue_dispatch_task.calls == []
    assert snapshots[-1]["status"] == "CleanupFailed"
    assert marked == [(
        "session-1",
        "turn-2",
        "Agent 运行时恢复失败，已阻止继续会话",
    )]


def test_retry_rejects_new_attachments_before_creating_checkpoint(monkeypatch):
    _patch_admin(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(
        routes,
        "create_empty_agent_runtime_checkpoint",
        lambda *_args: pytest.fail("带新附件的重试不得创建 checkpoint"),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "retry_last": "1",
            "expected_task_id": "turn-1",
            "attachments": (io.BytesIO(b"new"), "new.txt"),
        },
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 400, response.get_json()
    assert "不能同时上传新附件" in response.get_json()["message"]


def test_retry_race_removes_unreferenced_fallback_checkpoint(monkeypatch):
    _patch_admin(monkeypatch)
    _patch_frozen_endpoint(monkeypatch)
    monkeypatch.setattr(routes, "_agent_run_turn_task", _Task())
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="turn-2"))
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: _session())
    monkeypatch.setattr(
        routes,
        "begin_agent_session_retry",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AgentSessionBusyError("Agent 当前轮次已变化，请刷新后重试")
        ),
    )
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id, *, missing_ok=True: removed.append(
            (session_id, checkpoint_id, missing_ok)
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"retry_last": "1", "expected_task_id": "turn-1"},
        content_type="multipart/form-data",
        environ_overrides={"HTTP_COOKIE": "session=signed-cookie"},
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 409, response.get_json()
    assert "已变化" in response.get_json()["message"]
    assert removed == [("session-1", "turn-2-turn-2", True)]


def test_solve_button_creates_a_resumable_generic_user_session(monkeypatch):
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
        lambda **kwargs: create_calls.append(kwargs) or kwargs,
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
    assert create_calls[0]["user_message"] == routes.build_solution_agent_prompt(
        problem_id=9,
        problem_title="数值积分",
    )
    assert create_calls[0]["problem_id"] == 9
    assert create_calls[0]["base_runtime_checkpoint_id"] == "solve-1"
    assert create_calls[0]["base_native_session_id"] == ""


def test_testdata_button_creates_a_resumable_generic_admin_session(
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
        lambda **kwargs: create_calls.append(kwargs) or kwargs,
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
    assert create_calls[0]["access_role"] == "admin"
    assert create_calls[0]["problem_id"] == 9
    assert create_calls[0]["base_runtime_checkpoint_id"] == "testdata-1"
    assert create_calls[0]["base_native_session_id"] == ""
    assert create_calls[0]["user_message"] == routes.build_testdata_agent_prompt(
        problem_id=9,
        problem_title="数值积分",
        test_point_count=4,
        data_requirement="覆盖病态输入",
    )
    assert create_calls[0]["attachments"] == [{
        "name": "answer.py",
        "path": "attachments/testdata-1/answer.py",
    }]
    assert "dispatch_payload" not in create_calls[0]


def test_detail_get_defers_workspace_tree_until_after_first_render(monkeypatch):
    _patch_admin(monkeypatch)
    agent_session = _session()
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda _sid: [{"task_id": "turn-1", "status": "Completed"}],
    )
    current_state = {"task_id": "turn-1", "status": "Completed"}
    decorate_calls = []
    state_calls = []
    monkeypatch.setattr(
        routes,
        "_decorate_agent_turns",
        lambda turns, **kwargs: decorate_calls.append((turns, kwargs)) or turns,
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda task_id, **kwargs: state_calls.append((task_id, kwargs))
        or current_state,
    )
    monkeypatch.setattr(
        routes,
        "_agent_state_for_response",
        lambda *_args, **_kwargs: pytest.fail(
            "当前轮状态已预装饰，详情页不应再渲染"
        ),
    )
    monkeypatch.setattr(
        routes,
        "build_agent_workspace_tree",
        lambda _sid: pytest.fail("Agent 详情首屏不应同步扫描 workspace"),
    )
    quota_popup_calls = []
    monkeypatch.setattr(
        routes,
        "list_user_agent_endpoints",
        lambda _user_id: quota_popup_calls.append("personal") or [],
    )
    monkeypatch.setattr(
        routes,
        "list_pending_agent_quota_requests",
        lambda _user_id: quota_popup_calls.append("pending") or [],
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
    assert rendered[0][1]["agent_message_urls"] == {
        "state": "/agent/tasks/session-1/state",
        "stream": "/agent/tasks/session-1/stream",
        "update": (
            "/agent/tasks/session-1/messages/__MESSAGE_ID__/update"
        ),
        "delete": (
            "/agent/tasks/session-1/messages/__MESSAGE_ID__/delete"
        ),
            "send_now": (
                "/agent/tasks/session-1/messages/__MESSAGE_ID__/send-now"
            ),
            "resume": "/agent/tasks/session-1/queue/resume",
            "rename": "/agent/tasks/session-1/title",
        }
    assert rendered[0][1]["can_resume"] is True
    assert rendered[0][1]["can_retry"] is True
    assert rendered[0][1]["can_retry_now"] is True
    assert rendered[0][1]["workspace_tree"] == []
    assert quota_popup_calls == []
    assert "agent_personal_endpoints" not in rendered[0][1]
    assert "agent_quota_pending_count" not in rendered[0][1]
    assert "agent_quota_pending_requests" not in rendered[0][1]
    assert len(decorate_calls) == 1
    assert state_calls == [("turn-1", {"decorate_markdown": False})]
    assert decorate_calls[0][1] == {
        "current_task_id": "turn-1",
        "current_state": current_state,
        "include_trace": False,
        "steer_records": [],
    }


def test_detail_get_allows_retrying_specialized_generic_followup(monkeypatch):
    _patch_admin(monkeypatch)
    agent_session = _session(task_kind="solve")
    agent_session.update(current_task_id="turn-2", turn_count=2)
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda _sid: [{
            "task_id": "turn-2",
            "turn_index": 2,
            "status": "Completed",
            "base_runtime_checkpoint_id": "checkpoint-before-turn-2",
            "base_native_session_id": "native-after-solve",
        }],
    )
    monkeypatch.setattr(
        routes,
        "_decorate_agent_turns",
        lambda turns, **_kwargs: turns,
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id, **_kwargs: {
            "task_id": "turn-2",
            "status": "Completed",
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
    assert rendered[0][1]["can_retry"] is True
    assert rendered[0][1]["can_retry_now"] is True


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
    monkeypatch.setattr(
        routes,
        "_decorate_agent_turns",
        lambda values, **_kwargs: values,
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _tid, **_kwargs: current_state,
    )
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


def test_superseded_retry_source_remains_in_session_usage(monkeypatch):
    """重试只替换消息历史；实际发生过的模型用量继续累计。"""

    retry_usage = {
        "source": "codex",
        "request_count": 1,
        "input_uncached_tokens": 20,
        "input_cached_tokens": 0,
        "output_tokens": 5,
        "cost_rmb": "0.25",
    }
    turn_calls = []
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda session_id, include_superseded=False: (
            turn_calls.append((session_id, include_superseded))
            or [
                {"task_id": "turn-superseded"},
                {"task_id": "turn-retry"},
            ]
        ),
    )
    monkeypatch.setattr(
        routes,
        "get_agent_run_by_task_id",
        lambda task_id: {
            "task_id": task_id,
            "execution_trace": {"token_usage": retry_usage},
        },
    )
    monkeypatch.setattr(routes, "hydrate_agent_run_snapshot", lambda state: state)

    historical = routes._load_agent_historical_token_usages(
        "session-1",
        "turn-retry",
    )
    projected = routes._agent_state_with_session_token_usage(
        {
            "task_id": "turn-retry",
            "execution_trace": {"token_usage": {
                **retry_usage,
                "input_uncached_tokens": 30,
                "input_cached_tokens": 10,
                "output_tokens": 8,
                "cost_rmb": "0.40",
            }},
        },
        historical,
    )

    assert turn_calls == [("session-1", True)]
    assert historical.current_task_visible is True
    assert projected["session_token_usage"]["request_count"] == 2
    assert projected["session_token_usage"]["input_total_tokens"] == 60
    assert projected["session_token_usage"]["output_tokens"] == 13
    assert projected["session_token_usage"]["cost_rmb"] == "0.65"


def test_session_usage_cost_prefers_frozen_quota_ledger_amount():
    projected = routes._agent_state_with_session_token_usage({
        "task_id": "turn-1",
        "session_charged_amount_rmb": "1.25",
        "execution_trace": {"token_usage": {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 10,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 5,
            # 轨迹里的旧投影可能按后来修改过的端点价格计算。
            "cost_rmb": "99",
        }},
    })

    assert projected["session_token_usage"]["cost_rmb"] == "1.25"
    assert projected["session_token_usage"]["cost_complete"] is True


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


def test_decorate_turns_reuses_predecorated_current_state(monkeypatch):
    current_state = {
        "task_id": "turn-current",
        "harness": "codex",
        "status": "Completed",
        "execution_trace": {"trace_messages": [{
            "kind": "assistant",
            "text": "已完成",
            "html": "<p>已完成</p>",
        }]},
    }
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda _state: pytest.fail("当前轮不应重复 hydrate"),
    )
    monkeypatch.setattr(
        routes,
        "_decorate_agent_state_markdown",
        lambda _state: pytest.fail("当前轮不应重复渲染轨迹 Markdown"),
    )
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<p>{text or ''}</p>",
    )

    turn = routes._decorate_agent_turns(
        [{
            "task_id": "turn-current",
            "harness": "codex",
            "status": "Completed",
            "user_message": "继续",
        }],
        current_task_id="turn-current",
        current_state=current_state,
    )[0]

    assert turn["execution_trace"] == current_state["execution_trace"]
    assert turn["conclusion"] == "已完成"


def test_decorate_turns_can_defer_full_trace_markdown(monkeypatch):
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda state: {
            **state,
            "execution_trace": {"trace_messages": [
                {"kind": "thinking", "text": "很长的思考"},
                {"kind": "assistant", "text": "已完成具体任务"},
            ]},
        },
    )
    monkeypatch.setattr(
        routes,
        "_decorate_agent_state_markdown",
        lambda _state: pytest.fail("折叠轨迹不应在首屏渲染 Markdown"),
    )
    rendered = []
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: rendered.append(text) or f"<p>{text}</p>",
    )

    turn = routes._decorate_agent_turns([{
        "task_id": "turn-lazy",
        "status": "Completed",
        "user_message": "执行任务",
        "conclusion": "笼统结论",
    }], include_trace=False)[0]

    assert turn["has_detail"] is True
    assert turn["execution_trace"] == {}
    assert turn["conclusion"] == "已完成具体任务"
    assert rendered == ["执行任务", "已完成具体任务"]


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


@pytest.mark.parametrize("harness", ["pi", "claude_code"])
def test_canonical_incremental_trace_is_not_legacy_resume_filtered(harness):
    previous = [{"kind": "assistant", "text": "same opening"}]
    current = previous + [{"kind": "assistant", "text": "new answer"}]
    state = {
        "harness": harness,
        "execution_trace": {
            "incremental": True,
            "trace_messages": current,
        },
    }

    assert routes._agent_state_with_trace_delta(
        state,
        previous,
        harness,
    ) is state
    assert state["execution_trace"]["trace_messages"] == current


@pytest.mark.parametrize(
    ("status", "stored", "messages", "expected"),
    [
        (
            "Completed",
            "解题 Agent 已提交并通过",
            [{"kind": "assistant", "text": "代码已经提交，并通过全部测试。"}],
            "代码已经提交，并通过全部测试。",
        ),
        (
            "Completed",
            "测试数据格式检查通过并已发布，共 12 个测试点",
            [],
            "测试数据格式检查通过并已发布，共 12 个测试点",
        ),
        (
            "Failed",
            "测试数据发布失败",
            [{"kind": "assistant", "text": "候选数据已经生成。"}],
            "测试数据发布失败",
        ),
    ],
)
def test_agent_turn_conclusion_uses_trace_only_for_completed_output(
    monkeypatch,
    status,
    stored,
    messages,
    expected,
):
    monkeypatch.setattr(
        routes,
        "hydrate_agent_run_snapshot",
        lambda state: {
            **state,
            "execution_trace": {"trace_messages": messages},
        },
    )
    monkeypatch.setattr(
        routes,
        "render_rich_markdown",
        lambda text: f"<p>{text}</p>",
    )

    turn = routes._decorate_agent_turns([{
        "task_id": "turn-conclusion",
        "turn_index": 1,
        "harness": "codex",
        "status": status,
        "user_message": "完成任务",
        "conclusion": stored,
    }])[0]

    assert turn["conclusion"] == expected
    assert turn["conclusion_html"] == f"<p>{expected}</p>"


def test_detail_get_marks_another_admin_session_read_only(monkeypatch):
    _patch_admin(monkeypatch)
    agent_session = _session()
    agent_session["requested_by"] = "another-admin"
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(routes, "get_agent_session_turns", lambda _sid: [])
    monkeypatch.setattr(
        routes,
        "_decorate_agent_turns",
        lambda turns, **_kwargs: turns,
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id, **_kwargs: {
            "task_id": "turn-1",
            "status": "Completed",
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
    assert rendered[0][1]["can_resume"] is False


def test_detail_refresh_keeps_cleanup_failed_session_blocked_over_sticky_cancel(
    monkeypatch,
):
    _patch_admin(monkeypatch)
    agent_session = _session(status="CleanupFailed")
    agent_session["message"] = "容器清理状态未知"
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: agent_session)
    monkeypatch.setattr(routes, "get_agent_session_turns", lambda _sid: [])
    monkeypatch.setattr(
        routes,
        "_decorate_agent_turns",
        lambda turns, **_kwargs: turns,
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id, **_kwargs: {
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
