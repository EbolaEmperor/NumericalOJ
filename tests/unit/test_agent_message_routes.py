from types import SimpleNamespace

from flask import Flask

from oj_modules.agents.sessions import AgentSessionMessageConflictError
from oj_modules.routes import problem_core_routes as routes


ADMIN = {"id": 7, "username": "admin", "is_admin": 1}


class _QueueTask:
    def __init__(self):
        self.calls = []

    def apply_async(self, *, args):
        self.calls.append(args)


def _app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "agent-message-route-test"
    return app


def _session(status="Running"):
    return {
        "session_id": "session-1",
        "current_task_id": "task-1",
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "codex",
        "endpoint_id": 8,
        "endpoint_revision": 3,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-1",
        "status": status,
        "turn_count": 1,
        "queue_paused": False,
        "is_legacy": False,
    }


def _patch_common(monkeypatch, status="Running"):
    session = _session(status)
    monkeypatch.setattr(routes, "current_user", lambda: dict(ADMIN))
    monkeypatch.setattr(routes, "get_agent_session", lambda _sid: dict(session))
    monkeypatch.setattr(routes, "_agent_run_turn_task", object())
    monkeypatch.setattr(
        routes,
        "_agent_session_message_snapshot",
        lambda _session, current_state=None: {
            "current_task_id": "task-1",
            "status": status,
            "running": status == "Running",
            "messages": [],
        },
    )
    return session


def test_running_main_send_is_persisted_as_queue_and_wakes_dispatcher(monkeypatch):
    _patch_common(monkeypatch)
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="message-1"))
    attachments = [{"name": "input.txt", "path": "attachments/message-1/input.txt"}]
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: attachments)
    enqueued = []

    def enqueue(session_id, **kwargs):
        enqueued.append((session_id, kwargs))
        return {
            "message_id": kwargs["message_id"],
            "session_id": session_id,
            "delivery_mode": kwargs["delivery_mode"],
            "status": "queued",
            "user_message": kwargs["user_message"],
            "attachments": kwargs["attachments"],
        }

    monkeypatch.setattr(routes, "enqueue_agent_session_message", enqueue)

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={"message": "下一轮检查边界"},
        content_type="multipart/form-data",
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["delivery_mode"] == "queue"
    assert payload["agent_message"]["message_id"] == "message-1"
    assert enqueued[0][1]["target_task_id"] is None
    assert enqueued[0][1]["attachments"] == attachments
    assert queue_task.calls == [("session-1",)]


def test_client_message_id_replay_returns_existing_queue_record(monkeypatch):
    _patch_common(monkeypatch)
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    existing = {
        "message_id": "client-message-1",
        "session_id": "session-1",
        "created_by": "admin",
        "user_message": "下一轮检查边界",
        "delivery_mode": "queue",
        "status": "dispatching",
        "attachments": [{"path": "attachments/client-message-1/input.txt"}],
    }
    monkeypatch.setattr(
        routes,
        "get_agent_session_message",
        lambda message_id: existing if message_id == "client-message-1" else None,
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: (_ for _ in ()).throw(AssertionError("幂等重试不得重复保存附件")),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "message": "下一轮检查边界",
            "message_id": "client-message-1",
            "delivery_mode": "queue",
        },
        content_type="multipart/form-data",
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["idempotent"] is True
    assert payload["agent_message"]["message_id"] == "client-message-1"
    assert queue_task.calls == [("session-1",)]


def test_client_retry_replay_uses_existing_turn_while_session_is_running(
    monkeypatch,
):
    """响应丢失后的 retry 重放仍按 turn 幂等返回，不会误入运行中队列。"""

    _patch_common(monkeypatch, status="Pending")
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    existing = {
        "message_id": "retry-2",
        "session_id": "session-1",
        "created_by": "admin",
        "user_message": "重新完成上一条任务",
        "delivery_mode": "turn",
        "status": "dispatching",
        "attachments": [],
        "final_task_id": "retry-2",
    }
    monkeypatch.setattr(routes, "get_agent_session_message", lambda _mid: existing)
    monkeypatch.setattr(
        routes,
        "get_agent_session_turns",
        lambda _sid, *, include_superseded=False: [{
            "task_id": "retry-2",
            "turn_index": 3,
            "retry_of_task_id": "turn-2",
        }],
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "retry_last": "1",
            "expected_task_id": "turn-2",
            "message_id": "retry-2",
        },
        content_type="multipart/form-data",
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["idempotent"] is True
    assert payload["task_id"] == "retry-2"
    assert payload["replaced_task_id"] == "turn-2"
    assert payload["delivery_mode"] == "turn"
    assert queue_task.calls == [("session-1",)]


def test_steer_is_bound_to_client_task_and_does_not_enqueue_new_turn(monkeypatch):
    _patch_common(monkeypatch)
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    monkeypatch.setattr(routes, "read_agent_steer_capability", lambda *_args: (True, ""))
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="steer-1"))
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [])
    captured = []

    def enqueue(session_id, **kwargs):
        captured.append(kwargs)
        return {
            "message_id": "steer-1",
            "session_id": session_id,
            "delivery_mode": "steer",
            "status": "queued",
            "target_task_id": kwargs["target_task_id"],
            "user_message": kwargs["user_message"],
            "attachments": [],
        }

    monkeypatch.setattr(routes, "enqueue_agent_session_message", enqueue)

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "message": "先检查刚生成的数据",
            "delivery_mode": "steer",
            "expected_task_id": "task-1",
        },
        content_type="multipart/form-data",
    ):
        response = routes.admin_agent_task_detail("session-1")

    payload = response.get_json()
    assert payload["delivery_mode"] == "steer"
    assert captured[0]["target_task_id"] == "task-1"
    assert queue_task.calls == []


def test_stale_steer_conflict_removes_just_published_attachments(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", _QueueTask())
    monkeypatch.setattr(routes, "read_agent_steer_capability", lambda *_args: (True, ""))
    monkeypatch.setattr(routes, "uuid4", lambda: SimpleNamespace(hex="steer-1"))
    attachments = [{"path": "attachments/steer-1/input.txt"}]
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: attachments)
    monkeypatch.setattr(
        routes,
        "enqueue_agent_session_message",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AgentSessionMessageConflictError("Agent 当前任务已变化，请重新发送")
        ),
    )
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, values: removed.append((session_id, values)),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1",
        method="POST",
        data={
            "message": "迟到插话",
            "delivery_mode": "steer",
            "expected_task_id": "old-task",
        },
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_task_detail("session-1")

    assert status == 409
    assert "已变化" in response.get_json()["message"]
    assert removed == [("session-1", attachments)]


def test_queue_edit_cas_conflict_compensates_only_new_generation(monkeypatch):
    _patch_common(monkeypatch)
    original = {
        "name": "original.txt",
        "path": "attachments/original/original.txt",
    }
    added = {
        "name": "added.txt",
        "path": "attachments/added/added.txt",
    }
    current = {
        "message_id": "message-1",
        "delivery_mode": "queue",
        "status": "queued",
        "user_message": "原消息",
        "attachments": [original],
    }
    monkeypatch.setattr(
        routes,
        "list_agent_session_messages",
        lambda *_args, **_kwargs: [current],
    )
    monkeypatch.setattr(routes, "save_agent_attachments", lambda *_args: [added])
    update_calls = []

    def conflict_update(session_id, message_id, **kwargs):
        update_calls.append((session_id, message_id, kwargs))
        raise AgentSessionMessageConflictError(
            "Agent 排队消息已变化，请刷新后重试"
        )

    monkeypatch.setattr(
        routes,
        "update_queued_agent_session_message",
        conflict_update,
    )
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, values: removed.append((session_id, values)),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/messages/message-1/update",
        method="POST",
        data={"message": "并发编辑", "attachments": (b"new", "added.txt")},
        content_type="multipart/form-data",
    ):
        response, status = routes.admin_agent_task_message_update(
            "session-1",
            "message-1",
        )

    assert status == 409
    assert "已变化" in response.get_json()["message"]
    assert update_calls[0][2]["expected_attachments"] == [original]
    assert removed == [("session-1", [added])]


def test_queue_edit_cleans_only_data_layer_confirmed_removed_attachments(
    monkeypatch,
):
    _patch_common(monkeypatch)
    removed_attachment = {
        "name": "remove.txt",
        "path": "attachments/original/remove.txt",
    }
    kept_attachment = {
        "name": "keep.txt",
        "path": "attachments/original/keep.txt",
    }
    added_attachment = {
        "name": "added.txt",
        "path": "attachments/added/added.txt",
    }
    current = {
        "message_id": "message-1",
        "delivery_mode": "queue",
        "status": "queued",
        "user_message": "原消息",
        "attachments": [removed_attachment, kept_attachment],
    }
    updated = {
        **current,
        "user_message": "更新消息",
        "attachments": [kept_attachment, added_attachment],
    }
    reads = iter(([current], [updated]))
    monkeypatch.setattr(
        routes,
        "list_agent_session_messages",
        lambda *_args, **_kwargs: next(reads),
    )
    monkeypatch.setattr(
        routes,
        "save_agent_attachments",
        lambda *_args: [added_attachment],
    )
    update_calls = []

    def update(session_id, message_id, **kwargs):
        update_calls.append((session_id, message_id, kwargs))
        return [removed_attachment]

    monkeypatch.setattr(routes, "update_queued_agent_session_message", update)
    removed = []
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda session_id, values: removed.append((session_id, values)),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/messages/message-1/update",
        method="POST",
        data={
            "message": "更新消息",
            "remove_attachment": removed_attachment["path"],
            "attachments": (b"new", "added.txt"),
        },
        content_type="multipart/form-data",
    ):
        response = routes.admin_agent_task_message_update(
            "session-1",
            "message-1",
        )

    assert response.get_json()["success"] is True
    assert update_calls[0][2]["expected_attachments"] == [
        removed_attachment,
        kept_attachment,
    ]
    assert update_calls[0][2]["attachments"] == [
        kept_attachment,
        added_attachment,
    ]
    assert removed == [("session-1", [removed_attachment])]


def test_queue_delete_rejects_attachment_snapshot_changed_by_edit(monkeypatch):
    _patch_common(monkeypatch)
    original = {
        "name": "original.txt",
        "path": "attachments/original/original.txt",
    }
    current = {
        "message_id": "message-1",
        "delivery_mode": "queue",
        "status": "queued",
        "user_message": "原消息",
        "attachments": [original],
    }
    monkeypatch.setattr(
        routes,
        "list_agent_session_messages",
        lambda *_args, **_kwargs: [current],
    )
    cancel_calls = []

    def conflict_cancel(session_id, message_id, **kwargs):
        cancel_calls.append((session_id, message_id, kwargs))
        raise AgentSessionMessageConflictError(
            "Agent 排队消息已变化，请刷新后重试"
        )

    monkeypatch.setattr(
        routes,
        "cancel_queued_agent_session_message",
        conflict_cancel,
    )
    monkeypatch.setattr(
        routes,
        "remove_agent_attachments",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("CAS 冲突不得删除任何已提交附件")
        ),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/messages/message-1/delete",
        method="POST",
    ):
        response, status = routes.admin_agent_task_message_delete(
            "session-1",
            "message-1",
        )

    assert status == 409
    assert "已变化" in response.get_json()["message"]
    assert cancel_calls[0][2]["expected_attachments"] == [original]


def test_queue_send_now_promotes_the_existing_message_without_dispatch_task(
    monkeypatch,
):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        routes,
        "read_agent_steer_capability",
        lambda *_args: (True, ""),
    )
    promoted = []

    def promote(session_id, message_id, *, task_id):
        promoted.append((session_id, message_id, task_id))
        return {
            "message_id": message_id,
            "session_id": session_id,
            "delivery_mode": "steer",
            "status": "queued",
            "target_task_id": task_id,
            "user_message": "现在就检查",
            "attachments": [],
        }

    monkeypatch.setattr(
        routes,
        "steer_queued_agent_session_message",
        promote,
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/messages/message-1/send-now",
        method="POST",
        data={"expected_task_id": "task-1"},
    ):
        response = routes.admin_agent_task_message_send_now(
            "session-1",
            "message-1",
        )

    payload = response.get_json()
    assert payload["success"] is True
    assert payload["agent_message"]["delivery_mode"] == "steer"
    assert promoted == [("session-1", "message-1", "task-1")]
    assert payload["session_state"]["current_task_id"] == "task-1"


def test_continue_queue_clears_pause_and_schedules_dispatch(monkeypatch):
    _patch_common(monkeypatch, status="Failed")
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    continued = []
    monkeypatch.setattr(
        routes,
        "continue_agent_session_queue",
        lambda session_id: continued.append(session_id),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/queue/resume",
        method="POST",
    ):
        response = routes.admin_agent_task_queue_resume("session-1")

    assert response.get_json()["success"] is True
    assert continued == ["session-1"]
    assert queue_task.calls == [("session-1",)]


def test_continue_queue_allows_data_layer_to_mark_missing_native_session(
    monkeypatch,
):
    session = _patch_common(monkeypatch, status="Canceled")
    session["native_session_id"] = ""
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)
    continued = []
    monkeypatch.setattr(
        routes,
        "continue_agent_session_queue",
        lambda session_id: continued.append(session_id),
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/queue/resume",
        method="POST",
    ):
        response = routes.admin_agent_task_queue_resume("session-1")

    assert response.get_json()["success"] is True
    assert continued == ["session-1"]
    assert queue_task.calls == [("session-1",)]


def test_non_owner_admin_can_read_session_message_state(monkeypatch):
    _patch_common(monkeypatch)
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 8, "username": "reviewer", "is_admin": 1},
    )
    monkeypatch.setattr(
        routes,
        "_get_agent_run_state",
        lambda _task_id: {"status": "Running"},
    )
    monkeypatch.setattr(
        routes,
        "_agent_state_with_loaded_session_token_usage",
        lambda state: state,
    )

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/state",
        method="GET",
    ):
        response = routes.admin_agent_task_message_state("session-1")

    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_non_owner_admin_cannot_mutate_session_queue(monkeypatch):
    _patch_common(monkeypatch, status="Failed")
    monkeypatch.setattr(
        routes,
        "current_user",
        lambda: {"id": 8, "username": "reviewer", "is_admin": 1},
    )
    queue_task = _QueueTask()
    monkeypatch.setattr(routes, "_agent_queue_dispatch_task", queue_task)

    app = _app()
    with app.test_request_context(
        "/admin/agent_tasks/session-1/queue/resume",
        method="POST",
    ):
        response, status = routes.admin_agent_task_queue_resume("session-1")

    assert status == 403
    assert "自己发起" in response.get_json()["message"]
    assert queue_task.calls == []
