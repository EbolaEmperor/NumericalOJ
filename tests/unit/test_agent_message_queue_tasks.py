from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import queue


class _FakeCelery:
    def __init__(self):
        self.tasks = {}
        self.options = []

    def task(self, **options):
        self.options.append(options)
        return lambda function: function


class _RecordedTask:
    def __init__(self, error=None):
        self.calls = []
        self.error = error

    def apply_async(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error


@pytest.fixture(autouse=True)
def _stub_dispatch_receipts(monkeypatch):
    monkeypatch.setattr(
        queue,
        "mark_agent_session_message_broker_enqueued",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        queue,
        "release_agent_session_message_dispatch_attempt",
        lambda *_args, **_kwargs: True,
    )


def _claim():
    return {
        "message_id": "message-1",
        "session_id": "session-1",
        "task_id": "task-2",
        "dispatch_attempt_id": "attempt-1",
        "turn_index": 2,
        "user_message": "请继续处理",
        "attachments": [{"path": "attachments/message-1/input.txt"}],
        "task_kind": "custom",
        "problem_id": None,
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "pi",
        "endpoint_id": 8,
        "endpoint_model": "model-a",
        "native_session_id": "native-session",
        "dispatch_payload": {},
    }


def test_dispatch_claim_uses_fixed_task_id_and_cookieless_task_capability(monkeypatch):
    run_turn = _RecordedTask()
    snapshots = []
    receipts = []
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: _claim(),
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda state: snapshots.append(state))
    monkeypatch.setattr(
        queue,
        "mark_agent_session_message_broker_enqueued",
        lambda message_id, **kwargs: receipts.append((message_id, kwargs)) or True,
    )
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    result = dispatch(
        SimpleNamespace(retry=lambda **_kwargs: None),
        "session-1",
    )

    assert result["task_id"] == "task-2"
    assert snapshots[0]["status"] == "Pending"
    _args, kwargs = run_turn.calls[0]
    assert kwargs["task_id"] == "task-2"
    task_args = kwargs["args"]
    assert task_args[0] == "session-1"
    assert task_args[5] == ""
    assert "/workspace/attachments/message-1/input.txt" in task_args[6]
    assert task_args[8] == "native-session"
    assert task_args[10] == ""
    assert task_args[11] is False
    assert receipts == [(
        "message-1",
        {"dispatch_attempt_id": "attempt-1", "task_id": "task-2"},
    )]


class _RetryRaised(RuntimeError):
    pass


def _raise_retry(**kwargs):
    raise _RetryRaised(str(kwargs.get("exc") or "retry"))


def test_dispatch_releases_attempt_when_broker_rejects_publish(monkeypatch):
    run_turn = _RecordedTask(error=RuntimeError("broker unavailable"))
    released = []
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: _claim(),
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(
        queue,
        "release_agent_session_message_dispatch_attempt",
        lambda message_id, **kwargs: released.append((message_id, kwargs)) or True,
    )
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    with pytest.raises(_RetryRaised, match="broker unavailable"):
        dispatch(SimpleNamespace(retry=_raise_retry), "session-1")

    assert released == [(
        "message-1",
        {"dispatch_attempt_id": "attempt-1", "task_id": "task-2"},
    )]


def test_dispatch_keeps_attempt_when_broker_receipt_write_fails(monkeypatch):
    run_turn = _RecordedTask()
    released = []
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: _claim(),
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    monkeypatch.setattr(
        queue,
        "mark_agent_session_message_broker_enqueued",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("receipt unavailable")
        ),
    )
    monkeypatch.setattr(
        queue,
        "release_agent_session_message_dispatch_attempt",
        lambda *args, **kwargs: released.append((args, kwargs)) or True,
    )
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    with pytest.raises(_RetryRaised, match="receipt unavailable"):
        dispatch(SimpleNamespace(retry=_raise_retry), "session-1")

    assert len(run_turn.calls) == 1
    assert released == []


def test_explicit_continue_dispatches_marked_head_as_a_fresh_native_session(
    monkeypatch,
):
    run_turn = _RecordedTask()
    claim = {
        **_claim(),
        "native_session_id": "",
        "dispatch_payload": {"start_fresh_native_session": True},
    }
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: claim,
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    dispatch(SimpleNamespace(retry=lambda **_kwargs: None), "session-1")

    _args, kwargs = run_turn.calls[0]
    assert kwargs["args"][8] == ""
    assert kwargs["args"][10] == ""
    assert kwargs["args"][11] is True


def test_dispatch_does_nothing_when_session_has_no_claim(monkeypatch):
    run_turn = _RecordedTask()
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: None,
    )
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    result = dispatch(SimpleNamespace(), "session-1")

    assert result == {"success": True, "dispatched": False}
    assert run_turn.calls == []


def test_dispatch_prepares_queue_checkpoint_and_removes_previous_base(monkeypatch):
    run_turn = _RecordedTask()
    prepared = []
    removed = []
    claim = {
        **_claim(),
        "newly_promoted": True,
        "base_runtime_checkpoint_id": "task-2",
        "previous_base_runtime_checkpoint_id": "task-1-base",
    }

    def claim_next(session_id, **kwargs):
        kwargs["prepare_runtime_checkpoint"](session_id, "task-2")
        return claim

    monkeypatch.setattr(queue, "claim_next_agent_session_message", claim_next)
    monkeypatch.setattr(
        queue,
        "create_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: prepared.append(
            (session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(
        queue,
        "remove_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: removed.append(
            (session_id, checkpoint_id)
        ),
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    dispatch(SimpleNamespace(retry=lambda **_kwargs: None), "session-1")

    assert prepared == [("session-1", "task-2")]
    assert removed == [("session-1", "task-1-base")]


def test_dispatch_retry_restores_the_superseded_turn_baseline(monkeypatch):
    run_turn = _RecordedTask()
    claim = {
        **_claim(),
        "retry_of_task_id": "task-failed",
        "base_runtime_checkpoint_id": "checkpoint-before-failure",
    }
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: claim,
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    dispatch, _recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)

    dispatch(SimpleNamespace(retry=lambda **_kwargs: None), "session-1")

    _args, kwargs = run_turn.calls[0]
    assert kwargs["args"][10] == "checkpoint-before-failure"


def test_dispatch_first_solve_turn_uses_specialized_task(monkeypatch):
    run_turn = _RecordedTask()
    solve = _RecordedTask()
    claim = {
        **_claim(),
        "task_id": "solve-1",
        "session_id": "solve-1",
        "turn_index": 1,
        "task_kind": "solve",
        "problem_id": 9,
        "access_role": "user",
        "endpoint_revision": 4,
    }
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: claim,
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    dispatch, _recover = queue.register_agent_queue_tasks(
        _FakeCelery(),
        run_turn,
        agent_solve_problem_task=solve,
    )

    dispatch(SimpleNamespace(retry=lambda **_kwargs: None), "solve-1")

    assert run_turn.calls == []
    _args, kwargs = solve.calls[0]
    assert kwargs["task_id"] == "solve-1"
    assert kwargs["args"] == (9, "admin", "pi", 8, "", "session", 4)


def test_dispatch_first_testdata_turn_restores_private_payload(monkeypatch):
    run_turn = _RecordedTask()
    testdata = _RecordedTask()
    claim = {
        **_claim(),
        "task_id": "testdata-1",
        "session_id": "testdata-1",
        "turn_index": 1,
        "task_kind": "testdata",
        "problem_id": 9,
        "access_role": "user",
        "endpoint_revision": 5,
        "dispatch_payload": {
            "test_point_count": 6,
            "standard_code": "print(1)\n",
            "data_requirement": "覆盖边界",
            "standard_filename": "answer.py",
        },
    }
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_message",
        lambda _sid, **_kwargs: claim,
    )
    monkeypatch.setattr(queue, "upsert_agent_run_snapshot", lambda _state: None)
    dispatch, _recover = queue.register_agent_queue_tasks(
        _FakeCelery(),
        run_turn,
        agent_generate_testdata_task=testdata,
    )

    dispatch(SimpleNamespace(retry=lambda **_kwargs: None), "testdata-1")

    assert run_turn.calls == []
    _args, kwargs = testdata.calls[0]
    assert kwargs["task_id"] == "testdata-1"
    assert kwargs["args"] == (
        9,
        "admin",
        6,
        "print(1)\n",
        "覆盖边界",
        "answer.py",
        "pi",
        8,
        "",
        "session",
        5,
    )


def test_recovery_schedules_every_authoritative_candidate(monkeypatch):
    run_turn = _RecordedTask()
    monkeypatch.setattr(
        queue,
        "list_agent_session_queue_recovery_candidates",
        lambda **_kwargs: ["session-1", "session-2"],
    )
    dispatch, recover = queue.register_agent_queue_tasks(_FakeCelery(), run_turn)
    dispatch.apply_async = _RecordedTask().apply_async
    calls = []
    dispatch.apply_async = lambda *args, **kwargs: calls.append((args, kwargs))

    result = recover()

    assert result == {"success": True, "candidates": 2, "scheduled": 2}
    assert [call[1]["args"] for call in calls] == [
        ("session-1",),
        ("session-2",),
    ]


def test_control_bridge_delivers_one_steer_and_maps_ack(monkeypatch):
    completed = []
    monkeypatch.setattr(
        queue,
        "claim_next_agent_session_steer",
        lambda session_id, *, task_id: {
            "message_id": "steer-1",
            "user_message": "先检查附件",
            "attachments": [{"path": "attachments/steer-1/note.md"}],
        },
    )
    monkeypatch.setattr(
        queue,
        "finish_agent_session_message_delivery",
        lambda message_id, **kwargs: completed.append((message_id, kwargs)),
    )
    source, callback = queue.build_agent_control_bridge("session-1", "task-1")

    commands = source()
    assert commands == ({
        "id": "steer-1",
        "type": "steer",
        "target_task_id": "task-1",
        "message": (
            "先检查附件\n\n用户随本条消息上传了以下附件，文件已经放入 workspace。"
            "请在需要时直接读取：\n- /workspace/attachments/steer-1/note.md"
        ),
    },)

    callback("steer-1", "accepted")
    assert completed == [(
        "steer-1",
        {
            "status": "sent",
            "task_id": "task-1",
            "error_message": "",
        },
    )]
