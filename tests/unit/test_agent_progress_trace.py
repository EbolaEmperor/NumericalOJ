import json

from oj_modules.tasks.agent import shared


class _FakeRedis:
    def __init__(self):
        self.values = []
        self.messages = []

    def setex(self, key, ttl, payload):
        self.values.append((key, ttl, payload))

    def publish(self, channel, payload):
        self.messages.append((channel, payload))


def test_agent_state_persists_core_and_publishes_real_trace_snapshot(monkeypatch):
    database_states = []
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda state: database_states.append(dict(state)),
    )
    monkeypatch.setattr(
        shared,
        "hydrate_agent_run_snapshot",
        lambda state: {
            **state,
            "execution_trace": {
                "status": "running",
                "trace_messages": [{"kind": "assistant", "text": "真实消息"}],
            },
        },
    )
    state = {
        "task_id": "task-1",
        "status": "Pending",
        "attempts": [],
        "events": [{"message": "旧事件"}],
    }

    shared._update_agent_state(
        state,
        "Agent 正在运行",
        status="Running",
        stage="running_harness",
    )

    assert len(database_states) == 1
    assert database_states[0]["status"] == "Running"
    assert "events" not in database_states[0]
    assert "execution_trace" not in database_states[0]
    published = json.loads(redis.values[-1][2])
    assert published["execution_trace"]["trace_messages"] == [
        {"kind": "assistant", "text": "真实消息"},
    ]
    assert redis.messages[-1][1] == redis.values[-1][2]


def test_trace_tick_does_not_write_database(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda _state: (_ for _ in ()).throw(
            AssertionError("轨迹 tick 不应写数据库"),
        ),
    )
    monkeypatch.setattr(
        shared,
        "hydrate_agent_run_snapshot",
        lambda state: {**state, "execution_trace": {"trace_messages": []}},
    )

    shared._publish_agent_trace({"task_id": "task-2", "status": "Running"})

    assert len(redis.values) == 1
    assert len(redis.messages) == 1


def test_persisted_cancellation_overrides_late_worker_snapshot(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda _state: {
            "status": "Canceled",
            "message": "任务已由管理员终止",
        },
    )
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)
    state = {
        "task_id": "task-canceled",
        "status": "Running",
        "message": "仍在执行",
        "attempts": [],
    }

    shared._update_agent_state(state, "迟到的失败", status="Failed")

    assert state["status"] == "Canceled"
    assert state["message"] == "任务已由管理员终止"
    published = json.loads(redis.values[-1][2])
    assert published["status"] == "Canceled"
    assert published["harness_status"] == "canceled"


def test_cancel_agent_run_publishes_terminal_snapshot_and_marker(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "cancel_agent_run_snapshot",
        lambda _task_id, _message: ({
            "task_id": "task-3",
            "status": "Canceled",
            "message": "任务已由管理员终止",
            "attempts": [],
        }, True),
    )
    monkeypatch.setattr(
        shared,
        "get_agent_run_snapshot",
        lambda _task_id: {"task_id": "task-3", "harness": "pi"},
    )
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)

    result = shared.cancel_agent_run("task-3")

    assert result["exists"] is True
    assert result["changed"] is True
    assert result["canceled"] is True
    assert result["state"]["harness"] == "pi"
    assert redis.values[-2][0] == "agent_run_cancel:task-3"
    assert redis.values[-1][0] == "agent_run:task-3"
    assert json.loads(redis.messages[-1][1])["status"] == "Canceled"


def test_existing_terminal_result_short_circuits_broker_redelivery(monkeypatch):
    monkeypatch.setattr(
        shared,
        "get_agent_run_by_task_id",
        lambda _task_id: {
            "task_id": "task-completed",
            "status": "Completed",
            "message": "已完成",
            "final_submission_id": 91,
            "latest_submission_id": 92,
            "attempts": [{"submission_id": 91}],
        },
    )

    result = shared.existing_agent_terminal_result("task-completed")

    assert result == {
        "success": True,
        "message": "已完成",
        "task_id": "task-completed",
        "final_submission_id": 91,
        "latest_submission_id": 92,
        "attempts": [{"submission_id": 91}],
    }
