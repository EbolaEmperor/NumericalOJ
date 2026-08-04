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
