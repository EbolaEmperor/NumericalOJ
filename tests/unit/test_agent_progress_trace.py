import json

import pytest

from oj_modules import db_services
from oj_modules.agents import sessions as agent_sessions
from oj_modules.tasks.agent import shared


class _FakeRedis:
    def __init__(self):
        self.values = []
        self.messages = []

    def setex(self, key, ttl, payload):
        self.values.append((key, ttl, payload))

    def publish(self, channel, payload):
        self.messages.append((channel, payload))


def test_cancel_snapshot_keeps_owning_session_id(monkeypatch):
    projected = []
    class Cursor:
        rowcount = 1

        def __init__(self):
            self.calls = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            self.calls.append((" ".join(query.split()), params))

        def fetchone(self):
            return {
                "task_id": "turn-2",
                "session_id": "session-1",
                "status": "Canceled",
                "message": "任务已由管理员终止",
                "attempts_json": "[]",
            }

    class Connection:
        def __init__(self):
            self.cursor_instance = Cursor()
            self.commits = 0
            self.closed = False

        def cursor(self):
            return self.cursor_instance

        def commit(self):
            self.commits += 1

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        db_services,
        "get_db_connection",
        lambda: connection,
    )
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state_in_transaction",
        lambda cursor, state: projected.append((cursor, dict(state))) or True,
    )

    state, changed = db_services.cancel_agent_run_snapshot("turn-2")

    assert changed is True
    assert state["session_id"] == "session-1"
    select_query, select_params = connection.cursor_instance.calls[1]
    assert "LEFT JOIN agent_session_turns AS t ON t.task_id=r.task_id" in select_query
    assert "WHERE r.task_id=%s" in select_query
    assert select_params == ("turn-2",)
    assert projected == [(
        connection.cursor_instance,
        {
            "task_id": "turn-2",
            "session_id": "session-1",
            "status": "Canceled",
            "message": "任务已由管理员终止",
            "_preserve_conclusion": True,
        },
    )]
    assert connection.commits == 1
    assert connection.closed is True


def test_cancel_snapshot_claims_current_session_before_run_snapshot_exists(
    monkeypatch,
):
    """session/turn outbox 已提交时，停止必须抢在 dispatcher 前写入 sticky 终态。"""

    projected = []

    class Cursor:
        def __init__(self):
            self.calls = []
            self.values = iter([
                None,
                {
                    "session_id": "session-before-run",
                    "problem_id": None,
                    "problem_title": "通用 Agent",
                    "requested_by": "admin",
                    "harness": "codex",
                    "endpoint_id": 17,
                    "endpoint_model": "gpt-test",
                },
                {
                    "task_id": "turn-before-run",
                    "session_id": "session-before-run",
                    "requested_by": "admin",
                    "harness": "codex",
                    "endpoint_id": 17,
                    "endpoint_model": "gpt-test",
                    "status": "Canceled",
                    "message": "任务已由管理员终止",
                    "attempts_json": "[]",
                },
            ])
            self.rowcount = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params):
            normalized = " ".join(query.split())
            self.calls.append((normalized, params))
            self.rowcount = 1 if "INSERT INTO agent_task_runs" in normalized else 0

        def fetchone(self):
            return next(self.values)

    class Connection:
        def __init__(self):
            self.cursor_instance = Cursor()
            self.commits = 0
            self.closed = False

        def cursor(self):
            return self.cursor_instance

        def commit(self):
            self.commits += 1

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state_in_transaction",
        lambda cursor, state: projected.append((cursor, dict(state))) or True,
    )

    state, changed = db_services.cancel_agent_run_snapshot("turn-before-run")

    assert changed is True
    assert state["status"] == "Canceled"
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert "LOWER(s.status) IN ('pending', 'running')" in queries[2]
    assert "INSERT INTO agent_task_runs" in queries[3]
    assert "ON DUPLICATE KEY UPDATE" in queries[3]
    assert projected[0][1]["session_id"] == "session-before-run"
    assert projected[0][1]["status"] == "Canceled"
    assert connection.commits == 1
    assert connection.closed is True


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
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state",
        lambda _state: (_ for _ in ()).throw(
            AssertionError("sticky Canceled 只能由清理控制器投影到会话"),
        ),
    )
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


@pytest.mark.parametrize(
    ("persisted_status", "expected_harness_status"),
    [
        ("Completed", "completed"),
        ("Failed", "error"),
        ("CleanupFailed", "cleanup_failed"),
    ],
)
def test_persisted_terminal_overrides_late_conflicting_snapshot(
    monkeypatch,
    persisted_status,
    expected_harness_status,
):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda _state: {
            "status": persisted_status,
            "message": "已经提交的终态",
        },
    )
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)
    state = {
        "task_id": "task-terminal",
        "status": "Running",
        "message": "仍在执行",
        "attempts": [],
    }

    shared._update_agent_state(state, "迟到的失败", status="Failed")

    assert state["status"] == persisted_status
    assert state["message"] == "已经提交的终态"
    assert state["stage"] == "finished"
    assert state["harness_status"] == expected_harness_status
    published = json.loads(redis.values[-1][2])
    assert published["status"] == persisted_status


def test_session_projection_failure_does_not_mask_legacy_state_or_publish(
        monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(shared, "upsert_agent_run_snapshot", lambda state: dict(state))
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state",
        lambda _state: (_ for _ in ()).throw(RuntimeError("session db offline")),
    )
    state = {"task_id": "task-sync-failure", "status": "Running", "attempts": []}

    shared._persist_agent_state(state)

    assert state["status"] == "Running"
    assert json.loads(redis.values[-1][2])["task_id"] == "task-sync-failure"


def test_completed_session_wakes_persistent_fifo_after_state_commit(monkeypatch):
    redis = _FakeRedis()
    dispatched = []
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda state: {"status": state["status"], "message": state.get("message")},
    )
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        shared,
        "_agent_queue_dispatch_task",
        type("Dispatch", (), {
            "apply_async": staticmethod(
                lambda *, args: dispatched.append(args)
            ),
        })(),
    )

    shared._persist_agent_state({
        "task_id": "task-2",
        "session_id": "session-1",
        "status": "Completed",
        "message": "done",
        "attempts": [],
    })

    assert dispatched == [("session-1",)]


def test_failed_session_does_not_automatically_continue_fifo(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "upsert_agent_run_snapshot",
        lambda state: {"status": state["status"], "message": state.get("message")},
    )
    monkeypatch.setattr(shared, "hydrate_agent_run_snapshot", lambda state: state)
    monkeypatch.setattr(
        shared,
        "_agent_queue_dispatch_task",
        type("Dispatch", (), {
            "apply_async": staticmethod(
                lambda **_kwargs: pytest.fail("失败后队列必须暂停")
            ),
        })(),
    )

    shared._persist_agent_state({
        "task_id": "task-2",
        "session_id": "session-1",
        "status": "Failed",
        "message": "failed",
        "attempts": [],
    })


def test_cancel_agent_run_publishes_terminal_snapshot_and_marker(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(shared, "_agent_progress_rds", redis)
    monkeypatch.setattr(
        shared,
        "cancel_agent_run_snapshot",
        lambda _task_id, _message: ({
            "task_id": "task-3",
            "session_id": "session-3",
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
    assert result["state"]["session_id"] == "session-3"
    assert result["state"]["harness"] == "pi"
    assert redis.values[-2][0] == "agent_run_cancel:task-3"
    assert redis.values[-1][0] == "agent_run:task-3"
    assert json.loads(redis.messages[-1][1])["status"] == "Canceled"


def test_existing_terminal_result_short_circuits_broker_redelivery(monkeypatch):
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session_by_task_id",
        lambda _task_id: None,
    )
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


@pytest.mark.parametrize("status", ["CleanupFailed", "cleanup_failed"])
def test_cleanup_failed_result_short_circuits_broker_redelivery(
    monkeypatch,
    status,
):
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session_by_task_id",
        lambda _task_id: None,
    )
    monkeypatch.setattr(
        shared,
        "get_agent_run_by_task_id",
        lambda _task_id: {
            "task_id": "task-cleanup-failed",
            "status": status,
            "message": "容器清理状态未知",
        },
    )

    result = shared.existing_agent_terminal_result("task-cleanup-failed")

    assert result == {
        "success": False,
        "cleanup_failed": True,
        "message": "容器清理状态未知",
        "task_id": "task-cleanup-failed",
    }


def test_terminal_redelivery_repairs_current_session_before_short_circuit(
    monkeypatch,
):
    projected = []
    monkeypatch.setattr(
        shared,
        "get_agent_run_by_task_id",
        lambda _task_id: {
            "task_id": "turn-2",
            "status": "Completed",
            "message": "发布已完成",
        },
    )
    monkeypatch.setattr(
        agent_sessions,
        "get_agent_session_by_task_id",
        lambda _task_id: {
            "session_id": "session-1",
            "is_legacy": False,
        },
    )
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state",
        lambda state: projected.append(dict(state)) or True,
    )

    result = shared.existing_agent_terminal_result("turn-2")

    assert result["success"] is True
    assert projected == [{
        "task_id": "turn-2",
        "session_id": "session-1",
        "status": "Completed",
        "message": "发布已完成",
        "_preserve_conclusion": True,
    }]
