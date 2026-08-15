"""通用 Agent 会话/轮次数据层的并发与兼容查询契约。"""

from __future__ import annotations

from collections import deque

import pytest

from oj_modules.agents import sessions


class _ScriptedCursor:
    def __init__(self, *, one_values=(), all_values=()):
        self.one_values = deque(one_values)
        self.all_values = deque(all_values)
        self.calls = []
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))

    def fetchone(self):
        return self.one_values.popleft() if self.one_values else None

    def fetchall(self):
        return self.all_values.popleft() if self.all_values else []


class _ScriptedConnection:
    def __init__(self, *, one_values=(), all_values=()):
        self.cursor_instance = _ScriptedCursor(
            one_values=one_values,
            all_values=all_values,
        )
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def test_only_one_continuation_can_claim_a_terminal_session(monkeypatch):
    """第一次续聊把状态切回 Pending 后，竞争者必须在行锁内被拒绝。"""

    winner = _ScriptedConnection(
        one_values=[{
            "status": "Completed",
            "turn_count": 1,
            "requested_by": "admin",
        }],
    )
    loser = _ScriptedConnection(
        one_values=[{"status": "Pending", "turn_count": 2}],
    )
    connections = iter([winner, loser])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: next(connections))

    claim = sessions.begin_agent_session_turn(
        "session-1",
        task_id="turn-2",
        user_message="继续检查边界条件",
    )
    assert claim["turn_index"] == 2

    with pytest.raises(sessions.AgentSessionBusyError):
        sessions.begin_agent_session_turn(
            "session-1",
            task_id="turn-racing",
            user_message="与上一条并发到达",
        )

    winner_sql = [query for query, _params in winner.cursor_instance.calls]
    loser_sql = [query for query, _params in loser.cursor_instance.calls]
    assert "FOR UPDATE" in winner_sql[0]
    assert any("INSERT INTO agent_session_turns" in query for query in winner_sql)
    assert any(
        "SET current_task_id=%s, status='Pending'" in query
        for query in winner_sql
    )
    assert loser_sql == [loser_sql[0]]
    assert "FOR UPDATE" in loser_sql[0]
    assert winner.commits == 1
    assert loser.rollbacks == 1
    assert winner.closed is True
    assert loser.closed is True


def test_create_session_persists_the_first_turn_runtime_base(monkeypatch):
    connection = _ScriptedConnection()
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    sessions.create_agent_session(
        session_id="session-with-base",
        task_id="turn-with-base",
        requested_by="admin",
        harness="codex",
        endpoint_id=7,
        endpoint_revision=2,
        endpoint_model="gpt-test",
        user_message="从初始运行环境开始",
        attachments=[{"name": "input.txt"}],
        base_runtime_checkpoint_id="checkpoint-initial",
        base_native_session_id="native-initial",
    )

    calls = connection.cursor_instance.calls
    assert len(calls) == 3
    query, params = calls[1]
    assert "base_runtime_checkpoint_id" in query
    assert "base_native_session_id" in query
    assert params == (
        "session-with-base",
        "turn-with-base",
        "从初始运行环境开始",
        '[{"name": "input.txt"}]',
        "checkpoint-initial",
        "native-initial",
    )
    assert "INSERT INTO agent_session_messages" in calls[2][0]
    assert "'turn', 'dispatching'" in calls[2][0]
    assert connection.commits == 1


def test_continuation_freezes_runtime_base_and_locked_native_session(
    monkeypatch,
):
    connection = _ScriptedConnection(one_values=[{
        "status": "Completed",
        "turn_count": 2,
        "task_kind": "custom",
        "problem_id": None,
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "codex",
        "endpoint_id": 7,
        "endpoint_revision": 2,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-current",
        "previous_base_runtime_checkpoint_id": "checkpoint-previous",
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    claim = sessions.begin_agent_session_turn(
        "session-with-base",
        task_id="turn-3",
        user_message="继续完善",
        attachments=[],
        base_runtime_checkpoint_id="checkpoint-before-turn-3",
        base_native_session_id="native-current",
    )

    assert claim["turn_index"] == 3
    assert claim["native_session_id"] == "native-current"
    assert claim["base_native_session_id"] == "native-current"
    assert claim["base_runtime_checkpoint_id"] == "checkpoint-before-turn-3"
    assert claim["previous_base_runtime_checkpoint_id"] == (
        "checkpoint-previous"
    )
    insert_query, insert_params = connection.cursor_instance.calls[1]
    assert "base_runtime_checkpoint_id" in insert_query
    assert insert_params[-2:] == (
        "checkpoint-before-turn-3",
        "native-current",
    )


def test_continuation_rejects_a_stale_native_session_base(monkeypatch):
    connection = _ScriptedConnection(one_values=[{
        "status": "Completed",
        "turn_count": 1,
        "native_session_id": "native-authoritative",
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="原生会话基线已变化",
    ):
        sessions.begin_agent_session_turn(
            "session-stale-base",
            task_id="turn-2",
            user_message="继续",
            base_runtime_checkpoint_id="checkpoint-before-turn-2",
            base_native_session_id="native-stale",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_clones_current_turn_and_rolls_back_to_recorded_base(
    monkeypatch,
):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "turn-failed",
            "status": "Failed",
            "turn_count": 4,
            "task_kind": "custom",
            "problem_id": None,
            "requested_by": "admin",
            "access_role": "admin",
            "harness": "codex",
            "endpoint_id": 7,
            "endpoint_revision": 2,
            "endpoint_model": "gpt-test",
            "native_session_id": "native-after-failure",
        },
        {
            "task_id": "turn-failed",
            "turn_index": 4,
            "user_message": "请修复最后一个问题",
            "attachments_json": '[{"name": "case.txt"}]',
            "base_runtime_checkpoint_id": "checkpoint-before-failure",
            "base_native_session_id": "native-before-failure",
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    claim = sessions.begin_agent_session_retry(
        "session-retry",
        "turn-retry",
        "turn-failed",
        "unused-fallback",
    )

    assert claim == {
        "turn_index": 5,
        "task_kind": "custom",
        "problem_id": None,
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "codex",
        "endpoint_id": 7,
        "endpoint_revision": 2,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-before-failure",
        "user_message": "请修复最后一个问题",
        "attachments": [{"name": "case.txt"}],
        "base_runtime_checkpoint_id": "checkpoint-before-failure",
        "previous_base_runtime_checkpoint_id": "checkpoint-before-failure",
        "base_native_session_id": "native-before-failure",
        "retry_of_task_id": "turn-failed",
        "replaced_task_id": "turn-failed",
        "agent_message": {
            "message_id": "turn-retry",
            "session_id": "session-retry",
            "created_by": "admin",
            "user_message": "请修复最后一个问题",
            "attachments": [{"name": "case.txt"}],
            "delivery_mode": "turn",
            "status": "dispatching",
            "target_task_id": "turn-retry",
            "final_task_id": "turn-retry",
            "queue_position": 0,
            "error_message": "",
            "delivered_at": None,
            "created_at": None,
            "updated_at": None,
        },
    }
    calls = connection.cursor_instance.calls
    assert len(calls) == 7
    assert "FROM agent_sessions" in calls[0][0]
    assert "FOR UPDATE" in calls[0][0]
    assert "FROM agent_session_turns" in calls[1][0]
    assert "FOR UPDATE" in calls[1][0]
    assert "SET superseded_by_task_id=%s" in calls[2][0]
    assert calls[2][1] == (
        "turn-retry",
        "session-retry",
        "turn-failed",
    )
    assert "retry_of_task_id" in calls[3][0]
    assert calls[3][1] == (
        "session-retry",
        "turn-retry",
        5,
        "请修复最后一个问题",
        '[{"name": "case.txt"}]',
        "checkpoint-before-failure",
        "native-before-failure",
        "turn-failed",
    )
    assert "MAX(queue_position)" in calls[4][0]
    assert "INSERT INTO agent_session_messages" in calls[5][0]
    assert calls[5][1][0] == "turn-retry"
    assert calls[5][1][1] == "session-retry"
    assert calls[5][1][6:8] == ("turn-retry", "turn-retry")
    assert "native_session_id=NULLIF(%s, '')" in calls[6][0]
    assert calls[6][1] == (
        "turn-retry",
        "native-before-failure",
        5,
        "session-retry",
        "turn-failed",
    )
    assert connection.commits == 1
    assert connection.rollbacks == 0


@pytest.mark.parametrize(
    ("task_kind", "access_role"),
    [("solve", "user"), ("testdata", "admin")],
)
def test_retry_problem_agent_first_turn_uses_the_generic_contract(
    monkeypatch,
    task_kind,
    access_role,
):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "problem-first",
            "status": "Failed",
            "turn_count": 1,
            "task_kind": task_kind,
            "problem_id": 9,
            "requested_by": "admin",
            "access_role": access_role,
            "harness": "codex",
            "endpoint_id": 7,
            "endpoint_revision": 2,
            "endpoint_model": "gpt-test",
            "native_session_id": "native-after-failure",
        },
        {
            "task_id": "problem-first",
            "turn_index": 1,
            "user_message": "处理这道题",
            "attachments_json": "[]",
            "base_runtime_checkpoint_id": "checkpoint-before-first",
            "base_native_session_id": None,
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    claim = sessions.begin_agent_session_retry(
        "problem-session",
        "problem-retry",
        "problem-first",
        "unused-fallback",
    )

    assert claim["task_kind"] == task_kind
    assert claim["access_role"] == access_role
    assert claim["user_message"] == "处理这道题"
    assert claim["base_runtime_checkpoint_id"] == "checkpoint-before-first"
    assert claim["base_native_session_id"] == ""
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_retry_rejects_preupgrade_testdata_first_turn(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "testdata-first",
            "status": "Failed",
            "turn_count": 1,
            "task_kind": "testdata",
            "problem_id": 9,
            "requested_by": "admin",
            "access_role": "user",
            "harness": "codex",
            "endpoint_id": 7,
            "endpoint_revision": 2,
            "endpoint_model": "gpt-test",
            "native_session_id": "",
        },
        {
            "task_id": "testdata-first",
            "turn_index": 1,
            "user_message": "生成测试数据",
            "attachments_json": "[]",
            "base_runtime_checkpoint_id": "checkpoint-before-first",
            "base_native_session_id": None,
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="升级前造数据 Agent 的首轮不支持重试",
    ):
        sessions.begin_agent_session_retry(
            "testdata-session",
            "testdata-retry",
            "testdata-first",
            "unused-fallback",
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_allows_generic_followup_in_specialized_session(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "solve-followup",
            "status": "Completed",
            "turn_count": 2,
            "task_kind": "solve",
            "problem_id": 9,
            "requested_by": "admin",
            "access_role": "user",
            "harness": "codex",
            "endpoint_id": 7,
            "endpoint_revision": 2,
            "endpoint_model": "gpt-test",
            "native_session_id": "native-after-followup",
        },
        {
            "task_id": "solve-followup",
            "turn_index": 2,
            "user_message": "继续检查边界情况",
            "attachments_json": "[]",
            "base_runtime_checkpoint_id": "checkpoint-before-followup",
            "base_native_session_id": "native-after-solve",
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    claim = sessions.begin_agent_session_retry(
        "solve-session",
        "solve-followup-retry",
        "solve-followup",
        "unused-fallback",
    )

    assert claim["task_kind"] == "solve"
    assert claim["base_native_session_id"] == "native-after-solve"
    assert claim["user_message"] == "继续检查边界情况"
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_retry_legacy_first_turn_uses_fallback_and_empty_native(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "legacy-first",
            "status": "Completed",
            "turn_count": 1,
            "requested_by": "admin",
        },
        {
            "task_id": "legacy-first",
            "turn_index": 1,
            "user_message": "重试首轮",
            "attachments_json": "[]",
            "base_runtime_checkpoint_id": None,
            "base_native_session_id": None,
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    claim = sessions.begin_agent_session_retry(
        "legacy-session",
        "legacy-retry",
        "legacy-first",
        "checkpoint-initial-fallback",
    )

    assert claim["turn_index"] == 2
    assert claim["base_runtime_checkpoint_id"] == (
        "checkpoint-initial-fallback"
    )
    assert claim["base_native_session_id"] == ""
    assert claim["native_session_id"] == ""
    assert connection.cursor_instance.calls[6][1][1] == ""


def test_retry_rejects_unknown_nonfirst_legacy_base(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        {
            "current_task_id": "legacy-second",
            "status": "Completed",
            "turn_count": 2,
        },
        {
            "task_id": "legacy-second",
            "turn_index": 2,
            "user_message": "重试第二轮",
            "attachments_json": "[]",
            "base_runtime_checkpoint_id": None,
            "base_native_session_id": None,
            "superseded_by_task_id": None,
            "superseded_at": None,
        },
    ])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="缺少可恢复的运行时基线",
    ):
        sessions.begin_agent_session_retry(
            "legacy-session",
            "legacy-retry",
            "legacy-second",
            "checkpoint-fallback-must-not-be-used",
        )

    assert len(connection.cursor_instance.calls) == 2
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_rejects_stale_expected_task_under_session_lock(monkeypatch):
    connection = _ScriptedConnection(one_values=[{
        "current_task_id": "turn-newer",
        "status": "Completed",
        "turn_count": 3,
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="当前轮次已变化",
    ):
        sessions.begin_agent_session_retry(
            "session-racing-retry",
            "turn-retry",
            "turn-stale",
            "checkpoint-fallback",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert "FOR UPDATE" in connection.cursor_instance.calls[0][0]
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_cannot_overtake_a_persistent_queue(monkeypatch):
    connection = _ScriptedConnection(one_values=[{
        "current_task_id": "turn-failed",
        "status": "Failed",
        "turn_count": 2,
        "has_pending_queue": 1,
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="已有排队消息",
    ):
        sessions.begin_agent_session_retry(
            "session-with-queue",
            "turn-retry",
            "turn-failed",
            "checkpoint-fallback",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert "agent_session_messages AS queued_message" in (
        connection.cursor_instance.calls[0][0]
    )
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_rejects_cleanup_failed_session_before_reading_turn(monkeypatch):
    connection = _ScriptedConnection(one_values=[{
        "current_task_id": "turn-cleanup-failed",
        "status": "CleanupFailed",
        "turn_count": 2,
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="运行环境清理失败",
    ):
        sessions.begin_agent_session_retry(
            "session-cleanup-failed",
            "turn-retry",
            "turn-cleanup-failed",
            "checkpoint-fallback",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_retry_runtime_restore_failure_closes_outbox_and_pauses_queue(monkeypatch):
    connection = _ScriptedConnection()
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    sessions.mark_agent_turn_runtime_restore_failed(
        "session-retry",
        "turn-retry",
        "runtime checkpoint 损坏",
    )

    calls = connection.cursor_instance.calls
    assert len(calls) == 3
    assert "UPDATE agent_session_turns" in calls[0][0]
    assert "queue_paused=1" in calls[1][0]
    assert calls[1][1] == (
        "runtime checkpoint 损坏",
        "runtime checkpoint 损坏",
        "session-retry",
        "turn-retry",
    )
    assert "UPDATE agent_session_messages" in calls[2][0]
    assert "status='failed'" in calls[2][0]
    assert connection.commits == 1


def test_cleanup_failed_is_nonterminal_and_blocks_resume(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[{"status": "CleanupFailed", "turn_count": 3}],
    )
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    assert sessions.agent_status_is_terminal("CleanupFailed") is False
    with pytest.raises(sessions.AgentSessionBusyError):
        sessions.begin_agent_session_turn(
            "session-cleanup",
            task_id="turn-4",
            user_message="不能在残留容器未清理时恢复",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert "FOR UPDATE" in connection.cursor_instance.calls[0][0]
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_direct_turn_cannot_overtake_persistent_queue(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[{
            "status": "Completed",
            "turn_count": 1,
            "has_pending_queue": 1,
        }],
    )
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="已有排队消息",
    ):
        sessions.begin_agent_session_turn(
            "session-with-queue",
            task_id="turn-overtake",
            user_message="不能越过队首",
        )

    assert len(connection.cursor_instance.calls) == 1
    assert "agent_session_messages AS queued_message" in connection.cursor_instance.calls[0][0]
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_unchanged_empty_turn_attachments_confirm_the_current_cas_row(monkeypatch):
    """MySQL 的 changed-rows=0 不应把 [] -> [] 误报为换轮竞态。"""

    connection = _ScriptedConnection(
        one_values=[{"attachments_json": "[]"}],
    )
    connection.cursor_instance.rowcount = 0
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    assert sessions.set_agent_turn_attachments(
        "session-empty",
        "turn-empty",
        [],
    ) is True

    calls = connection.cursor_instance.calls
    assert len(calls) == 3
    assert "UPDATE agent_session_turns AS t" in calls[0][0]
    assert calls[0][1] == ("[]", "session-empty", "turn-empty", "turn-empty")
    assert "SELECT t.attachments_json" in calls[1][0]
    assert "s.current_task_id=%s AND LOWER(s.status)='pending'" in calls[1][0]
    assert "FOR UPDATE" in calls[1][0]
    assert calls[1][1] == ("session-empty", "turn-empty", "turn-empty")
    assert "UPDATE agent_session_messages" in calls[2][0]
    assert calls[2][1] == ("[]", "session-empty", "turn-empty")
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed is True


def test_zero_row_attachment_update_still_rejects_a_lost_cas(monkeypatch):
    connection = _ScriptedConnection(one_values=[None])
    connection.cursor_instance.rowcount = 0
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    with pytest.raises(
        sessions.AgentSessionBusyError,
        match="Agent 轮次附件状态已变化",
    ):
        sessions.set_agent_turn_attachments(
            "session-racing",
            "turn-racing",
            [],
        )

    assert len(connection.cursor_instance.calls) == 2
    assert "FOR UPDATE" in connection.cursor_instance.calls[1][0]
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert connection.closed is True


def test_late_old_turn_cannot_overwrite_the_current_turn(monkeypatch):
    connection = _ScriptedConnection(one_values=[None])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    changed = sessions.sync_agent_session_state({
        "session_id": "session-1",
        "task_id": "turn-old",
        "status": "Completed",
        "message": "迟到的旧结果",
        "title": "不应覆盖",
        "native_session_id": "native-old",
        "conclusion": "旧轮结论",
    })

    assert changed is False
    assert len(connection.cursor_instance.calls) == 1
    query, params = connection.cursor_instance.calls[0]
    assert "WHERE session_id=%s AND current_task_id=%s" in query
    assert params == ("session-1", "turn-old")
    assert connection.commits == 0
    assert connection.closed is True


@pytest.mark.parametrize("sticky_status", ["Canceled", "CleanupFailed"])
def test_late_worker_state_cannot_reopen_canceled_session(
    monkeypatch,
    sticky_status,
):
    connection = _ScriptedConnection(one_values=[{"status": sticky_status}])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    changed = sessions.sync_agent_session_state({
        "session_id": "session-1",
        "task_id": "turn-current",
        "status": "Running",
        "message": "迟到的 worker 快照",
    })

    assert changed is False
    assert len(connection.cursor_instance.calls) == 1
    query, params = connection.cursor_instance.calls[0]
    assert "SELECT status" in query
    assert "FOR UPDATE" in query
    assert params == ("session-1", "turn-current")
    assert connection.commits == 0
    assert connection.closed is True


@pytest.mark.parametrize(
    ("sticky_status", "incoming_status"),
    [("Completed", "Failed"), ("Failed", "Running")],
)
def test_late_worker_state_cannot_replace_committed_terminal_session(
    monkeypatch,
    sticky_status,
    incoming_status,
):
    connection = _ScriptedConnection(one_values=[{"status": sticky_status}])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    changed = sessions.sync_agent_session_state({
        "session_id": "session-terminal",
        "task_id": "turn-current",
        "status": incoming_status,
        "message": "迟到的冲突快照",
    })

    assert changed is False
    assert len(connection.cursor_instance.calls) == 1
    assert "FOR UPDATE" in connection.cursor_instance.calls[0][0]
    assert connection.commits == 0
    assert connection.closed is True


def test_cleanup_failure_can_escalate_a_canceled_session(monkeypatch):
    connection = _ScriptedConnection(one_values=[{"status": "Canceled"}])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    changed = sessions.sync_agent_session_state({
        "session_id": "session-1",
        "task_id": "turn-current",
        "status": "CleanupFailed",
        "message": "容器清理失败",
    })

    assert changed is True
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert len(queries) == 6
    assert "FOR UPDATE" in queries[0]
    assert "UPDATE agent_sessions" in queries[1]
    assert "UPDATE agent_session_turns" in queries[2]
    assert "UPDATE agent_session_messages" in queries[3]
    assert "delivery_mode='steer'" in queries[4]
    assert "delivery_mode='steer'" in queries[5]
    assert connection.commits == 1


def test_title_generation_claim_is_atomic_and_persists_fallback(monkeypatch):
    connection = _ScriptedConnection()
    connection.cursor_instance.rowcount = 1
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    assert sessions.claim_agent_session_title_generation(
        "session-1",
        "确定性回退标题",
    ) is True

    query, params = connection.cursor_instance.calls[0]
    assert "UPDATE agent_sessions" in query
    assert "title IS NULL OR title=''" in query
    assert params == ("确定性回退标题", "session-1")
    assert connection.commits == 1


def test_session_list_excludes_every_run_already_owned_by_a_turn(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[{"total": 1}],
        all_values=[[{
            "source_id": 8,
            "session_id": "session-visible",
            "current_task_id": "turn-new",
            "title": "继续完善程序",
            "task_kind": "custom",
            "problem_id": None,
            "problem_title": None,
            "requested_by": "admin",
            "access_role": "admin",
            "harness": "codex",
            "endpoint_id": 12,
            "endpoint_revision": 3,
            "endpoint_model": "gpt-test",
            "native_session_id": "native-1",
            "status": "Completed",
            "message": "完成",
            "turn_count": 2,
            "created_at": "2026-08-09 10:00:00",
            "updated_at": "2026-08-09 10:01:00",
            "is_legacy": 0,
        }]],
    )
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    result, page, total_pages = sessions.get_agent_sessions_paginated(
        page=1,
        per_page=20,
    )

    assert [item["session_id"] for item in result] == ["session-visible"]
    assert (page, total_pages) == (1, 1)
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert len(queries) == 2
    for query in queries:
        assert "FROM agent_task_runs AS r" in query
        assert "NOT EXISTS" in query
        assert "FROM agent_session_turns AS t" in query
        assert "t.task_id=r.task_id" in query
    assert (
        "ORDER BY updated_at DESC, is_legacy ASC, source_id DESC, session_id DESC"
        in queries[-1]
    )


def test_task_lookup_includes_historical_turns(monkeypatch):
    connection = _ScriptedConnection(one_values=[{
        "session_id": "session-1",
        "current_task_id": "turn-3",
        "title": "多轮任务",
        "task_kind": "solve",
        "problem_id": 9,
        "problem_title": "数值积分",
        "requested_by": "admin",
        "access_role": "user",
        "harness": "codex",
        "endpoint_id": 12,
        "endpoint_revision": 3,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-1",
        "status": "Completed",
        "message": "完成",
        "turn_count": 3,
        "created_at": None,
        "updated_at": None,
        "is_legacy": 0,
    }])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: connection)

    result = sessions.get_agent_session_by_task_id("turn-1")

    assert result["session_id"] == "session-1"
    query, params = connection.cursor_instance.calls[0]
    assert "LEFT JOIN agent_session_turns AS t" in query
    assert "s.current_task_id=%s OR t.task_id=%s" in query
    assert params == ("turn-1", "turn-1", "turn-1")


def test_turn_query_hides_superseded_attempts_unless_explicitly_requested(
    monkeypatch,
):
    turn_row = {
        "task_id": "turn-retried",
        "turn_index": 2,
        "user_message": "原消息",
        "attachments_json": "[]",
        "base_runtime_checkpoint_id": "checkpoint-base",
        "base_native_session_id": "native-base",
        "retry_of_task_id": "turn-original",
        "superseded_by_task_id": "turn-next-retry",
        "superseded_at": "2026-08-10 12:00:00",
        "status": "Failed",
        "conclusion": "失败结论",
        "harness": "codex",
        "endpoint_id": 7,
        "endpoint_model": "gpt-test",
        "created_at": None,
        "updated_at": None,
    }
    visible_connection = _ScriptedConnection(all_values=[[turn_row]])
    historical_connection = _ScriptedConnection(all_values=[[turn_row]])
    connections = iter([visible_connection, historical_connection])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: next(connections))

    visible = sessions.get_agent_session_turns("session-retry")
    historical = sessions.get_agent_session_turns(
        "session-retry",
        include_superseded=True,
    )

    assert visible[0]["retry_of_task_id"] == "turn-original"
    assert visible[0]["superseded_by_task_id"] == "turn-next-retry"
    assert visible[0]["superseded_at"] == "2026-08-10 12:00:00"
    assert historical == visible
    visible_query = visible_connection.cursor_instance.calls[0][0]
    historical_query = historical_connection.cursor_instance.calls[0][0]
    assert "AND t.superseded_at IS NULL" in visible_query
    assert "AND t.superseded_at IS NULL" not in historical_query
