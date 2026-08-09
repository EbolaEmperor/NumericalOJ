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
        one_values=[{"status": "Completed", "turn_count": 1}],
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
    assert len(calls) == 2
    assert "UPDATE agent_session_turns AS t" in calls[0][0]
    assert calls[0][1] == ("[]", "session-empty", "turn-empty", "turn-empty")
    assert "SELECT t.attachments_json" in calls[1][0]
    assert "s.current_task_id=%s AND LOWER(s.status)='pending'" in calls[1][0]
    assert "FOR UPDATE" in calls[1][0]
    assert calls[1][1] == ("session-empty", "turn-empty", "turn-empty")
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
    assert len(queries) == 3
    assert "FOR UPDATE" in queries[0]
    assert "UPDATE agent_sessions" in queries[1]
    assert "UPDATE agent_session_turns" in queries[2]
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
