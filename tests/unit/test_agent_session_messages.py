"""通用 Agent 持久消息队列的事务与 CAS 契约。"""

from __future__ import annotations

import pytest

from oj_modules.agents import messages
from tests.unit.test_agent_sessions import _ScriptedConnection


def _session_row(**overrides):
    row = {
        "current_task_id": "turn-current",
        "status": "Completed",
        "turn_count": 1,
        "queue_paused": 0,
        "fresh_native_session_pending": 0,
        "task_kind": "custom",
        "problem_id": None,
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "codex",
        "reasoning_effort": "default",
        "endpoint_id": 12,
        "endpoint_revision": 3,
        "endpoint_model": "gpt-test",
        "native_session_id": "native-1",
        "previous_base_runtime_checkpoint_id": "checkpoint-current-base",
    }
    row.update(overrides)
    return row


def _message_row(**overrides):
    row = {
        "message_id": "message-1",
        "session_id": "session-1",
        "created_by": "admin",
        "user_message": "继续检查",
        "attachments_json": "[]",
        "delivery_mode": "queue",
        "status": "queued",
        "target_task_id": None,
        "final_task_id": None,
        "queue_position": 2048,
        "error_message": None,
        "delivered_at": None,
        "created_at": None,
        "updated_at": None,
        "dispatch_attempt_id": None,
        "dispatch_attempted_at": None,
        "broker_enqueued_at": None,
    }
    row.update(overrides)
    return row


def test_enqueue_queue_message_locks_session_and_allocates_monotonic_position(
    monkeypatch,
):
    connection = _ScriptedConnection(
        one_values=[_session_row(), None, {"max_position": 2048}],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    result = messages.enqueue_agent_session_message(
        "session-1",
        message_id="message-1",
        created_by="admin",
        user_message="继续检查",
    )

    assert result["status"] == "queued"
    assert result["queue_position"] == 3072
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert "FROM agent_sessions" in queries[0]
    assert "FOR UPDATE" in queries[0]
    assert "WHERE message_id=%s" in queries[1]
    assert "MAX(queue_position)" in queries[2]
    assert "INSERT INTO agent_session_messages" in queries[3]
    assert connection.commits == 1


def test_steer_rejects_a_stale_client_task_without_falling_back_to_queue(
    monkeypatch,
):
    connection = _ScriptedConnection(
        one_values=[_session_row(status="Running"), None],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(
        messages.AgentSessionMessageConflictError,
        match="当前任务已变化",
    ):
        messages.enqueue_agent_session_message(
            "session-1",
            message_id="message-steer",
            created_by="admin",
            user_message="改变方向",
            delivery_mode="steer",
            target_task_id="turn-stale",
        )

    assert not any(
        "INSERT INTO agent_session_messages" in query
        for query, _params in connection.cursor_instance.calls
    )
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_queued_message_can_be_atomically_promoted_to_current_steer(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        _session_row(status="Running"),
        _message_row(),
    ])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    result = messages.steer_queued_agent_session_message(
        "session-1",
        "message-1",
        task_id="turn-current",
    )

    assert result["message_id"] == "message-1"
    assert result["delivery_mode"] == "steer"
    assert result["status"] == "queued"
    assert result["target_task_id"] == "turn-current"
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert "FROM agent_sessions" in queries[0] and "FOR UPDATE" in queries[0]
    assert "FROM agent_session_messages" in queries[1] and "FOR UPDATE" in queries[1]
    assert "SET delivery_mode='steer'" in queries[2]
    assert connection.commits == 1


def test_send_now_replay_returns_the_same_promoted_message(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        _session_row(status="Running"),
        _message_row(
            delivery_mode="steer",
            status="sent",
            target_task_id="turn-current",
        ),
    ])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    result = messages.steer_queued_agent_session_message(
        "session-1",
        "message-1",
        task_id="turn-current",
    )

    assert result["delivery_mode"] == "steer"
    assert result["status"] == "sent"
    assert not any(
        "UPDATE agent_session_messages" in query
        for query, _params in connection.cursor_instance.calls
    )


def test_claim_queue_message_creates_turn_and_updates_session_atomically(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[
            _session_row(
                fresh_native_session_pending=1,
                harness="pi",
                reasoning_effort="minimal",
            ),
            None,
            _message_row(dispatch_payload_json=(
                '{"private_value":7}'
            )),
        ],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)
    prepared = []

    claim = messages.claim_next_agent_session_message(
        "session-1",
        task_id="turn-next",
        prepare_runtime_checkpoint=(
            lambda session_id, checkpoint_id: prepared.append(
                (session_id, checkpoint_id)
            )
        ),
    )

    assert claim["message_id"] == "message-1"
    assert claim["task_id"] == "turn-next"
    assert claim["turn_index"] == 2
    assert claim["base_runtime_checkpoint_id"] == "turn-next"
    assert claim["previous_base_runtime_checkpoint_id"] == (
        "checkpoint-current-base"
    )
    assert claim["base_native_session_id"] == "native-1"
    assert claim["newly_promoted"] is True
    assert claim["reasoning_effort"] == "minimal"
    assert claim["dispatch_attempt_id"]
    assert claim["dispatch_payload"] == {
        "start_fresh_native_session": True,
        "private_value": 7,
    }
    assert prepared == [("session-1", "turn-next")]
    queries = [query for query, _params in connection.cursor_instance.calls]
    assert "FOR UPDATE" in queries[0]
    assert "m.status='dispatching'" in queries[1]
    assert "status='queued'" in queries[2]
    assert "dispatch_payload_json" in queries[2]
    assert "INSERT INTO agent_session_turns" in queries[3]
    assert "base_runtime_checkpoint_id" in queries[3]
    assert "SET status='dispatching', final_task_id=%s" in queries[4]
    assert "dispatch_attempt_id=%s" in queries[4]
    assert "SET current_task_id=%s, status='Pending'" in queries[5]
    assert "fresh_native_session_pending=0" in queries[5]
    assert connection.commits == 1


def test_claim_returns_existing_dispatch_record_after_lost_response(monkeypatch):
    existing = _message_row(
        status="dispatching",
        final_task_id="turn-next",
        turn_index=2,
        base_runtime_checkpoint_id="turn-next",
        base_native_session_id="native-1",
        retry_of_task_id="",
        previous_base_runtime_checkpoint_id="checkpoint-current-base",
    )
    connection = _ScriptedConnection(
        one_values=[_session_row(current_task_id="turn-next", status="Pending"), existing],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    claim = messages.claim_next_agent_session_message(
        "session-1",
        task_id="turn-next",
    )

    assert claim["message_id"] == "message-1"
    assert claim["task_id"] == "turn-next"
    assert claim["base_runtime_checkpoint_id"] == "turn-next"
    assert claim["newly_promoted"] is False
    assert claim["dispatch_attempt_id"]
    assert len(connection.cursor_instance.calls) == 3
    reclaim_query = connection.cursor_instance.calls[2][0]
    assert "broker_enqueued_at=NULL" in reclaim_query
    assert "AND broker_enqueued_at IS NULL" not in reclaim_query
    assert connection.commits == 1


def test_claim_recovers_initial_turn_outbox_with_private_dispatch_payload(monkeypatch):
    existing = _message_row(
        delivery_mode="turn",
        status="dispatching",
        final_task_id="turn-current",
        turn_index=1,
        dispatch_payload_json='{"test_point_count":4,"standard_code":"x"}',
    )
    connection = _ScriptedConnection(
        one_values=[
            _session_row(
                current_task_id="turn-current",
                status="Pending",
                task_kind="testdata",
            ),
            existing,
        ],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    claim = messages.claim_next_agent_session_message("session-1")

    assert claim["delivery_mode"] == "turn"
    assert claim["task_id"] == "turn-current"
    assert claim["dispatch_payload"] == {
        "test_point_count": 4,
        "standard_code": "x",
    }
    assert "delivery_mode IN ('turn','queue')" in (
        connection.cursor_instance.calls[1][0]
    )
    assert claim["dispatch_attempt_id"]


def test_recovery_candidates_include_turn_outbox_and_idle_queue(monkeypatch):
    connection = _ScriptedConnection(
        all_values=[[{"session_id": "session-1"}, {"session_id": "session-2"}]],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    assert messages.list_agent_session_queue_recovery_candidates(limit=10) == [
        "session-1",
        "session-2",
    ]
    query = connection.cursor_instance.calls[0][0]
    assert "m.delivery_mode IN ('turn','queue')" in query
    assert "m.broker_enqueued_at IS NULL" not in query
    assert "m.dispatch_attempted_at" in query
    assert "m.delivery_mode='queue' AND m.status='queued'" in query
    assert connection.cursor_instance.calls[0][1] == (
        messages._DISPATCH_ATTEMPT_LEASE_SECONDS,
        10,
    )


def test_terminal_snapshot_keeps_the_current_promoted_queue_message(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[{
            "current_task_id": "turn-next",
            "status": "Completed",
            "queue_paused": 0,
            "queue_pause_reason": None,
        }],
        all_values=[[_message_row(
            status="sent",
            final_task_id="turn-next",
        )]],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    snapshot = messages.get_agent_session_queue_snapshot("session-1")

    assert snapshot["running"] is False
    assert snapshot["messages"][0]["final_task_id"] == "turn-next"
    query, params = connection.cursor_instance.calls[1]
    assert "status='sent'" in query
    assert "%s=1" not in query
    assert params == ("session-1", "turn-next")


def test_delivery_ack_checks_linked_task_and_is_idempotent(monkeypatch):
    first = _ScriptedConnection(one_values=[{
        "status": "dispatching",
        "target_task_id": "turn-current",
        "final_task_id": None,
    }])
    second = _ScriptedConnection(one_values=[{
        "status": "sent",
        "target_task_id": "turn-current",
        "final_task_id": None,
    }])
    connections = iter([first, second])
    monkeypatch.setattr(messages, "get_db_connection", lambda: next(connections))

    assert messages.finish_agent_session_message_delivery(
        "message-steer",
        status="sent",
        task_id="turn-current",
    ) is True
    assert messages.finish_agent_session_message_delivery(
        "message-steer",
        status="sent",
        task_id="turn-current",
    ) is True
    assert len(first.cursor_instance.calls) == 2
    assert "WHERE message_id=%s AND status='dispatching'" in (
        first.cursor_instance.calls[1][0]
    )
    assert len(second.cursor_instance.calls) == 1


@pytest.mark.parametrize("status", ["Running", "CleanupFailed"])
def test_continue_queue_rechecks_terminal_state_under_session_lock(
    monkeypatch,
    status,
):
    connection = _ScriptedConnection(one_values=[_session_row(status=status)])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(messages.AgentSessionMessageConflictError):
        messages.continue_agent_session_queue("session-1")

    query = connection.cursor_instance.calls[0][0]
    assert "status, native_session_id" in query
    assert "FOR UPDATE" in query
    assert len(connection.cursor_instance.calls) == 1
    assert connection.rollbacks == 1


def test_continue_queue_sets_a_session_level_fresh_native_authorization(
    monkeypatch,
):
    connection = _ScriptedConnection(one_values=[
        _session_row(status="Canceled", native_session_id=""),
        {
            "message_id": "message-1",
        },
    ])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    assert messages.continue_agent_session_queue("session-1") is True

    queries = connection.cursor_instance.calls
    assert "status, native_session_id" in queries[0][0]
    assert "FOR UPDATE" in queries[0][0]
    assert "ORDER BY queue_position ASC, id ASC" in queries[1][0]
    assert "FOR UPDATE" in queries[1][0]
    assert "SET queue_paused=0" in queries[2][0]
    assert "fresh_native_session_pending=%s" in queries[2][0]
    assert queries[2][1] == (1, "session-1")
    assert not any(
        "UPDATE agent_session_messages" in query
        for query, _params in queries
    )
    assert connection.commits == 1


def test_active_dispatch_lease_coalesces_duplicate_wakes(monkeypatch):
    existing = _message_row(
        status="dispatching",
        final_task_id="turn-next",
        turn_index=2,
        dispatch_attempt_id="attempt-active",
        dispatch_attempted_at="2026-08-11 12:00:00",
        base_runtime_checkpoint_id="turn-next",
    )
    connection = _ScriptedConnection(one_values=[
        _session_row(current_task_id="turn-next", status="Pending"),
        existing,
    ])
    connection.cursor_instance.rowcount = 0
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    assert messages.claim_next_agent_session_message("session-1") is None
    assert "dispatch_attempted_at=CURRENT_TIMESTAMP" in (
        connection.cursor_instance.calls[2][0]
    )
    assert connection.commits == 0


def test_broker_receipt_and_pre_broker_release_are_attempt_scoped(monkeypatch):
    receipt_connection = _ScriptedConnection(one_values=[{
        "status": "dispatching",
        "final_task_id": "turn-next",
        "dispatch_attempt_id": "attempt-1",
        "broker_enqueued_at": None,
    }])
    release_connection = _ScriptedConnection()
    connections = iter([receipt_connection, release_connection])
    monkeypatch.setattr(messages, "get_db_connection", lambda: next(connections))

    assert messages.mark_agent_session_message_broker_enqueued(
        "message-1",
        dispatch_attempt_id="attempt-1",
        task_id="turn-next",
    ) is True
    assert messages.release_agent_session_message_dispatch_attempt(
        "message-1",
        dispatch_attempt_id="attempt-2",
        task_id="turn-next",
    ) is True

    receipt_update = receipt_connection.cursor_instance.calls[1]
    assert "SET broker_enqueued_at=CURRENT_TIMESTAMP" in receipt_update[0]
    assert receipt_update[1] == ("message-1", "turn-next", "attempt-1")
    release_update = release_connection.cursor_instance.calls[0]
    assert "SET dispatch_attempt_id=NULL" in release_update[0]
    assert release_update[1] == ("message-1", "turn-next", "attempt-2")


def test_continue_queue_without_native_requires_a_queued_head(monkeypatch):
    connection = _ScriptedConnection(one_values=[
        _session_row(status="Failed", native_session_id=""),
        None,
    ])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(
        messages.AgentSessionMessageConflictError,
        match="没有可继续",
    ):
        messages.continue_agent_session_queue("session-1")

    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_canceled_turn_stays_unsent_when_worker_never_confirmed_delivery():
    connection = _ScriptedConnection()
    cursor = connection.cursor_instance

    messages.sync_agent_message_state_in_transaction(
        cursor,
        task_id="turn-current",
        status="Canceled",
        reason="任务已被手动终止",
    )

    queries = [query for query, _params in cursor.calls]
    assert "SET status='canceled'" in queries[0]
    assert "SET status='sent'" not in queries[0]
    assert "delivery_mode='steer'" in queries[1]
    assert "delivery_mode='steer'" in queries[2]


def test_reorder_uses_the_complete_locked_fifo_set(monkeypatch):
    connection = _ScriptedConnection(
        one_values=[{"session_id": "session-1"}],
        all_values=[[{"message_id": "message-1"}, {"message_id": "message-2"}]],
    )
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(
        messages.AgentSessionMessageConflictError,
        match="已变化",
    ):
        messages.reorder_queued_agent_session_messages(
            "session-1",
            ["message-1"],
        )

    queries = [query for query, _params in connection.cursor_instance.calls]
    assert "FROM agent_sessions" in queries[0]
    assert "FOR UPDATE" in queries[0]
    assert "delivery_mode='queue' AND status='queued'" in queries[1]
    assert "FOR UPDATE" in queries[1]
    assert connection.rollbacks == 1


def test_queue_edit_cas_returns_only_lock_confirmed_removed_attachments(
    monkeypatch,
):
    first = {"name": "first.txt", "path": "attachments/a/first.txt"}
    second = {"name": "second.txt", "path": "attachments/b/second.txt"}
    connection = _ScriptedConnection(one_values=[{
        "delivery_mode": "queue",
        "status": "queued",
        "attachments_json": messages._json_text([first, second], []),
    }])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    removed = messages.update_queued_agent_session_message(
        "session-1",
        "message-1",
        user_message="保留第二份附件",
        attachments=[second],
        expected_attachments=[first, second],
    )

    assert removed == [first]
    calls = connection.cursor_instance.calls
    assert "attachments_json" in calls[0][0]
    assert "FOR UPDATE" in calls[0][0]
    assert "SET user_message=%s, attachments_json=%s" in calls[1][0]
    assert connection.commits == 1


def test_concurrent_queue_edit_rejects_a_stale_attachment_snapshot(monkeypatch):
    original = {"name": "input.txt", "path": "attachments/a/input.txt"}
    winner = {"name": "winner.txt", "path": "attachments/b/winner.txt"}
    connection = _ScriptedConnection(one_values=[{
        "delivery_mode": "queue",
        "status": "queued",
        "attachments_json": messages._json_text([original, winner], []),
    }])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(
        messages.AgentSessionMessageConflictError,
        match="已变化",
    ):
        messages.update_queued_agent_session_message(
            "session-1",
            "message-1",
            user_message="并发败者",
            attachments=[original],
            expected_attachments=[original],
        )

    assert len(connection.cursor_instance.calls) == 1
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_queue_delete_rejects_snapshot_changed_by_a_concurrent_edit(monkeypatch):
    original = {"name": "input.txt", "path": "attachments/a/input.txt"}
    added = {"name": "added.txt", "path": "attachments/b/added.txt"}
    connection = _ScriptedConnection(one_values=[{
        "delivery_mode": "queue",
        "status": "queued",
        "attachments_json": messages._json_text([original, added], []),
    }])
    monkeypatch.setattr(messages, "get_db_connection", lambda: connection)

    with pytest.raises(
        messages.AgentSessionMessageConflictError,
        match="已变化",
    ):
        messages.cancel_queued_agent_session_message(
            "session-1",
            "message-1",
            expected_attachments=[original],
        )

    assert len(connection.cursor_instance.calls) == 1
    assert connection.commits == 0
    assert connection.rollbacks == 1
