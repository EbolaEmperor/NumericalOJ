# -*- coding: utf-8 -*-
"""通用 Agent 会话在真实 MySQL 上的生命周期契约。"""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from oj_modules.agents.sessions import (
    AgentSessionBusyError,
    AgentSessionMessageConflictError,
    begin_agent_session_retry,
    begin_agent_session_turn,
    cancel_queued_agent_session_message,
    claim_next_agent_session_message,
    claim_next_agent_session_steer,
    continue_agent_session_queue,
    create_agent_session,
    enqueue_agent_session_message,
    finish_agent_session_message_delivery,
    get_agent_session,
    get_agent_session_by_task_id,
    get_agent_session_queue_snapshot,
    get_agent_session_turns,
    get_agent_sessions_paginated,
    list_agent_session_messages,
    list_agent_session_queue_recovery_candidates,
    mark_agent_session_message_broker_enqueued,
    pause_agent_session_queue,
    release_agent_session_message_dispatch_attempt,
    reorder_queued_agent_session_messages,
    set_agent_turn_attachments,
    sync_agent_session_state,
    update_queued_agent_session_message,
)
from oj_modules.db_services import upsert_agent_run_snapshot
from oj_modules.infrastructure.mysql import get_db_connection


def test_agent_session_round_trip_resume_and_atomic_state_projection():
    created = create_agent_session(
        session_id="db-agent-session",
        task_id="db-agent-turn-1",
        requested_by="admin",
        harness="codex",
        endpoint_id=17,
        endpoint_revision=4,
        endpoint_model="db-test-model",
        user_message="先完成第一轮",
        attachments=[{"name": "input.txt", "path": "attachments/turn-1/input.txt"}],
        base_runtime_checkpoint_id="db-checkpoint-initial",
        access_role="admin",
    )
    assert created["status"] == "Pending"
    first_messages = list_agent_session_messages("db-agent-session")
    assert [(item["message_id"], item["delivery_mode"], item["status"]) for item in first_messages] == [
        ("db-agent-turn-1", "turn", "dispatching")
    ]

    with pytest.raises(AgentSessionBusyError):
        begin_agent_session_turn(
            "db-agent-session",
            task_id="db-agent-racing-turn",
            user_message="不能抢占运行中的轮次",
        )

    assert sync_agent_session_state({
        "session_id": "db-agent-session",
        "task_id": "db-agent-turn-1",
        "status": "Completed",
        "message": "首轮完成",
        "title": "真实数据库会话",
        "native_session_id": "11111111-1111-4111-8111-111111111111",
        "conclusion": "首轮结论",
    }) is True

    first = get_agent_session("db-agent-session")
    assert first["title"] == "真实数据库会话"
    assert first["native_session_id"] == "11111111-1111-4111-8111-111111111111"
    assert first["endpoint_revision"] == 4
    assert list_agent_session_messages("db-agent-session")[0]["status"] == "sent"

    claim = begin_agent_session_turn(
        "db-agent-session",
        task_id="db-agent-turn-2",
        user_message="继续第二轮",
        base_runtime_checkpoint_id="db-checkpoint-before-turn-2",
        base_native_session_id="11111111-1111-4111-8111-111111111111",
    )
    assert claim == {
        "turn_index": 2,
        "task_kind": "custom",
        "problem_id": None,
        "requested_by": "admin",
        "access_role": "admin",
        "harness": "codex",
        "endpoint_id": 17,
        "endpoint_revision": 4,
        "endpoint_model": "db-test-model",
        "native_session_id": "11111111-1111-4111-8111-111111111111",
        "user_message": "继续第二轮",
        "attachments": [],
        "base_runtime_checkpoint_id": "db-checkpoint-before-turn-2",
        "previous_base_runtime_checkpoint_id": "db-checkpoint-initial",
        "base_native_session_id": "11111111-1111-4111-8111-111111111111",
        "retry_of_task_id": "",
        "replaced_task_id": "",
        "agent_message": {
            "message_id": "db-agent-turn-2",
            "session_id": "db-agent-session",
            "created_by": "admin",
            "user_message": "继续第二轮",
            "attachments": [],
            "delivery_mode": "turn",
            "status": "dispatching",
            "target_task_id": "db-agent-turn-2",
            "final_task_id": "db-agent-turn-2",
            "queue_position": 0,
            "error_message": "",
            "delivered_at": None,
            "created_at": None,
            "updated_at": None,
        },
    }
    assert [
        (item["message_id"], item["delivery_mode"], item["status"])
        for item in list_agent_session_messages("db-agent-session")
    ] == [
        ("db-agent-turn-1", "turn", "sent"),
        ("db-agent-turn-2", "turn", "dispatching"),
    ]
    assert sync_agent_session_state({
        "session_id": "db-agent-session",
        "task_id": "db-agent-turn-2",
        "status": "Completed",
        "message": "第二轮完成",
        "native_session_id": "22222222-2222-4222-8222-222222222222",
        "conclusion": "第二轮结论",
    }) is True

    turns = get_agent_session_turns("db-agent-session")
    assert [(turn["turn_index"], turn["status"], turn["conclusion"]) for turn in turns] == [
        (1, "Completed", "首轮结论"),
        (2, "Completed", "第二轮结论"),
    ]
    assert get_agent_session_by_task_id("db-agent-turn-1")["session_id"] == (
        "db-agent-session"
    )


def test_agent_session_retry_supersedes_only_the_failed_physical_attempt():
    create_agent_session(
        session_id="db-agent-retry",
        task_id="db-agent-retry-turn-1",
        requested_by="admin",
        harness="codex",
        endpoint_id=29,
        endpoint_revision=1,
        endpoint_model="retry-model",
        user_message="执行可能失败的任务",
        attachments=[{"name": "retry.txt"}],
        base_runtime_checkpoint_id="db-retry-checkpoint-initial",
        access_role="admin",
    )
    assert sync_agent_session_state({
        "session_id": "db-agent-retry",
        "task_id": "db-agent-retry-turn-1",
        "status": "Failed",
        "message": "首轮失败",
        "native_session_id": "44444444-4444-4444-8444-444444444444",
        "conclusion": "首轮失败结论",
    }) is True

    retry = begin_agent_session_retry(
        "db-agent-retry",
        "db-agent-retry-turn-2",
        "db-agent-retry-turn-1",
        "unused-fallback",
    )

    assert retry["turn_index"] == 2
    assert retry["user_message"] == "执行可能失败的任务"
    assert retry["attachments"] == [{"name": "retry.txt"}]
    assert retry["base_runtime_checkpoint_id"] == (
        "db-retry-checkpoint-initial"
    )
    assert retry["native_session_id"] == ""
    assert retry["retry_of_task_id"] == "db-agent-retry-turn-1"
    assert [
        (item["message_id"], item["delivery_mode"], item["status"])
        for item in list_agent_session_messages("db-agent-retry")
    ] == [
        ("db-agent-retry-turn-1", "turn", "sent"),
        ("db-agent-retry-turn-2", "turn", "dispatching"),
    ]

    visible_turns = get_agent_session_turns("db-agent-retry")
    all_turns = get_agent_session_turns(
        "db-agent-retry",
        include_superseded=True,
    )
    assert [turn["task_id"] for turn in visible_turns] == [
        "db-agent-retry-turn-2"
    ]
    assert [turn["task_id"] for turn in all_turns] == [
        "db-agent-retry-turn-1",
        "db-agent-retry-turn-2",
    ]
    assert all_turns[0]["superseded_by_task_id"] == (
        "db-agent-retry-turn-2"
    )
    assert all_turns[1]["retry_of_task_id"] == "db-agent-retry-turn-1"
    assert get_agent_session("db-agent-retry")["turn_count"] == 2


def test_session_list_deduplicates_compatibility_run_snapshot():
    create_agent_session(
        session_id="db-agent-list",
        task_id="db-agent-list-turn",
        requested_by="admin",
        harness="pi",
        endpoint_id=19,
        endpoint_revision=2,
        endpoint_model="list-model",
        user_message="验证兼容列表",
    )
    upsert_agent_run_snapshot({
        "task_id": "db-agent-list-turn",
        "session_id": "db-agent-list",
        "requested_by": "admin",
        "harness": "pi",
        "endpoint_id": 19,
        "endpoint_model": "list-model",
        "status": "Pending",
    })

    rows, page, total_pages = get_agent_sessions_paginated(page=1, per_page=20)

    assert page == 1
    assert total_pages == 1
    assert [row["session_id"] for row in rows] == ["db-agent-list"]


def test_empty_attachment_continuation_accepts_mysql_unchanged_rowcount():
    create_agent_session(
        session_id="db-agent-empty-attachments",
        task_id="db-agent-empty-turn-1",
        requested_by="admin",
        harness="pi",
        endpoint_id=23,
        endpoint_revision=1,
        endpoint_model="empty-attachment-model",
        user_message="先完成第一轮",
        attachments=[],
        access_role="admin",
    )
    assert sync_agent_session_state({
        "session_id": "db-agent-empty-attachments",
        "task_id": "db-agent-empty-turn-1",
        "status": "Completed",
        "message": "首轮完成",
        "native_session_id": "33333333-3333-4333-8333-333333333333",
        "conclusion": "首轮结论",
    }) is True

    begin_agent_session_turn(
        "db-agent-empty-attachments",
        task_id="db-agent-empty-turn-2",
        user_message="不带附件继续",
        attachments=[],
    )

    # begin_agent_session_turn 已写入 JSON []；真实 MySQL 对下面的
    # [] -> [] UPDATE 返回 affected_rows=0，但 CAS 目标仍然有效。
    assert set_agent_turn_attachments(
        "db-agent-empty-attachments",
        "db-agent-empty-turn-2",
        [],
    ) is True
    turns = get_agent_session_turns("db-agent-empty-attachments")
    assert turns[-1]["task_id"] == "db-agent-empty-turn-2"
    assert turns[-1]["attachments"] == []


def _create_completed_queue_session(session_id="db-agent-queue"):
    first_task_id = f"{session_id}-turn-1"
    create_agent_session(
        session_id=session_id,
        task_id=first_task_id,
        requested_by="admin",
        harness="codex",
        endpoint_id=31,
        endpoint_revision=7,
        endpoint_model="queue-model",
        user_message="首轮消息",
        access_role="admin",
    )
    assert sync_agent_session_state({
        "session_id": session_id,
        "task_id": first_task_id,
        "status": "Completed",
        "message": "首轮完成",
        "native_session_id": "queue-native-session",
        "conclusion": "首轮结论",
    }) is True
    return first_task_id


def test_agent_session_message_fifo_edit_reorder_cancel_and_claim():
    _create_completed_queue_session()
    first = enqueue_agent_session_message(
        "db-agent-queue",
        message_id="db-agent-message-1",
        created_by="admin",
        user_message="原第一条",
        attachments=[{"name": "one.txt", "path": "attachments/one.txt"}],
    )
    second = enqueue_agent_session_message(
        "db-agent-queue",
        message_id="db-agent-message-2",
        created_by="admin",
        user_message="原第二条",
    )
    third = enqueue_agent_session_message(
        "db-agent-queue",
        message_id="db-agent-message-3",
        created_by="admin",
        user_message="待删除",
    )
    assert first["queue_position"] < second["queue_position"] < third["queue_position"]

    assert update_queued_agent_session_message(
        "db-agent-queue",
        "db-agent-message-1",
        user_message="编辑后的第一条",
        attachments=[],
        expected_attachments=[{
            "name": "one.txt",
            "path": "attachments/one.txt",
        }],
    ) == [{"name": "one.txt", "path": "attachments/one.txt"}]
    assert cancel_queued_agent_session_message(
        "db-agent-queue",
        "db-agent-message-3",
        expected_attachments=[],
    ) == []
    assert reorder_queued_agent_session_messages(
        "db-agent-queue",
        ["db-agent-message-2", "db-agent-message-1"],
    ) is True

    queued = list_agent_session_messages(
        "db-agent-queue",
        delivery_modes="queue",
        statuses="queued",
    )
    assert [message["message_id"] for message in queued] == [
        "db-agent-message-2",
        "db-agent-message-1",
    ]
    claim = claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-2",
    )
    assert claim["message_id"] == "db-agent-message-2"
    assert claim["task_id"] == "db-agent-queue-turn-2"
    assert claim["turn_index"] == 2
    assert claim["requested_by"] == "admin"
    assert claim["access_role"] == "admin"
    assert claim["base_runtime_checkpoint_id"] == "db-agent-queue-turn-2"
    assert claim["base_native_session_id"] == "queue-native-session"
    assert claim["newly_promoted"] is True
    assert "db-agent-queue" not in (
        list_agent_session_queue_recovery_candidates()
    )

    # 活跃短租约会合并并发唤醒；确认 broker 未接收后释放，才可用同一
    # task_id 重新领取相同 outbox。
    assert claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-2",
    ) is None
    assert release_agent_session_message_dispatch_attempt(
        "db-agent-message-2",
        dispatch_attempt_id=claim["dispatch_attempt_id"],
        task_id="db-agent-queue-turn-2",
    ) is True
    assert "db-agent-queue" in list_agent_session_queue_recovery_candidates()
    repeated = claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-2",
    )
    assert repeated["message_id"] == "db-agent-message-2"
    assert repeated["base_runtime_checkpoint_id"] == "db-agent-queue-turn-2"
    assert repeated["newly_promoted"] is False
    assert repeated["dispatch_attempt_id"] != claim["dispatch_attempt_id"]
    assert mark_agent_session_message_broker_enqueued(
        "db-agent-message-2",
        dispatch_attempt_id=repeated["dispatch_attempt_id"],
        task_id="db-agent-queue-turn-2",
    ) is True
    assert "db-agent-queue" not in (
        list_agent_session_queue_recovery_candidates()
    )
    assert claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-2",
    ) is None

    # broker 回执不等于 worker 接收。若回执后的消息在租约期内始终没有
    # 投影为 Running/sent，恢复扫描必须用相同 task_id 再投一次。
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_session_messages
                SET dispatch_attempted_at=DATE_SUB(
                        CURRENT_TIMESTAMP, INTERVAL 120 SECOND
                    ),
                    broker_enqueued_at=DATE_SUB(
                        CURRENT_TIMESTAMP, INTERVAL 120 SECOND
                    )
                WHERE message_id=%s
                """,
                ("db-agent-message-2",),
            )
        conn.commit()
    finally:
        conn.close()
    assert "db-agent-queue" in list_agent_session_queue_recovery_candidates()
    recovered_after_receipt = claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-2",
    )
    assert recovered_after_receipt["message_id"] == "db-agent-message-2"
    assert recovered_after_receipt["task_id"] == "db-agent-queue-turn-2"
    assert recovered_after_receipt["dispatch_attempt_id"] != (
        repeated["dispatch_attempt_id"]
    )
    assert len(get_agent_session_turns("db-agent-queue")) == 2

    assert finish_agent_session_message_delivery(
        "db-agent-message-2",
        status="sent",
        task_id="db-agent-queue-turn-2",
    ) is True
    assert claim_next_agent_session_message("db-agent-queue") is None
    assert sync_agent_session_state({
        "session_id": "db-agent-queue",
        "task_id": "db-agent-queue-turn-2",
        "status": "Completed",
        "message": "第二轮完成",
        "conclusion": "第二轮结论",
    }) is True

    next_claim = claim_next_agent_session_message(
        "db-agent-queue",
        task_id="db-agent-queue-turn-3",
    )
    assert next_claim["message_id"] == "db-agent-message-1"
    assert next_claim["user_message"] == "编辑后的第一条"
    assert next_claim["turn_index"] == 3
    assert next_claim["base_runtime_checkpoint_id"] == "db-agent-queue-turn-3"
    assert next_claim["base_native_session_id"] == "queue-native-session"


def test_agent_session_steer_requires_current_task_and_tracks_ack():
    create_agent_session(
        session_id="db-agent-steer",
        task_id="db-agent-steer-turn",
        requested_by="admin",
        harness="pi",
        endpoint_id=33,
        endpoint_revision=2,
        endpoint_model="steer-model",
        user_message="运行首轮",
    )
    assert sync_agent_session_state({
        "session_id": "db-agent-steer",
        "task_id": "db-agent-steer-turn",
        "status": "Running",
        "message": "运行中",
    }) is True

    with pytest.raises(AgentSessionMessageConflictError, match="当前任务已变化"):
        enqueue_agent_session_message(
            "db-agent-steer",
            message_id="db-agent-stale-steer",
            created_by="admin",
            user_message="迟到的插话",
            delivery_mode="steer",
            target_task_id="db-agent-old-turn",
        )

    message = enqueue_agent_session_message(
        "db-agent-steer",
        message_id="db-agent-live-steer",
        created_by="admin",
        user_message="请先检查边界条件",
        delivery_mode="steer",
        target_task_id="db-agent-steer-turn",
    )
    # 相同 message_id 的网络重试不创建副本。
    retried = enqueue_agent_session_message(
        "db-agent-steer",
        message_id="db-agent-live-steer",
        created_by="admin",
        user_message="请先检查边界条件",
        delivery_mode="steer",
        target_task_id="db-agent-steer-turn",
    )
    assert retried["message_id"] == message["message_id"]

    claimed = claim_next_agent_session_steer(
        "db-agent-steer",
        task_id="db-agent-steer-turn",
    )
    assert claimed["status"] == "dispatching"
    assert claimed["user_message"] == "请先检查边界条件"
    assert finish_agent_session_message_delivery(
        "db-agent-live-steer",
        status="sent",
        task_id="db-agent-steer-turn",
    ) is True
    snapshot = get_agent_session_queue_snapshot("db-agent-steer")
    assert snapshot["running"] is True
    assert snapshot["messages"][-1]["status"] == "sent"


def test_agent_session_failure_pauses_fifo_until_explicit_continue():
    _create_completed_queue_session("db-agent-paused")
    enqueue_agent_session_message(
        "db-agent-paused",
        message_id="db-agent-paused-message",
        created_by="admin",
        user_message="失败后不要自动继续",
    )
    assert pause_agent_session_queue("db-agent-paused", "人工暂停") is True
    assert claim_next_agent_session_message("db-agent-paused") is None
    snapshot = get_agent_session_queue_snapshot("db-agent-paused")
    assert snapshot["queue_paused"] is True
    assert snapshot["queue_pause_reason"] == "人工暂停"

    assert continue_agent_session_queue("db-agent-paused") is True
    claim = claim_next_agent_session_message(
        "db-agent-paused",
        task_id="db-agent-paused-turn-2",
    )
    assert claim["message_id"] == "db-agent-paused-message"

    assert sync_agent_session_state({
        "session_id": "db-agent-paused",
        "task_id": "db-agent-paused-turn-2",
        "status": "Failed",
        "message": "执行失败",
    }) is True
    failed = get_agent_session("db-agent-paused")
    assert failed["queue_paused"] is True
    assert failed["queue_pause_reason"] == "执行失败"


def test_explicit_continue_after_pre_native_stop_starts_only_the_queue_head_fresh():
    session_id = "db-agent-pre-native-stop"
    first_task_id = f"{session_id}-turn-1"
    create_agent_session(
        session_id=session_id,
        task_id=first_task_id,
        requested_by="admin",
        harness="codex",
        endpoint_id=31,
        endpoint_revision=7,
        endpoint_model="queue-model",
        user_message="尚未建立原生会话的首轮",
        access_role="admin",
    )
    enqueue_agent_session_message(
        session_id,
        message_id="db-agent-pre-native-message-1",
        created_by="admin",
        user_message="停止后从现有 workspace 继续",
    )
    enqueue_agent_session_message(
        session_id,
        message_id="db-agent-pre-native-message-2",
        created_by="admin",
        user_message="后续仍按普通 FIFO 执行",
    )
    assert sync_agent_session_state({
        "session_id": session_id,
        "task_id": first_task_id,
        "status": "Canceled",
        "message": "首轮在原生会话建立前停止",
    }) is True
    stopped = get_agent_session(session_id)
    assert stopped["native_session_id"] == ""
    assert stopped["queue_paused"] is True

    assert continue_agent_session_queue(session_id) is True
    assert get_agent_session(session_id)["fresh_native_session_pending"] is True
    assert reorder_queued_agent_session_messages(
        session_id,
        [
            "db-agent-pre-native-message-2",
            "db-agent-pre-native-message-1",
        ],
    ) is True
    assert cancel_queued_agent_session_message(
        session_id,
        "db-agent-pre-native-message-2",
        expected_attachments=[],
    ) == []
    claim = claim_next_agent_session_message(
        session_id,
        task_id=f"{session_id}-turn-2",
    )

    assert claim["message_id"] == "db-agent-pre-native-message-1"
    assert claim["native_session_id"] == ""
    assert claim["base_native_session_id"] == ""
    assert claim["dispatch_payload"] == {
        "start_fresh_native_session": True,
    }
    assert get_agent_session(session_id)["fresh_native_session_pending"] is False

    assert release_agent_session_message_dispatch_attempt(
        claim["message_id"],
        dispatch_attempt_id=claim["dispatch_attempt_id"],
        task_id=f"{session_id}-turn-2",
    ) is True
    repeated = claim_next_agent_session_message(
        session_id,
        task_id=f"{session_id}-turn-2",
    )
    assert repeated["message_id"] == claim["message_id"]
    assert repeated["dispatch_payload"] == claim["dispatch_payload"]


def test_concurrent_fifo_claim_creates_only_one_turn():
    _create_completed_queue_session("db-agent-concurrent")
    enqueue_agent_session_message(
        "db-agent-concurrent",
        message_id="db-agent-concurrent-message-1",
        created_by="admin",
        user_message="第一条",
    )
    enqueue_agent_session_message(
        "db-agent-concurrent",
        message_id="db-agent-concurrent-message-2",
        created_by="admin",
        user_message="第二条",
    )

    def claim(task_id):
        try:
            result = claim_next_agent_session_message(
                "db-agent-concurrent",
                task_id=task_id,
            )
            return "claimed", result["message_id"] if result else None
        except AgentSessionMessageConflictError:
            return "conflict", None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, [
            "db-agent-concurrent-turn-a",
            "db-agent-concurrent-turn-b",
        ]))

    assert sorted(kind for kind, _message_id in results) == ["claimed", "conflict"]
    assert {message_id for _kind, message_id in results if message_id} == {
        "db-agent-concurrent-message-1"
    }
    turns = get_agent_session_turns("db-agent-concurrent")
    assert [turn["turn_index"] for turn in turns] == [1, 2]


def test_concurrent_queue_edits_use_attachment_snapshot_cas():
    session_id = "db-agent-concurrent-edit"
    _create_completed_queue_session(session_id)
    original = {
        "name": "original.txt",
        "path": "attachments/original/original.txt",
    }
    candidates = [
        {"name": "left.txt", "path": "attachments/left/left.txt"},
        {"name": "right.txt", "path": "attachments/right/right.txt"},
    ]
    enqueue_agent_session_message(
        session_id,
        message_id="db-agent-concurrent-edit-message",
        created_by="admin",
        user_message="等待并发编辑",
        attachments=[original],
    )
    barrier = Barrier(2)

    def edit(candidate):
        barrier.wait()
        try:
            removed = update_queued_agent_session_message(
                session_id,
                "db-agent-concurrent-edit-message",
                user_message=f"保留 {candidate['name']}",
                attachments=[candidate],
                expected_attachments=[original],
            )
            return "updated", candidate, removed
        except AgentSessionMessageConflictError:
            return "conflict", candidate, None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(edit, candidates))

    assert sorted(result[0] for result in results) == ["conflict", "updated"]
    winner = next(result[1] for result in results if result[0] == "updated")
    assert next(result[2] for result in results if result[0] == "updated") == [
        original
    ]
    stored = list_agent_session_messages(
        session_id,
        delivery_modes="queue",
        statuses="queued",
    )
    assert stored[0]["attachments"] == [winner]


def test_concurrent_queue_edit_and_delete_cannot_clean_a_newer_snapshot():
    session_id = "db-agent-edit-delete"
    _create_completed_queue_session(session_id)
    original = {
        "name": "original.txt",
        "path": "attachments/original/original.txt",
    }
    replacement = {
        "name": "replacement.txt",
        "path": "attachments/replacement/replacement.txt",
    }
    enqueue_agent_session_message(
        session_id,
        message_id="db-agent-edit-delete-message",
        created_by="admin",
        user_message="等待编辑或删除",
        attachments=[original],
    )
    barrier = Barrier(2)

    def edit():
        barrier.wait()
        try:
            removed = update_queued_agent_session_message(
                session_id,
                "db-agent-edit-delete-message",
                user_message="编辑胜出",
                attachments=[replacement],
                expected_attachments=[original],
            )
            return "updated", removed
        except AgentSessionMessageConflictError:
            return "conflict", None

    def delete():
        barrier.wait()
        try:
            removed = cancel_queued_agent_session_message(
                session_id,
                "db-agent-edit-delete-message",
                expected_attachments=[original],
            )
            return "canceled", removed
        except AgentSessionMessageConflictError:
            return "conflict", None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = [executor.submit(edit), executor.submit(delete)]
        results = [future.result() for future in results]

    assert sorted(result[0] for result in results) in (
        ["canceled", "conflict"],
        ["conflict", "updated"],
    )
    winner = next(result for result in results if result[0] != "conflict")
    assert winner[1] == [original]
    stored = list_agent_session_messages(session_id, delivery_modes="queue")
    assert len(stored) == 1
    if winner[0] == "updated":
        assert stored[0]["status"] == "queued"
        assert stored[0]["attachments"] == [replacement]
    else:
        assert stored[0]["status"] == "canceled"
        assert stored[0]["attachments"] == [original]
