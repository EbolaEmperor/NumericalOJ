# -*- coding: utf-8 -*-
"""通用 Agent 会话在真实 MySQL 上的生命周期契约。"""

import pytest

from oj_modules.agents.sessions import (
    AgentSessionBusyError,
    begin_agent_session_turn,
    create_agent_session,
    get_agent_session,
    get_agent_session_by_task_id,
    get_agent_session_turns,
    get_agent_sessions_paginated,
    set_agent_turn_attachments,
    sync_agent_session_state,
)
from oj_modules.db_services import upsert_agent_run_snapshot


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
        access_role="admin",
    )
    assert created["status"] == "Pending"

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

    claim = begin_agent_session_turn(
        "db-agent-session",
        task_id="db-agent-turn-2",
        user_message="继续第二轮",
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
    }
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
