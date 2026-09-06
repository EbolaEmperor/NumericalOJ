"""一次性 MySQL 上验证历史 Judge 提示词回填的事务和展示一致性。"""

from datetime import datetime

import pymysql
import pytest

from backend.oj_modules.agents import sessions
from backend.oj_modules.db_services import upsert_agent_run_snapshot
from backend.oj_modules.infrastructure.mysql import get_db_connection
from scripts import backfill_judge_history_prompts as backfill


HISTORICAL_TIME = datetime(2024, 1, 2, 3, 4, 5)


def _create_session(session_id, *, kind="agent_judge", historical=True, task_kind="judge", prompt=None):
    judge_fields = {}
    if task_kind == "judge":
        judge_fields = {
            "judge_kind": kind, "submission_id": 73, "attempt_id": "saved-attempt",
            "competition_id": 7,
            "runtime_config": {"historical_import": True, "historical_import_completed": 1}
            if historical else None,
        }
    sessions.create_agent_session(
        session_id=session_id, task_id=session_id, requested_by="admin",
        harness="pi", endpoint_id=0, endpoint_revision=1, endpoint_model="历史节点",
        user_message=backfill.PLACEHOLDER if prompt is None else prompt,
        task_kind=task_kind, title="历史 Judge 提示词", **judge_fields,
    )
    upsert_agent_run_snapshot({
        "task_id": session_id, "session_id": session_id, "requested_by": "admin",
        "task_kind": task_kind, "harness": "pi", "status": "Completed",
        "stage": "finished", "harness_status": "completed", "message": "历史评测已归档",
        "conclusion": "原有历史结论",
    })
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            for query in (
                "UPDATE agent_sessions SET created_at=%s, updated_at=%s WHERE session_id=%s",
                "UPDATE agent_session_turns SET created_at=%s, updated_at=%s WHERE session_id=%s",
                "UPDATE agent_session_messages SET created_at=%s, updated_at=%s, delivered_at=%s WHERE session_id=%s",
                "UPDATE agent_task_runs SET created_at=%s, updated_at=%s WHERE task_id=%s",
            ):
                values = (HISTORICAL_TIME,) * (3 if "delivered_at" in query else 2)
                cursor.execute(query, (*values, session_id))
        conn.commit()
    finally:
        conn.close()
    return session_id


def _snapshot(session_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            result = {}
            for key, query in (
                ("session", "SELECT * FROM agent_sessions WHERE session_id=%s"),
                ("turn", "SELECT * FROM agent_session_turns WHERE session_id=%s"),
                ("message", "SELECT * FROM agent_session_messages WHERE session_id=%s"),
                ("run", "SELECT * FROM agent_task_runs WHERE task_id=%s"),
            ):
                cursor.execute(query, (session_id,))
                result[key] = cursor.fetchall()
            for key, query in (
                ("ledger", "SELECT * FROM agent_usage_ledger ORDER BY id"),
                ("accounts", "SELECT * FROM agent_quota_accounts ORDER BY user_id"),
                ("trace", "SELECT * FROM agent_trace_events ORDER BY id"),
            ):
                cursor.execute(query)
                result[key] = cursor.fetchall()
            return result
    finally:
        conn.close()


def _recovered(text):
    return {"text": text, "status": "restored", "prompt_count": 2, "sources": ["saved-history.jsonl"]}


@pytest.mark.parametrize("kind", ["agent_judge", "reverse_quality", "reverse_answer"])
def test_backfill_restores_both_prompts_without_execution_or_other_mutation(monkeypatch, kind):
    session_id = _create_session(f"db-prompt-{kind}-history", kind=kind)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO agent_quota_accounts (user_id,granted_amount,used_amount) SELECT id,10,2 FROM users WHERE username='admin'")
        conn.commit()
    finally:
        conn.close()
    previous = _snapshot(session_id)
    row, = backfill.load_candidates()
    text = "历史输入 1\n\n请阅读题目。\n\n历史输入 2\n\n请按规则审核并保留原结论。"
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered(text))
    from celery import Celery
    monkeypatch.setattr(Celery, "send_task", lambda *_args, **_kwargs: pytest.fail("回填不能派发任务"))

    result = backfill.backfill_one(row)

    assert result["status"] == "restored"
    current = _snapshot(session_id)
    expected = previous
    expected["turn"][0]["user_message"] = text
    expected["message"][0]["user_message"] = text
    assert current == expected
    assert sessions.get_agent_session_turns(session_id)[0]["user_message"] == text
    assert sessions.get_agent_session_message(session_id)["user_message"] == text
    assert sessions.claim_next_agent_session_message(session_id) is None
    assert backfill.load_candidates() == []
    assert sessions.can_view_agent_session(sessions.get_agent_session(session_id), username="admin") is (kind == "reverse_answer")
    assert not sessions.can_view_agent_session(sessions.get_agent_session(session_id), username="another")


def test_candidate_selection_excludes_ordinary_native_and_already_restored_sessions():
    wanted = _create_session("db-prompt-selected-history")
    _create_session("db-prompt-ordinary", task_kind="custom")
    _create_session("db-prompt-native-judge", historical=False)
    _create_session("db-prompt-existing-history", prompt="已经保存的真实提示词")

    rows = backfill.load_candidates()

    assert [row["session_id"] for row in rows] == [wanted]
    assert rows[0]["task_id"] == rows[0]["message_id"] == wanted
    assert rows[0]["turn_prompt"] == rows[0]["message_prompt"] == backfill.PLACEHOLDER


def test_missing_original_prompt_records_explicit_notice_without_other_changes(monkeypatch):
    session_id = _create_session("db-prompt-missing-history")
    row, = backfill.load_candidates()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: {
        "text": backfill.MISSING_PROMPT, "status": "missing", "prompt_count": 0, "sources": [],
    })

    assert backfill.backfill_one(row)["status"] == "missing"
    before["turn"][0]["user_message"] = backfill.MISSING_PROMPT
    before["message"][0]["user_message"] = backfill.MISSING_PROMPT
    assert _snapshot(session_id) == before
    assert backfill.load_candidates() == []


def test_message_update_failure_rolls_back_already_updated_turn(monkeypatch):
    session_id = _create_session("db-prompt-rollback-history")
    row, = backfill.load_candidates()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered("真实历史输入"))
    statements = []
    real_connection = backfill.get_db_connection

    class Cursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def __enter__(self):
            self.cursor.__enter__()
            return self

        def __exit__(self, *args):
            return self.cursor.__exit__(*args)

        def execute(self, query, *args):
            normalized = " ".join(query.split()).upper()
            statements.append(normalized)
            if normalized.startswith("UPDATE AGENT_SESSION_MESSAGES"):
                raise pymysql.OperationalError(1205, "injected message update failure")
            return self.cursor.execute(query, *args)

        def __getattr__(self, name):
            return getattr(self.cursor, name)

    class Connection:
        def __init__(self):
            self.connection = real_connection()

        def cursor(self, *args, **kwargs):
            return Cursor(self.connection.cursor(*args, **kwargs))

        def __getattr__(self, name):
            return getattr(self.connection, name)

    monkeypatch.setattr(backfill, "get_db_connection", Connection)
    with pytest.raises(pymysql.OperationalError, match="injected message update failure"):
        backfill.backfill_one(row)

    assert any(query.startswith("UPDATE AGENT_SESSION_TURNS") for query in statements)
    assert _snapshot(session_id) == before


@pytest.mark.parametrize("existing_side", ["turn", "message"])
def test_existing_real_prompt_only_fills_the_other_placeholder(existing_side):
    session_id = _create_session("db-prompt-partial-history")
    text = "已经存在的真实提示词，不能重建或替换。"
    query = (
        "UPDATE agent_session_turns SET user_message=%s, updated_at=updated_at WHERE session_id=%s"
        if existing_side == "turn" else
        "UPDATE agent_session_messages SET user_message=%s, updated_at=updated_at WHERE session_id=%s"
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, (text, session_id))
        conn.commit()
    finally:
        conn.close()
    row, = backfill.load_candidates()
    before = _snapshot(session_id)

    assert backfill.backfill_one(row)["status"] == "existing"

    before["turn"][0]["user_message"] = text
    before["message"][0]["user_message"] = text
    assert _snapshot(session_id) == before
    assert backfill.load_candidates() == []


def test_candidate_changed_after_loading_is_not_overwritten(monkeypatch):
    session_id = _create_session("db-prompt-stale-history")
    row, = backfill.load_candidates()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE agent_session_turns SET user_message=%s WHERE session_id=%s",
                ("另一事务已写入的历史原文", session_id),
            )
        conn.commit()
    finally:
        conn.close()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered("迟到的回填文本"))

    assert backfill.backfill_one(row)["status"] == "skipped_changed"
    assert _snapshot(session_id) == before
