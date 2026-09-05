"""正式 Judge 在一次性 MySQL/Redis 上复用通用持久会话。"""

from types import SimpleNamespace

import pytest

from backend.oj_modules.agents import judge, quota, sessions, workspace
from backend.oj_modules import db_services
from backend.oj_modules.infrastructure.mysql import get_db_connection


def _submit(kind, **overrides):
    return dict(
        session_id=judge.judge_session_id(42, "attempt-db", kind),
        task_id=f"db-{kind}-first", requested_by="admin", judge_kind=kind,
        submission_id=42, attempt_id="attempt-db", competition_id=7,
        harness="pi", endpoint={"id": 17, "model": "private-model", "competition_id": 7},
        prompt="审核所给材料", timeout_seconds=120,
        celery_app=SimpleNamespace(send_task=lambda *_args, **_kwargs: None),
        **overrides,
    )


def test_judge_roundtrip_idempotent_dispatch_internal_resume_and_cancel(monkeypatch, tmp_path):
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", tmp_path / "agent-workspaces")
    kwargs = _submit("reverse_answer", files={"template/answer.txt": "待作答"})
    created = judge.submit_judge_turn(**kwargs)
    replay = judge.submit_judge_turn(**kwargs)
    sid = created["session_id"]
    assert replay["session_id"] == sid
    assert len(sessions.get_agent_session_turns(sid)) == 1
    assert sessions.get_agent_session_runtime_config(sid)["endpoint_source"] == "competition"
    assert "runtime_config_json" not in sessions.get_agent_session(sid)
    assert sessions.get_judge_session_for_attempt(42, "attempt-db", "reverse_answer")["session_id"] == sid
    assert not sessions.get_agent_sessions_paginated()[0]
    assert [row["session_id"] for row in sessions.get_agent_sessions_paginated(judge_only=True)[0]] == [sid]

    with pytest.raises(PermissionError):
        sessions.enqueue_agent_session_message(sid, message_id="injection", created_by="admin", user_message="人工插话", delivery_mode="steer", target_task_id=created["current_task_id"])
    sessions.sync_agent_session_state({
        "session_id": sid, "task_id": created["current_task_id"], "status": "Completed",
        "message": "首轮完成", "conclusion": "继续下一阶段",
        "native_session_id": "12121212-1212-4212-8212-121212121212",
    })
    kwargs.update(task_id="db-answer-finish", prompt="保存答案", timeout_seconds=10, files=None)
    resumed = judge.submit_judge_turn(**kwargs)
    assert resumed["turn_count"] == 2
    assert sessions.get_agent_session_runtime_config(sid, "db-answer-finish")["timeout_seconds"] == 10
    turns = sessions.get_agent_session_turns(sid)
    assert turns[-1]["base_runtime_checkpoint_id"] == "db-answer-finish"
    assert turns[-1]["base_native_session_id"] == "12121212-1212-4212-8212-121212121212"

    # dispatcher 尚未创建 agent_task_runs，取消仍必须原子关闭 outbox。
    canceled, changed = db_services.cancel_agent_run_snapshot("db-answer-finish")
    assert changed and canceled["status"] == "Canceled"
    assert sessions.get_agent_session(sid)["status"] == "Canceled"
    assert sessions.claim_next_agent_session_message(sid) is None


def test_judge_site_funding_needs_no_personal_quota_and_is_idempotent():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username='admin'")
            uid = cursor.fetchone()["id"]
    finally:
        conn.close()
    sessions.create_agent_session(
        session_id="db-funded-judge", task_id="db-funded-judge-turn",
        requested_by="admin", harness="pi", endpoint_id=998,
        endpoint_revision=1, endpoint_model="exclusive-judge-model", user_message="评测",
        task_kind="judge", judge_kind="agent_judge", submission_id=42,
        attempt_id="billing-db", competition_id=7,
    )
    usage = dict(
        user_id=uid, session_id="db-funded-judge", task_id="db-funded-judge-turn",
        source="relay_openai", usage_event_id="funded-request",
        endpoint_id=None, endpoint_revision=1, endpoint_model="exclusive-judge-model",
        usage={"input_uncached_tokens": 100_000, "input_cached_tokens": 0,
               "input_cache_write_tokens": 0, "output_tokens": 50_000, "reasoning_output_tokens": 0},
        pricing={"input_price_per_million": "2", "cached_input_price_per_million": "0",
                 "output_price_per_million": "4"}, site_funded=True,
    )
    first = quota.charge_agent_usage(**usage)
    replay = quota.charge_agent_usage(**usage)
    assert first["applied"] and not replay["applied"]
    assert first["charged_amount"] == "0.4" and first["remaining_amount"] is None
    assert not first["hard_stop"]
    assert quota.get_agent_session_usage_cost("db-funded-judge") == "0.4"
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS n FROM agent_quota_accounts WHERE user_id=%s", (uid,))
            assert cursor.fetchone()["n"] == 0
            cursor.execute("SELECT COUNT(*) AS n FROM agent_usage_ledger WHERE task_id=%s", ("db-funded-judge-turn",))
            assert cursor.fetchone()["n"] == 1
    finally:
        conn.close()
    with pytest.raises(quota.AgentQuotaValidationError, match="全站代付"):
        quota.charge_agent_usage(**{**usage, "task_id": "unrelated-task"})
