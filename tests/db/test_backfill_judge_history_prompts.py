"""一次性 MySQL 上验证历史 Judge 多轮回填的事务和展示一致性。"""

from datetime import datetime
import json

from celery import Celery
import pymysql
import pytest

from backend.oj_modules.agents import sessions, trace_store
from backend.oj_modules.db_services import upsert_agent_run_snapshot
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.ranking.reverse_judge import traces
from scripts import backfill_judge_history_prompts as backfill


HISTORICAL_TIME = datetime(2024, 1, 2, 3, 4, 5)
V1_MERGED = "以下为该次历史评测实际发送的输入，按原始顺序汇总；未重建历史轮次。\n\n### 第 1 次输入\n\n首轮\n\n### 第 2 次输入\n\n第二轮"


def _execute(query, values=()):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, values)
        conn.commit()
    finally:
        conn.close()


def _create_session(session_id, *, kind="agent_judge", historical=True,
                    task_kind="judge", prompt=None, version=None, harness="pi"):
    judge_fields = {}
    if task_kind == "judge":
        runtime = {"historical_import": True, "historical_import_completed": 1}
        if version is not None:
            runtime["historical_prompt_version"] = version
        judge_fields = {
            "judge_kind": kind, "submission_id": 73, "attempt_id": "saved-attempt",
            "competition_id": 7, "runtime_config": runtime if historical else None,
        }
    sessions.create_agent_session(
        session_id=session_id, task_id=session_id, requested_by="admin",
        harness=harness, endpoint_id=0, endpoint_revision=1, endpoint_model="历史节点",
        user_message=backfill.PLACEHOLDER if prompt is None else prompt,
        task_kind=task_kind, title="历史 Judge 提示词", **judge_fields,
    )
    upsert_agent_run_snapshot({
        "task_id": session_id, "session_id": session_id, "requested_by": "admin",
        "task_kind": task_kind, "harness": harness, "endpoint_id": 0,
        "endpoint_model": "历史节点", "status": "Completed", "stage": "finished",
        "harness_status": "completed", "message": "历史评测已归档",
        "conclusion": "原有历史结论",
    })
    for query in (
        "UPDATE agent_sessions SET created_at=%s, updated_at=%s WHERE session_id=%s",
        "UPDATE agent_session_turns SET created_at=%s, updated_at=%s WHERE session_id=%s",
        "UPDATE agent_session_messages SET created_at=%s, updated_at=%s, delivered_at=%s WHERE session_id=%s",
        "UPDATE agent_task_runs SET created_at=%s, updated_at=%s WHERE task_id=%s",
    ):
        values = (HISTORICAL_TIME,) * (3 if "delivered_at" in query else 2)
        _execute(query, (*values, session_id))
    return session_id


def _snapshot(session_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            result = {}
            for key, query in (
                ("session", "SELECT * FROM agent_sessions WHERE session_id=%s"),
                ("turns", "SELECT * FROM agent_session_turns WHERE session_id=%s ORDER BY turn_index"),
                ("messages", "SELECT * FROM agent_session_messages WHERE session_id=%s ORDER BY id"),
                ("runs", "SELECT r.* FROM agent_task_runs r JOIN agent_session_turns t ON t.task_id=r.task_id WHERE t.session_id=%s ORDER BY t.turn_index"),
                ("trace", "SELECT e.* FROM agent_trace_events e JOIN agent_session_turns t ON t.task_id=e.task_id WHERE t.session_id=%s ORDER BY e.id"),
                ("sync", "SELECT e.* FROM agent_trace_sync_state e JOIN agent_session_turns t ON t.task_id=e.task_id WHERE t.session_id=%s ORDER BY e.task_id"),
            ):
                cursor.execute(query, (session_id,))
                result[key] = cursor.fetchall()
            for key, query in (
                ("ledger", "SELECT * FROM agent_usage_ledger ORDER BY id"),
                ("accounts", "SELECT * FROM agent_quota_accounts ORDER BY user_id"),
            ):
                cursor.execute(query)
                result[key] = cursor.fetchall()
            return result
    finally:
        conn.close()


def _seed_trace(session_id):
    # 原工作块跨过真实轮次边界，且思考文本重复，回填必须按 event_id 拆分。
    events = [
        ("thinking", "重复的思考内容", 0),
        ("tool_result", "首轮工具结果", 0),
        ("thinking", "重复的思考内容", 1),
        ("tool_result", "第二轮工具结果", 1),
        ("assistant", "首轮回复", 0),
        ("assistant", "第二轮回复", 1),
    ]
    trace_store.ingest_agent_trace_records(session_id, [
        {"version": 1, "type": "numoj_trace", "sequence": index,
         "event": {"id": f"history-{index}", "kind": kind, "text": text}}
        for index, (kind, text, _turn) in enumerate(events, 1)
    ], final=True)
    trace_store.save_agent_trace_token_usage(session_id, {
        "source": "pi", "request_count": 2, "input_uncached_tokens": 120,
        "input_cached_tokens": 30, "output_tokens": 15,
    })
    _execute("UPDATE agent_trace_events SET created_at=%s WHERE task_id=%s", (HISTORICAL_TIME, session_id))
    _execute("INSERT INTO agent_quota_accounts (user_id,granted_amount,used_amount) SELECT id,10,2 FROM users WHERE username='admin'")
    stored = _snapshot(session_id)["trace"]
    return {event["event_id"]: events[event["event_order"] - 1][2] for event in stored}


def _recovered(*texts, event_turns=None, status="restored"):
    return {
        "turns": [{"text": text, "phase": ""} for text in texts],
        "event_turns": event_turns or {}, "status": status,
        "prompt_count": len(texts), "sources": ["saved-history.jsonl"], "warnings": [],
    }


def _assert_session_preserved(before, after, count):
    expected = dict(before["session"][0])
    runtime = json.loads(expected["runtime_config_json"])
    runtime["historical_prompt_version"] = 2
    expected["runtime_config_json"] = runtime
    expected["turn_count"] = count
    actual = dict(after["session"][0])
    actual["runtime_config_json"] = json.loads(actual["runtime_config_json"])
    assert actual == expected
    assert after["ledger"] == before["ledger"]
    assert after["accounts"] == before["accounts"]
    original_task_id = expected["current_task_id"]
    previous_usage = next((item["token_usage_json"] for item in before["sync"] if item["task_id"] == original_task_id), None)
    assert next((item["token_usage_json"] for item in after["sync"] if item["task_id"] == original_task_id), None) == previous_usage
    assert all(item["token_usage_json"] is None for item in after["sync"] if item["task_id"] != original_task_id)
    for message in after["messages"]:
        assert message["status"] == "sent"
        assert not message["dispatch_payload_json"]
        assert message["created_by"] == expected["requested_by"]
    assert sessions.claim_next_agent_session_message(expected["session_id"]) is None


@pytest.fixture
def no_dispatch(monkeypatch):
    monkeypatch.setattr(Celery, "send_task", lambda *_args, **_kwargs: pytest.fail("回填不能派发任务"))


@pytest.mark.parametrize("kind", ["agent_judge", "reverse_quality", "reverse_answer"])
def test_backfill_rebuilds_real_turns_and_separates_replies_and_work(monkeypatch, no_dispatch, kind):
    session_id = _create_session(f"db-prompt-{kind}-history", kind=kind)
    event_turns = _seed_trace(session_id)
    before = _snapshot(session_id)
    row, = backfill.load_candidates()
    # 相同输入不代表同一轮，事件归属也不能按相同文本猜测。
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered(
        "请继续检查。", "请继续检查。", event_turns=event_turns,
    ))

    assert backfill.backfill_one(row)["status"] == "restored"

    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 2)
    turns = sessions.get_agent_session_turns(session_id)
    assert [(turn["turn_index"], turn["user_message"], turn["status"], turn["conclusion"]) for turn in turns] == [
        (1, "请继续检查。", "Completed", "首轮回复"),
        (2, "请继续检查。", "Completed", "第二轮回复"),
    ]
    assert turns[-1]["task_id"] == session_id
    assert after["turns"][-1]["id"] == before["turns"][0]["id"]
    assert len(after["messages"]) == len(after["runs"]) == 2
    assert all(run["status"] == "Completed" for run in after["runs"])
    messages = {item["final_task_id"]: item for item in after["messages"]}
    for index, turn in enumerate(turns):
        task_id = turn["task_id"]
        assert messages[task_id]["user_message"] == turn["user_message"]
        assert sessions.get_agent_session_by_task_id(task_id)["session_id"] == session_id
        assert turn["harness"] == "pi"
        assert turn["endpoint_model"] == "历史节点"
        assert trace_store.get_last_agent_trace_assistant(task_id) == turn["conclusion"]
        timeline = trace_store.list_agent_trace_timeline(task_id, status="Completed")
        block, = [item for item in timeline if item["kind"] == "work_summary"]
        assert block["event_count"] == 2
        detail = trace_store.get_agent_trace_work_block(task_id, block["block_id"])
        assert [item["text"] for item in detail["messages"]] == [
            "重复的思考内容", "首轮工具结果" if index == 0 else "第二轮工具结果",
        ]
        other_task = turns[1 - index]["task_id"]
        assert trace_store.get_agent_trace_work_block(other_task, block["block_id"]) is None
    assert {event["event_id"] for event in after["trace"]} == set(event_turns)
    assert len(after["trace"]) == len(before["trace"])
    for event in after["trace"]:
        assert event["task_id"] == turns[event_turns[event["event_id"]]]["task_id"]
        assert event["created_at"] == HISTORICAL_TIME
    session = sessions.get_agent_session(session_id)
    assert sessions.can_view_agent_session(session, username="admin") is (kind == "reverse_answer")
    assert not sessions.can_view_agent_session(session, username="another")
    assert sessions.can_view_agent_session(session, username="administrator", is_admin=True)
    assert backfill.load_candidates() == []
    assert backfill.backfill_one(row)["status"].startswith("skipped")
    assert _snapshot(session_id) == after


def test_candidate_selection_includes_real_single_turn_history_but_excludes_native_and_v2():
    wanted = {
        _create_session("db-prompt-placeholder-history"),
        _create_session("db-prompt-missing-v1", prompt=backfill.MISSING_PROMPT, version=1),
        _create_session("db-prompt-merged-v1", prompt=V1_MERGED, version=1),
        _create_session("db-prompt-existing-history", prompt="已经保存的真实单轮提示词"),
    }
    _create_session("db-prompt-ordinary", task_kind="custom")
    _create_session("db-prompt-native-judge", historical=False)
    _create_session("db-prompt-finished-v2", prompt=backfill.MISSING_PROMPT, version=2)

    assert {row["session_id"] for row in backfill.load_candidates()} == wanted


def test_existing_real_single_prompt_keeps_text_and_replaces_old_summary_with_actual_reply(no_dispatch):
    text = "已准确恢复的单轮历史输入，不应修改。"
    session_id = _create_session("db-prompt-existing-reply-history", prompt=text, version=1)
    trace_store.ingest_agent_trace_records(session_id, [{
        "version": 1, "type": "numoj_trace", "sequence": 1,
        "event": {"id": "history-1", "kind": "assistant", "text": "历史模型实际回复"},
    }], final=True)
    before = _snapshot(session_id)
    assert before["turns"][0]["conclusion"] == "原有历史结论"
    row, = backfill.load_candidates()

    report = backfill.backfill_one(row)

    assert report["status"] == "existing"
    assert report["previous_conclusion"] == "原有历史结论"
    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 1)
    assert after["turns"][0]["user_message"] == after["messages"][0]["user_message"] == text
    assert after["turns"][0]["conclusion"] == "历史模型实际回复"
    assert after["trace"] == before["trace"]
    assert sessions.get_agent_session_turns(session_id)[0]["conclusion"] == "历史模型实际回复"
    assert backfill.load_candidates() == []


@pytest.mark.parametrize("old_prompt", [backfill.MISSING_PROMPT, V1_MERGED])
def test_v1_result_can_be_rebuilt_once_into_real_turns(monkeypatch, no_dispatch, old_prompt):
    session_id = _create_session("db-prompt-v1-history", prompt=old_prompt, version=1)
    event_turns = _seed_trace(session_id)
    row, = backfill.load_candidates()
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered(
        "首轮历史输入", "第二轮历史输入", event_turns=event_turns,
    ))

    assert backfill.backfill_one(row)["status"] == "restored"
    assert [turn["user_message"] for turn in sessions.get_agent_session_turns(session_id)] == ["首轮历史输入", "第二轮历史输入"]
    after = _snapshot(session_id)
    assert backfill.load_candidates() == []
    assert backfill.backfill_one(row)["status"].startswith("skipped")
    assert _snapshot(session_id) == after


def test_native_pi_history_recovers_inputs_and_db_events_without_mocked_recovery(monkeypatch, no_dispatch, tmp_path):
    session_id = _create_session("db-prompt-native-pi-history", kind="reverse_answer")
    submission_root = tmp_path / "submission"
    trace_root = submission_root / "reverse_agent_trace/saved-attempt"
    path = trace_root / ".pi/agent/sessions/reverse_solve_combined.jsonl"
    path.parent.mkdir(parents=True)
    events = [{"type": "session", "version": 3, "id": "native-pi-session"}]
    for index, (prompt, reply) in enumerate([("请解答原题。", "首轮实际回复"), ("请完成收尾。", "第二轮实际回复")], 1):
        for role, text, label in (
            ("user", prompt, "input"),
            ("toolResult", f"第 {index} 轮实际工具输出", "tool"),
            ("assistant", reply, "reply"),
        ):
            events.append({"type": "message", "id": f"{index}-{label}",
                           "message": {"role": role, "content": [{"type": "text", "text": text}]}})
    path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8")
    monkeypatch.setattr(backfill, "submission_dir", lambda _sid: str(submission_root))
    monkeypatch.setattr(backfill, "AGENT_WORKSPACE_ROOT", tmp_path / "generic")
    # 使用原导入方式存档，交由真正 recover_prompt 重新寻找原生输入及事件身份。
    old_messages = traces.collect_agent_trace_messages(trace_root, full_history=True)
    assert len(old_messages) == 4
    trace_store.ingest_agent_trace_records(session_id, [
        {"version": 1, "type": "numoj_trace", "sequence": index,
         "event": {**message, "id": f"history-{index}"}}
        for index, message in enumerate(old_messages, 1)
    ], final=True)
    row, = backfill.load_candidates()

    report = backfill.backfill_one(row)

    assert report["status"] == "restored"
    assert report["prompt_count"] == 2
    assert report["unassigned_trace_count"] == 0
    turns = sessions.get_agent_session_turns(session_id)
    assert [(turn["user_message"], turn["conclusion"]) for turn in turns] == [
        ("请解答原题。", "首轮实际回复"), ("请完成收尾。", "第二轮实际回复"),
    ]
    for index, turn in enumerate(turns, 1):
        timeline = trace_store.list_agent_trace_timeline(turn["task_id"], status="Completed")
        block, = [item for item in timeline if item["kind"] == "work_summary"]
        detail = trace_store.get_agent_trace_work_block(turn["task_id"], block["block_id"])
        assert [item["text"] for item in detail["messages"]] == [f"第 {index} 轮实际工具输出"]
    assert backfill.load_candidates() == []


def test_assistant_only_judge_phases_restore_archived_prompts_and_matching_work(monkeypatch, no_dispatch, tmp_path):
    session_id = _create_session("db-prompt-native-judge-history", harness="claude_code")
    submission_root = tmp_path / "submission"
    trace_root = submission_root / "agent_judge_trace/saved-attempt"
    journal = trace_root / ".claude/projects/-workspace/agent_judge_combined.jsonl"
    journal.parent.mkdir(parents=True)
    events = [{
        "type": "assistant", "uuid": f"assistant-{phase}", "sessionId": "original-native",
        "_trace_phase": phase,
        "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": f"{phase} 的实际工作过程"},
            {"type": "text", "text": reply},
        ]},
    } for phase, reply in [("setup", "环境准备完成"), ("rule_1", "第一条规则通过")]]
    journal.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8")
    generic_root = tmp_path / "generic"
    workspace = generic_root / "sessions" / session_id / "workspace"
    legacy = workspace / "historical_workspace"
    legacy.mkdir(parents=True)
    (workspace / "historical_record.json").write_text(json.dumps({
        "result": {"competition_title": "归档算法比赛", "orchestration_mode": "topological"},
    }, ensure_ascii=False), encoding="utf-8")
    (legacy / "rules.json").write_text(json.dumps([
        {"rule_id": 1, "rule_name": "首条历史规则", "rule": "结果误差不得超过 1e-8", "value": 7, "dependence": []},
        {"rule_id": 2, "rule_name": "未发送的规则二", "rule": "不应出现的规则正文", "value": 9, "dependence": [1]},
    ], ensure_ascii=False), encoding="utf-8")
    result_name = "result_" + "a" * 32 + ".jsonl.rule_1.jsonl"
    (legacy / result_name).write_text("", encoding="utf-8")
    (legacy / ".aj_session_state.jsonl").write_text("".join(json.dumps({
        "phase": phase, "session_id": "original-native", "returncode": 0,
    }) + "\n" for phase in ("setup", "rule_1")), encoding="utf-8")
    monkeypatch.setattr(backfill, "submission_dir", lambda _sid: str(submission_root))
    monkeypatch.setattr(backfill, "AGENT_WORKSPACE_ROOT", generic_root)
    old_messages = traces.collect_agent_trace_messages(trace_root, full_history=True)
    assert len(old_messages) == 4
    trace_store.ingest_agent_trace_records(session_id, [
        {"version": 1, "type": "numoj_trace", "sequence": index,
         "event": {**message, "id": f"history-{index}"}}
        for index, message in enumerate(old_messages, 1)
    ], final=True)
    row, = backfill.load_candidates()

    report = backfill.backfill_one(row)

    assert report["status"] == "reconstructed"
    assert report["prompt_count"] == 2
    assert report["unassigned_trace_count"] == 0
    assert report["trace_counts"] == [2, 2]
    turns = sessions.get_agent_session_turns(session_id)
    assert len(turns) == 2
    assert "请先完成评测前置准备" in turns[0]["user_message"]
    assert "本阶段不要判定任何评分规则" in turns[0]["user_message"]
    for expected in ("归档算法比赛", "- rule_id: 1", "首条历史规则", "结果误差不得超过 1e-8", "- value: 7.0", result_name):
        assert expected in turns[1]["user_message"]
    assert "不应出现的规则正文" not in "\n".join(turn["user_message"] for turn in turns)
    assert all("[历史" not in turn["user_message"] for turn in turns)
    assert [turn["conclusion"] for turn in turns] == ["环境准备完成", "第一条规则通过"]
    assert turns[-1]["task_id"] == session_id
    for turn, phase in zip(turns, ("setup", "rule_1")):
        timeline = trace_store.list_agent_trace_timeline(turn["task_id"], status="Completed")
        block, = [item for item in timeline if item["kind"] == "work_summary"]
        detail = trace_store.get_agent_trace_work_block(turn["task_id"], block["block_id"])
        assert [item["text"] for item in detail["messages"]] == [f"{phase} 的实际工作过程"]
    assert backfill.load_candidates() == []


def test_changed_native_event_signature_does_not_reassign_existing_history_id(monkeypatch, no_dispatch, tmp_path):
    session_id = _create_session("db-prompt-signature-history", kind="reverse_answer")
    submission_root = tmp_path / "submission"
    trace_root = submission_root / "reverse_agent_trace/saved-attempt"
    path = trace_root / ".pi/agent/sessions/reverse_solve_combined.jsonl"
    path.parent.mkdir(parents=True)
    events = [{"type": "session", "version": 3, "id": "original-native"}]
    for identifier, role, text in (
        ("u1", "user", "首轮原始输入"), ("a1", "assistant", "DB 保存的原始回复"),
        ("u2", "user", "第二轮原始输入"), ("a2", "assistant", "仍然匹配的第二轮回复"),
    ):
        events.append({"type": "message", "id": identifier,
                       "message": {"role": role, "content": [{"type": "text", "text": text}]}})
    path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8")
    old_messages = traces.collect_agent_trace_messages(trace_root, full_history=True)
    assert len(old_messages) == 2
    trace_store.ingest_agent_trace_records(session_id, [
        {"version": 1, "type": "numoj_trace", "sequence": index,
         "event": {**message, "id": f"history-{index}"}}
        for index, message in enumerate(old_messages, 1)
    ], final=True)
    before = _snapshot(session_id)
    # 保留相同 provider ID 和顺序，却改变源文件正文；history-N 单独不足以证明归属。
    events[2]["message"]["content"][0]["text"] = "后来变化的源文件回复"
    path.write_text("".join(json.dumps(event, ensure_ascii=False) + "\n" for event in events), encoding="utf-8")
    monkeypatch.setattr(backfill, "submission_dir", lambda _sid: str(submission_root))
    monkeypatch.setattr(backfill, "AGENT_WORKSPACE_ROOT", tmp_path / "generic")
    row, = backfill.load_candidates()

    report = backfill.backfill_one(row)

    assert report["status"] == "restored"
    assert report["unassigned_trace_count"] == 1
    turns = sessions.get_agent_session_turns(session_id)
    assert [(turn["user_message"], turn["conclusion"]) for turn in turns] == [
        ("首轮原始输入", ""), ("第二轮原始输入", "仍然匹配的第二轮回复"),
        (backfill.UNASSIGNED_PROMPT, "DB 保存的原始回复"),
    ]
    after = _snapshot(session_id)
    assert len(after["trace"]) == len(before["trace"])
    assert [(event["event_id"], event["text"]) for event in after["trace"]] == [
        (event["event_id"], event["text"]) for event in before["trace"]
    ]
    assert after["trace"][0]["task_id"] == session_id
    assert after["trace"][1]["task_id"] == turns[1]["task_id"]
    assert backfill.load_candidates() == []


def test_unmapped_events_are_kept_in_a_separate_archive_turn(monkeypatch, no_dispatch):
    session_id = _create_session("db-prompt-unmapped-history")
    event_turns = _seed_trace(session_id)
    before = _snapshot(session_id)
    unmapped = next(event for event in before["trace"] if event["text"] == "第二轮回复")
    del event_turns[unmapped["event_id"]]
    row, = backfill.load_candidates()
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered(
        "真实首轮", "真实第二轮", event_turns=event_turns,
    ))

    assert backfill.backfill_one(row)["status"] == "restored"

    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 3)
    turns = sessions.get_agent_session_turns(session_id)
    assert len(turns) == 3
    assert [turn["user_message"] for turn in turns[:2]] == ["真实首轮", "真实第二轮"]
    assert turns[-1]["user_message"] == backfill.UNASSIGNED_PROMPT
    assert turns[-1]["task_id"] == session_id
    assert turns[1]["conclusion"] != "第二轮回复"
    assert trace_store.get_last_agent_trace_assistant(turns[1]["task_id"]) == ""
    assert [event["event_id"] for event in after["trace"] if event["task_id"] == session_id] == [unmapped["event_id"]]
    assert {event["event_id"] for event in after["trace"]} == {event["event_id"] for event in before["trace"]}
    assert backfill.load_candidates() == []


@pytest.mark.parametrize("status", ["restored", "reconstructed"])
def test_single_historical_prompt_keeps_original_task_and_times(monkeypatch, no_dispatch, status):
    session_id = _create_session("db-prompt-single-history")
    row, = backfill.load_candidates()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered("恢复的单轮历史输入", status=status))

    assert backfill.backfill_one(row)["status"] == status

    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 1)
    assert len(after["turns"]) == len(after["messages"]) == len(after["runs"]) == 1
    assert after["turns"][0]["task_id"] == session_id
    assert after["turns"][0]["user_message"] == after["messages"][0]["user_message"] == "恢复的单轮历史输入"
    for table in ("turns", "messages", "runs"):
        for field in ("created_at", "updated_at"):
            assert after[table][0][field] == before[table][0][field]
    assert backfill.load_candidates() == []


def test_missing_original_prompt_records_notice_and_completes_v2_once(monkeypatch, no_dispatch):
    session_id = _create_session("db-prompt-missing-history")
    row, = backfill.load_candidates()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: {
        "turns": [{"text": backfill.MISSING_PROMPT, "phase": ""}],
        "event_turns": {}, "status": "missing", "prompt_count": 0, "sources": [], "warnings": [],
    })

    assert backfill.backfill_one(row)["status"] == "missing"

    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 1)
    assert after["turns"][0]["user_message"] == after["messages"][0]["user_message"] == backfill.MISSING_PROMPT
    assert backfill.load_candidates() == []


@pytest.mark.parametrize("failed_statement", ["UPDATE AGENT_SESSION_MESSAGES", "INSERT INTO AGENT_SESSION_MESSAGES"])
def test_message_write_failure_rolls_back_turns_traces_and_version(monkeypatch, no_dispatch, failed_statement):
    session_id = _create_session("db-prompt-rollback-history")
    event_turns = _seed_trace(session_id)
    row, = backfill.load_candidates()
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered("首轮", "第二轮", event_turns=event_turns))
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
            if normalized.startswith(failed_statement):
                raise pymysql.OperationalError(1205, "injected message write failure")
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
    with pytest.raises(pymysql.OperationalError, match="injected message write failure"):
        backfill.backfill_one(row)

    assert any(query.startswith(("UPDATE AGENT_SESSION_TURNS", "INSERT INTO AGENT_SESSION_TURNS")) for query in statements)
    assert _snapshot(session_id) == before


@pytest.mark.parametrize("existing_side", ["turn", "message"])
def test_existing_real_single_prompt_synchronizes_only_missing_copy(existing_side, no_dispatch):
    session_id = _create_session("db-prompt-partial-history")
    text = "已经存在的真实提示词，不能重建或替换。"
    query = (
        "UPDATE agent_session_turns SET user_message=%s, updated_at=updated_at WHERE session_id=%s"
        if existing_side == "turn" else
        "UPDATE agent_session_messages SET user_message=%s, updated_at=updated_at WHERE session_id=%s"
    )
    _execute(query, (text, session_id))
    row, = backfill.load_candidates()
    before = _snapshot(session_id)

    assert backfill.backfill_one(row)["status"] == "existing"

    after = _snapshot(session_id)
    _assert_session_preserved(before, after, 1)
    assert after["turns"][0]["user_message"] == after["messages"][0]["user_message"] == text
    assert backfill.load_candidates() == []


def test_candidate_changed_after_loading_is_not_overwritten(monkeypatch, no_dispatch):
    session_id = _create_session("db-prompt-stale-history")
    row, = backfill.load_candidates()
    _execute("UPDATE agent_session_turns SET user_message=%s WHERE session_id=%s", ("另一事务已写入的历史原文", session_id))
    before = _snapshot(session_id)
    monkeypatch.setattr(backfill, "recover_prompt", lambda _row: _recovered("迟到的首轮", "迟到的第二轮"))

    assert backfill.backfill_one(row)["status"] == "skipped_changed"
    assert _snapshot(session_id) == before
