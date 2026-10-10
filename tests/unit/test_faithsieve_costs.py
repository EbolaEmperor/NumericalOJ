"""费用按真实请求、原会话归属及冻结价格计入，缓存与缺失不得冒充收费。"""

from dataclasses import replace
from datetime import datetime, timezone, timedelta
from decimal import Decimal
import json
import os

import pytest

from backend.oj_modules.ai import endpoints
from backend.oj_modules.faithsieve import costs, views
from backend.oj_modules.faithsieve.checkpoints import CheckpointStore
from tests.unit.test_faithsieve_image_workflow import Script, seed
from tests.unit.test_faithsieve_empty_result_retry import EmptyResultScript


ATTEMPT = "a" * 32
PRICES = {"input_price_per_million": "10", "cached_input_price_per_million": "1",
          "output_price_per_million": "20"}


def run(**changes):
    return {"attempt_id": ATTEMPT, "execution_mode": "workflow", "status": "running",
            "session_id": "faithsieve-" + ATTEMPT, **changes}


def billed_usage():
    return endpoints._parse_usage({"prompt_tokens": 100, "completion_tokens": 20,
                                   "prompt_tokens_details": {"cached_tokens": 80}}, endpoints.LLMProtocol.OPENAI)


def read_events(root):
    return json.loads((root / costs.COST_PATH).read_text())


def test_openai_cache_and_reasoning_are_preserved_without_double_charging_output():
    usage = endpoints._parse_usage({"prompt_tokens": 100, "completion_tokens": 20,
                                   "prompt_cache_hit_tokens": 80,
                                   "completion_tokens_details": {"reasoning_tokens": 15}}, endpoints.LLMProtocol.OPENAI)
    assert usage == endpoints.LLMUsage(100, 20, 120)
    assert usage.billing_tokens == {"input_uncached_tokens": 20, "input_cached_tokens": 80,
                                    "input_cache_write_tokens": 0, "output_tokens": 20,
                                    "reasoning_output_tokens": 15, "estimated": False}
    counts = {key: value for key, value in usage.billing_tokens.items() if key != "estimated"}
    assert costs.calculate_agent_usage_charge(counts, PRICES)[2] == Decimal("0.00068")


def test_anthropic_cache_creation_is_not_lost_or_treated_as_a_cache_hit():
    usage = endpoints._parse_usage({"input_tokens": 20, "output_tokens": 20,
                                   "cache_read_input_tokens": 80, "cache_creation_input_tokens": 10},
                                  endpoints.LLMProtocol.ANTHROPIC)
    assert usage.billing_tokens["input_uncached_tokens"] == 20
    assert usage.billing_tokens["input_cache_write_tokens"] == 10
    assert usage.billing_tokens["estimated"] is False
    counts = {key: value for key, value in usage.billing_tokens.items() if key != "estimated"}
    assert costs.calculate_agent_usage_charge(counts, PRICES)[2] == Decimal("0.00078")


@pytest.mark.parametrize("data", [None, {}, {"prompt_tokens": -1, "completion_tokens": 2},
                                  {"prompt_tokens": True, "completion_tokens": 2},
                                  {"prompt_tokens": 3, "completion_tokens": 2, "prompt_cache_hit_tokens": 4}])
def test_missing_or_invalid_provider_usage_cannot_become_zero_cost(data):
    assert endpoints._parse_usage(data, endpoints.LLMProtocol.OPENAI).billing_tokens is None


def test_cache_breakdown_absent_is_explicitly_an_estimate():
    usage = endpoints._parse_usage({"prompt_tokens": 100, "completion_tokens": 20}, endpoints.LLMProtocol.OPENAI)
    assert usage.billing_tokens["input_uncached_tokens"] == 100
    assert usage.billing_tokens["estimated"] is True


@pytest.mark.parametrize("repair", [False, True])
def test_complete_workflow_counts_actual_retries_repairs_and_score_but_not_replay(tmp_path, repair):
    tmp_path.mkdir(exist_ok=True)
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=tmp_path)
    script = EmptyResultScript(tmp_path, retry_failure="syntax") if repair else Script(tmp_path)
    original = script.chat
    def chat(*args, **options):
        return replace(original(*args, **options), usage=billed_usage())
    script.chat = chat
    engine = seed(tmp_path, script, thinking=repair)
    engine.usage_recorder = recorder
    result = engine.run()
    assert result["verdict"] == "correct"
    document = read_events(tmp_path)
    expected = len(script.pure) + (len(script.repairs) if repair else 0)
    assert len(document["events"]) == expected
    assert document["history_complete"] is True
    assert all(Decimal(event["cost_rmb"]) == Decimal("0.00068") for event in document["events"])
    assert any(event["invocation_key"] == "final-scoring" for event in document["events"])
    if repair:
        assert sum(event["kind"] == "empty_result_retry" for event in document["events"]) == 1
        assert sum(event["kind"] == "json_repair" for event in document["events"]) == 1
    checkpoint_bytes = {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")}
    billing_bytes = (tmp_path / costs.COST_PATH).read_bytes()
    resumed = seed(tmp_path, script, thinking=repair)
    resumed.usage_recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=tmp_path)
    assert resumed.run() == result
    assert (tmp_path / costs.COST_PATH).read_bytes() == billing_bytes
    assert {p.name: p.read_bytes() for p in engine.checkpoints.directory.glob("*.json")} == checkpoint_bytes
    assert len(script.pure) + (len(script.repairs) if repair else 0) == expected
    assert costs.COST_PATH not in json.dumps([record["request"] for record in engine.checkpoints.read_records().values()])
    assert views._artifact_allowed(costs.COST_PATH) is False


def test_endpoint_failure_keeps_real_call_as_missing_usage_without_recording_free_call(tmp_path):
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=tmp_path)
    def fail():
        raise RuntimeError("API failure")
    with pytest.raises(RuntimeError, match="API failure"):
        recorder.call("role-000001-attempt-1", "role", fail)
    event = read_events(tmp_path)["events"][0]
    assert event["state"] == "failed" and event["cost_rmb"] is None and event["usage"] is None


def test_price_is_frozen_per_actual_call_and_missing_price_is_not_zero(tmp_path):
    prices = dict(PRICES)
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=prices, workspace=tmp_path)
    reply = endpoints.LLMChatResult("result", usage=billed_usage())
    recorder.call("role-000001-attempt-1", "role", lambda: reply)
    prices["output_price_per_million"] = "40"
    recorder.call("role-000002-attempt-1", "role", lambda: reply)
    prices["output_price_per_million"] = None
    recorder.call("role-000003-attempt-1", "role", lambda: reply)
    events = read_events(tmp_path)["events"]
    assert [Decimal(event["cost_rmb"]) for event in events[:2]] == [Decimal("0.00068"), Decimal("0.00108")]
    assert events[2]["cost_rmb"] is None


def test_peak_prices_use_actual_call_time_and_do_not_revalue_old_events(tmp_path, monkeypatch):
    from backend.oj_modules.site_config import services
    times = iter([datetime(2026, 10, 10, hour, tzinfo=timezone(timedelta(hours=8))) for hour in (8, 10)])
    monkeypatch.setattr(services, "_utc_plus_eight_now", lambda _now: next(times))
    prices = {**PRICES, "peak_pricing_enabled": True, "peak_time_ranges": "09:00-17:00",
              "peak_input_price_per_million": "20", "peak_cached_input_price_per_million": "2",
              "peak_output_price_per_million": "40"}
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=prices, workspace=tmp_path)
    reply = endpoints.LLMChatResult("result", usage=billed_usage())
    recorder.call("role-000001-attempt-1", "role", lambda: reply)
    recorder.call("role-000002-attempt-1", "role", lambda: reply)
    prices["output_price_per_million"] = "999"
    assert [Decimal(event["cost_rmb"]) for event in read_events(tmp_path)["events"]] == [Decimal("0.00068"), Decimal("0.00136")]


def test_anthropic_stream_merges_cache_input_and_final_output_usage(monkeypatch):
    events = [
        {"type": "message_start", "message": {"model": "model", "usage": {
            "input_tokens": 20, "output_tokens": 0, "cache_read_input_tokens": 80,
            "cache_creation_input_tokens": 10}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": "result"}},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 20}},
        {"type": "message_stop"},
    ]
    monkeypatch.setattr(endpoints, "_iter_sse_json", lambda *_a, **_k: iter(events))
    reply = endpoints._parse_anthropic_stream(object(), None, require_complete_stream=True)
    assert reply.usage.billing_tokens == {"input_uncached_tokens": 20, "input_cached_tokens": 80,
                                         "input_cache_write_tokens": 10, "output_tokens": 20,
                                         "reasoning_output_tokens": 0, "estimated": False}


@pytest.fixture
def managed(tmp_path, monkeypatch):
    root = tmp_path / "managed"
    workspace = root / "sessions" / ("faithsieve-" + ATTEMPT) / "workspace"
    workspace.mkdir(parents=True)
    monkeypatch.setattr(views.workspace_store, "AGENT_WORKSPACE_ROOT", root)
    return workspace


def test_historical_llm_gaps_keep_agent_subtotal_partial_and_native_estimate(managed):
    CheckpointStore(managed).put("role-000001-attempt-1", {"role": "tree-builder"}, state="completed", response={})
    before = {p: (p.stat().st_mtime_ns, p.stat().st_mode) for p in managed.rglob("*")}
    value = costs._merge_run_cost(run(), [{"cost_rmb": "4.25", "request_count": 7,
                                          "cached_fallback_request_count": 2}])
    assert value == {"cost_rmb": "4.25", "currency": "CNY", "complete": False,
                     "estimated": True, "missing_usage": True, "request_count": 7}
    assert before == {p: (p.stat().st_mtime_ns, p.stat().st_mode) for p in managed.rglob("*")}


def test_historical_requeue_cannot_become_complete_zero_or_complete_native_subtotal(managed):
    historical = run(status="queued", started_at="2026-10-09T10:00:00")
    assert costs._merge_run_cost(historical, [])["cost_rmb"] is None
    value = costs._merge_run_cost(historical, [{"cost_rmb": "4.25", "request_count": 7}])
    assert value["cost_rmb"] == "4.25" and not value["complete"] and value["missing_usage"]
    assert costs._merge_run_cost(run(execution_mode="skill", status="queued", started_at="yesterday"), [])["cost_rmb"] is None
    # 即使旧数据缺 started_at，真实调用检查点也不能被 queued 状态掩盖。
    CheckpointStore(managed).put("role-000001-attempt-1", {"role": "tree-builder"}, state="completed", response={})
    assert costs._merge_run_cost(run(status="queued"), [])["cost_rmb"] is None


def test_known_pure_and_native_cost_sum_and_zero_pricing_is_valid(managed):
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=managed)
    recorder.call("role-000001-attempt-1", "role", lambda: endpoints.LLMChatResult("result", usage=billed_usage()))
    value = costs._merge_run_cost(run(), [{"cost_rmb": "4.25", "request_count": 7}])
    assert Decimal(value["cost_rmb"]) == Decimal("4.25068")
    assert value["complete"] and value["request_count"] == 8 and not value["estimated"]
    recorder.endpoint = {key: "0" for key in PRICES}
    recorder.call("role-000002-attempt-1", "role", lambda: endpoints.LLMChatResult("result", usage=billed_usage()))
    assert Decimal(read_events(managed)["events"][-1]["cost_rmb"]) == 0


@pytest.mark.parametrize("corrupt", ["attempt", "amount", "symlink", "hardlink", "mode"])
def test_private_cost_file_corruption_or_links_do_not_supply_cost(managed, corrupt):
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=managed)
    recorder.call("role-000001-attempt-1", "role", lambda: endpoints.LLMChatResult("result", usage=billed_usage()))
    path = managed / costs.COST_PATH
    if corrupt in {"attempt", "amount"}:
        document = read_events(managed)
        if corrupt == "attempt": document["attempt_id"] = "b" * 32
        else: document["events"][0]["cost_rmb"] = "999"
        path.write_text(json.dumps(document))
    elif corrupt in {"symlink", "hardlink"}:
        original = managed / "private-copy.json"
        path.rename(original)
        if corrupt == "symlink": path.symlink_to(original)
        else: os.link(original, path)
    else:
        path.chmod(0o644)
    assert costs._workflow_cost(run())["cost_rmb"] is None
    assert costs._workflow_cost(run())["missing_usage"] is True


def test_skill_uses_formal_native_ledger_and_empty_history_is_unknown():
    value = costs._merge_run_cost(run(execution_mode="skill"), [{"cost_rmb": "2.5", "request_count": 12}])
    assert value["cost_rmb"] == "2.5" and value["complete"] and value["request_count"] == 12
    assert costs._merge_run_cost(run(execution_mode="skill"), [])["cost_rmb"] is None
    queued = costs._merge_run_cost(run(execution_mode="skill", status="queued"), [])
    assert queued["cost_rmb"] == "0" and queued["complete"]


def test_native_query_is_batched_parameterized_and_scoped_to_actual_turn_owner():
    class Cursor:
        def execute(self, sql, params): self.sql, self.params = sql, params
        def fetchall(self): return []
    cursor = Cursor()
    assert costs._agent_cost_rows(cursor, [ATTEMPT, "b" * 32]) == []
    assert cursor.params[-2:] == (ATTEMPT, "b" * 32)
    assert "a.attempt_id=r.attempt_id" in cursor.sql
    assert "l.session_id=a.session_id AND l.task_id=t.task_id" in cursor.sql
    assert "a.requested_by=r.requested_by" in cursor.sql and "a.requested_by=s.username" in cursor.sql
    assert "cached_fallback_request_count" in cursor.sql
    assert "t.task_id, t.status" in cursor.sql
    assert "a.requested_by=s.username OR s.id IS NULL" in cursor.sql
    assert ATTEMPT not in cursor.sql


@pytest.mark.parametrize("trace,missing", [
    ({"incremental": True, "request_count": 2}, True),
    ({"incremental": True, "request_count": 1}, False),
    ({"incremental": False, "request_count": 99}, False),
])
def test_native_incremental_trace_detects_partial_settlement_without_repricing(trace, missing):
    value = costs._merge_run_cost(run(execution_mode="skill"), [
        {"cost_rmb": "0.2", "request_count": 1, "trace_usage_json": json.dumps(trace)},
    ])
    assert value["cost_rmb"] == "0.2" and value["missing_usage"] is missing
    assert value["complete"] is not missing


def test_native_later_turn_without_ledger_is_not_hidden_by_prior_turn_cost():
    value = costs._merge_run_cost(run(execution_mode="skill"), [
        {"task_id": "old", "cost_rmb": "0.2", "request_count": 1},
        {"task_id": "new", "cost_rmb": None, "request_count": 0},
    ])
    assert value["cost_rmb"] == "0.2" and value["missing_usage"] and not value["complete"]


@pytest.mark.parametrize("settled", [False, True])
def test_native_outbox_pending_and_post_commit_residue_are_distinct(monkeypatch, settled):
    event = ("session", "task", "relay_openai", "event")
    monkeypatch.setattr(costs, "read_pending_usage_events", lambda mapping: [event])
    rows = [{"session_id": "session", "task_id": "task", "cost_rmb": "0.2", "request_count": 1}]
    class Cursor:
        def execute(self, sql, params):
            assert "(session_id, task_id, source, usage_event_id) IN" in sql
            assert params == event
        def fetchall(self):
            return [dict(zip(("session_id", "task_id", "source", "usage_event_id"), event))] if settled else []
    costs._mark_pending_usage(Cursor(), rows)
    value = costs._merge_run_cost(run(execution_mode="skill"), rows)
    assert value["cost_rmb"] == "0.2" and value["complete"] is settled
    assert value["missing_usage"] is not settled


def test_native_unsafe_outbox_keeps_known_subtotal_but_does_not_claim_complete(monkeypatch):
    monkeypatch.setattr(costs, "read_pending_usage_events", lambda _mapping: None)
    rows = [{"session_id": "session", "task_id": "task", "cost_rmb": "0.2", "request_count": 1}]
    costs._mark_pending_usage(object(), rows)
    value = costs._merge_run_cost(run(execution_mode="skill"), rows)
    assert value["cost_rmb"] == "0.2" and value["missing_usage"] and not value["complete"]


def test_response_write_failure_keeps_successful_checkpoint_replay_free_and_cost_unknown(tmp_path, monkeypatch):
    from tests.unit.test_faithsieve_transport import engine, response, role_result
    calls = []
    def chat(*_args, **_options):
        calls.append(1)
        return replace(response(role_result(), finish_reason="tool_calls"), usage=billed_usage())
    recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=tmp_path)
    real_write, writes = costs._write_costs, []
    def fail_after_response(workspace, document):
        writes.append(1)
        if len(writes) == 2:
            raise OSError("temporary disk failure")
        return real_write(workspace, document)
    monkeypatch.setattr(costs, "_write_costs", fail_after_response)
    workflow = engine(tmp_path, chat)
    workflow.usage_recorder = recorder
    first = workflow._invoke("decomposer", files={"problem.md": "题面"})
    assert read_events(tmp_path)["events"][0]["state"] == "pending"
    resumed = engine(tmp_path, chat)
    resumed.usage_recorder = costs.WorkflowUsageRecorder(run=run(), endpoint=PRICES, workspace=tmp_path)
    second = resumed._invoke("decomposer", files={"problem.md": "题面"})
    assert second.result == first.result and len(calls) == 1 and len(writes) == 2
    assert read_events(tmp_path)["events"][0]["cost_rmb"] is None
