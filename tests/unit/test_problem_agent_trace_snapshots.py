import json

import pytest

from backend.oj_modules.problems import agent_runs


@pytest.fixture(autouse=True)
def _empty_v2_timeline(monkeypatch):
    """快照测试默认不访问本机 MySQL；v2 存储语义由独立单测覆盖。"""

    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_timeline",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        agent_runs,
        "get_agent_trace_token_usage",
        lambda _task_id: None,
    )
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_subagents",
        lambda _task_id: [],
    )


def test_agent_trace_dir_is_task_scoped_and_rejects_untrusted_ids(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))

    assert agent_runs.agent_run_trace_dir("task-1") == (
        tmp_path.resolve() / "traces" / "task-1"
    )
    for task_id in ("", "../escape", "a/b", "task id", "x" * 65):
        with pytest.raises(ValueError):
            agent_runs.agent_run_trace_dir(task_id)


def test_hydrate_agent_run_snapshot_reads_public_v2_timeline_only(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    trace_dir = agent_runs.agent_run_trace_dir("task-2")
    trace_dir.mkdir(parents=True)
    (trace_dir / "codex_agent_judge.jsonl").write_text(
        json.dumps({"type": "agent_message", "message": "真实 harness 回复"})
        + "\n",
        encoding="utf-8",
    )

    public_timeline = [
        {"kind": "assistant", "text": "对用户可见的回复"},
        {
            "kind": "work_summary",
            "block_id": "work-1234567890abcdef",
            "thinking_count": 2,
            "tool_count": 1,
            "summary": "工作中…2 thinkings, 1 tool call",
        },
    ]
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_timeline",
        lambda task_id, **_kwargs: public_timeline if task_id == "task-2" else [],
    )
    original = {
        "task_id": "task-2",
        "status": "Running",
        "message": "正在运行",
        "events": [{"message": "旧自建轨迹"}],
    }
    snapshot = agent_runs.hydrate_agent_run_snapshot(original)

    assert "events" not in snapshot
    assert "events" in original
    trace = snapshot["execution_trace"]
    assert trace["status"] == "running"
    assert trace["trace_messages"] == public_timeline
    assert trace["subagents"] == []
    assert trace["trace_files"] == []
    assert all(
        message.get("text") != "真实 harness 回复"
        for message in trace["trace_messages"]
    )


def test_canonical_journal_marks_trace_incremental_before_usage_arrives(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    trace_dir = agent_runs.agent_run_trace_dir("task-canonical-running")
    trace_dir.mkdir(parents=True)
    (trace_dir / "numoj_trace_v1.jsonl").write_text(
        json.dumps({
            "v": 1,
            "record_type": "trace",
            "kind": "thinking",
            "text": "正在分析",
        }) + "\n",
        encoding="utf-8",
    )

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-canonical-running",
        "status": "Running",
    })

    assert trace["incremental"] is True
    assert trace["token_usage"] is None


def test_canonical_steer_boundary_is_delivery_fact_if_status_write_was_lost(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    trace_dir = agent_runs.agent_run_trace_dir("task-steer")
    trace_dir.mkdir(parents=True)
    captured = {}
    monkeypatch.setattr(
        agent_runs,
        "list_agent_session_messages",
        lambda *_args, **_kwargs: [{
            "message_id": "steer-1",
            "delivery_mode": "steer",
            "status": "unknown",
            "target_task_id": "task-steer",
            "user_message": "改为检查边界",
            "attachments": [{"name": "note.txt", "path": "note.txt"}],
            "delivered_at": "2026-08-17 10:00:00",
        }],
    )
    def timeline(task_id, *, status, steer_records):
        captured.update(
            task_id=task_id,
            status=status,
            steer_records=list(steer_records),
        )
        return [{
            "kind": "user",
            "message_id": "steer-1",
            "text": steer_records[0]["user_message"],
            "attachments": steer_records[0]["attachments"],
        }]

    monkeypatch.setattr(agent_runs, "list_agent_trace_timeline", timeline)

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-steer",
        "session_id": "session-1",
        "status": "Running",
    })

    assert [item["kind"] for item in trace["trace_messages"]] == ["user"]
    assert trace["trace_messages"][0]["text"] == "改为检查边界"
    assert trace["trace_messages"][0]["message_id"] == "steer-1"
    assert trace["trace_messages"][0]["attachments"][0]["name"] == "note.txt"
    assert captured["task_id"] == "task-steer"
    assert captured["status"] == "Running"


def test_agent_snapshot_includes_persisted_subagent_status(monkeypatch):
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_subagents",
        lambda task_id: [{
            "subagent_id": "worker-a",
            "name": "核对官方文档",
            "status": "completed",
        }] if task_id == "task-subagents" else [],
    )

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-subagents",
        "status": "Completed",
    })

    assert trace["subagents"] == [{
        "subagent_id": "worker-a",
        "name": "核对官方文档",
        "status": "completed",
    }]


def test_canonical_steer_boundary_does_not_render_unconfirmed_message(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    trace_dir = agent_runs.agent_run_trace_dir("task-steer-pending")
    trace_dir.mkdir(parents=True)
    monkeypatch.setattr(
        agent_runs,
        "list_agent_session_messages",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        agent_runs,
        "list_agent_trace_timeline",
        lambda _task_id, *, status, steer_records: (
            [] if not steer_records else pytest.fail("不应传入未确认插话")
        ),
    )

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-steer-pending",
        "session_id": "session-1",
        "status": "Running",
    })

    assert trace["trace_messages"] == []


@pytest.mark.parametrize(
    ("task_status", "trace_status"),
    [
        ("Pending", "pending"),
        ("Running", "running"),
        ("Completed", "passed"),
        ("Failed", "error"),
    ],
)
def test_agent_snapshot_maps_task_status_to_shared_trace_status(
    monkeypatch,
    tmp_path,
    task_status,
    trace_status,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))

    trace = agent_runs.build_agent_execution_trace({
        "task_id": "task-3",
        "status": task_status,
        "message": "状态说明",
    })

    assert trace["status"] == trace_status
    assert trace["error_message"] == (
        "状态说明" if trace_status == "error" else ""
    )


def test_agent_snapshot_recalculates_cost_from_the_current_endpoint_prices(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setattr(
        agent_runs,
        "get_agent_trace_token_usage",
        lambda _task_id: {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 200_000,
            "input_cached_tokens": 700_000,
            "input_cache_write_tokens": 0,
            "input_total_tokens": 900_000,
            "output_tokens": 50_000,
        },
    )

    current_endpoint = {
        "input_price_per_million": "2",
        "cached_input_price_per_million": "0.5",
        "output_price_per_million": "8",
    }
    monkeypatch.setattr(
        agent_runs,
        "get_llm_endpoint",
        lambda endpoint_id, **_kwargs: (
            current_endpoint if endpoint_id == 7 else None
        ),
    )
    state = {
        "task_id": "task-priced",
        "status": "Completed",
        "endpoint_id": 7,
        "token_pricing": {
            "input_price_per_million": "999",
            "cached_input_price_per_million": "999",
            "output_price_per_million": "999",
        },
    }
    trace = agent_runs.build_agent_execution_trace(state)

    assert trace["token_usage"]["input_total_tokens"] == 900_000
    assert trace["token_usage"]["input_cached_tokens"] == 700_000
    assert trace["token_usage"]["output_tokens"] == 50_000
    assert trace["token_usage"]["cost_rmb"] == "1.15"

    current_endpoint.update({
        "input_price_per_million": "1",
        "cached_input_price_per_million": "0.1",
        "output_price_per_million": "2",
    })
    refreshed = agent_runs.build_agent_execution_trace(state)
    assert refreshed["token_usage"]["cost_rmb"] == "0.37"

    hydrated = agent_runs.hydrate_agent_run_snapshot(state)
    assert "token_pricing" not in hydrated


def test_session_usage_treats_pi_resume_traces_as_cumulative_snapshots():
    usage = agent_runs.aggregate_agent_session_token_usage([
        ("turn-1", {
            "source": "pi",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 50,
            "input_cache_write_tokens": 0,
            "input_total_tokens": 150,
            "output_tokens": 20,
            "reasoning_output_tokens": 5,
            "cost_rmb": "0.20",
        }),
        # Pi resume 的第二轮轨迹再次包含 turn-1，不能与首轮相加。
        ("turn-2", {
            "source": "pi",
            "request_count": 2,
            "input_uncached_tokens": 160,
            "input_cached_tokens": 80,
            "input_cache_write_tokens": 10,
            "input_total_tokens": 250,
            "output_tokens": 35,
            "reasoning_output_tokens": 9,
            "cost_rmb": "0.35",
        }),
    ])

    assert usage == {
        "request_count": 2,
        "input_uncached_tokens": 160,
        "input_cached_tokens": 80,
        "input_cache_write_tokens": 10,
        "input_total_tokens": 250,
        "output_tokens": 35,
        "reasoning_output_tokens": 9,
        "source": "session",
        "sources": ["pi"],
        "turn_count": 2,
        "cost_complete": True,
        "cost_rmb": "0.35",
    }


def test_session_usage_aggregates_cached_fallback_audit_metadata():
    usage = agent_runs.aggregate_agent_session_token_usage([
        ("turn-1", {
            "source": "relay_anthropic",
            "request_count": 2,
            "input_uncached_tokens": 20,
            "input_cached_tokens": 180,
            "input_cache_write_tokens": 0,
            "input_total_tokens": 200,
            "output_tokens": 10,
            "reasoning_output_tokens": 0,
            "cached_fallback_request_count": 2,
            "cached_fallback_input_tokens": 200,
            "cost_rmb": "0.20",
        }),
    ])

    assert usage["cached_fallback_request_count"] == 2
    assert usage["cached_fallback_input_tokens"] == 200


def test_session_usage_sums_incremental_tasks_and_overlays_duplicate_task_id():
    usage = agent_runs.aggregate_agent_session_token_usage([
        ("turn-1", {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 0,
            "input_total_tokens": 999,  # 汇总必须从规范分量重算。
            "output_tokens": 10,
            "cost_rmb": "0.10",
        }),
        ("turn-2", {
            "source": "codex",
            "request_count": 1,
            "input_uncached_tokens": 40,
            "input_cached_tokens": 10,
            "input_cache_write_tokens": 2,
            "output_tokens": 5,
            "cost_rmb": "0.05",
        }),
        # SSE current overlay 以同 task_id 的最新快照替换，不能再加一遍。
        ("turn-2", {
            "source": "codex",
            "request_count": 2,
            "input_uncached_tokens": 70,
            "input_cached_tokens": 15,
            "input_cache_write_tokens": 3,
            "output_tokens": 8,
            "cost_rmb": "0.08",
        }),
    ])

    assert usage["request_count"] == 3
    assert usage["input_uncached_tokens"] == 170
    assert usage["input_cached_tokens"] == 35
    assert usage["input_cache_write_tokens"] == 3
    assert usage["input_total_tokens"] == 208
    assert usage["output_tokens"] == 18
    assert usage["turn_count"] == 2
    assert usage["cost_rmb"] == "0.18"


def test_session_usage_sums_canonical_incremental_pi_and_claude_tasks():
    usage = agent_runs.aggregate_agent_session_token_usage([
        ("pi-first", {
            "source": "pi",
            "incremental": True,
            "request_count": 1,
            "input_uncached_tokens": 100,
            "input_cached_tokens": 20,
            "input_cache_write_tokens": 0,
            "input_total_tokens": 120,
            "output_tokens": 10,
            "reasoning_output_tokens": 2,
            "cost_rmb": "0.1",
        }),
        ("pi-second", {
            "source": "pi",
            "incremental": True,
            "request_count": 2,
            "input_uncached_tokens": 200,
            "input_cached_tokens": 30,
            "input_cache_write_tokens": 5,
            "input_total_tokens": 235,
            "output_tokens": 20,
            "reasoning_output_tokens": 3,
            "cost_rmb": "0.2",
        }),
        ("claude-third", {
            "source": "claude_code",
            "incremental": True,
            "request_count": 1,
            "input_uncached_tokens": 300,
            "input_cached_tokens": 40,
            "input_cache_write_tokens": 7,
            "input_total_tokens": 347,
            "output_tokens": 30,
            "reasoning_output_tokens": 4,
            "cost_rmb": "0.3",
        }),
    ])

    assert usage["request_count"] == 4
    assert usage["input_uncached_tokens"] == 600
    assert usage["input_cached_tokens"] == 90
    assert usage["input_cache_write_tokens"] == 12
    assert usage["input_total_tokens"] == 702
    assert usage["output_tokens"] == 60
    assert usage["reasoning_output_tokens"] == 9
    assert usage["cost_rmb"] == "0.6"


def test_session_usage_hides_partial_cost_when_any_metered_turn_is_unpriced():
    usage = agent_runs.aggregate_agent_session_token_usage([
        ("turn-1", {
            "source": "opencode",
            "request_count": 1,
            "input_uncached_tokens": 100,
            "output_tokens": 10,
            "cost_rmb": "0.12",
        }),
        ("turn-2", {
            "source": "opencode",
            "request_count": 1,
            "input_uncached_tokens": 50,
            "output_tokens": 5,
        }),
    ])

    assert usage["input_total_tokens"] == 150
    assert usage["output_tokens"] == 15
    assert usage["cost_complete"] is False
    assert usage["cost_rmb"] is None
