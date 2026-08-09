import json

import pytest

from oj_modules.problems import agent_runs


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


def test_hydrate_agent_run_snapshot_reads_canonical_jsonl_only(
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
    assert [message["text"] for message in trace["trace_messages"]] == [
        "真实 harness 回复"
    ]
    assert trace["trace_files"][0]["path"] == "codex_agent_judge.jsonl"


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
    trace_dir = agent_runs.agent_run_trace_dir("task-priced")
    trace_dir.mkdir(parents=True)
    (trace_dir / "codex_reverse_solve.jsonl").write_text(
        json.dumps({
            "type": "turn.completed",
            "usage": {
                "input_tokens": 900_000,
                "cached_input_tokens": 700_000,
                "output_tokens": 50_000,
            },
        }) + "\n",
        encoding="utf-8",
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
