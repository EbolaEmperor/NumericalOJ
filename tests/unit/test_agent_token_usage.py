import json

from backend.oj_modules.ranking.reverse_judge.traces import (
    calculate_agent_token_cost_rmb,
    collect_agent_token_usage,
)


def _write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_claude_usage_deduplicates_content_events_by_provider_message_id(tmp_path):
    path = tmp_path / ".claude/projects/-workspace/reverse_solve_combined.jsonl"
    usage = {
        "input_tokens": 120,
        "cache_read_input_tokens": 800,
        "cache_creation_input_tokens": 30,
        "output_tokens": 45,
    }
    _write_jsonl(path, [
        {"type": "assistant", "uuid": "event-a", "message": {"id": "msg-1", "usage": usage}},
        {"type": "assistant", "uuid": "event-b", "message": {"id": "msg-1", "usage": usage}},
        {"type": "assistant", "uuid": "event-c", "message": {"id": "msg-2", "usage": {
            "input_tokens": 10,
            "cache_read_input_tokens": 20,
            "cache_creation_input_tokens": 0,
            "output_tokens": 5,
        }}},
    ])

    assert collect_agent_token_usage(tmp_path) == {
        "request_count": 2,
        "input_uncached_tokens": 130,
        "input_cached_tokens": 820,
        "input_cache_write_tokens": 30,
        "input_total_tokens": 980,
        "output_tokens": 50,
        "reasoning_output_tokens": 0,
        "source": "claude_code",
        "last_input_total_tokens": 30,
        "last_output_tokens": 5,
    }


def test_pi_usage_deduplicates_resumed_session_entries(tmp_path):
    path = tmp_path / ".pi/agent/sessions/reverse_solve_combined.jsonl"
    message = {
        "role": "assistant",
        "responseId": "response-1",
        "usage": {
            "input": 12,
            "cacheRead": 340,
            "cacheWrite": 5,
            "output": 67,
            "reasoning": 22,
        },
    }
    _write_jsonl(path, [
        {"type": "session", "version": 3},
        {"type": "message", "id": "entry-1", "message": message},
        {"type": "message", "id": "entry-1", "message": message},
    ])

    usage = collect_agent_token_usage(tmp_path)
    assert usage["request_count"] == 1
    assert usage["input_total_tokens"] == 357
    assert usage["last_input_total_tokens"] == 357
    assert usage["last_output_tokens"] == 67
    assert usage["output_tokens"] == 67
    assert usage["reasoning_output_tokens"] == 22
    assert usage["source"] == "pi"


def test_token_cost_uses_cache_price_and_charges_cache_write_as_regular_input():
    usage = {
        "input_uncached_tokens": 200_000,
        "input_cached_tokens": 700_000,
        "input_cache_write_tokens": 100_000,
        "output_tokens": 50_000,
    }
    pricing = {
        "input_price_per_million": "2",
        "cached_input_price_per_million": "0.5",
        "output_price_per_million": "8",
    }

    assert calculate_agent_token_cost_rmb(usage, pricing) == "1.35"
    assert calculate_agent_token_cost_rmb(usage, None) is None
