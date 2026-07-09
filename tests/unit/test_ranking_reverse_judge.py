# -*- coding: utf-8 -*-
"""反向评测纯逻辑单测：题目包识别、result.json 规范与反向得分公式。"""

import json
import zipfile

import pytest

import oj_modules.ranking_reverse_judge_db as rjdb
import oj_modules.tasks.ranking_reverse_judge_tasks as rj


def _make_package(root):
    for name in ("problem", "template", "solution"):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / "judge.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")


def test_find_package_root_accepts_direct_shape(tmp_path):
    _make_package(tmp_path)

    assert rj._find_package_root(str(tmp_path)) == str(tmp_path)


def test_find_package_root_accepts_single_top_level_directory(tmp_path):
    package = tmp_path / "reverse-task"
    _make_package(package)

    assert rj._find_package_root(str(tmp_path)) == str(package)


def test_safe_extract_zip_ignores_path_traversal(tmp_path):
    zip_path = tmp_path / "bad.zip"
    out_dir = tmp_path / "out"
    outside = tmp_path / "evil.txt"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("problem/readme.md", "ok")
        zf.writestr("../evil.txt", "bad")

    rj._safe_extract_zip(str(zip_path), str(out_dir))

    assert (out_dir / "problem" / "readme.md").read_text(encoding="utf-8") == "ok"
    assert not outside.exists()


def test_normalize_test_points_accepts_object_and_clamps_scores():
    out = rj._normalize_test_points({
        "case_1": {"description": "基础点", "max_score": 10, "score": 12},
    })

    assert out == {
        "case_1": {"description": "基础点", "max_score": 10.0, "score": 10.0},
    }


def test_normalize_test_points_accepts_list():
    out = rj._normalize_test_points([
        {"description": "第一点", "max_score": "5", "score": "4.5"},
    ])

    assert out == {
        "1": {"description": "第一点", "max_score": 5.0, "score": 4.5},
    }


@pytest.mark.parametrize("bad", [
    "not-dict",
    {"case": "bad"},
    {"case": {"description": "x", "max_score": "nan?", "score": 1}},
    {"case": {"description": "x", "max_score": 1, "score": -0.1}},
])
def test_normalize_test_points_rejects_invalid_shapes(bad):
    with pytest.raises(ValueError):
        rj._normalize_test_points(bad)


def test_load_result_json_validates_and_normalizes(tmp_path):
    payload = {
        "max_score": 20,
        "score": 18,
        "test_points": {
            "a": {"description": "A", "max_score": 10, "score": 8},
            "b": {"description": "B", "max_score": 10, "score": 10},
        },
    }
    (tmp_path / "result.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8",
    )

    result = rj._load_result_json(str(tmp_path))

    assert result["max_score"] == 20.0
    assert result["score"] == 18.0
    assert result["test_points"]["a"]["score"] == 8.0


def test_score_full_uses_tight_tolerance():
    assert rj._score_full({"score": 99.99999999, "max_score": 100})
    assert not rj._score_full({"score": 99.99, "max_score": 100})


@pytest.mark.parametrize("ai_score,ai_max,expected_user,expected_ai_percent", [
    (0, 100, 100.0, 0.0),
    (25, 100, 75.0, 25.0),
    (100, 100, 0.0, 100.0),
    (120, 100, 0.0, 100.0),
])
def test_reverse_user_score(ai_score, ai_max, expected_user, expected_ai_percent):
    user_score, ai_percent = rj._reverse_user_score(ai_score, ai_max)

    assert user_score == pytest.approx(expected_user)
    assert ai_percent == pytest.approx(expected_ai_percent)


def test_reverse_user_score_rejects_non_positive_max_score():
    with pytest.raises(ValueError):
        rj._reverse_user_score(1, 0)


def test_resolve_selected_endpoint_requires_user_choice(monkeypatch):
    monkeypatch.setattr(rj, "list_agent_judge_endpoints", lambda _cid: [])

    endpoint, message = rj._resolve_selected_endpoint(9, None)

    assert endpoint is None
    assert "未选择" in message


def test_resolve_selected_endpoint_rejects_paused_endpoint(monkeypatch):
    monkeypatch.setattr(rj, "list_agent_judge_endpoints", lambda _cid: [{
        "id": 17,
        "harness": "claude_code",
        "base_url": "https://example.test/anthropic",
        "api_key": "sk-test",
        "model": "mimo-v2.5-pro",
        "concurrency_limit": 1,
        "status": "paused",
    }])

    endpoint, message = rj._resolve_selected_endpoint(9, 17)

    assert endpoint is None
    assert "不可用" in message


def test_resolve_selected_endpoint_returns_only_selected_enabled_endpoint(monkeypatch):
    monkeypatch.setattr(rj, "list_agent_judge_endpoints", lambda _cid: [
        {
            "id": 16,
            "harness": "claude_code",
            "base_url": "https://qwen.example/anthropic",
            "api_key": "sk-qwen",
            "model": "qwen3.7-plus",
            "concurrency_limit": 4,
            "status": "enabled",
        },
        {
            "id": 17,
            "harness": "claude_code",
            "base_url": "https://mimo.example/anthropic",
            "api_key": "sk-mimo",
            "model": "mimo-v2.5-pro",
            "concurrency_limit": 2,
            "status": "enabled",
        },
    ])

    endpoint, message = rj._resolve_selected_endpoint(9, "17")

    assert message == ""
    assert endpoint == {
        "id": 17,
        "harness": "claude_code",
        "base_url": "https://mimo.example/anthropic",
        "api_key": "sk-mimo",
        "model": "mimo-v2.5-pro",
        "concurrency_limit": 2,
    }


def test_agent_container_base_url_maps_localhost_for_docker():
    assert (
        rj._agent_container_base_url("http://127.0.0.1:18080")
        == "http://host.docker.internal:18080"
    )
    assert (
        rj._agent_container_base_url("http://localhost:18080/v1")
        == "http://host.docker.internal:18080/v1"
    )
    assert (
        rj._agent_container_base_url("https://dashscope.aliyuncs.com/compatible-mode")
        == "https://dashscope.aliyuncs.com/compatible-mode"
    )


def test_collect_trace_files_prefers_single_claude_project_jsonl(tmp_path):
    trace = tmp_path / "trace"
    project = trace / ".claude" / "projects" / "-workspace"
    project.mkdir(parents=True)
    (trace / ".aj_harness.log").write_text("noise", encoding="utf-8")
    (project / "session.jsonl").write_text('{"type":"assistant"}\n', encoding="utf-8")

    files = rjdb._collect_trace_files(str(trace))

    assert len(files) == 1
    assert files[0]["path"].replace("\\", "/") == ".claude/projects/-workspace/session.jsonl"
    assert '{"type":"assistant"}' in files[0]["content"]


def test_collect_trace_messages_extracts_visible_reply_and_subagent(tmp_path):
    trace = tmp_path / "trace"
    project = trace / ".claude" / "projects" / "-workspace"
    project.mkdir(parents=True)
    lines = [
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "model": "qwen3.6-flash",
                "content": [{"type": "thinking", "thinking": "hidden"}],
            },
        },
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "model": "qwen3.6-flash",
                "content": [{"type": "text", "text": "我会先实现线段树。"}],
            },
        },
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "name": "Task",
                    "input": {"description": "检查边界样例", "subagent_type": "general-purpose"},
                }],
            },
        },
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [{
                    "type": "tool_use",
                    "name": "Bash",
                    "input": {"description": "运行样例", "command": "python3 solve.py < sample.txt"},
                }],
            },
        },
    ]
    (project / "session.jsonl").write_text(
        "\n".join(json.dumps(line, ensure_ascii=False) for line in lines),
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert messages == [
        {
            "kind": "thinking",
            "title": "思考片段",
            "text": "hidden",
            "html": "<p>hidden</p>",
            "meta": "qwen3.6-flash",
            "line": 1,
        },
        {
            "kind": "assistant",
            "title": "AI 回复",
            "text": "我会先实现线段树。",
            "html": "<p>我会先实现线段树。</p>",
            "meta": "qwen3.6-flash",
            "line": 2,
        },
        {
            "kind": "subagent",
            "title": "派出 subagent",
            "text": "类型：general-purpose\n任务：检查边界样例",
            "meta": "general-purpose",
            "format": "text",
            "line": 3,
        },
        {
            "kind": "tool",
            "title": "运行命令",
            "text": "说明：运行样例\n命令：\npython3 solve.py < sample.txt",
            "meta": "Bash",
            "format": "text",
            "line": 4,
        },
    ]


def test_collect_claude_trace_messages_keeps_unknown_tool_as_json(tmp_path):
    trace = tmp_path / "trace"
    project = trace / ".claude" / "projects" / "-workspace"
    project.mkdir(parents=True)
    item = {
        "type": "tool_use",
        "name": "MysteryTool",
        "input": {"value": 3},
    }
    (project / "session.jsonl").write_text(
        json.dumps({
            "type": "assistant",
            "message": {"role": "assistant", "content": [item]},
        }, ensure_ascii=False),
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert messages == [{
        "kind": "tool",
        "title": "调用 MysteryTool",
        "text": json.dumps(item, ensure_ascii=False, indent=2),
        "meta": "MysteryTool",
        "format": "json",
        "line": 1,
    }]


def test_collect_trace_files_prefers_codex_stdout_jsonl(tmp_path):
    trace = tmp_path / "trace"
    trace.mkdir()
    (trace / ".aj_harness.log").write_text("noise", encoding="utf-8")
    (trace / "codex_reverse_solve.jsonl").write_text(
        json.dumps({"type": "agent_message", "message": "done"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    files = rjdb._collect_trace_files(str(trace))

    assert len(files) == 1
    assert files[0]["path"] == "codex_reverse_solve.jsonl"
    assert '"agent_message"' in files[0]["content"]


def test_collect_codex_trace_messages_extracts_errors(tmp_path):
    trace = tmp_path / "trace"
    trace.mkdir()
    events = [
        {
            "type": "item.completed",
            "item": {
                "type": "error",
                "message": "Model metadata for `deepseek-v4-flash` not found.",
            },
        },
        {
            "type": "error",
            "message": "unexpected status 404 Not Found, url: https://api.deepseek.com/responses",
        },
        {
            "type": "turn.failed",
            "error": {
                "message": "unexpected status 404 Not Found, url: https://api.deepseek.com/responses",
            },
        },
    ]
    (trace / "codex_reverse_solve.jsonl").write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events),
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert messages == [
        {
            "kind": "tool",
            "title": "Codex 错误",
            "text": json.dumps(events[0], ensure_ascii=False, indent=2),
            "meta": "error",
            "format": "json",
            "line": 1,
        },
        {
            "kind": "tool",
            "title": "Codex 错误",
            "text": json.dumps(events[1], ensure_ascii=False, indent=2),
            "meta": "error",
            "format": "json",
            "line": 2,
        },
        {
            "kind": "tool",
            "title": "Codex 错误",
            "text": json.dumps(events[2], ensure_ascii=False, indent=2),
            "meta": "turn.failed",
            "format": "json",
            "line": 3,
        },
    ]


def test_collect_codex_trace_messages_extracts_reply_reasoning_and_tool(tmp_path):
    trace = tmp_path / "trace"
    trace.mkdir()
    events = [
        {"type": "agent_reasoning", "text": "先分析边界。", "model": "deepseek-v4-flash"},
        {"type": "agent_message", "message": "我会写一个动态规划。", "model": "deepseek-v4-flash"},
        {"type": "exec_command_begin", "command": "python3 solve.py"},
        {
            "type": "item.completed",
            "item": {
                "type": "function_call",
                "name": "apply_patch",
                "arguments": "{\"cmd\":\"patch\"}",
            },
        },
        {
            "type": "item.completed",
            "item": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "完成。"}],
            },
        },
    ]
    (trace / "codex_reverse_solve.jsonl").write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events),
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert messages == [
        {
            "kind": "thinking",
            "title": "思考片段",
            "text": "先分析边界。",
            "html": "<p>先分析边界。</p>",
            "meta": "deepseek-v4-flash",
            "line": 1,
        },
        {
            "kind": "assistant",
            "title": "AI 回复",
            "text": "我会写一个动态规划。",
            "html": "<p>我会写一个动态规划。</p>",
            "meta": "deepseek-v4-flash",
            "line": 2,
        },
        {
            "kind": "tool",
            "title": "运行命令",
            "text": "命令：python3 solve.py",
            "meta": "Shell",
            "format": "text",
            "line": 3,
        },
        {
            "kind": "tool",
            "title": "调用 apply_patch",
            "text": json.dumps({"cmd": "patch"}, ensure_ascii=False, indent=2),
            "meta": "apply_patch",
            "format": "text",
            "line": 4,
        },
        {
            "kind": "assistant",
            "title": "AI 回复",
            "text": "完成。",
            "html": "<p>完成。</p>",
            "meta": "item.completed",
            "line": 5,
        },
    ]
