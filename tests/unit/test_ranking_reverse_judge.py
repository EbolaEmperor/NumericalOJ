# -*- coding: utf-8 -*-
"""反向评测纯逻辑单测：题目包识别、result.json 规范与反向得分公式。"""

import json
import zipfile

import pytest

import oj_modules.ranking_reverse_judge_db as rjdb
import oj_modules.tasks.ranking_reverse_judge_tasks as rj


def _without_trace_identity(messages):
    ignored = {'offset', 'event_index', 'source', 'phase'}
    return [{key: value for key, value in message.items() if key not in ignored}
            for message in messages]


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


def test_safe_extract_zip_rejects_path_traversal_without_leaving_partial_files(tmp_path):
    zip_path = tmp_path / "bad.zip"
    out_dir = tmp_path / "out"
    outside = tmp_path / "evil.txt"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("problem/readme.md", "ok")
        zf.writestr("../evil.txt", "bad")

    with pytest.raises(RuntimeError, match="越界路径"):
        rj._safe_extract_zip(str(zip_path), str(out_dir))

    assert not out_dir.exists()
    assert not outside.exists()


def test_safe_extract_zip_rejects_member_count_size_and_compression_bombs(monkeypatch, tmp_path):
    too_many = tmp_path / "too-many.zip"
    with zipfile.ZipFile(too_many, "w") as zf:
        zf.writestr("a.txt", "a")
        zf.writestr("b.txt", "b")
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_MEMBERS", 1)
    with pytest.raises(RuntimeError, match="文件数量"):
        rj._safe_extract_zip(str(too_many), str(tmp_path / "many-out"))

    oversized = tmp_path / "oversized.zip"
    with zipfile.ZipFile(oversized, "w") as zf:
        zf.writestr("large.txt", "12345")
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_MEMBERS", 10)
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_FILE_BYTES", 4)
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_TOTAL_BYTES", 8)
    with pytest.raises(RuntimeError, match="单个文件"):
        rj._safe_extract_zip(str(oversized), str(tmp_path / "large-out"))

    ratio_bomb = tmp_path / "ratio.zip"
    with zipfile.ZipFile(ratio_bomb, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.txt", "0" * 10000)
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_FILE_BYTES", 20000)
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_TOTAL_BYTES", 20000)
    monkeypatch.setattr(rj, "REVERSE_PACKAGE_MAX_COMPRESSION_RATIO", 2.0)
    with pytest.raises(RuntimeError, match="压缩比"):
        rj._safe_extract_zip(str(ratio_bomb), str(tmp_path / "ratio-out"))


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


def test_historical_three_step_snapshot_is_projected_to_canonical_four_step_order(monkeypatch):
    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, *_args, **_kwargs):
            return None

        def fetchall(self):
            return [
                {"step_key": "solution_check", "step_order": 1, "title": "标准答案自检", "status": "passed"},
                {"step_key": "agent_answer", "step_order": 2, "title": "AI 作答", "status": "passed"},
                {"step_key": "ai_judge", "step_order": 3, "title": "评测 AI 答案", "status": "passed"},
            ]

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            return None

    monkeypatch.setattr(rjdb, "get_ranking_submission", lambda _sid: {"status": "Accepted"})
    monkeypatch.setattr(rjdb, "get_db_connection", lambda: Connection())

    steps = rjdb.list_reverse_judge_steps(17)

    assert [step["step_key"] for step in steps] == [
        "solution_check", "quality_gate", "agent_answer", "ai_judge",
    ]
    assert [step["step_order"] for step in steps] == [1, 2, 3, 4]
    assert steps[1]["status"] == "skipped"


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

    assert _without_trace_identity(messages) == [
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

    assert _without_trace_identity(messages) == [{
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

    assert _without_trace_identity(messages) == [
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

    assert _without_trace_identity(messages) == [
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


# 质量门禁新增逻辑：保持本文件既有 pytest + monkeypatch 风格，所有外部 I/O 都在
# 被测模块导入位置打桩。
import hashlib
from types import SimpleNamespace
from unittest.mock import MagicMock


def _quality_endpoint(endpoint_id=1, harness=None, **overrides):
    endpoint = {
        "id": endpoint_id,
        "pool_kind": "quality_gate",
        "harness": harness or rj.HARNESS_CLAUDE_CODE,
        "base_url": f"https://gate-{endpoint_id}.example/v1",
        "api_key": f"secret-{endpoint_id}",
        "model": f"model-{endpoint_id}",
        "concurrency_limit": 2,
    }
    endpoint.update(overrides)
    return endpoint


def _successful_run(result):
    return {
        "ok": True,
        "returncode": 0,
        "stdout": "ok",
        "stderr": "",
        "error": "",
        "result": result,
    }


def test_fake_reverse_judge_helpers_distinguish_solution_and_config(monkeypatch):
    solution = rj._fake_judge_result("  solution/  ")
    template = rj._fake_judge_result("template/")
    empty = rj._fake_judge_result(None)

    assert solution["score"] == solution["max_score"] == 100.0
    assert solution["test_points"]["fake"]["score"] == 100.0
    assert template["score"] == empty["score"] == 25.0
    assert template["test_points"]["fake"]["description"] == "本地 e2e 假反向评测"

    monkeypatch.delenv("NUMOJ_FAKE_REVERSE_JUDGE", raising=False)
    monkeypatch.setattr(rj._cfg, "NUMOJ_FAKE_REVERSE_JUDGE", True, raising=False)
    assert rj._fake_reverse_judge_enabled() is True
    monkeypatch.setenv("NUMOJ_FAKE_REVERSE_JUDGE", "  OFF  ")
    assert rj._fake_reverse_judge_enabled() is False
    monkeypatch.setenv("NUMOJ_FAKE_REVERSE_JUDGE", " YeS ")
    assert rj._fake_reverse_judge_enabled() is True

    monkeypatch.delenv("NUMOJ_FAKE_REVERSE_QUALITY_GATE", raising=False)
    monkeypatch.setattr(rj._cfg, "NUMOJ_FAKE_REVERSE_QUALITY_GATE", False, raising=False)
    assert rj._fake_reverse_quality_gate_enabled() is False
    monkeypatch.setenv("NUMOJ_FAKE_REVERSE_QUALITY_GATE", " ON ")
    assert rj._fake_reverse_quality_gate_enabled() is True


def test_safe_attempt_component_blocks_path_traversal_and_limits_length():
    assert rj._safe_attempt_component("../../attempt_A-1") == "attempt_A-1"
    assert rj._safe_attempt_component(None) == "legacy"
    assert rj._safe_attempt_component("../..") == "legacy"
    assert rj._safe_attempt_component("a" * 100) == "a" * 80


def test_attempt_workspace_cleanup_is_scoped_and_trace_retention_is_bounded(
        monkeypatch, tmp_path):
    workspace_root = tmp_path / "workspaces"
    current_workspace = workspace_root / "9" / "attempt-new"
    sibling_workspace = workspace_root / "9" / "attempt-old"
    current_workspace.mkdir(parents=True)
    sibling_workspace.mkdir(parents=True)
    monkeypatch.setattr(rj, "REVERSE_WORKSPACE_ROOT", str(workspace_root))

    rj._cleanup_attempt_workspace(9, "attempt-new")

    assert not current_workspace.exists()
    assert sibling_workspace.exists()

    submission_root = tmp_path / "submission"
    trace_parent = submission_root / "reverse_agent_trace"
    for name in ("keep", "newer", "old-a", "old-b"):
        path = trace_parent / name
        path.mkdir(parents=True)
        (path / "trace.jsonl").write_text("trace", encoding="utf-8")
    now = 1_000_000.0
    for name, mtime in (
        ("keep", now),
        ("newer", now - 10),
        ("old-a", now - 1000),
        ("old-b", now - 2000),
    ):
        __import__("os").utime(trace_parent / name, (mtime, mtime))
    monkeypatch.setattr(rj, "submission_dir", lambda _sid: str(submission_root))
    monkeypatch.setattr(rj.time, "time", lambda: now)
    monkeypatch.setattr(rj, "REVERSE_TRACE_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(rj, "REVERSE_TRACE_MIN_DELETE_AGE_SECONDS", 100)
    monkeypatch.setattr(rj, "REVERSE_TRACE_RETENTION_SECONDS", 5000)

    removed = rj._prune_reverse_trace_attempts(9, keep_attempt="keep")

    assert removed == 2
    assert (trace_parent / "keep").exists()
    assert (trace_parent / "newer").exists()
    assert not (trace_parent / "old-a").exists()
    assert not (trace_parent / "old-b").exists()


def test_parse_quality_gate_result_accepts_strict_json_and_fenced_json():
    passed = rj._parse_quality_gate_result(
        '```json\n{"passed": true, "summary": "符合标准", "violations": []}\n```'
    )
    rejected = rj._parse_quality_gate_result(json.dumps({
        "passed": False,
        "summary": "存在私有协议",
        "violations": [{
            "rule": "不得隐藏配对密码",
            "reason": "标准答案含私有调用",
            "evidence": [{
                "path": "solution/main.py",
                "line": "17",
                "excerpt": "secret_handshake()",
            }],
        }],
    }, ensure_ascii=False))

    assert passed == {
        "passed": True,
        "verdict": "pass",
        "summary": "符合标准",
        "violations": [],
    }
    assert rejected["passed"] is False
    assert rejected["verdict"] == "reject"
    assert rejected["violations"][0]["evidence"][0]["line"] == 17


def test_parse_quality_gate_result_rejects_pass_with_violations_and_caps_output():
    evidence = [{
        "path": "p" * 600,
        "line": "not-an-int",
        "excerpt": "e" * 2200,
    } for _ in range(21)]
    violations = [{
        "rule": "r" * 2200,
        "reason": "x" * 4200,
        "evidence": evidence,
    } for _ in range(51)]

    result = rj._parse_quality_gate_result(json.dumps({
        "passed": True,
        "summary": "s" * 4200,
        "violations": violations,
    }))

    assert result["passed"] is False
    assert result["verdict"] == "reject"
    assert len(result["summary"]) == 4000
    assert len(result["violations"]) == 50
    first = result["violations"][0]
    assert len(first["rule"]) == 2000
    assert len(first["reason"]) == 4000
    assert len(first["evidence"]) == 20
    assert first["evidence"][0]["line"] is None
    assert len(first["evidence"][0]["path"]) == 500
    assert len(first["evidence"][0]["excerpt"]) == 2000


@pytest.mark.parametrize("raw", [
    "not-json",
    'before {"passed":true,"summary":"ok","violations":[]} after',
    "[]",
    '{"passed":1,"summary":"ok","violations":[]}',
    '{"passed":true,"summary":" ","violations":[]}',
    '{"passed":true,"summary":"ok","violations":{}}',
    '{"passed":false,"summary":"bad","violations":[1]}',
    ('{"passed":false,"summary":"bad","violations":['
     '{"rule":"r","reason":"x","evidence":{}}]}'),
    ('{"passed":false,"summary":"bad","violations":['
     '{"rule":"r","reason":"x","evidence":[1]}]}'),
])
def test_parse_quality_gate_result_rejects_malformed_schema(raw):
    with pytest.raises(ValueError, match="质量门禁"):
        rj._parse_quality_gate_result(raw)


def test_prepare_workspace_freezes_original_package_and_restore_isolates_mutation(
        monkeypatch, tmp_path):
    upload = tmp_path / "submission.zip"
    with zipfile.ZipFile(upload, "w") as zf:
        zf.writestr("task/judge.sh", "#!/bin/sh\n")
        zf.writestr("task/problem/readme.md", "original problem")
        zf.writestr("task/template/main.py", "pass\n")
        zf.writestr("task/solution/main.py", "print(42)\n")
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(rj, "REVERSE_WORKSPACE_ROOT", str(workspace_root))

    ws, package_root, audit_root = rj._prepare_workspace(
        {"id": 9, "code_path": str(upload)}, "../../attempt-1",
    )

    assert ws == str((workspace_root / "9" / "attempt-1").resolve())
    assert package_root != audit_root
    assert (tmp_path / "workspaces" / "9" / "attempt-1" / "quality_gate_source"
            / "problem" / "readme.md").read_text() == "original problem"

    package_problem = __import__("pathlib").Path(package_root) / "problem" / "readme.md"
    audit_problem = __import__("pathlib").Path(audit_root) / "problem" / "readme.md"
    package_problem.write_text("mutated by judge.sh", encoding="utf-8")
    (__import__("pathlib").Path(package_root) / "private_protocol.txt").write_text(
        "hidden", encoding="utf-8",
    )
    rj._restore_runtime_package(package_root, audit_root)

    assert package_problem.read_text(encoding="utf-8") == "original problem"
    assert audit_problem.read_text(encoding="utf-8") == "original problem"
    assert not (__import__("pathlib").Path(package_root) / "private_protocol.txt").exists()


def test_prepare_workspace_rejects_missing_upload_and_invalid_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(rj, "REVERSE_WORKSPACE_ROOT", str(tmp_path / "ws"))
    with pytest.raises(RuntimeError, match="提交文件不存在"):
        rj._prepare_workspace({"id": 1, "code_path": str(tmp_path / "missing.zip")})

    invalid = tmp_path / "invalid.zip"
    with zipfile.ZipFile(invalid, "w") as zf:
        zf.writestr("problem/readme.md", "missing other required entries")
    with pytest.raises(RuntimeError, match="必须包含"):
        rj._prepare_workspace({"id": 2, "code_path": str(invalid)}, "a")


def test_quality_endpoint_payloads_uses_independent_enabled_pool_and_exclusions(monkeypatch):
    calls = []
    endpoints = [
        _quality_endpoint(1, concurrency_limit=0),
        _quality_endpoint(2, harness=rj.HARNESS_CODEX, concurrency_limit=3),
    ]
    monkeypatch.setattr(
        rj,
        "list_quality_gate_endpoints",
        lambda competition_id, enabled_only=False:
            calls.append((competition_id, enabled_only)) or endpoints,
    )

    result = rj._quality_endpoint_payloads(7, exclude_ids={2})

    assert calls == [(7, True)]
    assert result == [{
        "id": 1,
        "pool_kind": "quality_gate",
        "harness": rj.HARNESS_CLAUDE_CODE,
        "base_url": "https://gate-1.example/v1",
        "api_key": "secret-1",
        "model": "model-1",
        "concurrency_limit": 1,
    }]

    monkeypatch.setattr(
        rj, "list_quality_gate_endpoints",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("db down")),
    )
    assert rj._quality_endpoint_payloads(7) == []


@pytest.mark.parametrize("value,expected", [
    (True, True), (1, True), (" true ", True), ("YES", True), ("on", True),
    (False, False), (0, False), ("false", False), (None, False), ("", False),
])
def test_quality_gate_enabled_normalizes_explicit_values(value, expected):
    assert rj._quality_gate_enabled({"reverse_quality_gate_enabled": value}) is expected


def test_quality_gate_prompt_and_step_status_normalize_values(monkeypatch):
    assert rj._quality_gate_prompt({"reverse_quality_gate_prompt": "  rule  "}) == "rule"
    assert rj._quality_gate_prompt({}) == ""
    assert rj._quality_gate_prompt(None) == ""

    monkeypatch.setattr(rj, "list_reverse_judge_steps", lambda _sid: [
        {"step_key": "other", "status": "failed"},
        {"step_key": rj.STEP_QUALITY_GATE, "status": " PASSED "},
    ])
    assert rj._step_status(3, rj.STEP_QUALITY_GATE) == "passed"
    assert rj._step_status(3, "missing") == "pending"
    monkeypatch.setattr(rj, "list_reverse_judge_steps", lambda _sid: [
        {"step_key": rj.STEP_QUALITY_GATE, "status": ""},
    ])
    assert rj._step_status(3, rj.STEP_QUALITY_GATE) == "pending"


def test_start_isolated_quality_gate_proxy_builds_internal_agent_network(monkeypatch):
    calls = []
    endpoint_proxy = SimpleNamespace(
        token="attempt-only-token",
        local_base_url="http://127.0.0.1:43123/compatible/v1/",
        close=lambda: calls.append(("endpoint-close",)),
    )
    monkeypatch.setattr(
        rj, "_start_reverse_endpoint_proxy", lambda *_args: endpoint_proxy,
    )
    monkeypatch.setattr(rj, "_wait_quality_gate_container_ready", lambda _name: True)

    def docker_run(args, **_kwargs):
        calls.append(tuple(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(rj.subprocess, "run", docker_run)

    proxy = rj._start_isolated_quality_gate_proxy(
        "https://model.example/v1", "real-key", rj.HARNESS_CLAUDE_CODE,
        "gate-internal-net", "gate-trusted-relay",
    )

    assert proxy.network_name == "gate-internal-net"
    assert proxy.relay_name == "gate-trusted-relay"
    assert proxy.container_base_url == (
        f"http://quality-model-proxy:{rj.REVERSE_QUALITY_GATE_RELAY_PORT}"
        "/compatible/v1"
    )
    network_create = next(
        call for call in calls if call[:3] == ("docker", "network", "create")
    )
    assert "--internal" in network_create
    assert network_create.count("--opt") == 2
    assert "com.docker.network.bridge.gateway_mode_ipv4=isolated" in network_create
    assert "com.docker.network.bridge.gateway_mode_ipv6=isolated" in network_create
    assert network_create[-1] == "gate-internal-net"
    relay_run = next(call for call in calls if call[:3] == ("docker", "run", "-d"))
    assert relay_run[relay_run.index("--network") + 1] == "bridge"
    assert "host.docker.internal:host-gateway" in relay_run
    assert rj.JUDGE_IMAGE in relay_run
    assert (
        "docker", "network", "connect", "--alias", "quality-model-proxy",
        "gate-internal-net", "gate-trusted-relay",
    ) in calls
    assert ("endpoint-close",) not in calls


def test_start_isolated_quality_gate_proxy_failure_cleans_all_layers(monkeypatch):
    events = []
    endpoint_proxy = SimpleNamespace(
        token="attempt-only-token",
        local_base_url="http://127.0.0.1:43123/v1",
        close=lambda: events.append("endpoint-close"),
    )
    monkeypatch.setattr(
        rj, "_start_reverse_endpoint_proxy", lambda *_args: endpoint_proxy,
    )
    monkeypatch.setattr(rj, "_wait_quality_gate_container_ready", lambda _name: False)

    def docker_run(args, **_kwargs):
        if args[:4] == ["docker", "rm", "-f", "gate-relay"]:
            events.append("relay-rm")
        elif args[:4] == ["docker", "network", "rm", "gate-net"]:
            events.append("network-rm")
        else:
            events.append(tuple(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(rj.subprocess, "run", docker_run)

    with pytest.raises(RuntimeError, match="可信网络中继"):
        rj._start_isolated_quality_gate_proxy(
            "https://model.example/v1", "real-key", rj.HARNESS_CLAUDE_CODE,
            "gate-net", "gate-relay",
        )

    endpoint_index = events.index("endpoint-close")
    assert events[endpoint_index + 1:endpoint_index + 3] == ["relay-rm", "network-rm"]


def test_isolated_quality_gate_proxy_close_order_and_idempotence(monkeypatch):
    events = []
    endpoint_proxy = SimpleNamespace(
        token="temporary-token",
        close=lambda: events.append("endpoint-close"),
    )
    proxy = rj._ReverseIsolatedEndpointProxy(
        endpoint_proxy, "gate-net", "gate-relay",
        "http://quality-model-proxy:18080/v1",
    )

    def docker_run(args, **_kwargs):
        if args[:4] == ["docker", "rm", "-f", "gate-relay"]:
            events.append("relay-rm")
        elif args[:4] == ["docker", "network", "rm", "gate-net"]:
            events.append("network-rm")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(rj.subprocess, "run", docker_run)

    proxy.close()
    proxy.close()

    assert events == ["endpoint-close", "relay-rm", "network-rm"]


def _make_quality_gate_audit(monkeypatch, tmp_path, submission_id=31, attempt_id="a1"):
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(rj, "REVERSE_WORKSPACE_ROOT", str(workspace_root))
    audit = workspace_root / str(submission_id) / attempt_id / "quality_gate_source"
    for directory in ("problem", "template", "solution"):
        (audit / directory).mkdir(parents=True)
    (audit / "judge.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    return audit


def test_validate_quality_gate_source_accepts_complete_large_binary_package(
        monkeypatch, tmp_path):
    audit = _make_quality_gate_audit(monkeypatch, tmp_path)
    (audit / "problem" / "readme.md").write_text("题面", encoding="utf-8")
    (audit / "solution" / "large.bin").write_bytes(
        b"\x00\xff" + b"x" * (70 * 1024)
    )
    (audit / "template" / "main.py").write_text("pass\n", encoding="utf-8")

    validated, file_count = rj._validate_quality_gate_source(str(audit), 31, "a1")

    assert validated == str(audit.resolve())
    assert file_count == 4


def test_validate_quality_gate_source_rejects_wrong_attempt_and_symlink(
        monkeypatch, tmp_path):
    audit = _make_quality_gate_audit(monkeypatch, tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")

    with pytest.raises(RuntimeError, match="路径非法"):
        rj._validate_quality_gate_source(str(audit), 31, "other-attempt")

    (audit / "problem" / "outside-link").symlink_to(outside)
    with pytest.raises(RuntimeError, match="符号链接"):
        rj._validate_quality_gate_source(str(audit), 31, "a1")


def test_quality_gate_agent_prompt_only_describes_structure_not_package_contents():
    prompt = rj._quality_gate_agent_prompt("不得隐藏私有协议")

    assert "管理员审核标准：\n不得隐藏私有协议" in prompt
    assert "/evidence" in prompt
    assert all(name in prompt for name in ("problem/", "template/", "solution/", "judge.sh"))
    assert all(tool in prompt for tool in ("Read", "Glob", "Grep"))
    assert "不要写入文件" in prompt
    assert "PACKAGE_BODY_MUST_NEVER_BE_EMBEDDED" not in prompt
    assert "不得执行、导入、编译" in prompt


def test_quality_gate_container_uses_agent_judge_image_and_strict_isolation():
    proxy = SimpleNamespace(
        network_name="gate-internal-net",
        container_base_url="http://quality-model-proxy:18080/v1",
        token="attempt-only-proxy-token",
        real_api_key="REAL_ENDPOINT_API_KEY",
    )

    args = rj._quality_gate_container_args(
        "gate-container", "/srv/audit", proxy,
        rj.HARNESS_CODEX, "deepseek-v4-flash",
    )
    rendered = json.dumps(args, ensure_ascii=False)

    assert args[-4] == rj.JUDGE_IMAGE
    assert args[-3:] == ["bash", "-lc", "tail -f /dev/null"]
    assert ["--network", "gate-internal-net"] == (
        args[args.index("--network"):args.index("--network") + 2]
    )
    assert ["--user", "node"] == args[args.index("--user"):args.index("--user") + 2]
    assert "--read-only" in args
    assert ["--cap-drop", "ALL"] == args[args.index("--cap-drop"):args.index("--cap-drop") + 2]
    assert "type=bind,source=/srv/audit,target=/evidence,readonly" in args
    assert "AJ_AUDIT_READ_ONLY=1" in args
    assert "AJ_RESULT_FILE=" not in rendered
    assert "attempt-only-proxy-token" in rendered
    assert "REAL_ENDPOINT_API_KEY" not in rendered
    assert "docker.sock" not in rendered
    assert "host-gateway" not in rendered
    assert "bridge" not in args


def test_quality_gate_harness_result_extracts_structured_final_reply():
    verdict = json.dumps({
        "passed": True, "summary": "审核通过", "violations": [],
    }, ensure_ascii=False)
    samples = {
        rj.HARNESS_CLAUDE_CODE: json.dumps({
            "type": "result", "result": verdict,
        }, ensure_ascii=False),
        rj.HARNESS_CODEX: "\n".join([
            json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
            json.dumps({
                "type": "item.completed",
                "item": {"type": "agent_message", "text": verdict},
            }, ensure_ascii=False),
        ]),
        rj.HARNESS_OPENCODE: json.dumps({
            "type": "text", "part": {"type": "text", "text": verdict},
        }, ensure_ascii=False),
    }

    for harness, stdout in samples.items():
        assert rj._quality_gate_harness_result_text(stdout, harness) == verdict


@pytest.mark.parametrize("harness,stdout,error_fragment", [
    (rj.HARNESS_CLAUDE_CODE, "not-json", "Claude Code 输出不是合法 JSON"),
    (rj.HARNESS_CLAUDE_CODE, '{"type":"result"}', "缺少最终结论"),
    (
        rj.HARNESS_CODEX,
        '{"type":"item.completed","item":{"type":"command_execution"}}',
        "缺少最终结论",
    ),
])
def test_quality_gate_harness_result_rejects_malformed_structured_output(
        harness, stdout, error_fragment):
    with pytest.raises(ValueError, match=error_fragment):
        rj._quality_gate_harness_result_text(stdout, harness)


@pytest.mark.parametrize("harness,stdout", [
    (rj.HARNESS_CLAUDE_CODE, json.dumps({"result": "123456789"})),
    (
        rj.HARNESS_CODEX,
        json.dumps({
            "type": "item.completed",
            "item": {"type": "agent_message", "text": "123456789"},
        }),
    ),
    (
        rj.HARNESS_OPENCODE,
        json.dumps({"type": "text", "part": {"type": "text", "text": "123456789"}}),
    ),
])
def test_quality_gate_harness_result_rejects_oversized_reply(
        monkeypatch, harness, stdout):
    monkeypatch.setattr(rj, "REVERSE_QUALITY_GATE_RESULT_MAX_BYTES", 8)

    with pytest.raises(ValueError, match="审核结论过大"):
        rj._quality_gate_harness_result_text(stdout, harness)


@pytest.mark.parametrize("inspect_values,expected_commands,expected", [
    (["false"], ["stop", "inspect"], True),
    (["true", "false"], ["stop", "inspect", "kill", "inspect"], True),
    (["true", "true"], ["stop", "inspect", "kill", "inspect"], False),
])
def test_stop_quality_gate_container_confirms_shutdown_or_kills(
        monkeypatch, inspect_values, expected_commands, expected):
    commands = []
    states = iter(inspect_values)

    def docker_run(args, **_kwargs):
        command = args[1]
        commands.append(command)
        if command == "inspect":
            return SimpleNamespace(returncode=0, stdout=next(states), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(rj.subprocess, "run", docker_run)

    assert rj._stop_quality_gate_container("gate-agent") is expected
    assert commands == expected_commands


def test_run_quality_gate_agent_fake_pass_and_reject_include_full_package_metadata(
        monkeypatch, tmp_path):
    audit = _make_quality_gate_audit(monkeypatch, tmp_path)
    (audit / "solution" / "large.bin").write_bytes(b"\x00" + b"x" * (70 * 1024))
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: True)

    passed = rj._run_quality_gate_agent(
        31, "a1", str(audit), _quality_endpoint(), "rule", 30,
    )
    (audit / "quality_gate_reject.txt").write_text("reject", encoding="utf-8")
    rejected = rj._run_quality_gate_agent(
        31, "a1", str(audit), _quality_endpoint(), "rule", 30,
    )

    assert passed["ok"] is True
    assert passed["stdout"] == "fake quality gate agent"
    assert passed["result"]["verdict"] == "pass"
    assert passed["result"]["criteria_sha256"] == hashlib.sha256(b"rule").hexdigest()
    assert passed["result"]["source_file_count"] == 2
    assert passed["result"]["agentic_review"] is True
    assert rejected["ok"] is True
    assert rejected["result"]["verdict"] == "reject"
    assert rejected["result"]["violations"][0]["evidence"][0]["path"] == (
        "quality_gate_reject.txt"
    )
    assert rejected["result"]["source_file_count"] == 3


def test_run_quality_gate_agent_executes_harness_parses_json_and_cleans_up(
        monkeypatch, tmp_path):
    audit = _make_quality_gate_audit(monkeypatch, tmp_path, 42, "attempt-1")
    package_sentinel = "PACKAGE_BODY_MUST_NEVER_BE_EMBEDDED"
    (audit / "problem" / "readme.md").write_text(package_sentinel, encoding="utf-8")
    events = []
    docker_calls = []
    phase_calls = []
    real_key = "real-endpoint-api-key"
    endpoint_proxy = SimpleNamespace(
        token="attempt-only-proxy-token",
        close=lambda: events.append("endpoint-revoke"),
    )
    proxy = rj._ReverseIsolatedEndpointProxy(
        endpoint_proxy, "gate-internal-net", "gate-trusted-relay",
        "http://quality-model-proxy:18080/v1",
    )
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: False)
    monkeypatch.setattr(rj, "_start_isolated_quality_gate_proxy", lambda *_args: proxy)
    monkeypatch.setattr(rj.secrets, "token_hex", lambda _size: "nonce")
    monkeypatch.setattr(rj, "_quality_gate_container_running", lambda _name: True)
    monkeypatch.setattr(rj, "_quality_gate_image_supports_audit_mode", lambda _name: True)
    monkeypatch.setattr(
        rj, "_stop_quality_gate_container",
        lambda _name: events.append("stop-confirmed") or True,
    )

    def docker_run(args, **_kwargs):
        docker_calls.append(list(args))
        if args[1] == "run":
            events.append("agent-run")
        elif args[:4] == ["docker", "rm", "-f", "gate-trusted-relay"]:
            events.append("relay-rm")
        elif args[:4] == ["docker", "network", "rm", "gate-internal-net"]:
            events.append("network-rm")
        elif args[1] == "rm" and args[-1].endswith("_agent"):
            events.append("agent-rm")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def run_phase(container_name, runtime_dir, phase, prompt, timeout_s, **_kwargs):
        events.append("harness")
        phase_calls.append((container_name, runtime_dir, phase, prompt, timeout_s))
        verdict = json.dumps({
            "passed": True,
            "summary": f"通过，但不得泄露 {real_key}",
            "violations": [],
        }, ensure_ascii=False)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"type": "result", "result": verdict}, ensure_ascii=False),
            stderr="agent stderr",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj.subprocess, "run", docker_run)
    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_quality_gate_agent(
        42, "attempt-1", str(audit),
        _quality_endpoint(9, api_key=real_key), "不得隐藏私有协议", 45,
    )

    assert result["ok"] is True
    assert result["result"]["verdict"] == "pass"
    assert result["result"]["summary"] == "通过，但不得泄露 [redacted]"
    assert result["result"]["source_file_count"] == 2
    assert result["result"]["agentic_review"] is True
    assert real_key not in result["stdout"]
    assert "[redacted]" in result["stdout"]
    assert result["stderr"] == "agent stderr"
    assert phase_calls[0][0] == "rjg_42_attempt-_nonce_agent"
    assert phase_calls[0][1].endswith("/42/attempt-1/quality_gate_agent")
    assert phase_calls[0][2] == "quality_gate"
    assert phase_calls[0][4] == 45
    assert "不得隐藏私有协议" in phase_calls[0][3]
    assert package_sentinel not in phase_calls[0][3]
    stop_index = events.index("stop-confirmed")
    cleanup_agent_index = events.index("agent-rm", stop_index)
    assert events.index("endpoint-revoke") < stop_index
    assert stop_index < cleanup_agent_index < events.index("relay-rm")
    assert events.index("relay-rm") < events.index("network-rm")
    assert any(call[1] == "run" and rj.JUDGE_IMAGE in call for call in docker_calls)
    assert real_key not in json.dumps(docker_calls, ensure_ascii=False)
    assert real_key not in json.dumps(result, ensure_ascii=False)


@pytest.mark.parametrize("harness,stdout,error_fragment", [
    (rj.HARNESS_CLAUDE_CODE, "not-json", "Claude Code 输出不是合法 JSON"),
    (
        rj.HARNESS_CODEX,
        '{"type":"item.completed","item":{"type":"command_execution"}}',
        "缺少最终结论",
    ),
    (
        rj.HARNESS_OPENCODE,
        '{"type":"text","part":{"type":"text","text":"not-json"}}',
        "未返回合法 JSON",
    ),
])
def test_run_quality_gate_agent_fails_closed_on_malformed_structured_stdout(
        monkeypatch, tmp_path, harness, stdout, error_fragment):
    audit = _make_quality_gate_audit(monkeypatch, tmp_path)
    cleanup = []
    endpoint_proxy = SimpleNamespace(
        token="attempt-only-token",
        close=lambda: cleanup.append("revoke"),
    )
    proxy = rj._ReverseIsolatedEndpointProxy(
        endpoint_proxy, "gate-net", "gate-relay",
        "http://quality-model-proxy:18080/v1",
    )
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: False)
    monkeypatch.setattr(rj, "_start_isolated_quality_gate_proxy", lambda *_args: proxy)
    monkeypatch.setattr(rj, "_quality_gate_container_running", lambda _name: True)
    monkeypatch.setattr(rj, "_quality_gate_image_supports_audit_mode", lambda _name: True)
    monkeypatch.setattr(rj, "_stop_quality_gate_container", lambda _name: True)
    monkeypatch.setattr(
        rj.subprocess, "run",
        lambda args, **_kwargs: cleanup.append(args[1]) or SimpleNamespace(
            returncode=0, stdout="", stderr="",
        ),
    )
    monkeypatch.setattr(
        rj, "_exec_reverse_harness_phase",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=stdout, stderr="", aj_timed_out=False,
        ),
    )

    result = rj._run_quality_gate_agent(
        31, "a1", str(audit), _quality_endpoint(harness=harness), "rule", 30,
    )

    assert result["ok"] is False
    assert result["result"] is None
    assert error_fragment in result["error"]
    assert cleanup.index("revoke") < cleanup.index("network")
    assert cleanup[-1] == "rm"


def test_run_judge_script_and_agent_fake_paths_never_start_docker(monkeypatch, tmp_path):
    monkeypatch.setattr(rj, "_fake_reverse_judge_enabled", lambda: True)
    monkeypatch.setattr(
        rj.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("fake 模式不应启动 Docker"),
    )

    solution = rj._run_judge_script(1, str(tmp_path), "solution", 10)
    template = rj._run_judge_script(1, str(tmp_path), "template", 10)
    agent = rj._run_agent(1, "attempt", str(tmp_path), _quality_endpoint(), 10, 5)

    assert solution["ok"] is template["ok"] is agent["ok"] is True
    assert solution["result"]["score"] == 100.0
    assert template["result"]["score"] == 25.0
    assert agent["trace_dir"] is None


def test_run_agent_sync_trace_registers_once_and_always_cleans_container(
        monkeypatch, tmp_path):
    package = tmp_path / "package"
    (package / "template").mkdir(parents=True)
    (package / "problem").mkdir()
    sync_calls = []
    updates = []
    publications = []
    docker_calls = []
    dumps = []
    env_calls = []
    proxy_closes = []
    proxy = SimpleNamespace(
        container_base_url="http://host.docker.internal:43123/v1",
        token="attempt-only-token",
        close=lambda: proxy_closes.append(True),
    )

    monkeypatch.setattr(rj, "_fake_reverse_judge_enabled", lambda: False)
    monkeypatch.setattr(rj, "submission_dir", lambda _sid: str(tmp_path / "submission"))
    monkeypatch.setattr(
        rj, "_start_reverse_endpoint_proxy",
        lambda base_url, api_key, harness: (
            proxy if (base_url, api_key, harness) == (
                "https://gate-3.example/v1", "top-secret", rj.HARNESS_CLAUDE_CODE,
            ) else pytest.fail("代理收到错误的真实端点配置")
        ),
    )
    monkeypatch.setattr(
        rj, "_agent_env_args",
        lambda harness, base_url, api_key, model, *_args, **_kwargs:
            env_calls.append((harness, base_url, api_key, model)) or [],
    )
    monkeypatch.setattr(
        rj.subprocess, "run",
        lambda args, **_kwargs:
            docker_calls.append(args) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(rj, "_exec_container_apt_setup", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rj, "_prepare_agent_workspace_for_node", lambda *_args: None)
    monkeypatch.setattr(
        rj, "_sync_claude_project_jsonl",
        lambda *_args: sync_calls.append("sync") or True,
    )

    def fake_phase(*_args, on_tick=None, **_kwargs):
        on_tick()
        on_tick()
        return SimpleNamespace(returncode=0, stdout="done", stderr="", aj_timed_out=False)

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", fake_phase)
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda sid: publications.append(sid))
    monkeypatch.setattr(
        rj, "_dump_harness_trace",
        lambda *args: dumps.append(args),
    )

    result = rj._run_agent(
        12, "attempt-1", str(package),
        _quality_endpoint(3, api_key="top-secret"), 30, 10,
    )

    assert result["ok"] is True
    assert result["stdout"] == "done"
    assert len(sync_calls) == 4
    running_updates = [call for call in updates if call[1].get("status") == "running"]
    assert len(running_updates) == 1
    assert running_updates[0][1]["trace_dir"] == result["trace_dir"]
    assert publications == [12, 12, 12, 12]
    assert env_calls == [
        (
            rj.HARNESS_CLAUDE_CODE,
            "http://host.docker.internal:43123/v1",
            "attempt-only-token",
            "model-3",
        )
    ]
    assert proxy_closes == [True]
    assert "top-secret" not in json.dumps(docker_calls, ensure_ascii=False)
    assert "top-secret" not in json.dumps(result, ensure_ascii=False)
    assert len(dumps) == 1
    assert docker_calls[-1][:4] == ["docker", "rm", "-f", "rj_agent_12_attempt-1"]


def test_retry_queued_submission_requeues_current_attempt(monkeypatch):
    retry_calls = []
    statuses = []
    publications = []
    task = SimpleNamespace(retry=lambda **kwargs: retry_calls.append(kwargs))
    monkeypatch.setattr(rj, "get_ranking_submission", lambda _sid: {
        "id": 5, "judge_attempt_id": "a1", "status": "Judging",
    })
    monkeypatch.setattr(
        rj, "set_submission_status_for_attempt",
        lambda *args: statuses.append(args) or 1,
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda sid: publications.append(sid))
    monkeypatch.setattr(rj.secrets, "randbelow", lambda _limit: 2)

    result = rj._retry_queued_submission(task, 5, "a1", message="busy")

    assert result == {"success": False, "message": "busy"}
    assert statuses == [(5, "a1", "Queued")]
    assert retry_calls == [{
        "countdown": rj.JUDGE_QUEUE_RETRY_BASE + 2,
        "max_retries": rj.JUDGE_MAX_QUEUE_RETRIES,
    }]
    assert publications == [5]


def test_retry_queued_submission_marks_only_busy_step_after_retry_exhaustion(monkeypatch):
    updates = []
    final_errors = []
    task = SimpleNamespace(retry=lambda **_kwargs: (_ for _ in ()).throw(
        rj.MaxRetriesExceededError()
    ))
    monkeypatch.setattr(rj, "get_ranking_submission", lambda _sid: {
        "id": 5, "judge_attempt_id": "a1", "status": "Judging",
    })
    monkeypatch.setattr(rj, "set_submission_status_for_attempt", lambda *_args: 1)
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(
        rj, "_write_error_for_attempt",
        lambda *args: final_errors.append(args),
    )

    result = rj._retry_queued_submission(
        task, 5, "a1", timeout_message="gate busy", timeout_step_key=rj.STEP_QUALITY_GATE,
    )

    assert result == {"success": False, "message": "端点持续繁忙"}
    assert updates == [((5, "a1", rj.STEP_QUALITY_GATE), {
        "status": "error", "error_message": "gate busy",
    })]
    assert final_errors == [(5, "a1", "gate busy")]


def test_quality_gate_phase_disabled_records_skipped_without_using_pool(monkeypatch):
    updates = []
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(
        rj, "_quality_endpoint_payloads",
        lambda *_args, **_kwargs: pytest.fail("禁用门禁不得访问端点池"),
    )
    monkeypatch.setattr(
        rj, "_acquire_endpoint_slot",
        lambda *_args, **_kwargs: pytest.fail("禁用门禁不得占槽"),
    )

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "a1",
        {"id": 7, "reverse_quality_gate_enabled": False}, "/audit",
    )

    assert result == {"success": True, "message": "质量门禁未启用"}
    assert updates[0][0] == (8, "a1", rj.STEP_QUALITY_GATE)
    assert updates[0][1]["status"] == "skipped"
    assert updates[0][1]["result_json"]["verdict"] == "skipped"


def test_quality_gate_phase_switches_after_failed_hello_and_releases_every_slot(monkeypatch):
    bad = _quality_endpoint(1)
    good = _quality_endpoint(2)
    acquired = []
    released = []
    disabled = []
    updates = []
    gate_calls = []
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: False)
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_quality_endpoint_payloads",
        lambda _cid, exclude_ids=None:
            [ep for ep in (bad, good) if ep["id"] not in set(exclude_ids or ())],
    )

    def acquire(_client, endpoints, _sid, _ttl):
        endpoint = endpoints[0]
        acquired.append(endpoint["id"])
        return endpoint, f"slot-{endpoint['id']}", f"token-{endpoint['id']}"

    monkeypatch.setattr(rj, "_acquire_endpoint_slot", acquire)
    monkeypatch.setattr(
        rj, "_probe_endpoint",
        lambda endpoint: (endpoint["id"] == 2, "ok" if endpoint["id"] == 2 else "down"),
    )
    monkeypatch.setattr(
        rj, "_disable_unhealthy_endpoint",
        lambda endpoint, reason: disabled.append((endpoint["id"], reason)),
    )
    monkeypatch.setattr(
        rj, "_release_slot",
        lambda _client, key, token: released.append((key, token)),
    )
    monkeypatch.setattr(
        rj, "_run_quality_gate_agent",
        lambda sid, attempt, root, endpoint, criteria, timeout:
            gate_calls.append((sid, attempt, root, endpoint["id"], criteria, timeout)) or {
            "ok": True, "error": "", "stdout": "gate stdout",
            "stderr": "gate stderr", "trace_dir": "/trace/gate", "result": {
                "passed": True, "verdict": "pass", "summary": f"ep-{endpoint['id']}",
                "violations": [],
            },
        },
    )
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, "/audit",
    )

    assert result == {"success": True, "message": "质量门禁通过"}
    assert acquired == [1, 2]
    assert disabled == [(1, "down")]
    assert released == [("slot-1", "token-1"), ("slot-2", "token-2")]
    assert gate_calls == [(8, "a1", "/audit", 2, "rule", rj.REVERSE_QUALITY_GATE_TIMEOUT)]
    assert [kwargs["status"] for _args, kwargs in updates] == ["running", "passed"]
    assert updates[-1][1]["result_json"]["summary"] == "ep-2"
    assert updates[-1][1]["stdout"] == "gate stdout"
    assert updates[-1][1]["stderr"] == "gate stderr"
    assert updates[-1][1]["trace_dir"] == "/trace/gate"


def test_quality_gate_phase_rejects_and_releases_slot(monkeypatch):
    endpoint = _quality_endpoint(3)
    updates = []
    final_errors = []
    releases = []
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(rj, "_quality_endpoint_payloads", lambda *_args, **_kwargs: [endpoint])
    monkeypatch.setattr(
        rj, "_acquire_endpoint_slot",
        lambda *_args: (endpoint, "slot", "token"),
    )
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: True)
    monkeypatch.setattr(rj, "_probe_endpoint", lambda _endpoint: (True, "ok"))
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(rj, "_run_quality_gate_agent", lambda *_args: {
        "ok": True,
        "error": "",
        "stdout": "reject stdout",
        "stderr": "reject stderr",
        "trace_dir": "/trace/reject",
        "result": {
            "passed": False,
            "verdict": "reject",
            "summary": "隐藏私有调用",
            "violations": [{"rule": "rule", "reason": "reason", "evidence": []}],
        },
    })
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(
        rj, "_write_error_for_attempt", lambda *args: final_errors.append(args),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(
        rj, "_release_slot", lambda *_args: releases.append(_args[1:]),
    )

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, "/audit",
    )

    assert result == {"success": False, "message": "质量门禁未通过，请检查题目包后重试"}
    assert [kwargs["status"] for _args, kwargs in updates] == ["running", "failed"]
    assert updates[-1][1]["stdout"] == "reject stdout"
    assert updates[-1][1]["stderr"] == "reject stderr"
    assert updates[-1][1]["trace_dir"] == "/trace/reject"
    assert final_errors == [(8, "a1", "质量门禁未通过，请检查题目包后重试")]
    assert releases == [("slot", "token")]


def test_quality_gate_phase_agent_error_propagates_diagnostics(monkeypatch):
    endpoint = _quality_endpoint(6)
    updates = []
    final_errors = []
    releases = []
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(rj, "_quality_endpoint_payloads", lambda *_args, **_kwargs: [endpoint])
    monkeypatch.setattr(
        rj, "_acquire_endpoint_slot",
        lambda *_args: (endpoint, "slot", "token"),
    )
    monkeypatch.setattr(rj, "_probe_endpoint", lambda _endpoint: (True, "ok"))
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(rj, "_run_quality_gate_agent", lambda *_args: {
        "ok": False,
        "error": "质量门禁 Agent 结果异常",
        "stdout": "failure stdout",
        "stderr": "failure stderr",
        "trace_dir": "/trace/failure",
        "result": None,
    })
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(
        rj, "_write_error_for_attempt", lambda *args: final_errors.append(args),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(
        rj, "_release_slot", lambda *_args: releases.append(_args[1:]),
    )

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, "/audit",
    )

    assert result == {"success": False, "message": "质量门禁 Agent 结果异常"}
    assert [kwargs["status"] for _args, kwargs in updates] == ["running", "error"]
    assert updates[-1][1]["stdout"] == "failure stdout"
    assert updates[-1][1]["stderr"] == "failure stderr"
    assert updates[-1][1]["trace_dir"] == "/trace/failure"
    assert final_errors == [(8, "a1", "质量门禁 Agent 结果异常")]
    assert releases == [("slot", "token")]


def test_quality_gate_phase_busy_delegates_retry_without_marking_gate(monkeypatch):
    endpoint = _quality_endpoint(4)
    updates = []
    retry_calls = []
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(rj, "_quality_endpoint_payloads", lambda *_args, **_kwargs: [endpoint])
    monkeypatch.setattr(rj, "_acquire_endpoint_slot", lambda *_args: (None, None, None))
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )

    def retry(*args, **kwargs):
        retry_calls.append((args, kwargs))
        return {"success": False, "message": "queued"}

    monkeypatch.setattr(rj, "_retry_queued_submission", retry)

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, "/audit",
    )

    assert result == {"success": False, "message": "queued"}
    assert updates == []
    assert retry_calls[0][1]["timeout_step_key"] == rj.STEP_QUALITY_GATE


@pytest.mark.parametrize("current_sequence,agent_called", [
    ([False], False),
    ([True, False], True),
])
def test_quality_gate_phase_old_attempt_never_commits_result_and_releases_slot(
        monkeypatch, current_sequence, agent_called):
    endpoint = _quality_endpoint(5)
    updates = []
    releases = []
    runs = []
    checks = iter(current_sequence)
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(rj, "_quality_endpoint_payloads", lambda *_args, **_kwargs: [endpoint])
    monkeypatch.setattr(rj, "_acquire_endpoint_slot", lambda *_args: (endpoint, "slot", "token"))
    monkeypatch.setattr(rj, "_fake_reverse_quality_gate_enabled", lambda: True)
    monkeypatch.setattr(rj, "_probe_endpoint", lambda _endpoint: (True, "ok"))
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: next(checks))
    monkeypatch.setattr(
        rj, "_run_quality_gate_agent",
        lambda *_args: runs.append(True) or {
            "ok": True,
            "error": "",
            "result": {"passed": True, "summary": "pass", "violations": []},
        },
    )
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: updates.append((args, kwargs)),
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(rj, "_release_slot", lambda *_args: releases.append(_args[1:]))

    result = rj._run_quality_gate_phase(
        SimpleNamespace(), object(), 8, "old", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, "/audit",
    )

    assert result == {"success": True, "message": "旧评测 attempt，跳过"}
    assert bool(runs) is agent_called
    assert not any(kwargs.get("status") == "passed" for _args, kwargs in updates)
    assert releases == [("slot", "token")]


def _patch_reverse_pipeline_base(monkeypatch, tmp_path, events):
    package = tmp_path / "package"
    audit = tmp_path / "audit"
    for root in (package, audit):
        (root / "problem").mkdir(parents=True)
        (root / "problem" / "readme.md").write_text("original", encoding="utf-8")
    submission = {
        "id": 20,
        "competition_id": 7,
        "judge_attempt_id": "a1",
        "status": "Queued",
        "agent_endpoint_id": 44,
    }
    monkeypatch.setattr(rj, "set_submission_status_for_attempt", lambda *_args: 1)
    monkeypatch.setattr(rj, "ensure_reverse_judge_steps_for_attempt", lambda *_args: None)
    monkeypatch.setattr(rj, "_publish_snapshot", lambda _sid: None)
    monkeypatch.setattr(rj, "get_ranking_submission", lambda _sid: dict(submission))
    monkeypatch.setattr(
        rj, "_prepare_workspace",
        lambda *_args: (str(tmp_path / "ws"), str(package), str(audit)),
    )
    monkeypatch.setattr(rj, "_step_status", lambda *_args: "pending")
    monkeypatch.setattr(
        rj, "_persist_agent_answer_archive", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt",
        lambda *args, **kwargs: events.append(
            ("step", args[2], kwargs.get("status"), kwargs.get("stderr")),
        ),
    )
    monkeypatch.setattr(rj, "_write_error_for_attempt", lambda *_args: None)
    return package, audit, submission


@pytest.mark.parametrize("archive_fails", [False, True])
def test_run_reverse_judge_orders_gate_between_solution_and_agent_and_restores_snapshot(
        monkeypatch, tmp_path, archive_fails):
    events = []
    package, audit, _submission = _patch_reverse_pipeline_base(monkeypatch, tmp_path, events)
    endpoint = _quality_endpoint(9)
    final_results = []
    releases = []

    def judge(_sid, package_root, answer_dir, _timeout):
        events.append(("judge", answer_dir))
        if answer_dir == "solution":
            (__import__("pathlib").Path(package_root) / "problem" / "readme.md").write_text(
                "mutated by solution judge", encoding="utf-8",
            )
            return _successful_run({"max_score": 100.0, "score": 100.0, "test_points": {}})
        return _successful_run({"max_score": 100.0, "score": 25.0, "test_points": {}})

    def gate(_task, _client, _sid, _attempt, _competition, audit_root):
        events.append(("gate",))
        assert (__import__("pathlib").Path(audit_root) / "problem" / "readme.md").read_text() == (
            "original"
        )
        assert (package / "problem" / "readme.md").read_text() == "original"
        return {"success": True, "message": "pass"}

    monkeypatch.setattr(rj, "_run_judge_script", judge)
    monkeypatch.setattr(rj, "_run_quality_gate_phase", gate)
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_resolve_selected_endpoint",
        lambda *_args, **_kwargs: events.append(("resolve",)) or (endpoint, ""),
    )
    monkeypatch.setattr(
        rj, "_acquire_endpoint_slot",
        lambda *_args: (endpoint, "answer-slot", "answer-token"),
    )
    monkeypatch.setattr(rj, "_fake_reverse_judge_enabled", lambda: True)
    monkeypatch.setattr(
        rj, "_invalidate_reverse_answer_archive",
        lambda *_args: events.append(("invalidate",)) or False,
    )
    monkeypatch.setattr(
        rj, "_run_agent",
        lambda *_args: events.append(("agent",)) or {
            "ok": True, "stdout": "", "stderr": "", "error": "", "trace_dir": "/trace",
        },
    )
    def persist_archive(*_args, **_kwargs):
        events.append(("archive",))
        if archive_fails:
            raise OSError("disk full")

    monkeypatch.setattr(rj, "_persist_agent_answer_archive", persist_archive)
    monkeypatch.setattr(
        rj, "_release_slot",
        lambda *_args: events.append(("release",)) or releases.append(_args[1:]),
    )
    monkeypatch.setattr(
        rj, "update_submission_result_for_attempt",
        lambda *args, **kwargs: final_results.append((args, kwargs)),
    )

    result = rj._run_reverse_judge(
        SimpleNamespace(), object(), 20, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
            "scoring_script_timeout_seconds": 10,
            "agent_judge_timeout_seconds": 20,
            "reverse_judge_finalize_timeout_seconds": 5,
        }, endpoint_id=77,
    )

    assert result == {"success": True, "score": 75.0}
    assert [event for event in events if event[0] in {
        "judge", "gate", "resolve", "invalidate", "agent", "release", "archive",
    }] == [
        ("invalidate",), ("judge", "solution"), ("gate",), ("resolve",),
        ("agent",), ("release",), ("archive",), ("judge", "template"),
    ]
    assert releases == [("answer-slot", "answer-token")]
    assert final_results[0][0][:4] == (20, "a1", 75.0, "Accepted")
    assert final_results[0][1]["grade_details"]["quality_gate"] is True
    agent_step = next(
        event for event in events
        if event[:3] == ("step", rj.STEP_AGENT, "passed")
    )
    assert agent_step[3] == (
        "AI 解答未归档：产物不满足下载安全要求" if archive_fails else ""
    )
    assert (audit / "problem" / "readme.md").read_text() == "original"


def test_run_reverse_judge_gate_rejection_never_resolves_or_starts_answer_agent(
        monkeypatch, tmp_path):
    events = []
    _patch_reverse_pipeline_base(monkeypatch, tmp_path, events)
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_run_judge_script",
        lambda *_args: events.append(("solution",)) or _successful_run({
            "max_score": 100.0, "score": 100.0, "test_points": {},
        }),
    )
    monkeypatch.setattr(rj, "_restore_runtime_package", lambda *_args: None)
    monkeypatch.setattr(
        rj, "_run_quality_gate_phase",
        lambda *_args: events.append(("gate-reject",)) or {
            "success": False, "message": "quality rejected",
        },
    )
    monkeypatch.setattr(
        rj, "_resolve_selected_endpoint",
        lambda *_args, **_kwargs: pytest.fail("门禁拒绝后不得解析用户作答端点"),
    )
    monkeypatch.setattr(
        rj, "_run_agent", lambda *_args: pytest.fail("门禁拒绝后不得启动作答 Agent"),
    )

    result = rj._run_reverse_judge(
        SimpleNamespace(), object(), 20, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, endpoint_id=44,
    )

    assert result == {"success": False, "message": "quality rejected"}
    stage_events = [
        event for event in events
        if event[0] in {"solution", "gate-reject", "resolve", "agent"}
    ]
    assert stage_events == [("solution",), ("gate-reject",)]


def test_run_reverse_judge_busy_retry_keeps_passed_solution_and_does_not_rerun_it(
        monkeypatch, tmp_path):
    events = []
    _patch_reverse_pipeline_base(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        rj, "_step_status",
        lambda _sid, step: "passed" if step == rj.STEP_SOLUTION else "pending",
    )
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_run_judge_script",
        lambda *_args: pytest.fail("重排队恢复时不得重跑已通过的标准答案自检"),
    )
    monkeypatch.setattr(rj, "_restore_runtime_package", lambda *_args: events.append(("restore",)))
    monkeypatch.setattr(
        rj, "_run_quality_gate_phase",
        lambda *_args: events.append(("gate-busy",)) or {
            "success": False, "message": "queued",
        },
    )

    result = rj._run_reverse_judge(
        SimpleNamespace(), object(), 20, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, endpoint_id=44,
    )

    assert result == {"success": False, "message": "queued"}
    assert events[-2:] == [("restore",), ("gate-busy",)]
    assert not any(event[:2] == ("step", rj.STEP_SOLUTION) for event in events)


@pytest.mark.parametrize("current_sequence,forbidden_event", [
    ([False], "solution"),
    ([True, False], "gate"),
    ([True, True, False], "resolve"),
    ([True, True, True, False], "agent"),
    ([True, True, True, True, False], "ai-judge"),
    ([True, True, True, True, True, False], "ai-judge"),
    ([True, True, True, True, True, True, False], "final-result"),
])
def test_run_reverse_judge_old_attempt_stops_at_every_stage_boundary(
        monkeypatch, tmp_path, current_sequence, forbidden_event):
    events = []
    _patch_reverse_pipeline_base(monkeypatch, tmp_path, events)
    endpoint = _quality_endpoint(9)
    checks = iter(current_sequence)
    monkeypatch.setattr(rj, "_attempt_still_current", lambda *_args: next(checks))

    def judge(_sid, _root, answer_dir, _timeout):
        events.append("ai-judge" if answer_dir == "template" else "solution")
        score = 25.0 if answer_dir == "template" else 100.0
        return _successful_run({"max_score": 100.0, "score": score, "test_points": {}})

    monkeypatch.setattr(rj, "_run_judge_script", judge)
    monkeypatch.setattr(rj, "_restore_runtime_package", lambda *_args: events.append("restore"))
    monkeypatch.setattr(
        rj, "_run_quality_gate_phase",
        lambda *_args: events.append("gate") or {"success": True, "message": "pass"},
    )
    monkeypatch.setattr(
        rj, "_resolve_selected_endpoint",
        lambda *_args, **_kwargs: events.append("resolve") or (endpoint, ""),
    )
    monkeypatch.setattr(rj, "_acquire_endpoint_slot", lambda *_args: (endpoint, "slot", "token"))
    monkeypatch.setattr(rj, "_fake_reverse_judge_enabled", lambda: True)
    monkeypatch.setattr(
        rj, "_run_agent",
        lambda *_args: events.append("agent") or {
            "ok": True, "stdout": "", "stderr": "", "error": "", "trace_dir": None,
        },
    )
    monkeypatch.setattr(rj, "_release_slot", lambda *_args: events.append("release"))
    monkeypatch.setattr(
        rj, "update_submission_result_for_attempt",
        lambda *_args, **_kwargs: events.append("final-result"),
    )

    result = rj._run_reverse_judge(
        SimpleNamespace(), object(), 20, "a1", {
            "id": 7,
            "reverse_quality_gate_enabled": True,
            "reverse_quality_gate_prompt": "rule",
        }, endpoint_id=44,
    )

    assert result == {"success": True, "message": "旧评测 attempt，跳过"}
    assert forbidden_event not in events
    if "agent" in events:
        assert "release" in events


class _ReverseFakeCelery:
    def task(self, **_kwargs):
        def decorator(fn):
            return fn
        return decorator


class _ReverseTaskSelf:
    request = SimpleNamespace(id="req-quality")


def test_registered_reverse_task_lock_ttl_includes_quality_gate_and_forwards_only_answer_endpoint(
        monkeypatch):
    client = MagicMock()
    client.set.return_value = True
    client.get.return_value = "req-quality"
    submission = {
        "id": 41,
        "competition_id": 7,
        "judge_attempt_id": "attempt-1",
        "status": "Queued",
    }
    competition = {
        "id": 7,
        "scoring_script_timeout_seconds": 11,
        "agent_judge_timeout_seconds": 22,
        "reverse_judge_finalize_timeout_seconds": 33,
        "reverse_quality_gate_enabled": True,
        "reverse_quality_gate_prompt": "rule",
    }
    run_calls = []
    cleaned = []
    monkeypatch.setattr(rj, "_ensure_judge_redis", lambda: client)
    monkeypatch.setattr(rj, "get_ranking_submission", lambda _sid: dict(submission))
    monkeypatch.setattr(rj, "get_competition", lambda _cid: dict(competition))
    monkeypatch.setattr(rj, "set_agent_judge_task_id", lambda *_args: None)
    monkeypatch.setattr(
        rj, "_run_reverse_judge",
        lambda *args, **kwargs: run_calls.append((args, kwargs)) or {"success": True},
    )
    monkeypatch.setattr(
        rj, "_cleanup_attempt_workspace",
        lambda sid, attempt: cleaned.append((sid, attempt)),
    )

    task = rj.register_ranking_reverse_judge_task(_ReverseFakeCelery())
    result = task(_ReverseTaskSelf(), 41, "attempt-1", endpoint_id=9)

    assert result == {"success": True}
    assert run_calls[0][0][2:6] == (41, "attempt-1", competition)
    assert run_calls[0][1] == {"endpoint_id": 9}
    lock_call = client.set.call_args
    assert lock_call.args[:2] == (
        "ranking:reverse_judge:lock:41:attempt-1", "req-quality",
    )
    assert lock_call.kwargs["nx"] is True
    assert lock_call.kwargs["ex"] == (
        11 * 2 + 22 + 33 + rj.REVERSE_QUALITY_GATE_TIMEOUT
        + rj.JUDGE_SLOT_TTL_BUFFER * 2
    )
    client.delete.assert_called_once_with("ranking:reverse_judge:lock:41:attempt-1")
    assert cleaned == [(41, "attempt-1")]
