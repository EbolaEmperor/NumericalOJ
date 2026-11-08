# -*- coding: utf-8 -*-
"""反向评测纯逻辑单测：Harbor 题目包识别、持久编排与反向得分公式。"""

import json
import subprocess
import zipfile

import pytest

import backend.oj_modules.ranking.reverse_judge.db as reverse_db
import backend.oj_modules.ranking.reverse_judge.traces as rjdb
import backend.oj_modules.tasks.ranking.reverse_judge as rj
from backend.oj_modules.ranking.reverse_judge import trace_sync


def _without_trace_identity(messages):
    ignored = {'offset', 'event_index', 'source', 'phase'}
    return [{key: value for key, value in message.items() if key not in ignored}
            for message in messages]


def _make_package(root):
    for name in ('environment', 'tests', 'solution'):
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / 'task.toml').write_text('artifacts = ["/app"]\n', encoding='utf-8')
    (root / 'instruction.md').write_text('公开题面', encoding='utf-8')
    (root / 'environment/Dockerfile').write_text('FROM python:3.12-slim\nWORKDIR /app\n', encoding='utf-8')
    (root / 'solution/solve.sh').write_text('#!/bin/sh\nprintf 42 > /app/answer.txt\n', encoding='utf-8')
    (root / 'tests/test.sh').write_text('#!/bin/sh\necho 1 > /logs/verifier/reward.txt\n', encoding='utf-8')


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


def test_legacy_package_shape_is_rejected(tmp_path):
    for name in ('problem', 'template', 'solution'):
        (tmp_path / name).mkdir()
    (tmp_path / 'judge.sh').write_text('#!/bin/sh\n')
    assert not rj._has_reverse_package_shape(tmp_path)


@pytest.mark.parametrize('running', [True, None])
def test_cleanup_retains_harbor_identity_until_runtime_is_confirmed_stopped(monkeypatch, tmp_path, running):
    monkeypatch.setattr(rj, 'REVERSE_WORKSPACE_ROOT', str(tmp_path))
    root = tmp_path / '7' / 'attempt'
    trial = root / 'agent_trial'
    trial.mkdir(parents=True)
    (trial / '.run-name').write_text('official-trial')
    monkeypatch.setattr(rj, 'harbor_trial_running', lambda _: running)
    assert rj._cleanup_attempt_workspace(7, 'attempt') is False
    assert (trial / '.run-name').exists()
    monkeypatch.setattr(rj, 'harbor_trial_running', lambda _: False)
    assert rj._cleanup_attempt_workspace(7, 'attempt') is True
    assert not root.exists()


def test_cleanup_preserves_original_logs_when_native_session_copy_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(rj, 'REVERSE_WORKSPACE_ROOT', str(tmp_path))
    trial = tmp_path / '7/attempt/agent_trial'
    trial.mkdir(parents=True)
    (trial / '.preservation-failed').touch()
    (trial / 'native-session.jsonl').write_text('待恢复的原生会话')
    assert rj._cleanup_attempt_workspace(7, 'attempt') is False
    assert (trial / 'native-session.jsonl').exists()


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
        "model": "generic-model",
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
            "base_url": "https://model-a.example/anthropic",
            "api_key": "secret-a",
            "model": "model-a",
            "concurrency_limit": 4,
            "status": "enabled",
        },
        {
            "id": 17,
            "harness": "pi",
            "protocol": "anthropic",
            "base_url": "https://model-b.example/anthropic",
            "api_key": "secret-b",
            "model": "model-b",
            "thinking_format": "thinking_type",
            "concurrency_limit": 2,
            "status": "enabled",
        },
    ])

    endpoint, message = rj._resolve_selected_endpoint(9, "17")

    assert message == ""
    assert endpoint == {
        "id": 17,
        "harness": "pi",
        "protocol": "anthropic",
        "base_url": "https://model-b.example/anthropic",
        "api_key": "secret-b",
        "model": "model-b",
        "thinking_format": "thinking_type",
        "concurrency_limit": 2,
        "context_window_tokens": 1_000_000,
        "max_output_tokens": 384_000,
        "thinking_compatibility": True,
    }


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


def test_shared_claude_sync_copies_and_combines_container_sessions(
        monkeypatch, tmp_path):
    remote_paths = [
        "/workspace/sessions/first.jsonl",
        "/workspace/sessions/second.jsonl",
    ]
    payloads = {
        remote_paths[0]: (
            b'{"type":"assistant","uuid":"first","token":"top-secret"}\n'
        ),
        remote_paths[1]: b'{"type":"assistant","uuid":"second"}\n',
    }

    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        manifest = json.dumps(
            [
                {"name": path.rsplit("/", 1)[-1], "size": len(payloads[path])}
                for path in remote_paths
            ],
            separators=(",", ":"),
        ).encode("utf-8")
        output = kwargs["stdout"]
        output.write(len(manifest).to_bytes(4, "big"))
        output.write(manifest)
        for path in remote_paths:
            output.write(payloads[path])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_claude_project_jsonl(
        "container",
        str(tmp_path),
        container_project_dir="/workspace/sessions",
        secrets=("top-secret",),
    ) is True
    project = tmp_path / ".claude/projects/-workspace"
    first = (project / "first.jsonl").read_bytes()
    assert b"top-secret" not in first
    assert b"[REDACTED]" in first
    assert (project / "second.jsonl").read_bytes() == payloads[remote_paths[1]]
    assert (project / "reverse_solve_combined.jsonl").read_bytes() == (
        first + payloads[remote_paths[1]]
    )
    assert len(calls) == 1
    command, options = calls[0]
    assert command[:5] == ["docker", "exec", "container", "python3", "-c"]
    assert "capture_output" not in options
    assert "follow_symlinks=False" in command[-1]
    assert "O_NOFOLLOW" in command[-1]


@pytest.mark.parametrize(
    ("entries", "max_files", "max_file_bytes", "max_total_bytes"),
    [
        (
            [{"name": "one.jsonl", "size": 1}, {"name": "two.jsonl", "size": 1}],
            1,
            8,
            8,
        ),
        ([{"name": "large.jsonl", "size": 9}], 4, 8, 16),
        (
            [{"name": "one.jsonl", "size": 6}, {"name": "two.jsonl", "size": 6}],
            4,
            8,
            10,
        ),
    ],
)
def test_shared_claude_sync_rejects_manifest_resource_limit_violations(
    monkeypatch,
    tmp_path,
    entries,
    max_files,
    max_file_bytes,
    max_total_bytes,
):
    monkeypatch.setattr(trace_sync, "CLAUDE_TRACE_MAX_FILES", max_files)
    monkeypatch.setattr(
        trace_sync,
        "CLAUDE_TRACE_MAX_FILE_BYTES",
        max_file_bytes,
    )
    monkeypatch.setattr(
        trace_sync,
        "CLAUDE_TRACE_MAX_TOTAL_BYTES",
        max_total_bytes,
    )

    def fake_run(args, **kwargs):
        manifest = json.dumps(entries, separators=(",", ":")).encode("utf-8")
        kwargs["stdout"].write(len(manifest).to_bytes(4, "big"))
        kwargs["stdout"].write(manifest)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_claude_project_jsonl(
        "container",
        str(tmp_path),
    ) is False
    assert not (tmp_path / ".claude").exists()


def test_shared_trace_sync_caps_redacted_output_and_cleans_temporaries(
    monkeypatch,
    tmp_path,
):
    payload = b"x\n"
    manifest = json.dumps(
        [{"name": "session.jsonl", "size": len(payload)}],
        separators=(",", ":"),
    ).encode("utf-8")

    def fake_run(args, **kwargs):
        kwargs["stdout"].write(len(manifest).to_bytes(4, "big"))
        kwargs["stdout"].write(manifest)
        kwargs["stdout"].write(payload)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)
    monkeypatch.setattr(
        trace_sync,
        "CLAUDE_TRACE_MAX_PUBLISHED_FILE_BYTES",
        4,
    )

    assert trace_sync.sync_claude_project_jsonl(
        "container",
        str(tmp_path),
        secrets=("x",),
    ) is False
    project = tmp_path / ".claude/projects/-workspace"
    assert project.is_dir()
    assert list(project.iterdir()) == []

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

    monkeypatch.setattr(reverse_db, "get_ranking_submission", lambda _sid: {"status": "Accepted"})
    monkeypatch.setattr(reverse_db, "get_db_connection", lambda: Connection())

    steps = reverse_db.list_reverse_judge_steps(17)

    assert [step["step_key"] for step in steps] == [
        "build_environment", "solution_check", "quality_gate", "agent_answer", "ai_judge",
    ]
    assert [step["step_order"] for step in steps] == [0, 1, 2, 3, 4]
    assert steps[0]["status"] == steps[2]["status"] == "skipped"


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


def test_collect_pi_session_trace_renders_completed_semantic_events_only(tmp_path):
    trace = tmp_path / "trace"
    sessions = trace / ".pi" / "agent" / "sessions"
    sessions.mkdir(parents=True)
    image_payload = "base64-image-must-not-enter-snapshot"
    opaque_payload = "opaque-non-text-must-not-enter-snapshot"
    events = [
        {
            "type": "session",
            "version": 3,
            "id": "session-1",
            "timestamp": "2026-07-31T08:00:00.000Z",
            "cwd": "/workspace",
        },
        {
            # Pi JSON mode 的流式事件不是原生 session entry，必须忽略。
            "type": "message_update",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "不应渲染的 token delta"}],
            },
        },
        {
            "type": "message",
            "id": "assistant-1",
            "parentId": None,
            "timestamp": "2026-07-31T08:00:01.000Z",
            "message": {
                "role": "assistant",
                "model": "qwen3-coder",
                "content": [
                    {"type": "text", "text": "先检查 **输入**。"},
                    {"type": "thinking", "thinking": "需要覆盖空输入。"},
                    {
                        "type": "toolCall",
                        "id": "call-1",
                        "name": "bash",
                        "arguments": {"command": "python3 solve.py"},
                    },
                ],
                "stopReason": "toolUse",
            },
        },
        {
            "type": "message",
            "id": "tool-result-1",
            "parentId": "assistant-1",
            "timestamp": "2026-07-31T08:00:02.000Z",
            "message": {
                "role": "toolResult",
                "toolCallId": "call-1",
                "toolName": "bash",
                "content": [
                    {"type": "text", "text": "case 1: passed"},
                    {"type": "image", "data": image_payload, "mimeType": "image/png"},
                    {"type": "custom", "payload": opaque_payload},
                ],
                "isError": False,
            },
        },
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "不应重复渲染"}],
            },
        },
    ]
    path = sessions / "reverse_solve_combined.jsonl"
    path.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))
    raw_files = rjdb._collect_trace_files(str(trace))

    projected_messages = _without_trace_identity(messages)
    rendered_html = [
        message.pop("html")
        for message in projected_messages
        if message["kind"] in {"assistant", "thinking"}
    ]
    assert projected_messages == [
        {
            "kind": "assistant",
            "title": "AI 回复",
            "text": "先检查 **输入**。",
            "meta": "qwen3-coder",
            "line": 3,
        },
        {
            "kind": "thinking",
            "title": "思考片段",
            "text": "需要覆盖空输入。",
            "meta": "qwen3-coder",
            "line": 3,
        },
        {
            "kind": "tool",
            "title": "运行命令",
            "text": "命令：\npython3 solve.py",
            "meta": "Bash",
            "format": "text",
            "line": 3,
        },
        {
            "kind": "tool_result",
            "title": "工具结果",
            "text": "case 1: passed\n\n（已省略图片或非文本内容）",
            "meta": "bash",
            "format": "text",
            "is_error": False,
            "line": 4,
        },
    ]
    assert len(rendered_html) == 2
    assert all("<script" not in html.lower() for html in rendered_html)
    assert [(message["source"], message["event_index"]) for message in messages] == [
        ("pi", 0), ("pi", 1), ("pi", 2), ("pi", 0),
    ]
    assert len({message["offset"] for message in messages[:3]}) == 1
    assert messages[3]["offset"] > messages[2]["offset"]
    projected = json.dumps(messages, ensure_ascii=False)
    assert image_payload not in projected
    assert opaque_payload not in projected
    assert "token delta" not in projected
    assert "不应重复渲染" not in projected

    # Pi 原始 JSONL 保持原样落盘，但不得进入 snapshot / SSE 的 raw trace 投影。
    assert raw_files == []
    raw_text = path.read_text(encoding="utf-8")
    assert image_payload in raw_text
    assert opaque_payload in raw_text


def test_collect_pi_trace_projects_terminal_model_error(tmp_path):
    trace = tmp_path / "trace"
    sessions = trace / ".pi" / "agent" / "sessions"
    sessions.mkdir(parents=True)
    events = [
        {
            "type": "session",
            "version": 3,
            "id": "session-error",
            "cwd": "/workspace",
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "provider": "agent-judge",
                "model": "doubao-seed-evolving",
                "content": [],
                "stopReason": "error",
                "errorMessage": (
                    "400: invalid messages.role developer; "
                    "supported roles are system, assistant, user and tool"
                ),
            },
        },
    ]
    (sessions / "reverse_solve_combined.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert _without_trace_identity(messages) == [{
        "kind": "tool_result",
        "title": "模型调用失败",
        "text": (
            "400: invalid messages.role developer; "
            "supported roles are system, assistant, user and tool"
        ),
        "meta": "agent-judge / doubao-seed-evolving",
        "format": "text",
        "is_error": True,
        "line": 2,
    }]
    assert messages[0]["source"] == "pi"


def test_collect_pi_trace_projects_aborted_model_call_without_error_text(tmp_path):
    trace = tmp_path / "trace"
    sessions = trace / ".pi" / "agent" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "reverse_solve_combined.jsonl").write_text(
        json.dumps({
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [],
                "stopReason": "aborted",
            },
        }) + "\n",
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert len(messages) == 1
    assert messages[0]["title"] == "模型调用失败"
    assert messages[0]["text"] == "模型调用以 stopReason=aborted 结束"
    assert messages[0]["is_error"] is True


def test_collect_pi_trace_discovers_native_nested_session_and_bounds_tool_results(
        tmp_path):
    trace = tmp_path / "trace"
    session_dir = trace / ".pi" / "agent" / "sessions" / "--workspace--"
    session_dir.mkdir(parents=True)
    long_text = "x" * 2000
    events = [
        {
            "type": "session",
            "version": 3,
            "id": "session-native",
            "timestamp": "2026-07-31T08:00:00.000Z",
            "cwd": "/workspace",
        },
        {
            "type": "message",
            "message": {
                "role": "toolResult",
                # 缺少 toolName/toolCallId 仍应安全降级，不得丢掉可见文本。
                "content": [
                    {"type": "text", "text": long_text},
                    {"type": "image", "data": "do-not-project"},
                ],
                "isError": True,
            },
        },
        {
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [{"type": "toolCall"}],
            },
        },
    ]
    path = session_dir / "2026-07-31T08-00-00_session-native.jsonl"
    path.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )
    # 同目录的普通 JSONL 不能抢占原生 session。
    (session_dir / "newer-no-session-header.jsonl").write_text(
        json.dumps({"type": "message", "message": {"role": "assistant"}}),
        encoding="utf-8",
    )

    messages = rjdb._collect_trace_messages(str(trace))

    assert len(messages) == 2
    result = messages[0]
    assert result["kind"] == "tool_result"
    assert result["title"] == "工具执行失败"
    assert result["is_error"] is True
    assert len(result["text"]) <= 1200
    assert result["text"].endswith("（已省略图片或非文本内容）")
    assert "do-not-project" not in json.dumps(messages, ensure_ascii=False)
    assert messages[1]["kind"] == "tool"
    assert messages[1]["title"] == "调用 工具"
    assert all(message["source"] == "pi" for message in messages)


def test_collect_pi_trace_keeps_existing_tail_and_message_count_limits(tmp_path):
    trace = tmp_path / "trace"
    sessions = trace / ".pi" / "agent" / "sessions"
    sessions.mkdir(parents=True)
    events = [{
        "type": "session",
        "version": 3,
        "id": "bounded-session",
        "cwd": "/workspace",
    }]
    events.extend({
        "type": "message",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": f"message-{index}"}],
        },
    } for index in range(260))
    path = sessions / "reverse_solve_combined.jsonl"
    path.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    messages = rjdb._collect_pi_trace_messages(str(path))

    assert len(messages) == rjdb._TRACE_MAX_MESSAGES == 240
    assert messages[0]["text"] == "message-20"
    assert messages[-1]["text"] == "message-259"
    assert rjdb._TRACE_JSONL_PARSE_MAX_BYTES == 2 * 1024 * 1024


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


def test_safe_attempt_component_blocks_path_traversal_and_limits_length():
    assert rj._safe_attempt_component("../../attempt_A-1") == "attempt_A-1"
    assert rj._safe_attempt_component(None) == "legacy"
    assert rj._safe_attempt_component("../..") == "legacy"
    assert rj._safe_attempt_component("a" * 100) == "a" * 80


@pytest.mark.parametrize("passed", [True, False])
def test_parse_quality_gate_result_reads_boolean_and_reason_from_json_file(passed):
    result = rj._parse_quality_gate_result(json.dumps({
        "passed": passed, "reason": "  已按审核标准检查题目和标准答案。\n  ",
    }, ensure_ascii=False))

    assert result == {"passed": passed, "reason": "已按审核标准检查题目和标准答案。"}


def test_parse_quality_gate_result_preserves_full_reason():
    reason = '逐项依据包含 }、{、"quoted" 和路径说明。\n' * 500
    result = rj._parse_quality_gate_result(json.dumps({"passed": False, "reason": reason}))
    assert result == {"passed": False, "reason": reason.strip()}


def test_parse_quality_gate_result_uses_legacy_summary_only_when_reason_is_absent():
    result = rj._parse_quality_gate_result(json.dumps({
        "passed": True, "summary": "  旧任务审核说明  ",
        "violations": {"旧扩展字段": "不再解析或改变 passed"},
    }))
    assert result == {"passed": True, "reason": "旧任务审核说明"}
    result = rj._parse_quality_gate_result(json.dumps({
        "passed": False, "reason": "新格式理由", "summary": "旧格式摘要",
    }))
    assert result == {"passed": False, "reason": "新格式理由"}


@pytest.mark.parametrize("raw", [
    "not-json",
    '审核说明：\n{"passed":true,"reason":"ok"}',
    '```json\n{"passed":true,"reason":"ok"}\n```',
    '{"passed":true,"reason":"ok"} after',
    "[]",
    '{"passed":1,"reason":"ok"}',
    '{"passed":"true","reason":"ok"}',
    '{"passed":null,"reason":""}',
    '{"passed":true,"reason":" "}',
    '{"passed":false,"reason":42}',
    '{"passed":true}',
    '{"passed":true,"summary":" "}',
    '{"passed":true,"reason":null,"summary":"不能回退"}',
    '{"passed":true,"reason":"","summary":"不能回退"}',
])
def test_parse_quality_gate_result_rejects_malformed_schema(raw):
    with pytest.raises(ValueError):
        rj._parse_quality_gate_result(raw)


def test_prepare_workspace_freezes_original_harbor_task(monkeypatch, tmp_path):
    source = tmp_path / 'source' / 'task'
    _make_package(source)
    upload = tmp_path / 'submission.zip'
    with zipfile.ZipFile(upload, 'w') as zf:
        for path in source.rglob('*'):
            if path.is_file():
                zf.write(path, 'task/' + path.relative_to(source).as_posix())
    workspace_root = tmp_path / 'workspaces'
    monkeypatch.setattr(rj, 'REVERSE_WORKSPACE_ROOT', str(workspace_root))
    ws, package_root, audit_root = rj._prepare_workspace(
        {'id': 9, 'code_path': str(upload)}, '../../attempt-1',
    )
    assert ws == str((workspace_root / '9' / 'attempt-1').resolve())
    package_instruction = __import__('pathlib').Path(package_root) / 'instruction.md'
    audit_instruction = __import__('pathlib').Path(audit_root) / 'instruction.md'
    package_instruction.write_text('解压副本变化')
    assert audit_instruction.read_text() == '公开题面'
    assert rj._has_reverse_package_shape(audit_root)


def test_prepare_workspace_rejects_missing_upload_and_invalid_shape(monkeypatch, tmp_path):
    monkeypatch.setattr(rj, "REVERSE_WORKSPACE_ROOT", str(tmp_path / "ws"))
    with pytest.raises(RuntimeError, match="提交文件不存在"):
        rj._prepare_workspace({"id": 1, "code_path": str(tmp_path / "missing.zip")})

    invalid = tmp_path / "invalid.zip"
    with zipfile.ZipFile(invalid, "w") as zf:
        zf.writestr("problem/readme.md", "missing other required entries")
    with pytest.raises(RuntimeError, match="必须使用 Harbor 格式"):
        rj._prepare_workspace({"id": 2, "code_path": str(invalid)}, "a")


def test_quality_endpoint_payloads_uses_independent_enabled_pool_and_exclusions(monkeypatch):
    calls = []
    endpoints = [
        _quality_endpoint(1, concurrency_limit=0),
        _quality_endpoint(2, harness=rj.HARNESS_PI, concurrency_limit=3),
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
        "protocol": None,
        "base_url": "https://gate-1.example/v1",
        "api_key": "secret-1",
        "model": "model-1",
        "thinking_format": None,
        "concurrency_limit": 1,
        "context_window_tokens": 1_000_000,
        "max_output_tokens": 384_000,
        "thinking_compatibility": True,
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

    assert result == {"success": False, "message": "AI 服务繁忙。"}
    assert updates == [((5, "a1", rj.STEP_QUALITY_GATE), {
        "status": "error", "error_message": "gate busy",
    })]
    assert final_errors == [(5, "a1", "gate busy")]


@pytest.fixture
def unified_reverse(monkeypatch, tmp_path):
    from types import SimpleNamespace

    submission = {'id': 7, 'competition_id': 3, 'judge_attempt_id': 'attempt',
                  'username': 'alice', 'agent_endpoint_id': 11, 'status': 'Judging'}
    competition = {'id': 3, 'reverse_quality_gate_enabled': True,
                   'reverse_quality_gate_prompt': '题意和答案必须一致'}
    rows = {key: {'step_key': key, 'status': 'pending'} for key in reverse_db.STEP_KEYS}
    turns, dispatches, releases, schedules, scores = {}, [], [], [], []
    session_messages = {}
    endpoint = {'id': 11, 'harness': 'pi', 'concurrency_limit': 1,
                'api_key': 'server-key', 'base_url': 'https://llm.example', 'model': 'test'}
    root = tmp_path / 'attempt'
    audit = root / 'quality_gate_source'
    _make_package(audit)
    (audit / 'instruction.md').write_text('公开题面')
    (audit / 'solution' / 'solve.sh').write_text('标准答案私密内容')
    (audit / 'hidden.txt').write_text('私有评测附件')

    def update(_sid, _attempt, key, **values):
        rows[key].update(values)
        return 1

    def submit(**kwargs):
        dispatches.append(kwargs)
        turns.setdefault(kwargs['session_id'], []).append(
            {'task_id': kwargs['task_id'], 'status': 'Pending', 'conclusion': ''})
        return {'session_id': kwargs['session_id'], 'current_task_id': kwargs['task_id']}

    def finish_submission(_sid, _attempt, score, status, **kwargs):
        submission['status'] = status
        scores.append(score)
        return 1

    task = SimpleNamespace(app=None, apply_async=lambda **kwargs: schedules.append(kwargs))
    monkeypatch.setattr(rj, 'get_ranking_submission', lambda _sid: submission)
    monkeypatch.setattr(rj, 'list_reverse_judge_steps', lambda _sid: list(rows.values()))
    monkeypatch.setattr(rj, 'update_reverse_judge_step_for_attempt', update)
    monkeypatch.setattr(rj, 'update_submission_result_for_attempt', finish_submission)
    monkeypatch.setattr(rj, 'set_submission_status_for_attempt', lambda *args: 1)
    monkeypatch.setattr(rj, 'ensure_reverse_judge_steps_for_attempt', lambda *args: 1)
    monkeypatch.setattr(rj, '_publish_snapshot', lambda _sid: None)
    monkeypatch.setattr(rj, 'get_agent_session_turns', lambda sid: turns.get(sid, []))
    monkeypatch.setattr(rj, 'get_agent_session', lambda sid: {
        'current_task_id': turns[sid][-1]['task_id'], 'message': session_messages.get(sid, '')})
    monkeypatch.setattr(rj, 'submit_judge_turn', submit)
    monkeypatch.setattr(rj, '_quality_endpoint_payloads', lambda *args, **kwargs: [endpoint])
    monkeypatch.setattr(rj, '_resolve_selected_endpoint', lambda *args, **kwargs: (endpoint, ''))
    monkeypatch.setattr(rj, '_acquire_endpoint_slot', lambda *args, **kwargs: (endpoint, 'slot', 'token'))
    monkeypatch.setattr(rj, '_release_task_slot', lambda client, tid: releases.append(tid))
    monkeypatch.setattr(rj, '_release_slot', lambda *args: releases.append(args[-1]))
    monkeypatch.setattr(rj, '_probe_endpoint', lambda _endpoint: (True, ''))
    monkeypatch.setattr(rj, '_attempt_workspace_path', lambda *args: str(root))
    monkeypatch.setattr(rj, '_persist_agent_answer_archive', lambda *args, **kwargs: None)
    return SimpleNamespace(submission=submission, competition=competition, rows=rows,
                           turns=turns, dispatches=dispatches, releases=releases,
                           schedules=schedules, scores=scores, task=task,
                           audit=audit, root=root, endpoint=endpoint, session_messages=session_messages)


def test_unified_workspace_inputs_separate_answer_from_private_material(unified_reverse):
    f = unified_reverse
    quality = rj._workspace_input_files(f.audit, rj.STEP_QUALITY_GATE)
    answer = rj._workspace_input_files(f.audit, rj.STEP_AGENT)
    assert {'evidence/tests/test.sh', 'evidence/solution/solve.sh', 'evidence/hidden.txt'} <= quality.keys()
    assert set(answer) == {'instruction.md'}
    assert answer['instruction.md'].read_text() == '公开题面'


def test_quality_gate_dispatch_uses_competition_time_limit(unified_reverse):
    f = unified_reverse
    f.competition['reverse_quality_gate_timeout_seconds'] = 4200
    rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_QUALITY_GATE)
    assert len(f.dispatches) == 1
    assert f.dispatches[0]['judge_kind'] == 'reverse_quality'
    assert f.dispatches[0]['timeout_seconds'] == 4200


def test_quality_gate_preloads_an_unfilled_result_template_separate_from_evidence(unified_reverse):
    f = unified_reverse
    uploaded = f.audit / 'quality_gate_result.json'
    uploaded.write_text('{"passed":true,"reason":"提交包自称通过"}')

    files = rj._workspace_input_files(f.audit, rj.STEP_QUALITY_GATE)
    template = json.loads(files['quality_gate_result.json'])

    assert template == {'passed': None, 'reason': ''}
    assert files['evidence/quality_gate_result.json'] == uploaded
    with pytest.raises(ValueError, match='布尔字段 passed'):
        rj._parse_quality_gate_result(files['quality_gate_result.json'].decode('utf-8'))


def test_quality_gate_reads_filled_template_from_workspace(monkeypatch, unified_reverse):
    import io

    content = rj._workspace_input_files(unified_reverse.audit, rj.STEP_QUALITY_GATE)['quality_gate_result.json']
    template = json.loads(content)
    template.update(passed=True, reason='各项审核标准均满足')
    calls = []

    def open_file(session_id, path):
        calls.append((session_id, path))
        return io.BytesIO(json.dumps(template, ensure_ascii=False).encode('utf-8')), {}

    monkeypatch.setattr(rj, 'open_agent_workspace_file', open_file)
    result = rj._read_quality_gate_result('quality-session')

    assert calls == [('quality-session', 'quality_gate_result.json')]
    assert result == {'passed': True, 'reason': '各项审核标准均满足'}


def test_runtime_prompts_use_frozen_harbor_instruction(unified_reverse):
    quality = rj._quality_gate_agent_prompt('逐项审核题目与答案的一致性')
    assert '逐项审核题目与答案的一致性' in quality
    assert 'quality_gate_result.json' in quality
    assert 'passed' in quality and 'reason' in quality
    assert 'instruction.md' in quality and 'tests/test.sh' in quality
    assert rj._reverse_prompt(unified_reverse.audit) == '公开题面'


def test_unified_reverse_workflow_runs_oracle_and_uses_official_trial_reward(monkeypatch, unified_reverse):
    from pathlib import Path
    from backend.oj_modules.agents import workspace

    f = unified_reverse
    oracle_calls = []
    monkeypatch.setattr(workspace, 'AGENT_WORKSPACE_ROOT', f.root / 'agent-workspaces')

    def oracle(task_path, trial_dir, timeout, **kwargs):
        oracle_calls.append((task_path, trial_dir, timeout))
        kwargs['build_event_callback']({'event': 'output', 'text': '#1 CACHED\n'})
        kwargs['build_event_callback']({'event': 'complete', 'text': '构建完成', 'cached': True})
        return {'ok': True, 'stdout': '', 'stderr': '', 'result': {
            'max_score': 1, 'score': 1, 'test_points': {},
        }}

    monkeypatch.setattr(rj, 'run_harbor_oracle', oracle)
    monkeypatch.setattr(rj, 'load_harbor_result', lambda trial_dir: {
        'ok': True, 'stdout': '', 'stderr': '', 'result': {
            'max_score': 1, 'score': .25, 'test_points': {},
        },
    })
    monkeypatch.setattr(rj, '_read_quality_gate_result', lambda sid: {'passed': True, 'reason': '通过'})

    def advance():
        return rj._run_reverse_judge(f.task, object(), 7, 'attempt', f.competition, 11)

    assert advance()['pending'] is True
    assert len(oracle_calls) == 1
    assert oracle_calls[0][0] == str(f.audit)
    assert f.rows[rj.STEP_BUILD]['status'] == 'passed'
    assert 'CACHED' in f.rows[rj.STEP_BUILD]['stdout']
    assert f.rows[rj.STEP_BUILD]['result_json']['cached'] is True
    quality = f.dispatches[0]
    assert quality['judge_kind'] == 'reverse_quality'
    assert quality['files']['evidence/instruction.md'].read_text() == '公开题面'
    assert advance()['pending'] is True
    assert len(f.dispatches) == 1 and not f.releases
    assert all(item['queue'] == 'celery' and item['countdown'] > 0 for item in f.schedules)

    f.turns[quality['session_id']][0]['status'] = 'Completed'
    assert advance()['pending'] is True
    answer = f.dispatches[1]
    assert answer['judge_kind'] == 'reverse_answer'
    assert answer['session_id'] != quality['session_id']
    assert answer['requested_by'] == 'alice'
    assert answer['project_skill'] is False
    assert answer['harbor_runtime']['task_path'] == str(f.audit.resolve())
    assert answer['harbor_runtime']['trial_dir'] == str(f.root / 'agent_trial')
    assert 'finalize_timeout_seconds' not in answer['harbor_runtime']
    assert f.releases == [quality['task_id']]
    assert len(oracle_calls) == 1
    workspace.initialize_agent_task_workspace(answer['session_id'], harness='pi', access_role='user')
    workspace.inject_agent_workspace_files(answer['session_id'], answer['files'])
    workspace.write_agent_workspace_file(answer['session_id'], 'harbor-artifacts/app/answer.txt', 'AI交付物')
    f.turns[answer['session_id']][0]['status'] = 'Completed'
    assert advance() == {'success': True, 'score': 75.0}
    assert (f.root / 'answer_artifacts/app/answer.txt').read_text() == 'AI交付物'
    assert f.scores == [75.0]
    assert f.releases == [quality['task_id'], answer['task_id']]
    assert len(oracle_calls) == 1


def test_quality_gate_rejection_never_dispatches_answer(monkeypatch, unified_reverse):
    f = unified_reverse
    f.rows[rj.STEP_SOLUTION]['status'] = 'passed'
    result = rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_QUALITY_GATE)
    assert result['pending']
    sent = f.dispatches[0]
    f.turns[sent['session_id']][0]['status'] = 'Completed'
    monkeypatch.setattr(rj, '_read_quality_gate_result', lambda sid: {
        'passed': False, 'reason': '私有审核标准被违反'})
    result = rj._run_reverse_judge(f.task, object(), 7, 'attempt', f.competition, 11)
    assert result['success'] is False
    assert len(f.dispatches) == 1
    assert '私有' not in result['message']
    assert f.rows[rj.STEP_QUALITY_GATE]['result_json']['reason'] == '私有审核标准被违反'
    assert f.rows[rj.STEP_AGENT]['status'] == 'pending'


@pytest.mark.parametrize('step_key', [rj.STEP_QUALITY_GATE, rj.STEP_AGENT])
def test_unhealthy_endpoint_is_paused_before_dispatch(monkeypatch, unified_reverse, step_key):
    f = unified_reverse
    probes, pauses = [], []

    def probe(endpoint):
        probes.append(endpoint['id'])
        return False, 'HTTP 503'

    monkeypatch.setattr(rj, '_probe_endpoint', probe)
    monkeypatch.setattr(rj, '_disable_unhealthy_endpoint',
                        lambda endpoint, reason: pauses.append((endpoint['id'], reason)))
    result = rj._advance_agent_phase(
        f.task, object(), 7, 'attempt', f.competition, str(f.audit), step_key, 11,
    )

    assert result['success'] is False
    assert probes == [11]
    assert pauses == [(11, 'HTTP 503')]
    assert f.releases == ['token']
    assert f.dispatches == []
    assert f.submission['status'] == 'Error'
    assert f.rows[step_key]['status'] == 'error'


def test_harbor_timeout_failure_does_not_restart_environment(unified_reverse):
    f = unified_reverse
    assert rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)['pending']
    first = f.dispatches[0]
    f.turns[first['session_id']][0].update(status='Failed', conclusion='Harbor 环境超时')
    result = rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)
    assert result['success'] is False
    assert len(f.dispatches) == 1
    assert f.releases == [first['task_id']]


def test_endpoint_pool_full_does_not_send_generic_task(monkeypatch, unified_reverse):
    f = unified_reverse
    monkeypatch.setattr(rj, '_acquire_endpoint_slot', lambda *args, **kwargs: (None, None, None))
    monkeypatch.setattr(rj, '_retry_queued_submission', lambda *args, **kwargs: {'success': False, 'message': '排队'})
    result = rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_QUALITY_GATE)
    assert result['success'] is False
    assert f.dispatches == []
    assert f.rows[rj.STEP_QUALITY_GATE]['status'] == 'pending'


def test_cleanup_failure_does_not_release_endpoint_slot(unified_reverse):
    f = unified_reverse
    rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)
    first = f.dispatches[0]
    f.turns[first['session_id']][0].update(status='CleanupFailed', conclusion='清理失败')
    result = rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)
    assert result['success'] is False and not f.releases and len(f.dispatches) == 1
    assert result['message'] == '评测未完成，请联系管理员处理。'
    assert '通用 Agent' not in result['message'] and '端点名额' not in result['message']
    assert f.rows[rj.STEP_AGENT]['status'] == 'error'


def test_quota_failure_does_not_finalize_even_when_conclusion_mentions_timeout(monkeypatch, unified_reverse):
    f = unified_reverse
    rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)
    first = f.dispatches[0]
    f.turns[first['session_id']][0].update(status='Failed', conclusion='本地样例超时，我准备继续调试')
    f.session_messages[first['session_id']] = '额度耗尽'
    result = rj._advance_agent_phase(f.task, object(), 7, 'attempt', f.competition, str(f.audit), rj.STEP_AGENT, 11)
    assert result['success'] is False
    assert len(f.dispatches) == 1
