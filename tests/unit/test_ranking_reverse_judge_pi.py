# -*- coding: utf-8 -*-
"""反向评测 Pi 作答节点的端点协议与共用轨迹同步。"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import backend.oj_modules.tasks.ranking.reverse_judge as rj
import backend.oj_modules.tasks.ranking.agent_judge as aj
from backend.oj_modules.ranking.reverse_judge import trace_sync


_SESSION_ID = "12345678-1234-1234-1234-123456789abc"
_MISSING_STOP_REASON = object()


def _pi_endpoint():
    return {
        "id": 7,
        "pool_kind": "primary",
        "harness": rj.HARNESS_PI,
        "protocol": "openai",
        "base_url": "https://pi.example/v1",
        "api_key": "real-pi-key",
        "model": "pi-model",
        "concurrency_limit": 1,
    }


def _append_pi_session_message(
        tmp_path, stop_reason=_MISSING_STOP_REASON, *,
        session_id=_SESSION_ID, content_text="phase finished"):
    """向宿主镜像目录写入一条最小 Pi 原生 assistant 消息。"""
    session_path = (
        tmp_path
        / "submission"
        / "reverse_agent_trace"
        / "attempt-1"
        / ".pi"
        / "agent"
        / "sessions"
        / "--workspace--"
        / f"native_{session_id}.jsonl"
    )
    session_path.parent.mkdir(parents=True, exist_ok=True)
    if not session_path.exists():
        session_path.write_text(
            json.dumps({
                "type": "session",
                "version": 3,
                "id": session_id,
                "cwd": "/workspace",
            }) + "\n",
            encoding="utf-8",
        )
    message = {
        "role": "assistant",
        "content": [{"type": "text", "text": content_text}],
    }
    if stop_reason is not _MISSING_STOP_REASON:
        message["stopReason"] = stop_reason
    with session_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "type": "message",
            "id": f"assistant-{session_path.stat().st_size}",
            "message": message,
        }) + "\n")
    return session_path


def _pi_trace_dir(tmp_path):
    return (
        tmp_path
        / "submission"
        / "reverse_agent_trace"
        / "attempt-1"
    )


def test_pi_hello_probe_uses_openai_chat_completions_and_bearer():
    request, error = aj._hello_probe_request(_pi_endpoint())

    assert error is None
    assert request.full_url == "https://pi.example/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer real-pi-key"
    body = json.loads(request.data.decode("utf-8"))
    assert body["model"] == "pi-model"
    assert body["max_tokens"] == 8
    assert len(body["messages"]) == 1
    assert body["messages"][0]["role"] == "user"
    assert isinstance(body["messages"][0]["content"], str)
    assert body["messages"][0]["content"]


def test_pi_anthropic_hello_probe_uses_messages_and_x_api_key():
    endpoint = {**_pi_endpoint(), "protocol": "anthropic"}
    request, error = aj._hello_probe_request(endpoint)

    assert error is None
    assert request.full_url == "https://pi.example/v1/messages"
    assert request.get_header("X-api-key") == "real-pi-key"
    assert request.get_header("Anthropic-version") == "2023-06-01"
    assert request.get_header("Authorization") is None
    body = json.loads(request.data.decode("utf-8"))
    assert body["model"] == "pi-model"
    assert body["max_tokens"] == 8
    assert len(body["messages"]) == 1
    assert body["messages"][0]["role"] == "user"
    assert isinstance(body["messages"][0]["content"], str)
    assert body["messages"][0]["content"]


def test_pi_test_worker_preserves_root_template_and_creates_root_deliverable(monkeypatch, tmp_path):
    from backend.oj_modules.agents import sessions, workspace
    from tests.e2e import loopback_worker

    monkeypatch.setattr(workspace, 'AGENT_WORKSPACE_ROOT', tmp_path / 'workspaces')
    monkeypatch.setattr(sessions, 'get_agent_session', lambda _: {'judge_kind': 'reverse_answer'})
    package = tmp_path / 'package'
    for name, content in {
        'problem/problem.md': '公开题面', 'template/main.py': 'print(42)',
        'solution/main.py': '私密标准答案', 'judge.sh': '私密评分程序',
    }.items():
        source = package / name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(content)
    sid = 'pi-reverse-root'
    root = workspace.initialize_agent_task_workspace(sid, harness='pi', access_role='user')
    workspace.inject_agent_workspace_files(sid, rj._workspace_input_files(package, rj.STEP_AGENT))
    native_ids, trace = [], []

    result = loopback_worker._run_reverse_agent(
        session_id=sid, task_kind='judge', harness='pi',
        native_session_callback=native_ids.append,
        trace_records_callback=lambda records, **kwargs: trace.extend(records),
    )

    assert result.returncode == 0 and native_ids == [result.native_session_id]
    assert (root / 'main.py').read_text() == 'print(42)'
    assert (root / 'agent-output.txt').read_text() == '本地测试 Agent 的根目录交付物。\n'
    assert (root / 'problem' / 'problem.md').read_text() == '公开题面'
    assert not any((root / name).exists() for name in ('template', 'solution', 'judge.sh'))
    assert trace[0]['event']['kind'] == 'assistant'


def test_sync_pi_agent_sessions_mirrors_native_tree_and_streams_combined_trace(
        monkeypatch, tmp_path):
    trace_dir = tmp_path / "trace"
    calls = []
    first_relative = f"--workspace--/one_{_SESSION_ID}.jsonl"
    second_relative = (
        "--workspace--/nested/"
        "two_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.jsonl"
    )
    payloads = {
        first_relative: b'{"type":"session","id":"first","token":"pi-secret"}\n',
        second_relative: b'{"type":"message","id":"second"}',
    }

    entries = [
        {
            "relative_path": first_relative,
            "mtime_ns": 1_000_000_000,
            "size": len(payloads[first_relative]),
        },
        {
            "relative_path": second_relative,
            "mtime_ns": 2_000_000_000,
            "size": len(payloads[second_relative]),
        },
    ]

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        _write_framed_trace_export(
            kwargs["stdout"],
            entries,
            [payloads[first_relative], payloads[second_relative]],
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_pi_agent_sessions(
        "pi-container",
        str(trace_dir),
        container_session_dir="/custom/pi/sessions",
        runtime_user="501:20",
        secrets=("pi-secret",),
    ) is True

    session_root = trace_dir / ".pi" / "agent" / "sessions"
    combined = session_root / "reverse_solve_combined.jsonl"
    assert combined.read_bytes() == (
        b'{"type":"session","id":"first","token":"[REDACTED]"}\n'
        b'{"type":"message","id":"second"}\n'
    )
    first = session_root / "--workspace--" / f"one_{_SESSION_ID}.jsonl"
    second = (
        session_root
        / "--workspace--/nested/two_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.jsonl"
    )
    assert first.stat().st_mtime_ns == 1_000_000_000
    assert second.stat().st_mtime_ns == 2_000_000_000
    assert b"pi-secret" not in first.read_bytes()
    assert second.read_bytes() == payloads[second_relative]
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[:7] == [
        "docker", "exec", "--user", "501:20", "pi-container", "python3", "-c",
    ]
    assert "/custom/pi/sessions" in args[-1]
    assert "follow_symlinks=False" in args[-1]
    assert "O_NOFOLLOW" in args[-1]
    assert "capture_output" not in kwargs
    assert kwargs["stderr"] == rj.subprocess.DEVNULL


def test_sync_pi_agent_sessions_omits_empty_runtime_user(monkeypatch, tmp_path):
    payload = b'{"type":"session"}\n'
    entries = [{
        "relative_path": "--workspace--/session.jsonl",
        "mtime_ns": 1,
        "size": len(payload),
    }]
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        _write_framed_trace_export(kwargs["stdout"], entries, [payload])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_pi_agent_sessions(
        "pi-container",
        str(tmp_path / "trace"),
        container_session_dir="/workspace/custom-pi",
        runtime_user="",
    ) is True
    assert calls[0][0][:3] == ["docker", "exec", "pi-container"]
    assert "--user" not in calls[0][0]
    assert "/workspace/custom-pi" in calls[0][0][-1]


@pytest.mark.parametrize(
    ("entries", "max_files", "max_file_bytes", "max_total_bytes"),
    [
        (
            [
                {"relative_path": "a.jsonl", "size": 1, "mtime_ns": 1},
                {"relative_path": "b.jsonl", "size": 1, "mtime_ns": 2},
            ],
            1,
            8,
            8,
        ),
        (
            [{"relative_path": "large.jsonl", "size": 9, "mtime_ns": 1}],
            4,
            8,
            16,
        ),
        (
            [
                {"relative_path": "a.jsonl", "size": 6, "mtime_ns": 1},
                {"relative_path": "b.jsonl", "size": 6, "mtime_ns": 2},
            ],
            4,
            8,
            10,
        ),
    ],
)
def test_sync_pi_agent_sessions_rejects_manifest_resource_limit_violations(
    monkeypatch,
    tmp_path,
    entries,
    max_files,
    max_file_bytes,
    max_total_bytes,
):
    monkeypatch.setattr(trace_sync, "PI_TRACE_MAX_FILES", max_files)
    monkeypatch.setattr(trace_sync, "PI_TRACE_MAX_FILE_BYTES", max_file_bytes)
    monkeypatch.setattr(trace_sync, "PI_TRACE_MAX_TOTAL_BYTES", max_total_bytes)

    def fake_run(args, **kwargs):
        _write_framed_trace_export(kwargs["stdout"], entries)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_pi_agent_sessions(
        "pi-container",
        str(tmp_path / "trace"),
    ) is False
    assert not (tmp_path / "trace/.pi").exists()


def test_sync_pi_agent_sessions_counts_both_published_copies(
    monkeypatch,
    tmp_path,
):
    payload = b"x\n"
    entries = [{
        "relative_path": "session.jsonl",
        "size": len(payload),
        "mtime_ns": 1,
    }]

    def fake_run(args, **kwargs):
        _write_framed_trace_export(kwargs["stdout"], entries, [payload])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)
    monkeypatch.setattr(trace_sync, "PI_TRACE_MAX_PUBLISHED_TOTAL_BYTES", 3)

    assert trace_sync.sync_pi_agent_sessions(
        "pi-container",
        str(tmp_path / "trace"),
    ) is False
    session_root = tmp_path / "trace/.pi/agent/sessions"
    assert list(session_root.rglob("*.jsonl")) == []


def test_sync_pi_agent_sessions_keeps_previous_snapshot_on_truncated_export(
    monkeypatch,
    tmp_path,
):
    session_root = tmp_path / "trace/.pi/agent/sessions"
    native = session_root / "--workspace--/session.jsonl"
    native.parent.mkdir(parents=True)
    combined = session_root / trace_sync.PI_COMBINED_TRACE_NAME
    native.write_bytes(b"old-native\n")
    combined.write_bytes(b"old-combined\n")
    payload = b"new"
    entries = [{
        "relative_path": "--workspace--/session.jsonl",
        "size": len(payload) + 1,
        "mtime_ns": 2,
    }]

    def fake_run(args, **kwargs):
        _write_framed_trace_export(kwargs["stdout"], entries, [payload])
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(trace_sync.subprocess, "run", fake_run)

    assert trace_sync.sync_pi_agent_sessions(
        "pi-container",
        str(tmp_path / "trace"),
    ) is False
    assert native.read_bytes() == b"old-native\n"
    assert combined.read_bytes() == b"old-combined\n"
    assert not any(
        path.name.startswith((".session-", ".combined-"))
        for path in session_root.rglob("*")
    )


@pytest.mark.parametrize("value", [
    "",
    "/absolute.jsonl",
    "../escape.jsonl",
    "nested/../../escape.jsonl",
    "nested\\escape.jsonl",
    "nested/not-json.txt",
    "nested/control\n.jsonl",
    " reverse_solve.jsonl",
    trace_sync.PI_COMBINED_TRACE_NAME,
])
def test_pi_session_sync_rejects_unsafe_relative_paths(value):
    assert trace_sync._safe_pi_session_relative_path(value) == ""


def _write_framed_trace_export(stream, entries, payloads=()):
    manifest = json.dumps(entries, separators=(",", ":")).encode("utf-8")
    stream.write(len(manifest).to_bytes(4, "big"))
    stream.write(manifest)
    for payload in payloads:
        stream.write(payload)
