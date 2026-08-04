import json
import io
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.problems import agent_runs
from oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages
from oj_modules.tasks.agent import harness_runtime as runtime
from oj_modules.tasks.agent import identity_relay
from oj_modules.tasks.agent import traces as agent_traces
from oj_modules.tasks.agent.traces import AgentTraceRecorder


def _endpoint(protocol="openai"):
    return {
        "id": 9,
        "protocol": protocol,
        "category": "text",
        "base_url": "http://127.0.0.1:9000/v1",
        "api_key": "model-secret",
        "model": "model-a",
        "thinking_enabled": True,
        "thinking_format": "enable_thinking",
    }


def test_docker_args_make_workspace_the_only_writable_filesystem(tmp_path):
    env = runtime._runtime_env(_endpoint(), "codex", "solve")
    args = runtime._docker_args(
        container_name="numoj-agent-test",
        workspace=tmp_path,
        env=env,
    )

    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert args[args.index("--security-opt") + 1] == "no-new-privileges"
    assert args[args.index("--ipc") + 1] == "none"
    assert args[args.index("--workdir") + 1] == "/workspace"
    assert args.count("--volume") == 1
    volume = args[args.index("--volume") + 1]
    assert volume == f"{tmp_path.resolve()}:/workspace:rw"
    assert "--tmpfs" not in args
    assert "AJ_PROMPT_STDIN" in args
    assert "model-secret" not in " ".join(args)
    assert not any("session-cookie" in item for item in args)


def test_docker_args_use_colima_compatible_user_only_on_darwin(
    monkeypatch,
    tmp_path,
):
    env = runtime._runtime_env(_endpoint(), "codex", "solve")

    monkeypatch.setattr(runtime.platform, "system", lambda: "Darwin")
    darwin_args = runtime._docker_args(
        container_name="numoj-agent-darwin",
        workspace=tmp_path,
        env=env,
    )
    assert darwin_args[darwin_args.index("--user") + 1] == "0:0"

    monkeypatch.setattr(runtime.platform, "system", lambda: "Linux")
    monkeypatch.setattr(runtime.os, "getuid", lambda: 1001)
    monkeypatch.setattr(runtime.os, "getgid", lambda: 1002)
    linux_args = runtime._docker_args(
        container_name="numoj-agent-linux",
        workspace=tmp_path,
        env=env,
    )
    assert linux_args[linux_args.index("--user") + 1] == "1001:1002"


def test_container_name_is_stable_and_keeps_the_full_safe_task_id():
    task_id = "a" * 80 + ":retry"

    assert runtime._container_name_for_task_id(task_id) == (
        "numoj-agent-" + "a" * 80 + "-retry"
    )


def test_runtime_env_keeps_harness_state_and_numoj_config_in_workspace():
    env = runtime._runtime_env(_endpoint(), "codex", "solve")

    assert env["HOME"].startswith("/workspace/")
    assert env["TMPDIR"].startswith("/workspace/")
    assert env["XDG_CACHE_HOME"].startswith("/workspace/")
    assert env["AJ_RUNTIME_ROOT"] == "/workspace/.runtime"
    assert env["NUMOJ_USER_CONFIG"] == "/workspace/.numoj-agent/identity.json"
    assert "NUMOJ_CLI_CONFIG" not in env
    assert env["OPENAI_BASE_URL"] == "http://host.docker.internal:9000/v1"
    assert env["AJ_CONTEXT_WINDOW_TOKENS"] == "128000"
    assert env["AJ_MAX_OUTPUT_TOKENS"] == "16384"
    assert env["AJ_THINKING_FORMAT"] == "generic"

    testdata_env = runtime._runtime_env(_endpoint(), "pi", "testdata")
    assert testdata_env["NUMOJ_USER_CONFIG"] == "/workspace/.numoj-agent/identity.json"
    assert "NUMOJ_CLI_CONFIG" not in testdata_env
    assert testdata_env["AJ_PI_THINKING_FORMAT"] == "generic"


def test_runtime_env_injects_site_web_search_mcp_without_putting_secret_in_args(
        tmp_path):
    env = runtime._runtime_env(
        _endpoint(),
        "codex",
        "solve",
        web_search_settings={
            "base_url": "http://localhost:4123/mcp",
            "authorization": "Bearer web-search-secret",
        },
    )

    assert env["AJ_WEB_SEARCH_MCP_URL"] == (
        "http://host.docker.internal:4123/mcp"
    )
    assert env["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == "Bearer web-search-secret"
    assert env["AJ_WEB_SEARCH_MCP_TIMEOUT_SECONDS"] == str(
        runtime.MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS
    )
    args = runtime._docker_args(
        container_name="numoj-agent-web-search",
        workspace=tmp_path,
        env=env,
    )
    assert "AJ_WEB_SEARCH_MCP_AUTHORIZATION" in args
    assert "web-search-secret" not in " ".join(args)


def test_runtime_env_selects_deepseek_thinking_format_from_base_url():
    endpoint = _endpoint()
    endpoint["base_url"] = "https://api.deepseek.com/v1"

    env = runtime._runtime_env(endpoint, "pi", "solve")

    assert env["AJ_THINKING_FORMAT"] == "deepseek"
    assert env["AJ_PI_THINKING_FORMAT"] == "deepseek"


@pytest.mark.parametrize(
    ("task_kind", "harness", "skill_path", "config_env"),
    [
        (
            "solve",
            "claude_code",
            ".runtime/home/.claude/skills/numoj-user/SKILL.md",
            "NUMOJ_USER_CONFIG=/workspace/.numoj-agent/identity.json",
        ),
        (
            "testdata",
            "pi",
            ".runtime/pi/skills/numoj-user/SKILL.md",
            "NUMOJ_USER_CONFIG=/workspace/.numoj-agent/identity.json",
        ),
    ],
)
def test_run_materializes_current_skill_and_ephemeral_session(
    monkeypatch,
    tmp_path,
    task_kind,
    harness,
    skill_path,
    config_env,
):
    workspace_root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(runtime, "AGENT_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(runtime, "AGENT_CONTAINER_SITE_URL", "http://localhost:2025")
    monkeypatch.setattr(
        runtime,
        "get_web_search_settings",
        lambda **_kwargs: {
            "base_url": "https://search.example/mcp",
            "authorization": "Bearer search-secret",
        },
    )
    observed = {}

    class FakeRelayContext:
        def __enter__(self):
            return SimpleNamespace(
                base_url="http://host.docker.internal:43123",
                created_submission_ids=(81, 82),
            )

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        identity_relay,
        "run_numoj_identity_relay",
        lambda *_args, **_kwargs: FakeRelayContext(),
    )

    def fake_run(
        args,
        prompt,
        *,
        timeout,
        process_env=None,
        stdout_line_callback=None,
        on_tick=None,
        tick_interval=None,
    ):
        volume = args[args.index("--volume") + 1]
        workspace = Path(volume.split(":/workspace:rw", 1)[0])
        identity_path = workspace / ".numoj-agent/identity.json"
        observed.update(
            args=list(args),
            prompt=prompt,
            timeout=timeout,
            process_env=dict(process_env or {}),
            identity=json.loads(identity_path.read_text(encoding="utf-8")),
            identity_mode=identity_path.stat().st_mode & 0o777,
            skill=(workspace / skill_path).read_text(encoding="utf-8"),
            stdout_line_callback=stdout_line_callback,
            tick_interval=tick_interval,
        )
        if harness == "claude_code":
            source = (
                workspace
                / ".runtime/home/.claude/projects/-workspace/session.jsonl"
            )
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(json.dumps({
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "已完成 model-secret"}],
                },
            }, ensure_ascii=False) + "\n", encoding="utf-8")
        else:
            source = workspace / ".runtime/pi/agent/sessions/session.jsonl"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(
                json.dumps({"type": "session", "version": 3}) + "\n"
                + json.dumps({
                    "type": "message",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": "已完成 model-secret"}],
                    },
                }, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
        on_tick(final=False)
        on_tick(final=True)
        return runtime.HarnessRunResult(0, False, "ok", "")

    cleanups = []
    monkeypatch.setattr(runtime, "_run_with_bounded_output", fake_run)
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda args, **_kwargs: cleanups.append(list(args)) or SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )

    trace_updates = []
    result = runtime.run_agent_harness(
        task_id="task-1",
        task_kind=task_kind,
        problem_id=17,
        requested_by="admin",
        harness=harness,
        endpoint=_endpoint("anthropic" if harness == "claude_code" else "openai"),
        session_cookie="session-cookie",
        session_cookie_name="numoj_session",
        prompt="请完成任务",
        trace_callback=lambda: trace_updates.append("updated"),
    )

    assert result.returncode == 0
    assert result.created_submission_ids == (81, 82)
    assert observed["prompt"] == "请完成任务"
    assert observed["identity"] == {
        "base_url": "http://host.docker.internal:43123",
        "username": "admin",
        "cookies": {"session": "relay-placeholder"},
        "agent_task": {
            "task_id": "task-1",
            "task_kind": task_kind,
            "problem_id": 17,
            "skill": "numoj-user",
        },
    }
    assert observed["identity_mode"] == 0o600
    assert "name: numoj-" in observed["skill"]
    config_env_name, config_env_value = config_env.split("=", 1)
    assert config_env_name in observed["args"]
    assert observed["process_env"][config_env_name] == config_env_value
    assert observed["process_env"].get("OPENAI_API_KEY") == "model-secret" or (
        observed["process_env"].get("ANTHROPIC_API_KEY") == "model-secret"
    )
    assert "model-secret" not in " ".join(observed["args"])
    assert "session-cookie" not in " ".join(observed["args"])
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_URL"] == (
        "https://search.example/mcp"
    )
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == (
        "Bearer search-secret"
    )
    assert "search-secret" not in " ".join(observed["args"])
    assert "session-cookie" not in json.dumps(observed["identity"])
    container_name = observed["args"][observed["args"].index("--name") + 1]
    assert container_name == "numoj-agent-task-1"
    assert cleanups == [
        ["docker", "rm", "-f", container_name],
        ["docker", "rm", "-f", container_name],
    ]
    assert observed["tick_interval"] == runtime.AGENT_TRACE_SYNC_INTERVAL_SECONDS
    assert trace_updates == ["updated", "updated"]
    trace_dir = workspace_root / "traces/task-1"
    messages = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in messages] == ["已完成 [已脱敏]"]
    assert "model-secret" not in "".join(
        path.read_text(encoding="utf-8")
        for path in trace_dir.rglob("*.jsonl")
    )
    assert workspace_root.exists()
    assert [item.name for item in workspace_root.iterdir()] == ["traces"]


def test_workspace_file_path_cannot_escape(tmp_path):
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "../outside")
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "/absolute")


@pytest.mark.parametrize(
    ("harness", "event"),
    [
        (
            "codex",
            {"type": "agent_message", "message": "Codex model-secret"},
        ),
        (
            "opencode",
            {
                "type": "text",
                "part": {"type": "text", "text": "OpenCode model-secret"},
            },
        ),
    ],
)
def test_stdout_json_trace_is_live_parseable_and_redacted(
    tmp_path,
    harness,
    event,
):
    workspace = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    workspace.mkdir()
    trace_dir.mkdir()
    recorder = AgentTraceRecorder(
        workspace=workspace,
        trace_dir=trace_dir,
        harness=harness,
        secrets=("model-secret",),
    )

    recorder.ingest_stdout_line(
        json.dumps(event, ensure_ascii=False).encode("utf-8"),
        offset=37,
    )

    assert recorder.sync() is True
    assert recorder.sync() is False
    messages = collect_agent_trace_messages(trace_dir)
    assert len(messages) == 1
    assert "[已脱敏]" in messages[0]["text"]
    assert "model-secret" not in "".join(
        path.read_text(encoding="utf-8")
        for path in trace_dir.rglob("*.jsonl")
    )


def test_claude_trace_stably_merges_top_level_sessions_and_ignores_subagents(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    sessions = workspace / ".runtime/home/.claude/projects/-workspace"
    sessions.mkdir(parents=True)
    trace_dir.mkdir()

    def event(text, event_uuid):
        return json.dumps({
            "type": "assistant",
            "uuid": event_uuid,
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
            },
        }, ensure_ascii=False)

    first = sessions / "a-main.jsonl"
    second = sessions / "z-main.jsonl"
    first.write_text(event("主会话 A model-secret", "uuid-a") + "\n", encoding="utf-8")
    second.write_text(event("主会话 Z", "uuid-z") + "\n", encoding="utf-8")
    subagent = sessions / "a-main/subagents/agent-1.jsonl"
    subagent.parent.mkdir(parents=True)
    subagent.write_text(event("不得出现的 subagent", "uuid-sub") + "\n", encoding="utf-8")
    os.utime(first, (200, 200))
    os.utime(second, (100, 100))
    os.utime(subagent, (300, 300))

    recorder = AgentTraceRecorder(
        workspace=workspace,
        trace_dir=trace_dir,
        harness="claude_code",
        secrets=("model-secret",),
    )
    assert recorder.sync() is True
    initial = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in initial] == [
        "主会话 A [已脱敏]",
        "主会话 Z",
    ]
    initial_sources = [item["source"] for item in initial]

    with open(second, "a", encoding="utf-8") as stream:
        stream.write(event("主会话 Z 的后续", "uuid-z-2") + "\n")
    os.utime(first, (100, 100))
    os.utime(second, (400, 400))

    assert recorder.sync() is True
    updated = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in updated] == [
        "主会话 A [已脱敏]",
        "主会话 Z",
        "主会话 Z 的后续",
    ]
    assert [item["source"] for item in updated[:2]] == initial_sources
    assert all("subagent" not in item["text"] for item in updated)


def test_pi_trace_stably_merges_all_valid_sessions_without_mtime_switching(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    sessions = workspace / ".runtime/pi/agent/sessions"
    first = sessions / "2026/a/session.jsonl"
    second = sessions / "2027/b/session.jsonl"
    invalid = sessions / "2028/invalid.jsonl"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    invalid.parent.mkdir(parents=True)
    trace_dir.mkdir()

    def message(text):
        return json.dumps({
            "type": "message",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": text}],
            },
        }, ensure_ascii=False)

    header = json.dumps({"type": "session", "version": 3})
    first.write_text(header + "\n" + message("Pi A") + "\n", encoding="utf-8")
    second.write_text(header + "\n" + message("Pi B") + "\n", encoding="utf-8")
    invalid.write_text(
        json.dumps({"type": "session", "version": 2})
        + "\n"
        + message("无效 session")
        + "\n",
        encoding="utf-8",
    )
    os.utime(first, (300, 300))
    os.utime(second, (100, 100))

    recorder = AgentTraceRecorder(
        workspace=workspace,
        trace_dir=trace_dir,
        harness="pi",
    )
    assert recorder.sync() is True
    initial = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in initial] == ["Pi A", "Pi B"]
    second_source = initial[1]["source"]
    second_offset = initial[1]["offset"]

    with open(first, "a", encoding="utf-8") as stream:
        stream.write(message("Pi A 后续") + "\n")
    os.utime(first, (500, 500))
    os.utime(second, (200, 200))

    assert recorder.sync() is True
    updated = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in updated] == ["Pi A", "Pi A 后续", "Pi B"]
    assert updated[-1]["source"] == second_source
    assert updated[-1]["offset"] == second_offset
    assert all("无效 session" not in item["text"] for item in updated)


def test_pi_truncated_tail_keeps_single_safe_v3_header_and_latest_message(
    monkeypatch,
    tmp_path,
):
    workspace = tmp_path / "workspace"
    trace_dir = tmp_path / "trusted-trace"
    source = workspace / ".runtime/pi/agent/sessions/session.jsonl"
    source.parent.mkdir(parents=True)
    trace_dir.mkdir()

    header = json.dumps({
        "type": "session",
        "version": 3,
        "credential": "model-secret",
    })
    filler = json.dumps({
        "type": "message",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": "x" * 2048}],
        },
    })
    latest = json.dumps({
        "type": "message",
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": "保留下来的末条消息"}],
        },
    }, ensure_ascii=False)
    source.write_text(
        header + "\n" + filler + "\n" + latest + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(agent_traces, "_TRACE_SOURCE_MAX_BYTES", 512)

    recorder = AgentTraceRecorder(
        workspace=workspace,
        trace_dir=trace_dir,
        harness="pi",
        secrets=("model-secret",),
    )
    assert recorder.sync() is True

    combined = trace_dir / ".pi/agent/sessions/reverse_solve_combined.jsonl"
    rows = [
        json.loads(line)
        for line in combined.read_text(encoding="utf-8").splitlines()
    ]
    assert rows[0] == {"type": "session", "version": 3}
    assert sum(row.get("type") == "session" for row in rows) == 1
    assert "model-secret" not in combined.read_text(encoding="utf-8")
    assert [item["text"] for item in collect_agent_trace_messages(trace_dir)] == [
        "保留下来的末条消息",
    ]


def test_bounded_runner_publishes_periodic_and_final_trace_ticks(monkeypatch):
    ticks = []
    lines = []

    class FakeProcess:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(b'{"type":"one"}\n{"type":"two"}\n')
            self.stderr = io.BytesIO()
            self.wait_calls = 0

        def wait(self, timeout=None):
            self.wait_calls += 1
            if self.wait_calls < 4:
                raise runtime.subprocess.TimeoutExpired("docker", timeout)
            return 0

        def kill(self):
            return None

    process = FakeProcess()
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)
    clock = {"value": 0.0}

    def monotonic():
        clock["value"] += 0.3
        return clock["value"]

    monkeypatch.setattr(runtime.time, "monotonic", monotonic)

    result = runtime._run_with_bounded_output(
        ["docker"],
        "prompt",
        timeout=10,
        stdout_line_callback=lambda line, offset: lines.append((line, offset)),
        on_tick=lambda *, final=False: ticks.append(final),
        tick_interval=0.5,
    )

    assert result.returncode == 0
    assert lines == [
        (b'{"type":"one"}', 0),
        (b'{"type":"two"}', 15),
    ]
    assert ticks[-1] is True
    assert False in ticks


def test_stdout_line_callback_discards_oversized_unterminated_line():
    oversized = b"x" * (runtime._TRACE_STDOUT_LINE_MAX_BYTES * 4)
    valid = b'{"type":"agent_message","message":"ok"}'
    chunks = runtime.deque()
    sizes = {"stdout": 0}
    observed = []

    runtime._tail_reader(
        io.BytesIO(oversized + b"\n" + valid + b"\n"),
        chunks,
        sizes,
        "stdout",
        runtime._CAPTURE_LIMIT_BYTES,
        line_callback=lambda line, offset: observed.append((line, offset)),
    )

    assert observed == [(valid, len(oversized) + 1)]
    assert sizes["stdout"] <= runtime._CAPTURE_LIMIT_BYTES


def test_container_cleanup_failure_is_not_silently_ignored(monkeypatch):
    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Cannot connect to the Docker daemon",
        ),
    )

    with pytest.raises(RuntimeError, match="无法确认 Agent 容器"):
        runtime._remove_agent_container("numoj-agent-task-1")
