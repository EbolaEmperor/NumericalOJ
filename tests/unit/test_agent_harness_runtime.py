import json
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.problems import agent_runs
from oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages
from oj_modules.tasks.agent import harness_runtime as runtime
from oj_modules.tasks.agent import identity_relay
from oj_modules.tasks.agent import traces as agent_traces


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


def test_docker_process_env_keeps_host_docker_config_when_container_overrides_home(
    monkeypatch,
):
    monkeypatch.setenv("HOME", "/Users/host-user")
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    monkeypatch.setenv("DOCKER_CONTEXT", "colima")

    process_env = runtime._docker_process_env({
        "HOME": "/workspace/.runtime/home",
        "OPENAI_API_KEY": "secret",
    })

    assert process_env["HOME"] == "/workspace/.runtime/home"
    assert process_env["DOCKER_CONFIG"] == "/Users/host-user/.docker"
    assert process_env["DOCKER_CONTEXT"] == "colima"
    assert process_env["OPENAI_API_KEY"] == "secret"


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
    lifecycle = []

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
        stdout_capture_path=None,
        on_tick=None,
        tick_interval=None,
    ):
        lifecycle.append("exec")
        create_args = observed["create_args"]
        volume = create_args[create_args.index("--volume") + 1]
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
            stdout_capture_path=stdout_capture_path,
            tick_interval=tick_interval,
        )
        Path(stdout_capture_path).write_text("temporary stdout", encoding="utf-8")
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

    def fake_sync(
        _container_name,
        trace_dir,
        selected_harness,
        _stdout_path,
        *,
        secrets=(),
    ):
        lifecycle.append("sync")
        observed["trace_secrets"] = secrets
        trace_dir = Path(trace_dir)
        create_args = observed["create_args"]
        volume = create_args[create_args.index("--volume") + 1]
        workspace = Path(volume.split(":/workspace:rw", 1)[0])
        if selected_harness == "claude_code":
            source = workspace / ".runtime/home/.claude/projects/-workspace/session.jsonl"
            destination = trace_dir / ".claude/projects/-workspace/reverse_solve_combined.jsonl"
        else:
            source = workspace / ".runtime/pi/agent/sessions/session.jsonl"
            destination = trace_dir / ".pi/agent/sessions/reverse_solve_combined.jsonl"
        if not source.is_file():
            return False
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        return True

    monkeypatch.setattr(runtime, "sync_agent_trace", fake_sync)

    def fake_subprocess_run(args, **_kwargs):
        if list(args[:2]) == ["docker", "run"]:
            lifecycle.append("create")
            observed["create_args"] = list(args)
        elif list(args[:3]) == ["docker", "rm", "-f"]:
            lifecycle.append("remove")
            cleanups.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        runtime.subprocess,
        "run",
        fake_subprocess_run,
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
    assert observed["trace_secrets"] == (
        "session-cookie",
        "model-secret",
        "Bearer search-secret",
    )
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
    assert config_env_name in observed["create_args"]
    assert observed["process_env"][config_env_name] == config_env_value
    assert observed["process_env"].get("OPENAI_API_KEY") == "model-secret" or (
        observed["process_env"].get("ANTHROPIC_API_KEY") == "model-secret"
    )
    assert "model-secret" not in " ".join(observed["create_args"])
    assert "session-cookie" not in " ".join(observed["create_args"])
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_URL"] == (
        "https://search.example/mcp"
    )
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == (
        "Bearer search-secret"
    )
    assert "search-secret" not in " ".join(observed["args"])
    assert "session-cookie" not in json.dumps(observed["identity"])
    container_name = observed["create_args"][
        observed["create_args"].index("--name") + 1
    ]
    assert container_name == "numoj-agent-task-1"
    assert observed["create_args"][-4:] == [
        str(runtime.AGENT_JUDGE_DOCKER_IMAGE), "bash", "-lc", "tail -f /dev/null",
    ]
    assert observed["args"][:4] == ["docker", "exec", "-i", container_name]
    assert cleanups == [
        ["docker", "rm", "-f", container_name],
        ["docker", "rm", "-f", container_name],
    ]
    assert observed["tick_interval"] == runtime.AGENT_TRACE_SYNC_INTERVAL_SECONDS
    assert trace_updates == ["updated", "updated", "updated", "updated"]
    assert lifecycle == [
        "remove", "create", "sync", "exec", "sync", "sync", "sync", "remove",
    ]
    trace_dir = workspace_root / "traces/task-1"
    messages = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in messages] == ["已完成 model-secret"]
    assert not (trace_dir / ".agent_harness.stdout.tmp").exists()
    assert workspace_root.exists()
    assert [item.name for item in workspace_root.iterdir()] == ["traces"]


def test_workspace_file_path_cannot_escape(tmp_path):
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "../outside")
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "/absolute")



@pytest.mark.parametrize(
    ("harness", "expected_destination"),
    [
        ("codex", "codex_reverse_solve.jsonl"),
        ("opencode", "opencode_agent_judge.jsonl"),
    ],
)
def test_stdout_agents_reuse_reverse_stdout_sync(
    monkeypatch,
    tmp_path,
    harness,
    expected_destination,
):
    calls = []
    source = tmp_path / "stdout.jsonl"
    source.write_text('{"type":"agent_message","message":"live"}\n')
    monkeypatch.setattr(
        agent_traces,
        "sync_stdout_jsonl",
        lambda *args, **kwargs: calls.append((args, kwargs)) or True,
    )

    assert agent_traces.sync_agent_trace(
        "container", tmp_path / "trace", harness, source,
    ) is True
    assert calls == [
        (
            (source, str(tmp_path / "trace"), expected_destination),
            {"secrets": ()},
        ),
    ]


def test_shared_stdout_sync_keeps_more_than_4096_events(tmp_path):
    source = tmp_path / "stdout.jsonl"
    secret = "trace-secret"
    payload = (
        b'{"type":"agent_message","message":"live trace-secret"}\n' * 4100
    )
    source.write_bytes(payload)
    trace_dir = tmp_path / "trace"

    assert agent_traces.sync_agent_trace(
        "container", trace_dir, "codex", source, secrets=(secret,),
    ) is True
    rendered = (trace_dir / "codex_reverse_solve.jsonl").read_bytes()
    assert rendered.count(b'"type":"agent_message"') == 4100
    assert secret.encode() not in rendered
    assert b"[REDACTED]" in rendered


def test_native_agents_reuse_reverse_container_sync(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        agent_traces,
        "sync_claude_project_jsonl",
        lambda *args, **kwargs: calls.append(("claude", args, kwargs)) or True,
    )
    monkeypatch.setattr(
        agent_traces,
        "sync_pi_agent_sessions",
        lambda *args, **kwargs: calls.append(("pi", args, kwargs)) or True,
    )
    trace_dir = tmp_path / "trace"

    assert agent_traces.sync_agent_trace(
        "container", trace_dir, "claude_code", tmp_path / "stdout",
    ) is True
    assert agent_traces.sync_agent_trace(
        "container", trace_dir, "pi", tmp_path / "stdout",
    ) is True

    assert calls == [
        (
            "claude",
            ("container", str(trace_dir)),
            {
                "container_project_dir": (
                    "/workspace/.runtime/home/.claude/projects/-workspace"
                ),
                "secrets": (),
            },
        ),
        (
            "pi",
            ("container", str(trace_dir)),
            {
                "container_session_dir": "/workspace/.runtime/pi/agent/sessions",
                "runtime_user": "",
                "secrets": (),
            },
        ),
    ]


def test_bounded_runner_publishes_periodic_and_final_trace_ticks(
    monkeypatch,
    tmp_path,
):
    ticks = []
    stdout_path = tmp_path / "stdout.jsonl"

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
        stdout_capture_path=stdout_path,
        on_tick=lambda *, final=False: ticks.append(final),
        tick_interval=0.5,
    )

    assert result.returncode == 0
    assert stdout_path.read_bytes() == b'{"type":"one"}\n{"type":"two"}\n'
    assert ticks[-1] is True
    assert False in ticks


def test_stdout_mirror_is_complete_while_result_capture_stays_bounded():
    output = b"x" * (runtime._CAPTURE_LIMIT_BYTES + 1024)
    chunks = runtime.deque()
    sizes = {"stdout": 0}
    mirror = io.BytesIO()

    runtime._tail_reader(
        io.BytesIO(output),
        chunks,
        sizes,
        "stdout",
        runtime._CAPTURE_LIMIT_BYTES,
        mirror_stream=mirror,
    )

    assert mirror.getvalue() == output
    assert sizes["stdout"] == runtime._CAPTURE_LIMIT_BYTES


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
