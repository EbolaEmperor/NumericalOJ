import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import harness_runtime as runtime
from oj_modules.tasks.agent import identity_relay


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

    def fake_run(args, prompt, *, timeout, process_env=None):
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
        )
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
    assert workspace_root.exists()
    assert list(workspace_root.iterdir()) == []


def test_workspace_file_path_cannot_escape(tmp_path):
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "../outside")
    with pytest.raises(ValueError, match="路径"):
        runtime._safe_workspace_path(tmp_path, "/absolute")


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
