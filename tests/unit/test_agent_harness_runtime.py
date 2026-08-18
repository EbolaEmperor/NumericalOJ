import json
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from oj_modules.agents import workspace as agent_workspace
from oj_modules.agents import runtime_checkpoints
from oj_modules.problems import agent_runs
from oj_modules.ranking.reverse_judge import traces as reverse_traces
from oj_modules.ranking.reverse_judge.traces import (
    collect_agent_token_usage,
    collect_agent_trace_messages,
)
from oj_modules.tasks.agent import harness_runtime as runtime
from oj_modules.tasks.agent import identity_relay
from oj_modules.tasks.agent import secret_relay
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


_TEMP_ENDPOINT_BASE_URL = "http://host.docker.internal:43100/v1"
_TEMP_ENDPOINT_API_KEY = "temporary-endpoint-token"


def _runtime_env(endpoint, harness, task_kind, **kwargs):
    return runtime._runtime_env(
        endpoint,
        harness,
        task_kind,
        endpoint_base_url=_TEMP_ENDPOINT_BASE_URL,
        endpoint_api_key=_TEMP_ENDPOINT_API_KEY,
        **kwargs,
    )


def test_docker_args_make_workspace_the_only_writable_filesystem(tmp_path):
    env = _runtime_env(_endpoint(), "codex", "solve")
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


def test_docker_args_mount_materialized_skill_read_only_inside_workspace(
    tmp_path,
):
    skill = tmp_path / ".runtime/home/.agents/skills/numoj-user"
    skill.mkdir(parents=True)
    env = _runtime_env(_endpoint(), "codex", "solve")

    args = runtime._docker_args(
        container_name="numoj-agent-test",
        workspace=tmp_path,
        env=env,
        readonly_workspace_paths=(skill,),
    )

    volumes = [
        args[index + 1]
        for index, value in enumerate(args)
        if value == "--volume"
    ]
    assert volumes == [
        f"{tmp_path.resolve()}:/workspace:rw",
        (
            f"{skill.resolve()}:"
            "/workspace/.runtime/home/.agents/skills/numoj-user:ro"
        ),
    ]


def test_docker_args_use_colima_compatible_user_only_on_darwin(
    monkeypatch,
    tmp_path,
):
    env = _runtime_env(_endpoint(), "codex", "solve")

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
        "AJ_ENDPOINT_API_KEY": "secret",
    })

    assert process_env["HOME"] == "/workspace/.runtime/home"
    assert process_env["DOCKER_CONFIG"] == "/Users/host-user/.docker"
    assert process_env["DOCKER_CONTEXT"] == "colima"
    assert process_env["AJ_ENDPOINT_API_KEY"] == "secret"


def test_container_name_uses_the_shared_validated_task_id_contract():
    assert runtime._container_name_for_task_id("task-123") == (
        "numoj-agent-task-123"
    )
    with pytest.raises(ValueError, match="task_id"):
        runtime._container_name_for_task_id("task:123")


def test_docker_exec_has_no_agent_wall_clock_timeout_wrapper():
    args = runtime._docker_exec_args("numoj-agent-task")

    assert args == [
        "docker",
        "exec",
        "-i",
        "numoj-agent-task",
        "/usr/local/bin/run_harness",
    ]


def test_runtime_env_keeps_harness_state_and_numoj_config_in_workspace():
    env = _runtime_env(_endpoint(), "codex", "solve")

    assert env["HOME"].startswith("/workspace/")
    assert env["TMPDIR"] == "/workspace/.runtime/tmp"
    assert env["TMP"] == "/workspace/.runtime/tmp"
    assert env["TEMP"] == "/workspace/.runtime/tmp"
    assert env["XDG_CACHE_HOME"].startswith("/workspace/")
    assert env["AJ_RUNTIME_ROOT"] == "/workspace/.runtime"
    assert env["AJ_TASK_SCOPE"] == "problem_agent"
    assert env["NUMOJ_USER_CONFIG"] == "/workspace/.numoj-agent/identity.json"
    assert "NUMOJ_CLI_CONFIG" not in env
    assert env["AJ_ENDPOINT_PROTOCOL"] == "openai"
    assert env["AJ_ENDPOINT_BASE_URL"] == _TEMP_ENDPOINT_BASE_URL
    assert env["AJ_ENDPOINT_API_KEY"] == _TEMP_ENDPOINT_API_KEY
    assert "model-secret" not in env.values()
    assert env["AJ_ENDPOINT_MODEL"] == "model-a"
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "OPENCODE_API_KEY" not in env
    assert env["AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS"] == "384000"
    assert env["AJ_ENDPOINT_MAX_OUTPUT_TOKENS"] == "32000"
    assert env["AJ_ENDPOINT_THINKING_ENABLED"] == "1"
    assert env["AJ_ENDPOINT_THINKING_FORMAT"] == "enable_thinking"
    assert "AJ_THINKING_FORMAT" not in env

    testdata_env = _runtime_env(_endpoint(), "pi", "testdata")
    assert testdata_env["NUMOJ_USER_CONFIG"] == "/workspace/.numoj-agent/identity.json"
    assert "NUMOJ_CLI_CONFIG" not in testdata_env
    assert "AJ_PI_THINKING_FORMAT" not in testdata_env

    testdata_admin_env = _runtime_env(
        _endpoint(),
        "pi",
        "testdata",
        access_role="admin",
    )
    assert testdata_admin_env["NUMOJ_CLI_CONFIG"] == (
        "/workspace/.numoj-agent/identity.json"
    )
    assert "NUMOJ_USER_CONFIG" not in testdata_admin_env


def test_runtime_env_uses_selected_endpoint_capacity_instead_of_global_limit():
    endpoint = _endpoint()
    endpoint.update(
        context_window_tokens=131_072,
        max_output_tokens=24_000,
    )

    env = _runtime_env(endpoint, "pi", "custom")

    assert env["AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS"] == "131072"
    assert env["AJ_ENDPOINT_MAX_OUTPUT_TOKENS"] == "24000"


def test_custom_admin_runtime_uses_admin_skill_and_native_resume():
    native_id = "22222222-2222-2222-2222-222222222222"
    env = _runtime_env(
        _endpoint(),
        "codex",
        "custom",
        access_role="admin",
        resume_session_id=native_id,
    )

    assert env["NUMOJ_CLI_CONFIG"] == "/workspace/.numoj-agent/identity.json"
    assert "NUMOJ_USER_CONFIG" not in env
    assert env["AJ_RESUME_SESSION_ID"] == native_id
    assert env["AJ_FORK_SESSION"] == "0"


def test_opencode_native_session_id_is_opaque_and_preserves_case(tmp_path):
    native_id = "ses_MixedCase_19-Z"
    env = _runtime_env(
        _endpoint(),
        "opencode",
        "custom",
        access_role="user",
        resume_session_id=native_id,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".aj_session_state.json").write_text(
        json.dumps({"harness": "opencode", "session_id": native_id}),
        encoding="utf-8",
    )

    assert env["AJ_RESUME_SESSION_ID"] == native_id
    assert runtime.normalize_native_session_id(native_id, "opencode") == native_id
    assert runtime._read_native_session_id(workspace, "opencode") == native_id
    with pytest.raises(ValueError, match="session_id"):
        runtime.normalize_native_session_id(native_id, "codex")


@pytest.mark.parametrize(
    "native_id",
    ["ses_", "ses_has.dot", "SES_wrong_prefix", "ses_" + "a" * 121],
)
def test_opencode_native_session_id_rejects_invalid_values(native_id):
    with pytest.raises(ValueError, match="session_id"):
        runtime.normalize_native_session_id(native_id, "opencode")


def test_native_session_state_is_read_without_following_symlinks(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({
            "harness": "codex",
            "session_id": "33333333-3333-3333-3333-333333333333",
        }),
        encoding="utf-8",
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".aj_session_state.json").symlink_to(outside)

    with pytest.raises(ValueError, match="安全的普通文件"):
        runtime._read_native_session_id(workspace, "codex")


def test_identity_cleanup_never_traverses_workspace_parent_symlink(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    credential = outside / "identity.json"
    credential.write_text("must-survive", encoding="utf-8")
    (workspace / ".numoj-agent").symlink_to(outside, target_is_directory=True)

    with pytest.raises(runtime.AgentHarnessCleanupError, match="父目录不安全"):
        runtime._remove_identity_config(
            workspace,
            ".numoj-agent/identity.json",
        )

    assert credential.read_text(encoding="utf-8") == "must-survive"


def test_secret_relay_cleanup_failure_blocks_resumable_terminal_state(monkeypatch):
    class CleanupFailureContext:
        def __enter__(self):
            return SimpleNamespace(endpoint_base_url="unused")

        def __exit__(self, *_args):
            raise secret_relay.AgentSecretRelayCleanupError(
                "外部服务密钥代理未能彻底关闭"
            )

    monkeypatch.setattr(
        secret_relay,
        "run_agent_secret_relays",
        lambda *_args, **_kwargs: CleanupFailureContext(),
    )

    with pytest.raises(
        runtime.AgentHarnessCleanupError,
        match="外部服务密钥代理未能彻底关闭",
    ):
        with runtime._secret_relay_context({}, None):
            pass


def test_secret_relay_hard_stop_is_translated_for_generic_task():
    relayed = SimpleNamespace(
        wait_for_endpoint_usage=lambda: (_ for _ in ()).throw(
            secret_relay.AgentSecretRelayUsageHardStopError(
                "Agent 额度已达到硬停阈值，剩余额度 -5.1 元"
            )
        ),
        raise_if_usage_failed=lambda: None,
    )

    with pytest.raises(runtime.AgentUsageHardStopError, match="-5.1"):
        runtime._check_secret_relay_usage(relayed, wait=True)


def test_secret_relay_accounting_failure_is_not_swallowed():
    relayed = SimpleNamespace(
        raise_if_usage_failed=lambda: (_ for _ in ()).throw(
            RuntimeError("usage database unavailable")
        ),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        runtime._check_secret_relay_usage(relayed)


def test_runtime_env_injects_relayed_web_search_mcp_without_secret_in_args(
        tmp_path):
    env = _runtime_env(
        _endpoint(),
        "codex",
        "solve",
        web_search_settings={
            "base_url": "http://localhost:4123/mcp",
            "authorization": "Bearer temporary-search",
        },
    )

    assert env["AJ_WEB_SEARCH_MCP_URL"] == (
        "http://host.docker.internal:4123/mcp"
    )
    assert env["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == "Bearer temporary-search"
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


def test_runtime_env_does_not_derive_harness_settings_from_endpoint_url():
    endpoint = _endpoint()
    endpoint["base_url"] = "https://api.deepseek.com/v1"

    env = _runtime_env(endpoint, "pi", "solve")

    assert "AJ_THINKING_FORMAT" not in env
    assert "AJ_PI_THINKING_FORMAT" not in env


@pytest.mark.parametrize(
    ("harness", "reasoning_effort"),
    [("pi", "minimal"), ("claude_code", "xhigh")],
)
def test_runtime_env_injects_frozen_native_reasoning_effort(
    harness,
    reasoning_effort,
):
    env = _runtime_env(
        _endpoint(),
        harness,
        "custom",
        reasoning_effort=reasoning_effort,
    )

    assert env["AJ_EFFORT"] == reasoning_effort


def test_runtime_env_omits_reasoning_effort_for_legacy_default():
    endpoint = _endpoint()
    endpoint["thinking_enabled"] = False
    endpoint["thinking_format"] = "none"
    env = _runtime_env(endpoint, "pi", "custom")

    assert "AJ_EFFORT" not in env
    assert env["AJ_ENDPOINT_THINKING_ENABLED"] == "0"
    assert env["AJ_ENDPOINT_THINKING_FORMAT"] == "none"


@pytest.mark.parametrize(
    (
        "harness",
        "reasoning_effort",
        "protocol",
        "endpoint_enabled",
        "expected_enabled",
        "expected_format",
    ),
    [
        ("pi", "off", "openai", True, "0", "none"),
        ("pi", "high", "openai", False, "1", "enable_thinking"),
        ("pi", "minimal", "anthropic", False, "1", "thinking_type"),
        ("claude_code", "xhigh", "anthropic", False, "1", "thinking_type"),
    ],
)
def test_runtime_env_reasoning_effort_overrides_endpoint_thinking_switch(
    harness,
    reasoning_effort,
    protocol,
    endpoint_enabled,
    expected_enabled,
    expected_format,
):
    endpoint = _endpoint()
    endpoint["protocol"] = protocol
    endpoint["thinking_enabled"] = endpoint_enabled
    endpoint["thinking_format"] = (
        "thinking_type" if protocol == "anthropic" else "enable_thinking"
    ) if endpoint_enabled else "none"

    env = _runtime_env(
        endpoint,
        harness,
        "custom",
        reasoning_effort=reasoning_effort,
    )

    assert env["AJ_EFFORT"] == reasoning_effort
    assert env["AJ_ENDPOINT_THINKING_ENABLED"] == expected_enabled
    assert env["AJ_ENDPOINT_THINKING_FORMAT"] == expected_format


def test_runtime_env_rejects_reasoning_effort_unsupported_by_harness():
    with pytest.raises(ValueError, match="不支持该思考深度"):
        _runtime_env(
            _endpoint(),
            "claude_code",
            "custom",
            reasoning_effort="minimal",
        )


def test_run_exits_before_workspace_creation_when_already_canceled(
    monkeypatch,
    tmp_path,
):
    workspace_root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(agent_workspace, "AGENT_WORKSPACE_ROOT", workspace_root)

    result = runtime.run_agent_harness(
        task_id="task-canceled",
        task_kind="solve",
        problem_id=17,
        requested_by="admin",
        harness="codex",
        endpoint=_endpoint(),
        session_cookie="session-cookie",
        prompt="prompt",
        cancel_check=lambda: True,
    )

    assert result.returncode == -15
    assert result.timed_out is False
    assert not workspace_root.exists()


def test_retry_restores_runtime_before_checking_workspace_quota(
    monkeypatch,
    tmp_path,
):
    lifecycle = []
    monkeypatch.setattr(
        runtime,
        "_ensure_stable_workspace",
        lambda session_id: lifecycle.append(("workspace", session_id)) or tmp_path,
    )
    monkeypatch.setattr(
        runtime,
        "_remove_agent_container",
        lambda name: lifecycle.append(("remove", name)),
    )
    monkeypatch.setattr(
        runtime_checkpoints,
        "restore_agent_runtime_checkpoint",
        lambda session_id, checkpoint_id: lifecycle.append(
            ("restore", session_id, checkpoint_id)
        ),
    )

    class QuotaChecked(RuntimeError):
        pass

    def stop_after_quota(session_id):
        lifecycle.append(("quota", session_id))
        raise QuotaChecked

    monkeypatch.setattr(
        agent_workspace,
        "check_agent_workspace_quota",
        stop_after_quota,
    )

    with pytest.raises(QuotaChecked):
        runtime.run_agent_harness(
            task_id="task-retry",
            session_id="session-retry",
            task_kind="custom",
            access_role="admin",
            problem_id=None,
            requested_by="admin",
            harness="codex",
            endpoint=_endpoint(),
            session_cookie="session-cookie",
            prompt="重试",
            resume_session_id="",
            restore_runtime_checkpoint_id="checkpoint-before-attempt",
        )

    assert lifecycle == [
        ("workspace", "session-retry"),
        ("remove", "numoj-agent-task-retry"),
        ("restore", "session-retry", "checkpoint-before-attempt"),
        ("quota", "session-retry"),
    ]


@pytest.mark.parametrize(
    (
        "task_kind",
        "access_role",
        "harness",
        "skill_name",
        "skill_path",
        "config_env",
    ),
    [
        (
            "solve",
            "user",
            "claude_code",
            "numoj-user",
            ".runtime/home/.claude/skills/numoj-user/SKILL.md",
            "NUMOJ_USER_CONFIG=/workspace/.numoj-agent/identity.json",
        ),
        (
            "testdata",
            "admin",
            "pi",
            "numoj-admin",
            ".runtime/pi/skills/numoj-admin/SKILL.md",
            "NUMOJ_CLI_CONFIG=/workspace/.numoj-agent/identity.json",
        ),
    ],
)
def test_run_materializes_current_skill_and_persists_session_workspace(
    monkeypatch,
    tmp_path,
    task_kind,
    access_role,
    harness,
    skill_name,
    skill_path,
    config_env,
):
    workspace_root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(agent_workspace, "AGENT_WORKSPACE_ROOT", workspace_root)
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(runtime, "AGENT_CONTAINER_SITE_URL", "http://localhost:2025")
    previous_temporary_secret = "previous-turn-temporary-token"
    assert agent_workspace.merge_agent_temporary_redaction_candidates(
        "task-1",
        (previous_temporary_secret,),
    ) == (previous_temporary_secret,)
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
    identity_temporary_secret = "identity-relay-temporary-token"
    identity_userinfo = f"numoj-agent:{identity_temporary_secret}"
    identity_base_url = (
        f"http://{identity_userinfo}@host.docker.internal:43123"
    )
    identity_escaped_base_url = identity_base_url.replace("/", r"\/")
    identity_basic_payload = (
        "bnVtb2otYWdlbnQ6aWRlbnRpdHktcmVsYXktdGVtcG9yYXJ5LXRva2Vu"
    )
    identity_authorization = f"Basic {identity_basic_payload}"
    identity_temporary_secrets = (
        identity_base_url,
        identity_escaped_base_url,
        identity_authorization,
        identity_basic_payload,
        identity_userinfo,
        identity_temporary_secret,
    )

    class FakeRelayContext:
        def __enter__(self):
            return SimpleNamespace(
                base_url=identity_base_url,
                created_submission_ids=(81, 82),
                temporary_secrets=identity_temporary_secrets,
            )

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        identity_relay,
        "run_numoj_identity_relay",
        lambda *_args, **_kwargs: FakeRelayContext(),
    )

    endpoint_temporary = "endpoint-relay-temporary-token"
    web_search_temporary = "search-relay-temporary-token"

    class FakeSecretRelayContext:
        def __enter__(self):
            return SimpleNamespace(
                endpoint_base_url=(
                    "http://host.docker.internal:43124/v1"
                ),
                endpoint_api_key=endpoint_temporary,
                web_search_base_url=(
                    "http://host.docker.internal:43125/mcp"
                ),
                web_search_authorization=(
                    f"Bearer {web_search_temporary}"
                ),
                temporary_secrets=(
                    endpoint_temporary,
                    web_search_temporary,
                ),
            )

        def __exit__(self, *_args):
            return False

    def fake_secret_relays(endpoint, web_search_settings):
        observed["relay_endpoint"] = dict(endpoint)
        observed["relay_web_search"] = dict(web_search_settings)
        return FakeSecretRelayContext()

    monkeypatch.setattr(
        secret_relay,
        "run_agent_secret_relays",
        fake_secret_relays,
    )

    def fake_run(
        args,
        prompt,
        *,
        process_env=None,
        stdout_capture_path=None,
        on_tick=None,
        tick_interval=None,
        cancel_check=None,
        quota_check=None,
        quota_check_interval=None,
    ):
        lifecycle.append("exec")
        create_args = observed["create_args"]
        volume = create_args[create_args.index("--volume") + 1]
        workspace = Path(volume.split(":/workspace:rw", 1)[0])
        identity_path = workspace / ".numoj-agent/identity.json"
        observed.update(
            args=list(args),
            prompt=prompt,
            process_env=dict(process_env or {}),
            identity=json.loads(identity_path.read_text(encoding="utf-8")),
            identity_mode=identity_path.stat().st_mode & 0o777,
            skill=(workspace / skill_path).read_text(encoding="utf-8"),
            stdout_capture_path=stdout_capture_path,
            tick_interval=tick_interval,
            cancel_check=cancel_check,
            quota_check=quota_check,
            quota_check_interval=quota_check_interval,
        )
        Path(stdout_capture_path).write_text("temporary stdout", encoding="utf-8")
        (workspace / ".aj_session_state.json").write_text(
            json.dumps({
                "harness": harness,
                "session_id": "11111111-1111-1111-1111-111111111111",
            }),
            encoding="utf-8",
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
                    "content": [{
                        "type": "text",
                        "text": (
                            f"旧身份 {previous_temporary_secret}；"
                            f"身份 {identity_base_url} "
                            f"{identity_authorization} "
                            f"{identity_temporary_secret}；"
                            f"已完成 {endpoint_temporary}"
                        ),
                    }],
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
                        "content": [{
                            "type": "text",
                            "text": (
                                f"旧身份 {previous_temporary_secret}；"
                                f"身份 {identity_base_url} "
                                f"{identity_authorization} "
                                f"{identity_temporary_secret}；"
                                f"已完成 {endpoint_temporary}"
                            ),
                        }],
                    },
                }, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
        on_tick(final=False)
        on_tick(final=True)
        return runtime.HarnessRunResult(
            0,
            False,
            (
                f"ok {previous_temporary_secret} "
                f"{identity_base_url} {identity_authorization} "
                f"{identity_temporary_secret} model-secret {endpoint_temporary}"
            ),
            (
                f"{identity_escaped_base_url} {identity_userinfo} "
                f"Bearer search-secret {web_search_temporary}"
            ),
        )

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
        rendered = source.read_bytes()
        for secret in secrets:
            if secret:
                rendered = rendered.replace(
                    str(secret).encode("utf-8"),
                    b"[REDACTED]",
                )
        destination.write_bytes(rendered)
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
        access_role=access_role,
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
    assert result.native_session_id == "11111111-1111-1111-1111-111111111111"
    assert observed["trace_secrets"] == (
        previous_temporary_secret,
        *identity_temporary_secrets,
        endpoint_temporary,
        web_search_temporary,
        "session-cookie",
        "model-secret",
        "Bearer search-secret",
    )
    assert result.created_submission_ids == (81, 82)
    assert observed["prompt"] == "请完成任务"
    assert observed["identity"] == {
        "base_url": identity_base_url,
        "username": "admin",
        "cookies": {"session": "relay-placeholder"},
            "agent_task": {
                "task_id": "task-1",
                "session_id": "task-1",
                "task_kind": task_kind,
                "access_role": access_role,
                "problem_id": 17,
            "skill": skill_name,
        },
    }
    assert observed["identity_mode"] == 0o600
    assert "name: numoj-" in observed["skill"]
    config_env_name, config_env_value = config_env.split("=", 1)
    assert config_env_name in observed["create_args"]
    assert observed["process_env"][config_env_name] == config_env_value
    assert observed["process_env"]["AJ_ENDPOINT_API_KEY"] == endpoint_temporary
    assert "OPENAI_API_KEY" not in observed["process_env"]
    assert "ANTHROPIC_API_KEY" not in observed["process_env"]
    assert "model-secret" not in " ".join(observed["create_args"])
    assert "session-cookie" not in " ".join(observed["create_args"])
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_URL"] == (
        "http://host.docker.internal:43125/mcp"
    )
    assert observed["process_env"]["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == (
        f"Bearer {web_search_temporary}"
    )
    assert all(
        "model-secret" not in str(value)
        and "search-secret" not in str(value)
        for value in observed["process_env"].values()
    )
    assert "search-secret" not in " ".join(observed["args"])
    docker_visible_args = " ".join(
        observed["create_args"] + observed["args"]
    )
    assert "model-secret" not in docker_visible_args
    assert "search-secret" not in docker_visible_args
    assert "session-cookie" not in json.dumps(observed["identity"])
    container_name = observed["create_args"][
        observed["create_args"].index("--name") + 1
    ]
    assert container_name == "numoj-agent-task-1"
    workspace = workspace_root / "sessions/task-1/workspace"
    docker_volumes = [
        observed["create_args"][index + 1]
        for index, value in enumerate(observed["create_args"])
        if value == "--volume"
    ]
    assert docker_volumes == [
        f"{workspace.resolve()}:/workspace:rw",
        (
            f"{(workspace / skill_path).parent.resolve()}:"
            f"/workspace/{Path(skill_path).parent.as_posix()}:ro"
        ),
    ]
    assert observed["create_args"][-4:] == [
        str(runtime.AGENT_JUDGE_DOCKER_IMAGE), "bash", "-lc", "tail -f /dev/null",
    ]
    assert observed["args"][:4] == ["docker", "exec", "-i", container_name]
    assert cleanups == [
        ["docker", "rm", "-f", container_name],
        ["docker", "rm", "-f", container_name],
    ]
    assert observed["tick_interval"] == runtime.AGENT_TRACE_SYNC_INTERVAL_SECONDS
    assert callable(observed["quota_check"])
    assert observed["quota_check_interval"] == (
        runtime.AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS
    )
    assert trace_updates == ["updated", "updated", "updated", "updated"]
    assert lifecycle == [
        "remove", "create", "sync", "exec", "sync", "sync", "sync", "remove",
    ]
    trace_dir = workspace_root / "traces/task-1"
    messages = collect_agent_trace_messages(trace_dir)
    assert [item["text"] for item in messages] == [
        (
            "旧身份 [REDACTED]；身份 [REDACTED] [REDACTED] "
            "[REDACTED]；已完成 [REDACTED]"
        ),
    ]
    assert not (trace_dir / ".agent_harness.stdout.tmp").exists()
    workspace = workspace_root / "sessions/task-1/workspace"
    assert workspace.is_dir()
    workspace_payload = b"\n".join(
        path.read_bytes()
        for path in workspace.rglob("*")
        if path.is_file()
    )
    assert b"model-secret" not in workspace_payload
    assert b"search-secret" not in workspace_payload
    assert "model-secret" not in result.stdout + result.stderr
    assert "search-secret" not in result.stdout + result.stderr
    assert endpoint_temporary not in result.stdout + result.stderr
    assert web_search_temporary not in result.stdout + result.stderr
    assert previous_temporary_secret not in result.stdout + result.stderr
    assert identity_base_url not in result.stdout + result.stderr
    assert identity_escaped_base_url not in result.stdout + result.stderr
    assert identity_authorization not in result.stdout + result.stderr
    assert identity_basic_payload not in result.stdout + result.stderr
    assert identity_userinfo not in result.stdout + result.stderr
    assert identity_temporary_secret not in result.stdout + result.stderr
    assert not (workspace / ".numoj-agent/identity.json").exists()
    assert (workspace / ".aj_session_state.json").is_file()
    redaction_history_path = (
        workspace.parent / agent_workspace._REDACTION_HISTORY_FILENAME
    )
    assert redaction_history_path.stat().st_mode & 0o777 == 0o600
    redaction_history = redaction_history_path.read_text(encoding="utf-8")
    assert previous_temporary_secret in redaction_history
    assert identity_temporary_secret in redaction_history
    assert endpoint_temporary in redaction_history
    assert web_search_temporary in redaction_history
    assert "session-cookie" not in redaction_history
    assert "model-secret" not in redaction_history
    assert "search-secret" not in redaction_history
    assert sorted(item.name for item in workspace_root.iterdir()) == [
        "sessions",
        "traces",
    ]


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
        stdout_capture_path=stdout_path,
        on_tick=lambda *, final=False: ticks.append(final),
        tick_interval=0.5,
    )

    assert result.returncode == 0
    assert stdout_path.read_bytes() == b'{"type":"one"}\n{"type":"two"}\n'
    assert ticks[-1] is True
    assert False in ticks


def test_bounded_runner_stops_docker_exec_when_task_is_canceled(monkeypatch):
    checks = []

    class FakeProcess:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.terminated = False
            self.killed = False

        def wait(self, timeout=None):
            if self.terminated:
                return -15
            raise runtime.subprocess.TimeoutExpired("docker", timeout)

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)

    result = runtime._run_with_bounded_output(
        ["docker"],
        "prompt",
        cancel_check=lambda: checks.append("checked") or True,
    )

    assert checks == ["checked"]
    assert process.terminated is True
    assert process.killed is False
    assert result.returncode == -15
    assert result.timed_out is False


def test_control_observer_reports_only_valid_numoj_acknowledgements():
    observed = []
    observer = runtime._ControlEventObserver(
        lambda command_id, status, error: observed.append(
            (command_id, status, error)
        ),
    )

    observer.feed(b'{"type":"numoj_con')
    observer.feed(
        b'trol","id":"steer-1","status":"accepted"}\n'
        b'{"type":"numoj_trace","version":1,"event":{}}\n'
        b'{"type":"numoj_control","id":"bad","status":"sent"}\n'
        b'{"type":"numoj_control","id":"stop-1","status":"rejected","error":"idle"}\n'
    )

    assert observed == [
        ("steer-1", "accepted", ""),
        ("stop-1", "rejected", "idle"),
    ]


def test_interactive_runner_keeps_stdin_open_and_forwards_control_ack(monkeypatch):
    allow_stdout = __import__("threading").Event()
    writes = []
    callbacks = []

    class Input:
        closed = False

        def write(self, payload):
            assert not self.closed
            writes.append(bytes(payload))

        def flush(self):
            return None

        def close(self):
            self.closed = True

    class Output:
        emitted = False

        def read(self, _size):
            if self.emitted:
                return b""
            assert allow_stdout.wait(2)
            self.emitted = True
            return (
                b'{"type":"numoj_control","version":1,'
                b'"id":"steer-1","status":"accepted"}\n'
            )

        def close(self):
            return None

    class FakeProcess:
        def __init__(self):
            self.stdin = Input()
            self.stdout = Output()
            self.stderr = io.BytesIO()

        def wait(self, timeout=None):
            if len(writes) < 2:
                raise runtime.subprocess.TimeoutExpired("docker", timeout)
            allow_stdout.set()
            return 0

        def kill(self):
            return None

    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: FakeProcess())
    queued = [[{
        "id": "steer-1",
        "type": "steer",
        "message": "改为检查失败测试",
        "target_task_id": "task-1",
    }], []]

    result = runtime._run_with_bounded_output(
        ["docker"],
        "先执行首轮",
        control_source=lambda: queued.pop(0) if queued else (),
        control_callback=lambda command_id, status, error="": callbacks.append(
            (command_id, status, error)
        ),
        control_target_task_id="task-1",
    )

    assert result.returncode == 0
    frames = [json.loads(item) for item in writes]
    assert frames == [
        {
            "type": "start",
            "id": "__start__",
            "message": "先执行首轮",
            "target_task_id": "task-1",
        },
        {
            "type": "steer",
            "id": "steer-1",
            "message": "改为检查失败测试",
            "target_task_id": "task-1",
        },
    ]
    assert callbacks == [("steer-1", "accepted", "")]


def test_interactive_runner_does_not_force_kill_after_interrupt_is_rejected(
        monkeypatch):
    import threading

    interrupt_written = threading.Event()
    callback_seen = threading.Event()
    process_finished = threading.Event()
    writes = []
    callbacks = []

    class Input:
        def write(self, payload):
            writes.append(bytes(payload))
            frame = json.loads(payload)
            if frame.get("type") == "interrupt":
                interrupt_written.set()

        def flush(self):
            return None

        def close(self):
            return None

    class Output:
        emitted = False

        def read(self, _size):
            if not self.emitted:
                assert interrupt_written.wait(1)
                self.emitted = True
                return (
                    b'{"type":"numoj_control","version":1,'
                    b'"id":"stop-1","status":"rejected","error":"idle"}\n'
                )
            assert process_finished.wait(1)
            return b""

        def close(self):
            return None

    class FakeProcess:
        def __init__(self):
            self.stdin = Input()
            self.stdout = Output()
            self.stderr = io.BytesIO()
            self.terminated = False
            self.killed = False
            self.after_ack_waits = 0

        def wait(self, timeout=None):
            if self.terminated:
                process_finished.set()
                return -15
            if not interrupt_written.is_set():
                raise runtime.subprocess.TimeoutExpired("docker", timeout)
            assert callback_seen.wait(1)
            self.after_ack_waits += 1
            if self.after_ack_waits < 3:
                raise runtime.subprocess.TimeoutExpired("docker", timeout)
            process_finished.set()
            return 0

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True
            self.terminated = True

    process = FakeProcess()
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monotonic = iter(float(index) for index in range(20))
    monkeypatch.setattr(runtime.time, "monotonic", lambda: next(monotonic))
    queued = [[{"id": "stop-1", "type": "interrupt"}], []]

    def on_control(command_id, status, error=""):
        callbacks.append((command_id, status, error))
        callback_seen.set()

    result = runtime._run_with_bounded_output(
        ["docker"],
        "prompt",
        control_source=lambda: queued.pop(0) if queued else (),
        control_callback=on_control,
        interrupt_grace_seconds=0.5,
    )

    assert result.returncode == 0
    assert process.terminated is False
    assert process.killed is False
    assert callbacks == [("stop-1", "rejected", "idle")]


def test_read_agent_steer_capability_marks_legacy_opencode_only(
        monkeypatch, tmp_path):
    workspace_root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(agent_workspace, "AGENT_WORKSPACE_ROOT", workspace_root)
    workspace = workspace_root / "sessions/s-1/workspace"
    workspace.mkdir(parents=True)
    (workspace / ".aj_session_state.json").write_text(json.dumps({
        "harness": "opencode",
        "session_id": "ses_legacy",
    }), encoding="utf-8")

    supported, reason = runtime.read_agent_steer_capability("s-1", "opencode")
    assert supported is False
    assert "兼容探测" in reason

    (workspace / ".aj_session_state.json").write_text(json.dumps({
        "harness": "opencode",
        "session_id": "ses_current",
        "interactive_supported": True,
    }), encoding="utf-8")
    assert runtime.read_agent_steer_capability("s-1", "opencode") == (True, "")


def test_read_agent_steer_capability_does_not_scan_workspace_quota(
        monkeypatch, tmp_path):
    workspace_root = tmp_path / "agent-workspaces"
    monkeypatch.setattr(agent_workspace, "AGENT_WORKSPACE_ROOT", workspace_root)
    workspace = workspace_root / "sessions/s-1/workspace"
    workspace.mkdir(parents=True)
    (workspace / ".aj_session_state.json").write_text(json.dumps({
        "harness": "codex",
        "session_id": "00000000-0000-0000-0000-000000000001",
        "interactive_supported": True,
    }), encoding="utf-8")
    monkeypatch.setattr(
        agent_workspace,
        "_check_workspace_quota_fd",
        lambda *_args, **_kwargs: pytest.fail("读取插话能力不应扫描 workspace 配额"),
    )

    assert runtime.read_agent_steer_capability("s-1", "codex") == (True, "")


def test_canonical_journal_precedes_legacy_and_keeps_usage_incremental(tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    (trace_dir / "codex_reverse_solve.jsonl").write_text(
        json.dumps({"type": "agent_message", "message": "legacy"}) + "\n",
        encoding="utf-8",
    )
    records = [
        {"type": "numoj_control", "version": 1, "id": "s1", "status": "accepted"},
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "kind": "thinking",
                "title": "思考片段",
                "text": "先检查边界",
                "meta": "codex",
            },
        },
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "kind": "assistant",
                "text": "已经完成",
                "meta": "codex",
            },
        },
        {
            "type": "numoj_usage",
            "version": 1,
            "source": "codex",
            "id": "turn-1",
            "usage": {
                "input_uncached_tokens": 90,
                "input_cached_tokens": 10,
                "input_cache_write_tokens": 0,
                "output_tokens": 20,
                "reasoning_output_tokens": 5,
            },
        },
    ]
    (trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME).write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )

    messages = collect_agent_trace_messages(trace_dir)
    usage = collect_agent_token_usage(trace_dir)

    assert [(item["kind"], item["text"]) for item in messages] == [
        ("thinking", "先检查边界"),
        ("assistant", "已经完成"),
    ]
    assert usage == {
        "request_count": 1,
        "input_uncached_tokens": 90,
        "input_cached_tokens": 10,
        "input_cache_write_tokens": 0,
        "input_total_tokens": 100,
        "output_tokens": 20,
        "reasoning_output_tokens": 5,
        "source": "codex",
        "incremental": True,
        "last_input_total_tokens": 100,
        "last_output_tokens": 20,
    }


def test_canonical_reader_keeps_oversized_final_assistant_record(tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    # 控制字符会被 JSON 转义为 6 bytes，覆盖 producer 最大 assistant
    # 字符预算接近规范单记录上限、后面仍跟随 usage 的尾读边界。
    oversized_text = "最终回复：" + "\x01" * (2 * 1024 * 1024 + 257)
    record = {
        "type": "numoj_trace",
        "version": 1,
        "event": {
            "kind": "assistant",
            "text": oversized_text,
            "meta": "codex",
        },
    }
    trailing_usage = {
        "type": "numoj_usage",
        "version": 1,
        "source": "codex",
        "id": "usage-after-large-assistant",
        "usage": {
            "input_uncached_tokens": 1,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 1,
            "reasoning_output_tokens": 0,
            "padding": "u" * (512 * 1024),
        },
    }
    (trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME).write_text(
        (
            json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            + "\n"
            + json.dumps(
                trailing_usage,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ),
        encoding="utf-8",
    )

    messages = collect_agent_trace_messages(trace_dir)

    assert len(messages) == 1
    assert messages[0]["kind"] == "assistant"
    assert messages[0]["text"].startswith("最终回复：")
    assert messages[0]["text"].endswith("…")


def test_canonical_reader_deduplicates_native_trace_and_usage_ids(tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    records = [
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "id": "assistant-1:text:0",
                "kind": "assistant",
                "text": "只展示一次",
            },
        },
        {
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "id": "assistant-1:text:0",
                "kind": "assistant",
                "text": "只展示一次",
            },
        },
        *[
            {
                "type": "numoj_usage",
                "version": 1,
                "source": "claude_code",
                "id": record_id,
                "usage": {
                    "input_uncached_tokens": input_tokens,
                    "input_cached_tokens": 0,
                    "input_cache_write_tokens": 0,
                    "output_tokens": output_tokens,
                    "reasoning_output_tokens": 0,
                },
            }
            for record_id, input_tokens, output_tokens in (
                ("assistant-1", 10, 3),
                ("assistant-2", 20, 5),
                ("assistant-1", 10, 3),
            )
        ],
    ]
    (trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME).write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )

    messages = collect_agent_trace_messages(trace_dir)
    usage = collect_agent_token_usage(trace_dir)

    assert [item["text"] for item in messages] == ["只展示一次"]
    assert usage["request_count"] == 2
    assert usage["input_total_tokens"] == 30
    assert usage["last_input_total_tokens"] == 20
    assert usage["last_output_tokens"] == 5
    assert usage["output_tokens"] == 8


def test_canonical_journal_keeps_early_usage_after_large_stdout_and_redacts(
    tmp_path,
):
    source = tmp_path / "canonical.tmp"
    secret = "temporary-secret"
    observer = runtime._CanonicalJournalObserver(source, secrets=(secret,))
    observer.feed(
        (
            json.dumps({
                "type": "numoj_usage",
                "version": 1,
                "source": "pi",
                "id": "early-request",
                "usage": {
                    "input_uncached_tokens": 11,
                    "input_cached_tokens": 2,
                    "input_cache_write_tokens": 0,
                    "output_tokens": 3,
                    "reasoning_output_tokens": 0,
                },
            })
            + "\n"
        ).encode("utf-8")
    )
    # 旧 stdout mirror 超过 8 MiB 后会裁掉头部；规范 observer 只追加
    # NumOJ 事件，因此大量非协议输出不会删除已经记录的 usage。
    observer.feed(b"x" * (runtime._STDOUT_MIRROR_LIMIT_BYTES + 1))
    observer.feed(
        b"\n"
        + (
            json.dumps({
                "type": "numoj_control",
                "version": 1,
                "id": "steer-boundary",
                "status": "accepted",
            })
            + "\n"
            + json.dumps({
                "type": "numoj_trace",
                "version": 1,
                "event": {
                    "kind": "assistant",
                    "text": f"done {secret}",
                },
            })
            + "\n"
        ).encode("utf-8")
    )
    observer.close()

    trace_dir = tmp_path / "trace"
    assert agent_traces.sync_agent_trace(
        "container",
        trace_dir,
        "pi",
        source,
        canonical=True,
    ) is True

    rendered = (
        trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME
    ).read_text(encoding="utf-8")
    assert '"type":"numoj_steer"' in rendered
    assert '"message_id":"steer-boundary"' in rendered
    assert "numoj_control" not in rendered
    assert secret not in rendered
    assert "[REDACTED]" in rendered
    assert collect_agent_token_usage(trace_dir)["input_total_tokens"] == 13


def test_canonical_steer_markers_require_opt_in_and_survive_trace_cap(tmp_path):
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    records = [{
        "type": "numoj_steer",
        "version": 1,
        "message_id": "steer-kept",
    }]
    records.extend({
        "type": "numoj_trace",
        "version": 1,
        "event": {
            "id": f"thinking-{index}",
            "kind": "thinking",
            "text": f"步骤 {index}",
        },
    } for index in range(245))
    (trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME).write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )

    judge_messages = collect_agent_trace_messages(trace_dir)
    agent_messages = collect_agent_trace_messages(
        trace_dir,
        include_steer_markers=True,
    )

    assert len(judge_messages) == 240
    assert all(item["kind"] != "steer" for item in judge_messages)
    assert len(agent_messages) == 240
    assert [
        item.get("message_id")
        for item in agent_messages
        if item["kind"] == "steer"
    ] == ["steer-kept"]
    assert sum(item["kind"] == "thinking" for item in agent_messages) == 239


def test_canonical_journal_capacity_pins_steer_boundary(tmp_path):
    source = tmp_path / "canonical.tmp"
    observer = runtime._CanonicalJournalObserver(source, max_bytes=4096)
    observer.feed((json.dumps({
        "type": "numoj_control",
        "version": 1,
        "id": "steer-pinned",
        "status": "accepted",
    }) + "\n").encode("utf-8"))
    for index in range(12):
        observer.feed((json.dumps({
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "id": f"tool-{index}:result",
                "kind": "tool_result",
                "text": "x" * 700,
            },
        }) + "\n").encode("utf-8"))
    observer.feed((json.dumps({
        "type": "numoj_trace",
        "version": 1,
        "event": {
            "id": "assistant-final",
            "kind": "assistant",
            "text": "最终交付",
        },
    }, ensure_ascii=False) + "\n").encode("utf-8"))
    observer.close()

    records = [
        json.loads(line)
        for line in source.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        item.get("type") == "numoj_steer"
        and item.get("message_id") == "steer-pinned"
        for item in records
    )
    assert any(
        item.get("type") == "numoj_trace"
        and item.get("event", {}).get("id") == "assistant-final"
        for item in records
    )
    assert source.stat().st_size <= 4096


def test_canonical_steer_stays_live_and_is_found_before_tail_window(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "canonical.tmp"
    observer = runtime._CanonicalJournalObserver(source)
    observer.feed((json.dumps({
        "type": "numoj_control",
        "version": 1,
        "id": "steer-in-prefix",
        "status": "accepted",
    }) + "\n").encode("utf-8"))
    observer.feed((json.dumps({
        "type": "numoj_trace",
        "version": 1,
        "event": {"kind": "thinking", "text": "仍在实时输出"},
    }, ensure_ascii=False) + "\n").encode("utf-8"))

    # steer 不能让 observer 提前进入只在 close 时刷新的滚动尾模式。
    assert "仍在实时输出" in source.read_text(encoding="utf-8")
    observer.close()

    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    rendered = source.read_bytes() + (b"x" * 512 + b"\n")
    (trace_dir / agent_traces.CANONICAL_AGENT_TRACE_FILENAME).write_bytes(rendered)
    monkeypatch.setattr(reverse_traces, "_CANONICAL_JSONL_TAIL_MAX_BYTES", 128)

    messages = collect_agent_trace_messages(
        trace_dir,
        include_steer_markers=True,
    )

    assert [
        message.get("message_id")
        for message in messages
        if message.get("kind") == "steer"
    ] == ["steer-in-prefix"]


def test_canonical_journal_keeps_adapter_usage_as_trace_only(tmp_path):
    source = tmp_path / "canonical.tmp"
    observer = runtime._CanonicalJournalObserver(source)
    records = [
        {
            "type": "numoj_usage",
            "version": 1,
            "source": "pi",
            "id": record_id,
            "usage": {
                "input_uncached_tokens": index,
                "output_tokens": 1,
            },
        }
        for index, record_id in enumerate(("request-1", "request-2"), 1)
    ]

    observer.feed(
        "".join(json.dumps(item) + "\n" for item in records).encode("utf-8")
    )
    observer.close()

    stored = [
        json.loads(line)
        for line in source.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["id"] for item in stored] == ["request-1", "request-2"]
    assert [item["usage"]["input_uncached_tokens"] for item in stored] == [
        1,
        2,
    ]


def test_canonical_journal_skips_usage_without_stable_trace_id(tmp_path):
    source = tmp_path / "canonical.tmp"
    observer = runtime._CanonicalJournalObserver(source)

    observer.feed((json.dumps({
        "type": "numoj_usage",
        "version": 1,
        "source": "codex",
        "id": "  ",
        "usage": {"input_uncached_tokens": 1, "output_tokens": 1},
    }) + "\n").encode("utf-8"))

    observer.close()
    assert source.read_bytes() == b""


def test_canonical_journal_capacity_keeps_final_assistant_and_usage(tmp_path):
    source = tmp_path / "canonical.tmp"
    observer = runtime._CanonicalJournalObserver(source, max_bytes=4096)
    for index in range(8):
        observer.feed((json.dumps({
            "type": "numoj_trace",
            "version": 1,
            "event": {
                "id": f"tool-{index}:result",
                "kind": "tool_result",
                "text": "x" * 900,
            },
        }) + "\n").encode("utf-8"))
    observer.feed((json.dumps({
        "type": "numoj_trace",
        "version": 1,
        "event": {
            "id": "assistant-final",
            "kind": "assistant",
            "text": "最终交付",
        },
    }, ensure_ascii=False) + "\n").encode("utf-8"))
    observer.feed((json.dumps({
        "type": "numoj_usage",
        "version": 1,
        "source": "codex",
        "id": "usage-final",
        "usage": {
            "input_uncached_tokens": 3,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 2,
            "reasoning_output_tokens": 0,
        },
    }) + "\n").encode("utf-8"))
    observer.close()

    records = [
        json.loads(line)
        for line in source.read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        item.get("type") == "numoj_trace"
        and item.get("event", {}).get("id") == "assistant-final"
        for item in records
    )
    assert any(
        item.get("type") == "numoj_usage"
        and item.get("id") == "usage-final"
        for item in records
    )
    assert source.stat().st_size <= 4096


def test_bounded_runner_propagates_quota_failure_and_kills_docker_exec(
    monkeypatch,
):
    checks = []

    class FakeProcess:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.killed = False

        def wait(self, timeout=None):
            if self.killed:
                return -9
            raise runtime.subprocess.TimeoutExpired("docker", timeout)

        def kill(self):
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr(runtime.subprocess, "Popen", lambda *_args, **_kwargs: process)

    def reject_quota():
        checks.append("checked")
        raise agent_workspace.AgentWorkspaceQuotaError("workspace quota exceeded")

    with pytest.raises(
        agent_workspace.AgentWorkspaceQuotaError,
        match="quota exceeded",
    ):
        runtime._run_with_bounded_output(
            ["docker"],
            "prompt",
            quota_check=reject_quota,
            quota_check_interval=0.5,
        )

    assert checks == ["checked"]
    assert process.killed is True


def test_tail_reader_drains_mirror_while_result_capture_stays_bounded():
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


def test_tail_reader_prefers_available_pipe_bytes_over_waiting_for_full_block():
    class InteractivePipe:
        def __init__(self):
            self.blocks = iter((b'{"type":"numoj_trace"}\n', b""))
            self.closed = False

        def read1(self, size):
            assert size == 65536
            return next(self.blocks)

        def read(self, _size):
            raise AssertionError("交互管道不能使用等待填满的 read(size)")

        def close(self):
            self.closed = True

    stream = InteractivePipe()
    chunks = runtime.deque()
    sizes = {"stdout": 0}
    observed = []

    runtime._tail_reader(
        stream,
        chunks,
        sizes,
        "stdout",
        runtime._CAPTURE_LIMIT_BYTES,
        block_observer=observed.append,
    )

    assert observed == [b'{"type":"numoj_trace"}\n']
    assert stream.closed is True


def test_stdout_mirror_publishes_a_bounded_record_aligned_tail(tmp_path):
    destination = tmp_path / "stdout.jsonl"
    records = [f'{{"n":{index}}}\n'.encode("ascii") for index in range(1, 5)]
    mirror = runtime._BoundedStdoutMirror(destination, 17)

    for record in records:
        mirror.write(record)
    assert mirror.publish() is True
    mirror.close()

    rendered = destination.read_bytes()
    assert rendered == b"".join(records[-2:])
    assert len(rendered) <= 17


def test_bounded_runner_uses_bounded_stdout_mirror(monkeypatch, tmp_path):
    destination = tmp_path / "stdout.jsonl"
    records = [f'{{"n":{index}}}\n'.encode("ascii") for index in range(1, 5)]

    class FakeProcess:
        def __init__(self):
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(b"".join(records))
            self.stderr = io.BytesIO()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    monkeypatch.setattr(
        runtime.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(runtime, "_STDOUT_MIRROR_LIMIT_BYTES", 17)

    result = runtime._run_with_bounded_output(
        ["docker"],
        "prompt",
        stdout_capture_path=destination,
    )

    assert result.returncode == 0
    assert destination.read_bytes() == b"".join(records[-2:])


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


def test_container_cleanup_confirms_another_removal_has_finished(monkeypatch):
    calls = []
    responses = iter((
        SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=(
                "Error response from daemon: removal of container "
                "numoj-agent-task-1 is already in progress"
            ),
        ),
        SimpleNamespace(returncode=0, stdout='{"Id":"abc"}', stderr=""),
        SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Error: No such object: numoj-agent-task-1",
        ),
    ))

    def run(command, **_kwargs):
        calls.append(command)
        return next(responses)

    monkeypatch.setattr(runtime.subprocess, "run", run)
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)

    runtime._remove_agent_container("numoj-agent-task-1")

    assert calls == [
        ["docker", "rm", "-f", "numoj-agent-task-1"],
        ["docker", "container", "inspect", "numoj-agent-task-1"],
        ["docker", "container", "inspect", "numoj-agent-task-1"],
    ]
