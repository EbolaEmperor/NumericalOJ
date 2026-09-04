# -*- coding: utf-8 -*-
"""Agent Judge 镜像入口必须边执行边转发 CLI 输出。"""

import importlib.machinery
import importlib.util
import http.server
import io
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker" / "agent_judge" / "run_harness"


def _load_run_harness():
    loader = importlib.machinery.SourceFileLoader("agent_judge_run_harness_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _set_endpoint(
        monkeypatch, *, protocol="openai", model="generic-model",
        base_url=None, api_key="temporary-token"):
    monkeypatch.setenv("AJ_ENDPOINT_PROTOCOL", protocol)
    monkeypatch.setenv(
        "AJ_ENDPOINT_BASE_URL",
        base_url or (
            "https://model.example/anthropic"
            if protocol == "anthropic" else "https://model.example/v1"
        ),
    )
    monkeypatch.setenv("AJ_ENDPOINT_API_KEY", api_key)
    monkeypatch.setenv("AJ_ENDPOINT_MODEL", model)


def _set_anthropic_endpoint(monkeypatch, module, model="generic-model"):
    _set_endpoint(monkeypatch, protocol="anthropic", model=model)

    class FakeRelay:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            return "http://127.0.0.1:43123"

        def stop(self):
            pass

    monkeypatch.setattr(module, "_ClaudeEndpointRelay", FakeRelay)


@pytest.mark.parametrize(
    ("task_scope", "expected_kwargs"),
    [
        ("problem_agent", {}),
        ("", {"timeout": 300}),
    ],
)
def test_endpoint_relay_only_removes_request_timeout_for_ordinary_agent(
    monkeypatch,
    task_scope,
    expected_kwargs,
):
    module = _load_run_harness()
    calls = []

    class Opener:
        def open(self, request, **kwargs):
            calls.append((request, kwargs))
            return "response"

    if task_scope:
        monkeypatch.setenv("AJ_TASK_SCOPE", task_scope)
    else:
        monkeypatch.delenv("AJ_TASK_SCOPE", raising=False)
    request = object()

    assert module._open_endpoint_request(Opener(), request) == "response"
    assert calls == [(request, expected_kwargs)]


def test_run_relays_first_line_before_child_exits(monkeypatch, tmp_path):
    module = _load_run_harness()
    first_line = threading.Event()
    writes = []
    result = []

    class Recorder:
        def write(self, value):
            writes.append(value)
            if "first" in value:
                first_line.set()

        def flush(self):
            return None

    monkeypatch.setattr(module.sys, "stdout", Recorder())
    release = tmp_path / "release"
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,time; print('first',flush=True); "
            f"p=pathlib.Path({str(release)!r}); "
            "exec(\"while not p.exists():\\n time.sleep(0.02)\"); "
            "print('second',flush=True)"
        ),
    ]
    env = dict(os.environ, AJ_WORKSPACE=str(tmp_path))
    worker = threading.Thread(target=lambda: result.append(module._run(command, env=env)))
    worker.start()

    assert first_line.wait(3)
    assert worker.is_alive(), "收到 first 时子进程应仍在执行，证明不是结束后一次性回放"
    release.write_text("go", encoding="utf-8")
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert result[0].returncode == 0
    assert result[0].stdout == "first\nsecond\n"
    assert "".join(writes) == "first\nsecond\n"


def test_claude_audit_mode_is_bare_safe_and_read_tools_only(monkeypatch):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "1")
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setattr(
        module, "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs)) or SimpleNamespace(
            returncode=0, stdout="{}", stderr="",
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("audit prompt") == 0

    args, kwargs = calls[0]
    assert args[0] == "claude"
    assert "--bare" in args
    assert "--safe-mode" in args
    assert "--disable-slash-commands" in args
    assert "--no-session-persistence" in args
    assert args[args.index("--tools") + 1] == "Read,Glob,Grep"
    assert args[args.index("--allowed-tools") + 1] == "Read,Glob,Grep"
    assert args[args.index("--add-dir") + 1] == "/evidence"
    assert args[args.index("--output-format") + 1] == "json"
    assert args[args.index("--model") + 1] == "generic-model[1m]"
    assert args[-1] == "audit prompt"
    assert "--dangerously-skip-permissions" not in args
    assert "--resume" not in args
    assert "--fork-session" not in args
    assert all(forbidden not in ",".join(args) for forbidden in ("Bash", "Write", "Edit"))
    assert kwargs["env"]["CLAUDE_CODE_MAX_CONTEXT_TOKENS"] == "1000000"
    assert kwargs["env"]["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] == "384000"
    assert kwargs["env"]["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] == "1000000"
    assert kwargs["env"]["CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK"] == "1"
    assert "CLAUDE_CODE_DISABLE_THINKING" not in kwargs["env"]
    assert "DISABLE_INTERLEAVED_THINKING" not in kwargs["env"]


@pytest.mark.parametrize(("configured", "expected"), [
    (" HIGH ", "high"),
    ("xhigh", "xhigh"),
    ("turbo", None),
    ("", None),
])
def test_claude_effort_argument_is_normalized_and_allowlisted(
        monkeypatch, configured, expected):
    module = _load_run_harness()
    calls = []
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "0")
    monkeypatch.setenv("AJ_EFFORT", configured)
    monkeypatch.delenv("AJ_RESUME_SESSION_ID", raising=False)
    monkeypatch.setattr(
        module, "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs)) or SimpleNamespace(
            returncode=0, stdout="{}", stderr="",
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("solve") == 0

    args, _kwargs = calls[0]
    if expected is None:
        assert "--effort" not in args
    else:
        assert args[args.index("--effort") + 1] == expected


def test_claude_print_harness_keeps_lifecycle_out_of_model_prompts(
        monkeypatch):
    module = _load_run_harness()
    calls = []
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "0")
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs))
        or SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("research") == 0

    args, _kwargs = calls[0]
    assert "--append-system-prompt" not in args
    assert "--disallowed-tools" not in args


def test_claude_endpoint_capabilities_can_disable_thinking(monkeypatch):
    module = _load_run_harness()
    calls = []
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "131072")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "16384")
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_ENABLED", "false")
    monkeypatch.setenv("AJ_EFFORT", "high")
    monkeypatch.setattr(
        module, "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs)) or SimpleNamespace(
            returncode=0, stdout="{}", stderr="",
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("solve") == 0

    args, kwargs = calls[0]
    assert "--effort" not in args
    assert kwargs["env"]["CLAUDE_CODE_MAX_CONTEXT_TOKENS"] == "131072"
    assert kwargs["env"]["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] == "16384"
    assert kwargs["env"]["CLAUDE_CODE_DISABLE_THINKING"] == "1"
    assert kwargs["env"]["DISABLE_INTERLEAVED_THINKING"] == "1"


def test_claude_relay_only_overrides_main_streaming_messages_request():
    module = _load_run_harness()
    streaming = json.loads(module._rewrite_claude_request_body(
        "/v1/messages?beta=true",
        json.dumps({"stream": True, "max_tokens": 128_000}).encode("utf-8"),
        384_000,
        upstream_model="configured-model",
    ))
    internal = json.loads(module._rewrite_claude_request_body(
        "/v1/messages",
        json.dumps({"stream": False, "max_tokens": 8}).encode("utf-8"),
        384_000,
        upstream_model="configured-model",
    ))

    assert streaming["max_tokens"] == 384_000
    assert internal["max_tokens"] == 8
    assert streaming["model"] == "configured-model"
    assert internal["model"] == "configured-model"


@pytest.mark.parametrize(
    ("thinking_format", "enabled", "expected"),
    [
        ("thinking_type", True, {"thinking": {"type": "adaptive"}}),
        ("thinking_type", False, {}),
        ("none", False, {}),
    ],
)
def test_claude_messages_rewrite_uses_frozen_thinking_format(
        thinking_format, enabled, expected):
    module = _load_run_harness()
    raw = {
        "stream": True,
        "max_tokens": 128,
        "thinking": {"type": "stale"},
        "enable_thinking": True,
    }

    rewritten = json.loads(module._rewrite_claude_request_body(
        "/v1/messages",
        json.dumps(raw).encode("utf-8"),
        16_384,
        thinking_format,
        enabled,
    ))

    assert "enable_thinking" not in rewritten
    assert {key: rewritten[key] for key in expected} == expected
    if thinking_format == "none":
        assert "thinking" not in rewritten


@pytest.mark.parametrize(
    ("protocol", "path", "thinking_format", "enabled", "expected"),
    [
        ("openai", "/v1/chat/completions", "enable_thinking", True,
         {"enable_thinking": True}),
        ("openai", "/v1/chat/completions", "none", False, {}),
        ("anthropic", "/v1/messages", "thinking_type", True,
         {"thinking": {"type": "adaptive"}}),
        ("anthropic", "/v1/messages", "thinking_type", False, {}),
    ],
)
def test_pi_dual_protocol_relay_rewrites_real_request_shape(
        protocol, path, thinking_format, enabled, expected):
    module = _load_run_harness()
    relay = module._EndpointThinkingRelay(
        "https://upstream.example/v1",
        protocol,
        thinking_format,
        enabled,
    )
    raw = json.dumps({
        "model": "model",
        "messages": [],
        "thinking": {"type": "stale"},
        "enable_thinking": True,
    }).encode("utf-8")

    rewritten = json.loads(relay._rewrite_request_body(path, raw))

    assert {key: rewritten[key] for key in expected} == expected
    if "enable_thinking" not in expected:
        assert "enable_thinking" not in rewritten
    if "thinking" not in expected:
        assert "thinking" not in rewritten


def test_claude_run_uses_local_relay_and_stops_it(monkeypatch):
    module = _load_run_harness()
    events = []
    calls = []
    _set_endpoint(monkeypatch, protocol="anthropic", model="custom-model")
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "1000000")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "384000")

    class FakeRelay:
        def __init__(self, base_url, max_output_tokens, **kwargs):
            events.append(("init", base_url, max_output_tokens, kwargs))

        def start(self):
            events.append(("start",))
            return "http://127.0.0.1:45678"

        def stop(self):
            events.append(("stop",))

    monkeypatch.setattr(module, "_ClaudeEndpointRelay", FakeRelay)
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs))
        or SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: None)

    assert module._run_claude_code("solve") == 0

    assert events == [
        (
            "init",
            "https://model.example/anthropic",
            384_000,
            {"upstream_model": "custom-model"},
        ),
        ("start",),
        ("stop",),
    ]
    args, kwargs = calls[0]
    assert args[args.index("--model") + 1] == "custom-model[1m]"
    assert kwargs["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:45678"


def test_endpoint_capabilities_allow_context_above_one_million(monkeypatch):
    module = _load_run_harness()
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "2000000")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "32000")

    assert module._endpoint_model_capabilities()[:2] == (2_000_000, 32_000)


def test_claude_uses_strict_runtime_mcp_config_without_persisting_secret(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    calls = []
    runtime_root = tmp_path / "runtime"
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("AJ_RUNTIME_ROOT", str(runtime_root))
    monkeypatch.setenv("AJ_WEB_SEARCH_MCP_URL", "https://search.example/mcp")
    monkeypatch.setenv(
        "AJ_WEB_SEARCH_MCP_AUTHORIZATION",
        "Bearer must-not-be-written",
    )
    monkeypatch.setenv("AJ_WEB_SEARCH_MCP_TIMEOUT_SECONDS", "41")
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs))
        or SimpleNamespace(returncode=0, stdout="{}", stderr=""),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("solve") == 0

    args, kwargs = calls[0]
    assert "--strict-mcp-config" in args
    config_path = Path(args[args.index("--mcp-config") + 1])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config == {
        "mcpServers": {
            "numoj_web_search": {
                "type": "http",
                "url": "https://search.example/mcp",
                "headers": {
                    "Authorization": "${AJ_WEB_SEARCH_MCP_AUTHORIZATION}",
                },
                "timeout": 41_000,
            },
        },
    }
    assert "must-not-be-written" not in config_path.read_text(encoding="utf-8")
    assert kwargs["env"]["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == (
        "Bearer must-not-be-written"
    )


def test_endpoint_relay_path_join_preserves_base_and_request_queries():
    module = _load_run_harness()

    assert module._relay_upstream_url(
        "https://api.example.test/tenant/v1/?api-version=2026-08-01",
        "/v1/responses?stream=true",
    ) == (
        "https://api.example.test/tenant/v1/responses"
        "?api-version=2026-08-01&stream=true"
    )
    assert module._relay_upstream_url(
        "https://api.example.test/anthropic?api-version=2026-08-01",
        "/v1/messages",
    ) == (
        "https://api.example.test/anthropic/v1/messages"
        "?api-version=2026-08-01"
    )


@pytest.mark.parametrize(
    ("runner_name", "protocol"),
    [
        (
            "_run_claude_code",
            "anthropic",
        ),
        (
            "_run_pi",
            "openai",
        ),
    ],
)
@pytest.mark.parametrize("missing_name", [
    "AJ_ENDPOINT_BASE_URL", "AJ_ENDPOINT_API_KEY", "AJ_ENDPOINT_MODEL",
])
def test_all_harnesses_require_a_complete_endpoint(
        monkeypatch, runner_name, protocol, missing_name):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, protocol=protocol)
    monkeypatch.delenv(missing_name, raising=False)
    monkeypatch.setattr(
        module, "_run",
        lambda *_args, **_kwargs: pytest.fail("端点配置不完整时不得启动 harness"),
    )

    assert getattr(module, runner_name)("solve") == 2


@pytest.mark.parametrize(("runner_name", "protocol"), [
    ("_run_claude_code", "anthropic"),
    ("_run_pi", "openai"),
])
def test_all_harnesses_reject_invalid_endpoint_capabilities(
        monkeypatch, runner_name, protocol):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, protocol=protocol)
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "8192")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "16384")
    monkeypatch.setattr(
        module, "_run",
        lambda *_args, **_kwargs: pytest.fail("能力配置非法时不得启动 harness"),
    )

    assert getattr(module, runner_name)("solve") == 2


def test_pi_uses_isolated_openai_chat_config_and_resumes_same_session(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    session_dir = config_dir / "sessions"
    calls = []
    recorded = []
    resume_id = "44444444-4444-4444-4444-444444444444"
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(session_dir))
    _set_endpoint(
        monkeypatch,
        model="custom-reasoning-model",
        base_url="http://answer-model-proxy:18080/v1",
    )
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", resume_id)
    monkeypatch.setenv("AJ_PHASE", "reverse_solve")
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "1000000")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "384000")
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_ENABLED", "true")

    def run(args, env=None, input_text=None, stdout_session_only=False):
        calls.append((
            list(args), dict(env or {}), input_text, stdout_session_only,
        ))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                '{"type":"session","version":3,'
                '"id":"44444444-4444-4444-4444-444444444444"}\n'
                '{"type":"agent_end","messages":[]}\n'
            ),
            stderr="",
        )

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *args: recorded.append(args) or resume_id,
    )

    assert module._run_pi("solve prompt") == 0

    args, env, input_text, stdout_session_only = calls[0]
    assert args[:3] == ["pi", "--mode", "json"]
    assert args[args.index("--provider") + 1] == "agent-judge"
    assert args[args.index("--model") + 1] == "custom-reasoning-model"
    assert args[args.index("--session") + 1] == resume_id
    assert args[-1] == "solve prompt"
    assert input_text is None
    assert stdout_session_only is True
    for flag in (
        "--no-approve",
        "--no-extensions",
        "--no-skills",
        "--no-prompt-templates",
        "--no-themes",
    ):
        assert flag in args
    assert "--no-context-files" not in args
    assert "--thinking" not in args
    assert "--tools" not in args
    assert env["AJ_ENDPOINT_API_KEY"] == "temporary-token"
    assert env["PI_CODING_AGENT_DIR"] == str(config_dir)
    assert env["PI_CODING_AGENT_SESSION_DIR"] == str(session_dir)
    assert env["PI_OFFLINE"] == "1"
    assert env["PI_TELEMETRY"] == "0"
    assert env["PI_SKIP_VERSION_CHECK"] == "1"
    config = json.loads((config_dir / "models.json").read_text(encoding="utf-8"))
    provider = config["providers"]["agent-judge"]
    assert provider == {
        "baseUrl": "http://answer-model-proxy:18080/v1",
        "api": "openai-completions",
        "apiKey": "$AJ_ENDPOINT_API_KEY",
        "authHeader": True,
        "compat": {
            "supportsStore": False,
            "supportsDeveloperRole": False,
            "maxTokensField": "max_tokens",
        },
        "models": [{
            "id": "custom-reasoning-model",
            "name": "custom-reasoning-model",
            "reasoning": True,
            "input": ["text"],
            "contextWindow": 1_000_000,
            "maxTokens": 384_000,
        }],
    }
    assert recorded[0][0] == "pi"
    assert recorded[0][2] == resume_id


def test_pi_problem_agent_runs_exactly_one_native_cli_turn(monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    session_dir = config_dir / "sessions"
    session_id = "44444444-4444-4444-4444-444444444444"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(session_dir))
    monkeypatch.delenv("AJ_PHASE", raising=False)
    monkeypatch.delenv("AJ_AUDIT_READ_ONLY", raising=False)
    monkeypatch.delenv("AJ_RESUME_SESSION_ID", raising=False)
    monkeypatch.setenv("AJ_TASK_SCOPE", "problem_agent")
    _set_endpoint(monkeypatch)

    def run(args, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *_args, **_kwargs: session_id,
    )

    assert module._run_pi("solve") == 0

    assert len(calls) == 1
    assert "--session" not in calls[0]
    assert calls[0][-1] == "solve"
    assert "--thinking" not in calls[0]


def test_pi_explicitly_loads_only_the_trusted_web_search_mcp_extension(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(config_dir / "sessions"))
    _set_endpoint(monkeypatch)
    monkeypatch.setenv("AJ_WEB_SEARCH_MCP_URL", "https://search.example/mcp")
    monkeypatch.setenv("AJ_WEB_SEARCH_MCP_AUTHORIZATION", "Bearer search-secret")
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs))
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_pi("solve") == 0

    args, kwargs = calls[0]
    assert "--no-extensions" in args
    assert args[args.index("--extension") + 1] == (
        module.PI_WEB_SEARCH_MCP_EXTENSION
    )
    assert kwargs["env"]["AJ_WEB_SEARCH_MCP_AUTHORIZATION"] == (
        "Bearer search-secret"
    )


@pytest.mark.parametrize(
    ("phase", "effort", "expected_thinking"),
    [
        ("reverse_solve", "high", "high"),
        ("reverse_finalize", "max", "off"),
    ],
)
def test_pi_thinking_compatible_endpoint_controls_reverse_phase_thinking(
        monkeypatch, tmp_path, phase, effort, expected_thinking):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(config_dir / "sessions"))
    _set_endpoint(
        monkeypatch,
        model="custom-reasoning-model",
        base_url="http://answer-model-proxy:18080/v1",
    )
    monkeypatch.setenv("AJ_PHASE", phase)
    monkeypatch.setenv("AJ_EFFORT", effort)
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_ENABLED", "true")

    def run(args, _env=None, **_kwargs):
        calls.append(list(args))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_record_session", lambda *_args: "")

    assert module._run_pi("solve prompt") == 0
    args = calls[0]
    assert args[args.index("--thinking") + 1] == expected_thinking


def test_pi_endpoint_capabilities_are_model_agnostic_and_can_disable_thinking(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    module._write_pi_models_config(
        str(config_dir), "https://model.example/v1", "generic-model",
        context_window_tokens=131_072,
        max_output_tokens=16_384,
        thinking_compatibility=False,
    )

    config = json.loads((config_dir / "models.json").read_text(encoding="utf-8"))
    model = config["providers"]["agent-judge"]["models"][0]
    assert model == {
        "id": "generic-model",
        "name": "generic-model",
        "contextWindow": 131_072,
        "maxTokens": 16_384,
    }


def test_pi_anthropic_provider_config_uses_messages_without_openai_compat(tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"

    module._write_pi_models_config(
        str(config_dir),
        "http://answer-model-proxy:18080/anthropic",
        "generic-model",
        thinking_compatibility=True,
        protocol="anthropic",
    )

    config = json.loads((config_dir / "models.json").read_text(encoding="utf-8"))
    provider = config["providers"]["agent-judge"]
    assert provider["api"] == "anthropic-messages"
    assert provider["apiKey"] == "$AJ_ENDPOINT_API_KEY"
    assert provider["baseUrl"] == "http://answer-model-proxy:18080/anthropic"
    assert "authHeader" not in provider
    assert "compat" not in provider


def test_run_pi_anthropic_protocol_reads_anthropic_environment(monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(config_dir / "sessions"))
    monkeypatch.setenv("AJ_ENDPOINT_PROTOCOL", "anthropic")
    _set_endpoint(
        monkeypatch,
        protocol="anthropic",
        model="generic-model",
        base_url="http://answer-model-proxy:18080/anthropic",
    )
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, env=None, **_kwargs: (
            calls.append((list(args), dict(env or {})))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_pi("solve") == 0

    args, env = calls[0]
    assert args[args.index("--model") + 1] == "generic-model"
    assert env["AJ_ENDPOINT_API_KEY"] == "temporary-token"
    provider = json.loads(
        (config_dir / "models.json").read_text(encoding="utf-8")
    )["providers"]["agent-judge"]
    assert provider["api"] == "anthropic-messages"
    assert "must-not-use" not in json.dumps(provider)


def test_pi_thinking_config_is_model_agnostic(tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"

    module._write_pi_models_config(
        str(config_dir), "https://model.example/v1", "generic-model",
        thinking_compatibility=True,
    )

    config = json.loads((config_dir / "models.json").read_text(encoding="utf-8"))
    model = config["providers"]["agent-judge"]["models"][0]
    assert model["reasoning"] is True
    assert model["input"] == ["text"]
    assert "thinkingLevelMap" not in model
    assert "compat" not in model


def test_pi_audit_mode_uses_only_read_tools_and_never_resumes(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(config_dir / "sessions"))
    _set_endpoint(monkeypatch)
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "1")
    monkeypatch.setenv(
        "AJ_RESUME_SESSION_ID", "44444444-4444-4444-4444-444444444444",
    )
    monkeypatch.setattr(
        module, "_run",
        lambda args, **kwargs: calls.append((list(args), kwargs)) or SimpleNamespace(
            returncode=0, stdout='{"type":"agent_end","messages":[]}', stderr="",
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_pi("audit") == 0

    args, _kwargs = calls[0]
    assert args[args.index("--tools") + 1] == "read,grep,find,ls"
    assert "--session" not in args
    assert all(tool not in args[args.index("--tools") + 1].split(",") for tool in (
        "bash", "write", "edit",
    ))


def test_pi_disabled_thinking_compatibility_omits_thinking_cli_flag(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(config_dir / "sessions"))
    _set_endpoint(monkeypatch)
    monkeypatch.setenv("AJ_PHASE", "reverse_finalize")
    monkeypatch.setenv("AJ_EFFORT", "max")
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_ENABLED", "false")
    monkeypatch.setattr(
        module, "_run",
        lambda args, **_kwargs: calls.append(list(args)) or SimpleNamespace(
            returncode=0, stdout="", stderr="",
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args: "")

    assert module._run_pi("solve") == 0
    assert "--thinking" not in calls[0]
    config = json.loads((config_dir / "models.json").read_text(encoding="utf-8"))
    model = config["providers"]["agent-judge"]["models"][0]
    provider = config["providers"]["agent-judge"]
    assert model["contextWindow"] == 1_000_000
    assert model["maxTokens"] == 384_000
    assert "reasoning" not in model
    assert "thinkingLevelMap" not in model
    assert "compat" not in model
    assert provider["compat"]["supportsDeveloperRole"] is False


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "0"),
        ("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "not-a-number"),
        ("AJ_ENDPOINT_THINKING_ENABLED", "maybe"),
    ],
)
def test_pi_rejects_invalid_endpoint_capability_env(monkeypatch, name, value):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, model="model", api_key="secret")
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("能力配置非法时不得启动 Pi"),
    )

    assert module._run_pi("solve") == 2


def test_pi_rejects_output_limit_larger_than_context(monkeypatch):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, model="model", api_key="secret")
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "8192")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "16384")
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("能力配置非法时不得启动 Pi"),
    )

    assert module._run_pi("solve") == 2


@pytest.mark.parametrize("missing_name", [
    "AJ_ENDPOINT_BASE_URL",
    "AJ_ENDPOINT_API_KEY",
    "AJ_ENDPOINT_MODEL",
])
def test_pi_requires_complete_openai_endpoint(monkeypatch, missing_name):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, model="model", api_key="secret")
    monkeypatch.delenv(missing_name)
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("配置不完整时不得启动 Pi"),
    )

    assert module._run_pi("solve") == 2


def test_pi_session_header_id_is_recorded_with_existing_minimal_schema(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    state_path = tmp_path / "session.json"
    session_id = "55555555-5555-5555-5555-555555555555"
    monkeypatch.setenv("AJ_SESSION_STATE", str(state_path))
    monkeypatch.setenv("AJ_PHASE", "reverse_solve")
    proc = SimpleNamespace(
        returncode=0,
        stdout=(
            f'{{"type":"session","version":3,"id":"{session_id}"}}\n'
            '{"type":"agent_end","messages":[{"role":"assistant","content":"done"}]}\n'
        ),
        stderr="",
    )

    assert module._record_session("pi", proc) == session_id
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "harness": "pi",
        "phase": "reverse_solve",
        "session_id": session_id,
        "resume_session_id": "",
        "returncode": 0,
    }
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600


def test_session_state_atomic_replace_preserves_existing_permissions(tmp_path):
    module = _load_run_harness()
    state_path = tmp_path / "session.json"
    state_path.write_text("{}", encoding="utf-8")
    state_path.chmod(0o666)

    module._write_session_event(str(state_path), {"session_id": "session-id"})

    assert stat.S_IMODE(state_path.stat().st_mode) == 0o666
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "session_id": "session-id",
    }


def test_run_preserves_pi_session_id_when_header_falls_out_of_tail_capture(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    session_id = "66666666-6666-6666-6666-666666666666"
    command = [
        sys.executable,
        "-c",
        (
            f"print('{{\"type\":\"session\",\"version\":3,\"id\":\"{session_id}\"}}');"
            "print('x' * 4096)"
        ),
    ]
    env = dict(
        os.environ,
        AJ_WORKSPACE=str(tmp_path),
        AJ_CAPTURE_MAX_CHARS="1024",
        AJ_HARNESS="pi",
        AJ_SESSION_STATE=str(tmp_path / "live-session.json"),
    )

    proc = module._run(command, env=env)

    assert session_id not in proc.stdout
    assert proc.aj_session_id == session_id
    assert json.loads((tmp_path / "live-session.json").read_text(encoding="utf-8")) == {
        "harness": "pi",
        "phase": "",
        "session_id": session_id,
        "resume_session_id": "",
        "returncode": None,
        "running": True,
    }


def test_run_persists_native_session_before_child_finishes(monkeypatch, tmp_path):
    module = _load_run_harness()
    session_id = "88888888-8888-8888-8888-888888888888"
    state_path = tmp_path / "live-session.json"
    release = tmp_path / "release"
    result = []
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib,time; "
            f"print('{{\"type\":\"session\",\"version\":3,\"id\":\"{session_id}\"}}',flush=True); "
            f"p=pathlib.Path({str(release)!r}); "
            "exec(\"while not p.exists():\\n time.sleep(0.02)\")"
        ),
    ]
    env = dict(
        os.environ,
        AJ_WORKSPACE=str(tmp_path),
        AJ_HARNESS="pi",
        AJ_SESSION_STATE=str(state_path),
    )
    worker = threading.Thread(
        target=lambda: result.append(module._run(command, env=env)),
        daemon=True,
    )
    worker.start()

    try:
        for _attempt in range(150):
            if state_path.exists():
                break
            threading.Event().wait(0.02)

        assert state_path.exists()
        assert worker.is_alive()
        assert json.loads(
            state_path.read_text(encoding="utf-8")
        )["session_id"] == session_id
    finally:
        release.write_text("go", encoding="utf-8")
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert result[0].returncode == 0


def test_run_can_forward_only_pi_session_header_while_consuming_json_stream(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    session_id = "77777777-7777-7777-7777-777777777777"
    writes = []

    class Recorder:
        def write(self, value):
            writes.append(value)

        def flush(self):
            return None

    monkeypatch.setattr(module.sys, "stdout", Recorder())
    command = [
        sys.executable,
        "-c",
        (
            f"print('{{\"type\":\"session\",\"version\":3,\"id\":\"{session_id}\"}}');"
            "print('{\"type\":\"message_update\",\"delta\":\"model-controlled\"}');"
            "print('{\"type\":\"agent_end\"}')"
        ),
    ]
    env = dict(os.environ, AJ_WORKSPACE=str(tmp_path))

    proc = module._run(command, env=env, stdout_session_only=True)

    relayed = "".join(writes)
    assert proc.returncode == 0
    assert proc.aj_session_id == session_id
    assert relayed == (
        f'{{"type":"session","version":3,"id":"{session_id}"}}\n'
    )
    assert "message_update" not in relayed
    assert "agent_end" not in relayed


@pytest.mark.parametrize("alias", ["pi", "pi-agent", "pi_agent"])
def test_main_dispatches_pi_aliases(monkeypatch, alias):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_HARNESS", alias)
    monkeypatch.setenv("AJ_PROMPT", "solve")
    monkeypatch.setattr(
        module,
        "_run_pi",
        lambda prompt: calls.append(prompt) or 0,
    )

    assert module.main() == 0
    assert calls == ["solve"]


def test_main_keeps_empty_harness_claude_default(monkeypatch):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_HARNESS", "")
    monkeypatch.setenv("AJ_PROMPT", "solve")
    monkeypatch.setattr(
        module,
        "_run_claude_code",
        lambda prompt: calls.append(prompt) or 0,
    )
    monkeypatch.setattr(
        module,
        "_run_pi",
        lambda _prompt: pytest.fail("未知 harness 不能误入 Pi 分支"),
    )

    assert module.main() == 0
    assert calls == ["solve"]


def test_main_rejects_removed_or_unknown_harness(monkeypatch):
    module = _load_run_harness()
    monkeypatch.setenv("AJ_HARNESS", "opencode")
    monkeypatch.setenv("AJ_PROMPT", "solve")
    monkeypatch.setattr(
        module,
        "_run_claude_code",
        lambda _prompt: pytest.fail("已移除的 harness 不能回退到 Claude Code"),
    )

    assert module.main() == 2


class _InteractiveInput:
    def __init__(self):
        self.frames = []

    def write(self, value):
        self.frames.append(json.loads(value))

    def flush(self):
        return None

    def close(self):
        return None


class _InteractiveProcess:
    def __init__(self, args=("agent",)):
        self.args = list(args)
        self.stdin = _InteractiveInput()
        self.terminated = False

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


class _Commands:
    def __init__(self, *batches):
        self.batches = list(batches)

    def drain(self):
        return self.batches.pop(0) if self.batches else []


def _event_queue(*events):
    import queue

    result = queue.Queue()
    for event in events:
        result.put(event)
    return result


def test_pi_rpc_adapter_maps_steer_and_abort_with_real_ack(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["pi"])
    session_id = "33333333-3333-3333-3333-333333333333"
    events = _event_queue(
        {
            "type": "response",
            "id": "__numoj-state__",
            "command": "get_state",
            "success": True,
            "data": {"sessionId": session_id},
        },
        {"type": "response", "id": "__start__", "command": "prompt", "success": True},
        {"type": "response", "id": "steer-1", "command": "prompt", "success": True},
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "id": "answer-1",
                "content": [{"type": "text", "text": "完成"}],
                "usage": {"input": 10, "cacheRead": 4, "output": 3},
            },
        },
        {"type": "agent_end"},
        {"type": "agent_settled"},
        # Pi 0.82.1 abort() 等待 idle，因此真实顺序是 settled 后才 ack。
        {"type": "response", "id": "stop-1", "command": "abort", "success": True},
    )
    monkeypatch.setattr(module, "_start_json_process", lambda *_args, **_kwargs: (proc, events))
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))
    recorded = []
    monkeypatch.setattr(
        module,
        "_record_live_session",
        lambda value, **_kwargs: recorded.append(value),
    )

    completed = module._run_pi_interactive(
        ["pi", "--mode", "json"],
        {},
        "开始",
        _Commands([
            {"type": "steer", "id": "steer-1", "message": "调整"},
            {"type": "interrupt", "id": "stop-1"},
        ]),
        "",
    )

    assert completed.returncode == 0
    assert completed.aj_session_id == session_id
    assert recorded == [session_id]
    assert [item["type"] for item in proc.stdin.frames] == [
        "get_state", "prompt", "prompt", "abort",
    ]
    assert proc.stdin.frames[2]["streamingBehavior"] == "steer"
    assert [
        (item["id"], item["status"])
        for item in emitted if item.get("type") == "numoj_control"
    ] == [
        ("__start__", "accepted"),
        ("steer-1", "accepted"),
        ("stop-1", "accepted"),
    ]
    assert any(
        item.get("type") == "numoj_trace"
        and item["event"]["kind"] == "assistant"
        and item["event"]["text"] == "完成"
        for item in emitted
    )


def test_pi_usage_uses_response_id_when_message_has_no_id(monkeypatch):
    module = _load_run_harness()
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    module._normalize_stream_event("pi", {
        "type": "message_end",
        "message": {
            "role": "assistant",
            "responseId": "response-pi-1",
            "content": [{"type": "text", "text": "完成"}],
            "usage": {"input": 10, "cacheRead": 4, "output": 3},
        },
    })

    trace = next(item for item in emitted if item["type"] == "numoj_trace")
    usage = next(item for item in emitted if item["type"] == "numoj_usage")
    assert trace["event"]["id"].startswith("response-pi-1")
    assert usage["id"] == "response-pi-1"
    assert usage["usage"]["input_cached_tokens"] == 4


def test_pi_rpc_projects_retry_errors_and_omits_orphan_zero_usage(
        monkeypatch, capsys, tmp_path):
    module = _load_run_harness()
    proc = _InteractiveProcess(["pi"])
    session_id = "33333333-3333-3333-3333-333333333333"

    def error_event(timestamp, detail):
        return {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [],
                "stopReason": "error",
                "errorMessage": "HTTP 429: " + json.dumps({
                    "error": {"message": detail},
                    "user_id": "internal-user-id",
                }),
                "timestamp": timestamp,
                "usage": {
                    "input": 0,
                    "cacheRead": 0,
                    "cacheWrite": 0,
                    "output": 0,
                    "reasoning": 0,
                },
            },
        }

    events = _event_queue(
        {
            "type": "response",
            "id": "__numoj-state__",
            "command": "get_state",
            "success": True,
            "data": {"sessionId": session_id},
        },
        {"type": "response", "id": "__start__", "success": True},
        error_event(101, "第一次请求限流"),
        error_event(102, "上游仍在限流，请稍后重试"),
        {"type": "agent_settled"},
    )
    monkeypatch.setattr(
        module,
        "_start_json_process",
        lambda *_args, **_kwargs: (proc, events),
    )
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)

    completed = module._run_pi_interactive(
        ["pi", "--mode", "json"], {}, "开始", _Commands(), "",
    )

    assert completed.returncode == 2
    error_traces = [
        item for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("is_error") is True
    ]
    assert [item["event"]["id"] for item in error_traces] == [
        "101:error", "102:error",
    ]
    assert [item["event"]["text"] for item in error_traces] == [
        "HTTP 429：第一次请求限流",
        "HTTP 429：上游仍在限流，请稍后重试",
    ]
    assert all(item["event"]["title"] == "模型请求失败" for item in error_traces)
    assert not any(item.get("type") == "numoj_usage" for item in emitted)
    stderr = capsys.readouterr().err
    assert stderr.strip() == "模型请求失败：HTTP 429：上游仍在限流，请稍后重试"
    assert "internal-user-id" not in stderr

    from backend.oj_modules.tasks.agent import harness_runtime as runtime

    journal = tmp_path / "canonical.jsonl"
    observer = runtime._CanonicalJournalObserver(journal)
    for item in emitted:
        observer.feed(
            (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
        )
    observer.close()
    records = [
        json.loads(line)
        for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["type"] for item in records] == [
        "numoj_trace", "numoj_trace",
    ]
    assert all(item["event"]["is_error"] is True for item in records)


def test_pi_rpc_rejects_empty_success_if_protocol_proxy_misses_it(
        monkeypatch, capsys):
    module = _load_run_harness()
    proc = _InteractiveProcess(["pi"])
    events = _event_queue(
        {
            "type": "response",
            "id": "__numoj-state__",
            "command": "get_state",
            "success": True,
            "data": {
                "sessionId": "33333333-3333-3333-3333-333333333333",
            },
        },
        {"type": "response", "id": "__start__", "success": True},
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [],
                "stopReason": "stop",
                "timestamp": 103,
                "usage": {"input": 0, "output": 0},
            },
        },
        {"type": "agent_settled"},
    )
    monkeypatch.setattr(
        module,
        "_start_json_process",
        lambda *_args, **_kwargs: (proc, events),
    )
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)

    completed = module._run_pi_interactive(
        ["pi", "--mode", "json"], {}, "开始", _Commands(), "",
    )

    assert completed.returncode == 2
    error = next(
        item["event"] for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("is_error") is True
    )
    assert error["id"] == "103:error"
    assert "empty assistant content" in error["text"]
    assert capsys.readouterr().err.strip().startswith("模型请求失败：")


def test_pi_rpc_rejects_start_without_waiting_for_settled(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["pi"])
    events = _event_queue(
        {
            "type": "response",
            "id": "__numoj-state__",
            "command": "get_state",
            "success": True,
            "data": {"sessionId": "33333333-3333-3333-3333-333333333333"},
        },
        {
            "type": "response",
            "id": "__start__",
            "command": "prompt",
            "success": False,
            "error": "model unavailable",
        },
    )
    monkeypatch.setattr(module, "_start_json_process", lambda *_args, **_kwargs: (proc, events))
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)

    completed = module._run_pi_interactive(
        ["pi", "--mode", "json"], {}, "开始", _Commands(), "",
    )

    assert completed.returncode == 2
    assert [item["type"] for item in proc.stdin.frames] == ["get_state", "prompt"]
    assert [
        (item.get("id"), item.get("status"), item.get("error"))
        for item in emitted if item.get("type") == "numoj_control"
    ] == [("__start__", "rejected", "model unavailable")]


def test_pi_rpc_output_limit_stops_without_hidden_continuation(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["pi"])
    events = _event_queue(
        {
            "type": "response",
            "id": "__numoj-state__",
            "command": "get_state",
            "success": True,
            "data": {"sessionId": "33333333-3333-3333-3333-333333333333"},
        },
        {"type": "response", "id": "__start__", "command": "prompt", "success": True},
        {
            "type": "message_end",
            "message": {
                "role": "assistant",
                "id": "limited-answer",
                "content": [{"type": "text", "text": "尚未完成"}],
                "stopReason": "error",
                "rawStopReason": "max_tokens",
            },
        },
        {"type": "agent_settled"},
    )
    monkeypatch.setattr(module, "_start_json_process", lambda *_args, **_kwargs: (proc, events))
    monkeypatch.setattr(module, "_emit_numoj", lambda _item: None)
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)

    completed = module._run_pi_interactive(
        ["pi", "--mode", "json"],
        {"AJ_TASK_SCOPE": "problem_agent"},
        "开始",
        _Commands(),
        "",
    )

    assert completed.returncode == 2
    assert [item["type"] for item in proc.stdin.frames] == [
        "get_state", "prompt",
    ]
    assert proc.stdin.frames[-1]["message"] == "开始"


def test_claude_stream_json_adapter_acks_steer_only_after_user_replay(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    steer_uuid = module._stable_control_uuid("steer-1", "")
    events = _event_queue(
        {"type": "system", "subtype": "init"},
        {
            "type": "user",
            "uuid": steer_uuid,
            "isReplay": True,
            "message": {"role": "user", "content": "调整"},
        },
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "id": "answer-1",
                "content": [{"type": "text", "text": "完成"}],
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
        },
        {"type": "result", "session_id": "22222222-2222-2222-2222-222222222222"},
    )
    monkeypatch.setattr(module, "_start_json_process", lambda *_args, **_kwargs: (proc, events))
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands([{"type": "steer", "id": "steer-1", "message": "调整"}]),
        "",
    )

    assert completed.returncode == 0
    assert "--input-format" in completed.args
    assert "--replay-user-messages" in completed.args
    assert [frame["type"] for frame in proc.stdin.frames] == ["user", "user"]
    assert all(frame["session_id"] == "default" for frame in proc.stdin.frames)
    assert proc.stdin.frames[1]["uuid"] == steer_uuid
    assert [
        item["id"] for item in emitted
        if item.get("type") == "numoj_control" and item.get("status") == "accepted"
    ] == ["__start__", "steer-1"]


def test_claude_stream_json_waits_for_background_subagents_and_parent_result(
        monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    session_id = "22222222-2222-2222-2222-222222222222"
    events = _event_queue(
        {"type": "system", "subtype": "init", "session_id": session_id},
        {"type": "result", "session_id": session_id},
        {
            "type": "assistant",
            "session_id": session_id,
            "message": {
                "role": "assistant",
                "id": "answer-after-subagents",
                "content": [{"type": "text", "text": "已汇总全部结果"}],
                "usage": {"input_tokens": 10, "output_tokens": 2},
            },
        },
        {"type": "result", "session_id": session_id},
    )
    snapshots = iter([
        [{
            "subagent_id": "worker-a",
            "name": "检索官方文档",
            "status": "running",
        }],
        [{
            "subagent_id": "worker-a",
            "name": "检索官方文档",
            "status": "completed",
        }],
    ])
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        module,
        "_claude_subagent_snapshot",
        lambda _env, found_session_id: (
            next(snapshots) if found_session_id == session_id else []
        ),
    )
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands(),
        "",
    )

    assert completed.returncode == 0
    assert "--append-system-prompt" not in completed.args
    subagent_events = [
        json.loads(item["event"]["text"])
        for item in emitted
        if item.get("type") == "numoj_trace"
        and item.get("event", {}).get("meta")
        == module._CLAUDE_SUBAGENT_STATUS_META
    ]
    assert [item["status"] for item in subagent_events] == [
        "running", "completed",
    ]
    assert any(
        item.get("event", {}).get("text") == "已汇总全部结果"
        for item in emitted if item.get("type") == "numoj_trace"
    )


def test_claude_stream_json_does_not_finish_before_background_journal_exists(
        monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    session_id = "22222222-2222-2222-2222-222222222222"
    events = _event_queue(
        {"type": "system", "subtype": "init", "session_id": session_id},
        {
            "type": "assistant",
            "session_id": session_id,
            "message": {
                "role": "assistant",
                "id": "launch-background-agent",
                "content": [{
                    "type": "tool_use",
                    "id": "tool-agent-1",
                    "name": "Agent",
                    "input": {
                        "description": "检查实现",
                        "run_in_background": True,
                    },
                }],
            },
        },
        # journal 尚未落盘时 Claude 已先结束父模型的第一次调用。
        {"type": "result", "session_id": session_id},
        {
            "type": "assistant",
            "session_id": session_id,
            "message": {
                "role": "assistant",
                "id": "answer-after-notification",
                "content": [{"type": "text", "text": "后台结果已经汇总"}],
            },
        },
        {"type": "result", "session_id": session_id},
    )
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "_claude_subagent_snapshot", lambda *_args: [])
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands(),
        "",
    )

    assert completed.returncode == 0
    assert any(
        item.get("event", {}).get("text") == "后台结果已经汇总"
        for item in emitted if item.get("type") == "numoj_trace"
    )


def test_claude_subagent_snapshot_reads_workflow_journal_and_names(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    session_id = "22222222-2222-2222-2222-222222222222"
    workflow = (
        tmp_path / ".claude" / "projects" / "-workspace" / session_id
        / "subagents" / "workflows" / "wf-test"
    )
    workflow.mkdir(parents=True)
    (workflow / "journal.jsonl").write_text(
        "\n".join([
            json.dumps({
                "type": "started", "key": "one", "agentId": "agent-one",
            }),
            json.dumps({
                "type": "result", "key": "one", "agentId": "agent-one",
                "result": {"ok": True},
            }),
            json.dumps({
                "type": "started", "key": "two", "agentId": "agent-two",
            }),
        ]) + "\n",
        encoding="utf-8",
    )
    for agent_id, title in (
        ("agent-one", "## 第一组：官方资料"),
        ("agent-two", "## 第二组：限流核对"),
    ):
        (workflow / f"agent-{agent_id}.jsonl").write_text(
            json.dumps({
                "type": "user",
                "message": {"role": "user", "content": title},
            }, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    assert module._claude_subagent_snapshot(
        {"HOME": str(tmp_path)}, session_id,
    ) == [
        {
            "subagent_id": "agent-one",
            "name": "第一组：官方资料",
            "status": "completed",
        },
        {
            "subagent_id": "agent-two",
            "name": "第二组：限流核对",
            "status": "running",
        },
    ]


def test_claude_stream_json_does_not_ack_steer_for_tool_result_user_event(
        monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    steer_uuid = module._stable_control_uuid("steer-1", "")
    events = _event_queue(
        {"type": "system", "subtype": "init"},
        {
            "type": "user",
            "message": {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "tool-1"}],
            },
        },
        {
            "type": "user",
            "uuid": steer_uuid,
            "isReplay": True,
            "message": {"role": "user", "content": "调整"},
        },
        {"type": "result", "session_id": "22222222-2222-2222-2222-222222222222"},
    )
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands([{"type": "steer", "id": "steer-1", "message": "调整"}]),
        "",
    )

    assert completed.returncode == 0
    accepted = [
        item["id"] for item in emitted
        if item.get("type") == "numoj_control"
        and item.get("status") == "accepted"
    ]
    assert accepted == ["__start__", "steer-1"]


def test_claude_stream_json_accepted_interrupt_returns_130(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    events = _event_queue(
        {"type": "system", "subtype": "init"},
        {
            "type": "result",
            "is_error": True,
            "session_id": "22222222-2222-2222-2222-222222222222",
        },
        {
            "type": "control_response",
            "response": {
                "subtype": "success",
                "request_id": "numoj-stop-1",
            },
        },
    )
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands([{"type": "interrupt", "id": "stop-1"}]),
        "",
    )

    assert completed.returncode == 130
    interrupt = next(
        frame for frame in proc.stdin.frames
        if frame.get("type") == "control_request"
    )
    assert interrupt == {
        "type": "control_request",
        "request_id": "numoj-stop-1",
        "request": {"subtype": "interrupt"},
    }
    assert any(
        item.get("type") == "numoj_control"
        and item.get("id") == "stop-1"
        and item.get("status") == "accepted"
        for item in emitted
    )


def test_claude_failed_result_projects_error_and_stderr_summary(
        monkeypatch, capsys):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    session_id = "22222222-2222-2222-2222-222222222222"
    events = _event_queue(
        {"type": "system", "subtype": "init", "session_id": session_id},
        {
            "type": "result",
            "subtype": "error_during_execution",
            "is_error": True,
            "result": "HTTP 503：Claude 上游不可用",
            "session_id": session_id,
        },
    )
    monkeypatch.setattr(
        module,
        "_start_json_process",
        lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands(),
        "",
    )

    assert completed.returncode == 2
    error = next(
        item["event"] for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("is_error") is True
    )
    assert error["id"] == f"{session_id}:result:1:error"
    assert error["text"] == "HTTP 503：Claude 上游不可用"
    assert capsys.readouterr().err.strip() == (
        "模型请求失败：HTTP 503：Claude 上游不可用"
    )


def test_claude_stream_json_emits_incremental_usage_per_assistant_message(
        monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    first = {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "id": "assistant-1",
            "content": [{"type": "text", "text": "先调用工具"}],
            "usage": {
                "input_tokens": 10,
                "cache_read_input_tokens": 2,
                "output_tokens": 3,
            },
        },
    }
    events = _event_queue(
        {"type": "system", "subtype": "init"},
        first,
        {
            "type": "assistant",
            "message": {
                "role": "assistant",
                "id": "assistant-2",
                "content": [{"type": "text", "text": "最终完成"}],
                "usage": {
                    "input_tokens": 20,
                    "cache_read_input_tokens": 4,
                    "output_tokens": 5,
                },
            },
        },
        # CLI replay 可能重复同一 native message；journal reader 按 ID 去重。
        first,
        {
            "type": "result",
            "session_id": "22222222-2222-2222-2222-222222222222",
            "usage": {"input_tokens": 999, "output_tokens": 999},
        },
    )
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands(),
        "",
    )

    assert completed.returncode == 0
    usage = [item for item in emitted if item.get("type") == "numoj_usage"]
    assert [item["id"] for item in usage] == [
        "assistant-1", "assistant-2", "assistant-1",
    ]
    assert sum(item["usage"]["output_tokens"] for item in usage[:2]) == 8
    assert all(item["usage"]["output_tokens"] != 999 for item in usage)


def test_claude_result_usage_fallback_has_unique_id_per_result(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["claude"])
    steer_uuid = module._stable_control_uuid("steer-1", "")
    session_id = "22222222-2222-2222-2222-222222222222"
    events = _event_queue(
        {"type": "system", "subtype": "init"},
        {
            "type": "result",
            "session_id": session_id,
            "usage": {"input_tokens": 4, "output_tokens": 1},
        },
        {
            "type": "user",
            "uuid": steer_uuid,
            "isReplay": True,
            "message": {"role": "user", "content": "调整"},
        },
        {
            "type": "result",
            "session_id": session_id,
            "usage": {"input_tokens": 6, "output_tokens": 2},
        },
    )
    monkeypatch.setattr(
        module, "_start_json_process", lambda *_args, **_kwargs: (proc, events),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_claude_interactive(
        ["claude", "--output-format", "json", "-p"],
        {},
        "开始",
        _Commands([{"type": "steer", "id": "steer-1", "message": "调整"}]),
        "",
    )

    assert completed.returncode == 0
    usage = [item for item in emitted if item.get("type") == "numoj_usage"]
    assert [item["id"] for item in usage] == [
        f"{session_id}:result:1",
        f"{session_id}:result:2",
    ]


def test_trace_emitter_bounds_large_tool_before_canonical_journal(
        monkeypatch, tmp_path):
    from backend.oj_modules.tasks.agent import harness_runtime as runtime

    module = _load_run_harness()
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    module._emit_trace(
        "tool_result",
        "x" * (32 * 1024),
        title="工具结果",
        event_id="tool-1:result",
    )
    module._emit_trace(
        "assistant",
        "最终完成",
        event_id="assistant-final",
    )
    module._emit_usage(
        "pi",
        {
            "input_uncached_tokens": 3,
            "input_cached_tokens": 0,
            "input_cache_write_tokens": 0,
            "output_tokens": 2,
            "reasoning_output_tokens": 0,
        },
        "usage-final",
    )

    tool_text = emitted[0]["event"]["text"]
    assert len(tool_text) == module._TRACE_DETAIL_MAX_CHARS
    assert tool_text.endswith("…")

    # 缩小 journal 容量复现“首条工具结果先占满，最终回复/usage 丢失”。
    # 经过 adapter 的 UI 上限裁剪后，三条记录都应保留下来。
    journal = tmp_path / "canonical.jsonl"
    observer = runtime._CanonicalJournalObserver(journal, max_bytes=8192)
    for item in emitted:
        observer.feed(
            (json.dumps(item, ensure_ascii=False) + "\n").encode("utf-8")
        )
    observer.close()
    records = [
        json.loads(line)
        for line in journal.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["type"] for item in records] == [
        "numoj_trace", "numoj_trace", "numoj_usage",
    ]
    assert records[1]["event"]["text"] == "最终完成"

def test_adapter_terminal_statuses_and_pi_settles_only_at_safe_boundary():
    module = _load_run_harness()

    assert module._stream_terminal_status("claude_code", {
        "type": "result",
        "is_error": True,
    }) == "failed"
    assert module._normalize_stream_event("pi", {"type": "agent_end"}) is False
    assert module._normalize_stream_event("pi", {"type": "agent_settled"}) is True
    assert module._pi_event_failure_status({
        "type": "message_end",
        "message": {
            "role": "assistant",
            "stopReason": "error",
            "errorMessage": "provider failed",
        },
    }) == "failed"
