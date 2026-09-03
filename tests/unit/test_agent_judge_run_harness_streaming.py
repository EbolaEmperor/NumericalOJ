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


def test_claude_print_harness_promises_to_wait_for_background_workflows(
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
    completion_prompt = args[args.index("--append-system-prompt") + 1]
    assert "Background subagents and workflows are supported" in completion_prompt
    assert "Do not return the final answer" in completion_prompt
    assert "promise to report later is not completion" in completion_prompt
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
    ("path", "thinking_format", "enabled", "expected"),
    [
        ("/v1/chat/completions", "enable_thinking", True,
         {"enable_thinking": True}),
        ("/v1/responses", "enable_thinking", True,
         {"enable_thinking": True}),
        ("/v1/chat/completions", "enable_thinking", False, {}),
        ("/v1/responses", "thinking_type", True,
         {"enable_thinking": True}),
        ("/v1/chat/completions", "none", False, {}),
    ],
)
def test_codex_openai_requests_use_endpoint_thinking_format(
        path, thinking_format, enabled, expected):
    module = _load_run_harness()
    message_field = "input" if path.endswith("/responses") else "messages"
    raw = {
        "model": "local-metadata-model",
        message_field: [{"role": "user", "content": "hello"}],
        "thinking": {"type": "stale"},
        "enable_thinking": True,
    }

    rewritten = json.loads(module._rewrite_codex_request_body(
        path,
        json.dumps(raw).encode("utf-8"),
        16_384,
        enabled,
        "actual-model",
        thinking_format,
    ))

    assert rewritten["model"] == "actual-model"
    assert {key: rewritten[key] for key in expected} == expected
    if "enable_thinking" not in expected:
        assert "enable_thinking" not in rewritten
    if "thinking" not in expected:
        assert "thinking" not in rewritten


@pytest.mark.parametrize(
    ("path", "message_field"),
    [
        ("/v1/responses", "input"),
        ("/v1/chat/completions", "messages"),
    ],
)
def test_codex_relay_downgrades_developer_to_standard_system_role(
        path, message_field):
    module = _load_run_harness()
    payload = {
        message_field: [
            {"role": "developer", "content": "system policy"},
            {"role": "user", "content": "solve"},
            {"role": "assistant", "content": "working"},
            {"role": "tool", "content": "result"},
        ],
    }

    rewritten = json.loads(module._rewrite_codex_request_body(
        path,
        json.dumps(payload).encode("utf-8"),
        16_384,
        True,
    ))

    assert [
        message["role"] for message in rewritten[message_field]
    ] == ["system", "user", "assistant", "tool"]


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


def test_codex_audit_mode_uses_read_only_sandbox_without_bypass(monkeypatch):
    module = _load_run_harness()
    calls = []
    configs = []
    relay_events = []
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "true")
    _set_endpoint(
        monkeypatch,
        base_url="http://quality-model-proxy:18080/v1",
    )
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", "22222222-2222-2222-2222-222222222222")
    monkeypatch.setattr(
        module, "_write_codex_config",
        lambda home, base_url, model, **kwargs:
            configs.append((home, base_url, model, kwargs)),
    )

    class FakeRelay:
        def __init__(
                self, base_url, max_output_tokens, thinking_compatibility,
                upstream_model=None):
            relay_events.append((
                "init", base_url, max_output_tokens, thinking_compatibility,
                upstream_model,
            ))

        def start(self):
            relay_events.append(("start",))
            return "http://127.0.0.1:43123"

        def stop(self):
            relay_events.append(("stop",))

    monkeypatch.setattr(module, "_CodexEndpointRelay", FakeRelay)

    def run(args, env=None, input_text=None):
        calls.append((list(args), dict(env or {}), input_text))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_codex("audit prompt") == 0

    args, env, input_text = calls[0]
    assert configs == [(
        "/workspace/.codex", "http://127.0.0.1:43123",
        "generic-model",
        {
            "context_window_tokens": 1_000_000,
            "max_output_tokens": 384_000,
            "thinking_compatibility": True,
            "web_search_mcp": None,
        },
    )]
    assert relay_events == [
        (
            "init", "http://quality-model-proxy:18080/v1", 384_000, True,
            "generic-model",
        ),
        ("start",),
        ("stop",),
    ]
    assert args[:2] == ["codex", "exec"]
    assert "--json" in args
    assert args[args.index("--sandbox") + 1] == "read-only"
    assert args[args.index("--cd") + 1] == "/workspace"
    assert "--dangerously-bypass-approvals-and-sandbox" not in args
    assert "resume" not in args
    assert args[-1] == "-"
    assert input_text == "audit prompt"
    assert env["CODEX_HOME"] == "/workspace/.codex"
    assert env["AJ_ENDPOINT_API_KEY"] == "temporary-token"


@pytest.mark.parametrize(
    ("thinking_compatibility", "expected_summary"),
    [(True, "auto"), (False, "none")],
)
def test_codex_config_reserves_output_and_controls_reasoning_summary(
        tmp_path, thinking_compatibility, expected_summary):
    module = _load_run_harness()

    module._write_codex_config(
        str(tmp_path), "https://model.example/v1", "generic-model",
        context_window_tokens=131_072,
        max_output_tokens=16_384,
        thinking_compatibility=thinking_compatibility,
    )

    config = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert 'model = "generic-model"' in config
    assert "model_context_window = 131072" in config
    assert "model_auto_compact_token_limit = 114688" in config
    assert (
        "model_supports_reasoning_summaries = "
        + ("true" if thinking_compatibility else "false")
    ) in config
    assert f'model_reasoning_summary = "{expected_summary}"' in config
    assert 'wire_api = "responses"' in config
    assert "model_max_output_tokens" not in config


def test_codex_and_opencode_configs_reference_web_search_secret_from_env(tmp_path):
    module = _load_run_harness()
    settings = {
        "url": "https://search.example/mcp",
        "timeout_seconds": 37,
        "timeout_ms": 37_000,
    }

    module._write_codex_config(
        str(tmp_path),
        "https://model.example/v1",
        "generic-model",
        web_search_mcp=settings,
    )
    codex_config = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert "[mcp_servers.numoj_web_search]" in codex_config
    assert 'url = "https://search.example/mcp"' in codex_config
    assert (
        'env_http_headers = { Authorization = '
        '"AJ_WEB_SEARCH_MCP_AUTHORIZATION" }'
    ) in codex_config
    assert "tool_timeout_sec = 37" in codex_config

    opencode_config = json.loads(module._opencode_config_content(
        "https://model.example/v1",
        "AJ_ENDPOINT_API_KEY",
        "generic-model",
        web_search_mcp=settings,
    ))
    assert opencode_config["mcp"] == {
        "numoj_web_search": {
            "type": "remote",
            "url": "https://search.example/mcp",
            "headers": {
                "Authorization": "{env:AJ_WEB_SEARCH_MCP_AUTHORIZATION}",
            },
            "oauth": False,
            "timeout": 37_000,
        },
    }


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


def test_codex_relay_injects_output_limit_strips_thinking_and_streams_response():
    module = _load_run_harness()
    received = {}
    response_body = (
        b'data: {"id":"chatcmpl-relay","object":"chat.completion.chunk",'
        b'"choices":[{"index":0,"delta":{"role":"assistant",'
        b'"content":"ok"},"finish_reason":null}]}\n\n'
        b'data: {"id":"chatcmpl-relay","object":"chat.completion.chunk",'
        b'"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],'
        b'"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5,'
        b'"prompt_tokens_details":{"cached_tokens":1},'
        b'"completion_tokens_details":{"reasoning_tokens":1}}}\n\n'
        b'data: [DONE]\n\n'
    )

    class UpstreamHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            received["path"] = self.path
            received["authorization"] = self.headers.get("Authorization")
            received["body"] = json.loads(self.rfile.read(length))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    try:
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    except PermissionError:
        pytest.skip("当前沙箱不允许绑定 localhost 端口")
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    relay = module._CodexEndpointRelay(
        f"http://127.0.0.1:{upstream.server_port}/v1",
        max_output_tokens=384_000,
        thinking_compatibility=False,
        upstream_model="generic-model",
    )
    relay_url = relay.start()
    try:
        request = urllib.request.Request(
            relay_url + "/responses?stream=true",
            data=json.dumps({
                "model": "generic-model",
                "reasoning": {"effort": "high"},
                "input": [
                    {"type": "reasoning", "id": "hidden"},
                    {"role": "user", "content": "solve"},
                ],
            }).encode("utf-8"),
            headers={
                "Authorization": "Bearer temporary-token",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            relay_body = response.read().decode("utf-8")
    finally:
        relay.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)

    assert "response.output_item.added" in relay_body
    assert "response.output_text.delta" in relay_body
    assert "response.output_item.done" in relay_body
    assert "response.completed" in relay_body
    assert '"cached_tokens":1' in relay_body
    assert '"reasoning_tokens":1' in relay_body
    assert received["path"] == "/v1/chat/completions?stream=true"
    assert received["authorization"] == "Bearer temporary-token"
    assert received["body"] == {
        "model": "generic-model",
        "messages": [{"role": "user", "content": "solve"}],
        "stream": True,
        "stream_options": {"include_usage": True},
        "max_tokens": 384_000,
    }


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


def test_codex_responses_bridge_preserves_tool_round_trip():
    module = _load_run_harness()

    converted = json.loads(module._codex_responses_request_to_chat(json.dumps({
        "model": "generic-model",
        "max_output_tokens": 123,
        "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "run"}]},
            {
                "type": "function_call",
                "call_id": "call-1",
                "name": "shell",
                "arguments": '{"command":"pwd"}',
            },
            {
                "type": "function_call_output",
                "call_id": "call-1",
                "output": [{"type": "input_text", "text": "/workspace"}],
            },
        ],
        "tools": [{
            "type": "function",
            "name": "shell",
            "description": "run a command",
            "parameters": {"type": "object"},
            "strict": True,
        }],
        "tool_choice": {"type": "function", "name": "shell"},
    }).encode("utf-8")))

    assert converted["messages"] == [
        {"role": "user", "content": "run"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "call-1",
                "type": "function",
                "function": {
                    "name": "shell",
                    "arguments": '{"command":"pwd"}',
                },
            }],
        },
        {
            "role": "tool",
            "tool_call_id": "call-1",
            "content": '[{"type":"input_text","text":"/workspace"}]',
        },
    ]
    assert converted["tools"] == [{
        "type": "function",
        "function": {
            "name": "shell",
            "description": "run a command",
            "parameters": {"type": "object"},
            "strict": True,
        },
    }]
    assert converted["tool_choice"] == {
        "type": "function",
        "function": {"name": "shell"},
    }


def test_codex_responses_bridge_drops_unsupported_tools_without_prompt_rewrite():
    module = _load_run_harness()

    converted = json.loads(module._codex_responses_request_to_chat(json.dumps({
        "model": "generic-model",
        "instructions": "keep this system prompt unchanged",
        "input": [{"role": "user", "content": "edit it"}],
        "tools": [
            {
                "type": "custom",
                "name": "apply_patch",
                "description": "apply a patch",
                "format": {"type": "grammar", "syntax": "lark"},
            },
            {
                "type": "namespace",
                "name": "multi_agent_v1",
                "description": "delegate work",
                "tools": [],
            },
            {"type": "web_search", "external_web_access": True},
            {
                "type": "function",
                "name": "shell",
                "description": "run shell",
                "parameters": {"type": "object"},
            },
        ],
    }).encode("utf-8")))

    assert converted["messages"] == [
        {"role": "system", "content": "keep this system prompt unchanged"},
        {"role": "user", "content": "edit it"},
    ]
    assert [item["function"]["name"] for item in converted["tools"]] == [
        "shell",
    ]

    for item_type in ("custom_tool_call", "custom_tool_call_output"):
        with pytest.raises(ValueError, match=item_type):
            module._codex_responses_request_to_chat(json.dumps({
                "model": "generic-model",
                "input": [{
                    "type": item_type,
                    "call_id": "call-1",
                    "name": "apply_patch",
                    "input": "*** Begin Patch",
                    "output": "Done!",
                }],
            }).encode("utf-8"))


def test_codex_relay_refuses_redirect_without_forwarding_authorization():
    module = _load_run_harness()
    received = {"upstream_authorization": None, "redirect_hits": 0}

    class RedirectTarget(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            received["redirect_hits"] += 1
            self.send_response(204)
            self.end_headers()

    try:
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectTarget)
    except PermissionError:
        pytest.skip("当前沙箱不允许绑定 localhost 端口")
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    class RedirectingUpstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            received["upstream_authorization"] = self.headers.get("Authorization")
            self.send_response(307)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{target.server_port}/credential-sink",
            )
            self.end_headers()

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectingUpstream)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    relay = module._CodexEndpointRelay(
        f"http://127.0.0.1:{upstream.server_port}/v1",
        max_output_tokens=16_384,
        thinking_compatibility=True,
        upstream_model="generic-model",
    )
    relay_url = relay.start()
    try:
        request = urllib.request.Request(
            relay_url + "/responses",
            data=b"{}",
            headers={
                "Authorization": "Bearer must-not-follow-redirect",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(request, timeout=5)
        assert exc_info.value.code == 502
        assert b"redirects are refused" in exc_info.value.read()
    finally:
        relay.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)

    assert received == {
        "upstream_authorization": "Bearer must-not-follow-redirect",
        "redirect_hits": 0,
    }


def test_codex_relay_does_not_turn_invalid_upstream_stream_into_success():
    module = _load_run_harness()

    class Upstream(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if "case=json" in self.path:
                body = b'{"error":{"message":"model unavailable"}}'
                content_type = "application/json"
                content_encoding = ""
            elif "case=gzip" in self.path:
                body = b"not-actually-decoded"
                content_type = "text/event-stream"
                content_encoding = "gzip"
            elif "case=partial" in self.path:
                body = (
                    b'data: {"id":"chatcmpl-partial","choices":['
                    b'{"index":0,"delta":{"content":"partial"},'
                    b'"finish_reason":null}]}\n\n'
                )
                content_type = "text/event-stream"
                content_encoding = ""
            elif "case=length" in self.path:
                body = (
                    b'data: {"id":"chatcmpl-length","choices":['
                    b'{"index":0,"delta":{"content":"partial"},'
                    b'"finish_reason":"length"}]}\n\n'
                    b'data: [DONE]\n\n'
                )
                content_type = "text/event-stream"
                content_encoding = ""
            elif "case=empty" in self.path:
                body = (
                    b'data: {"id":"chatcmpl-empty","choices":['
                    b'{"index":0,"delta":{"role":"assistant"},'
                    b'"finish_reason":null}]}\n\n'
                    b'data: {"id":"chatcmpl-empty","choices":['
                    b'{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
                    b'data: [DONE]\n\n'
                )
                content_type = "text/event-stream"
                content_encoding = ""
            else:
                body = b'data: {"error":{"code":"quota","message":"quota exceeded"}}\n\n'
                content_type = "text/event-stream"
                content_encoding = ""
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            if content_encoding:
                self.send_header("Content-Encoding", content_encoding)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    except PermissionError:
        pytest.skip("当前沙箱不允许绑定 localhost 端口")
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    relay = module._CodexEndpointRelay(
        f"http://127.0.0.1:{upstream.server_port}/v1",
        max_output_tokens=16_384,
        thinking_compatibility=True,
        upstream_model="generic-model",
    )
    relay_url = relay.start()

    def request(case):
        return urllib.request.urlopen(urllib.request.Request(
            relay_url + f"/responses?case={case}",
            data=b'{"model":"generic-model","input":[]}',
            headers={"Content-Type": "application/json"},
            method="POST",
        ), timeout=5)

    try:
        with pytest.raises(urllib.error.HTTPError) as json_error:
            request("json")
        assert json_error.value.code == 502
        assert b"model unavailable" in json_error.value.read()

        with pytest.raises(urllib.error.HTTPError) as gzip_error:
            request("gzip")
        assert gzip_error.value.code == 502
        assert "压缩 SSE" in gzip_error.value.read().decode("utf-8")

        with request("sse-error") as response:
            stream_error = response.read().decode("utf-8")
        assert "response.failed" in stream_error
        assert "quota exceeded" in stream_error
        assert "response.completed" not in stream_error
        assert '"sequence_number":0' in stream_error

        with request("partial") as response:
            partial_error = response.read().decode("utf-8")
        assert "response.output_text.delta" in partial_error
        assert "response.failed" in partial_error
        assert "稳定终态前中断" in partial_error
        assert "response.completed" not in partial_error

        with request("length") as response:
            length_error = response.read().decode("utf-8")
        assert "response.failed" in length_error
        assert "finish_reason=length" in length_error
        assert "response.completed" not in length_error

        with request("empty") as response:
            empty_error = response.read().decode("utf-8")
        assert "response.failed" in empty_error
        assert "empty assistant content" in empty_error
        assert "response.completed" not in empty_error
    finally:
        relay.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_codex_relay_preserves_thinking_when_compatible():
    module = _load_run_harness()
    original = {
        "reasoning": {"effort": "high"},
        "input": [{"type": "reasoning", "id": "reasoning-item"}],
    }

    rewritten = json.loads(module._rewrite_codex_request_body(
        "/v1/responses", json.dumps(original).encode("utf-8"), 16_384, True,
    ))

    assert rewritten == {
        **original,
        "max_output_tokens": 16_384,
    }


def test_opencode_audit_mode_denies_all_except_evidence_read_tools(monkeypatch):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "on")
    _set_endpoint(
        monkeypatch,
        base_url="http://quality-model-proxy:18080/v1",
    )
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", "ses_AuditResume_333")
    monkeypatch.setattr(module.os, "makedirs", lambda *_args, **_kwargs: None)

    def run(args, env=None, input_text=None):
        calls.append((list(args), dict(env or {}), input_text))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_opencode("audit prompt") == 0

    args, env, input_text = calls[0]
    assert args[:3] == ["opencode", "--pure", "run"]
    assert args[args.index("--format") + 1] == "json"
    assert "--dangerously-skip-permissions" not in args
    assert "--session" not in args
    assert args[-1] == "audit prompt"
    assert input_text is None
    config = json.loads(env["OPENCODE_CONFIG_CONTENT"])
    assert config["permission"] == {
        "*": "deny",
        "read": "allow",
        "glob": "allow",
        "grep": "allow",
        "external_directory": {"/evidence/**": "allow"},
    }
    assert env["AJ_ENDPOINT_API_KEY"] == "temporary-token"
    assert env["OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX"] == "384000"
    model = config["provider"][module.OPENCODE_PROVIDER_ID]["models"]["generic-model"]
    assert model["limit"] == {"context": 1_000_000, "output": 384_000}
    assert model["reasoning"] is True
    assert "interleaved" not in model
    assert all(env[name] == "true" for name in (
        "OPENCODE_DISABLE_DEFAULT_PLUGINS",
        "OPENCODE_DISABLE_CLAUDE_CODE",
        "OPENCODE_DISABLE_AUTOUPDATE",
        "OPENCODE_DISABLE_LSP_DOWNLOAD",
        "OPENCODE_DISABLE_MODELS_FETCH",
    ))


def test_opencode_model_capabilities_are_model_agnostic_and_can_disable_thinking():
    module = _load_run_harness()

    config = json.loads(module._opencode_config_content(
        "https://model.example/v1", "AJ_ENDPOINT_API_KEY", "generic-model",
        context_window_tokens=131_072,
        max_output_tokens=16_384,
        thinking_compatibility=False,
    ))

    model = config["provider"][module.OPENCODE_PROVIDER_ID]["models"]["generic-model"]
    assert model["limit"] == {"context": 131_072, "output": 16_384}
    assert model["reasoning"] is False
    assert "interleaved" not in model


def test_opencode_consumes_same_endpoint_thinking_contract(monkeypatch):
    module = _load_run_harness()
    events = []
    calls = []
    _set_endpoint(monkeypatch)
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_FORMAT", "enable_thinking")
    monkeypatch.setenv("AJ_ENDPOINT_THINKING_ENABLED", "true")
    monkeypatch.setattr(module.os, "makedirs", lambda *_args, **_kwargs: None)

    class FakeRelay:
        def __init__(self, base_url, protocol, thinking_format, thinking_enabled):
            events.append((
                "init", base_url, protocol, thinking_format, thinking_enabled,
            ))

        def start(self):
            events.append(("start",))
            return "http://127.0.0.1:45678"

        def stop(self):
            events.append(("stop",))

    def run(args, env=None, input_text=None):
        calls.append((list(args), dict(env or {}), input_text))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module, "_EndpointThinkingRelay", FakeRelay)
    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_opencode("solve") == 0

    assert events == [
        ("init", "https://model.example/v1", "openai", "enable_thinking", True),
        ("start",),
        ("stop",),
    ]
    config = json.loads(calls[0][1]["OPENCODE_CONFIG_CONTENT"])
    provider = config["provider"][module.OPENCODE_PROVIDER_ID]
    assert provider["options"]["baseURL"] == "http://127.0.0.1:45678"


@pytest.mark.parametrize(
    ("runner_name", "protocol"),
    [
        (
            "_run_claude_code",
            "anthropic",
        ),
        (
            "_run_codex",
            "openai",
        ),
        (
            "_run_opencode",
            "openai",
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
    ("_run_codex", "openai"),
    ("_run_opencode", "openai"),
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


def test_opencode_records_and_resumes_opaque_mixed_case_session_id(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    state_path = tmp_path / "session.json"
    session_id = "ses_MixedCase_19-Z"
    monkeypatch.setenv("AJ_SESSION_STATE", str(state_path))
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", session_id)
    proc = SimpleNamespace(
        returncode=0,
        stdout=json.dumps({
            "type": "step_start",
            "properties": {"sessionID": session_id},
        }),
        stderr="",
    )

    assert module._resume_session_id_from_env("opencode") == session_id
    assert module._record_session("opencode", proc, session_id) == session_id
    assert json.loads(state_path.read_text(encoding="utf-8")) == {
        "harness": "opencode",
        "phase": "",
        "session_id": session_id,
        "resume_session_id": session_id,
        "returncode": 0,
    }
    with pytest.raises(ValueError, match="UUID"):
        module._resume_session_id_from_env("codex")


@pytest.mark.parametrize(
    "session_id",
    ["ses_", "ses_has.dot", "SES_wrong_prefix", "ses_" + "a" * 121],
)
def test_opencode_rejects_malformed_native_session_id(
        monkeypatch, session_id):
    module = _load_run_harness()
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", session_id)

    with pytest.raises(ValueError, match="OpenCode"):
        module._resume_session_id_from_env("opencode")


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


@pytest.mark.parametrize("value", ["", "unknown-harness"])
def test_main_keeps_legacy_claude_fallback_for_empty_or_unknown_harness(
        monkeypatch, value):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_HARNESS", value)
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


def test_codex_app_server_adapter_uses_expected_turn_for_steer(monkeypatch):
    module = _load_run_harness()
    proc = _InteractiveProcess(["codex"])
    thread_id = "11111111-1111-1111-1111-111111111111"
    events = _event_queue(
        {"id": "numoj-init", "result": {}},
        {"id": "numoj-thread", "result": {"thread": {"id": thread_id}}},
        {"id": "numoj-turn", "result": {"turn": {"id": "turn-1"}}},
        {
            "method": "thread/tokenUsage/updated",
            "params": {
                "turnId": "turn-1",
                "tokenUsage": {
                    "last": {
                        "inputTokens": 10,
                        "cachedInputTokens": 3,
                        "outputTokens": 2,
                        "reasoningOutputTokens": 1,
                    },
                    "total": {
                        "inputTokens": 10,
                        "cachedInputTokens": 3,
                        "outputTokens": 2,
                        "reasoningOutputTokens": 1,
                    },
                },
            },
        },
        {
            "method": "item/completed",
            "params": {"item": {"type": "agentMessage", "text": "完成"}},
        },
        {
            "method": "turn/completed",
            "params": {
                "turn": {
                    "id": "turn-1",
                    "usage": {"inputTokens": 10, "cachedInputTokens": 3, "outputTokens": 2},
                },
            },
        },
        # app-server 允许终态通知先于控制 RPC response 抵达。
        {"id": "numoj-command-steer-1", "result": {"turnId": "turn-1"}},
    )
    monkeypatch.setattr(module, "_start_json_process", lambda *_args, **_kwargs: (proc, events))
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_codex_interactive(
        "开始",
        _Commands([{"type": "steer", "id": "steer-1", "message": "调整"}]),
        {},
        "",
        "model-a",
    )

    assert completed.returncode == 0
    steer = next(
        frame for frame in proc.stdin.frames
        if frame.get("method") == "turn/steer"
    )
    assert steer["params"]["expectedTurnId"] == "turn-1"
    assert steer["params"]["clientUserMessageId"] == "steer-1"
    assert steer["params"]["input"][0]["text_elements"] == []
    thread_start = next(
        frame for frame in proc.stdin.frames
        if frame.get("method") == "thread/start"
    )
    assert thread_start["params"]["sandbox"] == "danger-full-access"
    turn_start = next(
        frame for frame in proc.stdin.frames
        if frame.get("method") == "turn/start"
    )
    assert turn_start["params"]["input"][0]["text_elements"] == []
    assert any(
        item.get("type") == "numoj_control"
        and item.get("id") == "steer-1"
        and item.get("status") == "accepted"
        for item in emitted
    )
    usage = next(item for item in emitted if item.get("type") == "numoj_usage")
    assert usage["usage"] == {
        "input_uncached_tokens": 7,
        "input_cached_tokens": 3,
        "input_cache_write_tokens": 0,
        "output_tokens": 2,
        "reasoning_output_tokens": 1,
    }


def test_codex_failed_turn_projects_error_and_stderr_summary(monkeypatch, capsys):
    module = _load_run_harness()
    proc = _InteractiveProcess(["codex"])
    thread_id = "11111111-1111-1111-1111-111111111111"
    events = _event_queue(
        {"id": "numoj-init", "result": {}},
        {"id": "numoj-thread", "result": {"thread": {"id": thread_id}}},
        {"id": "numoj-turn", "result": {"turn": {"id": "turn-failed"}}},
        {
            "method": "turn/completed",
            "params": {
                "turn": {
                    "id": "turn-failed",
                    "status": "failed",
                    "error": {"message": "HTTP 429：Codex 上游限流"},
                },
            },
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

    completed = module._run_codex_interactive(
        "开始", _Commands(), {}, "", "model-a",
    )

    assert completed.returncode == 2
    error = next(
        item["event"] for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("is_error") is True
    )
    assert error["id"] == "turn-failed:error"
    assert error["text"] == "HTTP 429：Codex 上游限流"
    assert capsys.readouterr().err.strip() == (
        "模型请求失败：HTTP 429：Codex 上游限流"
    )


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


def test_opencode_v2_normalizer_keeps_text_tools_and_incremental_usage(monkeypatch):
    module = _load_run_harness()
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    module._normalize_stream_event("opencode", {
        "id": "evt-1",
        "type": "session.next.text.ended",
        "data": {"text": "完成"},
    })
    module._normalize_stream_event("opencode", {
        "id": "evt-2",
        "type": "session.next.tool.called",
        "data": {"tool": "bash", "input": {"command": "pytest"}},
    })
    module._normalize_stream_event("opencode", {
        "id": "evt-3",
        "type": "session.next.step.ended",
        "data": {
            "assistantMessageID": "msg-a",
            "tokens": {
                "input": 12,
                "output": 4,
                "reasoning": 2,
                "cache": {"read": 5, "write": 1},
            },
        },
    })
    module._normalize_stream_event("opencode", {
        "id": "evt-4",
        "type": "session.next.step.failed",
        "data": {"error": {"message": "provider failed"}},
    })

    assert [
        item["event"]["kind"]
        for item in emitted if item.get("type") == "numoj_trace"
    ] == ["assistant", "tool", "tool_result"]
    failed = [
        item["event"]
        for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("is_error")
    ]
    assert failed[0]["title"] == "模型调用失败"
    usage = next(item for item in emitted if item.get("type") == "numoj_usage")
    assert usage["source"] == "opencode"
    assert usage["usage"] == {
        "input_uncached_tokens": 12,
        "input_cached_tokens": 5,
        "input_cache_write_tokens": 1,
        "output_tokens": 6,
        "reasoning_output_tokens": 2,
    }


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
        "opencode",
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


def test_opencode_v1_message_id_is_deterministic_and_sorts_before_native_ids():
    module = _load_run_harness()
    first = module._opencode_message_id("__start__", "task-1")

    assert first == module._opencode_message_id("__start__", "task-1")
    assert first != module._opencode_message_id("__start__", "task-2")
    assert first.startswith("msg_000000000001")
    assert len(first) == len("msg_") + 26
    assert first < "msg_019abcdef001AbCdEfGhIjKlMn"


def test_adapter_terminal_statuses_and_pi_settles_only_at_safe_boundary():
    module = _load_run_harness()

    assert module._stream_terminal_status("codex", {
        "method": "turn/completed",
        "params": {"turn": {"status": "failed"}},
    }) == "failed"
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


@pytest.mark.parametrize("confirmation_source", ("sse", "durable"))
def test_opencode_v1_uses_prompt_async_streams_trace_and_accepts_steer(
        monkeypatch, confirmation_source):
    module = _load_run_harness()
    servers = []
    prompt_payloads = []
    active_assistant_created = threading.Event()

    class Server:
        def __init__(self, args):
            self.args = list(args)
            self.stdout = ()
            self.stderr = ()
            self.stopped = threading.Event()

        def poll(self):
            return None

        def terminate(self):
            self.stopped.set()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.stopped.set()

    def popen(args, **_kwargs):
        server = Server(args)
        servers.append(server)
        return server

    def frame(event):
        return ("data: " + json.dumps(event) + "\n\n").encode()

    class SSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield frame({"type": "server.connected", "properties": {}})
            deadline = time.monotonic() + 2
            while len(prompt_payloads) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(prompt_payloads) == 1
            first_user = prompt_payloads[0]["messageID"]
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_numoj_current",
                    "status": {"type": "busy"},
                },
            })
            # 先创建当前 assistant，再允许测试命令源提交 steer。这覆盖了
            # 固定低 messageID 会排在 active assistant 之前、从而被 V1 loop
            # 忽略的真实竞态。
            yield frame({
                "type": "message.updated",
                "properties": {
                    "sessionID": "ses_numoj_current",
                    "info": {
                        "id": "msg_019abcdef001assistant",
                        "parentID": first_user,
                        "role": "assistant",
                    },
                },
            })
            active_assistant_created.set()
            deadline = time.monotonic() + 2
            while len(prompt_payloads) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(prompt_payloads) == 2
            assert "messageID" not in prompt_payloads[1]
            # steer 请求发出后，原轮 assistant 仍可能迟到上报 error；其
            # parent 已在 steer baseline 中，不能污染新 prompt 的终态。
            yield frame({
                "type": "message.updated",
                "properties": {
                    "sessionID": "ses_numoj_current",
                    "info": {
                        "id": "msg_019abcdef001assistant",
                        "parentID": first_user,
                        "role": "assistant",
                        "error": {"name": "OldStepError"},
                    },
                },
            })
            for index, text in enumerate(("第一段", "调整后完成"), start=1):
                assistant_id = f"msg_019abcdef00{index}assistant"
                if index == 2:
                    if confirmation_source == "sse":
                        yield frame({
                            "type": "message.updated",
                            "properties": {
                                "sessionID": "ses_numoj_current",
                                "info": {
                                    "id": "msg_server_generated_steer",
                                    "role": "user",
                                },
                            },
                        })
                    yield frame({
                        "type": "message.updated",
                        "properties": {
                            "sessionID": "ses_numoj_current",
                            "info": {
                                "id": assistant_id,
                                "parentID": "msg_server_generated_steer",
                                "role": "assistant",
                            },
                        },
                    })
                yield frame({
                    "type": "message.part.updated",
                    "properties": {
                        "sessionID": "ses_numoj_current",
                        "part": {
                            "id": f"prt-text-{index}",
                            "messageID": assistant_id,
                            "type": "text",
                            "text": text,
                            "time": {"start": 1, "end": 2},
                        },
                    },
                })
                yield frame({
                    "type": "message.part.updated",
                    "properties": {
                        "sessionID": "ses_numoj_current",
                        "part": {
                            "id": f"prt-step-{index}",
                            "messageID": assistant_id,
                            "type": "step-finish",
                            "tokens": {
                                "input": 3,
                                "output": 2,
                                "reasoning": 0,
                                "cache": {"read": 1, "write": 0},
                            },
                        },
                    },
                })
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_numoj_current",
                    "status": {"type": "idle"},
                },
            })

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session" and method == "POST":
            assert payload["model"] == {
                "providerID": "agent-judge",
                "id": "model-a",
            }
            assert payload["permission"][-1]["permission"] == "plan_exit"
            return {"id": "ses_numoj_current"}
        if path == "/session/ses_numoj_current/message" and method == "GET":
            if not prompt_payloads:
                return []
            first_user = prompt_payloads[0]["messageID"]
            records = [
                {"info": {"id": first_user, "role": "user"}, "parts": []},
                {
                    "info": {
                        "id": "msg_019abcdef001assistant",
                        "parentID": first_user,
                        "role": "assistant",
                    },
                    "parts": [],
                },
            ]
            if len(prompt_payloads) >= 2:
                records.append({
                    "info": {
                        "id": "msg_server_generated_steer",
                        "role": "user",
                    },
                    "parts": [],
                })
            return records
        if path == "/session/ses_numoj_current/prompt_async" and method == "POST":
            prompt_payloads.append(dict(payload))
            return None
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_args, **_kwargs: SSE())
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    class CommandsAfterAssistant:
        sent = False

        def drain(self):
            if self.sent or not active_assistant_created.is_set():
                return []
            self.sent = True
            return [{"type": "steer", "id": "steer-1", "message": "调整"}]

    completed = module._run_opencode_interactive(
        "第一轮",
        CommandsAfterAssistant(),
        {"AJ_TASK_ID": "task-turn-1"},
        "",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 0
    assert [item["parts"][0]["text"] for item in prompt_payloads] == [
        "第一轮", "调整",
    ]
    assert prompt_payloads[0]["messageID"].startswith("msg_000000000001")
    assert "messageID" not in prompt_payloads[1]
    assert [
        item["event"]["text"]
        for item in emitted
        if item.get("type") == "numoj_trace"
        and item["event"].get("kind") == "assistant"
    ] == ["第一段", "调整后完成"]
    assert len([item for item in emitted if item.get("type") == "numoj_usage"]) == 2
    first_trace_index = next(
        index for index, item in enumerate(emitted)
        if item.get("type") == "numoj_trace"
        and item["event"].get("text") == "第一段"
    )
    accepted_index = next(
        index for index, item in enumerate(emitted)
        if item.get("type") == "numoj_control"
        and item.get("id") == "steer-1"
        and item.get("status") == "accepted"
    )
    adjusted_trace_index = next(
        index for index, item in enumerate(emitted)
        if item.get("type") == "numoj_trace"
        and item["event"].get("text") == "调整后完成"
    )
    assert first_trace_index < accepted_index < adjusted_trace_index


def test_opencode_v1_resume_uses_server_generated_ordered_message_id(
        monkeypatch):
    module = _load_run_harness()
    prompt_payloads = []
    sse_attempts = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    def frame(event):
        return ("data: " + json.dumps(event) + "\n\n").encode()

    class SSE:
        def __init__(self, attempt):
            self.attempt = attempt

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield frame({"type": "server.connected", "properties": {}})
            if self.attempt == 1:
                return
            deadline = time.monotonic() + 2
            while not prompt_payloads and time.monotonic() < deadline:
                time.sleep(0.01)
            assert prompt_payloads
            assert "messageID" not in prompt_payloads[0]
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_existing",
                    "status": {"type": "busy"},
                },
            })
            yield frame({
                "type": "message.updated",
                "properties": {
                    "sessionID": "ses_existing",
                    "info": {
                        "id": "msg_019abcdef100assistant",
                        "parentID": "msg_019abcdef099serveruser",
                        "role": "assistant",
                    },
                },
            })
            yield frame({
                "type": "message.part.updated",
                "properties": {
                    "sessionID": "ses_existing",
                    "part": {
                        "id": "prt-resume-text",
                        "messageID": "msg_019abcdef100assistant",
                        "type": "text",
                        "text": "续聊完成",
                        "time": {"start": 1, "end": 2},
                    },
                },
            })
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_existing",
                    "status": {"type": "idle"},
                },
            })

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_existing" and method == "GET":
            return {"id": "ses_existing"}
        if path == "/session/ses_existing/prompt_async" and method == "POST":
            prompt_payloads.append(dict(payload))
            return None
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: Server())
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (
            sse_attempts.append(len(sse_attempts) + 1)
            or SSE(sse_attempts[-1])
        ),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_opencode_interactive(
        "继续",
        _Commands(),
        {"AJ_TASK_ID": "task-turn-2"},
        "ses_existing",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 0
    assert sse_attempts == [1, 2]
    assert "messageID" not in prompt_payloads[0]
    assert any(
        item.get("type") == "numoj_trace"
        and item["event"].get("text") == "续聊完成"
        for item in emitted
    )


@pytest.mark.parametrize(
    ("assistant_error", "expected_returncode"),
    [
        (None, 0),
        ({"name": "ProviderError", "data": {"message": "模型失败"}}, 2),
    ],
)
def test_opencode_v1_reconciles_terminal_message_lost_during_sse_gap(
        monkeypatch, capsys, assistant_error, expected_returncode):
    module = _load_run_harness()
    prompt_payloads = []
    durable_messages = []
    sse_attempts = []
    servers = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def __init__(self):
            self.stopped = threading.Event()

        def poll(self):
            return None

        def terminate(self):
            self.stopped.set()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.stopped.set()

    def frame(event):
        return ("data: " + json.dumps(event) + "\n\n").encode()

    class SSE:
        def __init__(self, attempt):
            self.attempt = attempt

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield frame({"type": "server.connected", "properties": {}})
            if self.attempt == 1:
                deadline = time.monotonic() + 2
                while not prompt_payloads and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert prompt_payloads
                user_id = "msg_server_generated_gap_user"
                assistant_info = {
                    "id": "msg_server_generated_gap_assistant",
                    "parentID": user_id,
                    "role": "assistant",
                    "finish": "stop",
                }
                if assistant_error is not None:
                    assistant_info["error"] = assistant_error
                    assistant_info.pop("finish", None)
                durable_messages.extend([
                    {"info": {"id": user_id, "role": "user"}, "parts": []},
                    {
                        "info": assistant_info,
                        "parts": [] if assistant_error is not None else [
                            {
                                "id": "prt-gap-text",
                                "messageID": assistant_info["id"],
                                "type": "text",
                                "text": "断线期间完成",
                            },
                            {
                                "id": "prt-gap-finish",
                                "messageID": assistant_info["id"],
                                "type": "step-finish",
                                "tokens": {"input": 3, "output": 2},
                            },
                        ],
                    },
                ])
                # terminal live events 正好落在 EOF 到重连之间，第二条流也
                # 不回放；adapter 必须依赖 durable message/status 对账。
                return
            while not servers[0].stopped.wait(0.01):
                pass

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_gap" and method == "GET":
            return {"id": "ses_gap"}
        if path == "/session/ses_gap/message" and method == "GET":
            return list(durable_messages)
        if path == "/session/status" and method == "GET":
            # OpenCode 会从 status map 删除已经 idle 的 session。
            return {}
        if path == "/session/ses_gap/prompt_async" and method == "POST":
            prompt_payloads.append(dict(payload))
            return None
        raise AssertionError((method, path, payload))

    def popen(*_args, **_kwargs):
        server = Server()
        servers.append(server)
        return server

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (
            sse_attempts.append(len(sse_attempts) + 1)
            or SSE(sse_attempts[-1])
        ),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_opencode_interactive(
        "继续",
        _Commands(),
        {"AJ_TASK_ID": "task-gap"},
        "ses_gap",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == expected_returncode
    assert prompt_payloads
    if assistant_error is None:
        assert any(
            item.get("type") == "numoj_trace"
            and item["event"].get("text") == "断线期间完成"
            for item in emitted
        )
    else:
        assert any(
            item.get("type") == "numoj_trace"
            and item["event"].get("is_error") is True
            for item in emitted
        )
        assert capsys.readouterr().err.strip() == (
            "模型请求失败：模型失败"
        )


def test_opencode_v1_bounds_persistent_sse_reconnect_failures(monkeypatch):
    module = _load_run_harness()
    prompt_sent = threading.Event()
    attempts = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    class InitialSSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield b'data: {"type":"server.connected","properties":{}}\n\n'
            assert prompt_sent.wait(2)

    def urlopen(request, **_kwargs):
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            return InitialSSE()
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "broken event stream",
            {},
            io.BytesIO(b"failed"),
        )

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_reconnect" and method == "GET":
            return {"id": "ses_reconnect"}
        if path == "/session/ses_reconnect/message" and method == "GET":
            return []
        if path == "/session/ses_reconnect/prompt_async" and method == "POST":
            prompt_sent.set()
            return None
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_a, **_k: Server())
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "OPENCODE_SSE_RECONNECT_FAILURE_SECONDS", 0.03)

    completed = module._run_opencode_interactive(
        "继续",
        _Commands(),
        {"AJ_TASK_ID": "task-reconnect"},
        "ses_reconnect",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 2
    assert len(attempts) >= 3


@pytest.mark.parametrize("persist_user", [False, True])
def test_opencode_v1_fails_if_accepted_prompt_never_creates_assistant(
        monkeypatch, capsys, persist_user):
    module = _load_run_harness()
    prompt_sent = threading.Event()
    durable_messages = [
        {"info": {"id": "msg_baseline_user", "role": "user"}, "parts": []},
        {
            "info": {"id": "msg_baseline_assistant", "role": "assistant"},
            "parts": [],
        },
    ]
    attempts = []
    servers = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def __init__(self):
            self.stopped = threading.Event()

        def poll(self):
            return None

        def terminate(self):
            self.stopped.set()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.stopped.set()

    class SSE:
        def __init__(self, attempt):
            self.attempt = attempt

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield b'data: {"type":"server.connected","properties":{}}\n\n'
            if self.attempt == 1:
                assert prompt_sent.wait(2)
                if persist_user:
                    yield (
                        b'data: {"type":"session.next.step.failed",'
                        b'"properties":{"sessionID":"ses_missing_assistant",'
                        b'"error":{"message":"provider failed"}}}\n\n'
                    )
                    yield (
                        b'data: {"type":"session.status","properties":'
                        b'{"sessionID":"ses_missing_assistant","status":'
                        b'{"type":"idle"}}}\n\n'
                    )
                else:
                    # 新 prompt 后仍可能收到原轮 active assistant 的更新；
                    # 其 parent 位于 baseline，不能冒充新 prompt 的回复。
                    yield (
                        b'data: {"type":"message.updated","properties":'
                        b'{"sessionID":"ses_missing_assistant","info":'
                        b'{"id":"msg_baseline_assistant","parentID":'
                        b'"msg_baseline_user","role":"assistant"}}}\n\n'
                    )
                    yield (
                        b'data: {"type":"session.status","properties":'
                        b'{"sessionID":"ses_missing_assistant","status":'
                        b'{"type":"idle"}}}\n\n'
                    )
                return
            while not servers[0].stopped.wait(0.01):
                pass

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_missing_assistant" and method == "GET":
            return {"id": "ses_missing_assistant"}
        if path == "/session/ses_missing_assistant/message" and method == "GET":
            return list(durable_messages)
        if path == "/session/status" and method == "GET":
            return {}
        if path == "/session/ses_missing_assistant/prompt_async" and method == "POST":
            if persist_user:
                durable_messages.append({
                    "info": {"id": "msg_accepted_user", "role": "user"},
                    "parts": [],
                })
            prompt_sent.set()
            return None
        raise AssertionError((method, path, payload))

    def popen(*_args, **_kwargs):
        server = Server()
        servers.append(server)
        return server

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (
            attempts.append(len(attempts) + 1)
            or SSE(attempts[-1])
        ),
    )
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))
    monkeypatch.setattr(module, "OPENCODE_PROMPT_PERSISTENCE_SECONDS", 0.04)
    monkeypatch.setattr(module, "OPENCODE_DURABLE_RECONCILE_INTERVAL_SECONDS", 0.01)

    completed = module._run_opencode_interactive(
        "触发模型初始化失败",
        _Commands(),
        {"AJ_TASK_ID": "task-missing-assistant"},
        "ses_missing_assistant",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 2
    assert prompt_sent.is_set()
    if persist_user:
        assert any(
            item.get("type") == "numoj_trace"
            and item["event"].get("is_error") is True
            and item["event"].get("text") == "provider failed"
            for item in emitted
        )
        assert capsys.readouterr().err.strip() == (
            "模型请求失败：provider failed"
        )


def test_opencode_v1_reconciles_interrupt_without_assistant_after_sse_gap(
        monkeypatch):
    module = _load_run_harness()
    durable_messages = []
    abort_sent = threading.Event()

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    class SSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield b'data: {"type":"server.connected","properties":{}}\n\n'
            assert abort_sent.wait(2)
            # abort 后的 idle live event 落在断线窗口中。

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_abort_gap" and method == "GET":
            return {"id": "ses_abort_gap"}
        if path == "/session/ses_abort_gap/message" and method == "GET":
            return list(durable_messages)
        if path == "/session/status" and method == "GET":
            return {}
        if path == "/session/ses_abort_gap/prompt_async" and method == "POST":
            durable_messages.append({
                "info": {"id": "msg_abort_gap_user", "role": "user"},
                "parts": [],
            })
            return None
        if path == "/session/ses_abort_gap/abort" and method == "POST":
            abort_sent.set()
            return True
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_a, **_k: Server())
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_a, **_k: SSE())
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)

    completed = module._run_opencode_interactive(
        "开始",
        _Commands([{"type": "interrupt", "id": "stop-gap"}]),
        {"AJ_TASK_ID": "task-abort-gap"},
        "ses_abort_gap",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 130
    assert abort_sent.is_set()


def test_opencode_v1_waits_past_intermediate_step_and_recovers_compaction_error(
        monkeypatch):
    module = _load_run_harness()
    prompt_sent = threading.Event()
    durable_messages = []
    session_busy = {"value": True}
    servers = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def __init__(self):
            self.stopped = threading.Event()

        def poll(self):
            return None

        def terminate(self):
            self.stopped.set()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.stopped.set()

    def frame(event):
        return ("data: " + json.dumps(event) + "\n\n").encode()

    class SSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield frame({"type": "server.connected", "properties": {}})
            assert prompt_sent.wait(2)
            user = {"info": {"id": "msg_compact_user", "role": "user"}, "parts": []}
            intermediate_info = {
                "id": "msg_compact_intermediate",
                "parentID": "msg_compact_user",
                "role": "assistant",
                "finish": "tool-calls",
            }
            intermediate_parts = [{
                "id": "prt-compact-intermediate",
                "messageID": intermediate_info["id"],
                "type": "step-finish",
                "tokens": {"input": 4, "output": 1},
            }]
            durable_messages.extend([
                user,
                {"info": intermediate_info, "parts": intermediate_parts},
            ])
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_compaction",
                    "status": {"type": "busy"},
                },
            })
            yield frame({
                "type": "session.error",
                "properties": {
                    "sessionID": "ses_compaction",
                    "error": {
                        "name": "ContextOverflowError",
                        "data": {"message": "compacting"},
                    },
                },
            })
            # 给 durable poll 足够时间观察“中间 step 已完成但 session busy”。
            time.sleep(module.OPENCODE_DURABLE_RECONCILE_INTERVAL_SECONDS + 0.2)
            final_info = {
                "id": "msg_compact_final",
                "parentID": "msg_compact_user",
                "role": "assistant",
                "finish": "stop",
            }
            final_part = {
                "id": "prt-compact-final",
                "messageID": final_info["id"],
                "type": "text",
                "text": "压缩后最终完成",
                "time": {"start": 2, "end": 3},
            }
            durable_messages.append({"info": final_info, "parts": [final_part]})
            session_busy["value"] = False
            yield frame({
                "type": "message.updated",
                "properties": {
                    "sessionID": "ses_compaction",
                    "info": final_info,
                },
            })
            yield frame({
                "type": "message.part.updated",
                "properties": {
                    "sessionID": "ses_compaction",
                    "part": final_part,
                },
            })
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_compaction",
                    "status": {"type": "idle"},
                },
            })
            while not servers[0].stopped.wait(0.01):
                pass

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_compaction" and method == "GET":
            return {"id": "ses_compaction"}
        if path == "/session/ses_compaction/message" and method == "GET":
            return list(durable_messages)
        if path == "/session/status" and method == "GET":
            return (
                {"ses_compaction": {"type": "busy"}}
                if session_busy["value"] else {}
            )
        if path == "/session/ses_compaction/prompt_async" and method == "POST":
            prompt_sent.set()
            return None
        raise AssertionError((method, path, payload))

    def popen(*_args, **_kwargs):
        server = Server()
        servers.append(server)
        return server

    monkeypatch.setattr(module.subprocess, "Popen", popen)
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_a, **_k: SSE())
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_opencode_interactive(
        "需要工具的任务",
        _Commands(),
        {"AJ_TASK_ID": "task-compaction"},
        "ses_compaction",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 0
    assert any(
        item.get("type") == "numoj_trace"
        and item["event"].get("text") == "压缩后最终完成"
        for item in emitted
    )


def test_opencode_rejected_steer_keeps_queued_terminal_events(monkeypatch):
    module = _load_run_harness()
    events_queued = threading.Event()
    prompt_payloads = []

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()
        stopped = threading.Event()

        def poll(self):
            return None

        def terminate(self):
            self.stopped.set()

        def wait(self, timeout=None):
            return 0

        def kill(self):
            self.stopped.set()

    def frame(event):
        return ("data: " + json.dumps(event) + "\n\n").encode()

    class SSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield frame({"type": "server.connected", "properties": {}})
            deadline = time.monotonic() + 2
            while not prompt_payloads and time.monotonic() < deadline:
                time.sleep(0.01)
            assert prompt_payloads
            assistant_id = "msg_final_before_rejected_steer"
            yield frame({
                "type": "message.updated",
                "properties": {
                    "sessionID": "ses_rejected_steer",
                    "info": {
                        "id": assistant_id,
                        "parentID": "msg_current_user",
                        "role": "assistant",
                    },
                },
            })
            yield frame({
                "type": "message.part.updated",
                "properties": {
                    "sessionID": "ses_rejected_steer",
                    "part": {
                        "id": "prt-final",
                        "messageID": assistant_id,
                        "type": "text",
                        "text": "原轮完成",
                        "time": {"start": 1, "end": 2},
                    },
                },
            })
            yield frame({
                "type": "session.status",
                "properties": {
                    "sessionID": "ses_rejected_steer",
                    "status": {"type": "idle"},
                },
            })
            events_queued.set()
            while not Server.stopped.wait(0.01):
                pass

    old_messages = [
        {"info": {"id": "msg_old_user", "role": "user"}, "parts": []},
        {"info": {"id": "msg_old_assistant", "role": "assistant"}, "parts": []},
    ]

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session/ses_rejected_steer" and method == "GET":
            return {"id": "ses_rejected_steer"}
        if path == "/session/ses_rejected_steer/message" and method == "GET":
            return old_messages
        if path == "/session/status" and method == "GET":
            return {"ses_rejected_steer": {"type": "busy"}}
        if path == "/session/ses_rejected_steer/prompt_async" and method == "POST":
            prompt_payloads.append(dict(payload))
            if len(prompt_payloads) > 1:
                raise urllib.error.HTTPError(
                    "http://127.0.0.1/prompt_async",
                    409,
                    "session already idle",
                    {},
                    io.BytesIO(b"session already idle"),
                )
            return None
        raise AssertionError((method, path, payload))

    class CommandsAfterTerminalQueued:
        sent = False

        def drain(self):
            if self.sent or not events_queued.is_set():
                return []
            self.sent = True
            return [{"type": "steer", "id": "late-steer", "message": "迟到插话"}]

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_a, **_k: Server())
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_a, **_k: SSE())
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_opencode_interactive(
        "继续原轮",
        CommandsAfterTerminalQueued(),
        {"AJ_TASK_ID": "task-rejected-steer"},
        "ses_rejected_steer",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 0
    assert len(prompt_payloads) == 1
    assert any(
        item.get("type") == "numoj_control"
        and item.get("id") == "late-steer"
        and item.get("status") == "rejected"
        for item in emitted
    )
    assert any(
        item.get("type") == "numoj_trace"
        and item["event"].get("text") == "原轮完成"
        for item in emitted
    )


def test_opencode_v1_abort_returns_interrupted(monkeypatch):
    module = _load_run_harness()
    prompt_sent = threading.Event()
    abort_sent = threading.Event()

    class Server:
        args = ["opencode", "serve"]
        stdout = ()
        stderr = ()

        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    class SSE:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def __iter__(self):
            yield b'data: {"type":"server.connected","properties":{}}\n\n'
            assert prompt_sent.wait(2)
            yield b'data: {"type":"session.status","properties":{"sessionID":"ses_numoj_current","status":{"type":"busy"}}}\n\n'
            assert abort_sent.wait(2)
            yield b'data: {"type":"session.status","properties":{"sessionID":"ses_numoj_current","status":{"type":"idle"}}}\n\n'

    def http_request(_base_url, path, *, method="GET", payload=None, **_kwargs):
        if path == "/session" and method == "POST":
            return {"id": "ses_numoj_current"}
        if path.endswith("/prompt_async") and method == "POST":
            prompt_sent.set()
            return None
        if path.endswith("/abort") and method == "POST":
            abort_sent.set()
            return True
        raise AssertionError((method, path, payload))

    monkeypatch.setattr(module.subprocess, "Popen", lambda *_args, **_kwargs: Server())
    monkeypatch.setattr(module, "_free_loopback_port", lambda: 18888)
    monkeypatch.setattr(module, "_wait_opencode_server", lambda *_args: None)
    monkeypatch.setattr(module, "_http_request", http_request)
    monkeypatch.setattr(module.urllib.request, "urlopen", lambda *_args, **_kwargs: SSE())
    monkeypatch.setattr(module, "_record_live_session", lambda *_args, **_kwargs: None)
    emitted = []
    monkeypatch.setattr(module, "_emit_numoj", lambda item: emitted.append(item))

    completed = module._run_opencode_interactive(
        "开始",
        _Commands([{"type": "interrupt", "id": "stop-1"}]),
        {"AJ_TASK_ID": "task-turn-1"},
        "",
        "model-a",
        ["opencode"],
    )

    assert completed.returncode == 130
    assert any(
        item.get("type") == "numoj_control"
        and item.get("id") == "stop-1"
        and item.get("status") == "accepted"
        for item in emitted
    )
