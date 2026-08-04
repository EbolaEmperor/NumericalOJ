# -*- coding: utf-8 -*-
"""Agent Judge 镜像入口必须边执行边转发 CLI 输出。"""

import importlib.machinery
import importlib.util
import http.server
import json
import os
from pathlib import Path
import sys
import threading
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


def _write_pi_terminal_message(session_dir, session_id, **terminal_fields):
    session_path = session_dir / "--workspace--" / f"native_{session_id}.jsonl"
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
        "content": [{"type": "text", "text": "state"}],
        **terminal_fields,
    }
    with session_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "type": "message",
            "id": f"assistant-{session_path.stat().st_size}",
            "message": message,
        }) + "\n")
    return session_path


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


def test_claude_adapter_rejects_context_above_supported_contract(monkeypatch):
    module = _load_run_harness()
    _set_anthropic_endpoint(monkeypatch, module)
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "1000001")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "384000")
    monkeypatch.setattr(
        module,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("unsupported context must fail before CLI"),
    )

    assert module._run_claude_code("solve") == 2


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
    response_body = b'data: {"type":"response.output_text.delta"}\n\ndata: [DONE]\n\n'

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
            assert response.read() == response_body
    finally:
        relay.stop()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)

    assert received["path"] == "/v1/responses?stream=true"
    assert received["authorization"] == "Bearer temporary-token"
    assert received["body"] == {
        "model": "generic-model",
        "input": [{"role": "user", "content": "solve"}],
        "max_output_tokens": 384_000,
    }


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
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", "33333333-3333-3333-3333-333333333333")
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


@pytest.mark.parametrize(("runner_name", "protocol"), [
    ("_run_claude_code", "anthropic"),
    ("_run_codex", "openai"),
    ("_run_opencode", "openai"),
    ("_run_pi", "openai"),
])
def test_all_harnesses_reject_context_above_one_million(
        monkeypatch, runner_name, protocol):
    module = _load_run_harness()
    _set_endpoint(monkeypatch, protocol=protocol)
    monkeypatch.setenv("AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS", "1000001")
    monkeypatch.setenv("AJ_ENDPOINT_MAX_OUTPUT_TOKENS", "384000")
    monkeypatch.setattr(
        module, "_run",
        lambda *_args, **_kwargs: pytest.fail("超过 1M 时不得启动 harness"),
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
        "--no-context-files",
    ):
        assert flag in args
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


@pytest.mark.parametrize(
    "terminal_fields",
    [
        {"stopReason": "length"},
        {"stopReason": "error", "rawStopReason": "max_tokens"},
    ],
)
def test_pi_ordinary_agent_auto_resumes_output_limit_in_same_native_session(
    monkeypatch,
    tmp_path,
    terminal_fields,
):
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
        if len(calls) == 1:
            _write_pi_terminal_message(
                session_dir,
                session_id,
                **terminal_fields,
            )
        else:
            _write_pi_terminal_message(
                session_dir,
                session_id,
                stopReason="stop",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *_args, **_kwargs: session_id,
    )

    assert module._run_pi("solve") == 0

    assert len(calls) == 2
    assert "--session" not in calls[0]
    assert calls[1][calls[1].index("--session") + 1] == session_id
    assert calls[1][calls[1].index("--thinking") + 1] == "off"


def test_pi_output_limit_continuation_fails_when_native_session_does_not_advance(
    monkeypatch,
    tmp_path,
):
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
        if len(calls) == 1:
            _write_pi_terminal_message(
                session_dir,
                session_id,
                stopReason="length",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *_args, **_kwargs: session_id,
    )

    assert module._run_pi("solve") == 2
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("stop_reason", "raw_stop_reason"),
    [("error", "upstream_error"), ("stop", "stop")],
)
def test_pi_ordinary_agent_does_not_resume_normal_or_error(
    monkeypatch,
    tmp_path,
    stop_reason,
    raw_stop_reason,
):
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
    _write_pi_terminal_message(
        session_dir,
        session_id,
        stopReason=stop_reason,
        rawStopReason=raw_stop_reason,
    )
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **_kwargs: (
            calls.append(list(args))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *_args, **_kwargs: session_id,
    )

    assert module._run_pi("solve") == 0
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("phase", "audit_read_only", "problem_agent_scope"),
    [
        ("reverse_solve", False, True),
        ("", True, True),
        ("", False, False),
    ],
)
def test_pi_nonordinary_or_unscoped_runs_do_not_auto_resume_output_limit(
    monkeypatch,
    tmp_path,
    phase,
    audit_read_only,
    problem_agent_scope,
):
    module = _load_run_harness()
    config_dir = tmp_path / "pi-agent"
    session_dir = config_dir / "sessions"
    session_id = "44444444-4444-4444-4444-444444444444"
    calls = []
    monkeypatch.setattr(module, "PI_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(module, "PI_SESSION_DIR", str(session_dir))
    if phase:
        monkeypatch.setenv("AJ_PHASE", phase)
    else:
        monkeypatch.delenv("AJ_PHASE", raising=False)
    if audit_read_only:
        monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "1")
    else:
        monkeypatch.delenv("AJ_AUDIT_READ_ONLY", raising=False)
    if problem_agent_scope:
        monkeypatch.setenv("AJ_TASK_SCOPE", "problem_agent")
    else:
        monkeypatch.delenv("AJ_TASK_SCOPE", raising=False)
    monkeypatch.delenv("AJ_RESUME_SESSION_ID", raising=False)
    _set_endpoint(monkeypatch)
    _write_pi_terminal_message(session_dir, session_id, stopReason="length")
    monkeypatch.setattr(
        module,
        "_run",
        lambda args, **_kwargs: (
            calls.append(list(args))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(
        module,
        "_record_session",
        lambda *_args, **_kwargs: session_id,
    )

    assert module._run_pi("solve") == 0
    assert len(calls) == 1


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
    )

    proc = module._run(command, env=env)

    assert session_id not in proc.stdout
    assert proc.aj_session_id == session_id


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
