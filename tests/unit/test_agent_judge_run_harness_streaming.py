# -*- coding: utf-8 -*-
"""Agent Judge 镜像入口必须边执行边转发 CLI 输出。"""

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker" / "agent_judge" / "run_harness"


def _load_run_harness():
    loader = importlib.machinery.SourceFileLoader("agent_judge_run_harness_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


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
    monkeypatch.setenv("ANTHROPIC_MODEL", "deepseek-v4-flash")
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
    assert args[-1] == "audit prompt"
    assert "--dangerously-skip-permissions" not in args
    assert "--resume" not in args
    assert "--fork-session" not in args
    assert all(forbidden not in ",".join(args) for forbidden in ("Bash", "Write", "Edit"))
    assert kwargs == {}


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


def test_codex_audit_mode_uses_read_only_sandbox_without_bypass(monkeypatch):
    module = _load_run_harness()
    calls = []
    configs = []
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "true")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://quality-model-proxy:18080/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "temporary-token")
    monkeypatch.setenv("OPENAI_MODEL", "deepseek-v4-flash")
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", "22222222-2222-2222-2222-222222222222")
    monkeypatch.setattr(
        module, "_write_codex_config",
        lambda home, base_url, model: configs.append((home, base_url, model)),
    )

    def run(args, env=None, input_text=None):
        calls.append((list(args), dict(env or {}), input_text))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(module, "_run", run)
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_codex("audit prompt") == 0

    args, env, input_text = calls[0]
    assert configs == [(
        "/workspace/.codex", "http://quality-model-proxy:18080/v1",
        "deepseek-v4-flash",
    )]
    assert args[:2] == ["codex", "exec"]
    assert "--json" in args
    assert args[args.index("--sandbox") + 1] == "read-only"
    assert args[args.index("--cd") + 1] == "/workspace"
    assert "--dangerously-bypass-approvals-and-sandbox" not in args
    assert "resume" not in args
    assert args[-1] == "-"
    assert input_text == "audit prompt"
    assert env["CODEX_HOME"] == "/workspace/.codex"
    assert env["AJ_OPENAI_API_KEY"] == "temporary-token"


def test_opencode_audit_mode_denies_all_except_evidence_read_tools(monkeypatch):
    module = _load_run_harness()
    calls = []
    monkeypatch.setenv("AJ_AUDIT_READ_ONLY", "on")
    monkeypatch.setenv("OPENCODE_BASE_URL", "http://quality-model-proxy:18080/v1")
    monkeypatch.setenv("OPENCODE_API_KEY", "temporary-token")
    monkeypatch.setenv("OPENCODE_MODEL", "deepseek-v4-flash")
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
    assert env["OPENCODE_API_KEY"] == "temporary-token"
    assert all(env[name] == "true" for name in (
        "OPENCODE_DISABLE_DEFAULT_PLUGINS",
        "OPENCODE_DISABLE_CLAUDE_CODE",
        "OPENCODE_DISABLE_AUTOUPDATE",
        "OPENCODE_DISABLE_LSP_DOWNLOAD",
        "OPENCODE_DISABLE_MODELS_FETCH",
    ))


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
    monkeypatch.setenv("OPENAI_BASE_URL", "http://answer-model-proxy:18080/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "temporary-token")
    monkeypatch.setenv("OPENAI_MODEL", "deepseek-v4-flash")
    monkeypatch.setenv("AJ_RESUME_SESSION_ID", resume_id)
    monkeypatch.setenv("AJ_PHASE", "reverse_solve")

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
    assert args[args.index("--model") + 1] == "deepseek-v4-flash"
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
    assert env["PI_API_KEY"] == "temporary-token"
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
        "apiKey": "$PI_API_KEY",
        "authHeader": True,
        "compat": {
            "supportsStore": False,
            "maxTokensField": "max_tokens",
        },
        "models": [{
            "id": "deepseek-v4-flash",
            "name": "deepseek-v4-flash",
        }],
    }
    assert "reasoning" not in json.dumps(config)
    assert recorded[0][0] == "pi"
    assert recorded[0][2] == resume_id


@pytest.mark.parametrize("missing_name", [
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
])
def test_pi_requires_complete_openai_endpoint(monkeypatch, missing_name):
    module = _load_run_harness()
    monkeypatch.setenv("OPENAI_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("OPENAI_MODEL", "model")
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
