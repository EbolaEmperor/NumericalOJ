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
