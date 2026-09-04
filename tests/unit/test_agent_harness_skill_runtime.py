# -*- coding: utf-8 -*-
"""Agent harness 的 stdin prompt、受管 home 与 skill 加载。"""

import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "docker" / "agent_judge" / "run_harness"


def _load_run_harness():
    loader = importlib.machinery.SourceFileLoader(
        "agent_harness_skill_runtime_test", str(SCRIPT),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _materialized_skill(runtime_root, harness):
    relative = {
        "claude_code": Path("home/.claude/skills/numoj-user"),
        "pi": Path("pi/skills/numoj-user"),
    }[harness]
    skill_dir = runtime_root / relative
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text(
        "---\nname: numoj-user\ndescription: test\n---\n", encoding="utf-8",
    )
    return skill_file


def _enable_runtime(monkeypatch, tmp_path, harness):
    runtime_root = tmp_path / ".runtime"
    runtime_root.mkdir()
    skill_file = _materialized_skill(runtime_root, harness)
    monkeypatch.setenv("AJ_ENABLE_SKILLS", "1")
    monkeypatch.setenv("AJ_RUNTIME_ROOT", str(runtime_root))
    monkeypatch.setenv("AJ_WORKSPACE", str(tmp_path))
    return runtime_root, skill_file


def _set_endpoint(monkeypatch, protocol="openai"):
    monkeypatch.setenv("AJ_ENDPOINT_PROTOCOL", protocol)
    monkeypatch.setenv(
        "AJ_ENDPOINT_BASE_URL",
        "https://model.example/anthropic"
        if protocol == "anthropic" else "https://model.example/v1",
    )
    monkeypatch.setenv("AJ_ENDPOINT_API_KEY", "temporary-token")
    monkeypatch.setenv("AJ_ENDPOINT_MODEL", "model")


def test_prompt_file_has_priority_over_stdin_and_environment(monkeypatch, tmp_path):
    module = _load_run_harness()
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("from-file", encoding="utf-8")
    monkeypatch.setenv("AJ_PROMPT_FILE", str(prompt_file))
    monkeypatch.setenv("AJ_PROMPT_STDIN", "1")
    monkeypatch.setenv("AJ_PROMPT", "from-env")
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("from-stdin"))

    assert module._prompt_from_env() == "from-file"


def test_prompt_stdin_has_priority_over_environment(monkeypatch):
    module = _load_run_harness()
    monkeypatch.delenv("AJ_PROMPT_FILE", raising=False)
    monkeypatch.setenv("AJ_PROMPT_STDIN", "true")
    monkeypatch.setenv("AJ_PROMPT", "from-env")
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("from-stdin"))

    assert module._prompt_from_env() == "from-stdin"


def test_prompt_environment_remains_legacy_default(monkeypatch):
    module = _load_run_harness()
    monkeypatch.delenv("AJ_PROMPT_FILE", raising=False)
    monkeypatch.delenv("AJ_PROMPT_STDIN", raising=False)
    monkeypatch.setenv("AJ_PROMPT", "from-env")
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("must-not-read"))

    assert module._prompt_from_env() == "from-env"






def test_pi_explicitly_loads_only_materialized_skill(monkeypatch, tmp_path):
    module = _load_run_harness()
    runtime_root, skill_file = _enable_runtime(monkeypatch, tmp_path, "pi")
    calls = []
    _set_endpoint(monkeypatch)
    monkeypatch.setattr(
        module, "_run",
        lambda args, env=None, **_kwargs: (
            calls.append((list(args), dict(env or {})))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_pi("solve") == 0
    args, env = calls[0]
    assert "--no-skills" in args
    assert args[args.index("--skill") + 1] == str(skill_file)
    assert env["PI_CODING_AGENT_DIR"] == str(runtime_root / "pi/agent")
    assert env["PI_CODING_AGENT_SESSION_DIR"] == str(
        runtime_root / "pi/agent/sessions",
    )
    models = json.loads(
        (runtime_root / "pi/agent/models.json").read_text(encoding="utf-8"),
    )
    assert models["providers"]["agent-judge"]["models"][0]["id"] == "model"


def test_claude_discovers_skill_from_workspace_runtime_home(monkeypatch, tmp_path):
    module = _load_run_harness()
    runtime_root, _skill_file = _enable_runtime(
        monkeypatch, tmp_path, "claude_code",
    )
    calls = []
    _set_endpoint(monkeypatch, "anthropic")

    class FakeRelay:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            return "http://127.0.0.1:43123"

        def stop(self):
            pass

    monkeypatch.setattr(module, "_ClaudeEndpointRelay", FakeRelay)
    monkeypatch.setattr(
        module, "_run",
        lambda args, env=None, **_kwargs: (
            calls.append((list(args), dict(env or {})))
            or SimpleNamespace(returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.setattr(module, "_record_session", lambda *_args, **_kwargs: "")

    assert module._run_claude_code("solve") == 0
    assert calls[0][1]["HOME"] == str(runtime_root / "home")


def test_enabled_skills_fail_closed_when_projection_is_missing(
        monkeypatch, tmp_path):
    module = _load_run_harness()
    runtime_root = tmp_path / ".runtime"
    runtime_root.mkdir()
    monkeypatch.setenv("AJ_ENABLE_SKILLS", "1")
    monkeypatch.setenv("AJ_RUNTIME_ROOT", str(runtime_root))
    monkeypatch.setenv("AJ_WORKSPACE", str(tmp_path))
    _set_endpoint(monkeypatch, "anthropic")
    monkeypatch.setattr(
        module, "_run",
        lambda *_args, **_kwargs: pytest.fail("缺少 skill 时不得启动 harness"),
    )

    assert module._run_claude_code("solve") == 2


def test_runtime_root_must_stay_inside_workspace(monkeypatch, tmp_path):
    module = _load_run_harness()
    monkeypatch.setenv("AJ_RUNTIME_ROOT", str(tmp_path / "outside"))
    monkeypatch.setenv("AJ_WORKSPACE", str(tmp_path / "workspace"))
    _set_endpoint(monkeypatch, "anthropic")
    monkeypatch.setattr(
        module, "_run",
        lambda *_args, **_kwargs: pytest.fail("运行时越界时不得启动 harness"),
    )

    assert module._run_claude_code("solve") == 2
