import os
import subprocess
from pathlib import Path

import pytest

from oj_modules.tasks.ranking import evaluate
from oj_modules.tasks.ranking import standard_container


def test_standard_scoring_uses_agent_judge_container_and_copied_inputs(
        tmp_path, monkeypatch):
    script = tmp_path / "score.py"
    user_answer = tmp_path / "student.json"
    reference_answer = tmp_path / "reference.json"
    script.write_text("print('{}')\n", encoding="utf-8")
    user_answer.write_text('{"answer": 1}\n', encoding="utf-8")
    reference_answer.write_text('{"answer": 2}\n', encoding="utf-8")
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(
        standard_container, "AGENT_JUDGE_WORKSPACE_ROOT", str(workspace_root),
    )
    monkeypatch.setattr(
        standard_container, "AGENT_JUDGE_IMAGE", "agent-judge:test",
    )

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        mount = command[command.index("-v") + 1]
        workspace = mount.rsplit(":/workspace", 1)[0]
        container_inputs = command[-4:-1]
        copied_inputs = [
            os.path.join(workspace, path.removeprefix("/workspace/"))
            for path in container_inputs
        ]
        assert [Path(path).read_text(encoding="utf-8") for path in copied_inputs] == [
            "print('{}')\n",
            '{"answer": 1}\n',
            '{"answer": 2}\n',
        ]
        assert os.path.isdir(os.path.join(workspace, ".runtime", "tmp"))
        return subprocess.CompletedProcess(
            command, 0, '{"score": 87, "details": {"ok": true}}\n', "",
        )

    monkeypatch.setattr(standard_container.subprocess, "run", fake_run)

    result = standard_container.run_standard_scoring_container(
        str(script), str(user_answer), str(reference_answer), 100, 37,
    )

    run_command, run_kwargs = calls[0]
    assert result.returncode == 0
    assert run_command[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in run_command
    assert run_command[run_command.index("--network") + 1] == "bridge"
    assert "agent-judge:test" in run_command
    assert run_command[-1] == "100"
    assert run_kwargs["timeout"] == 37
    assert calls[-1][0][:3] == ["docker", "rm", "-f"]
    assert list((workspace_root / "standard").iterdir()) == []


def test_standard_scoring_timeout_removes_container_and_workspace(
        tmp_path, monkeypatch):
    script = tmp_path / "score.py"
    user_answer = tmp_path / "student.txt"
    reference_answer = tmp_path / "reference.txt"
    for path in (script, user_answer, reference_answer):
        path.write_text("content\n", encoding="utf-8")
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(
        standard_container, "AGENT_JUDGE_WORKSPACE_ROOT", str(workspace_root),
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:3] == ["docker", "run", "--rm"]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(standard_container.subprocess, "run", fake_run)

    with pytest.raises(subprocess.TimeoutExpired):
        standard_container.run_standard_scoring_container(
            str(script), str(user_answer), str(reference_answer), 100, 5,
        )

    assert calls[-1][:3] == ["docker", "rm", "-f"]
    assert list((workspace_root / "standard").iterdir()) == []


def test_evaluate_parses_standard_container_result(monkeypatch):
    seen = {}

    def fake_run(script, user_answer, reference_answer, max_score, timeout):
        seen["args"] = (
            script, user_answer, reference_answer, max_score, timeout,
        )
        return subprocess.CompletedProcess(
            ["docker"], 0,
            'log line\n{"score": 91.5, "details": {"reason": "ok"}}\n',
            "",
        )

    monkeypatch.setattr(evaluate, "run_standard_scoring_container", fake_run)

    score, details = evaluate._run_scoring_script(
        "/host/score.py", "/host/user.txt", "/host/reference.txt", 100, 23,
    )

    assert seen["args"] == (
        "/host/score.py", "/host/user.txt", "/host/reference.txt", 100, 23,
    )
    assert score == 91.5
    assert details == {"reason": "ok"}


def test_evaluate_translates_standard_container_timeout(monkeypatch):
    def fake_run(*_args):
        raise subprocess.TimeoutExpired(["docker", "run"], 9)

    monkeypatch.setattr(evaluate, "run_standard_scoring_container", fake_run)

    with pytest.raises(RuntimeError, match=r"评测脚本执行超时（>9s）"):
        evaluate._run_scoring_script("score.py", "user", "reference", 100, 9)
