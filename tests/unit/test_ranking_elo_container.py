import os
import subprocess
import zipfile

import pytest

from oj_modules.shared.archive import ArchiveExtractionError
from oj_modules.tasks.ranking import elo_container


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def test_run_elo_scoring_container_uses_agent_judge_image_and_both_directories(
        tmp_path, monkeypatch):
    script = tmp_path / "score.py"
    script.write_text("print('{}')\n", encoding="utf-8")
    archive_a = _write_zip(tmp_path / "a.zip", {"bot.py": "print('a')\n"})
    archive_b = _write_zip(tmp_path / "b.zip", {"bot.py": "print('b')\n"})
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(elo_container, "AGENT_JUDGE_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(elo_container, "AGENT_JUDGE_IMAGE", "agent-judge:test")

    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        mount = command[command.index("-v") + 1]
        workspace = mount.rsplit(":/workspace", 1)[0]
        assert os.path.isfile(os.path.join(workspace, "scoring_script.py"))
        assert os.path.isfile(os.path.join(workspace, "submission_a", "bot.py"))
        assert os.path.isfile(os.path.join(workspace, "submission_b", "bot.py"))
        return subprocess.CompletedProcess(command, 0, '{"winner":0}\n', "")

    monkeypatch.setattr(elo_container.subprocess, "run", fake_run)

    result = elo_container.run_elo_scoring_container(
        str(script), str(archive_a), str(archive_b), 37,
    )

    run_command, run_kwargs = calls[0]
    assert result.returncode == 0
    assert run_command[:3] == ["docker", "run", "--rm"]
    assert run_command[run_command.index("--network") + 1] == "bridge"
    assert "agent-judge:test" in run_command
    assert run_command[-3:] == [
        "/workspace/scoring_script.py",
        "/workspace/submission_a",
        "/workspace/submission_b",
    ]
    assert run_kwargs["timeout"] == 37
    assert calls[-1][0][:3] == ["docker", "rm", "-f"]
    assert list((workspace_root / "elo").iterdir()) == []


def test_prepare_workspace_rejects_unsafe_submission_archive(tmp_path, monkeypatch):
    script = tmp_path / "score.py"
    script.write_text("print('{}')\n", encoding="utf-8")
    unsafe = _write_zip(tmp_path / "unsafe.zip", {"../escape.py": "bad"})
    valid = _write_zip(tmp_path / "valid.zip", {"bot.py": "pass\n"})
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(elo_container, "AGENT_JUDGE_WORKSPACE_ROOT", str(workspace_root))

    with pytest.raises(ArchiveExtractionError):
        elo_container._prepare_workspace(str(script), str(unsafe), str(valid))

    assert list((workspace_root / "elo").iterdir()) == []


def test_timeout_force_removes_container_and_workspace(tmp_path, monkeypatch):
    script = tmp_path / "score.py"
    script.write_text("print('{}')\n", encoding="utf-8")
    archive_a = _write_zip(tmp_path / "a.zip", {"bot.py": "pass\n"})
    archive_b = _write_zip(tmp_path / "b.zip", {"bot.py": "pass\n"})
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setattr(elo_container, "AGENT_JUDGE_WORKSPACE_ROOT", str(workspace_root))
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[:3] == ["docker", "run", "--rm"]:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(elo_container.subprocess, "run", fake_run)

    with pytest.raises(subprocess.TimeoutExpired):
        elo_container.run_elo_scoring_container(
            str(script), str(archive_a), str(archive_b), 5,
        )

    assert calls[-1][:3] == ["docker", "rm", "-f"]
    assert list((workspace_root / "elo").iterdir()) == []
