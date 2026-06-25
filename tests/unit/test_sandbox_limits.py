# -*- coding: utf-8 -*-
"""Docker 沙箱安全测试：验证容器隔离参数和清理逻辑。"""
import os
from unittest.mock import patch, MagicMock

from oj_modules import judger_core
from oj_modules import docker_sandbox


def test_guard_timeout_exceeds_base():
    assert judger_core._guard_timeout(2.0) > 2.0
    assert judger_core._guard_timeout(0) >= 1.0


def test_timeout_sec_from_ns_respects_factor():
    assert abs(judger_core._timeout_sec_from_ns(2_000_000_000, factor=1.5) - 3.0) < 0.01


def test_timeout_sec_from_ns_minimum_one_second():
    assert judger_core._timeout_sec_from_ns(0) >= 1.0
    assert judger_core._timeout_sec_from_ns(100) >= 1.0


def test_cleanup_run_artifacts_keeps_images(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    sid = "eoj-batch-999"
    run_dir = os.path.join(str(tmp_path), sid)
    os.makedirs(run_dir, exist_ok=True)
    for name in ("a.out", "main.c", "input_0.txt", "output_0.txt"):
        with open(os.path.join(run_dir, name), "w") as f:
            f.write("x")
    img = os.path.join(run_dir, "output_0.png")
    with open(img, "wb") as f:
        f.write(b"\x89PNG")

    judger_core.cleanup_run_artifacts(sid)

    assert not os.path.exists(os.path.join(run_dir, "a.out"))
    assert not os.path.exists(os.path.join(run_dir, "output_0.txt"))
    assert os.path.isfile(img)


def test_cleanup_run_artifacts_for_submission_prefixes(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    for sid in ("eoj-batch-7", "eoj-quick-compile-7", "eoj-7-1"):
        d = os.path.join(str(tmp_path), sid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "a.out"), "w") as f:
            f.write("x")
    other = os.path.join(str(tmp_path), "eoj-70-1")
    os.makedirs(other, exist_ok=True)
    with open(os.path.join(other, "a.out"), "w") as f:
        f.write("x")

    judger_core.cleanup_run_artifacts_for_submission(7)

    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-batch-7", "a.out"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-7-1", "a.out"))
    assert os.path.isfile(os.path.join(other, "a.out"))


def test_run_in_container_builds_correct_docker_cmd(monkeypatch):
    """Verify that run_in_container builds docker run with security flags."""
    captured_cmds = []

    class FakeProc:
        returncode = 0
        stdout = "hello"
        stderr = ""
        def communicate(self, input=None, timeout=None):
            return (self.stdout, self.stderr)
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    result = docker_sandbox.run_in_container(
        ["python3", "main.py"],
        run_dir="/tmp/test_run",
        input_text="hello",
        timeout_sec=10,
    )

    assert result.returncode == 0
    assert result.stdout == "hello"
    cmd = captured_cmds[0]
    assert "docker" in cmd[0]
    assert "--network" in cmd
    assert "none" in cmd
    assert "--security-opt" in cmd
    assert "no-new-privileges" in cmd
    assert "--read-only" in cmd
    assert "--user" in cmd
    assert "runner" in cmd
    assert "--pids-limit" in cmd


def test_run_in_container_honors_judger_image_env(monkeypatch):
    captured_cmds = []

    class FakeProc:
        returncode = 0
        stdout = "ok"
        stderr = ""
        def communicate(self, input=None, timeout=None):
            return (self.stdout, self.stderr)
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    docker_sandbox.run_in_container(["true"], run_dir="/tmp/test_run", timeout_sec=10)

    assert "numericaloj-judger-lite:latest" in captured_cmds[0]


def test_run_in_container_measure_time_strips_marker(monkeypatch):
    captured_cmds = []

    class FakeProc:
        returncode = 0
        stdout = "ok"
        stderr = "warning\n__NUMOJ_TIME_NS__=123456\n"
        def communicate(self, input=None, timeout=None):
            return (self.stdout, self.stderr)
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    result = docker_sandbox.run_in_container(
        ["python3", "main.py"],
        run_dir="/tmp/test_run",
        timeout_sec=10,
        measure_time=True,
    )

    assert result.elapsed_ns == 123456
    assert result.stderr == "warning"
    cmd = captured_cmds[0]
    image_index = cmd.index("numericaloj-judger:latest")
    assert cmd[image_index + 1:image_index + 4] == ["/bin/sh", "-c", docker_sandbox._TIME_WRAPPER_SCRIPT]
    assert cmd[-2:] == ["python3", "main.py"]


def test_container_session_lifecycle(monkeypatch):
    """Verify ContainerSession starts, execs, and cleans up."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(("run", cmd))
        result = MagicMock()
        if "docker" in cmd and "run" in cmd and "-d" in cmd:
            result.returncode = 0
            result.stdout = "abc123containerid\n"
        elif "docker" in cmd and "rm" in cmd:
            result.returncode = 0
            result.stdout = ""
        else:
            result.returncode = 0
            result.stdout = ""
        return result

    class FakeProc:
        returncode = 0
        def communicate(self, input=None, timeout=None):
            return ("output", "")
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        calls.append(("popen", cmd))
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    with docker_sandbox.ContainerSession(run_dir="/tmp/test") as session:
        result = session.exec(["./a.out"], input_text="1 2", workdir="/sandbox/case_0")
        assert result.returncode == 0
        assert result.stdout == "output"

    run_cmds = [c[1] for c in calls if c[0] == "run"]
    exec_cmds = [c[1] for c in calls if c[0] == "popen"]
    assert any("-d" in cmd for cmd in run_cmds)
    assert any("rm" in cmd and "-f" in cmd for cmd in run_cmds)
    assert exec_cmds[0][:4] == ["docker", "exec", "-i", "-w"]
    assert exec_cmds[0][4] == "/sandbox/case_0"


def test_container_session_exec_measure_time(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(("run", cmd))
        result = MagicMock()
        if "docker" in cmd and "run" in cmd and "-d" in cmd:
            result.returncode = 0
            result.stdout = "abc123containerid\n"
        elif "docker" in cmd and "rm" in cmd:
            result.returncode = 0
            result.stdout = ""
        return result

    class FakeProc:
        returncode = 0
        def communicate(self, input=None, timeout=None):
            return ("output", "__NUMOJ_TIME_NS__=789\n")
        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        calls.append(("popen", cmd))
        return FakeProc()

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    with docker_sandbox.ContainerSession(run_dir="/tmp/test") as session:
        result = session.exec(["./a.out"], workdir="/sandbox/case_0", measure_time=True)

    exec_cmd = [c[1] for c in calls if c[0] == "popen"][0]
    assert result.elapsed_ns == 789
    assert result.stderr == ""
    assert exec_cmd[:5] == ["docker", "exec", "-i", "-w", "/sandbox/case_0"]
    assert exec_cmd[6:9] == ["/bin/sh", "-c", docker_sandbox._TIME_WRAPPER_SCRIPT]


def test_docker_oom_kill_returns_mle(monkeypatch):
    """returncode 137 from container → Memory Limit Exceeded."""
    def fake_run_in_container(cmd, **kwargs):
        return docker_sandbox._RunResult(137, "", "Killed")

    monkeypatch.setattr("oj_modules.judger_core.run_in_container", fake_run_in_container)
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", "/tmp/test_jr")

    data = {
        "sid": "test-oom",
        "input": "",
        "code": "print('hi')",
        "timeLimit": 5_000_000_000,
        "forbidden": "",
    }
    os.makedirs("/tmp/test_jr/test-oom", exist_ok=True)
    try:
        result = judger_core.run_py(data)
        assert result["status"] == "Memory Limit Exceeded"
        assert result["memory"] == 0
    finally:
        import shutil
        shutil.rmtree("/tmp/test_jr/test-oom", ignore_errors=True)
