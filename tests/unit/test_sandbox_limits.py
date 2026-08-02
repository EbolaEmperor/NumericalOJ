# -*- coding: utf-8 -*-
"""Docker 沙箱安全测试：验证容器隔离参数和清理逻辑。"""
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from oj_modules.judging import core as judger_core
from oj_modules.judging import sandbox as docker_sandbox


ROOT = Path(__file__).resolve().parents[2]


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
    for name in ("a.out", "main.c", "submitted.c", "checker.c", "input_0.txt", "output_0.txt"):
        with open(os.path.join(run_dir, name), "w") as f:
            f.write("x")
    img = os.path.join(run_dir, "output_0.png")
    with open(img, "wb") as f:
        f.write(b"\x89PNG")

    judger_core.cleanup_run_artifacts(sid)

    assert not os.path.exists(os.path.join(run_dir, "a.out"))
    assert not os.path.exists(os.path.join(run_dir, "main.c"))
    assert not os.path.exists(os.path.join(run_dir, "submitted.c"))
    assert not os.path.exists(os.path.join(run_dir, "checker.c"))
    assert not os.path.exists(os.path.join(run_dir, "output_0.txt"))
    assert os.path.isfile(img)


def test_cleanup_run_artifacts_for_submission_prefixes(tmp_path, monkeypatch):
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(tmp_path))
    for sid in ("eoj-batch-7", "eoj-quick-compile-7", "eoj-7-1"):
        d = os.path.join(str(tmp_path), sid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "a.out"), "w") as f:
            f.write("x")
        with open(os.path.join(d, "main.cpp"), "w") as f:
            f.write("x")
    other = os.path.join(str(tmp_path), "eoj-70-1")
    os.makedirs(other, exist_ok=True)
    with open(os.path.join(other, "a.out"), "w") as f:
        f.write("x")

    judger_core.cleanup_run_artifacts_for_submission(7)

    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-batch-7", "a.out"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-7-1", "a.out"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-batch-7", "main.cpp"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-7-1", "main.cpp"))
    assert not os.path.exists(os.path.join(str(tmp_path), "eoj-quick-compile-7", "main.cpp"))
    assert os.path.isfile(os.path.join(other, "a.out"))


def test_run_in_container_builds_correct_docker_cmd(monkeypatch):
    """Verify that run_in_container builds docker run with security flags."""
    captured_cmds = []

    class FakeProc:
        returncode = 0

        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (b"hello", b"", False, False),
    )
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    result = docker_sandbox.run_in_container(
        ["python3", "main.py"],
        run_dir="/tmp/test_run",
        input_text="hello",
        timeout_sec=10,
        workdir="/sandbox/case_3",
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
    assert cmd[cmd.index("--user") + 1] == "65532:65532"
    assert cmd[cmd.index("-w") + 1] == "/sandbox/case_3"
    assert "--rm" in cmd
    assert "--pids-limit" in cmd
    assert "/tmp/test_run:/sandbox:ro" in cmd


def test_case_container_has_read_only_host_mount_and_bounded_tmpfs(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(
        docker_sandbox,
        "_get_config",
        lambda: type("C", (), {})(),
    )

    cmd = docker_sandbox._case_container_start_command(
        "numoj-case-test",
        str(run_dir),
    )

    mounts = [
        cmd[index + 1]
        for index, value in enumerate(cmd)
        if value == "-v"
    ]
    assert f"{run_dir.resolve()}:/sandbox:ro" in mounts
    assert not any(mount.endswith(":rw") for mount in mounts)
    tmpfs_mounts = [
        cmd[index + 1]
        for index, value in enumerate(cmd)
        if value == "--tmpfs"
    ]
    assert any(
        mount.startswith("/case:") and "size=134217728" in mount
        and "mode=1777" in mount
        for mount in tmpfs_mounts
    )
    assert any(
        mount.startswith("/export:") and "size=100663296" in mount
        and "mode=0700" in mount
        for mount in tmpfs_mounts
    )
    assert cmd[cmd.index("--user") + 1] == "0:0"
    assert "--cap-drop" in cmd
    assert set(
        cmd[index + 1]
        for index, value in enumerate(cmd)
        if value == "--cap-add"
    ) == {"SETUID", "SETGID", "KILL", "DAC_READ_SEARCH"}


def test_runner_uid_equal_to_host_fails_before_docker_start(monkeypatch):
    popen_calls = []
    monkeypatch.setenv(
        "JUDGER_DOCKER_RUNNER_UID",
        str(os.geteuid()),
    )
    monkeypatch.setattr(
        "subprocess.Popen",
        lambda *args, **kwargs: popen_calls.append((args, kwargs)),
    )

    try:
        docker_sandbox.run_in_container(
            ["true"],
            run_dir="/tmp/test_run",
        )
    except RuntimeError as exc:
        assert "UID" in str(exc)
    else:
        raise AssertionError("同 UID 必须 fail-closed")

    assert popen_calls == []


def test_all_ordinary_judger_images_create_the_fixed_numeric_runner():
    for relative in (
        "docker/judger/Dockerfile",
        "docker/judger-lite/Dockerfile",
    ):
        dockerfile = (ROOT / relative).read_text(encoding="utf-8")
        assert "ARG JUDGER_RUNNER_UID=65532" in dockerfile
        assert "ARG JUDGER_RUNNER_GID=65532" in dockerfile
        assert 'groupadd --gid "${JUDGER_RUNNER_GID}" runner' in dockerfile
        assert 'useradd --uid "${JUDGER_RUNNER_UID}"' in dockerfile


def test_run_in_container_timeout_force_removes_named_container(monkeypatch):
    removed = []

    class TimeoutProc:
        returncode = 124

        def kill(self):
            pass

    monkeypatch.setattr("subprocess.Popen", lambda *_args, **_kwargs: TimeoutProc())
    calls = {"count": 0}

    def fake_communicate(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise docker_sandbox.subprocess.TimeoutExpired("docker", 1)
        return b"", b"", False, False

    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        fake_communicate,
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_in_container(
        ["sleep", "infinity"],
        run_dir="/tmp/test_run",
        timeout_sec=1,
    )

    assert result.returncode == 124
    assert len(removed) == 1
    assert removed[0].startswith("numoj-run-")


def test_timeout_raises_when_container_is_confirmed_still_running(monkeypatch):
    class TimeoutProc:
        returncode = 124

        def kill(self):
            pass

    run_results = iter(
        [
            type("Result", (), {"returncode": 1, "stderr": "rm failed"})(),
            type("Result", (), {"returncode": 0, "stderr": ""})(),
        ]
    )
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TimeoutProc(),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            docker_sandbox.subprocess.TimeoutExpired("docker", 1)
        ),
    )
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: next(run_results),
    )

    with pytest.raises(
        docker_sandbox.ContainerCleanupError,
        match="仍在运行",
    ):
        docker_sandbox.run_in_container(
            ["sleep", "infinity"],
            run_dir="/tmp/test_run",
            timeout_sec=1,
        )


def test_timeout_can_return_when_inspect_confirms_container_absent(monkeypatch):
    class TimeoutProc:
        returncode = 124

        def kill(self):
            pass

    run_results = iter(
        [
            type("Result", (), {"returncode": 1, "stderr": "rm failed"})(),
            type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stderr": "Error: No such object: numoj-run",
                },
            )(),
        ]
    )
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TimeoutProc(),
    )
    calls = {"count": 0}

    def fake_communicate(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise docker_sandbox.subprocess.TimeoutExpired("docker", 1)
        return b"", b"", False, False

    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        fake_communicate,
    )
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: next(run_results),
    )

    result = docker_sandbox.run_in_container(
        ["sleep", "infinity"],
        run_dir="/tmp/test_run",
        timeout_sec=1,
    )

    assert result.returncode == 124


def test_run_in_container_honors_judger_image_env(monkeypatch):
    captured_cmds = []

    class FakeProc:
        returncode = 0

        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setenv("JUDGER_DOCKER_IMAGE", "numericaloj-judger-lite:latest")
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (b"ok", b"", False, False),
    )
    monkeypatch.setattr(docker_sandbox, "_get_config", lambda: type("C", (), {})())

    docker_sandbox.run_in_container(["true"], run_dir="/tmp/test_run", timeout_sec=10)

    assert "numericaloj-judger-lite:latest" in captured_cmds[0]


def test_run_in_container_measure_time_strips_marker(monkeypatch):
    captured_cmds = []

    class FakeProc:
        returncode = 0

        def kill(self):
            pass

    def fake_popen(cmd, **kwargs):
        captured_cmds.append(cmd)
        return FakeProc()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (
            b"ok",
            b"warning\n__NUMOJ_TIME_NS__=123456\n",
            False,
            False,
        ),
    )
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


def test_docker_oom_kill_returns_mle(monkeypatch):
    """cgroup memory.events 的 oom_kill 增量优先于子进程 signal 编码。"""
    def fake_run_in_container(cmd, **kwargs):
        return docker_sandbox._RunResult(
            -9,
            "",
            "Killed",
            oom_killed=True,
        )

    monkeypatch.setattr(
        "oj_modules.judging.core.run_case_in_container",
        fake_run_in_container,
    )
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


def test_user_self_sigkill_is_not_misclassified_as_mle(monkeypatch):
    monkeypatch.setattr(
        "oj_modules.judging.core.run_case_in_container",
        lambda *_args, **_kwargs: docker_sandbox._RunResult(
            -9,
            "",
            "Killed",
            oom_killed=False,
        ),
    )
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", "/tmp/test_jr")

    result = judger_core.run_py(
        {
            "sid": "test-self-kill",
            "input": "",
            "code": "pass",
            "timeLimit": 5_000_000_000,
            "forbidden": "",
        }
    )

    assert result["status"] == "Runtime Error"
