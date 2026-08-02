# -*- coding: utf-8 -*-
"""有界 tmpfs case runner 的纯单元安全契约。"""

import base64
import json
import os
import stat
import subprocess
import sys

import pytest

from oj_modules.judging import case_runner as judger_case_runner
from oj_modules.judging import sandbox as docker_sandbox


def _protocol_payload(
    *,
    artifacts=None,
    artifact_statuses=None,
    returncode=0,
):
    artifact_names = list(artifacts or [])
    if artifact_statuses is None:
        artifact_statuses = {
            name: "exported"
            for name in artifact_names
        }
    payload = {
        "version": 1,
        "returncode": returncode,
        "stdout_b64": base64.b64encode(b"hello").decode("ascii"),
        "stderr_b64": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "elapsed_ns": 123,
        "oom_killed": False,
        "artifacts": artifact_names,
        "artifact_statuses": dict(artifact_statuses),
    }
    return (
        docker_sandbox._CASE_PROTOCOL_PREFIX
        + base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        + "\n"
    ).encode("ascii")


def test_privilege_drop_clears_groups_before_gid_and_uid(monkeypatch):
    calls = []
    monkeypatch.setattr(
        judger_case_runner.os,
        "setgroups",
        lambda groups: calls.append(("groups", groups)),
    )
    monkeypatch.setattr(
        judger_case_runner.os,
        "setgid",
        lambda gid: calls.append(("gid", gid)),
    )
    monkeypatch.setattr(
        judger_case_runner.os,
        "setuid",
        lambda uid: calls.append(("uid", uid)),
    )
    monkeypatch.setattr(judger_case_runner.os, "umask", lambda _mask: None)

    judger_case_runner._drop_privileges(65532, 65531)

    assert calls == [
        ("groups", []),
        ("gid", 65531),
        ("uid", 65532),
    ]


def test_case_runner_source_accepts_root_or_service_owner_only(monkeypatch):
    mode = stat.S_IFREG | 0o644

    for trusted_uid in {0, os.geteuid()}:
        monkeypatch.setattr(
            docker_sandbox.os,
            "lstat",
            lambda _path, uid=trusted_uid: type(
                "Info",
                (),
                {"st_mode": mode, "st_uid": uid},
            )(),
        )
        assert docker_sandbox._validate_case_runner_source().endswith(
            "case_runner.py"
        )

    untrusted_uid = max(1, os.geteuid() + 1)
    if untrusted_uid in {0, os.geteuid()}:
        untrusted_uid += 1
    monkeypatch.setattr(
        docker_sandbox.os,
        "lstat",
        lambda _path: type(
            "Info",
            (),
            {"st_mode": mode, "st_uid": untrusted_uid},
        )(),
    )
    with pytest.raises(RuntimeError, match="可信属主"):
        docker_sandbox._validate_case_runner_source()


def test_export_rejects_symlink_fifo_and_oversized_file(tmp_path):
    source = tmp_path / "case"
    destination = tmp_path / "export"
    source.mkdir()
    destination.mkdir()
    (source / "output.txt").symlink_to("/proc/self/environ")
    os.mkfifo(source / "output.png")
    (source / "a.out").write_bytes(b"x" * 9)
    source_fd = judger_case_runner._open_directory(str(source))
    destination_fd = judger_case_runner._open_directory(str(destination))
    try:
        assert judger_case_runner._export_regular_file(
            source_fd,
            destination_fd,
            "output.txt",
            max_bytes=1024,
        ) == "rejected"
        assert judger_case_runner._export_regular_file(
            source_fd,
            destination_fd,
            "output.png",
            max_bytes=1024,
        ) == "rejected"
        assert judger_case_runner._export_regular_file(
            source_fd,
            destination_fd,
            "a.out",
            max_bytes=8,
        ) == "rejected"
    finally:
        os.close(destination_fd)
        os.close(source_fd)

    assert list(destination.iterdir()) == []


def test_export_copies_only_regular_file_to_root_staging(tmp_path):
    source = tmp_path / "case"
    destination = tmp_path / "export"
    source.mkdir()
    destination.mkdir()
    (source / "output.txt").write_bytes(b"answer")
    source_fd = judger_case_runner._open_directory(str(source))
    destination_fd = judger_case_runner._open_directory(str(destination))
    try:
        assert judger_case_runner._export_regular_file(
            source_fd,
            destination_fd,
            "output.txt",
            max_bytes=1024,
        ) == "exported"
    finally:
        os.close(destination_fd)
        os.close(source_fd)

    exported = destination / "output.txt"
    assert exported.read_bytes() == b"answer"
    assert exported.stat().st_nlink == 1
    assert exported.stat().st_mode & 0o777 == 0o600


def test_runner_nonblocking_stdin_delivers_all_bytes(tmp_path, monkeypatch):
    payload = b"x" * (2 * 1024 * 1024 + 17)
    monkeypatch.setattr(
        judger_case_runner,
        "_drop_privileges",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        judger_case_runner,
        "_kill_remaining_runner_processes",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        judger_case_runner,
        "_read_memory_events",
        lambda: {},
    )

    result = judger_case_runner._run_user_command(
        [
            sys.executable,
            "-c",
            "import sys; data=sys.stdin.buffer.read(); print(len(data))",
        ],
        workdir=str(tmp_path),
        input_data=payload,
        runner_uid=65532,
        runner_gid=65532,
        stdout_limit=1024,
        stderr_limit=1024,
    )

    assert result["returncode"] == 0
    assert result["stdout"].strip() == str(len(payload)).encode("ascii")


def test_runner_reports_cgroup_oom_kill_delta(tmp_path, monkeypatch):
    events = iter([
        {"oom_kill": 4},
        {"oom_kill": 5},
    ])
    monkeypatch.setattr(
        judger_case_runner,
        "_drop_privileges",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        judger_case_runner,
        "_kill_remaining_runner_processes",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        judger_case_runner,
        "_read_memory_events",
        lambda: next(events),
    )

    result = judger_case_runner._run_user_command(
        [sys.executable, "-c", "pass"],
        workdir=str(tmp_path),
        input_data=b"",
        runner_uid=65532,
        runner_gid=65532,
        stdout_limit=1024,
        stderr_limit=1024,
    )

    assert result["returncode"] == 0
    assert result["oom_killed"] is True


def test_host_bounded_communicate_delivers_all_input():
    payload = b"y" * (2 * 1024 * 1024 + 31)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; data=sys.stdin.buffer.read(); print(len(data))",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr, stdout_truncated, stderr_truncated = (
        docker_sandbox._communicate_bounded(
            proc,
            input_bytes=payload,
            timeout_sec=10,
            stdout_limit=1024,
            stderr_limit=1024,
        )
    )

    assert proc.returncode == 0
    assert stdout.strip() == str(len(payload)).encode("ascii")
    assert stderr == b""
    assert stdout_truncated is False
    assert stderr_truncated is False


def test_case_artifact_is_streamed_from_tmpfs_with_bounded_docker_exec(
    monkeypatch,
):
    commands = []
    binary_payload = b"\x00ELF\xffartifact"

    class FakeProc:
        returncode = 0

    def fake_popen(command, **kwargs):
        commands.append((list(command), kwargs))
        return FakeProc()

    monkeypatch.setattr(docker_sandbox.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda proc, **kwargs: (
            binary_payload,
            b"",
            False,
            False,
        ),
    )

    exported = docker_sandbox._copy_case_artifacts(
        "numoj-case-safe",
        {"a.out": len(binary_payload)},
    )

    assert exported == {"a.out": binary_payload}
    command, kwargs = commands[0]
    assert command == [
        "docker",
        "exec",
        "--user",
        "0:0",
        "numoj-case-safe",
        "cat",
        "--",
        "/export/a.out",
    ]
    assert "cp" not in command
    assert kwargs == {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }


@pytest.mark.parametrize(
    ("returncode", "payload", "truncated", "stderr_truncated"),
    [
        (1, b"", False, False),
        (0, b"12345", False, False),
        (0, b"1234", True, False),
        (0, b"1234", False, True),
    ],
)
def test_case_artifact_stream_fails_closed_on_exec_or_size_errors(
    monkeypatch,
    returncode,
    payload,
    truncated,
    stderr_truncated,
):
    class FakeProc:
        pass

    proc = FakeProc()
    proc.returncode = returncode
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: proc,
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (
            payload,
            b"docker exec failed" if returncode else b"",
            truncated,
            stderr_truncated,
        ),
    )

    with pytest.raises(RuntimeError, match="无法从判题容器导出 a.out"):
        docker_sandbox._read_case_artifact(
            "numoj-case-safe",
            "a.out",
            max_bytes=4,
        )


def test_case_artifact_stream_reaps_timed_out_docker_exec(monkeypatch):
    class FakeProc:
        returncode = None
        killed = False
        waited = False

        def kill(self):
            self.killed = True

        def wait(self, timeout=None):
            self.waited = True
            self.returncode = -9

    proc = FakeProc()
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: proc,
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("docker exec", 30)
        ),
    )

    with pytest.raises(RuntimeError, match="导出 a.out 超时"):
        docker_sandbox._read_case_artifact(
            "numoj-case-safe",
            "a.out",
            max_bytes=4,
        )

    assert proc.killed is True
    assert proc.waited is True


def test_case_protocol_rejects_unlisted_artifact():
    with pytest.raises(RuntimeError, match="白名单外"):
        docker_sandbox._parse_case_protocol(
            _protocol_payload(artifacts=["secret.env"]),
            stdout_limit=1024,
            stderr_limit=1024,
            allowed_artifacts={"output.txt": 1024},
        )


def test_case_protocol_requires_status_for_each_requested_artifact():
    with pytest.raises(RuntimeError, match="产物状态协议无效"):
        docker_sandbox._parse_case_protocol(
            _protocol_payload(artifact_statuses={}),
            stdout_limit=1024,
            stderr_limit=1024,
            allowed_artifacts={"output.txt": 1024},
        )


def test_case_protocol_preserves_absent_artifact_status():
    parsed = docker_sandbox._parse_case_protocol(
        _protocol_payload(
            artifact_statuses={"output.txt": "absent"},
        ),
        stdout_limit=1024,
        stderr_limit=1024,
        allowed_artifacts={"output.txt": 1024},
    )

    assert parsed["artifact_names"] == []
    assert parsed["artifact_statuses"] == {"output.txt": "absent"}


def test_run_case_uses_isolated_executor_and_removes_container(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    commands = []
    removed = []

    def fake_run(cmd, **_kwargs):
        commands.append(list(cmd))
        return type("Result", (), {"returncode": 0, "stderr": ""})()

    class FakeProc:
        returncode = 0

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            pass

    monkeypatch.setattr(docker_sandbox.subprocess, "run", fake_run)
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda cmd, **_kwargs: commands.append(list(cmd)) or FakeProc(),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (
            _protocol_payload(artifacts=["output.txt"]),
            b"",
            False,
            False,
        ),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_copy_case_artifacts",
        lambda _name, limits: {
            name: b"artifact"
            for name in limits
        },
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_case_in_container(
        ["python3", "-I", "-u", "/sandbox/main.py"],
        run_dir=str(run_dir),
        input_text="42\n",
        timeout_sec=7,
        output_name="output.txt",
    )

    assert result.returncode == 0
    assert result.stdout == "hello"
    assert result.elapsed_ns == 123
    assert result.artifacts == {"output.txt": b"artifact"}
    start_cmd, exec_cmd = commands
    assert "--rm" in start_cmd
    assert f"{run_dir.resolve()}:/sandbox:ro" in start_cmd
    assert any(
        str(value).startswith("/case:")
        and "size=134217728" in str(value)
        for value in start_cmd
    )
    assert start_cmd[-6:] == [
        "timeout",
        "-k",
        "1s",
        "67s",
        "sleep",
        "infinity",
    ]
    assert exec_cmd[exec_cmd.index("python3") + 1] == "-I"
    assert exec_cmd[-4:] == [
        "python3",
        "-I",
        "-u",
        "/sandbox/main.py",
    ]
    assert len(removed) == 1
    assert removed[0].startswith("numoj-case-")


def test_run_case_timeout_reaps_cli_even_when_kill_races(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    removed = []
    waited = []

    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stderr": ""},
        )(),
    )

    class TimeoutProc:
        returncode = None

        def kill(self):
            raise ProcessLookupError

        def wait(self, timeout=None):
            waited.append(timeout)
            self.returncode = -9
            return self.returncode

    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TimeoutProc(),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            docker_sandbox.subprocess.TimeoutExpired("docker exec", 1)
        ),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_case_in_container(
        ["true"],
        run_dir=str(run_dir),
        timeout_sec=1,
    )

    assert result.returncode == 124
    assert waited == [5]
    assert len(removed) == 1


def test_run_case_start_ack_timeout_still_confirms_named_container_removal(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    removed = []
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            docker_sandbox.subprocess.TimeoutExpired("docker run", 30)
        ),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_case_in_container(
        ["true"],
        run_dir=str(run_dir),
    )

    assert result.returncode == -1
    assert len(removed) == 1
    assert removed[0].startswith("numoj-case-")


def test_run_case_start_uncertainty_propagates_cleanup_failure(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            docker_sandbox.subprocess.TimeoutExpired("docker run", 30)
        ),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda _name: (_ for _ in ()).throw(
            docker_sandbox.ContainerCleanupError("状态未知")
        ),
    )

    with pytest.raises(
        docker_sandbox.ContainerCleanupError,
        match="状态未知",
    ):
        docker_sandbox.run_case_in_container(
            ["true"],
            run_dir=str(run_dir),
        )


def test_run_case_recovers_oom_fact_when_wrapper_protocol_is_missing(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    removed = []

    def fake_run(cmd, **_kwargs):
        if cmd[:4] == ["docker", "exec", "--user", "0:0"]:
            return type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": "low 0\noom 1\noom_kill 1\n",
                    "stderr": "",
                },
            )()
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "container-id\n", "stderr": ""},
        )()

    class FailedExecProc:
        returncode = 137

    monkeypatch.setattr(docker_sandbox.subprocess, "run", fake_run)
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FailedExecProc(),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (b"", b"", False, False),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_case_in_container(
        ["python3", "-c", "raise SystemExit"],
        run_dir=str(run_dir),
    )

    assert result.returncode == -9
    assert result.oom_killed is True
    assert len(removed) == 1


def test_run_case_fails_safe_on_exec_137_when_cgroup_events_are_gone(
    tmp_path,
    monkeypatch,
):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    removed = []

    def fake_run(cmd, **_kwargs):
        if cmd[:4] == ["docker", "exec", "--user", "0:0"]:
            return type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "No such container",
                },
            )()
        return type(
            "Result",
            (),
            {"returncode": 0, "stdout": "container-id\n", "stderr": ""},
        )()

    class OomKilledExecProc:
        returncode = 137

    monkeypatch.setattr(docker_sandbox.subprocess, "run", fake_run)
    monkeypatch.setattr(
        docker_sandbox.subprocess,
        "Popen",
        lambda *_args, **_kwargs: OomKilledExecProc(),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_communicate_bounded",
        lambda *_args, **_kwargs: (b"", b"", False, False),
    )
    monkeypatch.setattr(
        docker_sandbox,
        "_force_remove_container",
        lambda name: removed.append(name),
    )

    result = docker_sandbox.run_case_in_container(
        ["python3", "-c", "raise SystemExit"],
        run_dir=str(run_dir),
    )

    assert result.returncode == -9
    assert result.oom_killed is True
    assert len(removed) == 1
