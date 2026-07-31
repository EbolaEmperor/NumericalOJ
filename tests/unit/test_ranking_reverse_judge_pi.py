# -*- coding: utf-8 -*-
"""反向评测 Pi 作答节点的原生会话、轨迹同步与超时恢复。"""

import json
import os
from types import SimpleNamespace

import pytest

import oj_modules.tasks.ranking_reverse_judge_tasks as rj
import oj_modules.tasks.ranking_agent_judge_tasks as aj


_SESSION_ID = "12345678-1234-1234-1234-123456789abc"


def _pi_endpoint():
    return {
        "id": 7,
        "pool_kind": "primary",
        "harness": rj.HARNESS_PI,
        "base_url": "https://pi.example/v1",
        "api_key": "real-pi-key",
        "model": "pi-model",
        "concurrency_limit": 1,
    }


def _prepare_run_agent(
        monkeypatch, tmp_path, *, use_real_agent_env=False,
        subprocess_calls=None):
    package = tmp_path / "package"
    (package / "template").mkdir(parents=True)
    (package / "problem").mkdir()
    proxy_closes = []
    proxy_calls = []
    proxy = SimpleNamespace(
        container_base_url="http://host.docker.internal:43123/v1",
        token="attempt-token",
        close=lambda: proxy_closes.append(True),
    )
    monkeypatch.setattr(rj, "_fake_reverse_judge_enabled", lambda: False)
    monkeypatch.setattr(
        rj, "submission_dir", lambda _sid: str(tmp_path / "submission"),
    )
    monkeypatch.setattr(
        rj,
        "_start_reverse_endpoint_proxy",
        lambda base_url, api_key, harness: (
            proxy_calls.append((base_url, api_key, harness)) or proxy
        ),
    )
    if not use_real_agent_env:
        monkeypatch.setattr(rj, "_agent_env_args", lambda *_args, **_kwargs: [])

    def fake_subprocess_run(*args, **_kwargs):
        if subprocess_calls is not None:
            subprocess_calls.append(list(args[0]))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        rj.subprocess,
        "run",
        fake_subprocess_run,
    )
    monkeypatch.setattr(rj, "_exec_container_apt_setup", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(rj, "_prepare_agent_workspace_for_node", lambda *_args: None)
    monkeypatch.setattr(
        rj, "update_reverse_judge_step_for_attempt", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(rj, "_publish_snapshot", lambda *_args: None)
    monkeypatch.setattr(rj, "_dump_harness_trace", lambda *_args: None)
    return package, proxy_calls, proxy_closes


def test_pi_reverse_container_env_uses_attempt_proxy_and_openai_contract():
    args = rj._agent_env_args(
        rj.HARNESS_PI,
        "http://host.docker.internal:43123/v1",
        "attempt-token",
        "deepseek-v4-flash",
        "unused.jsonl",
        include_prompt=False,
    )
    env = {
        args[index + 1].split("=", 1)[0]: args[index + 1].split("=", 1)[1]
        for index, value in enumerate(args[:-1])
        if value == "-e" and "=" in args[index + 1]
    }

    assert env["AJ_HARNESS"] == rj.HARNESS_PI
    assert env["OPENAI_BASE_URL"] == "http://host.docker.internal:43123/v1"
    assert env["OPENAI_API_KEY"] == "attempt-token"
    assert env["OPENAI_MODEL"] == "deepseek-v4-flash"
    assert "AJ_PROMPT" not in env


def test_pi_reverse_run_never_injects_real_api_key_into_agent_container(
        monkeypatch, tmp_path):
    subprocess_calls = []
    package, proxy_calls, proxy_closes = _prepare_run_agent(
        monkeypatch,
        tmp_path,
        use_real_agent_env=True,
        subprocess_calls=subprocess_calls,
    )
    monkeypatch.setattr(
        rj,
        "_exec_reverse_harness_phase",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="completed",
            stderr="",
            aj_timed_out=False,
        ),
    )

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is True
    docker_run = next(
        command
        for command in subprocess_calls
        if command[:3] == ["docker", "run", "-d"]
    )
    serialized = "\0".join(docker_run)
    assert "real-pi-key" not in serialized
    assert "AJ_HARNESS=pi" in docker_run
    assert "OPENAI_BASE_URL=http://host.docker.internal:43123/v1" in docker_run
    assert "OPENAI_API_KEY=attempt-token" in docker_run
    assert "OPENAI_MODEL=pi-model" in docker_run
    assert proxy_calls == [
        ("https://pi.example/v1", "real-pi-key", rj.HARNESS_PI),
    ]
    assert proxy_closes == [True]


def test_pi_hello_probe_uses_openai_chat_completions_and_bearer():
    request, error = aj._hello_probe_request(_pi_endpoint())

    assert error is None
    assert request.full_url == "https://pi.example/v1/chat/completions"
    assert request.get_header("Authorization") == "Bearer real-pi-key"
    assert json.loads(request.data.decode("utf-8")) == {
        "model": "pi-model",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 8,
    }


def test_sync_pi_agent_sessions_mirrors_native_tree_and_streams_combined_trace(
        monkeypatch, tmp_path):
    trace_dir = tmp_path / "trace"
    copied = []
    first_relative = f"--workspace--/one_{_SESSION_ID}.jsonl"
    second_relative = (
        "--workspace--/nested/"
        "two_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.jsonl"
    )
    payloads = {
        first_relative: b'{"type":"session","id":"first"}\n',
        second_relative: b'{"type":"message","id":"second"}\n',
    }

    monkeypatch.setattr(
        rj,
        "_list_pi_session_files",
        lambda container_name: [
            {"relative_path": first_relative, "mtime_ns": 1_000_000_000},
            {"relative_path": second_relative, "mtime_ns": 2_000_000_000},
        ],
    )

    def fake_copy(container_name, relative_path, destination, mtime_ns):
        copied.append((
            container_name, relative_path, destination, mtime_ns,
        ))
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "wb") as stream:
            stream.write(payloads[relative_path])
        os.utime(destination, ns=(mtime_ns, mtime_ns))
        return True

    monkeypatch.setattr(rj, "_copy_pi_session_file", fake_copy)

    assert rj._sync_pi_agent_sessions("pi-container", str(trace_dir)) is True

    session_root = trace_dir / ".pi" / "agent" / "sessions"
    combined = session_root / "reverse_solve_combined.jsonl"
    assert [(item[0], item[1], item[3]) for item in copied] == [
        ("pi-container", first_relative, 1_000_000_000),
        ("pi-container", second_relative, 2_000_000_000),
    ]
    assert combined.read_bytes() == (
        b'{"type":"session","id":"first"}\n'
        b'{"type":"message","id":"second"}\n'
    )
    assert (session_root / "--workspace--" / f"one_{_SESSION_ID}.jsonl").is_file()


def test_copy_pi_session_file_streams_docker_stdout_to_atomic_temp(
        monkeypatch, tmp_path):
    destination = tmp_path / "trace" / "native.jsonl"
    payload = b'{"type":"session","version":3}\n' + b"x" * (256 * 1024)
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        kwargs["stdout"].write(payload)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(rj.subprocess, "run", fake_run)

    assert rj._copy_pi_session_file(
        "pi-container",
        f"--workspace--/native_{_SESSION_ID}.jsonl",
        str(destination),
        1_000_000_000,
    )
    assert destination.read_bytes() == payload
    assert not destination.with_suffix(".jsonl.tmp").exists()
    args, kwargs = calls[0]
    assert args[:6] == [
        "docker", "exec", "--user", "node", "pi-container", "python3",
    ]
    assert args[-2:] == [
        rj._PI_CONTAINER_SESSION_ROOT,
        f"--workspace--/native_{_SESSION_ID}.jsonl",
    ]
    assert "O_NOFOLLOW" in args[-3]
    assert "capture_output" not in kwargs
    assert kwargs["stderr"] == rj.subprocess.DEVNULL


def test_harness_capture_reader_keeps_bounded_head_and_tail(tmp_path):
    path = tmp_path / "harness.stdout"
    payload = b"session-header\n" + b"x" * (3 * 1024 * 1024) + b"\nerror-tail"
    path.write_bytes(payload)

    text = rj._read_text_file(str(path))

    assert text.startswith("session-header\n")
    assert text.endswith("\nerror-tail")
    assert "[harness output truncated]" in text
    assert len(text.encode("utf-8")) <= rj._HARNESS_CAPTURE_READ_MAX_BYTES


@pytest.mark.parametrize("value", [
    "",
    "/absolute.jsonl",
    "../escape.jsonl",
    "nested/../../escape.jsonl",
    "nested/not-json.txt",
    "nested/control\n.jsonl",
])
def test_pi_session_sync_rejects_unsafe_relative_paths(value):
    assert rj._safe_pi_session_relative_path(value) == ""


def test_resolve_pi_resume_session_uses_json_header_without_treating_stdout_as_trace(
        monkeypatch, tmp_path):
    monkeypatch.setattr(rj, "_read_session_id_from_workspace", lambda _ws: "")
    monkeypatch.setattr(
        rj,
        "_latest_pi_session_id_from_container",
        lambda _container: pytest.fail("JSON header 已包含 session id，不应扫描回退"),
    )
    stdout = "\n".join([
        json.dumps({
            "type": "session",
            "version": 3,
            "id": _SESSION_ID,
            "cwd": "/workspace",
        }),
        json.dumps({"type": "message_update", "id": "not-a-session-id"}),
    ])

    assert rj._resolve_resume_session_id(
        "pi-container", str(tmp_path), rj.HARNESS_PI, stdout=stdout,
    ) == _SESSION_ID


def test_run_agent_pi_timeout_resumes_same_native_session(
        monkeypatch, tmp_path):
    package, proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    sync_calls = []
    session_checks = []
    monkeypatch.setattr(
        rj,
        "_sync_pi_agent_sessions",
        lambda container, trace: sync_calls.append((container, trace)) or True,
    )
    monkeypatch.setattr(
        rj,
        "_pi_session_exists_in_container",
        lambda container, session_id: (
            session_checks.append((container, session_id)) or True
        ),
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        if len(phase_calls) == 1:
            kwargs["on_tick"]()
            return SimpleNamespace(
                returncode=124,
                stdout=json.dumps({
                    "type": "session", "version": 3, "id": _SESSION_ID,
                }),
                stderr="initial timeout",
                aj_timed_out=True,
            )
        kwargs["on_tick"]()
        with open(
            os.path.join(args[1], ".aj_session_state.json"),
            "w",
            encoding="utf-8",
        ) as stream:
            json.dump({"harness": "pi", "session_id": _SESSION_ID}, stream)
        return SimpleNamespace(
            returncode=0,
            stdout="finalized",
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is True
    assert result["stdout"].endswith("\n\nfinalized")
    assert len(phase_calls) == 2
    assert phase_calls[0][0][2] == "reverse_solve"
    assert "resume_session_id" not in phase_calls[0][1]
    assert phase_calls[1][0][2] == "reverse_finalize"
    assert phase_calls[1][1]["resume_session_id"] == _SESSION_ID
    assert phase_calls[1][1]["fork_session"] is False
    assert session_checks == [
        ("rj_agent_12_attempt-1", _SESSION_ID),
        ("rj_agent_12_attempt-1", _SESSION_ID),
    ]
    assert len(sync_calls) >= 5
    assert proxy_calls == [
        ("https://pi.example/v1", "real-pi-key", rj.HARNESS_PI),
    ]
    assert proxy_closes == [True]


def test_run_agent_pi_timeout_fails_when_native_session_is_missing(
        monkeypatch, tmp_path):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    monkeypatch.setattr(rj, "_sync_pi_agent_sessions", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_resolve_resume_session_id", lambda *_args, **_kwargs: _SESSION_ID,
    )
    monkeypatch.setattr(rj, "_pi_session_exists_in_container", lambda *_args: False)

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        return SimpleNamespace(
            returncode=124,
            stdout="session header",
            stderr="",
            aj_timed_out=True,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is False
    assert "Pi 原生会话不存在或无法恢复" in result["error"]
    assert len(phase_calls) == 1
    assert proxy_closes == [True]


def test_run_agent_pi_finalize_fails_when_cli_reports_a_different_session(
        monkeypatch, tmp_path):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    other_session_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    phase_calls = []
    monkeypatch.setattr(rj, "_sync_pi_agent_sessions", lambda *_args: True)
    monkeypatch.setattr(
        rj, "_resolve_resume_session_id", lambda *_args, **_kwargs: _SESSION_ID,
    )
    monkeypatch.setattr(rj, "_pi_session_exists_in_container", lambda *_args: True)

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        if len(phase_calls) == 1:
            return SimpleNamespace(
                returncode=124,
                stdout="initial timeout",
                stderr="",
                aj_timed_out=True,
            )
        with open(
            os.path.join(args[1], ".aj_session_state.json"),
            "w",
            encoding="utf-8",
        ) as stream:
            json.dump({"harness": "pi", "session_id": other_session_id}, stream)
        return SimpleNamespace(
            returncode=0,
            stdout="wrong session",
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is False
    assert result["error"] == "Pi 原生会话恢复校验失败"
    assert len(phase_calls) == 2
    assert phase_calls[1][1]["resume_session_id"] == _SESSION_ID
    assert proxy_closes == [True]
