# -*- coding: utf-8 -*-
"""反向评测 Pi 作答节点的原生会话、轨迹同步与超时恢复。"""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import oj_modules.tasks.ranking.reverse_judge as rj
import oj_modules.tasks.ranking.agent_judge as aj


_SESSION_ID = "12345678-1234-1234-1234-123456789abc"
_MISSING_STOP_REASON = object()


def _pi_endpoint():
    return {
        "id": 7,
        "pool_kind": "primary",
        "harness": rj.HARNESS_PI,
        "protocol": "openai",
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
        lambda base_url, api_key, harness, protocol=None: (
            proxy_calls.append((base_url, api_key, harness, protocol)) or proxy
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
    monkeypatch.setattr(
        rj, "_dump_harness_trace", lambda *_args, **_kwargs: None,
    )
    return package, proxy_calls, proxy_closes


def _append_pi_session_message(
        tmp_path, stop_reason=_MISSING_STOP_REASON, *,
        session_id=_SESSION_ID, content_text="phase finished"):
    """向宿主镜像目录写入一条最小 Pi 原生 assistant 消息。"""
    session_path = (
        tmp_path
        / "submission"
        / "reverse_agent_trace"
        / "attempt-1"
        / ".pi"
        / "agent"
        / "sessions"
        / "--workspace--"
        / f"native_{session_id}.jsonl"
    )
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
        "content": [{"type": "text", "text": content_text}],
    }
    if stop_reason is not _MISSING_STOP_REASON:
        message["stopReason"] = stop_reason
    with session_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "type": "message",
            "id": f"assistant-{session_path.stat().st_size}",
            "message": message,
        }) + "\n")
    return session_path


def _pi_trace_dir(tmp_path):
    return (
        tmp_path
        / "submission"
        / "reverse_agent_trace"
        / "attempt-1"
    )


def _write_pi_workspace_session(package, session_id=_SESSION_ID):
    state_path = package / "template" / ".aj_session_state.json"
    state_path.write_text(
        json.dumps({"harness": "pi", "session_id": session_id}),
        encoding="utf-8",
    )


def test_pi_reverse_container_env_uses_attempt_proxy_and_openai_contract():
    args = rj._agent_env_args(
        rj.HARNESS_PI,
        "http://host.docker.internal:43123/v1",
        "attempt-token",
        "deepseek-v4-flash",
        "unused.jsonl",
        include_prompt=False,
        endpoint={
            "context_window_tokens": 131_072,
            "max_output_tokens": 16_384,
            "thinking_compatibility": False,
        },
    )
    env = {
        args[index + 1].split("=", 1)[0]: args[index + 1].split("=", 1)[1]
        for index, value in enumerate(args[:-1])
        if value == "-e" and "=" in args[index + 1]
    }

    assert env["AJ_HARNESS"] == rj.HARNESS_PI
    assert env["AJ_ENDPOINT_PROTOCOL"] == "openai"
    assert env["OPENAI_BASE_URL"] == "http://host.docker.internal:43123/v1"
    assert env["OPENAI_API_KEY"] == "attempt-token"
    assert env["OPENAI_MODEL"] == "deepseek-v4-flash"
    assert env["AJ_CONTEXT_WINDOW_TOKENS"] == "131072"
    assert env["AJ_MAX_OUTPUT_TOKENS"] == "16384"
    assert env["AJ_THINKING_COMPATIBILITY"] == "0"
    assert env["AJ_ENDPOINT_THINKING_FORMAT"] == ""
    assert env["AJ_THINKING_FORMAT"] == "generic"
    assert env["AJ_PI_THINKING_FORMAT"] == "generic"
    assert "AJ_PROMPT" not in env


def test_pi_reverse_container_env_marks_anthropic_protocol():
    args = rj._agent_env_args(
        rj.HARNESS_PI,
        "http://host.docker.internal:43123/anthropic",
        "attempt-token",
        "mimo-v2.5-pro",
        "unused.jsonl",
        include_prompt=False,
        endpoint={
            "protocol": "anthropic",
            "base_url": "https://api.xiaomimimo.com/anthropic",
            "context_window_tokens": 131_072,
            "max_output_tokens": 16_384,
            "thinking_compatibility": True,
            "thinking_format": "thinking_type",
        },
    )
    env = {
        args[index + 1].split("=", 1)[0]: args[index + 1].split("=", 1)[1]
        for index, value in enumerate(args[:-1])
        if value == "-e" and "=" in args[index + 1]
    }

    assert env["AJ_ENDPOINT_PROTOCOL"] == "anthropic"
    assert env["AJ_ENDPOINT_THINKING_FORMAT"] == "thinking_type"
    assert env["ANTHROPIC_BASE_URL"] == "http://host.docker.internal:43123/anthropic"
    assert env["ANTHROPIC_API_KEY"] == "attempt-token"
    assert env["ANTHROPIC_MODEL"] == "mimo-v2.5-pro"


@pytest.mark.parametrize(("base_url", "expected"), [
    ("https://api.deepseek.com/v1", "deepseek"),
    ("https://gateway.deepseek.com/v1", "deepseek"),
    ("https://deepseek.com/v1", "deepseek"),
    ("http://api.deepseek.com/v1", "generic"),
    ("https://evil-deepseek.com/v1", "generic"),
    ("https://deepseek.com.attacker.example/v1", "generic"),
    ("https://model.example/v1", "generic"),
])
def test_thinking_wire_profile_uses_exact_canonical_endpoint_origin(
        base_url, expected):
    assert aj._thinking_wire_profile(base_url) == expected


def test_pi_reverse_proxy_keeps_original_deepseek_profile_without_exposing_origin():
    args = rj._agent_env_args(
        rj.HARNESS_PI,
        "http://host.docker.internal:43123/v1",
        "attempt-token",
        "opaque-model-name",
        "unused.jsonl",
        endpoint={
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "real-key-must-not-enter-container",
            "thinking_compatibility": True,
        },
    )
    rendered = json.dumps(args)

    assert "AJ_THINKING_FORMAT=deepseek" in args
    assert "AJ_PI_THINKING_FORMAT=deepseek" in args
    assert "api.deepseek.com" not in rendered
    assert "real-key-must-not-enter-container" not in rendered
    assert "attempt-token" in rendered


def test_copied_global_endpoint_does_not_use_vendor_url_wire_profile():
    args = rj._agent_env_args(
        rj.HARNESS_PI,
        "http://host.docker.internal:43123/v1",
        "attempt-token",
        "opaque-model-name",
        "unused.jsonl",
        endpoint={
            "base_url": "https://api.deepseek.com/v1",
            "api_key": "real-key-must-not-enter-container",
            "protocol": "openai",
            "thinking_compatibility": True,
            "thinking_format": "enable_thinking",
        },
    )

    assert "AJ_ENDPOINT_THINKING_FORMAT=enable_thinking" in args
    assert "AJ_THINKING_FORMAT=generic" in args
    assert "AJ_PI_THINKING_FORMAT=generic" in args


def test_pi_reverse_run_never_injects_real_api_key_into_agent_container(
        monkeypatch, tmp_path):
    subprocess_calls = []
    package, proxy_calls, proxy_closes = _prepare_run_agent(
        monkeypatch,
        tmp_path,
        use_real_agent_env=True,
        subprocess_calls=subprocess_calls,
    )
    def run_phase(*_args, **_kwargs):
        _write_pi_workspace_session(package)
        _append_pi_session_message(tmp_path, "stop")
        return SimpleNamespace(
            returncode=0,
            stdout="completed",
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

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
        ("https://pi.example/v1", "real-pi-key", rj.HARNESS_PI, "openai"),
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


def test_pi_anthropic_hello_probe_uses_messages_and_x_api_key():
    endpoint = {**_pi_endpoint(), "protocol": "anthropic"}
    request, error = aj._hello_probe_request(endpoint)

    assert error is None
    assert request.full_url == "https://pi.example/v1/messages"
    assert request.get_header("X-api-key") == "real-pi-key"
    assert request.get_header("Anthropic-version") == "2023-06-01"
    assert request.get_header("Authorization") is None
    assert json.loads(request.data.decode("utf-8")) == {
        "model": "pi-model",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": "hello"}],
    }


def test_sync_pi_agent_sessions_mirrors_native_tree_and_streams_combined_trace(
        monkeypatch, tmp_path):
    trace_dir = tmp_path / "trace"
    copied = []
    listed_runtime_users = []
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
        lambda container_name, **kwargs: (
            listed_runtime_users.append(kwargs.get("runtime_user")) or [
                {
                    "relative_path": first_relative,
                    "mtime_ns": 1_000_000_000,
                    "size": len(payloads[first_relative]),
                },
                {
                    "relative_path": second_relative,
                    "mtime_ns": 2_000_000_000,
                    "size": len(payloads[second_relative]),
                },
            ]
        ),
    )

    def fake_copy(
            container_name, relative_path, destination, mtime_ns,
            **kwargs):
        copied.append((
            container_name, relative_path, destination, mtime_ns,
            kwargs.get("runtime_user"),
        ))
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "wb") as stream:
            stream.write(payloads[relative_path])
        os.utime(destination, ns=(mtime_ns, mtime_ns))
        return True

    monkeypatch.setattr(rj, "_copy_pi_session_file", fake_copy)

    assert rj._sync_pi_agent_sessions(
        "pi-container", str(trace_dir), runtime_user="501:20",
    ) is True

    session_root = trace_dir / ".pi" / "agent" / "sessions"
    combined = session_root / "reverse_solve_combined.jsonl"
    assert listed_runtime_users == ["501:20"]
    assert [(item[0], item[1], item[3], item[4]) for item in copied] == [
        ("pi-container", first_relative, 1_000_000_000, "501:20"),
        ("pi-container", second_relative, 2_000_000_000, "501:20"),
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
        runtime_user="501:20",
    )
    assert destination.read_bytes() == payload
    assert not destination.with_suffix(".jsonl.tmp").exists()
    args, kwargs = calls[0]
    assert args[:6] == [
        "docker", "exec", "--user", "501:20", "pi-container", "cat",
    ]
    assert args[-2:] == [
        "--",
        (
            f"{rj._PI_CONTAINER_SESSION_ROOT}/--workspace--/"
            f"native_{_SESSION_ID}.jsonl"
        ),
    ]
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
        lambda _container, **_kwargs: pytest.fail(
            "JSON header 已包含 session id，不应扫描回退"
        ),
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


def test_pi_container_session_lookup_uses_runtime_user(monkeypatch):
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if "bash" in args:
            stdout = f"123.0 native_{_SESSION_ID}.jsonl\n"
        else:
            stdout = (
                f"{rj._PI_CONTAINER_SESSION_ROOT}/native_{_SESSION_ID}.jsonl\n"
            )
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(rj.subprocess, "run", fake_run)

    assert rj._latest_pi_session_id_from_container(
        "pi-container", runtime_user="501:20",
    ) == _SESSION_ID
    assert rj._pi_session_exists_in_container(
        "pi-container", _SESSION_ID, runtime_user="501:20",
    ) is True
    assert calls[0][2:5] == ["--user", "501:20", "pi-container"]
    assert calls[1][2:5] == ["--user", "501:20", "pi-container"]


def test_run_agent_pi_timeout_resumes_same_native_session(
        monkeypatch, tmp_path):
    package, proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    sync_calls = []
    session_checks = []
    resolve_users = []
    dump_users = []
    real_resolve = rj._resolve_resume_session_id
    monkeypatch.setattr(
        rj, "_prepare_agent_workspace_for_node", lambda *_args: "501:20",
    )
    monkeypatch.setattr(
        rj,
        "_resolve_resume_session_id",
        lambda *args, **kwargs: (
            resolve_users.append(kwargs.get("runtime_user"))
            or real_resolve(*args, **kwargs)
        ),
    )
    monkeypatch.setattr(
        rj,
        "_dump_harness_trace",
        lambda *_args, **kwargs: dump_users.append(
            kwargs.get("runtime_user")
        ),
    )
    monkeypatch.setattr(
        rj,
        "_sync_pi_agent_sessions",
        lambda container, trace, runtime_user="node", **_kwargs: (
            sync_calls.append((container, trace, runtime_user)) or True
        ),
    )
    monkeypatch.setattr(
        rj,
        "_pi_session_exists_in_container",
        lambda container, session_id, runtime_user="node": (
            session_checks.append((container, session_id, runtime_user)) or True
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
        _write_pi_workspace_session(package)
        _append_pi_session_message(tmp_path, "stop")
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
    assert [call[1]["runtime_user"] for call in phase_calls] == [
        "501:20", "501:20",
    ]
    assert session_checks == [
        ("rj_agent_12_attempt-1", _SESSION_ID, "501:20"),
        ("rj_agent_12_attempt-1", _SESSION_ID, "501:20"),
    ]
    assert len(sync_calls) >= 5
    assert all(call[2] == "501:20" for call in sync_calls)
    assert resolve_users == ["501:20"]
    assert dump_users == ["501:20"]
    assert proxy_calls == [
        ("https://pi.example/v1", "real-pi-key", rj.HARNESS_PI, "openai"),
    ]
    assert proxy_closes == [True]


def test_run_agent_pi_timeout_fails_when_native_session_is_missing(
        monkeypatch, tmp_path):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        rj, "_resolve_resume_session_id", lambda *_args, **_kwargs: _SESSION_ID,
    )
    monkeypatch.setattr(
        rj, "_pi_session_exists_in_container",
        lambda *_args, **_kwargs: False,
    )

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
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        rj, "_resolve_resume_session_id", lambda *_args, **_kwargs: _SESSION_ID,
    )
    monkeypatch.setattr(
        rj, "_pi_session_exists_in_container",
        lambda *_args, **_kwargs: True,
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        if len(phase_calls) == 1:
            return SimpleNamespace(
                returncode=124,
                stdout="initial timeout",
                stderr="",
                aj_timed_out=True,
            )
        _write_pi_workspace_session(package, other_session_id)
        _append_pi_session_message(tmp_path, "stop")
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


def test_run_agent_pi_length_resumes_same_native_session_and_finalize_stop_succeeds(
        monkeypatch, tmp_path):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    session_checks = []
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        rj,
        "_pi_session_exists_in_container",
        lambda container, session_id, runtime_user="node": (
            session_checks.append((container, session_id, runtime_user)) or True
        ),
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        _write_pi_workspace_session(package)
        if len(phase_calls) == 1:
            _append_pi_session_message(tmp_path, "length")
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    "type": "session", "version": 3, "id": _SESSION_ID,
                }),
                stderr="",
                aj_timed_out=False,
            )
        _append_pi_session_message(tmp_path, "stop")
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
    assert result["error"] == ""
    assert result["stdout"].endswith("\n\nfinalized")
    assert [call[0][2] for call in phase_calls] == [
        "reverse_solve", "reverse_finalize",
    ]
    assert "resume_session_id" not in phase_calls[0][1]
    assert phase_calls[1][1]["resume_session_id"] == _SESSION_ID
    assert phase_calls[1][1]["fork_session"] is False
    assert session_checks
    assert all(
        session_id == _SESSION_ID and runtime_user == "node"
        for _container, session_id, runtime_user in session_checks
    )
    assert proxy_closes == [True]


@pytest.mark.parametrize(
    "stop_reason",
    ["error", "aborted", _MISSING_STOP_REASON],
    ids=["error", "aborted", "missing"],
)
def test_run_agent_pi_zero_exit_rejects_non_success_stop_reason(
        monkeypatch, tmp_path, stop_reason):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        _write_pi_workspace_session(package)
        _append_pi_session_message(tmp_path, stop_reason)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "type": "session", "version": 3, "id": _SESSION_ID,
            }),
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is False
    expected_reason = (
        "missing" if stop_reason is _MISSING_STOP_REASON else stop_reason
    )
    assert f"stopReason={expected_reason}" in result["error"]
    assert len(phase_calls) == 1
    assert phase_calls[0][0][2] == "reverse_solve"
    assert proxy_closes == [True]


@pytest.mark.parametrize("finalize_stop_reason", ["length", "error"])
def test_run_agent_pi_finalize_rejects_non_stop_terminal_reason(
        monkeypatch, tmp_path, finalize_stop_reason):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        rj, "_pi_session_exists_in_container",
        lambda *_args, **_kwargs: True,
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        _write_pi_workspace_session(package)
        if len(phase_calls) == 1:
            _append_pi_session_message(tmp_path, "length")
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    "type": "session", "version": 3, "id": _SESSION_ID,
                }),
                stderr="",
                aj_timed_out=False,
            )
        _append_pi_session_message(tmp_path, finalize_stop_reason)
        return SimpleNamespace(
            returncode=0,
            stdout="finalize incomplete",
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is False
    assert f"stopReason={finalize_stop_reason}" in result["error"]
    assert [call[0][2] for call in phase_calls] == [
        "reverse_solve", "reverse_finalize",
    ]
    assert phase_calls[1][1]["resume_session_id"] == _SESSION_ID
    assert phase_calls[1][1]["fork_session"] is False
    assert proxy_closes == [True]


def test_latest_pi_terminal_state_is_bound_to_expected_native_session(tmp_path):
    other_session_id = "87654321-4321-4321-4321-cba987654321"
    expected_path = _append_pi_session_message(tmp_path, "length")
    other_path = _append_pi_session_message(
        tmp_path, "stop", session_id=other_session_id,
    )
    combined_path = expected_path.parents[1] / rj._PI_COMBINED_TRACE_NAME
    combined_path.write_bytes(other_path.read_bytes() + expected_path.read_bytes())

    state = rj._latest_pi_terminal_state(
        str(_pi_trace_dir(tmp_path)), _SESSION_ID,
    )

    assert state["session_id"] == _SESSION_ID
    assert state["stop_reason"] == "length"


def test_latest_pi_terminal_state_accepts_large_reasoning_line(tmp_path):
    _append_pi_session_message(
        tmp_path,
        "length",
        content_text="x" * (3 * 1024 * 1024),
    )

    state = rj._latest_pi_terminal_state(
        str(_pi_trace_dir(tmp_path)), _SESSION_ID,
    )

    assert state["stop_reason"] == "length"


def test_latest_pi_terminal_state_bounds_unknown_stop_reason(tmp_path):
    _append_pi_session_message(tmp_path, "x" * (1024 * 1024))

    state = rj._latest_pi_terminal_state(
        str(_pi_trace_dir(tmp_path)), _SESSION_ID,
    )

    assert state["stop_reason"] == "unknown"
    assert rj._pi_terminal_error(state).endswith("stopReason=unknown）")


def test_run_agent_pi_finalize_requires_new_native_session_event(
        monkeypatch, tmp_path):
    package, _proxy_calls, proxy_closes = _prepare_run_agent(monkeypatch, tmp_path)
    phase_calls = []
    session_paths = []
    monkeypatch.setattr(
        rj, "_sync_pi_agent_sessions", lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        rj, "_pi_session_exists_in_container",
        lambda *_args, **_kwargs: True,
    )

    def run_phase(*args, **kwargs):
        phase_calls.append((args, kwargs))
        _write_pi_workspace_session(package)
        if len(phase_calls) == 1:
            session_paths.append(_append_pi_session_message(tmp_path, "stop"))
            return SimpleNamespace(
                returncode=124,
                stdout=json.dumps({
                    "type": "session", "version": 3, "id": _SESSION_ID,
                }),
                stderr="",
                aj_timed_out=True,
            )
        with session_paths[0].open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({
                "type": "message",
                "id": "finalize-user-only",
                "message": {
                    "role": "user",
                    "content": [{"type": "text", "text": "finalize"}],
                },
            }) + "\n")
        return SimpleNamespace(
            returncode=0,
            stdout="finalize returned without touching the native session",
            stderr="",
            aj_timed_out=False,
        )

    monkeypatch.setattr(rj, "_exec_reverse_harness_phase", run_phase)

    result = rj._run_agent(
        12, "attempt-1", str(package), _pi_endpoint(), 30, 10,
    )

    assert result["ok"] is False
    assert result["error"] == "Pi 恢复收尾没有产生新的原生会话事件"
    assert [call[0][2] for call in phase_calls] == [
        "reverse_solve", "reverse_finalize",
    ]
    assert proxy_closes == [True]
