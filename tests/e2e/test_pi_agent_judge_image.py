# -*- coding: utf-8 -*-
"""真实 Agent Judge lite 镜像中的 Pi harness、session 与轨迹链路。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from oj_modules import ranking_reverse_judge_db as reverse_db
from oj_modules.tasks import ranking_reverse_judge_tasks as reverse_tasks


_IMAGE_ENV = "NUMOJ_PI_AGENT_JUDGE_IMAGE"
_API_KEY = "pi-e2e-token"
_MODEL = "deepseek-v4-flash"
_TOOL_OUTPUT = "PI_TOOL_RESULT_OK"
_FINAL_OUTPUT = "PI_FINAL_OK"
_RESUMED_OUTPUT = "PI_RESUMED_OK"
_TEMPLATE_SENTINEL = "PI_TEMPLATE_NOT_SOLVED"
_FINALIZED_ANSWER = "PI_REVERSE_FINALIZED_OK"
_CLAUDE_OUTPUT = "CLAUDE_CAPABILITY_CONTRACT_OK"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        not os.environ.get(_IMAGE_ENV),
        reason=f"需要通过 {_IMAGE_ENV} 指定已构建的 Agent Judge lite 镜像",
    ),
]


class _PiChatCompletionsHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests: list[dict[str, Any]] = []
    lock = threading.Lock()

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _reply_sse(self, chunks: list[dict[str, Any]]) -> None:
        body = "".join(
            f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
            for chunk in chunks
        )
        body += "data: [DONE]\n\n"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_error(400)
            return
        if (
            self.path != "/v1/chat/completions"
            or self.headers.get("Authorization") != f"Bearer {_API_KEY}"
            or request.get("model") != _MODEL
            or request.get("stream") is not True
            or request.get("max_tokens") != 384000
            or request.get("thinking") not in (None, {"type": "disabled"})
            or "reasoning_effort" in request
            or "max_completion_tokens" in request
            or "store" in request
        ):
            self.send_error(401)
            return
        with type(self).lock:
            type(self).requests.append(request)
            request_index = len(type(self).requests)

        common = {
            "object": "chat.completion.chunk",
            "created": 1,
            "model": _MODEL,
        }
        if request_index == 1:
            self._reply_sse([
                {
                    **common,
                    "id": "chatcmpl-pi-tool",
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "tool_calls": [{
                                "index": 0,
                                "id": "call_pi_bash",
                                "type": "function",
                                "function": {
                                    "name": "bash",
                                    "arguments": json.dumps({
                                        "command": f"printf '{_TOOL_OUTPUT}'",
                                    }),
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                },
            ])
            return

        text = _FINAL_OUTPUT if request_index == 2 else _RESUMED_OUTPUT
        self._reply_sse([
            {
                **common,
                "id": f"chatcmpl-pi-{request_index}",
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }],
            },
        ])


class _PiLengthFinalizeHandler(_PiChatCompletionsHandler):
    """让真实 Pi CLI 先触发 length，再在恢复轮用工具完成交付。"""

    requests: list[dict[str, Any]] = []
    lock = threading.Lock()

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_error(400)
            return
        if (
            self.path != "/v1/chat/completions"
            or self.headers.get("Authorization") != f"Bearer {_API_KEY}"
            or request.get("model") != _MODEL
            or request.get("stream") is not True
            or request.get("max_tokens") != 384000
            or "max_completion_tokens" in request
            or "store" in request
        ):
            self.send_error(401)
            return
        with type(self).lock:
            type(self).requests.append(request)
            request_index = len(type(self).requests)

        allowed_thinking = (
            (None, {"type": "enabled"})
            if request_index == 1
            else (None, {"type": "disabled"})
        )
        invalid_reasoning_effort = (
            request.get("reasoning_effort") != "high"
            if request_index == 1
            else "reasoning_effort" in request
        )
        if (
            request.get("thinking") not in allowed_thinking
            or invalid_reasoning_effort
        ):
            self.send_error(422)
            return

        common = {
            "object": "chat.completion.chunk",
            "created": 1,
            "model": _MODEL,
        }
        if request_index == 1:
            # Pi 的 JSON 模式在 length 时可能仍退出 0。worker 必须读取
            # 原生 session 的 stopReason，并自动用同一个 UUID 进入 finalize。
            self._reply_sse([
                {
                    **common,
                    "id": "chatcmpl-pi-length",
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "role": "assistant",
                            "reasoning_content": "先分析题目，但本轮输出额度已耗尽。",
                        },
                        "finish_reason": None,
                    }],
                },
                {
                    **common,
                    "id": "chatcmpl-pi-length",
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": "length",
                    }],
                },
            ])
            return

        if request_index == 2:
            command = (
                f"printf '{_FINALIZED_ANSWER}\\n' > answer.txt "
                "&& cat answer.txt"
            )
            self._reply_sse([{
                **common,
                "id": "chatcmpl-pi-finalize-tool",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "tool_calls": [{
                            "index": 0,
                            "id": "call_pi_finalize",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": json.dumps({"command": command}),
                            },
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
            }])
            return

        if request_index == 3:
            self._reply_sse([{
                **common,
                "id": "chatcmpl-pi-finalize-stop",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": "交付文件已经写入。",
                    },
                    "finish_reason": "stop",
                }],
            }])
            return

        self.send_error(409)


class _ClaudeMessagesHandler(BaseHTTPRequestHandler):
    """捕获 Claude Code 主流式请求，验证 adapter 没有静默压低输出上限。"""

    protocol_version = "HTTP/1.1"
    requests: list[dict[str, Any]] = []
    lock = threading.Lock()

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _reply_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _reply_sse(self) -> None:
        model = "custom-probe"
        events = [
            ("message_start", {
                "type": "message_start",
                "message": {
                    "id": "msg_capability_contract",
                    "type": "message",
                    "role": "assistant",
                    "model": model,
                    "content": [],
                    "stop_reason": None,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 0},
                },
            }),
            ("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            }),
            ("content_block_delta", {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": _CLAUDE_OUTPUT},
            }),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 4},
            }),
            ("message_stop", {"type": "message_stop"}),
        ]
        body = "".join(
            f"event: {event}\ndata: {json.dumps(payload)}\n\n"
            for event, payload in events
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
            request = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_error(400)
            return
        if self.path.split("?", 1)[0].endswith("/messages/count_tokens"):
            self._reply_json({"input_tokens": 1})
            return
        if not self.path.split("?", 1)[0].endswith("/messages"):
            self.send_error(404)
            return
        with type(self).lock:
            type(self).requests.append(request)
        if request.get("stream") is True:
            self._reply_sse()
        else:
            self._reply_json({
                "id": "msg_capability_contract",
                "type": "message",
                "role": "assistant",
                "model": "custom-probe",
                "content": [{"type": "text", "text": _CLAUDE_OUTPUT}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 4},
            })


def _run(
        args: list[str],
        *,
        timeout: int = 120,
        check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _docker_exec_pi(
        container_name: str,
        base_url: str,
        phase: str,
        prompt: str,
        *,
        session_id: str = "") -> subprocess.CompletedProcess[str]:
    env = {
        "AJ_HARNESS": "pi",
        "AJ_PHASE": phase,
        "AJ_EFFORT": "off",
        "AJ_PROMPT": prompt,
        "AJ_WORKSPACE": "/workspace",
        "AJ_SESSION_STATE": "/workspace/.aj_session_state.json",
        "AJ_PI_THINKING_FORMAT": "deepseek",
        "OPENAI_BASE_URL": base_url,
        "OPENAI_API_KEY": _API_KEY,
        "OPENAI_MODEL": _MODEL,
    }
    if session_id:
        env["AJ_RESUME_SESSION_ID"] = session_id
    args = ["docker", "exec", "--user", "node"]
    for key, value in env.items():
        args.extend(["-e", f"{key}={value}"])
    args.extend([container_name, "run_harness"])
    return _run(args)


def _message_contents(entries: list[dict[str, Any]], role: str) -> list[Any]:
    return [
        entry["message"].get("content")
        for entry in entries
        if (
            entry.get("type") == "message"
            and isinstance(entry.get("message"), dict)
            and entry["message"].get("role") == role
        )
    ]


def _session_entries(trace_dir: Path) -> list[dict[str, Any]]:
    session_path = reverse_db._latest_pi_jsonl(str(trace_dir))
    assert session_path
    return [
        json.loads(line)
        for line in Path(session_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_claude_lite_image_honors_one_million_context_and_384k_output_contract():
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI 不可用")
    image = os.environ[_IMAGE_ENV]
    try:
        _run(["docker", "image", "inspect", image], timeout=20)
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"本地不存在 Agent Judge 镜像 {image}")

    _ClaudeMessagesHandler.requests = []
    server = ThreadingHTTPServer(("0.0.0.0", 0), _ClaudeMessagesHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://host.docker.internal:{server.server_address[1]}"
    try:
        result = _run([
            "docker", "run", "--rm",
            "--add-host", "host.docker.internal:host-gateway",
            "--tmpfs", "/evidence:rw,nosuid,nodev,size=8m,mode=755",
            "--user", "node",
            "-e", "AJ_HARNESS=claude_code",
            "-e", "AJ_AUDIT_READ_ONLY=1",
            "-e", "AJ_PROMPT=Reply with the supplied deterministic response.",
            "-e", "AJ_CONTEXT_WINDOW_TOKENS=1000000",
            "-e", "AJ_MAX_OUTPUT_TOKENS=384000",
            "-e", "AJ_THINKING_COMPATIBILITY=1",
            "-e", f"ANTHROPIC_BASE_URL={base_url}",
            "-e", f"ANTHROPIC_API_KEY={_API_KEY}",
            "-e", f"ANTHROPIC_AUTH_TOKEN={_API_KEY}",
            "-e", "ANTHROPIC_MODEL=custom-probe",
            image,
            "run_harness",
        ], timeout=180)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert _CLAUDE_OUTPUT in result.stdout
    streaming = [
        request
        for request in _ClaudeMessagesHandler.requests
        if request.get("stream") is True
    ]
    assert streaming
    assert all(request.get("model") == "custom-probe" for request in streaming)
    assert all(request.get("max_tokens") == 384_000 for request in streaming)


def test_pi_lite_image_runs_tools_resumes_native_session_and_renders_trace(
        tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI 不可用")
    image = os.environ[_IMAGE_ENV]
    try:
        _run(["docker", "image", "inspect", image], timeout=20)
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"本地不存在 Agent Judge 镜像 {image}")

    assert _run(
        ["docker", "run", "--rm", image, "node", "--version"],
    ).stdout.strip().startswith("v24.")
    pi_version = _run(
        ["docker", "run", "--rm", image, "pi", "--version"],
    ).stdout.strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", pi_version)

    _PiChatCompletionsHandler.requests = []
    server = ThreadingHTTPServer(("0.0.0.0", 0), _PiChatCompletionsHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    # bind mount 两端的 UID 在 Linux CI 与 macOS/Colima 上都可能不同；
    # 一次性测试目录及状态文件由宿主预先放开，避免任一端事后 chmod/chown。
    workspace.chmod(0o777)
    state_path = workspace / ".aj_session_state.json"
    state_journal_path = workspace / ".aj_session_state.jsonl"
    state_path.touch()
    state_journal_path.touch()
    state_path.chmod(0o666)
    state_journal_path.chmod(0o666)
    trace_dir = tmp_path / "trace"
    container_name = f"numoj-pi-e2e-{uuid.uuid4().hex[:12]}"
    base_url = (
        f"http://host.docker.internal:{server.server_address[1]}/v1"
    )

    try:
        _run([
            "docker", "run", "-d", "--name", container_name,
            "--add-host", "host.docker.internal:host-gateway",
            "-v", f"{workspace}:/workspace",
            "-w", "/workspace",
            image, "bash", "-lc", "tail -f /dev/null",
        ])
        _run([
            "docker", "exec", container_name, "bash", "-lc",
            "mkdir -p /home/node && chown node:node /home/node",
        ])

        first = _docker_exec_pi(
            container_name,
            base_url,
            "reverse_solve",
            "Call the bash tool once, then finish.",
        )
        assert first.returncode == 0, first.stderr
        state = json.loads(
            state_path.read_text(encoding="utf-8"),
        )
        session_id = state["session_id"]
        assert state["harness"] == "pi"
        assert state["phase"] == "reverse_solve"
        assert reverse_tasks._normalize_pi_session_id(session_id) == session_id
        first_stdout_events = [
            json.loads(line)
            for line in first.stdout.splitlines()
            if line.strip()
        ]
        assert len(first_stdout_events) == 1
        assert first_stdout_events[0]["type"] == "session"
        assert first_stdout_events[0]["version"] == 3
        assert first_stdout_events[0]["id"] == session_id

        second = _docker_exec_pi(
            container_name,
            base_url,
            "reverse_finalize",
            "Return the final confirmation now.",
            session_id=session_id,
        )
        assert second.returncode == 0, second.stderr
        resumed_state = json.loads(
            state_path.read_text(encoding="utf-8"),
        )
        assert resumed_state["session_id"] == session_id
        assert resumed_state["resume_session_id"] == session_id
        assert resumed_state["phase"] == "reverse_finalize"
        second_stdout_events = [
            json.loads(line)
            for line in second.stdout.splitlines()
            if line.strip()
        ]
        assert len(second_stdout_events) == 1
        assert second_stdout_events[0]["type"] == "session"
        assert second_stdout_events[0]["id"] == session_id

        assert reverse_tasks._pi_session_exists_in_container(
            container_name, session_id,
        )
        assert reverse_tasks._sync_pi_agent_sessions(
            container_name, str(trace_dir),
        )
        session_path = reverse_db._latest_pi_jsonl(str(trace_dir))
        assert session_path
        native_paths = [
            path
            for path in (
                trace_dir / ".pi" / "agent" / "sessions"
            ).rglob("*.jsonl")
            if path.name != reverse_tasks._PI_COMBINED_TRACE_NAME
        ]
        assert len(native_paths) == 1
        assert session_id in native_paths[0].name
        entries = [
            json.loads(line)
            for line in Path(session_path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        headers = [entry for entry in entries if entry.get("type") == "session"]
        assert len(headers) == 1
        assert headers[0]["version"] == 3
        assert headers[0]["id"] == session_id
        assert any(
            _TOOL_OUTPUT in json.dumps(content, ensure_ascii=False)
            for content in _message_contents(entries, "toolResult")
        )

        projected = reverse_db._collect_trace_messages(str(trace_dir))
        kinds = [message["kind"] for message in projected]
        assert "tool" in kinds
        assert "tool_result" in kinds
        assert any(
            message["kind"] == "tool_result"
            and _TOOL_OUTPUT in message["text"]
            for message in projected
        )
        assert any(
            message["kind"] == "assistant"
            and _RESUMED_OUTPUT in message["text"]
            for message in projected
        )
        assert reverse_db._collect_trace_files(str(trace_dir)) == []

        requests = _PiChatCompletionsHandler.requests
        assert len(requests) == 3
        assert any(tool["function"]["name"] == "bash" for tool in requests[0]["tools"])
        assert any(
            message.get("role") == "tool" and _TOOL_OUTPUT in str(message.get("content"))
            for message in requests[1]["messages"]
        )
        assert any(
            message.get("role") == "assistant" and _FINAL_OUTPUT in str(message.get("content"))
            for message in requests[2]["messages"]
        )
    finally:
        _run(
            ["docker", "rm", "-f", container_name],
            timeout=30,
            check=False,
        )
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)


def test_pi_reverse_agent_length_auto_finalizes_same_native_session(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """真实 _run_agent 必须把 rc=0 + length 恢复成可评测交付物。"""
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI 不可用")
    image = os.environ[_IMAGE_ENV]
    try:
        _run(["docker", "image", "inspect", image], timeout=20)
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"本地不存在 Agent Judge 镜像 {image}")

    _PiLengthFinalizeHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PiLengthFinalizeHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    package = tmp_path / "package"
    template_dir = package / "template"
    problem_dir = package / "problem"
    template_dir.mkdir(parents=True)
    problem_dir.mkdir()
    answer_path = template_dir / "answer.txt"
    answer_path.write_text(_TEMPLATE_SENTINEL + "\n", encoding="utf-8")
    for state_name in (".aj_session_state.json", ".aj_session_state.jsonl"):
        state_path = template_dir / state_name
        state_path.touch()
    (problem_dir / "problem.md").write_text(
        "把 answer.txt 改为题目要求的最终答案，不得只保留模板。\n",
        encoding="utf-8",
    )

    submission_root = tmp_path / "submission"
    monkeypatch.setattr(reverse_tasks, "JUDGE_IMAGE", image)
    monkeypatch.setattr(
        reverse_tasks, "submission_dir", lambda _sid: str(submission_root),
    )
    monkeypatch.setattr(
        reverse_tasks,
        "update_reverse_judge_step_for_attempt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(reverse_tasks, "_publish_snapshot", lambda *_args: None)
    # apt 索引刷新与本回归无关；其余容器、挂载目录 UID:GID 映射、代理、
    # Pi CLI、session 同步和自动 finalize 都走生产 _run_agent 的真实实现。
    monkeypatch.setattr(
        reverse_tasks, "_exec_container_apt_setup", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(reverse_tasks, "REVERSE_DEFAULT_EFFORT", "high")
    monkeypatch.setattr(reverse_tasks, "REVERSE_TRACE_SYNC_INTERVAL", 0.1)

    endpoint = {
        "id": 5619,
        "harness": reverse_tasks.HARNESS_PI,
        "base_url": f"http://127.0.0.1:{server.server_address[1]}/v1",
        "api_key": _API_KEY,
        "model": _MODEL,
        "concurrency_limit": 1,
    }
    attempt_id = f"pi-length-{uuid.uuid4().hex}"
    try:
        result = reverse_tasks._run_agent(
            5619,
            attempt_id,
            str(package),
            endpoint,
            timeout_s=90,
            finalize_timeout_s=60,
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    assert result["ok"] is True, json.dumps(
        {"result": result, "requests": _PiLengthFinalizeHandler.requests},
        ensure_ascii=False,
        indent=2,
    )
    assert result["error"] == ""
    assert answer_path.read_text(encoding="utf-8") == _FINALIZED_ANSWER + "\n"

    journal_path = template_dir / ".aj_session_state.jsonl"
    journal = [
        json.loads(line)
        for line in journal_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [entry["phase"] for entry in journal] == [
        "reverse_solve",
        "reverse_finalize",
    ]
    session_id = journal[0]["session_id"]
    assert reverse_tasks._normalize_pi_session_id(session_id) == session_id
    assert journal[0]["returncode"] == 0
    assert journal[0]["resume_session_id"] == ""
    assert journal[1]["session_id"] == session_id
    assert journal[1]["resume_session_id"] == session_id
    assert journal[1]["returncode"] == 0

    trace_dir = Path(result["trace_dir"])
    entries = _session_entries(trace_dir)
    headers = [entry for entry in entries if entry.get("type") == "session"]
    assert len(headers) == 1
    assert headers[0]["id"] == session_id
    assistant_stop_reasons = [
        str(entry["message"].get("stopReason") or "").lower()
        for entry in entries
        if (
            entry.get("type") == "message"
            and isinstance(entry.get("message"), dict)
            and entry["message"].get("role") == "assistant"
        )
    ]
    assert assistant_stop_reasons[0] == "length"
    assert "tooluse" in assistant_stop_reasons
    assert assistant_stop_reasons[-1] == "stop"
    assert any(
        _FINALIZED_ANSWER in json.dumps(content, ensure_ascii=False)
        for content in _message_contents(entries, "toolResult")
    )

    projected = reverse_db._collect_trace_messages(str(trace_dir))
    assert any(message["kind"] == "tool" for message in projected)
    assert any(
        message["kind"] == "tool_result"
        and _FINALIZED_ANSWER in message["text"]
        for message in projected
    )
    assert _API_KEY not in json.dumps(projected, ensure_ascii=False)

    requests = _PiLengthFinalizeHandler.requests
    assert len(requests) == 3
    assert all(request["max_tokens"] == 384000 for request in requests)
    assert requests[0].get("thinking") in (None, {"type": "enabled"})
    assert requests[1].get("thinking") in (None, {"type": "disabled"})
    assert requests[2].get("thinking") in (None, {"type": "disabled"})
    assert requests[0]["reasoning_effort"] == "high"
    assert all(
        "reasoning_effort" not in request
        for request in requests[1:]
    )
    # Pi 不会把 stopReason=length 的未完成 assistant 重新送入上下文，但会保留
    # 原始题目请求并追加 finalize 指令；工作区和原生 session 仍沿用同一份。
    assert sum(
        message.get("role") == "user"
        for message in requests[1]["messages"]
    ) >= 2
    assert any(
        message.get("role") == "tool"
        and _FINALIZED_ANSWER in str(message.get("content"))
        for message in requests[2]["messages"]
    )


@pytest.mark.live_ai
def test_pi_reverse_agent_completes_with_real_deepseek_v4_flash(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """使用本地授权 Key 验证真实 DeepSeek、Pi、Docker 和轨迹投影全链路。"""
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI 不可用")
    image = os.environ[_IMAGE_ENV]
    try:
        _run(["docker", "image", "inspect", image], timeout=20)
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"本地不存在 Agent Judge 镜像 {image}")

    api_key = str(os.environ.get("NUMOJ_PI_LIVE_API_KEY") or "").strip()
    if not api_key:
        pytest.skip("未通过 NUMOJ_PI_LIVE_API_KEY 提供真实测试密钥")
    # Key 只保存在此测试的局部变量中；阻止 Flask/Celery、Docker 和 Agent 子进程
    # 从环境继承真实凭证。_run_agent 只把它交给宿主的一次性转发代理。
    monkeypatch.setenv("NUMOJ_PI_LIVE_API_KEY", "")
    monkeypatch.setenv("API_KEY", "")

    expected_answer = f"NUMOJ_PI_LIVE_OK_{uuid.uuid4().hex}"
    template_sentinel = "PI_LIVE_TEMPLATE_MUST_BE_REPLACED"
    package = tmp_path / "live-package"
    template_dir = package / "template"
    problem_dir = package / "problem"
    template_dir.mkdir(parents=True)
    problem_dir.mkdir()
    answer_path = template_dir / "answer.txt"
    answer_path.write_text(template_sentinel + "\n", encoding="utf-8")
    for state_name in (".aj_session_state.json", ".aj_session_state.jsonl"):
        state_path = template_dir / state_name
        state_path.touch()
    (problem_dir / "problem.md").write_text(
        "请使用工具把 /workspace/answer.txt 完全覆盖为下面这一行（末尾保留换行），"
        "然后再次读取文件确认内容；不要只在回复中复述，也不要创建说明文档：\n\n"
        f"{expected_answer}\n",
        encoding="utf-8",
    )

    submission_root = tmp_path / "live-submission"
    monkeypatch.setattr(reverse_tasks, "JUDGE_IMAGE", image)
    monkeypatch.setattr(
        reverse_tasks, "submission_dir", lambda _sid: str(submission_root),
    )
    monkeypatch.setattr(
        reverse_tasks,
        "update_reverse_judge_step_for_attempt",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(reverse_tasks, "_publish_snapshot", lambda *_args: None)
    monkeypatch.setattr(
        reverse_tasks, "_exec_container_apt_setup", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(reverse_tasks, "REVERSE_TRACE_SYNC_INTERVAL", 0.25)

    endpoint = {
        "id": 5619,
        "harness": reverse_tasks.HARNESS_PI,
        "base_url": "https://api.deepseek.com/v1",
        "api_key": api_key,
        "model": _MODEL,
        "concurrency_limit": 1,
    }
    result = reverse_tasks._run_agent(
        5619,
        f"pi-live-{uuid.uuid4().hex}",
        str(package),
        endpoint,
        timeout_s=300,
        finalize_timeout_s=120,
    )

    assert result["ok"] is True, result["error"]
    assert answer_path.read_text(encoding="utf-8") == expected_answer + "\n"
    trace_dir = Path(result["trace_dir"])
    entries = _session_entries(trace_dir)
    session_id = next(
        entry["id"] for entry in entries if entry.get("type") == "session"
    )
    terminal = reverse_tasks._latest_pi_terminal_state(
        str(trace_dir), session_id,
    )
    assert terminal["stop_reason"] == "stop"
    projected = reverse_db._collect_trace_messages(str(trace_dir))
    assert any(message["kind"] == "tool" for message in projected)
    assert any(message["kind"] == "tool_result" for message in projected)
    assert template_sentinel not in answer_path.read_text(encoding="utf-8")

    secret = api_key.encode("utf-8")
    leaked_paths = []
    for trace_path in trace_dir.rglob("*"):
        if trace_path.is_file() and secret in trace_path.read_bytes():
            leaked_paths.append(str(trace_path.relative_to(trace_dir)))
    assert not leaked_paths, f"真实 API Key 出现在轨迹文件中：{leaked_paths}"
