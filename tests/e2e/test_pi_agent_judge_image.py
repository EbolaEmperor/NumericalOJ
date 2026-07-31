# -*- coding: utf-8 -*-
"""真实 Agent Judge lite 镜像中的 Pi harness、session 与轨迹链路。"""

from __future__ import annotations

import json
import os
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
_MODEL = "pi-e2e-model"
_TOOL_OUTPUT = "PI_TOOL_RESULT_OK"
_FINAL_OUTPUT = "PI_FINAL_OK"
_RESUMED_OUTPUT = "PI_RESUMED_OK"

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
            or request.get("max_tokens") != 16384
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
        "AJ_PROMPT": prompt,
        "AJ_WORKSPACE": "/workspace",
        "AJ_SESSION_STATE": "/workspace/.aj_session_state.json",
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
    assert _run(
        ["docker", "run", "--rm", image, "pi", "--version"],
    ).stdout.strip() == "0.82.1"

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
