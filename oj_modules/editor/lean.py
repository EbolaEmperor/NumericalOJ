"""Lean 4 interactive proof service backed by isolated Docker containers."""

from __future__ import annotations

import atexit
from dataclasses import dataclass, field
import hashlib
import json
import os
import subprocess
import threading
import time
import uuid
from typing import Any

from oj_modules import config as _cfg
from oj_modules.editor.language_server import (
    LANGUAGE_RESPONSE_MAX_BYTES,
    LanguageServiceBusyError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
)


LEAN_SOURCE_MAX_BYTES = 512 * 1024
_DOCUMENT_URI = "file:///workspace/Submission.lean"


@dataclass
class _PendingResponse:
    event: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: BaseException | None = None


class LeanLanguageServerSession:
    """Own one ``lake serve`` process inside one Docker container."""

    def __init__(self, session_key: str) -> None:
        self.session_key = session_key
        self.last_used = time.monotonic()
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._pending: dict[int, _PendingResponse] = {}
        self._next_request_id = 1
        self._document_open = False
        self._document_version = 0
        self._source_digest = ""
        self._diagnostics: list[dict[str, Any]] = []
        self._processing: list[dict[str, Any]] = []
        self._semantic_legend: dict[str, list[str]] | None = None
        self._semantic_tokens: dict[str, Any] | None = None
        self._container_name = (
            f"numoj-lean-lsp-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        )

    @property
    def request_timeout(self) -> float:
        return float(getattr(_cfg, "LEAN4_INTERACTIVE_TIMEOUT_SECONDS", 60))

    def _command_line(self) -> list[str]:
        image = str(
            getattr(_cfg, "LEAN4_DOCKER_IMAGE", "numericaloj-lean4:latest")
        )
        return [
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--init",
            "--name",
            self._container_name,
            "--network",
            "none",
            "--memory",
            str(getattr(_cfg, "LEAN4_INTERACTIVE_MEM_LIMIT", "1g")),
            "--cpus",
            str(getattr(_cfg, "LEAN4_INTERACTIVE_CPU_LIMIT", "1")),
            "--pids-limit",
            str(getattr(_cfg, "LEAN4_INTERACTIVE_PIDS_LIMIT", 128)),
            "--user",
            "65532:65532",
            "--tmpfs",
            "/workspace:rw,nosuid,nodev,noexec,size=16m,uid=65532,gid=65532",
            "--workdir",
            "/workspace",
            image,
            "/usr/local/bin/numoj-lean-lsp",
            "/workspace",
        ]

    def _start_locked(self) -> None:
        if (
            self._process is not None
            and self._process.poll() is None
            and self._reader_thread is not None
            and self._reader_thread.is_alive()
        ):
            return
        self._reset_locked()
        try:
            process = subprocess.Popen(
                self._command_line(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise LanguageServiceUnavailableError(
                "Lean 4", "无法启动 Lean 4 交互容器"
            ) from exc
        if process.stdin is None or process.stdout is None:
            process.terminate()
            raise LanguageServiceUnavailableError(
                "Lean 4", "Lean 4 交互容器标准输入输出不可用"
            )
        self._process = process
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            args=(process,),
            name=f"numoj-lean-lsp-{self._container_name}",
            daemon=True,
        )
        self._reader_thread.start()
        try:
            initialize = self._request_locked(
                "initialize",
                {
                    "processId": None,
                    "clientInfo": {"name": "NumericalOJ", "version": "1"},
                    "rootUri": "file:///workspace",
                    "capabilities": {
                        "workspace": {"configuration": False},
                        "textDocument": {
                            "publishDiagnostics": {
                                "relatedInformation": True,
                                "versionSupport": True,
                            },
                            "semanticTokens": {
                                "dynamicRegistration": False,
                                "requests": {"full": True},
                                "tokenTypes": [],
                                "tokenModifiers": [],
                                "formats": ["relative"],
                                "overlappingTokenSupport": False,
                                "multilineTokenSupport": False,
                            },
                        },
                    },
                    "initializationOptions": {},
                    "workspaceFolders": [
                        {
                            "uri": "file:///workspace",
                            "name": "NumericalOJ Lean",
                        }
                    ],
                },
            )
            if not isinstance(initialize, dict) or not isinstance(
                initialize.get("capabilities"), dict
            ):
                raise LanguageServiceProtocolError(
                    "Lean 4", "Lean 4 语言服务初始化响应无效"
                )
            try:
                provider = initialize["capabilities"][
                    "semanticTokensProvider"
                ]
                if not isinstance(provider, dict) or not provider.get("full"):
                    raise TypeError
                legend = provider["legend"]
                raw_token_types = legend["tokenTypes"]
                raw_token_modifiers = legend["tokenModifiers"]
                if not isinstance(raw_token_types, list) or not isinstance(
                    raw_token_modifiers, list
                ):
                    raise TypeError
                token_types = list(raw_token_types)
                token_modifiers = list(raw_token_modifiers)
            except (KeyError, TypeError) as exc:
                raise LanguageServiceProtocolError(
                    "Lean 4", "Lean 4 语言服务未提供语义高亮"
                ) from exc
            if (
                not token_types
                or not all(isinstance(item, str) for item in token_types)
                or not all(isinstance(item, str) for item in token_modifiers)
            ):
                raise LanguageServiceProtocolError(
                    "Lean 4", "Lean 4 语义高亮图例无效"
                )
            self._semantic_legend = {
                "tokenTypes": token_types,
                "tokenModifiers": token_modifiers,
            }
            self._notify_locked("initialized", {})
        except BaseException:
            self._reset_locked()
            raise

    def check(
        self,
        source: str,
        position: dict[str, int],
    ) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise LanguageServiceBusyError(
                "Lean 4", "该 Lean 4 文档正在解析"
            )
        try:
            return self._check_locked(source, position)
        finally:
            self._lock.release()

    def _check_locked(
        self,
        source: str,
        position: dict[str, int],
    ) -> dict[str, Any]:
        encoded = source.encode("utf-8")
        if len(encoded) > LEAN_SOURCE_MAX_BYTES:
            raise ValueError("Lean 4 源码超过实时解析大小限制")
        digest = hashlib.sha256(encoded).hexdigest()
        self.last_used = time.monotonic()
        try:
            self._start_locked()
            if not self._document_open:
                self._document_version = 1
                self._source_digest = digest
                self._diagnostics = []
                self._processing = []
                self._semantic_tokens = None
                self._notify_locked(
                    "textDocument/didOpen",
                    {
                        "textDocument": {
                            "uri": _DOCUMENT_URI,
                            "languageId": "lean4",
                            "version": self._document_version,
                            "text": source,
                        },
                        "dependencyBuildMode": "never",
                    },
                )
                self._document_open = True
            elif digest != self._source_digest:
                self._document_version += 1
                self._source_digest = digest
                self._diagnostics = []
                self._processing = []
                self._semantic_tokens = None
                self._notify_locked(
                    "textDocument/didChange",
                    {
                        "textDocument": {
                            "uri": _DOCUMENT_URI,
                            "version": self._document_version,
                        },
                        "contentChanges": [{"text": source}],
                    },
                )
            self._request_locked(
                "textDocument/waitForDiagnostics",
                {
                    "uri": _DOCUMENT_URI,
                    "version": self._document_version,
                },
            )
            if self._semantic_tokens is None:
                semantic_response = self._request_locked(
                    "textDocument/semanticTokens/full",
                    {"textDocument": {"uri": _DOCUMENT_URI}},
                )
                if semantic_response is None:
                    semantic_data: list[int] = []
                elif isinstance(semantic_response, dict) and isinstance(
                    semantic_response.get("data"), list
                ):
                    semantic_data = semantic_response["data"]
                else:
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 语义高亮响应格式无效"
                    )
                if len(semantic_data) % 5 != 0 or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and 0 <= value <= 2_147_483_647
                    for value in semantic_data
                ):
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 语义高亮数据无效"
                    )
                assert self._semantic_legend is not None
                token_type_count = len(
                    self._semantic_legend["tokenTypes"]
                )
                if any(
                    semantic_data[index + 3] >= token_type_count
                    for index in range(0, len(semantic_data), 5)
                ):
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 语义高亮类型无效"
                    )
                modifier_count = len(
                    self._semantic_legend["tokenModifiers"]
                )
                if any(
                    semantic_data[index + 4] >= 1 << modifier_count
                    for index in range(0, len(semantic_data), 5)
                ):
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 语义高亮修饰符无效"
                    )
                self._semantic_tokens = {
                    "legend": {
                        "tokenTypes": list(
                            self._semantic_legend["tokenTypes"]
                        ),
                        "tokenModifiers": list(
                            self._semantic_legend["tokenModifiers"]
                        ),
                    },
                    "data": list(semantic_data),
                    "result_id": (
                        f"{self._document_version}:"
                        f"{self._source_digest[:12]}"
                    ),
                }
            plain_goal = self._request_locked(
                "$/lean/plainGoal",
                {
                    "textDocument": {"uri": _DOCUMENT_URI},
                    "position": position,
                },
            )
            goals: list[str] = []
            rendered = ""
            if plain_goal is not None:
                if not isinstance(plain_goal, dict):
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 goal 响应格式无效"
                    )
                raw_goals = plain_goal.get("goals", [])
                if not isinstance(raw_goals, list) or not all(
                    isinstance(goal, str) for goal in raw_goals
                ):
                    raise LanguageServiceProtocolError(
                        "Lean 4", "Lean 4 goal 列表格式无效"
                    )
                goals = list(raw_goals)
                rendered = str(plain_goal.get("rendered") or "")
            return {
                "goals": goals,
                "goal_rendered": rendered,
                "diagnostics": list(self._diagnostics),
                "processing": list(self._processing),
                "document_version": self._document_version,
                "semantic_tokens": {
                    "legend": {
                        "tokenTypes": list(
                            self._semantic_tokens["legend"]["tokenTypes"]
                        ),
                        "tokenModifiers": list(
                            self._semantic_tokens["legend"][
                                "tokenModifiers"
                            ]
                        ),
                    },
                    "data": list(self._semantic_tokens["data"]),
                    "result_id": self._semantic_tokens["result_id"],
                },
            }
        except (LanguageServiceProtocolError, LanguageServiceTimeoutError):
            self._reset_locked()
            raise

    def _handle_notification(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        params = message.get("params")
        if not isinstance(params, dict):
            return
        if method == "textDocument/publishDiagnostics":
            if params.get("uri") != _DOCUMENT_URI:
                return
            diagnostics = params.get("diagnostics")
            if isinstance(diagnostics, list) and all(
                isinstance(item, dict) for item in diagnostics
            ):
                self._diagnostics = list(diagnostics)
        elif method == "$/lean/fileProgress":
            text_document = params.get("textDocument")
            if not isinstance(text_document, dict) or text_document.get(
                "uri"
            ) != _DOCUMENT_URI:
                return
            processing = params.get("processing")
            if isinstance(processing, list) and all(
                isinstance(item, dict) for item in processing
            ):
                self._processing = list(processing)

    def _write_message(
        self,
        payload: dict[str, Any],
        *,
        process: subprocess.Popen[bytes] | None = None,
    ) -> None:
        target = process or self._process
        if target is None or target.stdin is None or target.poll() is not None:
            raise LanguageServiceUnavailableError(
                "Lean 4", "Lean 4 语言服务进程未运行"
            )
        body = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        try:
            with self._write_lock:
                target.stdin.write(frame)
                target.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise LanguageServiceUnavailableError(
                "Lean 4", "Lean 4 语言服务通信已中断"
            ) from exc

    def _request_locked(self, method: str, params: dict[str, Any]) -> Any:
        request_id = self._next_request_id
        self._next_request_id += 1
        pending = _PendingResponse()
        with self._pending_lock:
            self._pending[request_id] = pending
        try:
            self._write_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            )
            if not pending.event.wait(self.request_timeout):
                raise LanguageServiceTimeoutError(
                    "Lean 4", f"Lean 4 请求超时: {method}"
                )
            if pending.error is not None:
                raise pending.error
            return pending.result
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)

    def _notify_locked(self, method: str, params: dict[str, Any]) -> None:
        self._write_message(
            {"jsonrpc": "2.0", "method": method, "params": params}
        )

    @staticmethod
    def _read_message(stream) -> dict[str, Any] | None:
        headers: dict[str, str] = {}
        while True:
            line = stream.readline()
            if not line:
                return None
            if line in {b"\r\n", b"\n"}:
                break
            try:
                name, value = line.decode("ascii").split(":", 1)
            except (UnicodeDecodeError, ValueError) as exc:
                raise LanguageServiceProtocolError(
                    "Lean 4", "Lean 4 JSON-RPC 响应头无效"
                ) from exc
            headers[name.strip().lower()] = value.strip()
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError) as exc:
            raise LanguageServiceProtocolError(
                "Lean 4", "Lean 4 响应缺少 Content-Length"
            ) from exc
        if length < 0 or length > LANGUAGE_RESPONSE_MAX_BYTES:
            raise LanguageServiceProtocolError(
                "Lean 4", "Lean 4 响应体大小无效"
            )
        body_chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = stream.read(remaining)
            if not chunk:
                break
            body_chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(body_chunks)
        if remaining:
            raise LanguageServiceProtocolError(
                "Lean 4", "Lean 4 响应体被截断"
            )
        try:
            message = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LanguageServiceProtocolError(
                "Lean 4", "Lean 4 返回了无效 JSON"
            ) from exc
        if not isinstance(message, dict):
            raise LanguageServiceProtocolError(
                "Lean 4", "Lean 4 JSON-RPC 响应不是对象"
            )
        return message

    @staticmethod
    def _server_request_result(message: dict[str, Any]) -> Any:
        if message.get("method") == "workspace/configuration":
            items = message.get("params", {}).get("items", [])
            return [None for _ in items]
        if message.get("method") == "workspace/workspaceFolders":
            return [
                {"uri": "file:///workspace", "name": "NumericalOJ Lean"}
            ]
        return None

    def _reader_loop(self, process: subprocess.Popen[bytes]) -> None:
        failure: BaseException = LanguageServiceUnavailableError(
            "Lean 4", "Lean 4 语言服务进程已退出"
        )
        try:
            assert process.stdout is not None
            while True:
                message = self._read_message(process.stdout)
                if message is None:
                    break
                if "id" in message and (
                    "result" in message or "error" in message
                ):
                    with self._pending_lock:
                        pending = self._pending.get(message["id"])
                    if pending is None:
                        continue
                    if "error" in message:
                        pending.error = LanguageServiceProtocolError(
                            "Lean 4",
                            f"Lean 4 请求失败: {message['error']!r}",
                        )
                    else:
                        pending.result = message.get("result")
                    pending.event.set()
                    continue
                if "id" not in message and "method" in message:
                    if process is self._process:
                        self._handle_notification(message)
                    continue
                if "id" in message and "method" in message:
                    self._write_message(
                        {
                            "jsonrpc": "2.0",
                            "id": message["id"],
                            "result": self._server_request_result(message),
                        },
                        process=process,
                    )
        except BaseException as exc:
            failure = exc
        finally:
            if process is self._process:
                with self._pending_lock:
                    pending_responses = list(self._pending.values())
                for pending in pending_responses:
                    pending.error = failure
                    pending.event.set()

    def close(self) -> None:
        with self._lock:
            self._reset_locked()

    def _reset_locked(self) -> None:
        process = self._process
        reader_thread = self._reader_thread
        self._process = None
        self._reader_thread = None
        self._document_open = False
        self._document_version = 0
        self._source_digest = ""
        self._diagnostics = []
        self._processing = []
        self._semantic_legend = None
        self._semantic_tokens = None
        if process is not None:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
        if (
            reader_thread is not None
            and reader_thread is not threading.current_thread()
        ):
            reader_thread.join(timeout=1)


class LeanInteractiveService:
    """Maintain a small LRU of per-user/per-problem Lean sessions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, LeanLanguageServerSession] = {}

    def check(
        self,
        session_key: str,
        source: str,
        position: dict[str, int],
    ) -> dict[str, Any]:
        expired: list[LeanLanguageServerSession] = []
        with self._lock:
            now = time.monotonic()
            idle_seconds = float(
                getattr(_cfg, "LEAN4_INTERACTIVE_IDLE_SECONDS", 600)
            )
            for key, session in list(self._sessions.items()):
                if now - session.last_used >= idle_seconds:
                    expired.append(self._sessions.pop(key))
            session = self._sessions.get(session_key)
            if session is None:
                max_sessions = int(
                    getattr(_cfg, "LEAN4_INTERACTIVE_MAX_SESSIONS", 8)
                )
                if len(self._sessions) >= max_sessions:
                    oldest_key = min(
                        self._sessions,
                        key=lambda key: self._sessions[key].last_used,
                    )
                    expired.append(self._sessions.pop(oldest_key))
                session = LeanLanguageServerSession(session_key)
                self._sessions[session_key] = session
            session.last_used = now
        for old_session in expired:
            old_session.close()
        return session.check(source, position)

    def close(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()


_service = LeanInteractiveService()


def get_lean_interactive_service() -> LeanInteractiveService:
    return _service


atexit.register(_service.close)
