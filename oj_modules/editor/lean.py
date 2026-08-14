"""Lean 4 interactive proof service backed by isolated Docker containers."""

from __future__ import annotations

import atexit
from dataclasses import dataclass, field
import hashlib
import io
import json
import os
import subprocess
import tarfile
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


LEAN_SOURCE_MAX_BYTES = 8 * 1024 * 1024
_WORKSPACE_URI = "file:///workspace"
_DEFAULT_DOCUMENT_PATH = "Submission.lean"


def _document_uri(path: str) -> str:
    return f"{_WORKSPACE_URI}/{path}"


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
        self._open_documents: set[str] = set()
        self._document_versions: dict[str, int] = {}
        self._document_digests: dict[str, str] = {}
        self._workspace_digests: dict[str, str] = {}
        self._compiled_digests: dict[str, str] = {}
        self._diagnostics: dict[str, list[dict[str, Any]]] = {}
        self._processing: dict[str, list[dict[str, Any]]] = {}
        self._semantic_legend: dict[str, list[str]] | None = None
        self._semantic_tokens: dict[str, dict[str, Any]] = {}
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
            "/workspace:rw,nosuid,nodev,noexec,size=128m,uid=65532,gid=65532",
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
                    "rootUri": _WORKSPACE_URI,
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
                            "uri": _WORKSPACE_URI,
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
        sources: dict[str, str] | str,
        active_file: str | dict[str, int],
        position: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        if isinstance(sources, str):
            position = active_file if isinstance(active_file, dict) else None
            active_file = _DEFAULT_DOCUMENT_PATH
            sources = {_DEFAULT_DOCUMENT_PATH: sources}
        if not isinstance(active_file, str) or position is None:
            raise ValueError("Lean 4 当前文件或光标位置无效")
        if not self._lock.acquire(blocking=False):
            raise LanguageServiceBusyError(
                "Lean 4", "该 Lean 4 文档正在解析"
            )
        try:
            return self._check_locked(sources, active_file, position)
        finally:
            self._lock.release()

    def _check_locked(
        self,
        sources: dict[str, str],
        active_file: str,
        position: dict[str, int],
    ) -> dict[str, Any]:
        if not sources or active_file not in sources:
            raise ValueError("Lean 4 当前文件无效")
        if not all(
            isinstance(path, str)
            and path.endswith(".lean")
            and isinstance(source, str)
            for path, source in sources.items()
        ):
            raise ValueError("Lean 4 工作区源码无效")
        total_size = sum(
            len(source.encode("utf-8")) for source in sources.values()
        )
        if total_size > LEAN_SOURCE_MAX_BYTES:
            raise ValueError("Lean 4 源码超过实时解析大小限制")
        self.last_used = time.monotonic()
        try:
            self._start_locked()
            self._sync_workspace_locked(sources)
            dependencies_changed = self._compile_dependencies_locked(
                sources, active_file
            )
            if dependencies_changed:
                self._close_documents_locked()

            for path, source in sources.items():
                uri = _document_uri(path)
                digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
                if path not in self._open_documents:
                    version = self._document_versions.get(path, 0) + 1
                    self._document_versions[path] = version
                    self._document_digests[path] = digest
                    self._diagnostics[uri] = []
                    self._processing[uri] = []
                    self._semantic_tokens.pop(path, None)
                    self._notify_locked(
                        "textDocument/didOpen",
                        {
                            "textDocument": {
                                "uri": uri,
                                "languageId": "lean4",
                                "version": version,
                                "text": source,
                            },
                            "dependencyBuildMode": "never",
                        },
                    )
                    self._open_documents.add(path)
                elif digest != self._document_digests.get(path):
                    version = self._document_versions[path] + 1
                    self._document_versions[path] = version
                    self._document_digests[path] = digest
                    self._diagnostics[uri] = []
                    self._processing[uri] = []
                    self._semantic_tokens.pop(path, None)
                    self._notify_locked(
                        "textDocument/didChange",
                        {
                            "textDocument": {
                                "uri": uri,
                                "version": version,
                            },
                            "contentChanges": [{"text": source}],
                        },
                    )

            active_uri = _document_uri(active_file)
            active_version = self._document_versions[active_file]
            active_digest = self._document_digests[active_file]
            self._request_locked(
                "textDocument/waitForDiagnostics",
                {"uri": active_uri, "version": active_version},
            )
            if active_file not in self._semantic_tokens:
                semantic_response = self._request_locked(
                    "textDocument/semanticTokens/full",
                    {"textDocument": {"uri": active_uri}},
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
                token_type_count = len(self._semantic_legend["tokenTypes"])
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
                self._semantic_tokens[active_file] = {
                    "legend": {
                        "tokenTypes": list(
                            self._semantic_legend["tokenTypes"]
                        ),
                        "tokenModifiers": list(
                            self._semantic_legend["tokenModifiers"]
                        ),
                    },
                    "data": list(semantic_data),
                    "result_id": f"{active_version}:{active_digest[:12]}",
                }
            plain_goal = self._request_locked(
                "$/lean/plainGoal",
                {
                    "textDocument": {"uri": active_uri},
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

            diagnostics = []
            processing = []
            for path in sources:
                uri = _document_uri(path)
                diagnostics.extend(
                    {**item, "path": path, "uri": uri}
                    for item in self._diagnostics.get(uri, [])
                )
                processing.extend(
                    {**item, "path": path, "uri": uri}
                    for item in self._processing.get(uri, [])
                )
            semantic_tokens = self._semantic_tokens[active_file]
            return {
                "goals": goals,
                "goal_rendered": rendered,
                "diagnostics": diagnostics,
                "processing": processing,
                "document_version": active_version,
                "semantic_tokens": {
                    "legend": {
                        "tokenTypes": list(
                            semantic_tokens["legend"]["tokenTypes"]
                        ),
                        "tokenModifiers": list(
                            semantic_tokens["legend"]["tokenModifiers"]
                        ),
                    },
                    "data": list(semantic_tokens["data"]),
                    "result_id": semantic_tokens["result_id"],
                },
            }
        except (
            LanguageServiceProtocolError,
            LanguageServiceTimeoutError,
            LanguageServiceUnavailableError,
        ):
            self._reset_locked()
            raise

    def _sync_workspace_locked(self, sources: dict[str, str]) -> set[str]:
        digests = {
            path: hashlib.sha256(source.encode("utf-8")).hexdigest()
            for path, source in sources.items()
        }
        changed = {
            path
            for path, digest in digests.items()
            if self._workspace_digests.get(path) != digest
        }
        if self._process is not None and changed:
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as tar:
                directories = sorted(
                    {
                        directory
                        for path in changed
                        for directory in self._parent_directories(path)
                    },
                    key=lambda item: (item.count("/"), item),
                )
                for directory in directories:
                    info = tarfile.TarInfo(directory)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o700
                    tar.addfile(info)
                for path in sorted(changed):
                    source = sources[path]
                    encoded = source.encode("utf-8")
                    info = tarfile.TarInfo(path)
                    info.size = len(encoded)
                    info.mode = 0o600
                    tar.addfile(info, io.BytesIO(encoded))
            self._run_docker_exec(
                ["tar", "-xf", "-", "-C", "/workspace"],
                input_bytes=archive.getvalue(),
            )
            self._run_docker_exec(
                [
                    "rm",
                    "-f",
                    *[
                        f"/workspace/{path[:-5]}.olean"
                        for path in sorted(changed)
                    ],
                ]
            )
        for path in changed:
            self._compiled_digests.pop(path, None)
        self._workspace_digests = digests
        return changed

    @staticmethod
    def _parent_directories(path: str) -> list[str]:
        parts = path.split("/")[:-1]
        return ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]

    def _run_docker_exec(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            result = subprocess.run(
                ["docker", "exec", "-i", self._container_name, *arguments],
                input=input_bytes,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.request_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LanguageServiceTimeoutError(
                "Lean 4", "Lean 4 工作区准备超时"
            ) from exc
        except OSError as exc:
            raise LanguageServiceUnavailableError(
                "Lean 4", "无法同步 Lean 4 工作区"
            ) from exc
        if check and result.returncode != 0:
            raise LanguageServiceUnavailableError(
                "Lean 4", "无法同步 Lean 4 工作区"
            )
        return result

    def _compile_dependencies_locked(
        self, sources: dict[str, str], active_file: str
    ) -> bool:
        if self._process is None:
            return False
        cumulative = hashlib.sha256()
        rebuilt = False
        for path in sources:
            cumulative.update(path.encode("ascii"))
            cumulative.update(b"\0")
            cumulative.update(self._workspace_digests[path].encode("ascii"))
            if path == active_file:
                break
            expected = cumulative.hexdigest()
            if self._compiled_digests.get(path) == expected:
                continue
            source_path = f"/workspace/{path}"
            output_path = f"/workspace/{path[:-5]}.olean"
            result = self._run_docker_exec(
                [
                    "sh",
                    "-c",
                    'mathlib_path="$(cat /opt/numoj-lean-path)"; '
                    'export LEAN_PATH="$mathlib_path:/workspace"; '
                    'rm -f "$1"; lean -o "$1" "$2"',
                    "sh",
                    output_path,
                    source_path,
                ],
                check=False,
            )
            rebuilt = True
            if result.returncode == 0:
                self._compiled_digests[path] = expected
            else:
                self._compiled_digests.pop(path, None)
        return rebuilt

    def _close_documents_locked(self) -> None:
        for path in sorted(self._open_documents):
            self._notify_locked(
                "textDocument/didClose",
                {"textDocument": {"uri": _document_uri(path)}},
            )
        self._open_documents.clear()
        self._document_digests.clear()
        self._diagnostics.clear()
        self._processing.clear()
        self._semantic_tokens.clear()

    def _handle_notification(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        params = message.get("params")
        if not isinstance(params, dict):
            return
        if method == "textDocument/publishDiagnostics":
            uri = params.get("uri")
            if not isinstance(uri, str) or uri not in self._diagnostics:
                return
            diagnostics = params.get("diagnostics")
            if isinstance(diagnostics, list) and all(
                isinstance(item, dict) for item in diagnostics
            ):
                self._diagnostics[uri] = list(diagnostics)
        elif method == "$/lean/fileProgress":
            text_document = params.get("textDocument")
            if not isinstance(text_document, dict):
                return
            uri = text_document.get("uri")
            if not isinstance(uri, str) or uri not in self._processing:
                return
            processing = params.get("processing")
            if isinstance(processing, list) and all(
                isinstance(item, dict) for item in processing
            ):
                self._processing[uri] = list(processing)

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
                {"uri": _WORKSPACE_URI, "name": "NumericalOJ Lean"}
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
        self._open_documents.clear()
        self._document_versions.clear()
        self._document_digests.clear()
        self._workspace_digests.clear()
        self._compiled_digests.clear()
        self._diagnostics.clear()
        self._processing.clear()
        self._semantic_legend = None
        self._semantic_tokens.clear()
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
        sources: dict[str, str] | str,
        active_file: str | dict[str, int],
        position: dict[str, int] | None = None,
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
        return session.check(sources, active_file, position)

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
