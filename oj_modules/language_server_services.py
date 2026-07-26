"""Reusable persistent stdio language-server bridge for editor highlighting."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any


LANGUAGE_SOURCE_MAX_BYTES = 4 * 1024 * 1024
LANGUAGE_RESPONSE_MAX_BYTES = 64 * 1024 * 1024
LANGUAGE_REQUEST_TIMEOUT_SECONDS = 60.0
LANGUAGE_SERVICE_POOL_SIZE = 10
LANGUAGE_DOCUMENT_TTL_SECONDS = 10 * 60
LANGUAGE_MAX_OPEN_DOCUMENTS = 128
_WORKSPACE_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="numericaloj-language-services-"
)
_WORKSPACE_ROOT = Path(_WORKSPACE_DIRECTORY.name)


class LanguageServiceError(RuntimeError):
    """Base class for editor language-service failures."""

    def __init__(self, service_name: str, message: str) -> None:
        self.service_name = service_name
        super().__init__(message)


class LanguageServiceUnavailableError(LanguageServiceError):
    """The configured language-server executable is unavailable."""


class LanguageServiceTimeoutError(LanguageServiceError):
    """A language server missed the interactive response deadline."""


class LanguageServiceBusyError(LanguageServiceError):
    """The single persistent server is already handling a semantic request."""


class LanguageServiceProtocolError(LanguageServiceError):
    """A language server returned invalid JSON-RPC or semantic tokens."""


def find_language_service_executable(command: str, service_name: str) -> str:
    """Resolve a language runtime exactly as the production bridge does."""
    venv_candidate = Path(sys.executable).with_name(command)
    if venv_candidate.is_file() and os.access(venv_candidate, os.X_OK):
        return str(venv_candidate)
    executable = shutil.which(command)
    if executable is None:
        raise LanguageServiceUnavailableError(
            service_name,
            f"服务器尚未安装 {service_name}",
        )
    return executable


def _sandbox_read_paths(
    executable: str,
    extra_paths: tuple[Path, ...],
) -> tuple[Path, ...]:
    """Return the minimal runtime trees visible inside an LSP sandbox."""
    candidates = [
        Path(sys.prefix).resolve(),
        Path(sys.base_prefix).resolve(),
        *extra_paths,
    ]
    base_executable = Path(sys._base_executable).resolve()
    for runtime_root in (Path("/opt/homebrew"), Path("/usr/local")):
        if base_executable.is_relative_to(runtime_root):
            candidates.append(runtime_root)
    executable_path = Path(executable).resolve()
    if not any(
        executable_path == path or executable_path.is_relative_to(path)
        for path in candidates
    ) and not executable_path.is_relative_to(Path("/usr")):
        candidates.append(executable_path)
    unique: list[Path] = []
    for path in candidates:
        resolved = path.resolve()
        if resolved.exists() and resolved not in unique:
            unique.append(resolved)
    return tuple(unique)


def _macos_sandbox_profile(
    workspace: Path,
    read_paths: tuple[Path, ...],
) -> str:
    """Build a Seatbelt profile that exposes only runtimes and workspace."""
    system_paths = (
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/System"),
        Path("/Library"),
        Path("/private/var/db/dyld"),
        Path("/private/var/select"),
        Path("/var/select"),
        Path("/dev"),
    )
    readable = tuple(
        path
        for path in (*system_paths, *read_paths, workspace)
        if path.exists()
    )

    def allow_filters(
        subtree_paths: tuple[Path, ...],
        exact_paths: tuple[Path, ...] = (),
        *,
        include_ancestors: bool = False,
    ) -> str:
        subtrees = {str(path) for path in subtree_paths}
        literals = {str(path) for path in exact_paths}
        for path in subtree_paths:
            if include_ancestors:
                literals.update(
                    str(parent)
                    for parent in path.parents
                    if parent != Path("/") and parent not in subtree_paths
                )
        filters = [
            *(f"    (subpath {json.dumps(path)})" for path in sorted(subtrees)),
            *(f"    (literal {json.dumps(path)})" for path in sorted(literals)),
        ]
        return "\n".join(filters)

    read_filters = allow_filters(
        readable,
        (Path("/"),),
        include_ancestors=True,
    )
    write_filters = allow_filters(
        (workspace, Path("/dev/fd")),
        (Path("/dev/null"),),
    )
    return """(version 1)
(allow default)
(deny network*)
(deny file-read* file-test-existence
  (require-all
    (vnode-type REGULAR-FILE DIRECTORY SYMLINK)
    (require-not (require-any
%s))))
(deny file-write*
  (require-all
    (vnode-type REGULAR-FILE DIRECTORY SYMLINK)
    (require-not (require-any
%s))))
""" % (
        read_filters,
        write_filters,
    )


def sandbox_language_server_command(
    executable: str,
    arguments: tuple[str, ...],
    workspace: Path,
    *,
    extra_read_paths: tuple[Path, ...] = (),
) -> list[str]:
    """Wrap an LSP command in the platform filesystem/network sandbox."""
    read_paths = _sandbox_read_paths(executable, extra_read_paths)
    system = platform.system()
    if system == "Darwin":
        sandbox_exec = shutil.which("sandbox-exec")
        if sandbox_exec is None:
            raise LanguageServiceUnavailableError(
                "语言服务沙箱",
                "macOS 缺少 sandbox-exec，拒绝解析不可信代码",
            )
        return [
            sandbox_exec,
            "-p",
            _macos_sandbox_profile(workspace, read_paths),
            executable,
            *arguments,
        ]
    if system == "Linux":
        bubblewrap = shutil.which("bwrap")
        if bubblewrap is None:
            raise LanguageServiceUnavailableError(
                "语言服务沙箱",
                "服务器尚未安装 Bubblewrap，拒绝解析不可信代码",
            )
        command = [
            bubblewrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/etc",
            "--ro-bind-try",
            "/etc/ld.so.cache",
            "/etc/ld.so.cache",
            "--ro-bind-try",
            "/etc/localtime",
            "/etc/localtime",
        ]
        for raw_path in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            path = Path(raw_path)
            if path.is_symlink():
                command.extend(("--symlink", os.readlink(path), raw_path))
            elif path.exists():
                command.extend(("--ro-bind", raw_path, raw_path))
        for path in read_paths:
            if not path.is_relative_to(Path("/usr")):
                command.extend(("--ro-bind", str(path), str(path)))
        command.extend(
            (
                "--bind",
                str(workspace),
                str(workspace),
                "--chdir",
                str(workspace),
                executable,
                *arguments,
            )
        )
        return command
    raise LanguageServiceUnavailableError(
        "语言服务沙箱",
        f"不支持在 {system or '未知平台'} 上解析不可信代码",
    )


@dataclass
class _PendingResponse:
    event: threading.Event = field(default_factory=threading.Event)
    result: Any = None
    error: BaseException | None = None


@dataclass
class _DocumentState:
    uri: str
    version: int
    source_digest: str
    last_used: float


class SemanticLanguageServerService:
    """Own one lazy LSP process and a bounded set of in-memory documents."""

    def __init__(
        self,
        *,
        service_name: str,
        language_id: str,
        file_suffix: str,
        command: str,
        command_args: tuple[str, ...] = (),
        sandbox_read_paths: tuple[Path, ...] = (),
        request_timeout: float = LANGUAGE_REQUEST_TIMEOUT_SECONDS,
        workspace_key: str | None = None,
        clock=time.monotonic,
    ) -> None:
        self.service_name = service_name
        self.language = language_id
        self.file_suffix = file_suffix
        self.command = command
        self.command_args = command_args
        self.sandbox_read_paths = sandbox_read_paths
        self.request_timeout = request_timeout
        self.workspace_key = workspace_key or service_name.lower()
        self._clock = clock
        self._session_lock = threading.RLock()
        self._semantic_request_gate = threading.Lock()
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._pending: dict[int, _PendingResponse] = {}
        self._documents: dict[str, _DocumentState] = {}
        self._next_request_id = 1
        self._legend: dict[str, list[str]] | None = None

    def _find_executable(self) -> str:
        return find_language_service_executable(
            self.command,
            self.service_name,
        )

    def _command_line(self) -> list[str]:
        executable = self._find_executable()
        return sandbox_language_server_command(
            executable,
            self.command_args,
            self._workspace(),
            extra_read_paths=self.sandbox_read_paths,
        )

    def _initialization_options(self) -> dict[str, Any]:
        return {}

    def _prepare_source(self, source: str) -> str:
        return source

    def _workspace(self) -> Path:
        return (_WORKSPACE_ROOT / self.workspace_key).resolve()

    def _process_environment(self, workspace: Path) -> dict[str, str]:
        return {
            "HOME": str(workspace),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TMPDIR": str(workspace),
        }

    def _start_locked(self) -> None:
        if (
            self._process is not None
            and self._process.poll() is None
            and self._reader_thread is not None
            and self._reader_thread.is_alive()
        ):
            return
        self._reset_locked()
        workspace = self._workspace()
        try:
            workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
            process = subprocess.Popen(
                self._command_line(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                cwd=workspace,
                env=self._process_environment(workspace),
                close_fds=True,
                start_new_session=True,
            )
        except OSError as exc:
            raise LanguageServiceUnavailableError(
                self.service_name,
                f"无法启动 {self.service_name}",
            ) from exc
        if process.stdin is None or process.stdout is None:
            process.terminate()
            raise LanguageServiceUnavailableError(
                self.service_name,
                f"{self.service_name} 标准输入输出不可用",
            )
        self._process = process
        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            args=(process,),
            name=f"numoj-{self.service_name.lower()}-{self.language}",
            daemon=True,
        )
        self._reader_thread.start()
        try:
            self._initialize_locked()
        except BaseException:
            self._reset_locked()
            raise

    def _initialize_locked(self) -> None:
        workspace = self._workspace()
        initialize = self._request_locked(
            "initialize",
            {
                "processId": os.getpid(),
                "clientInfo": {"name": "NumericalOJ", "version": "1"},
                "rootUri": workspace.as_uri(),
                "capabilities": {
                    "workspace": {"configuration": False},
                    "textDocument": {
                        "semanticTokens": {
                            "dynamicRegistration": False,
                            "requests": {"full": True},
                            "tokenTypes": [],
                            "tokenModifiers": [],
                            "formats": ["relative"],
                        }
                    },
                },
                "initializationOptions": self._initialization_options(),
                "workspaceFolders": None,
            },
        )
        try:
            provider = initialize["capabilities"]["semanticTokensProvider"]
            legend = provider["legend"]
            token_types = list(legend["tokenTypes"])
            token_modifiers = list(legend["tokenModifiers"])
        except (KeyError, TypeError) as exc:
            raise LanguageServiceProtocolError(
                self.service_name,
                f"{self.service_name} 未提供 semantic tokens",
            ) from exc
        if not token_types:
            raise LanguageServiceProtocolError(
                self.service_name,
                f"{self.service_name} semantic token 类型为空",
            )
        self._legend = {
            "tokenTypes": token_types,
            "tokenModifiers": token_modifiers,
        }
        self._notify_locked("initialized", {})

    def _write_message(
        self,
        payload: dict[str, Any],
        *,
        process: subprocess.Popen[bytes] | None = None,
    ) -> None:
        target = process or self._process
        if target is None or target.stdin is None or target.poll() is not None:
            raise LanguageServiceUnavailableError(
                self.service_name,
                f"{self.service_name} 进程未运行",
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
                self.service_name,
                f"{self.service_name} 通信已中断",
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
                    self.service_name,
                    f"{self.service_name} 请求超时: {method}",
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
                    "语言服务", "语言服务 JSON-RPC 响应头无效"
                ) from exc
            headers[name.strip().lower()] = value.strip()
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError) as exc:
            raise LanguageServiceProtocolError(
                "语言服务", "语言服务响应缺少 Content-Length"
            ) from exc
        if length < 0 or length > LANGUAGE_RESPONSE_MAX_BYTES:
            raise LanguageServiceProtocolError(
                "语言服务", "语言服务响应体大小无效"
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
                "语言服务", "语言服务响应体被截断"
            )
        try:
            message = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LanguageServiceProtocolError(
                "语言服务", "语言服务返回了无效 JSON"
            ) from exc
        if not isinstance(message, dict):
            raise LanguageServiceProtocolError(
                "语言服务", "语言服务 JSON-RPC 响应不是对象"
            )
        return message

    @staticmethod
    def _server_request_result(message: dict[str, Any]) -> Any:
        if message.get("method") == "workspace/configuration":
            items = message.get("params", {}).get("items", [])
            return [None for _ in items]
        if message.get("method") == "workspace/workspaceFolders":
            return []
        return None

    def _reader_loop(self, process: subprocess.Popen[bytes]) -> None:
        failure: BaseException = LanguageServiceUnavailableError(
            self.service_name,
            f"{self.service_name} 进程已退出",
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
                            self.service_name,
                            f"{self.service_name} 请求失败: {message['error']!r}",
                        )
                    else:
                        pending.result = message.get("result")
                    pending.event.set()
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

    def _reset_locked(self) -> None:
        process = self._process
        reader_thread = self._reader_thread
        self._process = None
        self._reader_thread = None
        self._legend = None
        self._documents.clear()
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        if (
            reader_thread is not None
            and reader_thread is not threading.current_thread()
        ):
            reader_thread.join(timeout=1)

    def _evict_documents_locked(self, now: float) -> None:
        expired = [
            key
            for key, state in self._documents.items()
            if now - state.last_used >= LANGUAGE_DOCUMENT_TTL_SECONDS
        ]
        overflow = max(
            0,
            len(self._documents) - LANGUAGE_MAX_OPEN_DOCUMENTS + 1,
        )
        if overflow:
            remaining = sorted(
                (
                    (state.last_used, key)
                    for key, state in self._documents.items()
                    if key not in expired
                )
            )
            expired.extend(key for _, key in remaining[:overflow])
        for key in dict.fromkeys(expired):
            state = self._documents.pop(key, None)
            if state is not None:
                self._notify_locked(
                    "textDocument/didClose",
                    {"textDocument": {"uri": state.uri}},
                )

    def legend(self) -> dict[str, list[str]]:
        with self._session_lock:
            self._start_locked()
            assert self._legend is not None
            return {
                "tokenTypes": list(self._legend["tokenTypes"]),
                "tokenModifiers": list(self._legend["tokenModifiers"]),
            }

    def semantic_tokens(self, document_key: str, source: str) -> dict[str, Any]:
        if not self._semantic_request_gate.acquire(blocking=False):
            raise LanguageServiceBusyError(
                self.service_name,
                f"{self.service_name} 正在处理其他实时解析请求",
            )
        try:
            return self._semantic_tokens_serial(document_key, source)
        finally:
            self._semantic_request_gate.release()

    def _semantic_tokens_serial(
        self,
        document_key: str,
        source: str,
        *,
        document_path: Path | None = None,
    ) -> dict[str, Any]:
        source = self._prepare_source(source)
        encoded = source.encode("utf-8")
        if len(encoded) > LANGUAGE_SOURCE_MAX_BYTES:
            raise ValueError("代码超过实时解析大小限制")
        digest = hashlib.sha256(encoded).hexdigest()
        with self._session_lock:
            try:
                self._start_locked()
                now = self._clock()
                self._evict_documents_locked(now)
                state = self._documents.get(document_key)
                if state is None:
                    if document_path is None:
                        uri_digest = hashlib.sha256(
                            document_key.encode("utf-8")
                        ).hexdigest()
                        resolved_document_path = (
                            self._workspace()
                            / f"{uri_digest}{self.file_suffix}"
                        ).resolve()
                    else:
                        resolved_document_path = document_path.resolve()
                        if not resolved_document_path.is_relative_to(
                            self._workspace()
                        ):
                            raise LanguageServiceProtocolError(
                                self.service_name,
                                "语言服务文档路径越过隔离工作区",
                            )
                    uri = resolved_document_path.as_uri()
                    state = _DocumentState(
                        uri=uri,
                        version=1,
                        source_digest=digest,
                        last_used=now,
                    )
                    self._documents[document_key] = state
                    self._notify_locked(
                        "textDocument/didOpen",
                        {
                            "textDocument": {
                                "uri": uri,
                                "languageId": self.language,
                                "version": state.version,
                                "text": source,
                            }
                        },
                    )
                else:
                    state.last_used = now
                    if state.source_digest != digest:
                        state.version += 1
                        state.source_digest = digest
                        self._notify_locked(
                            "textDocument/didChange",
                            {
                                "textDocument": {
                                    "uri": state.uri,
                                    "version": state.version,
                                },
                                "contentChanges": [{"text": source}],
                            },
                        )
                response = self._request_locked(
                    "textDocument/semanticTokens/full",
                    {"textDocument": {"uri": state.uri}},
                )
                if response is None:
                    data: list[int] = []
                elif isinstance(response, dict) and isinstance(
                    response.get("data"), list
                ):
                    data = response["data"]
                else:
                    raise LanguageServiceProtocolError(
                        self.service_name,
                        f"{self.service_name} semantic tokens 响应格式无效",
                    )
                if len(data) % 5 != 0 or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in data
                ):
                    raise LanguageServiceProtocolError(
                        self.service_name,
                        f"{self.service_name} semantic token 数据无效",
                    )
                return {
                    "data": data,
                    "result_id": f"{state.version}:{digest[:12]}",
                }
            except LanguageServiceError:
                self._reset_locked()
                raise

    def close(self) -> None:
        with self._session_lock:
            self._reset_locked()


class SemanticLanguageServicePool:
    """Distribute semantic-token requests across isolated parser instances."""

    def __init__(
        self,
        *,
        service_name: str,
        factory,
        size: int = LANGUAGE_SERVICE_POOL_SIZE,
    ) -> None:
        if size < 1:
            raise ValueError("语言服务池大小必须大于零")
        self.service_name = service_name
        self.size = size
        self._services = tuple(factory(slot) for slot in range(size))
        self._available: queue.LifoQueue = queue.LifoQueue(maxsize=size)
        for service in self._services:
            self._available.put_nowait(service)

    def _acquire(self):
        try:
            return self._available.get_nowait()
        except queue.Empty as exc:
            raise LanguageServiceBusyError(
                self.service_name,
                f"{self.service_name} 的 {self.size} 个并发解析槽均在使用中",
            ) from exc

    def legend(self) -> dict[str, list[str]]:
        service = self._acquire()
        try:
            return service.legend()
        finally:
            self._available.put_nowait(service)

    def semantic_tokens(
        self,
        document_key: str,
        source: str,
    ) -> dict[str, Any]:
        service = self._acquire()
        try:
            return service.semantic_tokens(document_key, source)
        finally:
            self._available.put_nowait(service)

    def close(self) -> None:
        for service in self._services:
            close = getattr(service, "close", None)
            if close is not None:
                close()
