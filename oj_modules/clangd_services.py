"""Persistent clangd service for C/C++ editor semantic highlighting."""

from __future__ import annotations

import atexit
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import queue
import re
import shutil
import stat
import subprocess
import threading
from typing import Any

from oj_modules.editor_toolchain import (
    EditorToolchain,
    EditorToolchainError,
    load_editor_toolchain,
)
from oj_modules.language_server_services import (
    LANGUAGE_REQUEST_TIMEOUT_SECONDS,
    LANGUAGE_SOURCE_MAX_BYTES,
    LANGUAGE_SERVICE_POOL_SIZE,
    LanguageServiceBusyError,
    LanguageServiceError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
    SemanticLanguageServerService,
    SemanticLanguageServicePool,
)
from oj_modules.repository.language import (
    RepositorySemanticFile,
    RepositorySemanticSnapshot,
    RepositorySemanticTarget,
)


# Backward-compatible names keep route/tests readable while errors now share one base.
ClangdError = LanguageServiceError
ClangdUnavailableError = LanguageServiceUnavailableError
ClangdTimeoutError = LanguageServiceTimeoutError
ClangdProtocolError = LanguageServiceProtocolError

_AUTO_EDITOR_TOOLCHAIN = object()
REPOSITORY_LANGUAGE_SERVICE_POOL_SIZE = 4
REPOSITORY_SEMANTIC_MAX_TOKENS = 500_000
CLANGD_INACTIVE_REGIONS_MAX_RANGES = 4_096
CLANGD_INACTIVE_REGIONS_GRACE_SECONDS = 0.05
CLANGD_MINIMUM_MAJOR = 17
CLANGD_EXECUTABLE_CANDIDATES = (
    "clangd-20",
    "clangd-19",
    "clangd-18",
    "clangd-17",
    "clangd",
)
_MKL_SEMANTIC_PROBE = (
    "#include <mkl.h>\n"
    "MKLVersion official_mkl_version{};\n"
    "MKL_INT official_mkl_size = 0;\n"
    "auto *official_mkl_get_version = &MKL_Get_Version;\n",
    {
        "MKLVersion": {"class"},
        # oneMKL deliberately exposes MKL_INT as a public configuration macro,
        # not a typedef.  Resolving it as a macro proves mkl_types.h was parsed.
        "MKL_INT": {"macro"},
        "MKL_Get_Version": {"function"},
    },
)


def _clangd_major(version_output: str) -> int | None:
    match = re.search(
        r"\bclangd\s+version\s+([0-9]+)(?:[.\s]|$)",
        version_output,
        re.IGNORECASE,
    )
    return None if match is None else int(match.group(1))


@lru_cache(maxsize=1)
def _default_clangd_command() -> str:
    """Select the newest supported executable without trusting its filename."""
    for candidate in CLANGD_EXECUTABLE_CANDIDATES:
        executable = shutil.which(candidate)
        if executable is None:
            continue
        try:
            probe = subprocess.run(
                [executable, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        major = _clangd_major(f"{probe.stdout}\n{probe.stderr}")
        if (
            probe.returncode == 0
            and major is not None
            and major >= CLANGD_MINIMUM_MAJOR
        ):
            return executable
    raise LanguageServiceUnavailableError(
        "clangd",
        f"未找到 clangd {CLANGD_MINIMUM_MAJOR} 或更新版本",
    )


@dataclass
class _InactiveDocumentCycle:
    """One URI/version epoch eligible for clangd inactive-region updates."""

    version: int
    epoch: int
    # Kept only until the adjacent notification/response completes.  Retaining
    # every open document would duplicate up to 4 MiB per LSP document.
    source: str | None
    regions: tuple[tuple[int, int, int, int], ...] | None = None


def _selected_utf16_line_lengths(
    source: str,
    requested_lines: set[int],
) -> dict[int, int]:
    """Measure only referenced LSP lines without a source-sized offset table."""
    measured: dict[int, int] = {}
    line = 0
    width = 0
    index = 0
    while index < len(source):
        character = source[index]
        if character in {"\r", "\n"}:
            if line in requested_lines:
                measured[line] = width
            if (
                character == "\r"
                and index + 1 < len(source)
                and source[index + 1] == "\n"
            ):
                index += 1
            line += 1
            width = 0
        else:
            width += 2 if ord(character) > 0xFFFF else 1
        index += 1
    if line in requested_lines:
        measured[line] = width
    return measured


def _validated_inactive_regions(
    raw_regions: Any,
    source: str,
) -> tuple[tuple[int, int, int, int], ...] | None:
    """Validate clangd's extension atomically before exposing any range."""
    if (
        not isinstance(raw_regions, list)
        or len(raw_regions) > CLANGD_INACTIVE_REGIONS_MAX_RANGES
    ):
        return None

    def position(raw: Any) -> tuple[int, int] | None:
        if not isinstance(raw, dict):
            return None
        line = raw.get("line")
        character = raw.get("character")
        if (
            not isinstance(line, int)
            or isinstance(line, bool)
            or not isinstance(character, int)
            or isinstance(character, bool)
            or line < 0
            or character < 0
        ):
            return None
        return line, character

    validated: list[tuple[int, int, int, int]] = []
    requested_lines: set[int] = set()
    for raw_range in raw_regions:
        if not isinstance(raw_range, dict):
            return None
        start = position(raw_range.get("start"))
        end = position(raw_range.get("end"))
        if start is None or end is None or start > end:
            return None
        requested_lines.update((start[0], end[0]))
        validated.append((*start, *end))
    line_lengths = _selected_utf16_line_lengths(source, requested_lines)
    if any(
        start_line not in line_lengths
        or end_line not in line_lengths
        or start_character > line_lengths[start_line]
        or end_character > line_lengths[end_line]
        for start_line, start_character, end_line, end_character in validated
    ):
        return None
    return tuple(validated)


def _inactive_regions_payload(
    regions: tuple[tuple[int, int, int, int], ...],
) -> list[dict[str, dict[str, int]]]:
    """Build fresh JSON objects so callers cannot mutate the cached ranges."""
    return [
        {
            "start": {"line": start_line, "character": start_character},
            "end": {"line": end_line, "character": end_character},
        }
        for start_line, start_character, end_line, end_character in regions
    ]


def _parse_compiler_include_search(stderr: str) -> tuple[Path, ...]:
    """Extract real C++ standard-library roots from a compiler -v probe."""
    inside_search = False
    paths: list[Path] = []
    for raw_line in stderr.splitlines():
        line = raw_line.strip()
        if line == "#include <...> search starts here:":
            inside_search = True
            continue
        if inside_search and line == "End of search list.":
            break
        if not inside_search:
            continue
        candidate = line.split(" (framework directory)", 1)[0]
        path = Path(candidate)
        if (
            path.is_absolute()
            and path.is_dir()
            and "/c++/" in path.as_posix()
            and path not in paths
        ):
            paths.append(path.resolve())
    return tuple(paths)


@lru_cache(maxsize=1)
def _host_cpp_standard_library_paths() -> tuple[Path, ...]:
    """Locate a host GCC standard library that provides bits/stdc++.h."""
    candidate_names = [
        "g++",
        *(f"g++-{version}" for version in range(30, 9, -1)),
    ]
    attempted: set[str] = set()
    for name in candidate_names:
        compiler = shutil.which(name)
        if compiler is None:
            continue
        resolved = str(Path(compiler).resolve())
        if resolved in attempted:
            continue
        attempted.add(resolved)
        try:
            probe = subprocess.run(
                [
                    compiler,
                    "-E",
                    "-x",
                    "c++",
                    "-std=c++20",
                    "-v",
                    "-",
                ],
                input="#include <bits/stdc++.h>\n",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode != 0:
            continue
        include_paths = _parse_compiler_include_search(probe.stderr)
        if include_paths:
            return include_paths
    raise LanguageServiceUnavailableError(
        "clangd",
        "宿主机没有可供 clangd 读取且包含 bits/stdc++.h 的 GCC C++ 标准库",
    )


def _semantic_token_types_by_spelling(
    source: str,
    legend: dict[str, list[str]],
    data: list[int],
) -> dict[str, set[str]]:
    """Decode the ASCII runtime probe into spelling -> semantic type names."""
    lines = source.splitlines()
    token_types = legend["tokenTypes"]
    observed: dict[str, set[str]] = {}
    line = 0
    start = 0
    for index in range(0, len(data), 5):
        delta_line, delta_start, length, token_type, _ = data[index : index + 5]
        line += delta_line
        start = delta_start if delta_line else start + delta_start
        if line >= len(lines) or token_type >= len(token_types):
            continue
        spelling = lines[line][start : start + length]
        observed.setdefault(spelling, set()).add(token_types[token_type])
    return observed


class ClangdService(SemanticLanguageServerService):
    """Configure the reusable LSP bridge for clangd."""

    def __init__(
        self,
        language: str,
        *,
        command: str | None = None,
        request_timeout: float = LANGUAGE_REQUEST_TIMEOUT_SECONDS,
        workspace_key: str | None = None,
        clock=None,
        cpp_standard_library_paths: tuple[Path, ...] | None = None,
        editor_toolchain: EditorToolchain | None | object = _AUTO_EDITOR_TOOLCHAIN,
    ) -> None:
        if language not in {"c", "cpp"}:
            raise ValueError(f"clangd 不支持该语言: {language}")
        self._inactive_regions_condition = threading.Condition()
        self._inactive_document_cycles: dict[str, _InactiveDocumentCycle] = {}
        self._inactive_regions_epoch = 0
        self._inactive_regions_provider = False
        self._automatic_command = command is None
        kwargs = {}
        if clock is not None:
            kwargs["clock"] = clock

        if editor_toolchain is _AUTO_EDITOR_TOOLCHAIN:
            # An explicit standard-library fixture keeps unit tests and callers
            # deterministic; normal services always prefer the judge export.
            if cpp_standard_library_paths is not None:
                selected_toolchain = None
            else:
                try:
                    selected_toolchain = load_editor_toolchain()
                except EditorToolchainError as exc:
                    raise LanguageServiceUnavailableError(
                        "clangd",
                        f"判题器官方头文件工具链不可用：{exc}",
                    ) from exc
        elif editor_toolchain is None or isinstance(
            editor_toolchain, EditorToolchain
        ):
            selected_toolchain = editor_toolchain
        else:
            raise TypeError("editor_toolchain 类型无效")

        if selected_toolchain is not None:
            compiler_include_paths = selected_toolchain.include_paths_for(
                language
            )
            sandbox_read_paths = (selected_toolchain.root,)
        elif language == "cpp":
            standard_library_paths = (
                _host_cpp_standard_library_paths()
                if cpp_standard_library_paths is None
                else cpp_standard_library_paths
            )
            compiler_include_paths = standard_library_paths
            sandbox_read_paths = standard_library_paths
        else:
            compiler_include_paths = ()
            sandbox_read_paths = ()
        self.editor_toolchain = selected_toolchain
        self.compiler_include_paths = compiler_include_paths
        super().__init__(
            service_name="clangd",
            language_id=language,
            file_suffix=".c" if language == "c" else ".cpp",
            # Resolve lazily in _start_locked so test doubles and import-time
            # service pools do not depend on the host executable inventory.
            command=command or "clangd",
            command_args=(
                "--background-index=false",
                "--clang-tidy=false",
                "--header-insertion=never",
                "--log=error",
            ),
            sandbox_read_paths=sandbox_read_paths,
            request_timeout=request_timeout,
            workspace_key=workspace_key,
            **kwargs,
        )

    def _start_locked(self) -> None:
        if self._automatic_command:
            self.command = _default_clangd_command()
        super()._start_locked()

    def _text_document_capabilities(self):
        capabilities = super()._text_document_capabilities()
        capabilities["inactiveRegionsCapabilities"] = {
            "inactiveRegions": True,
        }
        return capabilities

    def _server_capabilities_received(self, capabilities):
        provider = capabilities.get("inactiveRegionsProvider")
        with self._inactive_regions_condition:
            self._inactive_regions_provider = (
                provider is True or isinstance(provider, dict)
            )
            self._inactive_regions_condition.notify_all()

    def _document_cycle_started(self, state, source):
        with self._inactive_regions_condition:
            self._inactive_regions_epoch += 1
            self._inactive_document_cycles[state.uri] = _InactiveDocumentCycle(
                version=state.version,
                epoch=self._inactive_regions_epoch,
                source=source,
            )
            self._inactive_regions_condition.notify_all()

    def _document_closed(self, state):
        with self._inactive_regions_condition:
            self._inactive_document_cycles.pop(state.uri, None)
            self._inactive_regions_condition.notify_all()

    def _reset_protocol_state(self):
        with self._inactive_regions_condition:
            self._inactive_regions_epoch += 1
            self._inactive_document_cycles.clear()
            self._inactive_regions_provider = False
            self._inactive_regions_condition.notify_all()

    def _handle_server_notification(self, message):
        if message.get("method") != "textDocument/inactiveRegions":
            return
        params = message.get("params")
        if not isinstance(params, dict):
            return
        document = params.get("textDocument")
        notification_version = None
        if "textDocument" in params:
            if not isinstance(document, dict):
                return
            uri = document.get("uri")
            if "version" in document:
                notification_version = document.get("version")
                if (
                    not isinstance(notification_version, int)
                    or isinstance(notification_version, bool)
                    or notification_version < 0
                ):
                    return
        else:
            # Older extension documentation described a top-level URI. Keep
            # accepting that wire shape, but bind it only to the current epoch.
            uri = params.get("uri")
        if not isinstance(uri, str) or not uri:
            return
        with self._inactive_regions_condition:
            cycle = self._inactive_document_cycles.get(uri)
            if (
                cycle is None
                or cycle.source is None
                or (
                    notification_version is not None
                    and notification_version != cycle.version
                )
            ):
                return
            expected_epoch = cycle.epoch
            source = cycle.source
        regions = _validated_inactive_regions(
            params.get("regions"),
            source,
        )
        if regions is None:
            return
        with self._inactive_regions_condition:
            current = self._inactive_document_cycles.get(uri)
            if (
                current is None
                or current.epoch != expected_epoch
                or (
                    notification_version is not None
                    and notification_version != current.version
                )
            ):
                return
            current.regions = regions
            current.source = None
            self._inactive_regions_provider = True
            self._inactive_regions_condition.notify_all()

    def _document_response_metadata(self, state):
        with self._inactive_regions_condition:
            cycle = self._inactive_document_cycles.get(state.uri)
            if cycle is None or cycle.version != state.version:
                return {
                    "inactive_regions": [],
                    "inactive_regions_supported": False,
                }
            expected_epoch = cycle.epoch
            if cycle.regions is None and self._inactive_regions_provider:
                self._inactive_regions_condition.wait_for(
                    lambda: (
                        (
                            current := self._inactive_document_cycles.get(
                                state.uri
                            )
                        )
                        is None
                        or current.epoch != expected_epoch
                        or current.regions is not None
                    ),
                    timeout=CLANGD_INACTIVE_REGIONS_GRACE_SECONDS,
                )
            current = self._inactive_document_cycles.get(state.uri)
            if (
                current is None
                or current.epoch != expected_epoch
                or current.version != state.version
                or current.regions is None
            ):
                if (
                    current is not None
                    and current.epoch == expected_epoch
                    and current.version == state.version
                ):
                    current.source = None
                return {
                    "inactive_regions": [],
                    "inactive_regions_supported": False,
                }
            current.source = None
            return {
                "inactive_regions": _inactive_regions_payload(
                    current.regions
                ),
                # A valid empty notification is still positive capability
                # evidence, distinct from an older clangd that stays silent.
                "inactive_regions_supported": True,
            }

    def _initialization_options(self):
        if self.language == "c":
            fallback_flags = ["-xc", "-std=c11"]
        else:
            fallback_flags = ["-xc++", "-std=c++20", "-nostdinc++"]
        if self.editor_toolchain is not None:
            # Prevent host /usr headers from turning deployment verification
            # into a false positive.  Every system root below came from the
            # candidate judge compiler's own search list.
            fallback_flags.insert(2, "-nostdinc")
        for path in self.compiler_include_paths:
            fallback_flags.extend(("-isystem", str(path)))
        return {
            "fallbackFlags": fallback_flags,
            "clangdFileStatus": False,
        }


class RepositoryClangdService(ClangdService):
    """Parse one repository generation at a time in a private copied mirror."""

    def __init__(self, language: str, **kwargs) -> None:
        super().__init__(language, **kwargs)
        self._active_repository: tuple[int, str, int] | None = None
        self.command_args = (
            *self.command_args,
            "--enable-config=false",
            f"--compile-commands-dir={self._workspace() / 'controlled-build'}",
        )

    def _repository_root(self) -> Path:
        return self._workspace() / "repository"

    def _initialization_options(self):
        options = super()._initialization_options()
        options["fallbackFlags"] = [
            *options["fallbackFlags"],
            "-I",
            str(self._repository_root()),
        ]
        return options

    def _scrub_workspace_locked(self) -> None:
        workspace_root = language_server_services_workspace_root()
        workspace_key = Path(self.workspace_key)
        if (
            workspace_key.name != self.workspace_key
            or self.workspace_key in {"", ".", ".."}
        ):
            raise LanguageServiceProtocolError(
                self.service_name,
                "仓库语言服务工作区路径非法",
            )
        workspace = workspace_root / self.workspace_key
        if workspace.is_symlink():
            raise LanguageServiceProtocolError(
                self.service_name,
                "仓库语言服务工作区不能是符号链接",
            )
        if workspace.exists():
            if not stat.S_ISDIR(workspace.lstat().st_mode):
                raise LanguageServiceProtocolError(
                    self.service_name,
                    "仓库语言服务工作区类型非法",
                )
            shutil.rmtree(workspace)

    def _materialize_snapshot_locked(
        self,
        snapshot: RepositorySemanticSnapshot,
    ) -> None:
        workspace = self._workspace()
        workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
        controlled_build = workspace / "controlled-build"
        controlled_build.mkdir(mode=0o700)
        candidate = workspace / "repository-next"
        candidate.mkdir(mode=0o700)
        try:
            for relative_path in sorted(
                snapshot.directories,
                key=lambda value: (value.count("/"), value),
            ):
                destination = candidate.joinpath(*relative_path.split("/"))
                destination.mkdir(mode=0o700, parents=True, exist_ok=False)
            written = 0
            for item in snapshot.files:
                destination = candidate.joinpath(
                    *item.relative_path.split("/")
                )
                destination.parent.mkdir(
                    mode=0o700,
                    parents=True,
                    exist_ok=True,
                )
                with destination.open("xb") as stream:
                    stream.write(item.content)
                destination.chmod(0o600)
                written += len(item.content)
            if written != snapshot.total_size:
                raise LanguageServiceProtocolError(
                    self.service_name,
                    "仓库语言服务快照大小不一致",
                )
            candidate.rename(self._repository_root())
        except BaseException:
            if candidate.exists():
                shutil.rmtree(candidate)
            raise

    def _activate_repository_locked(
        self,
        target: RepositorySemanticTarget,
        snapshot_loader,
    ) -> None:
        repository_key = (
            target.owner_id,
            target.storage_key,
            target.generation,
        )
        if self._active_repository == repository_key:
            return
        self._reset_locked()
        self._active_repository = None
        self._scrub_workspace_locked()
        snapshot = snapshot_loader()
        if snapshot.target != target:
            raise LanguageServiceProtocolError(
                self.service_name,
                "仓库语言服务快照身份不一致",
            )
        try:
            self._materialize_snapshot_locked(snapshot)
        except BaseException:
            self._scrub_workspace_locked()
            raise
        self._active_repository = repository_key

    def semantic_tokens(
        self,
        target: RepositorySemanticTarget,
        source: str,
        snapshot_loader,
    ) -> dict:
        if target.language != self.language:
            raise ValueError("仓库文件语言与 clangd 服务不匹配")
        if len(source.encode("utf-8")) > LANGUAGE_SOURCE_MAX_BYTES:
            raise ValueError("代码超过实时解析大小限制")
        if not self._semantic_request_gate.acquire(blocking=False):
            raise LanguageServiceBusyError(
                self.service_name,
                f"{self.service_name} 正在处理其他实时解析请求",
            )
        try:
            with self._session_lock:
                self._activate_repository_locked(target, snapshot_loader)
                document_path = self._repository_root().joinpath(
                    *target.relative_path.split("/")
                )
                try:
                    info = document_path.lstat()
                except FileNotFoundError as exc:
                    raise LanguageServiceProtocolError(
                        self.service_name,
                        "仓库语言服务目标文件不在快照中",
                    ) from exc
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise LanguageServiceProtocolError(
                        self.service_name,
                        "仓库语言服务目标文件类型非法",
                    )
                result = self._semantic_tokens_serial(
                    f"{target.owner_id}:{target.entry_id}:{self.language}",
                    source,
                    document_path=document_path,
                )
                if (
                    len(result["data"])
                    > REPOSITORY_SEMANTIC_MAX_TOKENS * 5
                ):
                    self._reset_locked()
                    raise LanguageServiceProtocolError(
                        self.service_name,
                        "仓库 semantic token 数量超过安全上限",
                    )
                result["result_id"] = (
                    f"repository:{target.generation}:{result['result_id']}"
                )
                return result
        finally:
            self._semantic_request_gate.release()

    def close(self) -> None:
        with self._session_lock:
            self._reset_locked()
            self._active_repository = None
            self._scrub_workspace_locked()


def language_server_services_workspace_root() -> Path:
    """Late import keeps the private global workspace behind one testable seam."""

    from oj_modules import language_server_services

    return language_server_services._WORKSPACE_ROOT.resolve()


class RepositoryClangdServicePool:
    """Distribute tenant-isolated repository mirrors across clangd slots."""

    def __init__(
        self,
        language: str,
        *,
        size=REPOSITORY_LANGUAGE_SERVICE_POOL_SIZE,
    ) -> None:
        self.language = language
        self.size = size
        self._services = tuple(
            RepositoryClangdService(
                language,
                workspace_key=f"repository-clangd-{language}-{slot}",
            )
            for slot in range(size)
        )
        self._available: queue.LifoQueue = queue.LifoQueue(maxsize=size)
        for service in self._services:
            self._available.put_nowait(service)
        self._owners_lock = threading.Lock()
        self._active_owners: set[int] = set()

    def semantic_tokens(self, target, source, snapshot_loader):
        with self._owners_lock:
            if target.owner_id in self._active_owners:
                raise LanguageServiceBusyError(
                    "clangd",
                    "同一用户已有一个仓库实时解析请求正在处理",
                )
            self._active_owners.add(target.owner_id)
        try:
            try:
                service = self._available.get_nowait()
            except queue.Empty as exc:
                raise LanguageServiceBusyError(
                    "clangd",
                    f"clangd 的 {self.size} 个仓库解析槽均在使用中",
                ) from exc
            try:
                return service.semantic_tokens(
                    target,
                    source,
                    snapshot_loader,
                )
            finally:
                self._available.put_nowait(service)
        finally:
            with self._owners_lock:
                self._active_owners.discard(target.owner_id)

    def close(self) -> None:
        for service in self._services:
            service.close()


def verify_clangd_runtime(*, require_official_toolchain: bool = False) -> None:
    """Exercise official headers and prove host files stay outside clangd."""
    service = ClangdService("cpp")
    try:
        if require_official_toolchain and service.editor_toolchain is None:
            raise RuntimeError("clangd 未加载候选判题镜像的官方头文件工具链")
        legend = service.legend()
        probe_source = (
            "#include <bits/stdc++.h>\n"
            "std::vector<std::string> values;\n"
            "std::deque<std::tuple<int, int, int>> pending;\n"
            "int buffer[4];\n"
            "memset(buffer, 0, sizeof(buffer));\n"
        )
        tokens = service.semantic_tokens(
            "runtime-self-check",
            probe_source,
        )
        if not legend.get("tokenTypes") or not tokens.get("data"):
            raise RuntimeError("clangd 语义令牌自检失败")
        observed = _semantic_token_types_by_spelling(
            probe_source,
            legend,
            tokens["data"],
        )
        expected = {
            "vector": {"class"},
            "string": {"class"},
            "deque": {"class"},
            "tuple": {"class"},
            # clangd exposes C library callables as variable + defaultLibrary
            # on some host toolchains and as function on others.
            "memset": {"function", "variable"},
        }
        missing = [
            spelling
            for spelling, token_types in expected.items()
            if observed.get(spelling, set()).isdisjoint(token_types)
        ]
        if missing:
            raise RuntimeError(
                "clangd 标准库语义令牌自检失败: " + ", ".join(missing)
            )

        inactive_probe = (
            "#if 0\n"
            "int disabled_runtime_probe = 1;\n"
            "#endif\n"
            "int active_runtime_probe = 1;\n"
        )
        inactive_result = service.semantic_tokens(
            "runtime-inactive-region-probe",
            inactive_probe,
        )
        inactive_regions = inactive_result.get("inactive_regions", [])
        disabled_line_end = len("int disabled_runtime_probe = 1;")
        inactive_line_covered = any(
            (
                region["start"]["line"],
                region["start"]["character"],
            )
            <= (1, 0)
            and (
                region["end"]["line"],
                region["end"]["character"],
            )
            >= (1, disabled_line_end)
            for region in inactive_regions
        )
        if (
            not inactive_result.get("inactive_regions_supported")
            or not inactive_line_covered
        ):
            raise RuntimeError("clangd 无效条件编译区域通知自检失败")

        if service.editor_toolchain is not None:
            official_probes = (
                (
                    "eigen",
                    "#include <Eigen/Eigen>\n"
                    "#include <Eigen/SparseLU>\n"
                    "Eigen::SparseMatrix<double> official_matrix;\n"
                    "Eigen::SparseLU<Eigen::SparseMatrix<double>> "
                    "official_solver;\n",
                    {
                        "SparseMatrix": {"class"},
                        "SparseLU": {"class"},
                    },
                ),
                (
                    "cblas",
                    "#include <cblas.h>\n"
                    "auto *official_cblas = &cblas_dgemm;\n",
                    {"cblas_dgemm": {"function"}},
                ),
                (
                    "lapacke",
                    "#include <lapacke.h>\n"
                    "auto *official_lapacke = &LAPACKE_dgesv;\n",
                    {"LAPACKE_dgesv": {"function"}},
                ),
                (
                    "mkl",
                    *_MKL_SEMANTIC_PROBE,
                ),
            )
            official_missing: list[str] = []
            for probe_name, probe_source, expected_tokens in official_probes:
                probe_data = service.semantic_tokens(
                    f"runtime-official-library-{probe_name}",
                    probe_source,
                )["data"]
                probe_observed = _semantic_token_types_by_spelling(
                    probe_source,
                    legend,
                    probe_data,
                )
                official_missing.extend(
                    spelling
                    for spelling, token_types in expected_tokens.items()
                    if probe_observed.get(spelling, set()).isdisjoint(
                        token_types
                    )
                )
            if official_missing:
                raise RuntimeError(
                    "clangd 判题器官方库语义令牌自检失败: "
                    + ", ".join(official_missing)
                )

            repository_source = (
                '#include "A/OfficialDependency.h"\n'
                "RelativeDependency repository_value;\n"
            )
            repository_header = (
                "#pragma once\n"
                "#include <Eigen/Eigen>\n"
                "#include <Eigen/SparseLU>\n"
                "#ifdef NUMOJ_UNTRUSTED_CONFIG\n"
                "int RelativeDependency;\n"
                "#else\n"
                "class RelativeDependency {\n"
                "  Eigen::SparseLU<Eigen::SparseMatrix<double>> solver;\n"
                "};\n"
                "#endif\n"
            )
            repository_target = RepositorySemanticTarget(
                owner_id=1,
                storage_key="0" * 32,
                generation=1,
                entry_id=1,
                relative_path="NA/main.cpp",
                language="cpp",
            )
            repository_snapshot = RepositorySemanticSnapshot(
                target=repository_target,
                directories=("A", "NA"),
                files=(
                    RepositorySemanticFile(
                        ".clangd",
                        (
                            b"CompileFlags:\n"
                            b"  Add: [-DNUMOJ_UNTRUSTED_CONFIG]\n"
                        ),
                    ),
                    RepositorySemanticFile(
                        "compile_commands.json",
                        (
                            b'[{"directory":".","file":"NA/main.cpp",'
                            b'"command":"clang++ '
                            b'-DNUMOJ_UNTRUSTED_CONFIG '
                            b'-xc NA/main.cpp"}]'
                        ),
                    ),
                    RepositorySemanticFile(
                        "A/OfficialDependency.h",
                        repository_header.encode("utf-8"),
                    ),
                    RepositorySemanticFile(
                        "NA/main.cpp",
                        repository_source.encode("utf-8"),
                    ),
                ),
                total_size=(
                    len(repository_header.encode("utf-8"))
                    + len(repository_source.encode("utf-8"))
                    + len(
                        b"CompileFlags:\n"
                        b"  Add: [-DNUMOJ_UNTRUSTED_CONFIG]\n"
                    )
                    + len(
                        b'[{"directory":".","file":"NA/main.cpp",'
                        b'"command":"clang++ '
                        b'-DNUMOJ_UNTRUSTED_CONFIG '
                        b'-xc NA/main.cpp"}]'
                    )
                ),
            )
            repository_service = RepositoryClangdService(
                "cpp",
                workspace_key="repository-clangd-runtime-self-check",
                editor_toolchain=service.editor_toolchain,
            )
            try:
                repository_data = repository_service.semantic_tokens(
                    repository_target,
                    repository_source,
                    lambda: repository_snapshot,
                )["data"]
                repository_observed = _semantic_token_types_by_spelling(
                    repository_source,
                    legend,
                    repository_data,
                )
                if "class" not in repository_observed.get(
                    "RelativeDependency",
                    set(),
                ):
                    raise RuntimeError(
                        "clangd 仓库目录、官方库或配置隔离自检失败"
                    )
            finally:
                repository_service.close()

        host_probe_source = (
            '#if __has_include("/etc/passwd")\n'
            "class HostFileVisible {};\n"
            "#else\n"
            "int HostFileVisible;\n"
            "#endif\n"
        )
        probe_data = service.semantic_tokens(
            "runtime-host-file-probe",
            host_probe_source,
        )["data"]
        host_observed = _semantic_token_types_by_spelling(
            host_probe_source,
            legend,
            probe_data,
        )
        observed_types = host_observed.get("HostFileVisible", set())
        if "class" in observed_types or "variable" not in observed_types:
            raise RuntimeError("clangd 进程沙箱未能隔离宿主文件")
    finally:
        service.close()


_services_lock = threading.Lock()
_services: dict[str, SemanticLanguageServicePool] = {}
_repository_services: dict[str, RepositoryClangdServicePool] = {}


def get_clangd_service(language: str) -> SemanticLanguageServicePool:
    normalized = "cpp" if language == "cpp" else "c" if language == "c" else ""
    if not normalized:
        raise ValueError("仅 C/C++ 支持 clangd 语义解析")
    with _services_lock:
        service = _services.get(normalized)
        if service is None:
            service = SemanticLanguageServicePool(
                service_name="clangd",
                size=LANGUAGE_SERVICE_POOL_SIZE,
                factory=lambda slot: ClangdService(
                    normalized,
                    workspace_key=f"clangd-{normalized}-{slot}",
                ),
            )
            _services[normalized] = service
        return service


def get_repository_clangd_service(
    language: str,
) -> RepositoryClangdServicePool:
    normalized = "cpp" if language == "cpp" else "c" if language == "c" else ""
    if not normalized:
        raise ValueError("仅 C/C++ 支持仓库 clangd 语义解析")
    with _services_lock:
        service = _repository_services.get(normalized)
        if service is None:
            service = RepositoryClangdServicePool(normalized)
            _repository_services[normalized] = service
        return service


def close_clangd_services() -> None:
    with _services_lock:
        services = [
            *_services.values(),
            *_repository_services.values(),
        ]
        _services.clear()
        _repository_services.clear()
    for service in services:
        service.close()


atexit.register(close_clangd_services)
