"""Persistent clangd service for C/C++ editor semantic highlighting."""

from __future__ import annotations

import atexit
from functools import lru_cache
from pathlib import Path
import shutil
import subprocess
import threading

from oj_modules.language_server_services import (
    LANGUAGE_REQUEST_TIMEOUT_SECONDS,
    LANGUAGE_SERVICE_POOL_SIZE,
    LanguageServiceError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
    SemanticLanguageServerService,
    SemanticLanguageServicePool,
)


# Backward-compatible names keep route/tests readable while errors now share one base.
ClangdError = LanguageServiceError
ClangdUnavailableError = LanguageServiceUnavailableError
ClangdTimeoutError = LanguageServiceTimeoutError
ClangdProtocolError = LanguageServiceProtocolError


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
        command: str = "clangd",
        request_timeout: float = LANGUAGE_REQUEST_TIMEOUT_SECONDS,
        workspace_key: str | None = None,
        clock=None,
        cpp_standard_library_paths: tuple[Path, ...] | None = None,
    ) -> None:
        if language not in {"c", "cpp"}:
            raise ValueError(f"clangd 不支持该语言: {language}")
        kwargs = {}
        if clock is not None:
            kwargs["clock"] = clock
        if language == "cpp":
            standard_library_paths = (
                _host_cpp_standard_library_paths()
                if cpp_standard_library_paths is None
                else cpp_standard_library_paths
            )
        else:
            standard_library_paths = ()
        super().__init__(
            service_name="clangd",
            language_id=language,
            file_suffix=".c" if language == "c" else ".cpp",
            command=command,
            command_args=(
                "--background-index=false",
                "--clang-tidy=false",
                "--header-insertion=never",
                "--log=error",
            ),
            sandbox_read_paths=standard_library_paths,
            request_timeout=request_timeout,
            workspace_key=workspace_key,
            **kwargs,
        )

    def _initialization_options(self):
        if self.language == "c":
            fallback_flags = ["-xc", "-std=c11"]
        else:
            fallback_flags = ["-xc++", "-std=c++20", "-nostdinc++"]
            for path in self.sandbox_read_paths:
                fallback_flags.extend(("-isystem", str(path)))
        return {
            "fallbackFlags": fallback_flags,
            "clangdFileStatus": False,
        }


def verify_clangd_runtime() -> None:
    """Exercise STL semantics and prove host files stay outside clangd."""
    service = ClangdService("cpp")
    try:
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


def close_clangd_services() -> None:
    with _services_lock:
        services = list(_services.values())
        _services.clear()
    for service in services:
        service.close()


atexit.register(close_clangd_services)
