"""Persistent clangd service for C/C++ editor semantic highlighting."""

from __future__ import annotations

import atexit
import json
from pathlib import Path
import threading

from oj_modules.language_server_services import (
    LANGUAGE_REQUEST_TIMEOUT_SECONDS,
    LanguageServiceError,
    LanguageServiceProtocolError,
    LanguageServiceTimeoutError,
    LanguageServiceUnavailableError,
    SemanticLanguageServerService,
)


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_COMPAT_INCLUDE = _PROJECT_ROOT / "clangd" / "include"

# Backward-compatible names keep route/tests readable while errors now share one base.
ClangdError = LanguageServiceError
ClangdUnavailableError = LanguageServiceUnavailableError
ClangdTimeoutError = LanguageServiceTimeoutError
ClangdProtocolError = LanguageServiceProtocolError


class ClangdService(SemanticLanguageServerService):
    """Configure the reusable LSP bridge for clangd."""

    def __init__(
        self,
        language: str,
        *,
        command: str = "clangd",
        request_timeout: float = LANGUAGE_REQUEST_TIMEOUT_SECONDS,
        clock=None,
    ) -> None:
        if language not in {"c", "cpp"}:
            raise ValueError(f"clangd 不支持该语言: {language}")
        kwargs = {}
        if clock is not None:
            kwargs["clock"] = clock
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
            sandbox_read_paths=(_COMPAT_INCLUDE,),
            request_timeout=request_timeout,
            **kwargs,
        )

    def _initialization_options(self):
        overlay = self._write_vfs_overlay()
        if self.language == "c":
            fallback_flags = [
                "-xc",
                "-std=c11",
                "-nostdinc",
                "-ivfsoverlay",
                str(overlay),
            ]
        else:
            fallback_flags = [
                "-xc++",
                "-std=c++20",
                "-nostdinc",
                "-nostdinc++",
                "-ivfsoverlay",
                str(overlay),
                "-I/numericaloj/include",
                "-include",
                "/numericaloj/include/bits/stdc++.h",
            ]
        return {
            "fallbackFlags": fallback_flags,
            "clangdFileStatus": False,
        }

    def _write_vfs_overlay(self) -> Path:
        """Map a fixed compatibility header inside the process sandbox."""
        workspace = self._workspace()
        workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
        overlay = workspace / "vfs-overlay.json"
        payload = {
            "version": 0,
            "case-sensitive": "true",
            "use-external-names": False,
            # The draft main file only exists in clangd's in-memory filesystem,
            # so clang's VFS must fall through. Host paths remain inaccessible
            # because the entire clangd process runs inside the OS sandbox.
            "fallthrough": True,
            "roots": [
                {
                    "type": "file",
                    "name": "/numericaloj/include/bits/stdc++.h",
                    "external-contents": str(
                        _COMPAT_INCLUDE / "bits/stdc++.h"
                    ),
                }
            ],
        }
        overlay.write_text(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
            encoding="utf-8",
        )
        overlay.chmod(0o600)
        return overlay


def verify_clangd_runtime() -> None:
    """Exercise STL semantics and prove host files stay outside clangd."""
    service = ClangdService("cpp")
    try:
        legend = service.legend()
        tokens = service.semantic_tokens(
            "runtime-self-check",
            "std::vector<std::string> values;\nvalues.size();\n",
        )
        if not legend.get("tokenTypes") or not tokens.get("data"):
            raise RuntimeError("clangd 语义令牌自检失败")

        probe_source = (
            '#if __has_include("/etc/passwd")\n'
            "class HostFileVisible {};\n"
            "#else\n"
            "int HostFileVisible;\n"
            "#endif\n"
        )
        probe_data = service.semantic_tokens(
            "runtime-host-file-probe",
            probe_source,
        )["data"]
        lines = probe_source.splitlines()
        line = 0
        start = 0
        observed_types: list[str] = []
        token_types = legend["tokenTypes"]
        for index in range(0, len(probe_data), 5):
            delta_line, delta_start, length, token_type, _ = probe_data[
                index : index + 5
            ]
            line += delta_line
            start = delta_start if delta_line else start + delta_start
            if (
                lines[line][start : start + length] == "HostFileVisible"
                and token_type < len(token_types)
            ):
                observed_types.append(token_types[token_type])
        if "class" in observed_types or "variable" not in observed_types:
            raise RuntimeError("clangd 进程沙箱未能隔离宿主文件")
    finally:
        service.close()


_services_lock = threading.Lock()
_services: dict[str, ClangdService] = {}


def get_clangd_service(language: str) -> ClangdService:
    normalized = "cpp" if language == "cpp" else "c" if language == "c" else ""
    if not normalized:
        raise ValueError("仅 C/C++ 支持 clangd 语义解析")
    with _services_lock:
        service = _services.get(normalized)
        if service is None:
            service = ClangdService(normalized)
            _services[normalized] = service
        return service


def close_clangd_services() -> None:
    with _services_lock:
        services = list(_services.values())
        _services.clear()
    for service in services:
        service.close()


atexit.register(close_clangd_services)
