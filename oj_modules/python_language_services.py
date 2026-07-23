"""Persistent BasedPyright service for Python editor semantic highlighting."""

from __future__ import annotations

import atexit
import subprocess
import threading

from oj_modules.language_server_services import (
    LANGUAGE_REQUEST_TIMEOUT_SECONDS,
    LANGUAGE_SERVICE_POOL_SIZE,
    SemanticLanguageServerService,
    SemanticLanguageServicePool,
    find_language_service_executable,
)


class BasedPyrightService(SemanticLanguageServerService):
    def __init__(
        self,
        *,
        command: str = "basedpyright-langserver",
        request_timeout: float = LANGUAGE_REQUEST_TIMEOUT_SECONDS,
        workspace_key: str | None = None,
    ) -> None:
        super().__init__(
            service_name="BasedPyright",
            language_id="python",
            file_suffix=".py",
            command=command,
            command_args=("--stdio",),
            request_timeout=request_timeout,
            workspace_key=workspace_key,
        )


def verify_python_language_runtime() -> str:
    """Verify both the production LSP entrypoint and its pinned CLI package."""
    find_language_service_executable(
        "basedpyright-langserver",
        "BasedPyright",
    )
    cli = find_language_service_executable("basedpyright", "BasedPyright")
    result = subprocess.run(
        [cli, "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (result.stdout or result.stderr).strip()
    if result.returncode or not output.startswith("basedpyright "):
        raise RuntimeError("BasedPyright 版本核验失败")
    service = BasedPyrightService()
    try:
        legend = service.legend()
        tokens = service.semantic_tokens(
            "runtime-self-check",
            "values: list[str] = []\nvalues.append('ok')\n",
        )
        if not legend.get("tokenTypes") or not tokens.get("data"):
            raise RuntimeError("BasedPyright 语义令牌自检失败")
    finally:
        service.close()
    return output.splitlines()[0]


_service_lock = threading.Lock()
_service: SemanticLanguageServicePool | None = None


def get_python_language_service(language: str) -> SemanticLanguageServicePool:
    if language not in {"py", "python"}:
        raise ValueError("仅 Python 支持 BasedPyright 语义解析")
    global _service
    with _service_lock:
        if _service is None:
            _service = SemanticLanguageServicePool(
                service_name="BasedPyright",
                size=LANGUAGE_SERVICE_POOL_SIZE,
                factory=lambda slot: BasedPyrightService(
                    workspace_key=f"basedpyright-{slot}",
                ),
            )
        return _service


def close_python_language_service() -> None:
    global _service
    with _service_lock:
        service = _service
        _service = None
    if service is not None:
        service.close()


atexit.register(close_python_language_service)
