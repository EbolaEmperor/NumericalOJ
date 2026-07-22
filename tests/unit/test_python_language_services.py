from __future__ import annotations

from types import SimpleNamespace

import pytest

from oj_modules import language_server_services, python_language_services


def test_basedpyright_service_uses_stdio_entrypoint(monkeypatch, tmp_path):
    binary = tmp_path / "basedpyright-langserver"
    binary.write_text("", encoding="utf-8")
    binary.chmod(0o700)
    service = python_language_services.BasedPyrightService()
    monkeypatch.setattr(service, "_find_executable", lambda: str(binary))
    monkeypatch.setattr(
        language_server_services,
        "sandbox_language_server_command",
        lambda executable, arguments, workspace, **kwargs: [
            executable,
            *arguments,
        ],
    )

    assert service._command_line() == [str(binary), "--stdio"]
    assert service.language == "python"
    assert service.file_suffix == ".py"


def test_python_language_service_accepts_aliases_and_rejects_other_languages(
    monkeypatch,
):
    fake = object()
    monkeypatch.setattr(python_language_services, "_service", fake)

    assert python_language_services.get_python_language_service("py") is fake
    assert python_language_services.get_python_language_service("python") is fake
    with pytest.raises(ValueError, match="仅 Python"):
        python_language_services.get_python_language_service("cpp")


def test_runtime_verification_reuses_language_executable_resolution(monkeypatch):
    resolved = []
    service_calls = []

    class FakeService:
        def legend(self):
            return {"tokenTypes": ["class"]}

        def semantic_tokens(self, document_key, source):
            service_calls.append((document_key, source))
            return {"data": [0, 0, 4, 0, 0]}

        def close(self):
            service_calls.append(("closed", ""))

    monkeypatch.setattr(python_language_services, "BasedPyrightService", FakeService)
    monkeypatch.setattr(
        python_language_services,
        "find_language_service_executable",
        lambda command, service_name: resolved.append((command, service_name))
        or f"/venv/bin/{command}",
    )
    monkeypatch.setattr(
        python_language_services.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="basedpyright 1.39.9\n",
            stderr="",
        ),
    )

    assert python_language_services.verify_python_language_runtime() == (
        "basedpyright 1.39.9"
    )
    assert resolved == [
        ("basedpyright-langserver", "BasedPyright"),
        ("basedpyright", "BasedPyright"),
    ]
    assert service_calls[0][0] == "runtime-self-check"
    assert service_calls[-1] == ("closed", "")
