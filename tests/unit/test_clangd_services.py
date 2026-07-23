from __future__ import annotations

from io import BytesIO

import pytest

from oj_modules import clangd_services, language_server_services


class FakeClangdService(clangd_services.ClangdService):
    def __init__(self, clock=lambda: 100.0):
        super().__init__(
            "cpp",
            clock=clock,
            cpp_standard_library_paths=(),
        )
        self.notifications = []
        self.requests = []
        self._legend = {
            "tokenTypes": ["variable", "class"],
            "tokenModifiers": ["declaration"],
        }

    def _start_locked(self):
        return None

    def _notify_locked(self, method, params):
        self.notifications.append((method, params))

    def _request_locked(self, method, params):
        self.requests.append((method, params))
        return {"data": [0, 0, 6, 1, 1]}


def test_semantic_tokens_open_change_and_reuse_document():
    service = FakeClangdService()

    first = service.semantic_tokens("user:2:cpp", "vector<int> value;")
    second = service.semantic_tokens("user:2:cpp", "vector<int> value;")
    third = service.semantic_tokens("user:2:cpp", "vector<long> value;")

    assert first["data"] == [0, 0, 6, 1, 1]
    assert first["result_id"].startswith("1:")
    assert second["result_id"] == first["result_id"]
    assert third["result_id"].startswith("2:")
    methods = [method for method, _ in service.notifications]
    assert methods == ["textDocument/didOpen", "textDocument/didChange"]
    assert [method for method, _ in service.requests] == [
        "textDocument/semanticTokens/full",
        "textDocument/semanticTokens/full",
        "textDocument/semanticTokens/full",
    ]
    assert "vector<long>" in service.notifications[-1][1]["contentChanges"][0]["text"]


def test_semantic_tokens_reject_oversized_or_malformed_data(monkeypatch):
    service = FakeClangdService()
    monkeypatch.setattr(language_server_services, "LANGUAGE_SOURCE_MAX_BYTES", 4)
    with pytest.raises(ValueError, match="大小限制"):
        service.semantic_tokens("user:2:cpp", "12345")

    monkeypatch.setattr(language_server_services, "LANGUAGE_SOURCE_MAX_BYTES", 1024)
    service._request_locked = lambda method, params: {"data": [0, 0, 1]}
    with pytest.raises(clangd_services.ClangdProtocolError, match="数据无效"):
        service.semantic_tokens("user:2:cpp", "int x;")


def test_clangd_uses_host_cpp_standard_library_inside_sandbox(tmp_path):
    generic_include = tmp_path / "include" / "c++" / "16"
    target_include = generic_include / "aarch64-host"
    target_include.mkdir(parents=True)
    service = clangd_services.ClangdService(
        "cpp",
        cpp_standard_library_paths=(generic_include, target_include),
    )

    options = service._initialization_options()
    flags = options["fallbackFlags"]
    assert flags[:3] == ["-xc++", "-std=c++20", "-nostdinc++"]
    assert "-nostdinc" not in flags
    assert "-ivfsoverlay" not in flags
    assert "-include" not in flags
    assert flags[3:] == [
        "-isystem",
        str(generic_include),
        "-isystem",
        str(target_include),
    ]
    assert service.sandbox_read_paths == (generic_include, target_include)


def test_compiler_include_probe_keeps_only_real_cpp_roots(tmp_path):
    cpp_root = tmp_path / "include" / "c++" / "16"
    target_root = cpp_root / "aarch64-host"
    c_root = tmp_path / "sdk" / "usr" / "include"
    cpp_root.mkdir(parents=True)
    target_root.mkdir()
    c_root.mkdir(parents=True)

    stderr = "\n".join(
        (
            '#include "..." search starts here:',
            "#include <...> search starts here:",
            f" {cpp_root}",
            f" {target_root}",
            f" {c_root}",
            "End of search list.",
        )
    )

    assert clangd_services._parse_compiler_include_search(stderr) == (
        cpp_root.resolve(),
        target_root.resolve(),
    )


def test_semantic_tokens_reject_concurrent_request_without_queueing():
    service = FakeClangdService()
    service._semantic_request_gate.acquire()
    try:
        with pytest.raises(language_server_services.LanguageServiceBusyError):
            service.semantic_tokens("user:2:cpp", "int value;")
    finally:
        service._semantic_request_gate.release()


def test_language_server_environment_does_not_inherit_web_secrets(monkeypatch, tmp_path):
    service = FakeClangdService()
    monkeypatch.setenv("MYSQL_PASSWORD", "secret")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "secret")

    environment = service._process_environment(tmp_path)

    assert environment["HOME"] == str(tmp_path)
    assert environment["TMPDIR"] == str(tmp_path)
    assert "MYSQL_PASSWORD" not in environment
    assert "DASHSCOPE_API_KEY" not in environment


def test_linux_language_server_command_is_network_and_filesystem_sandboxed(
    monkeypatch,
    tmp_path,
):
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime"
    workspace.mkdir()
    runtime.mkdir()
    monkeypatch.setattr(language_server_services.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        language_server_services.shutil,
        "which",
        lambda command: "/usr/bin/bwrap" if command == "bwrap" else None,
    )
    monkeypatch.setattr(
        language_server_services,
        "_sandbox_read_paths",
        lambda executable, extra_paths: (runtime,),
    )

    command = language_server_services.sandbox_language_server_command(
        "/usr/bin/clangd",
        ("--log=error",),
        workspace,
    )

    assert command[0] == "/usr/bin/bwrap"
    assert "--unshare-all" in command
    assert "--share-net" not in command
    assert ["--bind", str(workspace), str(workspace)] == command[
        command.index("--bind") : command.index("--bind") + 3
    ]
    runtime_bind = ["--ro-bind", str(runtime), str(runtime)]
    assert any(
        command[index : index + 3] == runtime_bind
        for index in range(len(command) - 2)
    )


def test_macos_language_server_profile_denies_network_and_non_runtime_files(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime"
    workspace.mkdir()
    runtime.mkdir()

    profile = language_server_services._macos_sandbox_profile(
        workspace,
        (runtime,),
    )

    assert "(deny network*)" in profile
    assert "(require-not (require-any" in profile
    assert f'(subpath "{runtime}")' in profile
    assert f'(subpath "{workspace}")' in profile
    assert "/etc/passwd" not in profile


def test_legend_is_copied_and_language_is_restricted():
    service = FakeClangdService()
    legend = service.legend()
    legend["tokenTypes"].append("mutated")
    assert service.legend()["tokenTypes"] == ["variable", "class"]
    with pytest.raises(ValueError, match=r"仅 C/C\+\+"):
        clangd_services.get_clangd_service("python")


def test_json_rpc_frame_reader():
    payload = b'{"jsonrpc":"2.0","id":1,"result":{}}'
    stream = BytesIO(
        f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload
    )
    assert clangd_services.ClangdService._read_message(stream) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {},
    }


def test_json_rpc_frame_reader_rejects_oversized_body(monkeypatch):
    monkeypatch.setattr(language_server_services, "LANGUAGE_RESPONSE_MAX_BYTES", 3)
    stream = BytesIO(b"Content-Length: 4\r\n\r\nnull")
    with pytest.raises(clangd_services.ClangdProtocolError, match="大小无效"):
        clangd_services.ClangdService._read_message(stream)
