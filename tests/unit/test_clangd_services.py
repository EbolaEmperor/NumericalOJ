from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import threading

import pytest

from backend.oj_modules.editor import clangd as clangd_services
from backend.oj_modules.editor import language_server as language_server_services
from backend.oj_modules.editor.toolchain import EditorToolchain


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
    assert first["inactive_regions"] == []
    assert first["inactive_regions_supported"] is False
    assert first["result_id"].startswith("1:")
    assert second["result_id"] == first["result_id"]
    assert third["result_id"].startswith("2:")
    assert all(
        cycle.source is None
        for cycle in service._inactive_document_cycles.values()
    )
    methods = [method for method, _ in service.notifications]
    assert methods == ["textDocument/didOpen", "textDocument/didChange"]
    assert [method for method, _ in service.requests] == [
        "textDocument/semanticTokens/full",
        "textDocument/semanticTokens/full",
        "textDocument/semanticTokens/full",
    ]
    assert "vector<long>" in service.notifications[-1][1]["contentChanges"][0]["text"]


def test_clangd_advertises_inactive_regions_client_capability():
    service = FakeClangdService()

    assert service._text_document_capabilities()[
        "inactiveRegionsCapabilities"
    ] == {"inactiveRegions": True}


def test_default_clangd_prefers_newest_supported_versioned_executable(
    monkeypatch,
):
    paths = {
        "clangd-20": "/usr/bin/clangd-20",
        "clangd-19": "/usr/bin/clangd-19",
        "clangd": "/usr/bin/clangd",
    }
    versions = {
        "/usr/bin/clangd-20": 16,
        "/usr/bin/clangd-19": 19,
        "/usr/bin/clangd": 21,
    }
    monkeypatch.setattr(
        clangd_services.shutil,
        "which",
        paths.get,
    )

    def run(command, **kwargs):
        major = versions[command[0]]
        return type(
            "Probe",
            (),
            {
                "returncode": 0,
                "stdout": f"Debian clangd version {major}.1.0\n",
                "stderr": "",
            },
        )()

    monkeypatch.setattr(clangd_services.subprocess, "run", run)
    clangd_services._default_clangd_command.cache_clear()
    try:
        assert (
            clangd_services._default_clangd_command()
            == "/usr/bin/clangd-19"
        )
    finally:
        clangd_services._default_clangd_command.cache_clear()


def test_default_clangd_rejects_old_unversioned_executable(monkeypatch):
    monkeypatch.setattr(
        clangd_services.shutil,
        "which",
        lambda command: "/usr/bin/clangd" if command == "clangd" else None,
    )
    monkeypatch.setattr(
        clangd_services.subprocess,
        "run",
        lambda command, **kwargs: type(
            "Probe",
            (),
            {
                "returncode": 0,
                "stdout": "Debian clangd version 14.0.6\n",
                "stderr": "",
            },
        )(),
    )
    clangd_services._default_clangd_command.cache_clear()
    try:
        with pytest.raises(
            clangd_services.ClangdUnavailableError,
            match="clangd 17",
        ):
            clangd_services._default_clangd_command()
    finally:
        clangd_services._default_clangd_command.cache_clear()


def test_selected_absolute_clangd_path_is_accepted(tmp_path):
    executable = tmp_path / "clangd-19"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    service = clangd_services.ClangdService(
        "cpp",
        command=str(executable),
        cpp_standard_library_paths=(),
    )

    assert service._find_executable() == str(executable)


def test_semantic_tokens_include_current_official_inactive_regions_notification():
    service = FakeClangdService()
    original_request = service._request_locked

    def request_with_inactive_regions(method, params):
        if method == "textDocument/semanticTokens/full":
            uri = params["textDocument"]["uri"]
            service._handle_server_notification(
                {
                    "jsonrpc": "2.0",
                    "method": "textDocument/inactiveRegions",
                    "params": {
                        "textDocument": {
                            "uri": uri,
                        },
                        "regions": [
                            {
                                "start": {"line": 1, "character": 0},
                                # 😀 occupies two UTF-16 code units.
                                "end": {"line": 1, "character": 8},
                            }
                        ],
                    },
                }
            )
        return original_request(method, params)

    service._request_locked = request_with_inactive_regions

    result = service.semantic_tokens(
        "user:2:cpp",
        "#if 0\n😀value;\n#endif\n",
    )

    assert result["inactive_regions_supported"] is True
    assert result["inactive_regions"] == [
        {
            "start": {"line": 1, "character": 0},
            "end": {"line": 1, "character": 8},
        }
    ]


def test_inactive_regions_compatibility_shape_and_valid_empty_notification():
    service = FakeClangdService()
    original_request = service._request_locked

    def request_with_legacy_notification(method, params):
        if method == "textDocument/semanticTokens/full":
            service._handle_server_notification(
                {
                    "method": "textDocument/inactiveRegions",
                    "params": {
                        "uri": params["textDocument"]["uri"],
                        "regions": [],
                    },
                }
            )
        return original_request(method, params)

    service._request_locked = request_with_legacy_notification

    result = service.semantic_tokens("user:2:cpp", "int value;\n")

    assert result["inactive_regions"] == []
    assert result["inactive_regions_supported"] is True


def test_semantic_response_waits_for_adjacent_inactive_regions_notification():
    service = FakeClangdService()
    service._server_capabilities_received({"inactiveRegionsProvider": True})
    original_request = service._request_locked
    timers = []

    def request_before_notification(method, params):
        if method == "textDocument/semanticTokens/full":
            uri = params["textDocument"]["uri"]
            state = next(iter(service._documents.values()))
            timer = threading.Timer(
                0.01,
                service._handle_server_notification,
                args=(
                    {
                        "method": "textDocument/inactiveRegions",
                        "params": {
                            "textDocument": {
                                "uri": uri,
                                "version": state.version,
                            },
                            "regions": [
                                {
                                    "start": {"line": 0, "character": 0},
                                    "end": {"line": 0, "character": 3},
                                }
                            ],
                        },
                    },
                ),
            )
            timers.append(timer)
            timer.start()
        return original_request(method, params)

    service._request_locked = request_before_notification
    try:
        result = service.semantic_tokens("user:2:cpp", "int value;\n")
    finally:
        for timer in timers:
            timer.join()

    assert result["inactive_regions_supported"] is True
    assert result["inactive_regions"] == [
        {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 3},
        }
    ]


def test_inactive_regions_reject_stale_version_and_malformed_ranges_atomically():
    service = FakeClangdService()
    original_request = service._request_locked

    def request_with_invalid_notifications(method, params):
        if method == "textDocument/semanticTokens/full":
            uri = params["textDocument"]["uri"]
            state = next(iter(service._documents.values()))
            for version, regions in (
                (
                    state.version - 1,
                    [
                        {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 3},
                        }
                    ],
                ),
                (
                    state.version,
                    [
                        {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 3},
                        },
                        {
                            "start": {"line": 99, "character": 0},
                            "end": {"line": 99, "character": 1},
                        },
                    ],
                ),
            ):
                service._handle_server_notification(
                    {
                        "method": "textDocument/inactiveRegions",
                        "params": {
                            "textDocument": {
                                "uri": uri,
                                "version": version,
                            },
                            "regions": regions,
                        },
                    }
                )
        return original_request(method, params)

    service._request_locked = request_with_invalid_notifications

    result = service.semantic_tokens("user:2:cpp", "int value;\n")

    assert result["inactive_regions"] == []
    assert result["inactive_regions_supported"] is False


def test_inactive_regions_reject_range_count_above_browser_safety_limit(
    monkeypatch,
):
    monkeypatch.setattr(
        clangd_services,
        "CLANGD_INACTIVE_REGIONS_MAX_RANGES",
        1,
    )
    raw_range = {
        "start": {"line": 0, "character": 0},
        "end": {"line": 0, "character": 1},
    }

    assert (
        clangd_services._validated_inactive_regions(
            [raw_range, raw_range],
            "0123456789",
        )
        is None
    )


def test_did_change_and_reset_clear_inactive_region_cycles():
    service = FakeClangdService()
    original_request = service._request_locked
    notify = True

    def maybe_notify(method, params):
        if method == "textDocument/semanticTokens/full" and notify:
            uri = params["textDocument"]["uri"]
            state = next(iter(service._documents.values()))
            service._handle_server_notification(
                {
                    "method": "textDocument/inactiveRegions",
                    "params": {
                        "textDocument": {
                            "uri": uri,
                            "version": state.version,
                        },
                        "regions": [
                            {
                                "start": {"line": 0, "character": 0},
                                "end": {"line": 0, "character": 3},
                            }
                        ],
                    },
                }
            )
        return original_request(method, params)

    service._request_locked = maybe_notify
    first = service.semantic_tokens("user:2:cpp", "int value;\n")
    notify = False
    changed = service.semantic_tokens("user:2:cpp", "long value;\n")
    service._reset_locked()
    reopened = service.semantic_tokens("user:2:cpp", "long value;\n")

    assert first["inactive_regions_supported"] is True
    assert changed["inactive_regions"] == []
    assert changed["inactive_regions_supported"] is False
    assert reopened["inactive_regions"] == []
    assert reopened["inactive_regions_supported"] is False


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


@pytest.mark.parametrize(
    ("language", "initial_flags"),
    (
        ("c", ["-xc", "-std=c11"]),
        ("cpp", ["-xc++", "-std=c++20", "-nostdinc++"]),
    ),
)
def test_clangd_uses_managed_judge_headers_inside_sandbox(
    tmp_path,
    language,
    initial_flags,
):
    root = tmp_path / "editor-toolchain"
    cpp_include = root / "usr/include/c++/12"
    eigen_include = root / "usr/include/eigen3"
    mkl_include = root / "opt/mkl/include"
    for path in (cpp_include, eigen_include, mkl_include):
        path.mkdir(parents=True)
    toolchain = EditorToolchain(
        root=root,
        c_include_paths=(mkl_include,),
        cpp_include_paths=(cpp_include, eigen_include, mkl_include),
        required_headers=(),
        source_image_reference="numericaloj-judger:deploy-test",
        source_image_id="sha256:test",
    )

    service = clangd_services.ClangdService(
        language,
        editor_toolchain=toolchain,
    )

    assert service.sandbox_read_paths == (root,)
    assert service.editor_toolchain is toolchain
    expected_include_paths = (
        (mkl_include,)
        if language == "c"
        else (cpp_include, eigen_include, mkl_include)
    )
    managed_initial_flags = [
        *initial_flags[:2],
        "-nostdinc",
        *initial_flags[2:],
    ]
    assert service._initialization_options()["fallbackFlags"] == [
        *managed_initial_flags,
        *[
            item
            for path in expected_include_paths
            for item in ("-isystem", str(path))
        ],
    ]


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


def test_mkl_runtime_probe_matches_public_header_declaration_kinds():
    source, expected_tokens = clangd_services._MKL_SEMANTIC_PROBE

    assert "#include <mkl.h>" in source
    assert "MKLVersion" in source
    assert "MKL_Get_Version" in source
    assert expected_tokens == {
        "MKLVersion": {"class"},
        "MKL_INT": {"macro"},
        "MKL_Get_Version": {"function"},
    }


@pytest.mark.parametrize("inactive_supported", (True, False))
def test_runtime_verification_requires_inactive_region_notifications(
    monkeypatch,
    inactive_supported,
):
    class RuntimeService:
        editor_toolchain = None

        def legend(self):
            return {
                "tokenTypes": ["variable", "class", "function"],
                "tokenModifiers": [],
            }

        def semantic_tokens(self, document_key, source):
            result = {
                "data": [0, 0, 1, 0, 0],
                "result_id": document_key,
            }
            if document_key == "runtime-inactive-region-probe":
                result.update(
                    {
                        "inactive_regions_supported": inactive_supported,
                        "inactive_regions": (
                            [
                                {
                                    "start": {"line": 1, "character": 0},
                                    "end": {"line": 1, "character": 31},
                                }
                            ]
                            if inactive_supported
                            else []
                        ),
                    }
                )
            return result

        def close(self):
            return None

    monkeypatch.setattr(
        clangd_services,
        "ClangdService",
        lambda _language: RuntimeService(),
    )

    def observed_tokens(source, _legend, _data):
        if "HostFileVisible" in source:
            return {"HostFileVisible": {"variable"}}
        return {
            "vector": {"class"},
            "string": {"class"},
            "deque": {"class"},
            "tuple": {"class"},
            "memset": {"function"},
        }

    monkeypatch.setattr(
        clangd_services,
        "_semantic_token_types_by_spelling",
        observed_tokens,
    )

    if inactive_supported:
        clangd_services.verify_clangd_runtime()
    else:
        with pytest.raises(RuntimeError, match="条件编译区域"):
            clangd_services.verify_clangd_runtime()


def test_semantic_tokens_reject_concurrent_request_without_queueing():
    service = FakeClangdService()
    service._semantic_request_gate.acquire()
    try:
        with pytest.raises(language_server_services.LanguageServiceBusyError):
            service.semantic_tokens("user:2:cpp", "int value;")
    finally:
        service._semantic_request_gate.release()


def test_language_service_pool_runs_requests_on_isolated_slots_concurrently():
    pool_size = language_server_services.LANGUAGE_SERVICE_POOL_SIZE
    barrier = threading.Barrier(pool_size)
    entered = []
    entered_lock = threading.Lock()

    class FakePooledService:
        def __init__(self, slot):
            self.slot = slot

        def semantic_tokens(self, document_key, source):
            with entered_lock:
                entered.append((self.slot, document_key, source))
            barrier.wait(timeout=2)
            return {"data": [0, 0, 1, 0, 0], "result_id": str(self.slot)}

        def close(self):
            return None

    pool = language_server_services.SemanticLanguageServicePool(
        service_name="test-language-server",
        size=pool_size,
        factory=FakePooledService,
    )
    try:
        requests = tuple(
            (f"user:{index}:cpp", f"int value_{index};")
            for index in range(pool_size)
        )
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            results = list(
                executor.map(
                    lambda request: pool.semantic_tokens(*request),
                    requests,
                )
            )
    finally:
        pool.close()

    assert len(entered) == pool_size
    assert {slot for slot, _, _ in entered} == set(range(pool_size))
    assert {result["result_id"] for result in results} == {
        str(slot) for slot in range(pool_size)
    }


def test_language_service_limits_cover_large_submissions():
    assert language_server_services.LANGUAGE_SERVICE_POOL_SIZE == 10
    assert language_server_services.LANGUAGE_SOURCE_MAX_BYTES == 4 * 1024 * 1024
    assert language_server_services.LANGUAGE_REQUEST_TIMEOUT_SECONDS == 60.0


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


def test_json_rpc_frame_reader_collects_fragmented_body():
    payload = (
        b'{"jsonrpc":"2.0","id":7,"result":{"data":['
        + b",".join(str(index).encode("ascii") for index in range(20_000))
        + b"]}}"
    )

    class FragmentedStream(BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 7) if size >= 0 else 7)

    stream = FragmentedStream(
        f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload
    )

    message = clangd_services.ClangdService._read_message(stream)

    assert message["id"] == 7
    assert message["result"]["data"][-1] == 19_999


def test_json_rpc_frame_reader_rejects_truly_truncated_fragmented_body():
    payload = b'{"jsonrpc":"2.0","id":8,"result":{"data":[0,1,2]}}'

    class FragmentedStream(BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 3) if size >= 0 else 3)

    stream = FragmentedStream(
        f"Content-Length: {len(payload) + 4}\r\n\r\n".encode("ascii") + payload
    )

    with pytest.raises(clangd_services.ClangdProtocolError, match="响应体被截断"):
        clangd_services.ClangdService._read_message(stream)


def test_json_rpc_frame_reader_rejects_oversized_body(monkeypatch):
    monkeypatch.setattr(language_server_services, "LANGUAGE_RESPONSE_MAX_BYTES", 3)
    stream = BytesIO(b"Content-Length: 4\r\n\r\nnull")
    with pytest.raises(clangd_services.ClangdProtocolError, match="大小无效"):
        clangd_services.ClangdService._read_message(stream)
