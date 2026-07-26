from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import queue
import threading
import uuid

import pytest

from oj_modules import clangd_services
from oj_modules.repository import language as repository_language
from oj_modules.repository import storage
from oj_modules.repository import tree


def test_repository_language_pool_has_a_separate_bounded_capacity():
    assert clangd_services.REPOSITORY_LANGUAGE_SERVICE_POOL_SIZE == 4
    assert clangd_services.REPOSITORY_SEMANTIC_MAX_TOKENS == 500_000


class _Connection:
    class _Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    def cursor(self):
        return self._Cursor()

    def close(self):
        return None


def _row(
    entry_id: int,
    relative_path: str,
    *,
    entry_type: str = "file",
    content: bytes = b"",
):
    return {
        "id": entry_id,
        "entry_type": entry_type,
        "relative_path": relative_path,
        "file_size": len(content),
        "content_sha256": hashlib.sha256(content).hexdigest(),
    }


def _patch_repository_reads(monkeypatch, *, generation, rows, contents):
    @contextmanager
    def locked(_owner_id, *, exclusive=False):
        assert exclusive is False
        yield {"storage_key": "a" * 32}

    monkeypatch.setattr(tree, "repository_user_lock", locked)
    monkeypatch.setattr(repository_language, "get_db_connection", _Connection)
    monkeypatch.setattr(
        tree,
        "_load_state",
        lambda _cursor, _owner_id: {"repository_generation": generation},
    )
    monkeypatch.setattr(tree, "_load_entries", lambda _cursor, _owner_id: rows)
    monkeypatch.setattr(
        tree,
        "_find_entry",
        lambda _cursor, owner_id, *, entry_id: next(
            (
                row
                for row in rows
                if int(row["id"]) == int(entry_id) and int(owner_id) == 7
            ),
            None,
        ),
    )
    monkeypatch.setattr(
        storage,
        "read_file",
        lambda storage_key, relative_path: contents[relative_path],
    )


def test_repository_semantic_target_is_derived_from_owned_metadata(
    monkeypatch,
):
    rows = [_row(42, "NA/BSplineN.h", content=b"class BSplineN {};")]
    _patch_repository_reads(
        monkeypatch,
        generation=9,
        rows=rows,
        contents={"NA/BSplineN.h": b"class BSplineN {};"},
    )

    target = repository_language.get_repository_semantic_target(7, 42, "cpp")

    assert target == repository_language.RepositorySemanticTarget(
        owner_id=7,
        storage_key="a" * 32,
        generation=9,
        entry_id=42,
        relative_path="NA/BSplineN.h",
        language="cpp",
    )
    with pytest.raises(tree.RepositoryDomainError, match="不存在"):
        repository_language.get_repository_semantic_target(8, 42, "cpp")
    with pytest.raises(tree.RepositoryDomainError, match="语言不匹配"):
        repository_language.get_repository_semantic_target(7, 42, "python")


def test_repository_semantic_snapshot_preserves_tree_and_checks_integrity(
    monkeypatch,
):
    header = b"class Dependency {};\n"
    source = b'#include "A/Dependency.h"\nDependency value;\n'
    rows = [
        _row(1, "A", entry_type="directory"),
        _row(2, "A/Empty", entry_type="directory"),
        _row(3, "A/Dependency.h", content=header),
        _row(4, "main.cpp", content=source),
    ]
    contents = {
        "A/Dependency.h": header,
        "main.cpp": source,
    }
    _patch_repository_reads(
        monkeypatch,
        generation=11,
        rows=rows,
        contents=contents,
    )
    target = repository_language.RepositorySemanticTarget(
        owner_id=7,
        storage_key="a" * 32,
        generation=11,
        entry_id=4,
        relative_path="main.cpp",
        language="cpp",
    )

    snapshot = repository_language.capture_repository_semantic_snapshot(target)

    assert snapshot.directories == ("A", "A/Empty")
    assert {
        item.relative_path: item.content for item in snapshot.files
    } == contents
    assert snapshot.total_size == len(header) + len(source)

    contents["main.cpp"] = b"tampered"
    with pytest.raises(tree.RepositoryDomainError, match="校验失败"):
        repository_language.capture_repository_semantic_snapshot(target)


def test_repository_semantic_snapshot_rejects_generation_change_before_reads(
    monkeypatch,
):
    reads = []
    rows = [_row(4, "main.cpp", content=b"int main() {}")]
    _patch_repository_reads(
        monkeypatch,
        generation=12,
        rows=rows,
        contents={"main.cpp": b"int main() {}"},
    )
    monkeypatch.setattr(
        storage,
        "read_file",
        lambda *_args: reads.append(True),
    )
    target = repository_language.RepositorySemanticTarget(
        owner_id=7,
        storage_key="a" * 32,
        generation=11,
        entry_id=4,
        relative_path="main.cpp",
        language="cpp",
    )

    with pytest.raises(tree.RepositoryDomainError, match="已变化") as raised:
        repository_language.capture_repository_semantic_snapshot(target)

    assert raised.value.status == 409
    assert reads == []


def test_repository_semantic_result_rechecks_generation(monkeypatch):
    expected = repository_language.RepositorySemanticTarget(
        owner_id=7,
        storage_key="a" * 32,
        generation=11,
        entry_id=4,
        relative_path="main.cpp",
        language="cpp",
    )
    monkeypatch.setattr(
        repository_language,
        "get_repository_semantic_target",
        lambda *_args: expected,
    )

    repository_language.ensure_repository_semantic_target_current(expected)

    monkeypatch.setattr(
        repository_language,
        "get_repository_semantic_target",
        lambda *_args: repository_language.RepositorySemanticTarget(
            owner_id=7,
            storage_key="a" * 32,
            generation=12,
            entry_id=4,
            relative_path="main.cpp",
            language="cpp",
        ),
    )
    with pytest.raises(tree.RepositoryDomainError) as raised:
        repository_language.ensure_repository_semantic_target_current(
            expected
        )
    assert raised.value.code == "repository_changed"
    assert raised.value.status == 409


class _FakeRepositoryClangdService(
    clangd_services.RepositoryClangdService
):
    def __init__(self):
        super().__init__(
            "cpp",
            workspace_key=f"repository-test-{uuid.uuid4().hex}",
            cpp_standard_library_paths=(),
        )
        self.notifications = []
        self.requests = []
        self._legend = {
            "tokenTypes": ["variable", "class"],
            "tokenModifiers": [],
        }

    def _start_locked(self):
        return None

    def _notify_locked(self, method, params):
        self.notifications.append((method, params))

    def _request_locked(self, method, params):
        self.requests.append((method, params))
        return {"data": [0, 0, 5, 1, 0]}


def _semantic_snapshot(
    owner_id: int,
    generation: int,
    entry_id: int,
    relative_path: str,
    files: dict[str, bytes],
):
    target = repository_language.RepositorySemanticTarget(
        owner_id=owner_id,
        storage_key=(f"{owner_id:x}" * 32)[:32],
        generation=generation,
        entry_id=entry_id,
        relative_path=relative_path,
        language="cpp",
    )
    directories = {
        "/".join(path.split("/")[:index])
        for path in files
        for index in range(1, len(path.split("/")))
    }
    return repository_language.RepositorySemanticSnapshot(
        target=target,
        directories=tuple(sorted(directories)),
        files=tuple(
            repository_language.RepositorySemanticFile(path, content)
            for path, content in sorted(files.items())
        ),
        total_size=sum(len(content) for content in files.values()),
    )


def test_repository_clangd_uses_true_path_and_unsaved_source_overlay():
    saved_source = b'#include "A/Dependency.h"\nDependency saved;\n'
    snapshot = _semantic_snapshot(
        7,
        3,
        42,
        "NA/main.cpp",
        {
            "A/Dependency.h": b"class Dependency {};\n",
            "NA/main.cpp": saved_source,
        },
    )
    service = _FakeRepositoryClangdService()
    try:
        result = service.semantic_tokens(
            snapshot.target,
            '#include "A/Dependency.h"\nDependency unsaved;\n',
            lambda: snapshot,
        )

        opened = service.notifications[0]
        assert opened[0] == "textDocument/didOpen"
        assert opened[1]["textDocument"]["uri"].endswith(
            "/repository/NA/main.cpp"
        )
        assert "Dependency unsaved" in opened[1]["textDocument"]["text"]
        assert (
            service._repository_root() / "NA" / "main.cpp"
        ).read_bytes() == saved_source
        assert result["result_id"].startswith("repository:3:1:")
        flags = service._initialization_options()["fallbackFlags"]
        assert flags[-2:] == ["-I", str(service._repository_root())]
    finally:
        service.close()


def test_repository_clangd_reuses_generation_and_scrubs_before_tenant_switch():
    first = _semantic_snapshot(
        7,
        1,
        1,
        "A/main.cpp",
        {"A/main.cpp": b"int first;"},
    )
    second = _semantic_snapshot(
        8,
        1,
        2,
        "B/main.cpp",
        {"B/main.cpp": b"int second;"},
    )
    service = _FakeRepositoryClangdService()
    first_loads = 0
    try:
        def load_first():
            nonlocal first_loads
            first_loads += 1
            return first

        service.semantic_tokens(first.target, "int first;", load_first)
        service.semantic_tokens(
            first.target,
            "int first_changed;",
            lambda: pytest.fail("同一代次不应重建仓库快照"),
        )
        assert first_loads == 1

        def load_second():
            assert not service._workspace().exists()
            return second

        service.semantic_tokens(second.target, "int second;", load_second)

        assert not (service._repository_root() / "A").exists()
        assert (service._repository_root() / "B" / "main.cpp").is_file()
        open_uris = [
            params["textDocument"]["uri"]
            for method, params in service.notifications
            if method == "textDocument/didOpen"
        ]
        assert len(open_uris) == 2
        assert "/repository/A/main.cpp" in open_uris[0]
        assert "/repository/B/main.cpp" in open_uris[1]
    finally:
        service.close()


def test_repository_clangd_loader_failure_leaves_slot_inactive_and_clean():
    first = _semantic_snapshot(
        7,
        1,
        1,
        "A/main.cpp",
        {"A/main.cpp": b"int first;"},
    )
    second = _semantic_snapshot(
        8,
        1,
        2,
        "B/main.cpp",
        {"B/main.cpp": b"int second;"},
    )
    service = _FakeRepositoryClangdService()
    try:
        service.semantic_tokens(first.target, "int first;", lambda: first)
        with pytest.raises(RuntimeError, match="capture failed"):
            service.semantic_tokens(
                second.target,
                "int second;",
                lambda: (_ for _ in ()).throw(
                    RuntimeError("capture failed")
                ),
            )

        assert service._active_repository is None
        assert not service._workspace().exists()

        service.semantic_tokens(
            second.target,
            "int second;",
            lambda: second,
        )
        assert (service._repository_root() / "B" / "main.cpp").is_file()
    finally:
        service.close()


def test_repository_clangd_rejects_large_source_before_loading_snapshot(
    monkeypatch,
):
    snapshot = _semantic_snapshot(
        7,
        1,
        1,
        "main.cpp",
        {"main.cpp": b"int value;"},
    )
    service = _FakeRepositoryClangdService()
    loads = []
    monkeypatch.setattr(clangd_services, "LANGUAGE_SOURCE_MAX_BYTES", 3)
    try:
        with pytest.raises(ValueError, match="大小限制"):
            service.semantic_tokens(
                snapshot.target,
                "1234",
                lambda: loads.append(True),
            )
    finally:
        service.close()

    assert loads == []


def test_repository_clangd_pool_allows_only_one_request_per_owner():
    entered = threading.Event()
    release = threading.Event()

    class BlockingService:
        def semantic_tokens(self, target, source, snapshot_loader):
            entered.set()
            assert release.wait(timeout=2)
            return {"data": [], "result_id": "done"}

    pool = clangd_services.RepositoryClangdServicePool.__new__(
        clangd_services.RepositoryClangdServicePool
    )
    pool.language = "cpp"
    pool.size = 1
    pool._services = (BlockingService(),)
    pool._available = queue.LifoQueue(maxsize=1)
    pool._available.put_nowait(pool._services[0])
    pool._owners_lock = threading.Lock()
    pool._active_owners = set()
    snapshot = _semantic_snapshot(
        7,
        1,
        1,
        "main.cpp",
        {"main.cpp": b"int value;"},
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        active = executor.submit(
            pool.semantic_tokens,
            snapshot.target,
            "int value;",
            lambda: snapshot,
        )
        assert entered.wait(timeout=2)
        with pytest.raises(
            clangd_services.LanguageServiceBusyError,
            match="同一用户",
        ):
            pool.semantic_tokens(
                snapshot.target,
                "int other;",
                lambda: snapshot,
            )
        release.set()
        assert active.result(timeout=2)["result_id"] == "done"
