from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import threading

import pytest

from oj_modules.vibehub import maintenance, quotas, storage


def _snapshot(root: Path, version: int, *, slug: str = "demo-vibe") -> Path:
    target = root / slug / "versions" / f"v{version}"
    app = target / "app"
    app.mkdir(parents=True)
    (app / "main.py").write_text(f"VERSION = {version}\n", encoding="utf-8")
    (target / "package.zip").write_bytes(f"package-{version}".encode())
    return target


class _FakeCursor:
    def __init__(self, connection) -> None:
        self.connection = connection
        self.rows = []

    def __enter__(self):
        self.connection.events.append("cursor-enter")
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.connection.events.append("cursor-exit")

    def execute(self, query, params=()) -> None:
        normalized = " ".join(str(query).split())
        if "FROM vibehub_projects" in normalized:
            self.connection.events.append("projects-for-update")
            self.rows = self.connection.project_rows
        elif "FROM vibehub_versions" in normalized:
            self.connection.events.append("versions-for-update")
            self.rows = self.connection.version_rows
        else:  # pragma: no cover - 新查询必须显式纳入测试事实
            raise AssertionError(f"unexpected query: {normalized}")
        self.connection.params.append(tuple(params))

    def fetchall(self):
        return list(self.rows)


class _FakeConnection:
    def __init__(self, *, project_rows=(), version_rows=()) -> None:
        self.project_rows = list(project_rows)
        self.version_rows = list(version_rows)
        self.events = []
        self.params = []
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def rollback(self) -> None:
        self.events.append("rollback")
        self.rolled_back = True

    def close(self) -> None:
        self.events.append("close")
        self.closed = True


def _connection_for_demo() -> _FakeConnection:
    return _FakeConnection(
        project_rows=(
            {
                "id": 7,
                "slug": "demo-vibe",
                "latest_version_id": 22,
                "public_version_id": None,
                "review_version_id": None,
            },
        ),
        version_rows=(
            {"project_id": 7, "id": 11, "version_number": 1},
            {"project_id": 7, "id": 22, "version_number": 2},
        ),
    )


def _empty_connection() -> _FakeConnection:
    return _FakeConnection(project_rows=(), version_rows=())


def test_background_gc_reclaims_aged_marker_without_another_user_write(tmp_path):
    retired = _snapshot(tmp_path, 1)
    live = _snapshot(tmp_path, 2)
    with quotas.storage_mutation_lock(tmp_path):
        marked = storage.prune_project_snapshots(
            "demo-vibe",
            {1, 2},
            {2},
            upload_root=tmp_path,
            now=100,
            grace_seconds=3_600,
        )
        staging = quotas.create_upload_staging_directory(tmp_path)
        staged_snapshot = staging / "snapshot"
        staged_snapshot.mkdir()
        (staged_snapshot / "partial.zip").write_bytes(b"unfinished")
        os.utime(staging, (100, 100))

    marker = tmp_path / "demo-vibe" / ".gc" / "v1.json"
    assert marked.newly_retired == (1,)
    assert retired.is_dir()
    assert marker.is_file()
    assert staging.is_dir()

    connection = _connection_for_demo()
    result = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=lambda: connection,
        now=3_700,
        snapshot_grace_seconds=3_600,
        upload_staging_grace_seconds=3_600,
    )

    assert result.snapshots.deleted_expired == (("demo-vibe", 1),)
    assert result.upload_staging.deleted_expired == (staging.name,)
    assert not retired.exists()
    assert not marker.exists()
    assert not staging.exists()
    assert live.is_dir()
    assert connection.rolled_back is True
    assert connection.closed is True


def test_background_gc_reclaims_db_unknown_version_and_crashed_clone(tmp_path):
    live = _snapshot(tmp_path, 1)
    orphan = _snapshot(tmp_path, 2)
    clone = tmp_path / "demo-vibe" / "versions" / (".v3.clone-" + "a" * 32)
    clone.mkdir()
    (clone / "partial").write_bytes(b"partial-clone")
    connection = _FakeConnection(
        project_rows=(
            {
                "id": 7,
                "slug": "demo-vibe",
                "latest_version_id": 11,
                "public_version_id": None,
                "review_version_id": None,
            },
        ),
        version_rows=(
            {"project_id": 7, "id": 11, "version_number": 1},
        ),
    )

    first = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=lambda: connection,
        now=100,
    )

    assert first.crash_orphans.newly_marked == (
        "clone:demo-vibe:.v3.clone-" + "a" * 32,
        "version:demo-vibe:v2",
    )
    assert first.crash_orphans.deleted_expired == ()
    assert orphan.is_dir()
    assert clone.is_dir()

    expired = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=lambda: _FakeConnection(
            project_rows=connection.project_rows,
            version_rows=connection.version_rows,
        ),
        now=3_700,
    )

    assert expired.crash_orphans.deleted_expired == (
        "clone:demo-vibe:.v3.clone-" + "a" * 32,
        "version:demo-vibe:v2",
    )
    assert live.is_dir()
    assert not orphan.exists()
    assert not clone.exists()


def test_install_before_commit_project_orphan_uses_fresh_inode_grace(tmp_path):
    first_orphan = _snapshot(tmp_path, 1, slug="lost-vibe")
    first = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=100,
    )

    assert first.crash_orphans.newly_marked == ("project:lost-vibe",)
    assert first_orphan.is_dir()

    # 模拟用户重试时业务层清理旧孤儿，随后又在 commit 前崩溃。
    with quotas.storage_mutation_lock(tmp_path):
        assert storage.cleanup_orphan_project_storage(
            "lost-vibe",
            upload_root=tmp_path,
        )
    replacement = _snapshot(tmp_path, 1, slug="lost-vibe")
    refreshed = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=3_700,
    )

    assert refreshed.crash_orphans.refreshed_markers == ("project:lost-vibe",)
    assert refreshed.crash_orphans.deleted_expired == ()
    assert replacement.is_dir()

    expired = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=7_300,
    )

    assert expired.crash_orphans.deleted_expired == ("project:lost-vibe",)
    assert not (tmp_path / "lost-vibe").exists()


def test_orphan_gc_audits_entire_root_before_deleting(tmp_path):
    orphan = _snapshot(tmp_path, 1, slug="lost-vibe")
    maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=100,
    )
    (tmp_path / ".unexpected").write_text("stop", encoding="utf-8")

    with pytest.raises(storage.SnapshotReconciliationError, match="未知入口"):
        maintenance.run_storage_gc_once(
            upload_root=tmp_path,
            connection_factory=_empty_connection,
            now=3_700,
        )

    assert orphan.is_dir()


def test_orphan_gc_excludes_builtin_project_roots(tmp_path):
    builtin = tmp_path / "circle-cat" / "builtin" / "releases" / ("a" * 64)
    builtin.mkdir(parents=True)
    (builtin / "package.zip").write_bytes(b"builtin")

    result = maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=10_000,
    )

    assert result.crash_orphans.newly_marked == ()
    assert result.crash_orphans.deleted_expired == ()
    assert builtin.is_dir()


def test_orphan_gc_rejects_non_numeric_marker_time_without_deleting(tmp_path):
    orphan = _snapshot(tmp_path, 1, slug="lost-vibe")
    maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=_empty_connection,
        now=100,
    )
    marker = next(
        (tmp_path / storage.CRASH_ORPHAN_MARKER_DIRECTORY).glob("*.json")
    )
    payload = json.loads(marker.read_text(encoding="utf-8"))
    payload["orphaned_at"] = True
    marker.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    marker.chmod(0o600)

    with pytest.raises(storage.SnapshotReconciliationError, match="无法解析"):
        maintenance.run_storage_gc_once(
            upload_root=tmp_path,
            connection_factory=_empty_connection,
            now=10_000,
        )

    assert orphan.is_dir()


def test_orphan_gc_never_accepts_grace_shorter_than_one_hour(tmp_path):
    with quotas.storage_mutation_lock(tmp_path):
        with pytest.raises(storage.SnapshotReconciliationError, match="不得少于一小时"):
            storage.reclaim_expired_crash_orphans(
                (),
                upload_root=tmp_path,
                now=100,
                grace_seconds=3_599,
            )


def test_gc_holds_storage_then_db_locks_before_reclaim(monkeypatch, tmp_path):
    events = []
    lock_held = False

    @contextmanager
    def fake_storage_lock(root):
        nonlocal lock_held
        assert Path(root) == tmp_path
        lock_held = True
        events.append("storage-enter")
        try:
            yield tmp_path
        finally:
            events.append("storage-exit")
            lock_held = False

    connection = _connection_for_demo()

    def connect():
        assert lock_held is True
        events.append("connect")
        return connection

    def reclaim_snapshots(states, **kwargs):
        assert lock_held is True
        assert connection.events[-1] == "versions-for-update"
        assert states == (
            {
                "slug": "demo-vibe",
                "known_versions": {1, 2},
                "live_versions": {2},
            },
        )
        events.append("snapshot-reclaim")
        return storage.SnapshotRetirementGCResult((), (), (), 0)

    def reclaim_orphans(states, **kwargs):
        assert lock_held is True
        assert connection.events[-1] == "versions-for-update"
        events.append("orphan-reclaim")
        return storage.CrashOrphanGCResult((), (), (), (), (), 0)

    def reclaim_staging(root, **kwargs):
        assert lock_held is True
        events.append("staging-reclaim")
        return quotas.UploadStagingReclaimResult((), (), (), 0)

    monkeypatch.setattr(maintenance.quotas, "storage_mutation_lock", fake_storage_lock)
    monkeypatch.setattr(
        maintenance.storage,
        "reclaim_expired_crash_orphans",
        reclaim_orphans,
    )
    monkeypatch.setattr(
        maintenance.storage,
        "reclaim_expired_retired_snapshots",
        reclaim_snapshots,
    )
    monkeypatch.setattr(
        maintenance.quotas,
        "reclaim_expired_upload_staging",
        reclaim_staging,
    )

    maintenance.run_storage_gc_once(
        upload_root=tmp_path,
        connection_factory=connect,
    )

    assert events == [
        "storage-enter",
        "connect",
        "orphan-reclaim",
        "snapshot-reclaim",
        "staging-reclaim",
        "storage-exit",
    ]
    assert connection.events == [
        "cursor-enter",
        "projects-for-update",
        "versions-for-update",
        "cursor-exit",
        "rollback",
        "close",
    ]


def test_gc_fails_closed_when_db_live_set_exceeds_bound(monkeypatch, tmp_path):
    monkeypatch.setattr(maintenance, "MAX_GC_PROJECTS", 1)
    connection = _FakeConnection(
        project_rows=(
            {
                "id": 1,
                "slug": "first-vibe",
                "latest_version_id": None,
                "public_version_id": None,
                "review_version_id": None,
            },
            {
                "id": 2,
                "slug": "second-vibe",
                "latest_version_id": None,
                "public_version_id": None,
                "review_version_id": None,
            },
        ),
    )
    # 任何超界事实都必须在进入文件系统回收前停止。
    called = []
    monkeypatch.setattr(
        maintenance.storage,
        "reclaim_expired_retired_snapshots",
        lambda *args, **kwargs: called.append("snapshots"),
    )
    monkeypatch.setattr(
        maintenance.quotas,
        "reclaim_expired_upload_staging",
        lambda *args, **kwargs: called.append("staging"),
    )

    with pytest.raises(maintenance.VibeHubMaintenanceError, match="作品数量"):
        maintenance.run_storage_gc_once(
            upload_root=tmp_path,
            connection_factory=lambda: connection,
        )

    assert called == []
    assert connection.rolled_back is True
    assert connection.closed is True


@pytest.mark.parametrize("value", [59, 86_401, True, float("nan"), float("inf")])
def test_configured_gc_interval_is_strictly_bounded(value):
    with pytest.raises(ValueError, match="VIBEHUB_STORAGE_GC_INTERVAL_SECONDS"):
        maintenance._maintenance_kwargs_from_config(
            {"VIBEHUB_STORAGE_GC_INTERVAL_SECONDS": value}
        )


def test_daemon_start_is_idempotent_and_failure_does_not_stop_retry(tmp_path):
    succeeded = threading.Event()
    attempts = []

    def run_once():
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            raise RuntimeError("transient database outage")
        succeeded.set()

    service = maintenance.VibeHubStorageGC(
        upload_root=tmp_path,
        interval_seconds=0.05,
        run_once_callback=run_once,
    )
    service.start()
    first_thread = service._thread
    service.start()

    try:
        assert service._thread is first_thread
        assert succeeded.wait(2)
        assert service.is_running() is True
        assert len(attempts) >= 2
    finally:
        service.stop()

    assert service.is_running() is False
