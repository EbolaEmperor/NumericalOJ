from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.oj_modules.vibehub import quotas, storage


def _snapshot(root: Path, version: int, *, slug="demo-vibe", content=None) -> Path:
    target = root / slug / "versions" / f"v{version}"
    app = target / "app"
    app.mkdir(parents=True)
    (app / "main.py").write_text(content or f"VERSION = {version}\n", encoding="utf-8")
    (target / "package.zip").write_bytes(f"package-{version}".encode())
    return target


def _retire(
    root: Path,
    *,
    slug="demo-vibe",
    known=(1, 2),
    live=(2,),
    now=0,
) -> None:
    result = storage.prune_project_snapshots(
        slug,
        set(known),
        set(live),
        upload_root=root,
        now=now,
        grace_seconds=storage.SNAPSHOT_RETIREMENT_GRACE_SECONDS,
    )
    assert result.deleted_expired == ()


def test_update_retry_removes_only_uncommitted_same_version_and_clone(tmp_path):
    _snapshot(tmp_path, 1)
    orphan = _snapshot(tmp_path, 2, content="ORPHAN = True\n")
    clone = tmp_path / "demo-vibe" / "versions" / (
        ".v2.clone-" + "a" * 32
    )
    clone.mkdir()
    (clone / "partial").write_bytes(b"partial")

    with quotas.storage_mutation_lock(tmp_path):
        removed = storage.cleanup_uncommitted_version_snapshot(
            "demo-vibe",
            2,
            {1},
            upload_root=tmp_path,
        )
        assert not orphan.exists()
        assert not clone.exists()
        retried = storage.clone_snapshot(
            "demo-vibe",
            1,
            2,
            upload_root=tmp_path,
        )

    assert removed is True
    assert not clone.exists()
    assert (retried / "app" / "main.py").read_text(encoding="utf-8") == "VERSION = 1\n"


def test_create_retry_cleans_strict_orphan_slug_tree(tmp_path):
    _snapshot(tmp_path, 1, slug="retry-vibe")
    storage.write_pointer(
        "retry-vibe",
        "latest",
        version_number=1,
        version_id=99,
        upload_root=tmp_path,
    )

    with quotas.storage_mutation_lock(tmp_path):
        assert storage.cleanup_orphan_project_storage(
            "retry-vibe",
            upload_root=tmp_path,
        ) is True

    assert not (tmp_path / "retry-vibe").exists()


def test_review_live_set_keeps_three_snapshots_and_drops_db_orphan(tmp_path):
    for version in (1, 2, 3, 4):
        _snapshot(tmp_path, version)

    with quotas.storage_mutation_lock(tmp_path):
        result = storage.prune_project_snapshots(
            "demo-vibe",
            {1, 2, 3},
            {1, 2, 3},
            upload_root=tmp_path,
            now=100,
        )

    assert result.retained == (1, 2, 3)
    assert result.deleted_orphans == (4,)
    assert sorted(
        path.name for path in (tmp_path / "demo-vibe" / "versions").iterdir()
    ) == ["v1", "v2", "v3"]
    assert not (tmp_path / "demo-vibe" / ".gc").exists()


def test_historical_metadata_survives_while_physical_snapshot_uses_grace(tmp_path):
    for version in (1, 2, 3):
        _snapshot(tmp_path, version)

    with quotas.storage_mutation_lock(tmp_path):
        first = storage.prune_project_snapshots(
            "demo-vibe",
            {1, 2, 3},
            {2, 3},
            upload_root=tmp_path,
            now=1_000,
            grace_seconds=3_600,
        )
        within_grace = storage.prune_project_snapshots(
            "demo-vibe",
            {1, 2, 3},
            {2, 3},
            upload_root=tmp_path,
            now=4_599,
            grace_seconds=3_600,
        )
        expired = storage.prune_project_snapshots(
            "demo-vibe",
            {1, 2, 3},
            {2, 3},
            upload_root=tmp_path,
            now=4_600,
            grace_seconds=3_600,
        )

    assert first.newly_retired == (1,)
    assert within_grace.retained == (1, 2, 3)
    assert expired.deleted_expired == (1,)
    assert not (tmp_path / "demo-vibe" / "versions" / "v1").exists()
    # known_version_numbers 仍包含 v1：回收只删物理快照，不删 DB 历史。
    assert expired.retained == (2, 3)


def test_retirement_marker_binds_version_to_snapshot_device_and_inode(tmp_path):
    first = _snapshot(tmp_path, 1)
    _snapshot(tmp_path, 2)

    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, now=100)

    payload = json.loads(
        (tmp_path / "demo-vibe" / ".gc" / "v1.json").read_text(encoding="utf-8")
    )
    identity = first.lstat()
    assert payload == {
        "schema_version": 2,
        "version": 1,
        "retired_at": 100.0,
        "snapshot_device": identity.st_dev,
        "snapshot_inode": identity.st_ino,
    }


def test_prequota_retirement_gc_releases_user_storage_deadlock(tmp_path):
    retired = _snapshot(tmp_path, 1)
    live = _snapshot(tmp_path, 2)
    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, now=0)
        live_bytes = quotas.logical_tree_bytes(live)
        projection = quotas.enforce_storage_quota(
            ["demo-vibe"],
            1,
            tmp_path,
            retirement_project_states=(
                {
                    "slug": "demo-vibe",
                    "known_versions": {1, 2},
                    "live_versions": {2},
                },
            ),
            user_limit_bytes=live_bytes + 1,
        )

    assert not retired.exists()
    assert live.is_dir()
    assert projection.user_existing_bytes == live_bytes
    assert projection.user_projected_bytes == live_bytes + 1


def test_prequota_repairs_commit_prune_gap_then_reclaims_on_later_quota_retry(
    tmp_path,
    monkeypatch,
):
    retired = _snapshot(tmp_path, 1)
    live = _snapshot(tmp_path, 2)
    retired_bytes = quotas.logical_tree_bytes(retired)
    live_bytes = quotas.logical_tree_bytes(live)
    states = (
        {
            "slug": "demo-vibe",
            "known_versions": {1, 2},
            "live_versions": {2},
        },
    )
    current_time = [1_000.0]
    monkeypatch.setattr(storage.time, "time", lambda: current_time[0])

    with quotas.storage_mutation_lock(tmp_path):
        # 模拟 DB 已提交 live-set，但进程尚未进入常规 prune 就退出。
        with pytest.raises(quotas.VibeHubStorageQuotaExceeded) as first_attempt:
            quotas.enforce_storage_quota(
                ["demo-vibe"],
                1,
                tmp_path,
                retirement_project_states=states,
                user_limit_bytes=live_bytes + 1,
            )

        marker_path = tmp_path / "demo-vibe" / ".gc" / "v1.json"
        payload = json.loads(marker_path.read_text(encoding="utf-8"))
        identity = retired.lstat()
        assert payload["snapshot_device"] == identity.st_dev
        assert payload["snapshot_inode"] == identity.st_ino
        assert first_attempt.value.details["current_bytes"] == (
            retired_bytes + live_bytes
        )
        assert retired.is_dir()

        current_time[0] = 4_600.0
        projection = quotas.enforce_storage_quota(
            ["demo-vibe"],
            1,
            tmp_path,
            retirement_project_states=states,
            user_limit_bytes=live_bytes + 1,
        )

    assert not retired.exists()
    assert live.is_dir()
    assert not marker_path.exists()
    assert projection.user_existing_bytes == live_bytes
    assert projection.user_projected_bytes == live_bytes + 1


def test_prequota_new_marker_never_deletes_snapshot_in_same_call(tmp_path):
    retired = _snapshot(tmp_path, 1)
    _snapshot(tmp_path, 2)

    with quotas.storage_mutation_lock(tmp_path):
        result = storage.reclaim_expired_retired_snapshots(
            (
                {
                    "slug": "demo-vibe",
                    "known_versions": {1, 2},
                    "live_versions": {2},
                },
            ),
            upload_root=tmp_path,
            now=1_000,
            grace_seconds=0,
        )

    assert result.newly_retired == (("demo-vibe", 1),)
    assert result.deleted_expired == ()
    assert retired.is_dir()


def test_prequota_never_marks_unmarked_live_snapshot(tmp_path):
    live = _snapshot(tmp_path, 1)

    with quotas.storage_mutation_lock(tmp_path):
        result = storage.reclaim_expired_retired_snapshots(
            (
                {
                    "slug": "demo-vibe",
                    "known_versions": {1},
                    "live_versions": {1},
                },
            ),
            upload_root=tmp_path,
            now=10_000,
        )

    assert result.newly_retired == ()
    assert live.is_dir()
    assert not (tmp_path / "demo-vibe" / ".gc").exists()


def test_prequota_retirement_gc_releases_retired_bytes_across_user_projects(tmp_path):
    retired = _snapshot(tmp_path, 1, slug="alpha-vibe")
    alpha_live = _snapshot(tmp_path, 2, slug="alpha-vibe")
    beta_live = _snapshot(tmp_path, 1, slug="beta-vibe")
    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, slug="alpha-vibe", now=0)
        expected_user = (
            quotas.logical_tree_bytes(alpha_live)
            + quotas.logical_tree_bytes(beta_live)
        )
        projection = quotas.enforce_storage_quota(
            ["alpha-vibe", "beta-vibe"],
            1,
            tmp_path,
            retirement_project_states=(
                {
                    "slug": "alpha-vibe",
                    "known_versions": {1, 2},
                    "live_versions": {2},
                },
                {
                    "slug": "beta-vibe",
                    "known_versions": {1},
                    "live_versions": {1},
                },
            ),
            user_limit_bytes=expected_user + 1,
        )

    assert not retired.exists()
    assert alpha_live.is_dir()
    assert beta_live.is_dir()
    assert projection.user_existing_bytes == expected_user
    assert projection.user_projected_bytes == expected_user + 1


def test_prequota_retirement_gc_keeps_snapshot_within_grace(tmp_path):
    retired = _snapshot(tmp_path, 1)
    live = _snapshot(tmp_path, 2)
    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, now=1_000)
        result = storage.reclaim_expired_retired_snapshots(
            (
                {
                    "slug": "demo-vibe",
                    "known_versions": {1, 2},
                    "live_versions": {2},
                },
            ),
            upload_root=tmp_path,
            now=4_599,
            grace_seconds=3_600,
        )

    assert result.deleted_expired == ()
    assert retired.is_dir()
    assert live.is_dir()


def test_prequota_retirement_gc_never_deletes_live_with_anomalous_marker(tmp_path):
    first = _snapshot(tmp_path, 1)
    second = _snapshot(tmp_path, 2)
    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, now=0)
        marker_path = tmp_path / "demo-vibe" / ".gc" / "v1.json"
        payload = json.loads(marker_path.read_text(encoding="utf-8"))
        payload["snapshot_inode"] += 1
        marker_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        marker_path.chmod(0o600)

        with pytest.raises(storage.SnapshotReconciliationError, match="身份不一致"):
            storage.reclaim_expired_retired_snapshots(
                (
                    {
                        "slug": "demo-vibe",
                        "known_versions": {1, 2},
                        "live_versions": {1, 2},
                    },
                ),
                upload_root=tmp_path,
                now=10_000,
            )

    assert first.is_dir()
    assert second.is_dir()


def test_prequota_retirement_gc_audits_all_projects_before_deletion(tmp_path):
    retired = _snapshot(tmp_path, 1, slug="alpha-vibe")
    _snapshot(tmp_path, 2, slug="alpha-vibe")
    unknown = tmp_path / "beta-vibe" / "versions" / "v0"
    unknown.mkdir(parents=True)
    with quotas.storage_mutation_lock(tmp_path):
        _retire(tmp_path, slug="alpha-vibe", now=0)
        with pytest.raises(storage.SnapshotReconciliationError, match="未知入口"):
            storage.reclaim_expired_retired_snapshots(
                (
                    {
                        "slug": "alpha-vibe",
                        "known_versions": {1, 2},
                        "live_versions": {2},
                    },
                    {
                        "slug": "beta-vibe",
                        "known_versions": set(),
                        "live_versions": set(),
                    },
                ),
                upload_root=tmp_path,
                now=10_000,
            )

    assert retired.is_dir()
    assert unknown.is_dir()


def test_prequota_audits_all_projects_before_repairing_missing_marker(tmp_path):
    retired = _snapshot(tmp_path, 1, slug="alpha-vibe")
    _snapshot(tmp_path, 2, slug="alpha-vibe")
    unknown = tmp_path / "beta-vibe" / "versions" / "v0"
    unknown.mkdir(parents=True)

    with quotas.storage_mutation_lock(tmp_path):
        with pytest.raises(storage.SnapshotReconciliationError, match="未知入口"):
            storage.reclaim_expired_retired_snapshots(
                (
                    {
                        "slug": "alpha-vibe",
                        "known_versions": {1, 2},
                        "live_versions": {2},
                    },
                    {
                        "slug": "beta-vibe",
                        "known_versions": set(),
                        "live_versions": set(),
                    },
                ),
                upload_root=tmp_path,
                now=10_000,
            )

    assert retired.is_dir()
    assert unknown.is_dir()
    assert not (tmp_path / "alpha-vibe" / ".gc").exists()


def test_prune_rejects_symlink_version_without_touching_target(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("keep", encoding="utf-8")
    versions = tmp_path / "demo-vibe" / "versions"
    versions.mkdir(parents=True)
    (versions / "v1").symlink_to(outside, target_is_directory=True)

    with quotas.storage_mutation_lock(tmp_path):
        with pytest.raises(storage.SnapshotReconciliationError, match="真实目录"):
            storage.prune_project_snapshots(
                "demo-vibe",
                set(),
                set(),
                upload_root=tmp_path,
            )

    assert (outside / "secret").read_text(encoding="utf-8") == "keep"
    assert (versions / "v1").is_symlink()


def test_prune_rejects_unknown_version_entry_before_any_deletion(tmp_path):
    orphan = _snapshot(tmp_path, 2)
    unknown = tmp_path / "demo-vibe" / "versions" / "v0"
    unknown.mkdir()

    with quotas.storage_mutation_lock(tmp_path):
        with pytest.raises(storage.SnapshotReconciliationError, match="未知入口"):
            storage.prune_project_snapshots(
                "demo-vibe",
                set(),
                set(),
                upload_root=tmp_path,
            )

    assert orphan.is_dir()
    assert unknown.is_dir()
