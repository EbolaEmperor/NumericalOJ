from __future__ import annotations

import fcntl
import logging
import multiprocessing
import os
from pathlib import Path
import stat
import time

import pytest

from oj_modules.vibehub import quotas


def _try_nonblocking_flock(lock_path: str, connection) -> None:
    fd = os.open(lock_path, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            connection.send(False)
        else:
            connection.send(True)
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
        connection.close()


def _try_any_nonblocking_flock(lock_paths: tuple[str, ...], connection) -> None:
    acquired = False
    for lock_path in lock_paths:
        fd = os.open(lock_path, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                continue
            else:
                acquired = True
                fcntl.flock(fd, fcntl.LOCK_UN)
                break
        finally:
            os.close(fd)
    connection.send(acquired)
    connection.close()


def _write_version(root: Path, slug: str, version: int, payload: bytes) -> Path:
    target = root / slug / "versions" / f"v{version}"
    target.mkdir(parents=True, exist_ok=True)
    (target / "package.zip").write_bytes(payload)
    return target


def test_mutation_lock_hardens_permissions_and_blocks_another_process(tmp_path):
    root = tmp_path / "uploads" / "vibehub"

    with quotas.storage_mutation_lock(root) as locked_root:
        assert locked_root == root
        lock_path = root / quotas.MUTATION_LOCK_FILENAME
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600

        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(
            target=_try_nonblocking_flock,
            args=(os.fspath(lock_path), child),
        )
        process.start()
        child.close()
        assert parent.poll(10), "child did not report flock result"
        assert parent.recv() is False
        process.join(timeout=10)
        assert process.exitcode == 0

    fd = os.open(root / quotas.MUTATION_LOCK_FILENAME, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_mutation_lock_rejects_symlink_root(tmp_path):
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(quotas.VibeHubStorageSecurityError) as raised:
        with quotas.storage_mutation_lock(linked_root):
            pass

    assert raised.value.status_code == 409
    assert raised.value.code == "storage_security_conflict"


def test_multipart_parse_slots_bound_threads_and_processes_then_release(tmp_path):
    root = tmp_path / "uploads" / "vibehub"
    with quotas.multipart_parse_slot(root, slots=2, wait_seconds=0) as first:
        with quotas.multipart_parse_slot(root, slots=2, wait_seconds=0) as second:
            assert {first, second} == {0, 1}
            with pytest.raises(quotas.VibeHubMultipartCapacityExceeded) as raised:
                with quotas.multipart_parse_slot(root, slots=2, wait_seconds=0):
                    pytest.fail("第三个解析不应越过两个槽")
            assert raised.value.status_code == 429

            lock_paths = tuple(
                os.fspath(root / quotas.MULTIPART_SLOT_FILENAME_TEMPLATE.format(index))
                for index in range(2)
            )
            context = multiprocessing.get_context("spawn")
            parent, child = context.Pipe(duplex=False)
            process = context.Process(
                target=_try_any_nonblocking_flock,
                args=(lock_paths, child),
            )
            process.start()
            child.close()
            assert parent.poll(10), "child did not report multipart slot result"
            assert parent.recv() is False
            process.join(timeout=10)
            assert process.exitcode == 0

    with quotas.multipart_parse_slot(root, slots=2, wait_seconds=0) as reacquired:
        assert reacquired in {0, 1}
    for index in range(2):
        lock_path = root / quotas.MULTIPART_SLOT_FILENAME_TEMPLATE.format(index)
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600


def test_multipart_parse_slot_releases_after_exception(tmp_path):
    root = tmp_path / "vibehub"
    with pytest.raises(RuntimeError, match="boom"):
        with quotas.multipart_parse_slot(root, slots=1, wait_seconds=0):
            raise RuntimeError("boom")

    with quotas.multipart_parse_slot(root, slots=1, wait_seconds=0) as slot:
        assert slot == 0


@pytest.mark.parametrize("slots", [0, 9, True, 2.0, "2"])
def test_multipart_parse_slot_count_is_strictly_limited(tmp_path, slots):
    with pytest.raises(quotas.VibeHubStorageSecurityError, match="1–8"):
        with quotas.multipart_parse_slot(
            tmp_path / "vibehub",
            slots=slots,
            wait_seconds=0,
        ):
            pass


def test_multipart_parse_slot_rejects_symlink_lock(tmp_path):
    root = tmp_path / "vibehub"
    root.mkdir()
    outside = tmp_path / "outside.lock"
    outside.write_text("keep", encoding="utf-8")
    (root / quotas.MULTIPART_SLOT_FILENAME_TEMPLATE.format(0)).symlink_to(outside)

    with pytest.raises(quotas.VibeHubStorageSecurityError, match="无法安全打开"):
        with quotas.multipart_parse_slot(root, slots=1, wait_seconds=0):
            pass

    assert outside.read_text(encoding="utf-8") == "keep"


def test_logical_tree_bytes_counts_regular_files_and_hardlinks(tmp_path):
    root = tmp_path / "tree"
    nested = root / "a" / "b"
    nested.mkdir(parents=True)
    original = nested / "source.bin"
    original.write_bytes(b"12345")
    os.link(original, root / "hard-link.bin")
    (root / "empty").mkdir()

    assert quotas.logical_tree_bytes(root) == 10


def test_logical_tree_bytes_never_follows_symlinks(tmp_path):
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"do-not-count")
    root = tmp_path / "tree"
    root.mkdir()
    (root / "link.bin").symlink_to(outside)

    with pytest.raises(quotas.VibeHubStorageSecurityError, match="符号链接"):
        quotas.logical_tree_bytes(root)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="platform has no FIFO")
def test_logical_tree_bytes_rejects_special_nodes(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    os.mkfifo(root / "pipe")

    with pytest.raises(quotas.VibeHubStorageSecurityError, match="特殊节点"):
        quotas.logical_tree_bytes(root)


def test_project_snapshot_usage_ignores_pointer_metadata(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")
    (root / "alpha-demo" / "latest.json").write_bytes(b"pointer")

    assert quotas.project_snapshots_logical_bytes(root, "alpha-demo") == 4
    assert quotas.project_snapshots_logical_bytes(root, "missing-demo") == 0


def test_staged_incoming_is_counted_for_user_projection(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")
    staged = root / ".staging" / f"upload-{'1' * 32}" / "snapshot"
    staged.mkdir(parents=True)
    (staged / "package.zip").write_bytes(b"1234567")

    with quotas.storage_mutation_lock(root):
        projection = quotas.enforce_storage_quota(
            ["alpha-demo", "alpha-demo"],
            7,
            root,
            staged_incoming_path=staged,
            user_limit_bytes=11,
        )

    assert projection.user_existing_bytes == 4
    assert projection.user_projected_bytes == 11
    assert projection.incoming_already_staged is True


def test_other_staging_data_is_not_charged_to_current_user(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")
    current = root / ".staging" / f"upload-{'1' * 32}" / "snapshot"
    current.mkdir(parents=True)
    (current / "payload").write_bytes(b"123")
    abandoned = root / ".staging" / f"upload-{'2' * 32}"
    abandoned.mkdir(parents=True)
    (abandoned / "payload").write_bytes(b"56789")

    with quotas.storage_mutation_lock(root):
        projection = quotas.enforce_storage_quota(
            ["alpha-demo"],
            3,
            root,
            staged_incoming_path=current,
            user_limit_bytes=7,
        )

    assert projection.user_existing_bytes == 4
    assert projection.user_projected_bytes == 7
    assert abandoned.is_dir()


def test_not_yet_staged_incoming_is_added_to_user_projection(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")

    with quotas.storage_mutation_lock(root):
        projection = quotas.enforce_storage_quota(
            ["alpha-demo"],
            6,
            root,
            user_limit_bytes=10,
        )

    assert projection.user_existing_bytes == 4
    assert projection.user_projected_bytes == 10


def test_user_storage_quota_has_safe_413_error(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")

    with quotas.storage_mutation_lock(root):
        with pytest.raises(quotas.VibeHubStorageQuotaExceeded) as raised:
            quotas.enforce_storage_quota(
                ["alpha-demo"],
                7,
                root,
                user_limit_bytes=10,
            )

    assert raised.value.status_code == 413
    assert raised.value.code == "user_storage_quota_exceeded"
    assert raised.value.details["projected_bytes"] == 11


def test_staged_path_must_be_exact_safe_staging_subtree(tmp_path):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")
    staged = root / ".staging" / f"upload-{'1' * 32}" / "snapshot"
    staged.mkdir(parents=True)
    (staged / "payload").write_bytes(b"123")

    with quotas.storage_mutation_lock(root):
        with pytest.raises(quotas.VibeHubStorageSecurityError, match="不一致"):
            quotas.enforce_storage_quota(
                ["alpha-demo"],
                2,
                root,
                staged_incoming_path=staged,
                user_limit_bytes=100,
            )
        with pytest.raises(quotas.VibeHubStorageSecurityError, match=".staging"):
            quotas.enforce_storage_quota(
                ["alpha-demo"],
                4,
                root,
                staged_incoming_path=root / "alpha-demo" / "versions" / "v1",
                user_limit_bytes=100,
            )


def test_expired_managed_staging_is_reclaimed_before_user_quota_scan(
    tmp_path,
    caplog,
):
    root = tmp_path / "vibehub"
    _write_version(root, "alpha-demo", 1, b"1234")
    active = root / ".staging" / f"upload-{'1' * 32}" / "snapshot"
    active.mkdir(parents=True)
    (active / "payload").write_bytes(b"123")
    orphan_root = root / ".staging" / f"upload-{'2' * 32}"
    orphan_root.mkdir(parents=True)
    (orphan_root / "payload").write_bytes(b"stale")
    expired_at = time.time() - quotas.DEFAULT_UPLOAD_STAGING_GRACE_SECONDS - 10
    os.utime(orphan_root, (expired_at, expired_at))

    with caplog.at_level(logging.INFO, logger=quotas.__name__):
        with quotas.storage_mutation_lock(root):
            projection = quotas.enforce_storage_quota(
                ["alpha-demo"],
                3,
                root,
                staged_incoming_path=active,
                user_limit_bytes=7,
            )

    assert projection.user_existing_bytes == 4
    assert projection.user_projected_bytes == 7
    assert active.parent.is_dir()
    assert not orphan_root.exists()
    assert orphan_root.name in caplog.text
    assert "bytes=5" in caplog.text


def test_active_staging_is_never_reclaimed_even_when_older_than_grace(tmp_path):
    root = tmp_path / "vibehub"
    active_root = root / ".staging" / f"upload-{'a' * 32}"
    active = active_root / "snapshot"
    active.mkdir(parents=True)
    (active / "payload").write_bytes(b"active")
    expired_at = time.time() - quotas.DEFAULT_UPLOAD_STAGING_GRACE_SECONDS - 10
    os.utime(active_root, (expired_at, expired_at))

    with quotas.storage_mutation_lock(root):
        result = quotas.reclaim_expired_upload_staging(
            root,
            active_staging_paths=(active,),
        )

    assert result.active == (active_root.name,)
    assert result.deleted_expired == ()
    assert (active / "payload").read_bytes() == b"active"


def test_staging_reclaim_fails_closed_on_unknown_entry_without_partial_delete(tmp_path):
    root = tmp_path / "vibehub"
    expired = root / ".staging" / f"upload-{'1' * 32}"
    expired.mkdir(parents=True)
    (expired / "payload").write_bytes(b"keep-on-audit-failure")
    expired_at = time.time() - quotas.DEFAULT_UPLOAD_STAGING_GRACE_SECONDS - 10
    os.utime(expired, (expired_at, expired_at))
    unknown = root / ".staging" / "not-a-managed-upload"
    unknown.mkdir()

    with quotas.storage_mutation_lock(root):
        with pytest.raises(quotas.VibeHubStorageSecurityError, match="未知入口"):
            quotas.reclaim_expired_upload_staging(root)

    assert expired.is_dir()
    assert (expired / "payload").read_bytes() == b"keep-on-audit-failure"
    assert unknown.is_dir()


def test_staging_reclaim_fails_closed_on_symlink_without_touching_target(tmp_path):
    root = tmp_path / "vibehub"
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"do-not-touch")
    expired = root / ".staging" / f"upload-{'1' * 32}"
    expired.mkdir(parents=True)
    (expired / "escape").symlink_to(outside)
    expired_at = time.time() - quotas.DEFAULT_UPLOAD_STAGING_GRACE_SECONDS - 10
    os.utime(expired, (expired_at, expired_at))

    with quotas.storage_mutation_lock(root):
        with pytest.raises(quotas.VibeHubStorageSecurityError, match="符号链接"):
            quotas.reclaim_expired_upload_staging(root)

    assert expired.is_dir()
    assert (expired / "escape").is_symlink()
    assert outside.read_bytes() == b"do-not-touch"


def test_staging_reclaim_requires_global_mutation_lock(tmp_path):
    root = tmp_path / "vibehub"

    with pytest.raises(quotas.VibeHubStorageSecurityError, match="全局存储变更锁"):
        quotas.reclaim_expired_upload_staging(root)


@pytest.mark.parametrize(
    ("function", "current", "incoming", "limit", "code"),
    [
        (quotas.enforce_project_count, 1, 1, 2, None),
        (quotas.enforce_project_count, 2, 1, 2, "projects_quota_exceeded"),
        (quotas.enforce_version_count, 999, 1, 1000, None),
        (quotas.enforce_version_count, 1000, 1, 1000, "versions_quota_exceeded"),
    ],
)
def test_count_quotas_are_pure_and_enforce_exact_boundaries(
    function,
    current,
    incoming,
    limit,
    code,
):
    if code is None:
        assert function(current, incoming, limit=limit) == limit
        return

    with pytest.raises(quotas.VibeHubCountQuotaExceeded) as raised:
        function(current, incoming, limit=limit)
    assert raised.value.status_code == 409
    assert raised.value.code == code
    assert raised.value.details["projected"] == limit + 1


@pytest.mark.parametrize("value", [-1, True, 1.5, "1"])
def test_quota_inputs_fail_closed_with_business_safe_error(tmp_path, value):
    with pytest.raises(quotas.VibeHubStorageSecurityError) as raised:
        quotas.enforce_project_count(value)
    assert raised.value.status_code == 409

    root = tmp_path / f"root-{str(value).replace('.', '-') }"
    with pytest.raises(quotas.VibeHubStorageSecurityError):
        quotas.enforce_storage_quota([], value, root)
