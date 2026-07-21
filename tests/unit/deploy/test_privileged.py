import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from deploy.backup import privileged


@pytest.fixture
def root_context(monkeypatch):
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(
        privileged,
        "_require_physical_owner",
        lambda _metadata: None,
    )
    monkeypatch.setattr(
        privileged,
        "_require_target_owner",
        lambda _metadata: None,
    )


def _tree(tmp_path: Path):
    physical = tmp_path / "backups" / "physical"
    target = physical / "run-1"
    nested = target / "nested"
    nested.mkdir(parents=True)
    (target / "root-file").write_bytes(b"root")
    (nested / "child-file").write_bytes(b"child")
    return physical, target


def _layout(tmp_path: Path):
    root = tmp_path / "backups"
    root.mkdir(mode=0o700)
    for name in ("plans", "logical", "physical", "manifests"):
        (root / name).mkdir(mode=0o700)
        (root / name).chmod(0o700)
    root.chmod(0o700)
    return root, root / "physical"


def _remove(physical: Path, target: Path) -> None:
    parent_identity = physical.stat(follow_symlinks=False)
    target_identity = target.stat(follow_symlinks=False)
    privileged.remove_physical_tree(
        physical,
        target.name,
        parent_identity.st_dev,
        parent_identity.st_ino,
        target_identity.st_dev,
        target_identity.st_ino,
    )


def test_normal_tree_is_deleted_using_descriptor_relative_operations(
    root_context, tmp_path
):
    physical, target = _tree(tmp_path)

    _remove(physical, target)

    assert physical.is_dir()
    assert not target.exists()


def test_internal_symlink_is_unlinked_without_touching_external_sentinel(
    root_context, tmp_path
):
    physical, target = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    (target / "outside-link").symlink_to(outside, target_is_directory=True)

    _remove(physical, target)

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert not target.exists()


def test_symlinked_physical_directory_is_rejected(
    root_context, tmp_path
):
    real_physical, target = _tree(tmp_path)
    linked_parent = tmp_path / "linked" / "physical"
    linked_parent.parent.mkdir()
    linked_parent.symlink_to(real_physical, target_is_directory=True)
    parent_identity = real_physical.stat()
    target_identity = target.stat()

    with pytest.raises(privileged.PrivilegedRemovalError, match="符号链接"):
        privileged.remove_physical_tree(
            linked_parent,
            target.name,
            parent_identity.st_dev,
            parent_identity.st_ino,
            target_identity.st_dev,
            target_identity.st_ino,
        )

    assert target.exists()


@pytest.mark.parametrize("mismatch", ["parent", "target"])
def test_inode_mismatch_is_rejected_before_deletion(
    root_context, tmp_path, mismatch
):
    physical, target = _tree(tmp_path)
    parent_identity = physical.stat()
    target_identity = target.stat()
    parent_ino = parent_identity.st_ino + (mismatch == "parent")
    target_ino = target_identity.st_ino + (mismatch == "target")

    with pytest.raises(
        privileged.PrivilegedRemovalError, match="inode 身份不匹配"
    ):
        privileged.remove_physical_tree(
            physical,
            target.name,
            parent_identity.st_dev,
            parent_ino,
            target_identity.st_dev,
            target_ino,
        )

    assert (target / "root-file").read_bytes() == b"root"


def test_parent_path_rename_cannot_redirect_deletion_to_external_tree(
    root_context, monkeypatch, tmp_path
):
    physical, target = _tree(tmp_path)
    outside = tmp_path / "outside"
    external_target = outside / target.name
    external_target.mkdir(parents=True)
    sentinel = external_target / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    moved_physical = physical.with_name("physical-moved")
    remove_contents = privileged._remove_tree_contents
    raced = False

    def rename_parent_then_remove(directory_fd, expected_dev):
        nonlocal raced
        if not raced:
            raced = True
            physical.rename(moved_physical)
            physical.symlink_to(outside, target_is_directory=True)
        remove_contents(directory_fd, expected_dev)

    monkeypatch.setattr(
        privileged, "_remove_tree_contents", rename_parent_then_remove
    )

    _remove(physical, target)

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert physical.is_symlink()
    assert not (moved_physical / target.name).exists()


def test_target_name_replacement_is_not_removed(
    root_context, monkeypatch, tmp_path
):
    physical, target = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    moved_target = physical / "moved-run"
    remove_contents = privileged._remove_tree_contents
    raced = False

    def replace_target_then_remove(directory_fd, expected_dev):
        nonlocal raced
        if not raced:
            raced = True
            target.rename(moved_target)
            target.symlink_to(outside, target_is_directory=True)
        remove_contents(directory_fd, expected_dev)

    monkeypatch.setattr(
        privileged, "_remove_tree_contents", replace_target_then_remove
    )

    with pytest.raises(
        privileged.PrivilegedRemovalError, match="最终物理备份目标"
    ):
        _remove(physical, target)

    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert target.is_symlink()
    assert moved_target.is_dir()


def test_cross_device_entry_is_rejected_before_any_deletion(
    root_context, monkeypatch, tmp_path
):
    physical, target = _tree(tmp_path)
    foreign = target / "foreign"
    foreign.mkdir()
    sentinel = foreign / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    lstat_at = privileged._lstat_at

    def report_foreign_device(directory_fd, name):
        metadata = lstat_at(directory_fd, name)
        if name != "foreign":
            return metadata
        values = list(metadata)
        values[2] = metadata.st_dev + 1
        return os.stat_result(values)

    monkeypatch.setattr(privileged, "_lstat_at", report_foreign_device)

    with pytest.raises(privileged.PrivilegedRemovalError, match="跨文件系统"):
        _remove(physical, target)

    assert (target / "root-file").read_bytes() == b"root"
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_root_sudo_and_owner_guards_are_fail_closed(monkeypatch, tmp_path):
    physical, target = _tree(tmp_path)
    identity = physical.stat()
    target_identity = target.stat()
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 1234)

    with pytest.raises(privileged.PrivilegedRemovalError, match="root 身份"):
        privileged.remove_physical_tree(
            physical,
            target.name,
            identity.st_dev,
            identity.st_ino,
            target_identity.st_dev,
            target_identity.st_ino,
        )

    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    with pytest.raises(privileged.PrivilegedRemovalError, match="SUDO_UID"):
        privileged.remove_physical_tree(
            physical,
            target.name,
            identity.st_dev,
            identity.st_ino,
            target_identity.st_dev,
            target_identity.st_ino,
        )


def test_owner_validation_rejects_unexpected_parent_and_target():
    directory_mode = stat.S_IFDIR | 0o700
    parent = SimpleNamespace(st_mode=directory_mode, st_uid=2000)
    target = SimpleNamespace(
        st_mode=directory_mode,
        st_uid=1000,
        st_gid=1000,
    )

    with pytest.raises(privileged.PrivilegedRemovalError, match="root:root"):
        privileged._require_physical_owner(parent)
    with pytest.raises(privileged.PrivilegedRemovalError, match="root:root"):
        privileged._require_target_owner(target)


def test_harden_layout_fixes_backup_root_before_physical(
    monkeypatch, tmp_path
):
    root, physical = _layout(tmp_path)
    root_identity = root.stat()
    physical_identity = physical.stat()
    calls = []
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(
        privileged,
        "_layout_directory_state",
        lambda _metadata, _sudo_uid, _label: "legacy",
    )
    monkeypatch.setattr(
        privileged,
        "_require_private_deploy_directory",
        lambda _metadata, _sudo_uid, _label: None,
    )
    monkeypatch.setattr(
        privileged,
        "_harden_descriptor",
        lambda _fd, label: calls.append(label),
    )
    monkeypatch.setattr(
        privileged,
        "_require_hardened_directory",
        lambda _metadata, _label: None,
    )

    privileged.harden_physical_layout(
        root,
        root_identity.st_dev,
        root_identity.st_ino,
        physical_identity.st_dev,
        physical_identity.st_ino,
    )

    assert calls == ["backup root", "physical directory"]
    for name in ("plans", "logical", "manifests"):
        child = root / name
        assert child.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("mismatch", ["root", "physical"])
def test_harden_layout_rejects_inode_mismatch(
    monkeypatch, tmp_path, mismatch
):
    root, physical = _layout(tmp_path)
    root_identity = root.stat()
    physical_identity = physical.stat()
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(
        privileged,
        "_layout_directory_state",
        lambda _metadata, _sudo_uid, _label: "legacy",
    )
    monkeypatch.setattr(
        privileged,
        "_require_private_deploy_directory",
        lambda _metadata, _sudo_uid, _label: None,
    )

    with pytest.raises(
        privileged.PrivilegedRemovalError, match="inode 身份不匹配"
    ):
        privileged.harden_physical_layout(
            root,
            root_identity.st_dev,
            root_identity.st_ino + (mismatch == "root"),
            physical_identity.st_dev,
            physical_identity.st_ino + (mismatch == "physical"),
        )


def test_harden_layout_rejects_symlinked_physical_directory(
    monkeypatch, tmp_path
):
    root, physical = _layout(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    physical.rmdir()
    physical.symlink_to(outside, target_is_directory=True)
    root_identity = root.stat()
    physical_identity = physical.stat(follow_symlinks=False)
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(
        privileged,
        "_layout_directory_state",
        lambda _metadata, _sudo_uid, _label: "legacy",
    )

    with pytest.raises(privileged.PrivilegedRemovalError, match="目录"):
        privileged.harden_physical_layout(
            root,
            root_identity.st_dev,
            root_identity.st_ino,
            physical_identity.st_dev,
            physical_identity.st_ino,
        )

    assert physical.is_symlink()


def test_harden_layout_detects_a_managed_child_replacement(
    monkeypatch, tmp_path
):
    root, physical = _layout(tmp_path)
    root_identity = root.stat()
    physical_identity = physical.stat()
    outside = tmp_path / "outside"
    outside.mkdir()
    moved_plans = root / "plans-moved"
    monkeypatch.setattr(privileged.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(
        privileged,
        "_layout_directory_state",
        lambda _metadata, _sudo_uid, _label: "legacy",
    )
    monkeypatch.setattr(
        privileged,
        "_require_private_deploy_directory",
        lambda _metadata, _sudo_uid, _label: None,
    )
    monkeypatch.setattr(
        privileged,
        "_require_hardened_directory",
        lambda _metadata, _label: None,
    )
    raced = False

    def replace_plans(_fd, label):
        nonlocal raced
        if label == "backup root" and not raced:
            raced = True
            (root / "plans").rename(moved_plans)
            (root / "plans").symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(privileged, "_harden_descriptor", replace_plans)

    with pytest.raises(
        privileged.PrivilegedRemovalError, match="最终 plans directory"
    ):
        privileged.harden_physical_layout(
            root,
            root_identity.st_dev,
            root_identity.st_ino,
            physical_identity.st_dev,
            physical_identity.st_ino,
        )

    assert (root / "plans").is_symlink()
    assert moved_plans.is_dir()


def test_layout_state_accepts_only_legacy_or_restart_safe_root_states():
    directory_mode = stat.S_IFDIR
    legacy = SimpleNamespace(
        st_mode=directory_mode | 0o700, st_uid=1000, st_gid=1000
    )
    interrupted = SimpleNamespace(
        st_mode=directory_mode | 0o711, st_uid=1000, st_gid=1000
    )
    hardened = SimpleNamespace(
        st_mode=directory_mode | 0o711, st_uid=0, st_gid=0
    )
    unsafe = SimpleNamespace(
        st_mode=directory_mode | 0o777, st_uid=1000, st_gid=1000
    )

    assert privileged._layout_directory_state(legacy, 1000, "layout") == "legacy"
    assert (
        privileged._layout_directory_state(interrupted, 1000, "layout")
        == "transitional"
    )
    assert (
        privileged._layout_directory_state(hardened, 1000, "layout")
        == "hardened"
    )
    with pytest.raises(privileged.PrivilegedRemovalError, match="owner/mode"):
        privileged._layout_directory_state(unsafe, 1000, "layout")


def test_harden_descriptor_changes_mode_before_owner(monkeypatch):
    calls = []
    hardened = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o711,
        st_uid=0,
        st_gid=0,
    )
    monkeypatch.setattr(
        privileged.os,
        "fchmod",
        lambda fd, mode: calls.append(("chmod", fd, mode)),
    )
    monkeypatch.setattr(
        privileged.os,
        "fchown",
        lambda fd, uid, gid: calls.append(("chown", fd, uid, gid)),
    )
    monkeypatch.setattr(
        privileged.os,
        "fsync",
        lambda fd: calls.append(("fsync", fd)),
    )
    monkeypatch.setattr(privileged.os, "fstat", lambda _fd: hardened)

    privileged._harden_descriptor(42, "layout")

    assert calls == [
        ("chmod", 42, 0o711),
        ("fsync", 42),
        ("chown", 42, 0, 0),
        ("fsync", 42),
    ]


def test_hardening_interruption_leaves_a_traversable_retry_state(monkeypatch):
    calls = []

    def fail_chown(fd, uid, gid):
        calls.append(("chown", fd, uid, gid))
        raise OSError("interrupted")

    monkeypatch.setattr(
        privileged.os,
        "fchmod",
        lambda fd, mode: calls.append(("chmod", fd, mode)),
    )
    monkeypatch.setattr(
        privileged.os,
        "fsync",
        lambda fd: calls.append(("fsync", fd)),
    )
    monkeypatch.setattr(privileged.os, "fchown", fail_chown)

    with pytest.raises(privileged.PrivilegedRemovalError, match="无法硬化"):
        privileged._harden_descriptor(42, "layout")

    assert calls == [
        ("chmod", 42, 0o711),
        ("fsync", 42),
        ("chown", 42, 0, 0),
    ]
    interrupted = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o711,
        st_uid=1000,
        st_gid=1000,
    )
    assert (
        privileged._layout_directory_state(interrupted, 1000, "layout")
        == "transitional"
    )


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (
            [
                "remove-physical-tree",
                "--physical-directory",
                "/srv/oj/.deploy/backups/physical",
                "--run-id",
                "run-1",
                "--expected-parent-dev",
                "1",
                "--expected-parent-ino",
                "2",
                "--expected-target-dev",
                "1",
                "--expected-target-ino",
                "3",
            ],
            "remove-physical-tree",
        ),
        (
            [
                "harden-physical-layout",
                "--backup-root",
                "/srv/oj/.deploy/backups",
                "--expected-root-dev",
                "1",
                "--expected-root-ino",
                "2",
                "--expected-physical-dev",
                "1",
                "--expected-physical-ino",
                "3",
            ],
            "harden-physical-layout",
        ),
    ],
)
def test_privileged_cli_argument_helpers(argv, command):
    arguments = privileged.parse_privileged_arguments(argv)

    assert arguments.command == command


@pytest.mark.parametrize("run_id", ["../escape", ".", "run/escape", ""])
def test_run_id_is_strictly_validated(root_context, tmp_path, run_id):
    physical, target = _tree(tmp_path)
    parent_identity = physical.stat()
    target_identity = target.stat()

    with pytest.raises(privileged.PrivilegedRemovalError, match="run-id 无效"):
        privileged.remove_physical_tree(
            physical,
            run_id,
            parent_identity.st_dev,
            parent_identity.st_ino,
            target_identity.st_dev,
            target_identity.st_ino,
        )
