#!/usr/bin/env python3
"""Root-only filesystem operations for deployment backup retention.

This module is intentionally small and does not invoke ``sudo`` itself.  Its
caller must first capture the device/inode identities of the managed physical
directory and backup target, then execute this module as root with those facts.
All traversal and deletion stays bound to already-open directory descriptors;
paths are never resolved again after the privileged boundary is entered.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import sys
from typing import Iterator, Sequence


RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | os.O_CLOEXEC
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
)


class PrivilegedRemovalError(RuntimeError):
    """A physical backup tree could not be proven safe to remove."""


def _required_identity(value: int, label: str, *, allow_zero: bool) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise PrivilegedRemovalError(
            f"{label} 必须是大于等于 {minimum} 的整数"
        )
    return value


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise PrivilegedRemovalError(f"run-id 无效: {run_id!r}")
    return run_id


def _validate_physical_directory(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise PrivilegedRemovalError("physical directory 路径无效")
    path = Path(raw)
    if path.anchor != "/" or ".." in path.parts:
        raise PrivilegedRemovalError(
            "physical directory 必须是无 .. 的绝对路径"
        )
    if path == Path(path.anchor):
        raise PrivilegedRemovalError(
            "拒绝把文件系统根目录作为 physical directory"
        )
    if path.name != "physical":
        raise PrivilegedRemovalError(
            "physical directory 的叶目录必须名为 physical"
        )
    return path


def _validate_backup_root(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise PrivilegedRemovalError("backup root 路径无效")
    path = Path(raw)
    if path.anchor != "/" or ".." in path.parts:
        raise PrivilegedRemovalError("backup root 必须是无 .. 的绝对路径")
    if path == Path(path.anchor):
        raise PrivilegedRemovalError("拒绝把文件系统根目录作为 backup root")
    if path.name != "backups":
        raise PrivilegedRemovalError("backup root 的叶目录必须名为 backups")
    return path


def _sudo_uid() -> int:
    raw = os.environ.get("SUDO_UID")
    if raw is None or re.fullmatch(r"[0-9]+", raw) is None:
        raise PrivilegedRemovalError("必须由 sudo 提供有效的 SUDO_UID")
    uid = int(raw)
    if uid <= 0:
        raise PrivilegedRemovalError("SUDO_UID 必须指向非 root 部署用户")
    return uid


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PrivilegedRemovalError(
            "物理备份特权 helper 只能以 root 身份运行"
        )


def _require_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise PrivilegedRemovalError(f"{label} 不是目录")


def _require_physical_owner(metadata: os.stat_result) -> None:
    _require_hardened_directory(metadata, "physical directory")


def _require_target_owner(metadata: os.stat_result) -> None:
    if metadata.st_uid != 0 or metadata.st_gid != 0:
        raise PrivilegedRemovalError("物理备份目标必须由 root:root 拥有")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PrivilegedRemovalError("物理备份目标权限必须精确为 0700")


def _require_hardened_directory(
    metadata: os.stat_result,
    label: str,
) -> None:
    _require_directory(metadata, label)
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o711
    ):
        raise PrivilegedRemovalError(
            f"{label} 必须由 root:root 拥有且权限为 0711"
        )


def _layout_directory_state(
    metadata: os.stat_result,
    sudo_uid: int,
    label: str,
) -> str:
    """Return a restart-safe hardening state for one layout directory."""

    _require_directory(metadata, label)
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == sudo_uid and mode == 0o700:
        return "legacy"
    if metadata.st_uid == sudo_uid and mode == 0o711:
        # ``fchmod`` completed but ``fchown`` did not; the deployment user can
        # still traverse the directory and a privileged retry may finish.
        return "transitional"
    if metadata.st_uid == 0 and metadata.st_gid == 0 and mode == 0o711:
        return "hardened"
    raise PrivilegedRemovalError(
        f"{label} owner/mode 异常: "
        f"uid={metadata.st_uid}, gid={metadata.st_gid}, mode={mode:o}"
    )


def _require_private_deploy_directory(
    metadata: os.stat_result,
    sudo_uid: int,
    label: str,
) -> None:
    _require_directory(metadata, label)
    if metadata.st_uid != sudo_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PrivilegedRemovalError(
            f"{label} 必须保持由部署用户拥有且权限为 0700"
        )


def _harden_descriptor(directory_fd: int, label: str) -> None:
    try:
        os.fchmod(directory_fd, 0o711)
        # Persist the traversable mode before changing ownership.  A crash may
        # leave either SUDO_UID:0700 or SUDO_UID:0711, both retryable states.
        os.fsync(directory_fd)
        os.fchown(directory_fd, 0, 0)
        os.fsync(directory_fd)
    except OSError as exc:
        raise PrivilegedRemovalError(f"无法硬化 {label}: {exc}") from exc
    try:
        _require_hardened_directory(os.fstat(directory_fd), label)
    except PrivilegedRemovalError as exc:
        raise PrivilegedRemovalError(
            f"{label} 硬化后 owner/mode 校验失败"
        ) from exc


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _require_identity(
    metadata: os.stat_result,
    *,
    expected_dev: int,
    expected_ino: int,
    label: str,
) -> None:
    actual = _identity(metadata)
    expected = (expected_dev, expected_ino)
    if actual != expected:
        raise PrivilegedRemovalError(
            f"{label} inode 身份不匹配: expected={expected}, actual={actual}"
        )


def _lstat_at(directory_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as exc:
        raise PrivilegedRemovalError(f"无法读取目录项 {name!r}: {exc}") from exc


def _open_child_directory(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
) -> int:
    try:
        child_fd = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
    except OSError as exc:
        raise PrivilegedRemovalError(
            f"拒绝打开目录项 {name!r}"
            f"（可能已被替换或是符号链接）: {exc}"
        ) from exc
    try:
        actual = os.fstat(child_fd)
        _require_directory(actual, f"目录项 {name!r}")
        _require_identity(
            actual,
            expected_dev=expected.st_dev,
            expected_ino=expected.st_ino,
            label=f"目录项 {name!r}",
        )
    except BaseException:
        os.close(child_fd)
        raise
    return child_fd


@contextmanager
def _open_directory_from_root(path: Path) -> Iterator[int]:
    """Open every component relative to the preceding descriptor."""

    try:
        current_fd = os.open(path.anchor, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise PrivilegedRemovalError("无法打开文件系统根目录") from exc
    try:
        for component in path.parts[1:]:
            try:
                next_fd = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise PrivilegedRemovalError(
                    f"拒绝打开路径组件 {component!r}"
                    f"（可能是符号链接）: {exc}"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        yield current_fd
    finally:
        os.close(current_fd)


def _entry_names(directory_fd: int) -> list[str]:
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        raise PrivilegedRemovalError("无法枚举物理备份目录") from exc
    if any(name in {"", ".", ".."} or "/" in name for name in names):
        raise PrivilegedRemovalError("物理备份包含无效目录项")
    return sorted(names)


def _validate_tree_device(directory_fd: int, expected_dev: int) -> None:
    """Validate the entire tree before the first destructive operation."""

    for name in _entry_names(directory_fd):
        metadata = _lstat_at(directory_fd, name)
        if metadata.st_dev != expected_dev:
            raise PrivilegedRemovalError(
                f"拒绝跨文件系统删除目录项 {name!r}: "
                f"expected_dev={expected_dev}, actual_dev={metadata.st_dev}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        child_fd = _open_child_directory(directory_fd, name, metadata)
        try:
            _validate_tree_device(child_fd, expected_dev)
        finally:
            os.close(child_fd)
        current = _lstat_at(directory_fd, name)
        _require_identity(
            current,
            expected_dev=metadata.st_dev,
            expected_ino=metadata.st_ino,
            label=f"目录项 {name!r}",
        )


def _remove_tree_contents(directory_fd: int, expected_dev: int) -> None:
    for name in _entry_names(directory_fd):
        metadata = _lstat_at(directory_fd, name)
        if metadata.st_dev != expected_dev:
            raise PrivilegedRemovalError(
                f"删除期间检测到跨文件系统目录项 {name!r}"
            )
        if stat.S_ISDIR(metadata.st_mode):
            child_fd = _open_child_directory(directory_fd, name, metadata)
            try:
                _remove_tree_contents(child_fd, expected_dev)
            finally:
                os.close(child_fd)
            current = _lstat_at(directory_fd, name)
            _require_identity(
                current,
                expected_dev=metadata.st_dev,
                expected_ino=metadata.st_ino,
                label=f"待删除目录项 {name!r}",
            )
            try:
                os.rmdir(name, dir_fd=directory_fd)
            except OSError as exc:
                raise PrivilegedRemovalError(
                    f"无法删除目录项 {name!r}: {exc}"
                ) from exc
            continue

        current = _lstat_at(directory_fd, name)
        _require_identity(
            current,
            expected_dev=metadata.st_dev,
            expected_ino=metadata.st_ino,
            label=f"待删除文件 {name!r}",
        )
        try:
            # unlinkat semantics never follow a symbolic-link leaf.
            os.unlink(name, dir_fd=directory_fd)
        except OSError as exc:
            raise PrivilegedRemovalError(
                f"无法删除文件 {name!r}: {exc}"
            ) from exc


def remove_physical_tree(
    physical_directory: str | os.PathLike[str],
    run_id: str,
    expected_parent_dev: int,
    expected_parent_ino: int,
    expected_target_dev: int,
    expected_target_ino: int,
) -> None:
    """Remove one root-owned physical backup without following path races."""

    _require_root()
    _sudo_uid()
    path = _validate_physical_directory(physical_directory)
    run_id = _validate_run_id(run_id)
    expected_parent_dev = _required_identity(
        expected_parent_dev, "expected-parent-dev", allow_zero=True
    )
    expected_parent_ino = _required_identity(
        expected_parent_ino, "expected-parent-ino", allow_zero=False
    )
    expected_target_dev = _required_identity(
        expected_target_dev, "expected-target-dev", allow_zero=True
    )
    expected_target_ino = _required_identity(
        expected_target_ino, "expected-target-ino", allow_zero=False
    )

    with _open_directory_from_root(path) as parent_fd:
        parent = os.fstat(parent_fd)
        _require_directory(parent, "physical directory")
        _require_identity(
            parent,
            expected_dev=expected_parent_dev,
            expected_ino=expected_parent_ino,
            label="physical directory",
        )
        _require_physical_owner(parent)

        target_entry = _lstat_at(parent_fd, run_id)
        _require_directory(target_entry, "物理备份目标")
        _require_identity(
            target_entry,
            expected_dev=expected_target_dev,
            expected_ino=expected_target_ino,
            label="物理备份目标",
        )
        if target_entry.st_dev != parent.st_dev:
            raise PrivilegedRemovalError(
                "物理备份目标是跨文件系统挂载点"
            )

        target_fd = _open_child_directory(parent_fd, run_id, target_entry)
        try:
            target = os.fstat(target_fd)
            _require_target_owner(target)
            _validate_tree_device(target_fd, target.st_dev)
            _remove_tree_contents(target_fd, target.st_dev)

            # Never rmdir a replacement if an unexpected privileged actor
            # changes the entry while deletion is in progress.
            final_entry = _lstat_at(parent_fd, run_id)
            _require_directory(final_entry, "最终物理备份目标")
            _require_identity(
                final_entry,
                expected_dev=target.st_dev,
                expected_ino=target.st_ino,
                label="最终物理备份目标",
            )
            try:
                os.rmdir(run_id, dir_fd=parent_fd)
            except OSError as exc:
                raise PrivilegedRemovalError(
                    f"无法删除物理备份根目录 {run_id!r}: {exc}"
                ) from exc
        finally:
            os.close(target_fd)


def harden_physical_layout(
    backup_root: str | os.PathLike[str],
    expected_root_dev: int,
    expected_root_ino: int,
    expected_physical_dev: int,
    expected_physical_ino: int,
) -> None:
    """Make the physical-backup pathname immutable to the deployment user.

    The operation is restart-safe.  It accepts the legacy ``SUDO_UID:0700``
    state, the final ``root:root:0711`` state, and the traversable
    ``SUDO_UID:0711`` state left if a process dies between ``fchmod`` and
    ``fchown``.
    """

    _require_root()
    sudo_uid = _sudo_uid()
    root_path = _validate_backup_root(backup_root)
    expected_root_dev = _required_identity(
        expected_root_dev, "expected-root-dev", allow_zero=True
    )
    expected_root_ino = _required_identity(
        expected_root_ino, "expected-root-ino", allow_zero=False
    )
    expected_physical_dev = _required_identity(
        expected_physical_dev, "expected-physical-dev", allow_zero=True
    )
    expected_physical_ino = _required_identity(
        expected_physical_ino, "expected-physical-ino", allow_zero=False
    )

    with _open_directory_from_root(root_path) as root_fd:
        root_metadata = os.fstat(root_fd)
        _require_identity(
            root_metadata,
            expected_dev=expected_root_dev,
            expected_ino=expected_root_ino,
            label="backup root",
        )
        root_state = _layout_directory_state(
            root_metadata, sudo_uid, "backup root"
        )

        physical_entry = _lstat_at(root_fd, "physical")
        _require_identity(
            physical_entry,
            expected_dev=expected_physical_dev,
            expected_ino=expected_physical_ino,
            label="physical directory",
        )
        if physical_entry.st_dev != root_metadata.st_dev:
            raise PrivilegedRemovalError("physical directory 不得跨文件系统")
        physical_fd = _open_child_directory(
            root_fd, "physical", physical_entry
        )
        try:
            physical_metadata = os.fstat(physical_fd)
            physical_state = _layout_directory_state(
                physical_metadata, sudo_uid, "physical directory"
            )

            # These directories remain writable only by the deployment user.
            # Validate all of them before changing either parent owner.
            deploy_children: dict[str, tuple[int, int]] = {}
            for name in ("plans", "logical", "manifests"):
                child_entry = _lstat_at(root_fd, name)
                if child_entry.st_dev != root_metadata.st_dev:
                    raise PrivilegedRemovalError(
                        f"{name} directory 不得跨文件系统"
                    )
                child_fd = _open_child_directory(root_fd, name, child_entry)
                try:
                    child_metadata = os.fstat(child_fd)
                    _require_private_deploy_directory(
                        child_metadata, sudo_uid, f"{name} directory"
                    )
                    deploy_children[name] = _identity(child_metadata)
                finally:
                    os.close(child_fd)

            # Harden the root first.  Its 0711 mode keeps every managed child
            # traversable, while root ownership fixes the ``physical`` name in
            # place before the leaf itself changes owner.
            if root_state != "hardened":
                _harden_descriptor(root_fd, "backup root")
            if physical_state != "hardened":
                _harden_descriptor(physical_fd, "physical directory")

            # Once backup_root is root-owned, the invoking user can no longer
            # replace its ``physical`` entry.  Confirm that the name still
            # identifies the descriptor hardened above.
            final_physical = _lstat_at(root_fd, "physical")
            _require_identity(
                final_physical,
                expected_dev=expected_physical_dev,
                expected_ino=expected_physical_ino,
                label="最终 physical directory",
            )
            _require_hardened_directory(
                final_physical, "最终 physical directory"
            )
            _require_hardened_directory(os.fstat(root_fd), "最终 backup root")
            for name, (child_dev, child_ino) in deploy_children.items():
                final_child = _lstat_at(root_fd, name)
                _require_identity(
                    final_child,
                    expected_dev=child_dev,
                    expected_ino=child_ino,
                    label=f"最终 {name} directory",
                )
                _require_private_deploy_directory(
                    final_child, sudo_uid, f"最终 {name} directory"
                )
        finally:
            os.close(physical_fd)

    # The backup root's own parent remains outside this helper's ownership.
    # Re-walk from / once so a concurrent rename cannot be reported as a
    # successful hardening of the pathname the caller will subsequently use.
    with _open_directory_from_root(root_path) as verified_root_fd:
        verified_root = os.fstat(verified_root_fd)
        _require_identity(
            verified_root,
            expected_dev=expected_root_dev,
            expected_ino=expected_root_ino,
            label="重新定位的 backup root",
        )
        _require_hardened_directory(verified_root, "重新定位的 backup root")


def _identity_argument(value: str) -> int:
    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("必须是十进制非负整数")
    return int(value)


def add_remove_physical_tree_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--physical-directory", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--expected-parent-dev", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-parent-ino", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-target-dev", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-target-ino", type=_identity_argument, required=True
    )


def add_harden_physical_layout_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument(
        "--expected-root-dev", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-root-ino", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-physical-dev", type=_identity_argument, required=True
    )
    parser.add_argument(
        "--expected-physical-ino", type=_identity_argument, required=True
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Root-only filesystem operations for MySQL backups."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    remove_parser = subparsers.add_parser("remove-physical-tree")
    add_remove_physical_tree_arguments(remove_parser)
    harden_parser = subparsers.add_parser("harden-physical-layout")
    add_harden_physical_layout_arguments(harden_parser)
    return parser


def parse_privileged_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """Parse the stable CLI contract used by the deployment orchestrator."""

    return build_argument_parser().parse_args(argv)


def parse_remove_physical_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """Backward-compatible alias for the initial privileged CLI helper."""

    return parse_privileged_arguments(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_privileged_arguments(argv)
    try:
        if args.command == "remove-physical-tree":
            remove_physical_tree(
                args.physical_directory,
                args.run_id,
                args.expected_parent_dev,
                args.expected_parent_ino,
                args.expected_target_dev,
                args.expected_target_ino,
            )
        elif args.command == "harden-physical-layout":
            harden_physical_layout(
                args.backup_root,
                args.expected_root_dev,
                args.expected_root_ino,
                args.expected_physical_dev,
                args.expected_physical_ino,
            )
        else:  # pragma: no cover - argparse enforces the command choices.
            raise PrivilegedRemovalError(f"未知特权命令: {args.command}")
    except PrivilegedRemovalError as exc:
        print(f"[backup privileged] failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
