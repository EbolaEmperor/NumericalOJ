#!/usr/bin/env python3
"""按部署清单安全激活和回滚 Git 受管文件。

清单中的叶子文件/符号链接是部署唯一拥有的路径。父目录只会在为空时
删除；未被旧清单拥有的冲突路径一律拒绝覆盖。
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import posixpath
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def load_manifest(path: Path) -> tuple[str, ...]:
    entries = tuple(path.read_text(encoding="utf-8").splitlines())
    if list(entries) != sorted(set(entries)):
        raise ValueError(f"manifest must be sorted and unique: {path}")
    seen: set[str] = set()
    for entry in entries:
        _parts(entry)
        parents = PurePosixPath(entry).parents
        if any(parent.as_posix() in seen for parent in parents):
            raise ValueError(f"manifest contains a leaf and its descendant: {entry}")
        seen.add(entry)
    return entries


def _parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        not relative
        or "\n" in relative
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"unsafe managed path: {relative!r}")
    return path.parts


def _validate_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir() or root.resolve() != root.absolute():
        raise ValueError(f"managed root must be a real directory: {root}")


def _open_parent(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    current = os.open(root, _DIRECTORY_FLAGS)
    try:
        for component in parts[:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=current)
                    os.fsync(current)
                except FileExistsError:
                    pass
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _safe_symlink_target(relative: str, target: str) -> None:
    target_path = PurePosixPath(target)
    if not target or target_path.is_absolute():
        raise ValueError(f"unsafe managed symlink target: {relative} -> {target}")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    if resolved == ".." or resolved.startswith("../"):
        raise ValueError(f"managed symlink escapes root: {relative} -> {target}")


def _leaf_metadata(root: Path, relative: str):
    parts = _parts(relative)
    try:
        parent_fd = _open_parent(root, parts, create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(parts[-1], dir_fd=parent_fd)
            _safe_symlink_target(relative, target)
            return metadata, "symlink", target
        if stat.S_ISREG(metadata.st_mode):
            return metadata, "file", None
        raise ValueError(f"managed leaf is neither regular file nor symlink: {relative}")
    finally:
        os.close(parent_fd)


def _open_regular(root: Path, relative: str) -> tuple[int, os.stat_result]:
    parts = _parts(relative)
    parent_fd = _open_parent(root, parts, create=False)
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"managed source is not a regular file: {relative}")
    return descriptor, metadata


def _remove_leaf(root: Path, relative: str, *, expected_identity=None) -> None:
    parts = _parts(relative)
    try:
        parent_fd = _open_parent(root, parts, create=False)
    except FileNotFoundError:
        return
    try:
        try:
            metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
            raise ValueError(f"refusing to remove non-leaf managed path: {relative}")
        if expected_identity is not None and (
            metadata.st_dev,
            metadata.st_ino,
        ) != expected_identity:
            raise RuntimeError(f"managed path changed during deployment: {relative}")
        os.unlink(parts[-1], dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _prune_empty_parents(root: Path, entries: tuple[str, ...]) -> None:
    parents = {
        parent.as_posix()
        for entry in entries
        for parent in PurePosixPath(entry).parents
        if parent.as_posix() != "."
    }
    for relative in sorted(parents, key=lambda item: (item.count("/"), item), reverse=True):
        parts = _parts(relative)
        try:
            parent_fd = _open_parent(root, parts, create=False)
        except FileNotFoundError:
            continue
        try:
            try:
                os.rmdir(parts[-1], dir_fd=parent_fd)
                os.fsync(parent_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                if exc.errno not in {errno.ENOTEMPTY, errno.EEXIST}:
                    raise
        finally:
            os.close(parent_fd)


def _install_regular(
    target_root: Path,
    relative: str,
    source: BinaryIO,
    mode: int,
    on_create: Callable[[tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    parts = _parts(relative)
    parent_fd = _open_parent(target_root, parts, create=True)
    destination_fd = -1
    identity = None
    try:
        destination_fd = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
            mode & 0o777,
            dir_fd=parent_fd,
        )
        metadata = os.fstat(destination_fd)
        identity = (metadata.st_dev, metadata.st_ino)
        if on_create is not None:
            on_create(identity)
        while chunk := source.read(1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fchmod(destination_fd, mode & 0o777)
        os.fsync(destination_fd)
        os.fsync(parent_fd)
        return identity
    except BaseException:
        if identity is not None:
            try:
                observed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) == identity:
                    os.unlink(parts[-1], dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(parent_fd)


def _install_symlink(
    target_root: Path,
    relative: str,
    target: str,
    on_create: Callable[[tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    _safe_symlink_target(relative, target)
    parts = _parts(relative)
    parent_fd = _open_parent(target_root, parts, create=True)
    identity = None
    try:
        os.symlink(target, parts[-1], dir_fd=parent_fd)
        metadata = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino)
        if on_create is not None:
            on_create(identity)
        os.fsync(parent_fd)
        return identity
    except BaseException:
        if identity is not None:
            try:
                observed = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) == identity:
                    os.unlink(parts[-1], dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _append_record(record: Path, relative: str, identity: tuple[int, int]) -> None:
    payload = json.dumps(
        {"path": relative, "dev": identity[0], "ino": identity[1]},
        sort_keys=True,
        separators=(",", ":"),
    )
    descriptor = os.open(
        record,
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | _FILE_NOFOLLOW,
        0o600,
    )
    original_size = os.lseek(descriptor, 0, os.SEEK_END)
    try:
        remaining = memoryview(payload.encode("utf-8") + b"\n")
        while remaining:
            written = os.write(descriptor, remaining)
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException:
        os.ftruncate(descriptor, original_size)
        os.fsync(descriptor)
        raise
    finally:
        os.close(descriptor)


def create_backup(target_root: Path, manifest: Path, archive: Path) -> None:
    _validate_root(target_root)
    entries = load_manifest(manifest)
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as output:
        for relative in entries:
            leaf = _leaf_metadata(target_root, relative)
            if leaf is None:
                continue
            metadata, kind, target = leaf
            info = tarfile.TarInfo(relative)
            info.mode = stat.S_IMODE(metadata.st_mode)
            info.mtime = int(metadata.st_mtime)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = target
                output.addfile(info)
                continue
            descriptor, observed = _open_regular(target_root, relative)
            try:
                if (observed.st_dev, observed.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise RuntimeError(f"managed file changed during backup: {relative}")
                info.size = observed.st_size
                with os.fdopen(descriptor, "rb") as source:
                    descriptor = -1
                    output.addfile(info, source)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    validate_backup(archive, manifest)


def _archive_members(archive: Path, manifest: Path):
    allowed = set(load_manifest(manifest))
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise ValueError("managed backup contains duplicate members")
        for member in members:
            _parts(member.name)
            if member.name not in allowed:
                raise ValueError(f"managed backup contains unowned path: {member.name}")
            if not (member.isfile() or member.issym()):
                raise ValueError(f"unsupported managed backup member: {member.name}")
            if member.issym():
                _safe_symlink_target(member.name, member.linkname)
        yield source, members


def validate_backup(archive: Path, manifest: Path) -> None:
    for _source, _members in _archive_members(archive, manifest):
        return


def activate(
    source_root: Path,
    target_root: Path,
    old_manifest: Path,
    new_manifest: Path,
    record: Path,
) -> None:
    _validate_root(source_root)
    _validate_root(target_root)
    old_entries = load_manifest(old_manifest)
    new_entries = load_manifest(new_manifest)
    sources = {}
    for relative in new_entries:
        leaf = _leaf_metadata(source_root, relative)
        if leaf is None:
            raise FileNotFoundError(f"candidate manifest entry is missing: {relative}")
        sources[relative] = leaf
    if record.exists() and record.stat().st_size:
        raise ValueError("managed activation record must start empty")

    for relative in sorted(old_entries, key=lambda item: (item.count("/"), item), reverse=True):
        _remove_leaf(target_root, relative)
    _prune_empty_parents(target_root, old_entries)

    for relative in new_entries:
        metadata, kind, symlink_target = sources[relative]
        if kind == "file":
            descriptor, observed = _open_regular(source_root, relative)
            try:
                if (observed.st_dev, observed.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise RuntimeError(f"candidate changed during activation: {relative}")
                with os.fdopen(descriptor, "rb") as source:
                    descriptor = -1
                    _install_regular(
                        target_root,
                        relative,
                        source,
                        stat.S_IMODE(observed.st_mode),
                        lambda created, path=relative: _append_record(
                            record, path, created
                        ),
                    )
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        else:
            _install_symlink(
                target_root,
                relative,
                symlink_target,
                lambda created, path=relative: _append_record(record, path, created),
            )


def _recorded_entries(record: Path):
    if not record.exists():
        return []
    entries = []
    for line in record.read_text(encoding="utf-8").splitlines():
        payload = json.loads(line)
        relative = str(payload["path"])
        _parts(relative)
        entries.append((relative, (int(payload["dev"]), int(payload["ino"]))))
    return entries


def _member_matches(target_root: Path, member: tarfile.TarInfo, source) -> bool:
    leaf = _leaf_metadata(target_root, member.name)
    if leaf is None:
        return False
    metadata, kind, target = leaf
    if member.issym():
        return kind == "symlink" and target == member.linkname
    if kind != "file" or stat.S_IMODE(metadata.st_mode) != member.mode:
        return False
    descriptor, _ = _open_regular(target_root, member.name)
    archived = source.extractfile(member)
    if archived is None:
        os.close(descriptor)
        raise ValueError(f"backup file has no data: {member.name}")
    with os.fdopen(descriptor, "rb") as current, archived:
        while True:
            current_chunk = current.read(1024 * 1024)
            archived_chunk = archived.read(1024 * 1024)
            if current_chunk != archived_chunk:
                return False
            if not current_chunk:
                return True


def rollback(
    target_root: Path,
    old_manifest: Path,
    new_manifest: Path,
    record: Path,
    archive: Path,
) -> None:
    _validate_root(target_root)
    new_entries = load_manifest(new_manifest)
    installed = _recorded_entries(record)
    for relative, identity in sorted(
        installed, key=lambda item: (item[0].count("/"), item[0]), reverse=True
    ):
        _remove_leaf(target_root, relative, expected_identity=identity)
    _prune_empty_parents(target_root, new_entries)

    for source, members in _archive_members(archive, old_manifest):
        for member in members:
            if _member_matches(target_root, member, source):
                continue
            if _leaf_metadata(target_root, member.name) is not None:
                raise RuntimeError(f"rollback destination is occupied: {member.name}")
            if member.issym():
                _install_symlink(target_root, member.name, member.linkname)
            else:
                archived = source.extractfile(member)
                if archived is None:
                    raise ValueError(f"backup file has no data: {member.name}")
                with archived:
                    _install_regular(target_root, member.name, archived, member.mode)
        for member in members:
            if not _member_matches(target_root, member, source):
                raise RuntimeError(f"rollback verification failed: {member.name}")


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    backup_parser = subparsers.add_parser("backup")
    backup_parser.add_argument("--target-root", type=Path, required=True)
    backup_parser.add_argument("--manifest", type=Path, required=True)
    backup_parser.add_argument("--archive", type=Path, required=True)

    validate_parser = subparsers.add_parser("validate-backup")
    validate_parser.add_argument("--manifest", type=Path, required=True)
    validate_parser.add_argument("--archive", type=Path, required=True)

    activate_parser = subparsers.add_parser("activate")
    activate_parser.add_argument("--source-root", type=Path, required=True)
    activate_parser.add_argument("--target-root", type=Path, required=True)
    activate_parser.add_argument("--old-manifest", type=Path, required=True)
    activate_parser.add_argument("--new-manifest", type=Path, required=True)
    activate_parser.add_argument("--record", type=Path, required=True)

    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--target-root", type=Path, required=True)
    rollback_parser.add_argument("--old-manifest", type=Path, required=True)
    rollback_parser.add_argument("--new-manifest", type=Path, required=True)
    rollback_parser.add_argument("--record", type=Path, required=True)
    rollback_parser.add_argument("--archive", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    if args.command == "backup":
        create_backup(args.target_root, args.manifest, args.archive)
    elif args.command == "validate-backup":
        validate_backup(args.archive, args.manifest)
    elif args.command == "activate":
        activate(
            args.source_root,
            args.target_root,
            args.old_manifest,
            args.new_manifest,
            args.record,
        )
    else:
        rollback(
            args.target_root,
            args.old_manifest,
            args.new_manifest,
            args.record,
            args.archive,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
