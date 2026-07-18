#!/usr/bin/env python3
"""安全地追加或回滚生产 static 文件。

所有目标路径都通过目录 fd 逐层打开，拒绝父目录符号链接；新文件使用
O_EXCL 创建，因此预检后的并发写入也不会被覆盖。
"""

from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path, PurePosixPath


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    parts = path.parts
    if (
        not parts
        or parts[0] != "static"
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError(f"unsafe static path: {relative!r}")
    return parts


def _open_parent(target_root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    current = os.open(target_root, _DIRECTORY_FLAGS)
    try:
        for component in parts[:-1]:
            try:
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _unlink_if_same(parent_fd: int, name: str, identity: tuple[int, int]) -> None:
    try:
        observed_fd = os.open(name, os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=parent_fd)
    except OSError:
        return
    try:
        observed = os.fstat(observed_fd)
    finally:
        os.close(observed_fd)
    if (observed.st_dev, observed.st_ino) == identity:
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)


def install(source: Path, target_root: Path, relative: str, record: Path) -> None:
    parts = _parts(relative)
    source_fd = os.open(source, os.O_RDONLY | _FILE_NOFOLLOW)
    parent_fd = -1
    destination_fd = -1
    identity: tuple[int, int] | None = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError(f"static source is not a regular file: {source}")
        parent_fd = _open_parent(target_root, parts, create=True)
        destination_fd = os.open(
            parts[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
            0o644,
            dir_fd=parent_fd,
        )
        created = os.fstat(destination_fd)
        identity = (created.st_dev, created.st_ino)
        while chunk := os.read(source_fd, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        os.fsync(parent_fd)
        with record.open("ab", buffering=0) as record_file:
            record_file.write(
                os.fsencode(relative)
                + b"\0"
                + str(identity[0]).encode("ascii")
                + b"\0"
                + str(identity[1]).encode("ascii")
                + b"\0"
            )
            os.fsync(record_file.fileno())
    except BaseException:
        if identity is not None and parent_fd >= 0:
            _unlink_if_same(parent_fd, parts[-1], identity)
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(source_fd)


def classify(source: Path, target_root: Path, relative: str) -> str:
    """返回 MISSING/IDENTICAL；内容冲突或符号链接路径直接报错。"""
    parts = _parts(relative)
    source_fd = os.open(source, os.O_RDONLY | _FILE_NOFOLLOW)
    parent_fd = -1
    destination_fd = -1
    try:
        if not stat.S_ISREG(os.fstat(source_fd).st_mode):
            raise ValueError(f"static source is not a regular file: {source}")
        try:
            parent_fd = _open_parent(target_root, parts, create=False)
        except FileNotFoundError:
            return "MISSING"
        try:
            destination_fd = os.open(
                parts[-1], os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=parent_fd
            )
        except FileNotFoundError:
            return "MISSING"
        if not stat.S_ISREG(os.fstat(destination_fd).st_mode):
            raise ValueError(f"static destination is not a regular file: {relative}")
        while True:
            source_chunk = os.read(source_fd, 1024 * 1024)
            destination_chunk = os.read(destination_fd, 1024 * 1024)
            if source_chunk != destination_chunk:
                raise FileExistsError(f"static destination has different content: {relative}")
            if not source_chunk:
                return "IDENTICAL"
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(source_fd)


def remove_recorded(target_root: Path, record: Path) -> None:
    fields = record.read_bytes().split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 3:
        raise ValueError("invalid static installation record")
    for index in range(0, len(fields), 3):
        relative = os.fsdecode(fields[index])
        identity = (int(fields[index + 1]), int(fields[index + 2]))
        parts = _parts(relative)
        try:
            parent_fd = _open_parent(target_root, parts, create=False)
        except FileNotFoundError:
            continue
        try:
            try:
                observed_fd = os.open(
                    parts[-1], os.O_RDONLY | _FILE_NOFOLLOW, dir_fd=parent_fd
                )
            except FileNotFoundError:
                continue
            try:
                observed = os.fstat(observed_fd)
            finally:
                os.close(observed_fd)
            if (observed.st_dev, observed.st_ino) != identity:
                raise RuntimeError(
                    f"static file changed after deployment created it: {relative}"
                )
            os.unlink(parts[-1], dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--source", type=Path, required=True)
    install_parser.add_argument("--target-root", type=Path, required=True)
    install_parser.add_argument("--relative", required=True)
    install_parser.add_argument("--record", type=Path, required=True)

    classify_parser = subparsers.add_parser("classify")
    classify_parser.add_argument("--source", type=Path, required=True)
    classify_parser.add_argument("--target-root", type=Path, required=True)
    classify_parser.add_argument("--relative", required=True)

    recorded_parser = subparsers.add_parser("remove-recorded")
    recorded_parser.add_argument("--target-root", type=Path, required=True)
    recorded_parser.add_argument("--record", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    if args.command == "install":
        install(args.source, args.target_root, args.relative, args.record)
    elif args.command == "classify":
        print(classify(args.source, args.target_root, args.relative))
    elif args.command == "remove-recorded":
        remove_recorded(args.target_root, args.record)
    else:
        raise AssertionError(f"unhandled static command: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
