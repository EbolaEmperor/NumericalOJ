#!/usr/bin/env python3
"""创建并校验可复用生产虚拟环境的只读完整性封印。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


SEAL_NAME = ".numericaloj-integrity.json"
FORMAT_VERSION = 1


def _entries(root: Path):
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in tuple(directories) + tuple(files):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if relative == SEAL_NAME:
                continue
            yield relative, path


def tree_digest(root: Path, *, require_readonly: bool) -> str:
    digest = hashlib.sha256()
    for relative, path in _entries(root):
        metadata = path.lstat()
        if (
            require_readonly
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_mode & 0o222
        ):
            raise ValueError(f"venv entry is writable: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            kind = b"D"
        elif stat.S_ISREG(metadata.st_mode):
            kind = b"F"
        elif stat.S_ISLNK(metadata.st_mode):
            kind = b"L"
        else:
            raise ValueError(f"unsupported venv entry type: {relative}")
        digest.update(kind)
        digest.update(b"\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(metadata.st_mode) & 0o555:o}".encode("ascii"))
        digest.update(b"\0")
        if kind == b"F":
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        elif kind == b"L":
            digest.update(os.fsencode(os.readlink(path)))
        digest.update(b"\0")
    return digest.hexdigest()


def _remove_write_bits(root: Path) -> None:
    paths = [root, *(path for _, path in _entries(root)), root / SEAL_NAME]
    for path in reversed(paths):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            continue
        os.chmod(path, stat.S_IMODE(metadata.st_mode) & ~0o222)


def seal(root: Path, requirements_sha256: str) -> None:
    _validate_root(root)
    seal_path = root / SEAL_NAME
    if seal_path.exists() or seal_path.is_symlink():
        raise FileExistsError(f"venv seal already exists: {seal_path}")
    payload = {
        "format": FORMAT_VERSION,
        "python": "3.12",
        "requirements_sha256": _validate_digest(requirements_sha256),
        "tree_sha256": tree_digest(root, require_readonly=False),
    }
    seal_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _remove_write_bits(root)
    verify(root, requirements_sha256)


def verify(root: Path, requirements_sha256: str) -> None:
    _validate_root(root)
    if root.stat().st_mode & 0o222:
        raise ValueError("venv root must be read-only")
    seal_path = root / SEAL_NAME
    metadata = seal_path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222:
        raise ValueError("venv integrity seal must be a read-only regular file")
    payload = json.loads(seal_path.read_text(encoding="utf-8"))
    expected = {
        "format": FORMAT_VERSION,
        "python": "3.12",
        "requirements_sha256": _validate_digest(requirements_sha256),
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"venv seal mismatch for {key}")
    observed = tree_digest(root, require_readonly=True)
    if payload.get("tree_sha256") != observed:
        raise ValueError("venv tree digest mismatch")


def _validate_root(root: Path) -> None:
    if root.is_symlink() or not root.is_dir() or root.resolve() != root.absolute():
        raise ValueError(f"venv root must be a real directory: {root}")


def _validate_digest(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("requirements digest must be lowercase sha256")
    return value


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("seal", "verify"):
        child = subparsers.add_parser(command)
        child.add_argument("--venv", type=Path, required=True)
        child.add_argument("--requirements-sha256", required=True)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    if args.command == "seal":
        seal(args.venv, args.requirements_sha256)
    else:
        verify(args.venv, args.requirements_sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
