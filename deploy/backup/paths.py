"""Filesystem guards shared by database deployment helpers.

Deployment metadata and backup artifacts are deliberately confined to a small
managed tree.  These helpers reject lexical traversal and every existing
symbolic-link component before callers create, read, execute against, or delete
one of those paths.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


class UnsafePathError(RuntimeError):
    """A deployment path cannot be proven to stay inside its managed tree."""


def absolute_lexical_path(
    value: str | os.PathLike[str],
    *,
    label: str,
) -> Path:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise UnsafePathError(f"{label} 路径无效")
    path = Path(raw)
    if ".." in path.parts:
        raise UnsafePathError(f"{label} 路径不能包含 ..: {path}")
    if not path.is_absolute():
        raise UnsafePathError(f"{label} 必须是绝对路径: {path}")
    return path


def assert_no_symlink_components(
    value: str | os.PathLike[str],
    *,
    label: str,
    allow_missing_leaf: bool = False,
) -> Path:
    path = absolute_lexical_path(value, label=label)
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:], 1):
        current /= part
        is_leaf = index == len(path.parts) - 1
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and is_leaf:
                return path
            raise UnsafePathError(f"{label} 路径组件不存在: {current}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise UnsafePathError(f"{label} 路径不能包含符号链接: {current}")
    return path


def existing_directory(
    value: str | os.PathLike[str],
    *,
    label: str,
) -> Path:
    path = assert_no_symlink_components(value, label=label)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise UnsafePathError(f"{label} 不是目录: {path}")
    return path


def ensure_directory(
    value: str | os.PathLike[str],
    *,
    label: str,
    mode: int = 0o700,
) -> Path:
    """Create one missing leaf below a verified existing parent."""

    path = absolute_lexical_path(value, label=label)
    if path.exists() or path.is_symlink():
        return existing_directory(path, label=label)
    existing_directory(path.parent, label=f"{label} parent")
    created = False
    try:
        path.mkdir(mode=mode)
        created = True
    except FileExistsError:
        pass
    directory = existing_directory(path, label=label)
    if created:
        os.chmod(directory, mode)
    return directory


def managed_path(
    root: str | os.PathLike[str],
    relative: str | os.PathLike[str],
    *,
    label: str,
    allow_missing_leaf: bool = False,
) -> Path:
    managed_root = existing_directory(root, label="managed root")
    raw_relative = os.fspath(relative)
    if not isinstance(raw_relative, str) or not raw_relative or "\x00" in raw_relative:
        raise UnsafePathError(f"{label} 相对路径无效")
    relative_path = Path(raw_relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise UnsafePathError(f"{label} 必须是 managed root 内相对路径")
    candidate = managed_root / relative_path
    return assert_no_symlink_components(
        candidate,
        label=label,
        allow_missing_leaf=allow_missing_leaf,
    )


def validate_layout(
    root: str | os.PathLike[str],
    names: tuple[str, ...],
) -> dict[str, Path]:
    managed_root = existing_directory(root, label="backup root")
    layout = {"root": managed_root}
    for name in names:
        if not name or "/" in name or name in {".", ".."}:
            raise UnsafePathError(f"受管子目录名称无效: {name!r}")
        layout[name] = existing_directory(
            managed_root / name,
            label=f"backup {name} directory",
        )
    return layout
