#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""代码仓库相对路径与判题工作树的安全适配。

仓库路径统一使用 POSIX 相对路径。消费者必须保留目录结构，不能再通过
``basename`` 把不同子目录中的同名文件折叠到一起。
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Iterable, Mapping

from backend.oj_modules.repository import storage


REPOSITORY_SANDBOX_DIRECTORY = "repository"
REPOSITORY_CONTAINER_ROOT = "/sandbox/repository"


class InvalidRepositoryPath(ValueError):
    """仓库条目的相对路径不满足安全约束。"""


def normalize_repository_relative_path(value) -> str:
    """校验并返回规范的 POSIX 仓库相对路径。

    这里是消费者侧的纵深防御；写入侧仍须执行同等或更严格的校验。允许空格、
    Unicode 和任意文本文件扩展名，但拒绝绝对路径、空分量、目录穿越、控制字符
    以及反斜杠歧义。
    """

    try:
        return storage.validate_relative_path(value)
    except storage.RepositoryPathError as exc:
        raise InvalidRepositoryPath(str(exc)) from exc


def repository_target_path(root, relative_path) -> str:
    """把仓库相对路径安全解析到给定根目录下。"""

    normalized = normalize_repository_relative_path(relative_path)
    root_abs = os.path.abspath(os.fspath(root))
    target = os.path.abspath(os.path.join(root_abs, *normalized.split("/")))
    if os.path.commonpath((root_abs, target)) != root_abs:
        raise InvalidRepositoryPath("仓库路径越过目标根目录")
    return target


def _iter_repository_entries(entries) -> Iterable[tuple[str, str, object]]:
    """产出 ``(path, type, content)``；旧 ``{path: content}`` 仍按文件兼容。"""

    if isinstance(entries, Mapping):
        for path, content in entries.items():
            yield path, "file", content
        return
    for item in entries or ():
        if not isinstance(item, Mapping):
            raise TypeError("仓库条目必须是映射")
        path = (
            item.get("relative_path")
            or item.get("path")
            or item.get("filename")
        )
        entry_type = str(item.get("entry_type") or item.get("type") or "file")
        if entry_type not in {"file", "directory"}:
            raise InvalidRepositoryPath(f"仓库条目类型非法：{entry_type}")
        if "content" in item:
            content = item.get("content")
        else:
            content = item.get("file_content")
        yield path, entry_type, content


def _iter_repository_files(files) -> Iterable[tuple[str, object]]:
    if isinstance(files, Mapping):
        yield from files.items()
        return
    for path, entry_type, content in _iter_repository_entries(files):
        if entry_type == "file":
            yield path, content


def normalize_repository_files(files) -> list[tuple[str, str]]:
    """规范仓库文件集合并拒绝规范化后的重复路径。"""

    normalized = []
    seen = set()
    for raw_path, raw_content in _iter_repository_files(files):
        relative_path = normalize_repository_relative_path(raw_path)
        if relative_path in seen:
            raise InvalidRepositoryPath(f"仓库文件路径重复：{relative_path}")
        seen.add(relative_path)
        content = raw_content if isinstance(raw_content, str) else str(raw_content or "")
        normalized.append((relative_path, content))
    normalized.sort(key=lambda item: item[0])
    return normalized


def normalize_repository_entries(entries) -> list[tuple[str, str, str]]:
    """规范完整仓库树（含空目录）并拒绝文件/目录路径冲突。"""

    normalized = []
    seen = {}
    for raw_path, entry_type, raw_content in _iter_repository_entries(entries):
        relative_path = normalize_repository_relative_path(raw_path)
        if relative_path in seen:
            raise InvalidRepositoryPath(f"仓库条目路径重复：{relative_path}")
        seen[relative_path] = entry_type
        content = ""
        if entry_type == "file":
            content = raw_content if isinstance(raw_content, str) else str(raw_content or "")
        normalized.append((relative_path, entry_type, content))

    for relative_path, _entry_type, _content in normalized:
        parent = relative_path.rpartition("/")[0]
        while parent:
            if seen.get(parent) == "file":
                raise InvalidRepositoryPath(f"仓库文件与目录路径冲突：{relative_path}")
            parent = parent.rpartition("/")[0]
    normalized.sort(key=lambda item: (item[0].count("/"), item[0], item[1] != "directory"))
    return normalized


def materialize_repository_tree(run_dir, files) -> list[str]:
    """在 ``run_dir/repository`` 中重建只含文本文件的仓库树。

    目标子根每次都会被完整替换，避免复用 sid 时残留旧文件。所有写入都发生在
    明确的 ``repository`` 子目录中；仓库里的 ``.c/.cpp`` 只会作为普通文件落盘，
    编译命令仍只编译沙箱根下的 ``main.c/main.cpp``。
    """

    run_root = os.path.abspath(os.fspath(run_dir))
    repository_root = os.path.join(run_root, REPOSITORY_SANDBOX_DIRECTORY)
    if os.path.lexists(repository_root):
        if os.path.islink(repository_root) or not os.path.isdir(repository_root):
            os.unlink(repository_root)
        else:
            shutil.rmtree(repository_root)
    os.makedirs(repository_root, mode=0o755, exist_ok=False)

    normalized_entries = normalize_repository_entries(files)
    created = []
    for relative_path, entry_type, content in normalized_entries:
        target = repository_target_path(repository_root, relative_path)
        if entry_type == "directory":
            if os.path.lexists(target):
                if not os.path.isdir(target) or os.path.islink(target):
                    raise InvalidRepositoryPath(f"仓库目录路径冲突：{relative_path}")
            else:
                os.makedirs(target, mode=0o755, exist_ok=False)
            created.append(relative_path)
            continue

        parent = os.path.dirname(target)
        os.makedirs(parent, mode=0o755, exist_ok=True)

        # 前一条目可能把当前父路径占成普通文件；明确拒绝而不是覆盖或跟随链接。
        current = repository_root
        for part in relative_path.split("/")[:-1]:
            current = os.path.join(current, part)
            mode = os.lstat(current).st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise InvalidRepositoryPath(f"仓库目录路径冲突：{relative_path}")
        if os.path.lexists(target):
            raise InvalidRepositoryPath(f"仓库文件路径冲突：{relative_path}")
        with open(target, "x", encoding="utf-8", newline="") as handle:
            handle.write(content)
        created.append(relative_path)
    return created
