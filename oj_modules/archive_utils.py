#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""受限 ZIP 解压工具。

调用方通过 :class:`ZipExtractionPolicy` 明确资源上限和非法成员的处理方式；
本模块只负责校验与流式落盘，不包含任何业务错误文案。
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import math
import os
import posixpath
import re
import shutil
import stat
import zipfile


_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:/")
_UNSAFE_MEMBER_REASONS = frozenset({
    "absolute_path",
    "path_traversal",
    "outside_destination",
    "symlink",
})


@dataclass(frozen=True)
class ZipExtractionPolicy:
    """ZIP 解压约束；所有大小单位均为字节。

    ``unsafe_member_action`` 仅控制绝对路径、目录穿越、越界目标和符号链接：
    ``raise`` 拒绝整个压缩包，``skip`` 忽略该成员后继续。资源上限、重复路径、
    加密成员和数据完整性错误始终拒绝整个压缩包。

    ``cleanup_on_error`` 适用于调用方专门创建的临时目录。启用后，任何解压异常
    都会删除整个目标目录，因此不应对含有既有业务文件的目录使用。
    """

    max_members: int | None
    max_file_bytes: int | None
    max_total_bytes: int | None
    max_compression_ratio: float | None
    require_non_empty: bool = False
    reject_encrypted: bool = True
    reject_symlinks: bool = True
    reject_duplicate_targets: bool = True
    unsafe_member_action: str = "raise"
    cleanup_on_error: bool = False
    chunk_size: int = 1024 * 1024

    def __post_init__(self):
        for name in ("max_members", "max_file_bytes", "max_total_bytes"):
            value = getattr(self, name)
            if value is not None and int(value) <= 0:
                raise ValueError(f"{name} must be positive or None")
        if self.max_compression_ratio is not None:
            ratio = float(self.max_compression_ratio)
            if not math.isfinite(ratio) or ratio <= 0:
                raise ValueError("max_compression_ratio must be finite and positive or None")
        if self.unsafe_member_action not in {"raise", "skip"}:
            raise ValueError("unsafe_member_action must be 'raise' or 'skip'")
        if int(self.chunk_size) <= 0:
            raise ValueError("chunk_size must be positive")


class ArchiveExtractionError(RuntimeError):
    """压缩包违反解压策略。

    ``reason`` 是稳定的机器可读原因；业务层可据此保留自己的用户提示文案。
    """

    def __init__(self, reason: str, member_name: str | None = None):
        self.reason = str(reason)
        self.member_name = member_name
        detail = f": {member_name}" if member_name else ""
        super().__init__(f"zip extraction rejected ({self.reason}){detail}")


def _raise_violation(reason: str, member_name: str | None = None):
    raise ArchiveExtractionError(reason, member_name)


def _is_within_directory(base_dir: str, path: str):
    try:
        return os.path.commonpath((base_dir, path)) == base_dir
    except ValueError:
        # Windows 上跨盘符路径无法计算 commonpath，应视为越界。
        return False


def _normalized_member_target(base_dir: str, raw_name: str):
    member_name = str(raw_name or "").replace("\\", "/")
    if not member_name:
        return None
    if "\x00" in member_name:
        _raise_violation("outside_destination", raw_name)
    if member_name.startswith("/") or _WINDOWS_ABSOLUTE_PATH.match(member_name):
        _raise_violation("absolute_path", raw_name)

    parts = member_name.split("/")
    if any(part == ".." for part in parts):
        _raise_violation("path_traversal", raw_name)

    normalized = posixpath.normpath(member_name)
    if normalized in {"", "."}:
        return None
    target = os.path.realpath(os.path.join(base_dir, normalized))
    if not _is_within_directory(base_dir, target):
        _raise_violation("outside_destination", raw_name)
    return target


def _is_zip_symlink(info: zipfile.ZipInfo):
    mode = (int(info.external_attr or 0) >> 16) & 0xFFFF
    return bool(mode and stat.S_ISLNK(mode))


def _handle_unsafe_member(policy: ZipExtractionPolicy, error: ArchiveExtractionError):
    if error.reason in _UNSAFE_MEMBER_REASONS and policy.unsafe_member_action == "skip":
        return True
    raise error


def _prepare_members(zf: zipfile.ZipFile, base_dir: str, policy: ZipExtractionPolicy):
    infos = zf.infolist()
    if policy.require_non_empty and not infos:
        _raise_violation("empty_archive")
    if policy.max_members is not None and len(infos) > int(policy.max_members):
        _raise_violation("too_many_members")

    announced_total = sum(max(0, int(info.file_size or 0)) for info in infos)
    if policy.max_total_bytes is not None and announced_total > int(policy.max_total_bytes):
        _raise_violation("total_too_large")

    prepared = []
    targets = set()
    for info in infos:
        raw_name = str(info.filename or "")
        try:
            resolved = _normalized_member_target(base_dir, raw_name)
            if resolved is None:
                continue
            target = resolved
            if policy.reject_symlinks and _is_zip_symlink(info):
                _raise_violation("symlink", raw_name)
        except ArchiveExtractionError as error:
            if _handle_unsafe_member(policy, error):
                continue
            raise

        if policy.reject_duplicate_targets and target in targets:
            _raise_violation("duplicate_target", raw_name)
        targets.add(target)
        if policy.reject_encrypted and info.flag_bits & 0x1:
            _raise_violation("encrypted_member", raw_name)

        is_dir = info.is_dir() or raw_name.replace("\\", "/").endswith("/")
        if not is_dir:
            declared_size = max(0, int(info.file_size or 0))
            if policy.max_file_bytes is not None and declared_size > int(policy.max_file_bytes):
                _raise_violation("file_too_large", raw_name)
            compressed_size = max(0, int(info.compress_size or 0))
            if declared_size and policy.max_compression_ratio is not None:
                ratio = declared_size / compressed_size if compressed_size else float("inf")
                if ratio > float(policy.max_compression_ratio):
                    _raise_violation("compression_ratio", raw_name)
        prepared.append((info, target, is_dir))

    # 同一路径的重复成员在上方处理；这里补足文件与后代路径的冲突。例如 ``a``
    # 是文件时，``a/b`` 无论出现在它之前还是之后都不可能安全落盘。
    sorted_targets = sorted(targets)
    member_names = {target: str(info.filename or "") for info, target, _ in prepared}
    for _, target, is_dir in prepared:
        if is_dir:
            continue
        descendant_prefix = target + os.sep
        index = bisect_left(sorted_targets, descendant_prefix)
        if index < len(sorted_targets) and sorted_targets[index].startswith(descendant_prefix):
            _raise_violation("target_conflict", member_names[sorted_targets[index]])
    return prepared


def _open_output_file(path: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    # 与内置 ``open(path, "wb")`` 保持相同权限语义，最终权限仍受进程 umask 约束。
    fd = os.open(path, flags, 0o666)
    return os.fdopen(fd, "wb")


def extract_zip(zip_path, destination, *, policy: ZipExtractionPolicy):
    """按 ``policy`` 将 ZIP 流式解压到 ``destination``。

    ``zipfile.BadZipFile``、文件系统错误等底层异常保持原类型；策略违规统一抛出
    :class:`ArchiveExtractionError`。若启用清理，所有异常（包括底层异常）都会移除
    目标目录。
    """

    destination_path = os.path.abspath(os.fspath(destination))
    os.makedirs(destination_path, exist_ok=True)
    base_dir = os.path.realpath(destination_path)

    try:
        with zipfile.ZipFile(os.fspath(zip_path), "r") as zf:
            members = _prepare_members(zf, base_dir, policy)
            actual_total = 0
            for info, target, is_dir in members:
                if is_dir:
                    os.makedirs(target, exist_ok=True)
                    continue

                parent = os.path.dirname(target)
                os.makedirs(parent, exist_ok=True)
                # 防止目标目录中预先存在的符号链接在预检后把写入重定向到目录外。
                resolved_parent = os.path.realpath(parent)
                if not _is_within_directory(base_dir, resolved_parent):
                    _raise_violation("outside_destination", info.filename)

                declared_size = max(0, int(info.file_size or 0))
                written = 0
                with zf.open(info, "r") as source, _open_output_file(target) as output:
                    while True:
                        chunk = source.read(int(policy.chunk_size))
                        if not chunk:
                            break
                        written += len(chunk)
                        actual_total += len(chunk)
                        if written > declared_size:
                            _raise_violation("size_mismatch", info.filename)
                        if policy.max_file_bytes is not None and written > int(policy.max_file_bytes):
                            _raise_violation("file_too_large", info.filename)
                        if policy.max_total_bytes is not None and actual_total > int(policy.max_total_bytes):
                            _raise_violation("total_too_large", info.filename)
                        output.write(chunk)
                if written != declared_size:
                    _raise_violation("size_mismatch", info.filename)
    except Exception:
        if policy.cleanup_on_error:
            shutil.rmtree(destination_path, ignore_errors=True)
        raise
