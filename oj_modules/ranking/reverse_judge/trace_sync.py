#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse Judge 与 Problem Agent 共用的 harness 轨迹同步。"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile


CLAUDE_PROJECT_DIR = "/home/node/.claude/projects/-workspace"
PI_SESSION_DIR = "/home/node/.pi/agent/sessions"
PI_COMBINED_TRACE_NAME = "reverse_solve_combined.jsonl"
TRACE_REDACTION_MARKER = b"[REDACTED]"
CLAUDE_TRACE_MAX_FILES = 64
CLAUDE_TRACE_MAX_FILE_BYTES = 16 * 1024 * 1024
CLAUDE_TRACE_MAX_TOTAL_BYTES = 64 * 1024 * 1024
CLAUDE_TRACE_MAX_PUBLISHED_FILE_BYTES = 32 * 1024 * 1024
CLAUDE_TRACE_MAX_PUBLISHED_TOTAL_BYTES = (
    2 * CLAUDE_TRACE_MAX_TOTAL_BYTES + CLAUDE_TRACE_MAX_FILES + 1
)
CLAUDE_TRACE_MANIFEST_MAX_BYTES = 64 * 1024
CLAUDE_TRACE_SYNC_TIMEOUT_SECONDS = 30
PI_TRACE_MAX_FILES = 128
PI_TRACE_MAX_FILE_BYTES = 16 * 1024 * 1024
PI_TRACE_MAX_TOTAL_BYTES = 64 * 1024 * 1024
PI_TRACE_MAX_PUBLISHED_FILE_BYTES = 32 * 1024 * 1024
PI_TRACE_MAX_PUBLISHED_TOTAL_BYTES = (
    2 * PI_TRACE_MAX_TOTAL_BYTES + PI_TRACE_MAX_FILES + 1
)
PI_TRACE_MAX_DIRECTORIES = 512
PI_TRACE_MAX_SCANNED_ENTRIES = 4096
PI_TRACE_MAX_DEPTH = 16
PI_TRACE_MAX_PATH_BYTES = 1024
PI_TRACE_MANIFEST_MAX_BYTES = 128 * 1024
PI_TRACE_SYNC_TIMEOUT_SECONDS = 30
STDOUT_TRACE_MAX_BYTES = 8 * 1024 * 1024
STDOUT_TRACE_MAX_PUBLISHED_BYTES = 16 * 1024 * 1024


def _trace_secret_patterns(secrets):
    patterns = set()
    for value in secrets or ():
        if isinstance(value, bytes):
            encoded = value
        else:
            encoded = str(value or "").encode("utf-8")
        if encoded and encoded != TRACE_REDACTION_MARKER:
            patterns.add(encoded)
    return sorted(patterns, key=len, reverse=True)


def _redact_trace_bytes(payload, secrets):
    redacted = payload
    for secret in _trace_secret_patterns(secrets):
        redacted = redacted.replace(secret, TRACE_REDACTION_MARKER)
    return redacted


def _publish_redacted_stream(
    source,
    destination,
    secrets,
    *,
    max_output_bytes=None,
):
    """逐行脱敏并原子发布 JSONL，避免正式轨迹短暂出现明文凭证。"""

    temporary = destination + ".tmp"
    patterns = _trace_secret_patterns(secrets)
    written = 0
    try:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(temporary, "wb") as target:
            for chunk in source:
                for secret in patterns:
                    chunk = chunk.replace(secret, TRACE_REDACTION_MARKER)
                written += len(chunk)
                if max_output_bytes is not None and written > max_output_bytes:
                    raise ValueError("脱敏后的轨迹超过发布上限")
                target.write(chunk)
        os.replace(temporary, destination)
        return True
    except Exception:
        try:
            os.remove(temporary)
        except OSError:
            pass
        return False


def _read_exact(source, size):
    payload = bytearray()
    while len(payload) < size:
        chunk = source.read(size - len(payload))
        if not chunk:
            raise ValueError("轨迹导出流提前结束")
        payload.extend(chunk)
    return bytes(payload)


def _copy_redacted_exact(
    source,
    size,
    destinations,
    secrets,
    *,
    max_file_output_bytes,
    total_output_state,
):
    """从有界导出流复制一个文件，逐行脱敏后同时写入目标。"""

    patterns = _trace_secret_patterns(secrets)
    remaining = int(size)
    output_size = 0
    wrote_any = False
    last_byte = b""
    while remaining:
        # 单行最坏占用受 CLAUDE_TRACE_MAX_FILE_BYTES 约束；使用 readline
        # 可让跨普通读取块的凭证仍在同一轮替换中被完整脱敏。
        chunk = source.readline(remaining)
        if not chunk:
            raise ValueError("轨迹导出文件提前结束")
        remaining -= len(chunk)
        for secret in patterns:
            chunk = chunk.replace(secret, TRACE_REDACTION_MARKER)
        output_size += len(chunk)
        total_output_state["size"] += len(chunk) * len(destinations)
        if output_size > max_file_output_bytes:
            raise ValueError("脱敏后的单个轨迹超过发布上限")
        if total_output_state["size"] > total_output_state["limit"]:
            raise ValueError("脱敏后的轨迹总发布量超过上限")
        for destination in destinations:
            destination.write(chunk)
        if chunk:
            wrote_any = True
            last_byte = chunk[-1:]
    return wrote_any, last_byte


def _charge_trace_output(total_output_state, size):
    total_output_state["size"] += int(size)
    if total_output_state["size"] > total_output_state["limit"]:
        raise ValueError("脱敏后的轨迹总发布量超过上限")


def _iter_exact_lines(source, size):
    remaining = int(size)
    while remaining:
        chunk = source.readline(remaining)
        if not chunk:
            raise ValueError("轨迹源文件提前结束")
        remaining -= len(chunk)
        yield chunk


def _safe_claude_trace_entry(item, *, combined_filename):
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "")
    if (
        not name
        or name in {".", "..", combined_filename}
        or not name.endswith(".jsonl")
        or os.path.basename(name) != name
        or any(ord(char) < 32 or ord(char) == 127 for char in name)
    ):
        return None
    size = item.get("size")
    if isinstance(size, bool) or not isinstance(size, int):
        return None
    if size < 0 or size > CLAUDE_TRACE_MAX_FILE_BYTES:
        return None
    return name, size


def _claude_trace_export_script(container_project_dir):
    """生成单次 docker exec 使用的 no-follow、有界导出程序。"""

    return (
        "import json, os, stat, sys\n"
        f"base={str(container_project_dir)!r}\n"
        f"max_files={int(CLAUDE_TRACE_MAX_FILES)}\n"
        f"max_file_bytes={int(CLAUDE_TRACE_MAX_FILE_BYTES)}\n"
        f"max_total_bytes={int(CLAUDE_TRACE_MAX_TOTAL_BYTES)}\n"
        "flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|"
        "getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)\n"
        "try:\n"
        "    directory_fd=os.open(base, flags)\n"
        "except OSError:\n"
        "    sys.exit(2)\n"
        "try:\n"
        "    entries=[]\n"
        "    total=0\n"
        "    with os.scandir(directory_fd) as scanner:\n"
        "        for entry in scanner:\n"
        "            if not entry.name.endswith('.jsonl'):\n"
        "                continue\n"
        "            try:\n"
        "                info=entry.stat(follow_symlinks=False)\n"
        "            except OSError:\n"
        "                continue\n"
        "            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:\n"
        "                continue\n"
        "            if len(entries) >= max_files:\n"
        "                sys.exit(3)\n"
        "            if info.st_size < 0 or info.st_size > max_file_bytes:\n"
        "                sys.exit(4)\n"
        "            total += info.st_size\n"
        "            if total > max_total_bytes:\n"
        "                sys.exit(5)\n"
        "            entries.append((info.st_mtime_ns, entry.name, "
        "info.st_dev, info.st_ino, info.st_size))\n"
        "    entries.sort(key=lambda item:(item[0], item[1]))\n"
        "    manifest=json.dumps([{'name':item[1],'size':item[4]} "
        "for item in entries], ensure_ascii=False, "
        "separators=(',',':')).encode('utf-8')\n"
        "    output=sys.stdout.buffer\n"
        "    output.write(len(manifest).to_bytes(4, 'big'))\n"
        "    output.write(manifest)\n"
        "    file_flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|"
        "getattr(os,'O_CLOEXEC',0)\n"
        "    for _mtime, name, device, inode, expected_size in entries:\n"
        "        fd=os.open(name, file_flags, dir_fd=directory_fd)\n"
        "        try:\n"
        "            current=os.fstat(fd)\n"
        "            if (not stat.S_ISREG(current.st_mode) or "
        "current.st_nlink != 1 or current.st_dev != device or "
        "current.st_ino != inode or current.st_size != expected_size):\n"
        "                sys.exit(6)\n"
        "            remaining=expected_size\n"
        "            while remaining:\n"
        "                chunk=os.read(fd, min(65536, remaining))\n"
        "                if not chunk:\n"
        "                    sys.exit(7)\n"
        "                output.write(chunk)\n"
        "                remaining -= len(chunk)\n"
        "        finally:\n"
        "            os.close(fd)\n"
        "    output.flush()\n"
        "finally:\n"
        "    os.close(directory_fd)\n"
    )


def sync_claude_project_jsonl(
    container_name,
    trace_dir,
    *,
    container_project_dir=CLAUDE_PROJECT_DIR,
    combined_filename="reverse_solve_combined.jsonl",
    secrets=(),
):
    """同步 Claude Code 主会话 JSONL，并生成稳定的合并轨迹。"""

    export_script = _claude_trace_export_script(container_project_dir)
    try:
        with tempfile.TemporaryFile(mode="w+b") as exported:
            copied = subprocess.run(
                ["docker", "exec", container_name, "python3", "-c", export_script],
                stdout=exported,
                stderr=subprocess.DEVNULL,
                timeout=CLAUDE_TRACE_SYNC_TIMEOUT_SECONDS,
            )
            if copied.returncode != 0:
                return False
            exported.seek(0)
            manifest_size = int.from_bytes(_read_exact(exported, 4), "big")
            if manifest_size > CLAUDE_TRACE_MANIFEST_MAX_BYTES:
                return False
            manifest = json.loads(
                _read_exact(exported, manifest_size).decode("utf-8")
            )
            if not isinstance(manifest, list) or not manifest:
                return False
            if len(manifest) > CLAUDE_TRACE_MAX_FILES:
                return False

            entries = []
            seen_names = set()
            total_size = 0
            for item in manifest:
                entry = _safe_claude_trace_entry(
                    item,
                    combined_filename=combined_filename,
                )
                if entry is None or entry[0] in seen_names:
                    return False
                seen_names.add(entry[0])
                total_size += entry[1]
                if total_size > CLAUDE_TRACE_MAX_TOTAL_BYTES:
                    return False
                entries.append(entry)

            project_dir = os.path.join(
                trace_dir,
                ".claude",
                "projects",
                "-workspace",
            )
            os.makedirs(project_dir, exist_ok=True)
            pending = []
            combined_destination = os.path.join(project_dir, combined_filename)
            combined_temporary = None
            wrote_combined = False
            combined_last_byte = b""
            total_output_state = {
                "size": 0,
                "limit": CLAUDE_TRACE_MAX_PUBLISHED_TOTAL_BYTES,
            }
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w+b",
                    dir=project_dir,
                    prefix=".combined-",
                    delete=False,
                ) as combined_stream:
                    combined_temporary = combined_stream.name
                    for name, size in entries:
                        destination = os.path.join(project_dir, name)
                        with tempfile.NamedTemporaryFile(
                            mode="w+b",
                            dir=project_dir,
                            prefix=".session-",
                            delete=False,
                        ) as file_stream:
                            file_temporary = file_stream.name
                            pending.append((file_temporary, destination))
                            if (
                                size
                                and wrote_combined
                                and combined_last_byte != b"\n"
                            ):
                                _charge_trace_output(total_output_state, 1)
                                combined_stream.write(b"\n")
                            wrote_file, last_byte = _copy_redacted_exact(
                                exported,
                                size,
                                (file_stream, combined_stream),
                                secrets,
                                max_file_output_bytes=(
                                    CLAUDE_TRACE_MAX_PUBLISHED_FILE_BYTES
                                ),
                                total_output_state=total_output_state,
                            )
                            if wrote_file:
                                wrote_combined = True
                                combined_last_byte = last_byte
                    if exported.read(1):
                        raise ValueError("轨迹导出流包含额外数据")
                    if not wrote_combined:
                        raise ValueError("轨迹导出为空")
                    if combined_last_byte != b"\n":
                        _charge_trace_output(total_output_state, 1)
                        combined_stream.write(b"\n")

                for temporary, destination in pending:
                    os.replace(temporary, destination)
                os.replace(combined_temporary, combined_destination)
                return True
            except Exception:
                for temporary, _destination in pending:
                    try:
                        os.remove(temporary)
                    except OSError:
                        pass
                if combined_temporary:
                    try:
                        os.remove(combined_temporary)
                    except OSError:
                        pass
                return False
    except Exception:
        return False


def sync_stdout_jsonl(
    source_path,
    trace_dir,
    destination_filename,
    *,
    secrets=(),
):
    """按 Reverse Judge 的方式把宿主捕获 stdout 原子发布为轨迹 JSONL。"""

    try:
        before = os.lstat(source_path)
    except OSError:
        return False
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > STDOUT_TRACE_MAX_BYTES
    ):
        return False
    destination = os.path.join(trace_dir, destination_filename)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        os.makedirs(trace_dir, exist_ok=True)
        fd = os.open(source_path, flags)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or opened.st_size > STDOUT_TRACE_MAX_BYTES
            ):
                return False
            with os.fdopen(fd, "rb", closefd=False) as source:
                return _publish_redacted_stream(
                    _iter_exact_lines(source, opened.st_size),
                    destination,
                    secrets,
                    max_output_bytes=STDOUT_TRACE_MAX_PUBLISHED_BYTES,
                )
        finally:
            os.close(fd)
    except Exception:
        return False


def _safe_pi_session_relative_path(value):
    relative_path = str(value or "")
    parts = relative_path.split("/")
    if (
        not relative_path
        or relative_path != relative_path.strip()
        or relative_path.startswith("/")
        or not relative_path.endswith(".jsonl")
        or "\\" in relative_path
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in relative_path)
        or len(parts) > PI_TRACE_MAX_DEPTH + 1
        or len(relative_path.encode("utf-8")) > PI_TRACE_MAX_PATH_BYTES
        or parts[-1] == PI_COMBINED_TRACE_NAME
    ):
        return ""
    return relative_path


def _safe_pi_trace_entry(item):
    if not isinstance(item, dict):
        return None
    relative_path = _safe_pi_session_relative_path(item.get("relative_path"))
    size = item.get("size")
    mtime_ns = item.get("mtime_ns")
    if (
        not relative_path
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 0
        or size > PI_TRACE_MAX_FILE_BYTES
        or isinstance(mtime_ns, bool)
        or not isinstance(mtime_ns, int)
        or mtime_ns < 0
    ):
        return None
    return relative_path, size, mtime_ns


def _pi_trace_export_script(container_session_dir):
    """生成单次 Pi session 递归导出的 no-follow、有界程序。"""

    return (
        "import json, os, stat, sys\n"
        f"base={str(container_session_dir)!r}\n"
        f"max_files={int(PI_TRACE_MAX_FILES)}\n"
        f"max_file_bytes={int(PI_TRACE_MAX_FILE_BYTES)}\n"
        f"max_total_bytes={int(PI_TRACE_MAX_TOTAL_BYTES)}\n"
        f"max_directories={int(PI_TRACE_MAX_DIRECTORIES)}\n"
        f"max_scanned_entries={int(PI_TRACE_MAX_SCANNED_ENTRIES)}\n"
        f"max_depth={int(PI_TRACE_MAX_DEPTH)}\n"
        f"max_path_bytes={int(PI_TRACE_MAX_PATH_BYTES)}\n"
        f"max_manifest_bytes={int(PI_TRACE_MANIFEST_MAX_BYTES)}\n"
        "directory_flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|"
        "getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)\n"
        "file_flags=os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|"
        "getattr(os,'O_CLOEXEC',0)\n"
        "state={'directories':1,'scanned':0,'total':0}\n"
        "entries=[]\n"
        "base_fd=None\n"
        "def visit(directory_fd, parts, depth):\n"
        "    with os.scandir(directory_fd) as scanner:\n"
        "        for entry in scanner:\n"
        "            state['scanned'] += 1\n"
        "            if state['scanned'] > max_scanned_entries:\n"
        "                sys.exit(3)\n"
        "            name=entry.name\n"
        "            if (not name or name in ('.','..') or '/' in name or "
        "'\\\\' in name or any(ord(ch)<32 or ord(ch)==127 for ch in name)):\n"
        "                continue\n"
        "            try:\n"
        "                info=entry.stat(follow_symlinks=False)\n"
        "            except OSError:\n"
        "                continue\n"
        "            relative_parts=parts+(name,)\n"
        "            relative_path='/'.join(relative_parts)\n"
        "            if len(relative_path.encode('utf-8')) > max_path_bytes:\n"
        "                sys.exit(4)\n"
        "            if stat.S_ISDIR(info.st_mode):\n"
        "                if depth >= max_depth:\n"
        "                    sys.exit(5)\n"
        "                state['directories'] += 1\n"
        "                if state['directories'] > max_directories:\n"
        "                    sys.exit(6)\n"
        "                child_fd=os.open(name, directory_flags, "
        "dir_fd=directory_fd)\n"
        "                try:\n"
        "                    opened=os.fstat(child_fd)\n"
        "                    if (not stat.S_ISDIR(opened.st_mode) or "
        "opened.st_dev != info.st_dev or opened.st_ino != info.st_ino):\n"
        "                        sys.exit(7)\n"
        "                    visit(child_fd, relative_parts, depth+1)\n"
        "                finally:\n"
        "                    os.close(child_fd)\n"
        "                continue\n"
        "            if not name.endswith('.jsonl') or "
        "not stat.S_ISREG(info.st_mode):\n"
        "                continue\n"
        "            if info.st_nlink != 1:\n"
        "                sys.exit(8)\n"
        "            if len(entries) >= max_files:\n"
        "                sys.exit(9)\n"
        "            if info.st_size < 0 or info.st_size > max_file_bytes:\n"
        "                sys.exit(10)\n"
        "            state['total'] += info.st_size\n"
        "            if state['total'] > max_total_bytes:\n"
        "                sys.exit(11)\n"
        "            fd=os.open(name, file_flags, dir_fd=directory_fd)\n"
        "            opened=os.fstat(fd)\n"
        "            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 "
        "or opened.st_dev != info.st_dev or opened.st_ino != info.st_ino "
        "or opened.st_size != info.st_size):\n"
        "                os.close(fd)\n"
        "                sys.exit(12)\n"
        "            entries.append((info.st_mtime_ns, relative_path, "
        "info.st_size, fd))\n"
        "try:\n"
        "    base_fd=os.open(base, directory_flags)\n"
        "    visit(base_fd, (), 0)\n"
        "    entries.sort(key=lambda item:(item[0], item[1]))\n"
        "    manifest=json.dumps([{'relative_path':item[1],"
        "'size':item[2],'mtime_ns':item[0]} for item in entries], "
        "ensure_ascii=False,separators=(',',':')).encode('utf-8')\n"
        "    if len(manifest) > max_manifest_bytes:\n"
        "        sys.exit(13)\n"
        "    output=sys.stdout.buffer\n"
        "    output.write(len(manifest).to_bytes(4, 'big'))\n"
        "    output.write(manifest)\n"
        "    for _mtime, _relative_path, expected_size, fd in entries:\n"
        "        remaining=expected_size\n"
        "        while remaining:\n"
        "            chunk=os.read(fd, min(65536, remaining))\n"
        "            if not chunk:\n"
        "                sys.exit(14)\n"
        "            output.write(chunk)\n"
        "            remaining -= len(chunk)\n"
        "    output.flush()\n"
        "finally:\n"
        "    for _mtime, _relative_path, _size, fd in entries:\n"
        "        try:\n"
        "            os.close(fd)\n"
        "        except OSError:\n"
        "            pass\n"
        "    if base_fd is not None:\n"
        "        os.close(base_fd)\n"
    )


def _ensure_trace_subdirectory(root, relative_parts):
    current = root
    for part in relative_parts:
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, mode=0o700)
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Pi 轨迹目标目录不安全")
    return current


def sync_pi_agent_sessions(
    container_name,
    trace_dir,
    *,
    container_session_dir=PI_SESSION_DIR,
    runtime_user="node",
    secrets=(),
):
    """复制 Pi session，并生成供公共轨迹解析器读取的合并 JSONL。"""

    export_script = _pi_trace_export_script(container_session_dir)
    try:
        with tempfile.TemporaryFile(mode="w+b") as exported:
            command = ["docker", "exec"]
            if runtime_user:
                command.extend(["--user", runtime_user])
            command.extend([container_name, "python3", "-c", export_script])
            copied = subprocess.run(
                command,
                stdout=exported,
                stderr=subprocess.DEVNULL,
                timeout=PI_TRACE_SYNC_TIMEOUT_SECONDS,
            )
            if copied.returncode != 0:
                return False
            exported.seek(0)
            manifest_size = int.from_bytes(_read_exact(exported, 4), "big")
            if manifest_size > PI_TRACE_MANIFEST_MAX_BYTES:
                return False
            manifest = json.loads(
                _read_exact(exported, manifest_size).decode("utf-8")
            )
            if not isinstance(manifest, list) or not manifest:
                return False
            if len(manifest) > PI_TRACE_MAX_FILES:
                return False

            entries = []
            seen_paths = set()
            total_size = 0
            for item in manifest:
                entry = _safe_pi_trace_entry(item)
                if entry is None or entry[0] in seen_paths:
                    return False
                seen_paths.add(entry[0])
                total_size += entry[1]
                if total_size > PI_TRACE_MAX_TOTAL_BYTES:
                    return False
                entries.append(entry)
            if entries != sorted(entries, key=lambda item: (item[2], item[0])):
                return False

            os.makedirs(trace_dir, mode=0o700, exist_ok=True)
            session_root = _ensure_trace_subdirectory(
                trace_dir,
                (".pi", "agent", "sessions"),
            )
            normalized_root = os.path.realpath(session_root)
            combined_destination = os.path.join(
                session_root,
                PI_COMBINED_TRACE_NAME,
            )
            combined_temporary = None
            pending = []
            wrote_combined = False
            combined_last_byte = b""
            total_output_state = {
                "size": 0,
                "limit": PI_TRACE_MAX_PUBLISHED_TOTAL_BYTES,
            }
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w+b",
                    dir=session_root,
                    prefix=".combined-",
                    delete=False,
                ) as combined_stream:
                    combined_temporary = combined_stream.name
                    for relative_path, size, mtime_ns in entries:
                        parts = relative_path.split("/")
                        parent = _ensure_trace_subdirectory(
                            session_root,
                            parts[:-1],
                        )
                        destination = os.path.join(parent, parts[-1])
                        if not os.path.realpath(destination).startswith(
                            normalized_root + os.sep
                        ):
                            raise ValueError("Pi 轨迹目标路径越界")
                        try:
                            destination_info = os.lstat(destination)
                        except FileNotFoundError:
                            destination_info = None
                        if destination_info is not None and (
                            stat.S_ISLNK(destination_info.st_mode)
                            or not stat.S_ISREG(destination_info.st_mode)
                            or destination_info.st_nlink != 1
                        ):
                            raise ValueError("Pi 轨迹目标文件不安全")
                        with tempfile.NamedTemporaryFile(
                            mode="w+b",
                            dir=parent,
                            prefix=".session-",
                            delete=False,
                        ) as file_stream:
                            file_temporary = file_stream.name
                            pending.append((file_temporary, destination, mtime_ns))
                            if (
                                size
                                and wrote_combined
                                and combined_last_byte != b"\n"
                            ):
                                _charge_trace_output(total_output_state, 1)
                                combined_stream.write(b"\n")
                            wrote_file, last_byte = _copy_redacted_exact(
                                exported,
                                size,
                                (file_stream, combined_stream),
                                secrets,
                                max_file_output_bytes=(
                                    PI_TRACE_MAX_PUBLISHED_FILE_BYTES
                                ),
                                total_output_state=total_output_state,
                            )
                            if wrote_file:
                                wrote_combined = True
                                combined_last_byte = last_byte
                        os.utime(
                            file_temporary,
                            ns=(mtime_ns, mtime_ns),
                            follow_symlinks=False,
                        )
                    if exported.read(1):
                        raise ValueError("Pi 轨迹导出流包含额外数据")
                    if not wrote_combined:
                        raise ValueError("Pi 轨迹导出为空")
                    if combined_last_byte != b"\n":
                        _charge_trace_output(total_output_state, 1)
                        combined_stream.write(b"\n")

                for temporary, destination, _mtime_ns in pending:
                    os.replace(temporary, destination)
                os.replace(combined_temporary, combined_destination)
                return True
            except Exception:
                for temporary, _destination, _mtime_ns in pending:
                    try:
                        os.remove(temporary)
                    except OSError:
                        pass
                if combined_temporary:
                    try:
                        os.remove(combined_temporary)
                    except OSError:
                        pass
                return False
    except Exception:
        return False


__all__ = [
    "sync_claude_project_jsonl",
    "sync_pi_agent_sessions",
    "sync_stdout_jsonl",
]
