#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reverse Judge 与 Problem Agent 共用的 harness 轨迹同步。"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile


CLAUDE_PROJECT_DIR = "/home/node/.claude/projects/-workspace"
PI_SESSION_DIR = "/home/node/.pi/agent/sessions"
PI_COMBINED_TRACE_NAME = "reverse_solve_combined.jsonl"
TRACE_REDACTION_MARKER = b"[REDACTED]"


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


def _publish_redacted_stream(source, destination, secrets):
    """逐行脱敏并原子发布 JSONL，避免正式轨迹短暂出现明文凭证。"""

    temporary = destination + ".tmp"
    patterns = _trace_secret_patterns(secrets)
    try:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(temporary, "wb") as target:
            for chunk in source:
                for secret in patterns:
                    chunk = chunk.replace(secret, TRACE_REDACTION_MARKER)
                target.write(chunk)
        os.replace(temporary, destination)
        return True
    except Exception:
        try:
            os.remove(temporary)
        except OSError:
            pass
        return False


def sync_claude_project_jsonl(
    container_name,
    trace_dir,
    *,
    container_project_dir=CLAUDE_PROJECT_DIR,
    combined_filename="reverse_solve_combined.jsonl",
    secrets=(),
):
    """同步 Claude Code 主会话 JSONL，并生成稳定的合并轨迹。"""

    os.makedirs(trace_dir, exist_ok=True)
    find_cmd = (
        "python3 - <<'PY'\n"
        "import json, os\n"
        f"base={str(container_project_dir)!r}\n"
        "try:\n"
        "    items=[os.path.join(base,n) for n in os.listdir(base) if n.endswith('.jsonl')]\n"
        "except Exception:\n"
        "    items=[]\n"
        "items=[p for p in items if os.path.isfile(p)]\n"
        "items.sort(key=lambda p: os.path.getmtime(p))\n"
        "print(json.dumps(items, ensure_ascii=False))\n"
        "PY"
    )
    try:
        located = subprocess.run(
            ["docker", "exec", container_name, "bash", "-lc", find_cmd],
            capture_output=True,
            text=True,
            timeout=8,
        )
        remote_paths = json.loads((located.stdout or "[]").strip() or "[]")
    except Exception:
        return False
    if not isinstance(remote_paths, list):
        return False
    remote_paths = [
        str(path).strip()
        for path in remote_paths
        if str(path).strip().endswith(".jsonl")
    ]
    if not remote_paths:
        return False

    project_dir = os.path.join(trace_dir, ".claude", "projects", "-workspace")
    combined_chunks = []
    try:
        os.makedirs(project_dir, exist_ok=True)
        for remote_path in remote_paths:
            data = subprocess.run(
                ["docker", "exec", container_name, "cat", remote_path],
                capture_output=True,
                timeout=12,
            )
            if data.returncode != 0:
                continue
            payload = _redact_trace_bytes(data.stdout or b"", secrets)
            destination = os.path.join(project_dir, os.path.basename(remote_path))
            temporary = destination + ".tmp"
            with open(temporary, "wb") as stream:
                stream.write(payload)
            os.replace(temporary, destination)
            if payload:
                combined_chunks.append(payload.rstrip(b"\n"))
        if not combined_chunks:
            return False
        combined = b"\n".join(combined_chunks) + b"\n"
        destination = os.path.join(project_dir, combined_filename)
        temporary = destination + ".tmp"
        with open(temporary, "wb") as stream:
            stream.write(combined)
        os.replace(temporary, destination)
        return True
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

    if not os.path.isfile(source_path):
        return False
    destination = os.path.join(trace_dir, destination_filename)
    try:
        os.makedirs(trace_dir, exist_ok=True)
        with open(source_path, "rb") as source:
            return _publish_redacted_stream(source, destination, secrets)
    except Exception:
        return False


def _list_pi_session_files(
    container_name,
    *,
    container_session_dir=PI_SESSION_DIR,
    runtime_user="node",
):
    """列出 Pi 生成的普通 session JSONL。"""

    list_cmd = (
        "python3 - <<'PY'\n"
        "import json, os, stat\n"
        f"base={str(container_session_dir)!r}\n"
        "try:\n"
        "    for root, dirs, names in os.walk(base, followlinks=False):\n"
        "        dirs[:]=[name for name in dirs "
        "if not os.path.islink(os.path.join(root, name))]\n"
        "        for name in names:\n"
        "            if not name.endswith('.jsonl'):\n"
        "                continue\n"
        "            path=os.path.join(root, name)\n"
        "            try:\n"
        "                info=os.lstat(path)\n"
        "            except OSError:\n"
        "                continue\n"
        "            if not stat.S_ISREG(info.st_mode):\n"
        "                continue\n"
        "            print(json.dumps({\n"
        "                'relative_path': os.path.relpath(path, base),\n"
        "                'mtime_ns': info.st_mtime_ns,\n"
        "            }, ensure_ascii=False), flush=True)\n"
        "except Exception:\n"
        "    pass\n"
        "PY"
    )
    with tempfile.TemporaryFile(mode="w+b") as listing:
        try:
            command = ["docker", "exec"]
            if runtime_user:
                command.extend(["--user", runtime_user])
            command.extend([container_name, "bash", "-lc", list_cmd])
            located = subprocess.run(
                command,
                stdout=listing,
                stderr=subprocess.DEVNULL,
                timeout=8,
            )
            if located.returncode != 0:
                return
            listing.seek(0)
            for raw_line in listing:
                if len(raw_line) > 64 * 1024:
                    continue
                try:
                    item = json.loads(raw_line.decode("utf-8", "replace"))
                except Exception:
                    continue
                if isinstance(item, dict):
                    yield item
        except Exception:
            return


def _safe_pi_session_relative_path(value):
    relative_path = str(value or "").strip().replace("\\", "/")
    parts = relative_path.split("/")
    if (
        not relative_path
        or relative_path.startswith("/")
        or not relative_path.endswith(".jsonl")
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(char) < 32 or ord(char) == 127 for char in relative_path)
    ):
        return ""
    return relative_path


def _copy_pi_session_file(
    container_name,
    relative_path,
    destination,
    *,
    container_session_dir=PI_SESSION_DIR,
    mtime_ns=None,
    runtime_user="node",
    secrets=(),
):
    try:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        remote_path = container_session_dir.rstrip("/") + "/" + relative_path
        command = ["docker", "exec"]
        if runtime_user:
            command.extend(["--user", runtime_user])
        command.extend([container_name, "cat", "--", remote_path])
        with tempfile.TemporaryFile(mode="w+b") as stream:
            copied = subprocess.run(
                command,
                stdout=stream,
                stderr=subprocess.DEVNULL,
                timeout=12,
            )
            if copied.returncode != 0:
                return False
            stream.seek(0)
            if not _publish_redacted_stream(stream, destination, secrets):
                return False
        try:
            normalized_mtime = int(mtime_ns)
            if normalized_mtime >= 0:
                os.utime(destination, ns=(normalized_mtime, normalized_mtime))
        except (TypeError, ValueError, OSError):
            pass
        return True
    except Exception:
        return False


def _iter_pi_session_paths(session_root, combined_filename):
    pending_dirs = [session_root]
    while pending_dirs:
        current = pending_dirs.pop()
        try:
            entries = os.scandir(current)
        except OSError:
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        pending_dirs.append(entry.path)
                    elif (
                        entry.name.endswith(".jsonl")
                        and entry.name != combined_filename
                        and entry.is_file(follow_symlinks=False)
                    ):
                        yield entry.path
                except OSError:
                    continue


def _combine_pi_session_jsonl(
    trace_dir,
    *,
    combined_filename=PI_COMBINED_TRACE_NAME,
):
    session_root = os.path.join(trace_dir, ".pi", "agent", "sessions")
    if not os.path.isdir(session_root):
        return False
    combined_path = os.path.join(session_root, combined_filename)
    temporary = combined_path + ".tmp"
    wrote_any = False
    last_byte = b""
    try:
        with open(temporary, "wb") as combined:
            for path in _iter_pi_session_paths(session_root, combined_filename):
                try:
                    if wrote_any and last_byte != b"\n":
                        combined.write(b"\n")
                    with open(path, "rb") as source:
                        while True:
                            chunk = source.read(64 * 1024)
                            if not chunk:
                                break
                            combined.write(chunk)
                            last_byte = chunk[-1:]
                    wrote_any = True
                except OSError:
                    continue
            if wrote_any and last_byte != b"\n":
                combined.write(b"\n")
        if not wrote_any:
            os.remove(temporary)
            return False
        os.replace(temporary, combined_path)
        return True
    except Exception:
        try:
            os.remove(temporary)
        except OSError:
            pass
        return False


def sync_pi_agent_sessions(
    container_name,
    trace_dir,
    *,
    container_session_dir=PI_SESSION_DIR,
    runtime_user="node",
    secrets=(),
):
    """复制 Pi session，并生成供公共轨迹解析器读取的合并 JSONL。"""

    session_root = os.path.join(trace_dir, ".pi", "agent", "sessions")
    copied_any = False
    for item in _list_pi_session_files(
        container_name,
        container_session_dir=container_session_dir,
        runtime_user=runtime_user,
    ):
        relative_path = _safe_pi_session_relative_path(item.get("relative_path"))
        if not relative_path:
            continue
        destination = os.path.realpath(
            os.path.join(session_root, *relative_path.split("/"))
        )
        normalized_root = os.path.realpath(session_root)
        if not destination.startswith(normalized_root + os.sep):
            continue
        if _copy_pi_session_file(
            container_name,
            relative_path,
            destination,
            container_session_dir=container_session_dir,
            mtime_ns=item.get("mtime_ns"),
            runtime_user=runtime_user,
            secrets=secrets,
        ):
            copied_any = True
    if not copied_any:
        return False
    _combine_pi_session_jsonl(trace_dir)
    return True


__all__ = [
    "sync_claude_project_jsonl",
    "sync_pi_agent_sessions",
    "sync_stdout_jsonl",
]
