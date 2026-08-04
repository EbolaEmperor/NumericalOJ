#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Problem Agent 的受信任实时 JSONL 轨迹采集。

容器只能写临时 ``/workspace``。本模块把其中的 harness 原生会话文件，或
Docker 客户端收到的 JSONL stdout，先解析并永久脱敏，再写入容器不可见的
任务级目录。展示层继续复用 Reverse Judge 的公共轨迹解析器。
"""

from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading

from oj_modules.problems.agent_runs import agent_run_trace_dir


AGENT_TRACE_SYNC_INTERVAL_SECONDS = 2.0
_TRACE_JOURNAL_MAX_BYTES = 32 * 1024 * 1024
_TRACE_SOURCE_MAX_BYTES = 32 * 1024 * 1024
_TRACE_EVENT_MAX_BYTES = 256 * 1024
_TRACE_SCAN_MAX_ENTRIES = 512
_TRACE_NATIVE_MAX_FILES = 48
_TRACE_NATIVE_MAX_EVENTS = 4096
_TRACE_ENV_SECRET_RE = re.compile(
    r"(?i)((?:api[_-]?key|auth(?:orization)?|token|session(?:_cookie)?|cookie)"
    r"\s*[=:]\s*)([^\s,;]+)"
)

_TRACE_DESTINATIONS = {
    "claude_code": Path(
        ".claude/projects/-workspace/agent_judge_combined.jsonl"
    ),
    "codex": Path("codex_agent_judge.jsonl"),
    "opencode": Path("opencode_agent_judge.jsonl"),
    "pi": Path(".pi/agent/sessions/reverse_solve_combined.jsonl"),
}
_PI_COMBINED_HEADER = json.dumps(
    {"type": "session", "version": 3},
    ensure_ascii=False,
    separators=(",", ":"),
).encode("utf-8") + b"\n"


def prepare_agent_trace_dir(task_id):
    """为一次 late-ack 安全执行清空并重建确定性的可信轨迹目录。"""

    trace_dir = agent_run_trace_dir(task_id)
    root = trace_dir.parent
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass

    try:
        current = trace_dir.lstat()
    except FileNotFoundError:
        current = None
    if current is not None:
        if stat.S_ISDIR(current.st_mode) and not stat.S_ISLNK(current.st_mode):
            shutil.rmtree(trace_dir)
        else:
            trace_dir.unlink()
    trace_dir.mkdir(mode=0o700)
    return trace_dir


def ensure_agent_trace_dir(task_id):
    """取得已准备的可信轨迹目录；不清除本次任务已经采集的内容。"""

    trace_dir = agent_run_trace_dir(task_id)
    trace_dir.parent.mkdir(parents=True, exist_ok=True)
    trace_dir.mkdir(mode=0o700, exist_ok=True)
    return trace_dir


def _redact_text(value, secrets):
    text = str(value or "")
    for secret in secrets:
        secret = str(secret or "")
        if secret:
            text = text.replace(secret, "[已脱敏]")
    return _TRACE_ENV_SECRET_RE.sub(r"\1[已脱敏]", text)


def _sanitize_json_value(value, secrets):
    if isinstance(value, str):
        return _redact_text(value, secrets)
    if isinstance(value, list):
        return [_sanitize_json_value(item, secrets) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _sanitize_json_value(item, secrets)
            for key, item in value.items()
        }
    return value


def _json_event_from_line(raw_line, secrets):
    if len(raw_line) > _TRACE_EVENT_MAX_BYTES:
        return None
    try:
        event = json.loads(bytes(raw_line).decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(event, dict):
        return None
    return _sanitize_json_value(event, secrets)


def _json_text(value):
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("text", "message", "content", "output", "summary"):
            text = _json_text(value.get(key))
            if text:
                return text
        return ""
    if isinstance(value, list):
        return "\n\n".join(
            text for text in (_json_text(item) for item in value) if text
        ).strip()
    return ""


def _normalize_opencode_event(event):
    """把 OpenCode JSON stream 投影成公共 Codex JSONL 解析器认识的事件。"""

    event_type = str(event.get("type") or "").strip()
    part = event.get("part") if isinstance(event.get("part"), dict) else {}
    part_type = str(part.get("type") or "").strip().lower().replace("-", "_")

    if event_type in {"agent_message", "assistant_message", "error"}:
        return event

    if event_type in {"text", "message"} or part_type in {
        "text",
        "message",
    }:
        text = _json_text(part or event)
        if text:
            return {
                "type": "assistant_message",
                "message": text,
                "model": event.get("model") or part.get("model") or "opencode",
                "_trace_original_type": event_type or part_type,
            }

    if event_type in {"reasoning", "thinking"} or part_type in {
        "reasoning",
        "thinking",
    }:
        text = _json_text(part or event)
        if text:
            return {
                "type": "agent_reasoning",
                "message": text,
                "model": event.get("model") or part.get("model") or "opencode",
                "_trace_original_type": event_type or part_type,
            }

    if "tool" in event_type.lower() or part_type == "tool":
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        tool_name = (
            part.get("tool")
            or part.get("name")
            or event.get("tool")
            or event.get("name")
            or "工具"
        )
        tool_input = (
            state.get("input")
            if isinstance(state.get("input"), dict)
            else part.get("input")
        )
        return {
            "type": "tool_call",
            "item": {
                "type": "tool_call",
                "name": str(tool_name),
                "input": tool_input if isinstance(tool_input, dict) else {},
            },
            "_trace_original_type": event_type or part_type,
        }
    return event


def _safe_read_regular_file(path, max_bytes):
    """从容器可写目录读取普通文件，并拒绝 symlink/inode 置换。"""

    try:
        before = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            return None
        size = max(0, int(opened.st_size))
        start = max(0, size - int(max_bytes))
        read_start = max(0, start - 1)
        os.lseek(fd, read_start, os.SEEK_SET)
        remaining = min(size - read_start, int(max_bytes) + 1)
        chunks = []
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if start > 0:
            previous = payload[:1]
            payload = payload[1:]
            if previous != b"\n":
                boundary = payload.find(b"\n")
                if boundary < 0:
                    return b"", start
                payload = payload[boundary + 1:]
                start += boundary + 1
        return payload, start
    finally:
        os.close(fd)


def _safe_read_prefix(path, max_bytes):
    """读取不可信普通文件的有界前缀，用于验证 Pi session header。"""

    try:
        before = path.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            return None
        return os.read(fd, max(1, int(max_bytes)))
    finally:
        os.close(fd)


def _resolved_session_root(root, workspace):
    """解析容器可写会话根，并拒绝越出本任务 workspace。"""

    workspace = Path(workspace).resolve()
    root = Path(root)
    try:
        resolved_root = root.resolve()
    except OSError:
        return None
    if resolved_root != workspace and workspace not in resolved_root.parents:
        return None
    if not resolved_root.is_dir():
        return None
    return resolved_root


def _claude_session_jsonls(root, workspace):
    """只发现 Claude 主会话目录顶层 JSONL，明确排除 subagents。"""

    resolved_root = _resolved_session_root(root, workspace)
    if resolved_root is None:
        return []
    candidates = []
    try:
        entries = os.scandir(resolved_root)
    except OSError:
        return []
    with entries:
        for index, entry in enumerate(entries):
            if index >= _TRACE_SCAN_MAX_ENTRIES:
                break
            try:
                if (
                    entry.name.endswith(".jsonl")
                    and not entry.is_symlink()
                    and entry.is_file(follow_symlinks=False)
                ):
                    candidates.append((entry.name, Path(entry.path)))
            except OSError:
                continue
    candidates.sort(key=lambda item: item[0])
    return candidates[-_TRACE_NATIVE_MAX_FILES:]


def _is_pi_session_jsonl(path):
    prefix = _safe_read_prefix(path, _TRACE_EVENT_MAX_BYTES)
    if not prefix:
        return False
    first_line = prefix.splitlines()[0] if prefix.splitlines() else b""
    try:
        header = json.loads(first_line.decode("utf-8", "replace"))
        return (
            isinstance(header, dict)
            and header.get("type") == "session"
            and int(header.get("version")) == 3
        )
    except Exception:
        return False


def _pi_session_jsonls(root, workspace):
    """稳定收集 Pi sessions 树中的全部合法 v3 session JSONL。"""

    resolved_root = _resolved_session_root(root, workspace)
    if resolved_root is None:
        return []

    candidates = []
    pending = [resolved_root]
    scanned = 0
    while pending and scanned < _TRACE_SCAN_MAX_ENTRIES:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            for entry in entries:
                scanned += 1
                if scanned > _TRACE_SCAN_MAX_ENTRIES:
                    break
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif (
                        entry.name.endswith(".jsonl")
                        and entry.is_file(follow_symlinks=False)
                        and _is_pi_session_jsonl(Path(entry.path))
                    ):
                        relative = Path(entry.path).relative_to(
                            resolved_root,
                        ).as_posix()
                        candidates.append((relative, Path(entry.path)))
                except OSError:
                    continue
    if not candidates:
        return []
    candidates.sort(key=lambda item: item[0])
    return candidates[-_TRACE_NATIVE_MAX_FILES:]


def _sanitized_jsonl_events(
    raw,
    secrets,
    *,
    source,
    base_offset=0,
    skip_session_headers=False,
):
    offset = max(0, int(base_offset or 0))
    for encoded_line in bytes(raw or b"").splitlines(keepends=True):
        raw_line = encoded_line.rstrip(b"\r\n")
        event = _json_event_from_line(raw_line, secrets)
        if event is not None:
            if skip_session_headers and event.get("type") == "session":
                offset += len(encoded_line)
                continue
            event["_trace_source"] = source
            event["_trace_offset"] = offset
            yield json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n"
        offset += len(encoded_line)


def _merge_native_jsonls(candidates, secrets, *, harness):
    """按稳定路径顺序构造有界 combined journal，并保留最近完整事件。"""

    remaining = _TRACE_SOURCE_MAX_BYTES
    selected = []
    # 先从稳定顺序的尾部反向分配总读取预算，再按正序输出。这样即使会话总量
    # 超限，也保留最新一组稳定会话，而不是永久冻结在最早 32 MiB。
    for relative, path in reversed(candidates):
        if remaining <= 0:
            break
        read_result = _safe_read_regular_file(path, remaining)
        if read_result is None:
            continue
        raw, base_offset = read_result
        if not raw:
            continue
        selected.append((relative, raw, base_offset))
        remaining -= len(raw)
    selected.reverse()

    journal = deque()
    prefix = _PI_COMBINED_HEADER if harness == "pi" else b""
    journal_size = len(prefix)
    for relative, raw, base_offset in selected:
        source = f"{harness}-" + hashlib.sha256(
            relative.encode("utf-8", "replace"),
        ).hexdigest()[:16]
        for encoded_event in _sanitized_jsonl_events(
            raw,
            secrets,
            source=source,
            base_offset=base_offset,
            skip_session_headers=(harness == "pi"),
        ):
            journal.append(encoded_event)
            journal_size += len(encoded_event)
            while journal and (
                len(journal) > _TRACE_NATIVE_MAX_EVENTS
                or journal_size > _TRACE_JOURNAL_MAX_BYTES
            ):
                journal_size -= len(journal.popleft())
    return prefix + b"".join(journal)


def _atomic_write(path, payload):
    path = Path(path)
    payload = bytes(payload or b"")
    try:
        if path.read_bytes() == payload:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        with open(temporary, "wb") as stream:
            stream.write(payload)
        temporary.chmod(0o600)
        os.replace(temporary, path)
        return True
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        return False


class AgentTraceRecorder:
    """一次 Problem Agent harness 的线程安全轨迹记录器。"""

    def __init__(self, *, workspace, trace_dir, harness, secrets=()):
        self.workspace = Path(workspace).resolve()
        self.trace_dir = Path(trace_dir).resolve()
        self.harness = str(harness or "").strip().lower()
        self.secrets = tuple(str(item or "") for item in secrets if str(item or ""))
        self.destination = self.trace_dir / _TRACE_DESTINATIONS[self.harness]
        self._lock = threading.Lock()
        self._changed = False
        self._journal_size = 0
        self._journal_full = False

    def ingest_stdout_line(self, raw_line, offset=0):
        """Codex/OpenCode stdout 到达时立即写成已脱敏的规范 JSONL。"""

        if self.harness not in {"codex", "opencode"}:
            return
        event = _json_event_from_line(raw_line, self.secrets)
        if event is None:
            return
        if self.harness == "opencode":
            event = _normalize_opencode_event(event)
        event["_trace_source"] = self.harness
        event["_trace_offset"] = max(0, int(offset or 0))
        payload = json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n"

        with self._lock:
            if self._journal_full:
                return
            if self._journal_size + len(payload) > _TRACE_JOURNAL_MAX_BYTES:
                marker = json.dumps({
                    "type": "assistant_message",
                    "message": "执行轨迹已达到持久化上限，后续事件不再记录。",
                    "_trace_source": self.harness,
                    "_trace_offset": max(0, int(offset or 0)),
                }, ensure_ascii=False).encode("utf-8") + b"\n"
                payload = (
                    marker
                    if self._journal_size + len(marker) <= _TRACE_JOURNAL_MAX_BYTES
                    else b""
                )
                self._journal_full = True
            if not payload:
                return
            self.destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(self.destination, "ab") as stream:
                    stream.write(payload)
                self.destination.chmod(0o600)
            except OSError:
                return
            self._journal_size += len(payload)
            self._changed = True

    def _sync_native_session(self):
        if self.harness == "claude_code":
            source_root = (
                self.workspace / ".runtime/home/.claude/projects/-workspace"
            )
            candidates = _claude_session_jsonls(source_root, self.workspace)
        elif self.harness == "pi":
            source_root = self.workspace / ".runtime/pi/agent/sessions"
            candidates = _pi_session_jsonls(source_root, self.workspace)
        else:
            return False
        if not candidates:
            return False
        payload = _merge_native_jsonls(
            candidates,
            self.secrets,
            harness=("claude" if self.harness == "claude_code" else "pi"),
        )
        if not payload:
            return False
        return _atomic_write(self.destination, payload)

    def sync(self):
        """同步原生会话并返回自上次 tick 起轨迹是否发生变化。"""

        native_changed = self._sync_native_session()
        with self._lock:
            changed = bool(native_changed or self._changed)
            self._changed = False
        return changed


__all__ = [
    "AGENT_TRACE_SYNC_INTERVAL_SECONDS",
    "AgentTraceRecorder",
    "ensure_agent_trace_dir",
    "prepare_agent_trace_dir",
]
