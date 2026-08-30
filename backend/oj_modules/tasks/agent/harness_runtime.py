#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在只读 Docker 根文件系统中运行一次解题或造数据 harness。"""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from backend.oj_modules.config import (
    AGENT_CONTAINER_SITE_URL,
    AGENT_JUDGE_CPU_LIMIT,
    AGENT_JUDGE_DOCKER_IMAGE,
    AGENT_JUDGE_MEM_LIMIT,
    AGENT_JUDGE_PIDS_LIMIT,
    AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS,
    MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS,
)
from backend.oj_modules.problems.agent_launch import (
    AGENT_ACCESS_ROLE_USER,
    normalize_agent_access_role,
    normalize_agent_reasoning_effort,
    normalize_agent_task_kind,
    normalize_launch_harness,
    skill_for_agent_task,
)
from backend.oj_modules.problems.agent_runs import agent_run_container_name
from backend.oj_modules.site_config.services import (
    DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
    DEFAULT_LLM_MAX_OUTPUT_TOKENS,
    get_web_search_settings,
)
from backend.oj_modules.tasks.agent.traces import (
    AGENT_TRACE_SYNC_INTERVAL_SECONDS,
    ensure_agent_trace_dir,
    prepare_agent_trace_dir,
    sync_agent_trace,
)


_CAPTURE_LIMIT_BYTES = 2 * 1024 * 1024
_STDOUT_MIRROR_LIMIT_BYTES = 8 * 1024 * 1024
_CANONICAL_JOURNAL_MAX_BYTES = 64 * 1024 * 1024
_CANONICAL_JOURNAL_RECORD_MAX_BYTES = 16 * 1024 * 1024
_CANONICAL_JOURNAL_TAIL_RESERVE_BYTES = 17 * 1024 * 1024
_IDENTITY_CONFIG_PATH = "/workspace/.numoj-agent/identity.json"
_SKILL_CONFIG_ENV = {
    "numoj-user": "NUMOJ_USER_CONFIG",
    "numoj-admin": "NUMOJ_CLI_CONFIG",
}
_WEB_SEARCH_MCP_URL_ENV = "AJ_WEB_SEARCH_MCP_URL"
_WEB_SEARCH_MCP_AUTH_ENV = "AJ_WEB_SEARCH_MCP_AUTHORIZATION"
_WEB_SEARCH_MCP_TIMEOUT_ENV = "AJ_WEB_SEARCH_MCP_TIMEOUT_SECONDS"
_NATIVE_SESSION_ID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z",
)
_OPENCODE_NATIVE_SESSION_ID_RE = re.compile(
    r"ses_[A-Za-z0-9_-]{1,120}\Z",
)
_SESSION_STATE_RELATIVE_PATH = ".aj_session_state.json"
_SESSION_STATE_MAX_BYTES = 64 * 1024
_SKILL_WORKSPACE_RESERVATION_BYTES = 10 * 1024 * 1024
_SKILL_WORKSPACE_RESERVATION_FILES = 513
_SKILL_WORKSPACE_RESERVATION_DIRECTORIES = 512
_CONTAINER_REMOVAL_CONFIRM_TIMEOUT_SECONDS = 20.0
_CONTAINER_REMOVAL_CONFIRM_POLL_SECONDS = 0.25


@dataclass(frozen=True, slots=True)
class HarnessRunResult:
    returncode: int
    timed_out: bool
    stdout: str
    stderr: str
    artifacts: dict[str, bytes] = field(default_factory=dict)
    created_submission_ids: tuple[int, ...] = ()
    native_session_id: str = ""


class AgentHarnessCleanupError(RuntimeError):
    """无法证明本轮容器已停止；会话不得进入可续聊终态。"""


class AgentUsageHardStopError(RuntimeError):
    """本次 usage 扣费已经触发 Agent 额度硬停。"""


_NUMOJ_STDOUT_EVENT_TYPES = frozenset({
    "numoj_control", "numoj_steer", "numoj_trace", "numoj_usage",
})


def extract_harness_failure_detail(result, *, max_chars=800):
    """提取用户可见的 harness 错误，忽略 stdout 中的内部协议帧。"""

    try:
        limit = max(1, int(max_chars))
    except (TypeError, ValueError):
        limit = 800
    stderr = str(getattr(result, "stderr", "") or "").strip()
    if stderr:
        for line in reversed(stderr.splitlines()):
            summary = line.strip()
            if summary.startswith("模型请求失败："):
                return summary[-limit:]
        return stderr[-limit:]
    visible_lines = []
    for raw_line in str(getattr(result, "stdout", "") or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except (TypeError, ValueError):
            payload = None
        if (
            isinstance(payload, dict)
            and str(payload.get("type") or "") in _NUMOJ_STDOUT_EVENT_TYPES
        ):
            continue
        visible_lines.append(line)
    return "\n".join(visible_lines).strip()[-limit:]


def _containerize_url(value):
    """让容器内的 localhost 端点显式回到宿主机。"""

    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw
    if str(parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
        return raw
    port = f":{parsed.port}" if parsed.port else ""
    return urlunsplit(
        (
            parsed.scheme,
            f"host.docker.internal{port}",
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _safe_workspace_path(workspace, relative_path):
    relative = Path(str(relative_path or ""))
    if relative.is_absolute() or not relative.parts:
        raise ValueError("Agent 工作区文件路径无效")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Agent 工作区文件路径无效")
    target = (Path(workspace) / relative).resolve()
    root = Path(workspace).resolve()
    if target == root or root not in target.parents:
        raise ValueError("Agent 工作区文件越界")
    return target


def _workspace_entry_path(workspace, relative_path):
    relative = Path(str(relative_path or ""))
    if relative.is_absolute() or not relative.parts:
        raise ValueError("Agent 工作区文件路径无效")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Agent 工作区文件路径无效")
    root = Path(workspace).resolve()
    return root, relative, root / relative


def _ensure_workspace_directory(workspace, relative_path, *, mode=0o700):
    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    current = root
    for part in relative.parts:
        current = current / part
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=mode)
            continue
        if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError("Agent 工作区目录不安全")
    return current


def _write_workspace_file(session_id, relative_path, content, *, mode=0o600):
    from backend.oj_modules.agents.workspace import write_agent_workspace_file

    return write_agent_workspace_file(
        session_id,
        relative_path,
        content,
        mode=mode,
    )


def _prepare_workspace_temp_path(workspace, relative_path):
    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    parent = (
        root
        if len(relative.parts) == 1
        else _ensure_workspace_directory(root, Path(*relative.parts[:-1]))
    )
    target = parent / relative.name
    try:
        current = target.lstat()
    except FileNotFoundError:
        return target
    if stat.S_ISDIR(current.st_mode):
        raise ValueError("Agent 临时文件路径被目录占用")
    target.unlink()
    return target


def _read_workspace_artifacts(workspace, artifact_files):
    """容器已停止后，安全读取显式声明的任务产物。"""

    root = Path(workspace).resolve()
    result = {}
    for relative_path in artifact_files or ():
        relative = Path(str(relative_path or ""))
        _safe_workspace_path(root, relative)

        current = root
        for part in relative.parts[:-1]:
            current = current / part
            try:
                current_stat = current.lstat()
            except OSError as exc:
                raise ValueError(f"Agent 产物目录不存在：{relative_path}") from exc
            if stat.S_ISLNK(current_stat.st_mode) or not stat.S_ISDIR(current_stat.st_mode):
                raise ValueError(f"Agent 产物目录不安全：{relative_path}")

        target = root / relative
        try:
            target_stat = target.lstat()
        except OSError as exc:
            raise ValueError(f"Agent 没有生成预期产物：{relative_path}") from exc
        if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
            raise ValueError(f"Agent 产物必须是普通文件：{relative_path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags)
        try:
            opened_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(opened_stat.st_mode)
                or opened_stat.st_dev != target_stat.st_dev
                or opened_stat.st_ino != target_stat.st_ino
            ):
                raise ValueError(f"Agent 产物读取时发生变化：{relative_path}")
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(fd)
        result[str(relative)] = payload
    return result


def normalize_native_session_id(value, harness):
    """按 harness 校验不透明原生 ID；OpenCode 的大小写必须原样保留。"""

    normalized = str(value or "").strip()
    if not normalized:
        return ""
    normalized_harness = str(harness or "").strip().lower().replace("-", "_")
    if normalized_harness == "opencode":
        if not _OPENCODE_NATIVE_SESSION_ID_RE.fullmatch(normalized):
            raise ValueError("Agent 原生 session_id 无效")
        return normalized
    if not _NATIVE_SESSION_ID_RE.fullmatch(normalized):
        raise ValueError("Agent 原生 session_id 无效")
    return normalized.lower()


def _ensure_stable_workspace(session_id):
    """延迟导入会话工作区，避免任务包导入时触发目录写入。"""

    from backend.oj_modules.agents.workspace import ensure_agent_workspace

    workspace = Path(ensure_agent_workspace(session_id)).expanduser().resolve()
    if not workspace.is_dir() or workspace.is_symlink():
        raise RuntimeError("Agent 会话工作区不可用")
    return workspace


def _read_stable_workspace(session_id):
    """验证已有工作区路径，不触发递归配额扫描。"""

    from backend.oj_modules.agents.workspace import get_existing_agent_workspace_path

    workspace = Path(get_existing_agent_workspace_path(session_id)).expanduser().resolve()
    if not workspace.is_dir() or workspace.is_symlink():
        raise RuntimeError("Agent 会话工作区不可用")
    return workspace


def _clear_current_session_state(workspace):
    """每轮启动前移除上一轮摘要，防止把陈旧 session 当成新结果。"""

    state_path = Path(workspace) / _SESSION_STATE_RELATIVE_PATH
    try:
        current = state_path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(current.st_mode):
        raise ValueError("Agent 原生会话状态路径被目录占用")
    state_path.unlink()


def _remove_identity_config(workspace, relative_path):
    """删除本轮身份占位配置；异常类型会阻止会话被误标为可续聊。"""

    root, relative, _target = _workspace_entry_path(workspace, relative_path)
    parent = root
    for part in relative.parts[:-1]:
        parent = parent / part
        try:
            parent_state = parent.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc
        if stat.S_ISLNK(parent_state.st_mode) or not stat.S_ISDIR(parent_state.st_mode):
            raise AgentHarnessCleanupError("Agent 身份配置清理失败：父目录不安全")
    identity_path = parent / relative.name
    try:
        current = identity_path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc
    if stat.S_ISDIR(current.st_mode):
        raise AgentHarnessCleanupError("Agent 身份配置清理失败：路径被目录占用")
    try:
        identity_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AgentHarnessCleanupError("Agent 身份配置清理失败") from exc


@contextmanager
def _identity_relay_context(*args, **kwargs):
    from backend.oj_modules.tasks.agent.identity_relay import (
        IdentityRelayCleanupError,
        run_numoj_identity_relay,
    )

    try:
        with run_numoj_identity_relay(*args, **kwargs) as relay:
            yield relay
    except IdentityRelayCleanupError as exc:
        raise AgentHarnessCleanupError(str(exc)) from exc


@contextmanager
def _secret_relay_context(*args, **kwargs):
    from backend.oj_modules.tasks.agent.secret_relay import (
        AgentSecretRelayCleanupError,
        run_agent_secret_relays,
    )

    try:
        with run_agent_secret_relays(*args, **kwargs) as relay:
            yield relay
    except AgentSecretRelayCleanupError as exc:
        raise AgentHarnessCleanupError(str(exc)) from exc


def _check_secret_relay_usage(secret_relay, *, wait=False):
    from backend.oj_modules.tasks.agent.secret_relay import (
        AgentSecretRelayUsageHardStopError,
    )

    try:
        waiter = getattr(secret_relay, "wait_for_endpoint_usage", None)
        checker = getattr(secret_relay, "raise_if_usage_failed", None)
        if wait and callable(waiter):
            waiter()
        if callable(checker):
            checker()
    except AgentSecretRelayUsageHardStopError as exc:
        raise AgentUsageHardStopError(str(exc)) from exc


def _read_native_session_state(workspace, harness):
    """以 no-follow + inode 复核读取原生 session 摘要。"""
    state_path = Path(workspace) / _SESSION_STATE_RELATIVE_PATH
    try:
        before = state_path.lstat()
    except FileNotFoundError:
        return ""
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("Agent 原生会话状态不是安全的普通文件")
    if before.st_size > _SESSION_STATE_MAX_BYTES:
        raise ValueError("Agent 原生会话状态过大")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(state_path, flags)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise ValueError("Agent 原生会话状态读取时发生变化")
        payload = os.read(fd, _SESSION_STATE_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(payload) > _SESSION_STATE_MAX_BYTES:
        raise ValueError("Agent 原生会话状态过大")
    try:
        state = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Agent 原生会话状态无效") from exc
    if not isinstance(state, dict):
        raise ValueError("Agent 原生会话状态无效")
    if str(state.get("harness") or "").strip().lower() != str(harness):
        raise ValueError("Agent 原生会话状态与 harness 不一致")
    return state


def _read_native_session_id(workspace, harness):
    state = _read_native_session_state(workspace, harness)
    if not state:
        return ""
    return normalize_native_session_id(state.get("session_id"), harness)


def read_agent_native_session_id(session_id, harness):
    """读取正在运行或已结束会话的最近原生恢复点。"""

    normalized_harness = normalize_launch_harness(harness)
    workspace = _ensure_stable_workspace(session_id)
    return _read_native_session_id(workspace, normalized_harness)


def read_agent_steer_capability(session_id, harness):
    """返回会话当前原生 harness 是否支持同轮软插话及原因。"""

    normalized_harness = normalize_launch_harness(harness)
    workspace = _read_stable_workspace(session_id)
    state = _read_native_session_state(workspace, normalized_harness)
    if isinstance(state, dict) and "interactive_supported" in state:
        supported = bool(state.get("interactive_supported"))
        reason = str(state.get("interactive_unsupported_reason") or "").strip()
        return supported, "" if supported else (
            reason or "当前原生会话不能使用中途插话"
        )
    if normalized_harness == "opencode" and state:
        return False, "旧 OpenCode 会话需要在下一轮完成兼容探测后才能使用中途插话"
    return True, ""


class _BoundedStdoutMirror:
    """保留 stdout 的有界完整行尾部，并以原子快照供轨迹同步读取。"""

    def __init__(self, path, limit):
        self._path = os.fspath(path)
        self._limit = max(1, int(limit))
        self._chunks = deque()
        self._size = 0
        self._starts_mid_record = False
        self._closed = False
        self._lock = threading.Lock()

    def write(self, block):
        payload = bytes(block or b"")
        if not payload:
            return 0
        with self._lock:
            if self._closed:
                raise OSError("stdout mirror 已关闭")
            self._chunks.append(payload)
            self._size += len(payload)
            overflow = self._size - self._limit
            removed_last_byte = b""
            while self._chunks and overflow > 0:
                first = self._chunks[0]
                if len(first) <= overflow:
                    removed = self._chunks.popleft()
                    removed_last_byte = removed[-1:]
                    self._size -= len(removed)
                    overflow -= len(removed)
                else:
                    removed_last_byte = first[overflow - 1 : overflow]
                    self._chunks[0] = first[overflow:]
                    self._size -= overflow
                    overflow = 0
            if removed_last_byte:
                self._starts_mid_record = removed_last_byte != b"\n"
        return len(payload)

    def _snapshot(self):
        with self._lock:
            payload = b"".join(self._chunks)
            starts_mid_record = self._starts_mid_record
        if starts_mid_record:
            boundary = payload.find(b"\n")
            if boundary < 0:
                return b""
            payload = payload[boundary + 1 :]
        return payload

    def publish(self):
        payload = self._snapshot()
        directory = os.path.dirname(self._path) or "."
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                dir=directory,
                prefix=f".{os.path.basename(self._path)}.",
                suffix=".tmp",
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
            os.replace(temporary, self._path)
            return True
        except OSError:
            if temporary:
                try:
                    os.remove(temporary)
                except OSError:
                    pass
            return False

    def close(self):
        with self._lock:
            self._closed = True


def _tail_reader(
    stream,
    chunks,
    size_state,
    key,
    limit,
    *,
    mirror_stream=None,
    block_observer=None,
):
    try:
        read_block = getattr(stream, "read1", None)
        if not callable(read_block):
            read_block = stream.read
        while True:
            # BufferedReader.read(size) 会等待填满 size 或 EOF；交互 harness
            # 往往长期保持 stdout 开放且单轮输出不足 64 KiB，导致运行轨迹
            # 直到任务结束才出现。read1() 只读取当前可用字节。
            block = read_block(65536)
            if not block:
                break
            if mirror_stream is not None:
                try:
                    mirror_stream.write(block)
                except OSError:
                    # 轨迹落盘失败不能阻断 stdout drain，否则 harness 可能因
                    # pipe 写满而卡死；任务结果仍保留有界尾部。
                    mirror_stream = None
            if callable(block_observer):
                try:
                    block_observer(block)
                except Exception:
                    # 控制回执旁路不能阻断 stdout drain；进程结束后仍会把
                    # 未确认命令收口为 unknown。
                    pass
            chunks.append(block)
            size_state[key] += len(block)
            while chunks and size_state[key] > limit:
                overflow = size_state[key] - limit
                if len(chunks[0]) <= overflow:
                    size_state[key] -= len(chunks.popleft())
                else:
                    chunks[0] = chunks[0][overflow:]
                    size_state[key] -= overflow
    finally:
        stream.close()


class _ControlEventObserver:
    """从 harness stdout 中提取 NumOJ 控制回执，不消费轨迹字节。"""

    def __init__(self, callback):
        self._callback = callback
        self._buffer = bytearray()
        self._lock = threading.Lock()

    def feed(self, block):
        if not callable(self._callback):
            return
        with self._lock:
            self._buffer.extend(bytes(block or b""))
            while True:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    # 单条控制帧不应无限增长；超限内容是普通 harness 输出，
                    # 丢弃观察缓冲不影响 stdout mirror 中的真实轨迹。
                    if len(self._buffer) > 1024 * 1024:
                        self._buffer.clear()
                    return
                raw = bytes(self._buffer[:newline])
                del self._buffer[:newline + 1]
                try:
                    event = json.loads(raw.decode("utf-8"))
                except Exception:
                    continue
                if not isinstance(event, dict) or event.get("type") != "numoj_control":
                    continue
                command_id = str(event.get("id") or "").strip()
                status = str(event.get("status") or "").strip().lower()
                if not command_id or status not in {"accepted", "rejected", "unknown"}:
                    continue
                self._callback(
                    command_id,
                    status,
                    str(event.get("error") or ""),
                )


class _CanonicalJournalObserver:
    """把 adapter stdout 中的规范事件追加为完整、已脱敏的 journal。"""

    _EVENT_TYPES = frozenset({"numoj_trace", "numoj_usage"})

    def __init__(
        self,
        path,
        *,
        secrets=(),
        max_bytes=_CANONICAL_JOURNAL_MAX_BYTES,
    ):
        self._path = os.fspath(path)
        self._patterns = tuple(
            sorted(
                {
                    str(value)
                    for value in secrets or ()
                    if str(value or "")
                },
                key=len,
                reverse=True,
            )
        )
        self._max_bytes = max(1, int(max_bytes))
        self._tail_reserve_bytes = min(
            self._max_bytes,
            _CANONICAL_JOURNAL_TAIL_RESERVE_BYTES,
        )
        self._direct_limit = self._max_bytes - self._tail_reserve_bytes
        self._written = 0
        self._tail_records = deque()
        self._tail_bytes = 0
        self._tail_mode = False
        self._buffer = bytearray()
        self._discarding_record = False
        self._closed = False
        self._trace_sequence = 0
        self._pending_trace_records = []
        self._lock = threading.Lock()
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self._fd = os.open(self._path, flags, 0o600)
        opened = os.fstat(self._fd)
        if not stat.S_ISREG(opened.st_mode):
            os.close(self._fd)
            self._closed = True
            raise OSError("Agent 规范轨迹临时文件不是普通文件")

    def _redact(self, value):
        if isinstance(value, str):
            result = value
            for secret in self._patterns:
                result = result.replace(secret, "[REDACTED]")
            return result
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        if isinstance(value, dict):
            return {
                self._redact(str(key)): self._redact(item)
                for key, item in value.items()
            }
        return value

    def _write_payload(self, payload):
        offset = 0
        while offset < len(payload):
            offset += os.write(self._fd, payload[offset:])
        self._written += len(payload)

    def _drop_oldest_tail_record(self):
        if not self._tail_records:
            return None
        remove_index = None
        for index, (_payload, pinned) in enumerate(self._tail_records):
            if not pinned:
                remove_index = index
                break
        if remove_index is None:
            payload, _pinned = self._tail_records.popleft()
            return payload
        self._tail_records.rotate(-remove_index)
        payload, _pinned = self._tail_records.popleft()
        self._tail_records.rotate(remove_index)
        return payload

    def _store_payload(self, payload, *, pinned=False):
        if len(payload) > self._max_bytes:
            return
        if (
            not self._tail_mode
            and self._written + len(payload) <= self._direct_limit
        ):
            # 文件头保留最早的 usage/事件；剩余固定容量作为滚动尾部，
            # 确保再多中间工具输出也不会挤掉最终 assistant 与尾随 usage。
            self._write_payload(payload)
            return
        self._tail_mode = True
        self._tail_records.append((payload, bool(pinned)))
        self._tail_bytes += len(payload)
        while (
            self._tail_records
            and self._tail_bytes > self._tail_reserve_bytes
        ):
            removed = self._drop_oldest_tail_record()
            if removed is None:
                break
            self._tail_bytes -= len(removed)

    def _append_record(self, raw):
        try:
            event = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if (
            isinstance(event, dict)
            and event.get("type") == "numoj_control"
            and event.get("version") == 1
            and str(event.get("status") or "").strip().lower() == "accepted"
        ):
            command_id = str(event.get("id") or "").strip()
            if not command_id or command_id.startswith("__"):
                return
            # 不把 control 回执或 prompt 写入轨迹，只在同一 stdout
            # 顺序点留下一个不含用户内容的插话边界。页面再用
            # MySQL 中的持久消息补齐文本和附件。
            event = {
                "type": "numoj_steer",
                "version": 1,
                "message_id": command_id,
            }
        if (
            not isinstance(event, dict)
            or event.get("type") not in self._EVENT_TYPES | {"numoj_steer"}
            or event.get("version") != 1
        ):
            return
        if event.get("type") in {"numoj_trace", "numoj_steer"}:
            self._trace_sequence += 1
            event["sequence"] = self._trace_sequence
        if event.get("type") == "numoj_trace":
            trace_event = (
                event.get("event")
                if isinstance(event.get("event"), dict)
                else None
            )
            if trace_event is None:
                return
            record_id = str(trace_event.get("id") or "").strip()
            if not record_id:
                record_id = f"trace-{self._trace_sequence}"
                trace_event["id"] = record_id
        if event.get("type") == "numoj_usage":
            record_id = str(event.get("id") or "").strip()
            if not record_id:
                return
            event["id"] = record_id
        redacted_event = self._redact(event)
        payload = (
            json.dumps(
                redacted_event,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        # adapter usage 只用于轨迹和 token 展示。实际扣费以宿主 relay
        # 完整读取到的 provider usage 为准，不能在这里再次记账。
        self._store_payload(
            payload,
            pinned=event.get("type") == "numoj_steer",
        )
        if event.get("type") in {"numoj_trace", "numoj_steer"}:
            self._pending_trace_records.append(redacted_event)

    def drain_trace_records(self):
        with self._lock:
            records = tuple(self._pending_trace_records)
            self._pending_trace_records.clear()
            return records

    def feed(self, block):
        payload = bytes(block or b"")
        if not payload:
            return
        with self._lock:
            if self._closed:
                return
            self._buffer.extend(payload)
            while True:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    if len(self._buffer) > _CANONICAL_JOURNAL_RECORD_MAX_BYTES:
                        self._buffer.clear()
                        self._discarding_record = True
                    return
                raw = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                if self._discarding_record:
                    self._discarding_record = False
                    continue
                if len(raw) > _CANONICAL_JOURNAL_RECORD_MAX_BYTES:
                    continue
                self._append_record(raw)
                if self._closed:
                    return

    def close(self):
        with self._lock:
            if self._closed:
                return
            for payload, _pinned in self._tail_records:
                if self._written + len(payload) > self._max_bytes:
                    break
                self._write_payload(payload)
            self._tail_records.clear()
            self._tail_bytes = 0
            self._closed = True
            os.close(self._fd)


class _CompositeBlockObserver:
    def __init__(self, *observers):
        self._observers = tuple(item for item in observers if item is not None)

    def feed(self, block):
        for observer in self._observers:
            try:
                observer.feed(block)
            except Exception:
                continue


def _iter_control_commands(control_source):
    if not callable(control_source):
        return ()
    try:
        commands = control_source()
    except Exception:
        # 控制队列暂时不可读不能中断正在执行的 Agent；下一轮轮询重试。
        return ()
    if commands is None:
        return ()
    if isinstance(commands, dict):
        return (commands,)
    try:
        return tuple(commands)
    except TypeError:
        return ()


def _normalize_control_command(command):
    if not isinstance(command, dict):
        raise ValueError("Agent 控制命令必须是对象")
    command_id = str(command.get("id") or "").strip()
    command_type = str(command.get("type") or "").strip().lower()
    if not command_id:
        raise ValueError("Agent 控制命令缺少 id")
    if command_type not in {"steer", "interrupt"}:
        raise ValueError("Agent 控制命令类型无效")
    normalized = {
        "type": command_type,
        "id": command_id,
    }
    if command_type == "steer":
        message = str(command.get("message") or "")
        if not message.strip():
            raise ValueError("Agent 插话消息不能为空")
        normalized["message"] = message
        attachments = command.get("attachments")
        if isinstance(attachments, list):
            normalized["attachments"] = [
                item for item in attachments if isinstance(item, dict)
            ]
    target_task_id = str(command.get("target_task_id") or "").strip()
    if target_task_id:
        normalized["target_task_id"] = target_task_id
    return normalized


def _run_with_bounded_output(
    args,
    prompt,
    *,
    process_env=None,
    stdout_capture_path=None,
    on_tick=None,
    tick_interval=AGENT_TRACE_SYNC_INTERVAL_SECONDS,
    cancel_check=None,
    cancel_check_interval=1.0,
    quota_check=None,
    quota_check_interval=AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS,
    control_source=None,
    control_callback=None,
    control_target_task_id="",
    interrupt_grace_seconds=10.0,
    canonical_journal_path=None,
    canonical_journal_secrets=(),
):
    final_tick_error = None
    interactive = callable(control_source)
    stdout_mirror = (
        _BoundedStdoutMirror(
            stdout_capture_path,
            _STDOUT_MIRROR_LIMIT_BYTES,
        )
        if stdout_capture_path else None
    )
    canonical_observer = None
    try:
        if canonical_journal_path:
            canonical_observer = _CanonicalJournalObserver(
                canonical_journal_path,
                secrets=canonical_journal_secrets,
            )
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=process_env,
        )
    except BaseException:
        if stdout_mirror is not None:
            stdout_mirror.close()
        if canonical_observer is not None:
            canonical_observer.close()
        raise
    stdout_chunks = deque()
    stderr_chunks = deque()
    sizes = {"stdout": 0, "stderr": 0}
    pending_control_ids = set()
    seen_control_ids = set()
    interrupt_control_ids = set()
    interrupt_sent_at = None
    control_lock = threading.Lock()

    def publish_control(command_id, status, error=""):
        nonlocal interrupt_sent_at
        with control_lock:
            pending_control_ids.discard(command_id)
            if (
                status == "rejected"
                and command_id != "__cancel__"
                and command_id in interrupt_control_ids
            ):
                interrupt_control_ids.discard(command_id)
                if not interrupt_control_ids:
                    interrupt_sent_at = None
        if callable(control_callback):
            control_callback(command_id, status, error)

    control_observer = _ControlEventObserver(publish_control) if interactive else None
    observer = _CompositeBlockObserver(control_observer, canonical_observer)
    threads = [
        threading.Thread(
            target=_tail_reader,
            args=(proc.stdout, stdout_chunks, sizes, "stdout", _CAPTURE_LIMIT_BYTES),
            kwargs={
                "mirror_stream": stdout_mirror,
                "block_observer": observer.feed if observer is not None else None,
            },
            daemon=True,
        ),
        threading.Thread(
            target=_tail_reader,
            args=(proc.stderr, stderr_chunks, sizes, "stderr", _CAPTURE_LIMIT_BYTES),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        if interactive:
            start_frame = {
                "type": "start",
                "id": "__start__",
                "message": str(prompt or ""),
            }
            if str(control_target_task_id or "").strip():
                start_frame["target_task_id"] = str(control_target_task_id).strip()
            try:
                proc.stdin.write(
                    (json.dumps(start_frame, ensure_ascii=False) + "\n").encode("utf-8")
                )
                proc.stdin.flush()
            except BrokenPipeError:
                pass
        else:
            try:
                proc.stdin.write(str(prompt or "").encode("utf-8"))
            except BrokenPipeError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
        # 与 Reverse Judge 一致：进入执行循环后立即做第一次同步，后续再按
        # 固定间隔同步，避免前端必须空等完整的 tick 周期。
        last_tick = 0.0
        last_cancel_check = None
        last_quota_check = None
        while True:
            try:
                returncode = proc.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if interactive:
                    for raw_command in _iter_control_commands(control_source):
                        try:
                            command = _normalize_control_command(raw_command)
                            target = str(command.get("target_task_id") or "")
                            expected = str(control_target_task_id or "")
                            if target and expected and target != expected:
                                raise ValueError("Agent 控制命令目标任务已变化")
                            with control_lock:
                                if command["id"] in seen_control_ids:
                                    raise ValueError("Agent 控制命令 id 已处理")
                                seen_control_ids.add(command["id"])
                                pending_control_ids.add(command["id"])
                                if command["type"] == "interrupt":
                                    interrupt_control_ids.add(command["id"])
                                    interrupt_sent_at = now
                            payload = (
                                json.dumps(command, ensure_ascii=False) + "\n"
                            ).encode("utf-8")
                            proc.stdin.write(payload)
                            proc.stdin.flush()
                        except (BrokenPipeError, OSError) as exc:
                            command_id = str(
                                raw_command.get("id")
                                if isinstance(raw_command, dict) else ""
                            ).strip()
                            if command_id:
                                publish_control(command_id, "unknown", str(exc))
                        except ValueError as exc:
                            command_id = str(
                                raw_command.get("id")
                                if isinstance(raw_command, dict) else ""
                            ).strip()
                            if command_id:
                                publish_control(command_id, "rejected", str(exc))
                if (
                    callable(quota_check)
                    and (
                        last_quota_check is None
                        or now - last_quota_check
                        >= max(0.5, float(quota_check_interval))
                    )
                ):
                    last_quota_check = now
                    # 配额与磁盘保留检查是安全边界，异常必须
                    # 传播到外层杀死 docker exec，不得像 trace tick 那样吞掉。
                    quota_check()
                if (
                    callable(cancel_check)
                    and (
                        last_cancel_check is None
                        or now - last_cancel_check
                        >= max(0.5, float(cancel_check_interval))
                    )
                ):
                    last_cancel_check = now
                    try:
                        canceled = bool(cancel_check())
                    except Exception:
                        canceled = False
                    if canceled:
                        if interactive and interrupt_sent_at is None:
                            interrupt_frame = {
                                "type": "interrupt",
                                "id": "__cancel__",
                            }
                            try:
                                with control_lock:
                                    pending_control_ids.add("__cancel__")
                                    interrupt_control_ids.add("__cancel__")
                                proc.stdin.write(
                                    (json.dumps(interrupt_frame) + "\n").encode("utf-8")
                                )
                                proc.stdin.flush()
                                interrupt_sent_at = now
                            except (BrokenPipeError, OSError):
                                interrupt_sent_at = now - float(interrupt_grace_seconds)
                        elif not interactive:
                            proc.terminate()
                            try:
                                returncode = proc.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                proc.kill()
                                returncode = proc.wait()
                            break
                if (
                    interactive
                    and interrupt_sent_at is not None
                    and now - interrupt_sent_at >= max(0.5, float(interrupt_grace_seconds))
                ):
                    proc.terminate()
                    try:
                        returncode = proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        returncode = proc.wait()
                    break
                if (
                    callable(on_tick)
                    and now - last_tick >= max(0.5, float(tick_interval))
                ):
                    try:
                        if stdout_mirror is not None:
                            stdout_mirror.publish()
                        if canonical_observer is not None:
                            on_tick(
                                final=False,
                                trace_records=(
                                    canonical_observer.drain_trace_records()
                                ),
                            )
                        else:
                            on_tick(final=False)
                    except Exception:
                        pass
                    last_tick = now
    except BaseException:
        try:
            proc.kill()
            proc.wait(timeout=10)
        except Exception:
            pass
        raise
    finally:
        if interactive:
            try:
                proc.stdin.close()
            except Exception:
                pass
        for thread in threads:
            thread.join()
        if canonical_observer is not None:
            canonical_observer.close()
        with control_lock:
            unresolved = tuple(pending_control_ids)
            pending_control_ids.clear()
        for command_id in unresolved:
            if callable(control_callback):
                control_callback(
                    command_id,
                    "unknown",
                    "harness 已结束，但没有确认控制命令",
                )
        if stdout_mirror is not None:
            stdout_mirror.publish()
        if callable(on_tick):
            try:
                if canonical_observer is not None:
                    on_tick(
                        final=True,
                        trace_records=canonical_observer.drain_trace_records(),
                    )
                else:
                    on_tick(final=True)
            except Exception as exc:
                # 中间 tick 可以等待下一轮重试；最后一次 canonical tick
                # 没有后继，必须把 v2 持久化失败交给任务收束逻辑处理。
                if canonical_observer is not None:
                    final_tick_error = exc
        if stdout_mirror is not None:
            stdout_mirror.close()
    if final_tick_error is not None:
        raise final_tick_error
    return HarnessRunResult(
        returncode=int(returncode),
        timed_out=False,
        stdout=b"".join(stdout_chunks).decode("utf-8", "replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", "replace"),
    )


def _web_search_mcp_env(settings):
    if not settings:
        return {}
    base_url = _containerize_url(settings.get("base_url"))
    authorization = str(settings.get("authorization") or "").strip()
    if not base_url or not authorization:
        raise RuntimeError("站点 Web Search MCP 配置不完整")
    try:
        timeout_seconds = int(MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout_seconds = 90
    timeout_seconds = max(10, min(240, timeout_seconds))
    return {
        _WEB_SEARCH_MCP_URL_ENV: base_url,
        _WEB_SEARCH_MCP_AUTH_ENV: authorization,
        _WEB_SEARCH_MCP_TIMEOUT_ENV: str(timeout_seconds),
    }


def _runtime_env(
    endpoint,
    harness,
    task_kind,
    *,
    endpoint_base_url,
    endpoint_api_key,
    access_role=AGENT_ACCESS_ROLE_USER,
    resume_session_id="",
    web_search_settings=None,
    interactive=False,
    reasoning_effort="default",
):
    protocol = str(endpoint.get("protocol") or "").strip().lower()
    # 长期密钥和真实上游地址不得进入容器；这里只接受本轮宿主 relay
    # 返回的容器地址与临时 API Key。
    base_url = str(endpoint_base_url or "").strip()
    api_key = str(endpoint_api_key or "").strip()
    if not base_url or not api_key:
        raise RuntimeError("Agent 外部服务密钥代理配置不完整")
    model = str(endpoint.get("model") or "").strip()
    context_window_tokens = int(
        endpoint.get("context_window_tokens")
        or DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
    )
    max_output_tokens = int(
        endpoint.get("max_output_tokens") or DEFAULT_LLM_MAX_OUTPUT_TOKENS
    )
    if context_window_tokens <= 0 or not 0 < max_output_tokens <= context_window_tokens:
        raise RuntimeError("Agent 模型节点的上下文容量配置无效")
    thinking_enabled = bool(endpoint.get("thinking_enabled"))
    thinking_format = str(endpoint.get("thinking_format") or "none").strip().lower()
    access_role = normalize_agent_access_role(access_role, task_kind=task_kind)
    reasoning_effort = normalize_agent_reasoning_effort(
        reasoning_effort,
        harness,
    )
    if reasoning_effort != "default":
        # 通用 Agent 会话中用户选择的深度是最终配置：Pi 的 off
        # 强制关闭，其余 Pi/Claude 档位按协议默认 wire shape 强制开启，
        # 不再受节点的思考开关与随开关关闭的格式字段覆盖。
        thinking_enabled = reasoning_effort != "off"
        thinking_format = (
            "thinking_type" if protocol == "anthropic" else "enable_thinking"
        ) if thinking_enabled else "none"
    skill_name = skill_for_agent_task(task_kind, access_role)
    resume_session_id = normalize_native_session_id(resume_session_id, harness)

    env = {
        "IS_SANDBOX": "1",
        "HOME": "/workspace/.runtime/home",
        # 容器只有 /workspace 可写；把各类临时目录变量统一收敛到会话
        # workspace，避免工具把可恢复状态写进容器自身的 /tmp。
        "TMPDIR": "/workspace/.runtime/tmp",
        "TMP": "/workspace/.runtime/tmp",
        "TEMP": "/workspace/.runtime/tmp",
        "XDG_CACHE_HOME": "/workspace/.runtime/xdg-cache",
        "XDG_CONFIG_HOME": "/workspace/.runtime/xdg-config",
        "XDG_DATA_HOME": "/workspace/.runtime/xdg-data",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "AJ_HARNESS": harness,
        "AJ_ENDPOINT_PROTOCOL": protocol,
        "AJ_ENDPOINT_BASE_URL": base_url,
        "AJ_ENDPOINT_API_KEY": api_key,
        "AJ_ENDPOINT_MODEL": model,
        "AJ_ENDPOINT_CONTEXT_WINDOW_TOKENS": str(context_window_tokens),
        "AJ_ENDPOINT_MAX_OUTPUT_TOKENS": str(max_output_tokens),
        "AJ_ENDPOINT_THINKING_ENABLED": "1" if thinking_enabled else "0",
        "AJ_ENDPOINT_THINKING_FORMAT": thinking_format,
        "AJ_ENABLE_SKILLS": "1",
        "AJ_TASK_SCOPE": "problem_agent",
        "AJ_RUNTIME_ROOT": "/workspace/.runtime",
        "AJ_PROMPT_STDIN": "1",
        "AJ_WORKSPACE": "/workspace",
        _SKILL_CONFIG_ENV[skill_name]: _IDENTITY_CONFIG_PATH,
    }
    if resume_session_id:
        env["AJ_RESUME_SESSION_ID"] = resume_session_id
        # 真正的“继续会话”必须复用同一个原生 session；Claude Code 的
        # --fork-session 会创建分支，不能作为通用 Agent 的续聊语义。
        env["AJ_FORK_SESSION"] = "0"
    if reasoning_effort != "default":
        env["AJ_EFFORT"] = reasoning_effort
    if interactive:
        # run_harness 在此模式消费 NumOJ NDJSON 控制帧；未设置时继续读取
        # 原始 prompt stdin，保证 Reverse Judge 和旧调用方完全兼容。
        env["AJ_CONTROL_PROTOCOL"] = "numoj-ndjson-v1"
        env["AJ_INTERACTIVE_SUPPORTED"] = "1"
        env.pop("AJ_PROMPT_STDIN", None)
    env.update(_web_search_mcp_env(web_search_settings))
    return env


def _docker_args(
    *,
    container_name,
    workspace,
    env,
    readonly_workspace_paths=(),
):
    # Colima/virtiofs 会把 macOS bind mount 的属主统一投影为容器 root，数值
    # keep-id 反而无法写入任务目录。本地 Darwin 仅在已经只读根、无 capability、
    # no-new-privileges 的容器中使用 root；Linux 生产仍严格沿用部署用户 UID/GID。
    if platform.system() == "Darwin":
        container_user = "0:0"
    else:
        container_user = f"{os.getuid()}:{os.getgid()}"
    workspace_path = Path(workspace).resolve()
    args = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--ipc",
        "none",
        "--pids-limit",
        str(AGENT_JUDGE_PIDS_LIMIT),
        "--memory",
        str(AGENT_JUDGE_MEM_LIMIT),
        "--cpus",
        str(AGENT_JUDGE_CPU_LIMIT),
        "--user",
        container_user,
        "--add-host",
        "host.docker.internal:host-gateway",
        "--volume",
        f"{workspace_path}:/workspace:rw",
        "--workdir",
        "/workspace",
    ]
    # /workspace 本身承载项目文件和原生 Harness session，必须持续可写；
    # 仓库投影的受信任 skill 则通过更深一层的只读 bind mount 覆盖，避免
    # Agent 在运行中删除或改写它，同时不影响同一 HOME 下的其它配置。
    for source in readonly_workspace_paths:
        source_path = Path(source).resolve()
        relative_path = source_path.relative_to(workspace_path)
        container_path = Path("/workspace") / relative_path
        args.extend([
            "--volume",
            f"{source_path}:{container_path}:ro",
        ])
    # 只把变量名放进 docker 命令行；值通过 docker 客户端自身的环境继承，
    # 避免 LLM API Key 出现在宿主进程参数和常规进程清单中。
    for key in env:
        args.extend(["--env", key])
    args.extend([
        str(AGENT_JUDGE_DOCKER_IMAGE),
        "bash",
        "-lc",
        "tail -f /dev/null",
    ])
    return args


def _docker_exec_args(container_name):
    return [
        "docker",
        "exec",
        "-i",
        container_name,
        "/usr/local/bin/run_harness",
    ]


def _docker_process_env(container_env):
    """构造 Docker CLI 环境，同时保留宿主的 context 配置位置。"""

    process_env = os.environ.copy()
    host_home = str(process_env.get("HOME") or "").strip()
    if not str(process_env.get("DOCKER_CONFIG") or "").strip() and host_home:
        # `docker run --env HOME` 仍需从此环境读取容器值，但 Docker CLI 自身
        # 必须继续从宿主 ~/.docker 读取 Colima/Desktop context。
        process_env["DOCKER_CONFIG"] = str(Path(host_home) / ".docker")
    process_env.update(container_env)
    return process_env


def _sanitize_output(result, *, secrets):
    stdout = result.stdout
    stderr = result.stderr
    values = {
        str(secret or "")
        for secret in secrets
        if str(secret or "")
    }
    for value in sorted(values, key=len, reverse=True):
        stdout = stdout.replace(value, "[已脱敏]")
        stderr = stderr.replace(value, "[已脱敏]")
    return HarnessRunResult(
        returncode=result.returncode,
        timed_out=result.timed_out,
        stdout=stdout,
        stderr=stderr,
        artifacts=dict(result.artifacts or {}),
        created_submission_ids=tuple(result.created_submission_ids or ()),
        native_session_id=str(result.native_session_id or ""),
    )


def _agent_container_not_found(detail):
    normalized_detail = str(detail or "").lower()
    return (
        "no such container" in normalized_detail
        or "no such object" in normalized_detail
    )


def _remove_agent_container(container_name):
    """确认同名容器已不存在；并发清理必须等到 daemon 给出最终状态。"""

    last_detail = ""
    for _attempt in range(2):
        try:
            completed = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except Exception as exc:
            last_detail = str(exc)
            continue
        detail = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
        if completed.returncode == 0 or _agent_container_not_found(detail):
            return
        last_detail = detail or f"docker rm exited {completed.returncode}"
        normalized_detail = detail.lower()
        if (
            "removal of container" not in normalized_detail
            or "already in progress" not in normalized_detail
        ):
            continue

        # 手动终止、broker 重投和 harness finally 都可能发起同名清理。Docker
        # 已经开始移除时会拒绝第二个 rm；这不是失败，只有 inspect 在限定时间内
        # 仍能证明容器存在时才算失败。daemon 状态未知仍保持 fail-closed。
        deadline = time.monotonic() + _CONTAINER_REMOVAL_CONFIRM_TIMEOUT_SECONDS
        while True:
            try:
                inspected = subprocess.run(
                    ["docker", "container", "inspect", container_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            except Exception as exc:
                last_detail = f"{last_detail}; docker inspect 失败：{exc}"
                break
            inspect_detail = (
                f"{inspected.stdout or ''}\n{inspected.stderr or ''}"
            ).strip()
            if (
                inspected.returncode != 0
                and _agent_container_not_found(inspect_detail)
            ):
                return
            if inspected.returncode != 0:
                last_detail = (
                    f"{last_detail}; docker inspect exited "
                    f"{inspected.returncode}: {inspect_detail}"
                )
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(_CONTAINER_REMOVAL_CONFIRM_POLL_SECONDS)
    raise AgentHarnessCleanupError(
        f"无法确认 Agent 容器 {container_name} 已清理：{last_detail[:500]}"
    )


def _container_name_for_task_id(task_id):
    return agent_run_container_name(task_id)


def run_agent_harness(
    *,
    task_id,
    task_kind,
    problem_id=None,
    requested_by,
    harness,
    endpoint,
    session_cookie,
    prompt,
    session_id=None,
    access_role=AGENT_ACCESS_ROLE_USER,
    resume_session_id="",
    restore_runtime_checkpoint_id="",
    session_cookie_name="session",
    workspace_files=None,
    artifact_files=None,
    trace_callback=None,
    trace_records_callback=None,
    cancel_check=None,
    reset_trace=True,
    control_source=None,
    control_callback=None,
    control_target_task_id=None,
    usage_callback=None,
    native_session_callback=None,
    reasoning_effort="default",
):
    """在稳定会话工作区内运行一轮 harness，结束后只删除容器和凭证。"""

    task_kind = normalize_agent_task_kind(task_kind)
    harness = normalize_launch_harness(harness)
    access_role = normalize_agent_access_role(access_role, task_kind=task_kind)
    reasoning_effort = normalize_agent_reasoning_effort(
        reasoning_effort,
        harness,
    )
    resume_session_id = normalize_native_session_id(resume_session_id, harness)
    quota_check_interval = float(AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS)
    if quota_check_interval <= 0:
        raise RuntimeError(
            "AGENT_WORKSPACE_QUOTA_CHECK_INTERVAL_SECONDS 必须是正数"
        )
    if callable(cancel_check):
        try:
            canceled_before_start = bool(cancel_check())
        except Exception:
            canceled_before_start = False
        if canceled_before_start:
            return HarnessRunResult(
                returncode=-15,
                timed_out=False,
                stdout="",
                stderr="Agent task canceled before harness startup",
            )
    skill_name = skill_for_agent_task(task_kind, access_role)
    normalized_session_id = str(session_id or task_id or "").strip()
    workspace = _ensure_stable_workspace(normalized_session_id)
    last_published_native_session_id = resume_session_id

    def publish_native_session_snapshot():
        """尽早发布 workspace 中已经原子落盘的原生恢复点。"""

        nonlocal last_published_native_session_id
        try:
            native_session_id = (
                _read_native_session_id(workspace, harness)
                or resume_session_id
            )
        except (OSError, ValueError):
            # Harness 可能正在替换 current-session 文件；下一 tick、退出
            # 边界和最外层 finally 都会再次读取。
            return last_published_native_session_id
        if (
            native_session_id
            and native_session_id != last_published_native_session_id
            and callable(native_session_callback)
        ):
            native_session_callback(native_session_id)
        if native_session_id:
            last_published_native_session_id = native_session_id
        return native_session_id

    restore_runtime_checkpoint_id = str(
        restore_runtime_checkpoint_id or ""
    ).strip()
    from backend.oj_modules.agents.workspace import (
        check_agent_workspace_quota,
        merge_agent_temporary_redaction_candidates,
    )

    container_name = _container_name_for_task_id(task_id)
    # late-ack 重投可能留下同 task_id 的旧容器。必须先确认它已经停止，
    # 才能安全替换私有 runtime；否则旧进程会与 checkpoint 恢复并发写入。
    _remove_agent_container(container_name)
    if restore_runtime_checkpoint_id:
        # “重试上一条消息”只回退 harness 的私有会话状态；普通 workspace
        # 文件继续保留当前内容。checkpoint 位于 workspace 挂载之外，Agent
        # 无法篡改，恢复也必须发生在新容器启动之前。
        from backend.oj_modules.agents.runtime_checkpoints import (
            restore_agent_runtime_checkpoint,
        )

        restore_agent_runtime_checkpoint(
            normalized_session_id,
            restore_runtime_checkpoint_id,
        )
    # 重试应先丢弃被替代尝试可能写爆的 runtime，再按恢复后的真实目录
    # 计算配额；普通 workspace 文件仍会参与检查且不会被回退。
    check_agent_workspace_quota(normalized_session_id)
    trace_dir = (
        prepare_agent_trace_dir(task_id)
        if reset_trace
        else ensure_agent_trace_dir(task_id)
    )
    runtime_dirs = (
        ".runtime/home",
        ".runtime/tmp",
        ".runtime/xdg-cache",
        ".runtime/xdg-config",
        ".runtime/xdg-data",
    )
    for relative in runtime_dirs:
        _ensure_workspace_directory(workspace, relative)

    # Session 只驻留在宿主转发器内存中。工作区里的固定占位 cookie 仅用于
    # NumOJ CLI 的本地“已登录”检查，没有任何站点权限。
    from backend.oj_modules.tasks.agent.skill_runtime import materialize_skill

    cookie_name = str(session_cookie_name or "").strip() or "session"
    identity_relative_path = ".numoj-agent/identity.json"
    stdout_trace_path = _prepare_workspace_temp_path(
        trace_dir,
        ".agent_harness.stdout.tmp",
    )
    canonical_trace_path = None
    canonical_enabled = callable(control_source) or callable(usage_callback)
    if canonical_enabled:
        canonical_trace_path = _prepare_workspace_temp_path(
            trace_dir,
            ".agent_harness.canonical.tmp",
        )
    _clear_current_session_state(workspace)
    try:
        with _identity_relay_context(
            task_kind,
            problem_id,
            AGENT_CONTAINER_SITE_URL,
            cookie_name,
            str(session_cookie or ""),
            requested_by=str(requested_by or ""),
            access_role=access_role,
            session_id=normalized_session_id,
            task_id=str(task_id or ""),
        ) as identity_relay:
            agent_task = {
                "task_id": str(task_id or ""),
                "session_id": normalized_session_id,
                "task_kind": task_kind,
                "access_role": access_role,
                "skill": skill_name,
            }
            if problem_id is not None:
                agent_task["problem_id"] = int(problem_id)
            identity_config = {
                "base_url": identity_relay.base_url,
                "username": str(requested_by or ""),
                "cookies": {"session": "relay-placeholder"},
                "agent_task": agent_task,
            }
            _write_workspace_file(
                normalized_session_id,
                ".numoj-agent/identity.json",
                json.dumps(identity_config, ensure_ascii=False, indent=2),
            )
            for relative_path, content in (workspace_files or {}).items():
                _write_workspace_file(
                    normalized_session_id,
                    relative_path,
                    content,
                )

            # 每一轮都从仓库规范源重新投影唯一允许的 skill；会话工作区虽会
            # 持久化，但不能信任上一轮留下的运行时配置。
            check_agent_workspace_quota(
                normalized_session_id,
                additional_bytes=_SKILL_WORKSPACE_RESERVATION_BYTES,
                additional_files=_SKILL_WORKSPACE_RESERVATION_FILES,
                additional_entries=_SKILL_WORKSPACE_RESERVATION_DIRECTORIES,
            )
            materialized_skill = materialize_skill(
                workspace,
                harness,
                skill_name,
            )
            check_agent_workspace_quota(normalized_session_id)
            web_search_settings = get_web_search_settings(include_secret=True)
            usage_stop_event = (
                threading.Event() if callable(usage_callback) else None
            )
            secret_relay_kwargs = {}
            if usage_stop_event is not None:
                secret_relay_kwargs["endpoint_stop_event"] = usage_stop_event
                secret_relay_kwargs["require_endpoint_usage_ack"] = True
                secret_relay_kwargs["endpoint_usage_callback"] = usage_callback
            with _secret_relay_context(
                endpoint,
                web_search_settings,
                **secret_relay_kwargs,
            ) as secret_relay:
                relayed_web_search_settings = None
                if secret_relay.web_search_base_url:
                    relayed_web_search_settings = {
                        "base_url": secret_relay.web_search_base_url,
                        "authorization": (
                            secret_relay.web_search_authorization
                        ),
                    }
                env = _runtime_env(
                    endpoint,
                    harness,
                    task_kind,
                    endpoint_base_url=secret_relay.endpoint_base_url,
                    endpoint_api_key=secret_relay.endpoint_api_key,
                    access_role=access_role,
                    resume_session_id=resume_session_id,
                    web_search_settings=relayed_web_search_settings,
                    interactive=callable(control_source),
                    reasoning_effort=reasoning_effort,
                )
                docker_args = _docker_args(
                    container_name=container_name,
                    workspace=workspace,
                    env=env,
                    readonly_workspace_paths=(materialized_skill,),
                )
                docker_process_env = _docker_process_env(env)
                identity_temporary_secrets = tuple(
                    getattr(identity_relay, "temporary_secrets", ()) or (),
                )
                # 原生 resume 会保留并再次同步旧轮次 session 文件。这里只把
                # 短生命周期 relay 候选写入容器不可见的宿主会话元数据；真实
                # Session cookie 和长期 endpoint / MCP 凭据仍只驻留本轮内存。
                temporary_trace_secrets = (
                    *identity_temporary_secrets,
                    *secret_relay.temporary_secrets,
                )
                historical_temporary_secrets = (
                    merge_agent_temporary_redaction_candidates(
                        normalized_session_id,
                        temporary_trace_secrets,
                    )
                )
                trace_secrets = (
                    *historical_temporary_secrets,
                    session_cookie,
                    endpoint.get("api_key"),
                    (web_search_settings or {}).get("authorization"),
                )

                pending_trace_records = []

                def sync_trace(*, final=False, trace_records=()):
                    publish_native_session_snapshot()
                    pending_trace_records.extend(trace_records or ())
                    sync_kwargs = {"secrets": trace_secrets}
                    if canonical_enabled:
                        sync_kwargs["canonical"] = True
                    sync_agent_trace(
                        container_name,
                        trace_dir,
                        harness,
                        canonical_trace_path or stdout_trace_path,
                        **sync_kwargs,
                    )
                    if callable(trace_records_callback) and (
                        pending_trace_records or final
                    ):
                        try:
                            trace_records_callback(
                                tuple(pending_trace_records),
                                final=bool(final),
                            )
                        except Exception:
                            # v2 入库失败时保留批次，下一次 tick 重试；轨迹
                            # 中间故障不能堵塞 stdout drain；final 已没有后继，
                            # 必须向上传递，避免终态缺少 conclude/工作详情。
                            if final:
                                raise
                        else:
                            pending_trace_records.clear()
                    if callable(trace_callback):
                        try:
                            trace_callback()
                        except Exception:
                            # 轨迹缓存不可用不能中止已运行的 Agent；终态仍会走任务状态
                            # 的规范持久化链路。
                            pass

                def enforce_workspace_quota():
                    _check_secret_relay_usage(secret_relay)
                    return check_agent_workspace_quota(normalized_session_id)

                try:
                    # Docker 启动是最后一个外部副作用；在此前再校验一次，
                    # 确保宿主注入和 skill 投影没有越过配额。
                    enforce_workspace_quota()
                    subprocess.run(
                        docker_args,
                        check=True,
                        capture_output=True,
                        env=docker_process_env,
                        timeout=120,
                    )
                    sync_trace()
                    run_kwargs = {
                        "process_env": docker_process_env,
                        "stdout_capture_path": stdout_trace_path,
                        "on_tick": sync_trace,
                        "tick_interval": AGENT_TRACE_SYNC_INTERVAL_SECONDS,
                        "cancel_check": cancel_check,
                        "quota_check": enforce_workspace_quota,
                        "quota_check_interval": quota_check_interval,
                    }
                    if callable(control_source):
                        run_kwargs.update({
                            "control_source": control_source,
                            "control_callback": control_callback,
                            "control_target_task_id": str(
                                control_target_task_id or task_id or ""
                            ),
                            "canonical_journal_path": canonical_trace_path,
                            "canonical_journal_secrets": trace_secrets,
                        })
                    elif canonical_enabled:
                        run_kwargs.update({
                            "canonical_journal_path": canonical_trace_path,
                            "canonical_journal_secrets": trace_secrets,
                        })
                    result = _run_with_bounded_output(
                        _docker_exec_args(container_name),
                        prompt,
                        **run_kwargs,
                    )
                    # usage 解析、配额检查或最终轨迹同步都可能失败；原生
                    # session 必须先于这些旁路被持久化到会话状态。
                    publish_native_session_snapshot()
                    _check_secret_relay_usage(secret_relay, wait=True)
                    enforce_workspace_quota()
                    sync_trace()
                finally:
                    try:
                        publish_native_session_snapshot()
                    finally:
                        try:
                            _remove_agent_container(container_name)
                        finally:
                            try:
                                stdout_trace_path.unlink()
                            except FileNotFoundError:
                                pass
                            if canonical_trace_path is not None:
                                try:
                                    canonical_trace_path.unlink()
                                except FileNotFoundError:
                                    pass
            artifacts = _read_workspace_artifacts(workspace, artifact_files)
            native_session_id = publish_native_session_snapshot()
            result = HarnessRunResult(
                returncode=result.returncode,
                timed_out=result.timed_out,
                stdout=result.stdout,
                stderr=result.stderr,
                artifacts=artifacts,
                created_submission_ids=identity_relay.created_submission_ids,
                native_session_id=native_session_id,
            )
            return _sanitize_output(result, secrets=trace_secrets)
    finally:
        try:
            # 覆盖身份 relay、模型 relay、清理及结果组装阶段的所有异常。
            publish_native_session_snapshot()
        finally:
            # 保留 Agent 工作产物和原生 session，真实 Session 从未落盘；本地
            # CLI 占位配置也在每轮结束后删除，避免闲置工作区保留可误用入口。
            _remove_identity_config(workspace, identity_relative_path)


__all__ = [
    "AgentHarnessCleanupError",
    "AgentUsageHardStopError",
    "HarnessRunResult",
    "extract_harness_failure_detail",
    "normalize_native_session_id",
    "read_agent_native_session_id",
    "read_agent_steer_capability",
    "run_agent_harness",
]
