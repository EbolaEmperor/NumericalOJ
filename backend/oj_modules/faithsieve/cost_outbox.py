"""只读识别正式 Judge 轮次的计费待办，不创建目录或尝试结算。"""

from __future__ import annotations

import json
import os
import re
import stat

from backend.oj_modules.agents import workspace as workspace_store

from .artifacts import _reject_json_constant, _unique_json_object


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")
_MAX_RECORD_BYTES = 64 * 1024
_MAX_FILES = 1000
_MAX_READ_BYTES = 4 * 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _read_event(directory, name):
    fd = os.open(name, _FILE_FLAGS, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= _MAX_RECORD_BYTES):
            raise ValueError("Agent 计费待办不是受限的宿主私有普通文件")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            payload = stream.read(_MAX_RECORD_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (len(payload) != info.st_size or len(payload) > _MAX_RECORD_BYTES
                or after.st_nlink != 1 or after.st_mode & 0o077):
            raise ValueError("Agent 计费待办在读取期间发生变化")
        event = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_json_object,
                           parse_constant=_reject_json_constant)
        if type(event) is not dict or type(event.get("version")) is not int or event["version"] != 1:
            raise ValueError("Agent 计费待办版本或结构无效")
        session_id, task_id = event.get("session_id"), event.get("task_id")
        source, event_id = event.get("source"), event.get("usage_event_id")
        if (type(session_id) is not str or not _IDENTIFIER.fullmatch(session_id)
                or type(task_id) is not str or not _IDENTIFIER.fullmatch(task_id)
                or type(source) is not str or not _SOURCE.fullmatch(source)
                or type(event_id) is not str or not event_id.strip() or len(event_id) > 191):
            raise ValueError("Agent 计费待办身份无效")
        return (session_id, task_id, source, event_id), len(payload)
    finally:
        if fd is not None:
            os.close(fd)


def read_pending_usage_events(session_tasks: dict[str, set[str]]) -> list[tuple[str, str, str, str]] | None:
    """返回待核对的原账本幂等键；不可安全读取时返回 ``None``。

    调用方只传数据库已确认归属的会话与轮次，并查账本排除已结算但尚未
    删除的文件。这里不读取价格、模型正文或文件名中的摘要，不回写待办。
    """
    if not session_tasks:
        return []
    if (type(session_tasks) is not dict
            or any(type(session) is not str or not _IDENTIFIER.fullmatch(session)
                   or type(tasks) not in {set, frozenset}
                   or any(type(task) is not str or not _IDENTIFIER.fullmatch(task) for task in tasks)
                   for session, tasks in session_tasks.items())):
        return None
    opened = []
    try:
        root = workspace_store._workspace_root()
        directory = os.open(root.anchor, _DIRECTORY_FLAGS)
        opened.append(directory)
        for part in (*root.parts[1:], ".usage-outbox"):
            directory = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory)
            opened.append(directory)
        if os.fstat(directory).st_mode & 0o077:
            raise ValueError("Agent 计费待办目录必须仅供宿主用户访问")
        # 名字只是宿主索引，不生成或核验文件摘要；临时发布文件不参与读取。
        names = [name for name in os.listdir(directory) if name.endswith(".json")]
        if len(names) > _MAX_FILES:
            raise ValueError("Agent 计费待办超过只读展示预算")
        keys, total_bytes = set(), 0
        for name in sorted(names):
            try:
                (session_id, task_id, source, event_id), size = _read_event(directory, name)
            except FileNotFoundError:
                # 周期结算已删除文件；后续查询仍以 MySQL 已提交的账本为准。
                continue
            total_bytes += size
            if total_bytes > _MAX_READ_BYTES:
                raise ValueError("Agent 计费待办超过只读展示预算")
            if task_id in session_tasks.get(session_id, ()):
                keys.add((session_id, task_id, source, event_id))
        return sorted(keys)
    except FileNotFoundError:
        return []
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return None
    finally:
        for fd in reversed(opened):
            os.close(fd)
