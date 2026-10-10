"""冻结单次工作流的纯 LLM 运行选项，隔离 Celery 重入期间的站点配置变化。"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

from backend.oj_modules.site_config.services import get_faithsieve_pure_reasoning_effort


SNAPSHOT_FILENAME = ".numoj-agent-faithsieve-runtime.json"
_LOCK_FILENAME = ".numoj-agent-faithsieve-runtime.lock"
_MAX_SNAPSHOT_BYTES = 4096
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class FaithSieveRuntimeSnapshotError(ValueError):
    """运行选项不能可靠冻结或重放，不能继续请求模型。"""


def _effort(value):
    if value is None or (type(value) is str and value in {"low", "medium"}):
        return value
    raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照的思考强度无效")


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照有重复字段")
        result[key] = value
    return result


def _reject_constant(_value):
    raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照不是标准 JSON")


def _read_snapshot(root_fd, endpoint_id):
    fd = os.open(SNAPSHOT_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=root_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > _MAX_SNAPSHOT_BYTES:
            raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照不是受限的独立普通文件")
        data = stream.read(_MAX_SNAPSHOT_BYTES + 1)
        if len(data) > _MAX_SNAPSHOT_BYTES or os.fstat(stream.fileno()).st_nlink != 1:
            raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照超出安全边界")
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields,
                             parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照无法安全解析") from None
    if type(payload) is not dict or set(payload) != {"endpoint_id", "initial_reasoning_effort"}:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照字段无效")
    if type(payload["endpoint_id"]) is not int or payload["endpoint_id"] != endpoint_id:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照端点与本次请求不一致")
    return _effort(payload["initial_reasoning_effort"])


def _has_checkpoints(root_fd):
    work_fd = checkpoint_fd = None
    try:
        work_fd = os.open("faithsieve-work", _DIRECTORY_FLAGS, dir_fd=root_fd)
        checkpoint_fd = os.open("checkpoints", _DIRECTORY_FLAGS, dir_fd=work_fd)
        # 即使旧记录本身损坏，也不能替它套入今天的新运行选项。
        return any(name.endswith(".json") for name in os.listdir(checkpoint_fd))
    except FileNotFoundError:
        return False
    finally:
        for fd in (checkpoint_fd, work_fd):
            if fd is not None:
                os.close(fd)


@contextmanager
def _snapshot_lock(root_fd):
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        # 原子创建；竞争者只打开已有锁，避免 macOS 上并发 O_CREAT 的 ENOENT。
        fd = os.open(_LOCK_FILENAME, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=root_fd)
    except FileExistsError:
        fd = os.open(_LOCK_FILENAME, flags, dir_fd=root_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0:
            raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照锁不是独立普通文件")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _write_snapshot(root_fd, endpoint_id, effort):
    data = json.dumps({"endpoint_id": endpoint_id, "initial_reasoning_effort": effort},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    name = f".numoj-agent-faithsieve-runtime-{uuid4().hex}.tmp"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=root_fd)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(name, SNAPSHOT_FILENAME, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass


def freeze_initial_reasoning_effort(workspace, endpoint_id):
    """首次读取站点设置并冻结；旧 checkpoint 兼容原来的默认 None。"""
    if type(endpoint_id) is not int or endpoint_id <= 0:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照端点 ID 必须是正整数")
    root_fd = None
    try:
        root_fd = os.open(Path(workspace), _DIRECTORY_FLAGS)
        with _snapshot_lock(root_fd):
            try:
                return _read_snapshot(root_fd, endpoint_id)
            except FileNotFoundError:
                pass
            effort = None if _has_checkpoints(root_fd) else _effort(
                get_faithsieve_pure_reasoning_effort(endpoint_id)
            )
            _write_snapshot(root_fd, endpoint_id, effort)
            return effort
    except OSError:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照无法安全读取或保存") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)


def read_initial_reasoning_effort(workspace, endpoint_id):
    """恢复预检只读取既有快照，不创建锁、文件或查询今天的配置。"""
    if type(endpoint_id) is not int or endpoint_id <= 0:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 运行快照端点 ID 必须是正整数")
    root_fd = None
    try:
        root_fd = os.open(Path(workspace), _DIRECTORY_FLAGS)
        return _read_snapshot(root_fd, endpoint_id)
    except OSError:
        raise FaithSieveRuntimeSnapshotError("FaithSieve 原运行快照无法安全读取") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)
