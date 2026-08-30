"""VibeHub 持久快照的跨进程串行化与存储配额。

这个模块只依赖文件系统，因此 Web、CLI 和部署种子工具可以共用同一套
边界。调用方必须在 :func:`storage_mutation_lock` 的上下文中完成“检查 +
安装/克隆”，避免多个 Gunicorn/Celery 进程同时通过检查。

用量是“逻辑字节数”：每个普通文件的 ``st_size`` 按目录入口累加，因此
硬链接也会保守地重复计数。扫描从不跟随符号链接，并在遇到链接、设备、
FIFO、socket、嵌套挂载或无法确认的竞态时 fail closed。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import logging
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Iterable, Iterator
import uuid


GIB = 1024 ** 3
DEFAULT_USER_STORAGE_BYTES = 20 * GIB
DEFAULT_PROJECTS_PER_USER = 2
DEFAULT_VERSIONS_PER_PROJECT = 1_000
DEFAULT_STORAGE_MUTATION_SLOTS = 2
DEFAULT_STORAGE_MUTATION_SLOT_WAIT_SECONDS = 0.1
MAX_STORAGE_MUTATION_SLOTS = 8
MAX_STORAGE_MUTATION_SLOT_WAIT_SECONDS = 1.0
# 保留首版 multipart 名称作为调用兼容别名；它们指向同一组
# 全宿主持久变更槽，不得在同一请求中嵌套获取。
DEFAULT_MULTIPART_PARSE_SLOTS = DEFAULT_STORAGE_MUTATION_SLOTS
DEFAULT_MULTIPART_SLOT_WAIT_SECONDS = DEFAULT_STORAGE_MUTATION_SLOT_WAIT_SECONDS
MAX_MULTIPART_PARSE_SLOTS = MAX_STORAGE_MUTATION_SLOTS
MAX_MULTIPART_SLOT_WAIT_SECONDS = MAX_STORAGE_MUTATION_SLOT_WAIT_SECONDS

MUTATION_LOCK_FILENAME = ".mutation.lock"
STORAGE_MUTATION_SLOT_FILENAME_TEMPLATE = ".storage-mutation-slot-{}.lock"
MULTIPART_SLOT_FILENAME_TEMPLATE = STORAGE_MUTATION_SLOT_FILENAME_TEMPLATE
DEFAULT_UPLOAD_STAGING_GRACE_SECONDS = 60 * 60
MAX_SCAN_ENTRIES = 2_000_000
MAX_SCAN_DEPTH = 128

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_UPLOAD_STAGING_RE = re.compile(r"^upload-([0-9a-f]{32})$")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_LOCK_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)

_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}
_STORAGE_MUTATION_THREAD_LOCKS_GUARD = threading.Lock()
_STORAGE_MUTATION_THREAD_LOCKS: dict[tuple[int, str, int], threading.Lock] = {}
_LOCK_STATE = threading.local()
_LOGGER = logging.getLogger(__name__)


class VibeHubQuotaPolicyError(RuntimeError):
    """可安全转成 VibeHub 业务响应的配额错误。"""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        code: str,
        details: dict | None = None,
    ) -> None:
        self.status_code = int(status_code)
        self.code = str(code)
        self.details = dict(details or {})
        super().__init__(str(message))


class VibeHubStorageSecurityError(VibeHubQuotaPolicyError):
    """存储树不再满足安全扫描的先决条件。"""

    def __init__(self, message: str = "VibeHub 存储状态异常，请稍后重试") -> None:
        super().__init__(
            message,
            status_code=409,
            code="storage_security_conflict",
        )


class VibeHubStorageQuotaExceeded(VibeHubQuotaPolicyError):
    """单用户逻辑存储超过硬上限。"""

    def __init__(
        self,
        *,
        scope: str,
        current_bytes: int,
        incoming_bytes: int,
        projected_bytes: int,
        limit_bytes: int,
    ) -> None:
        if scope != "user":
            raise ValueError("scope must be user")
        super().__init__(
            f"VibeHub 个人存储配额不足（上限 {limit_bytes} 字节）",
            status_code=413,
            code=f"{scope}_storage_quota_exceeded",
            details={
                "scope": scope,
                "current_bytes": int(current_bytes),
                "incoming_bytes": int(incoming_bytes),
                "projected_bytes": int(projected_bytes),
                "limit_bytes": int(limit_bytes),
            },
        )


class VibeHubCountQuotaExceeded(VibeHubQuotaPolicyError):
    """项目数或不可变版本数超过业务上限。"""

    def __init__(
        self,
        *,
        resource: str,
        current: int,
        incoming: int,
        projected: int,
        limit: int,
    ) -> None:
        if resource not in {"projects", "versions"}:
            raise ValueError("resource must be projects or versions")
        label = "作品数" if resource == "projects" else "作品版本数"
        super().__init__(
            f"VibeHub {label}不能超过 {limit}",
            status_code=409,
            code=f"{resource}_quota_exceeded",
            details={
                "resource": resource,
                "current": int(current),
                "incoming": int(incoming),
                "projected": int(projected),
                "limit": int(limit),
            },
        )


class VibeHubStorageMutationCapacityExceeded(VibeHubQuotaPolicyError):
    """宿主持久变更槽已满，调用方应快速返回 429。"""

    def __init__(self, *, slots: int) -> None:
        super().__init__(
            "VibeHub 持久变更并发已满，请稍后重试",
            status_code=429,
            code="storage_mutation_capacity_exceeded",
            details={"slots": int(slots)},
        )


VibeHubMultipartCapacityExceeded = VibeHubStorageMutationCapacityExceeded


@dataclass(frozen=True, slots=True)
class StorageQuotaProjection:
    """一次存储变更前后的逻辑用量。"""

    user_existing_bytes: int
    incoming_bytes: int
    user_projected_bytes: int
    incoming_already_staged: bool


@dataclass(frozen=True, slots=True)
class UploadStagingReclaimResult:
    """一次受管上传暂存审计和老化回收的结果。"""

    inspected: tuple[str, ...]
    active: tuple[str, ...]
    deleted_expired: tuple[str, ...]
    reclaimed_bytes: int


def _absolute(path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _nonnegative_integer(value, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VibeHubStorageSecurityError(f"{label}必须是非负整数")
    return int(value)


def _positive_integer(value, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise VibeHubStorageSecurityError(f"{label}必须是正整数")
    return int(value)


def _safe_slug(value) -> str:
    slug = str(value or "")
    if not _SLUG_RE.fullmatch(slug):
        raise VibeHubStorageSecurityError("VibeHub 作品存储标识无效")
    return slug


def _thread_lock_for(root: Path) -> threading.Lock:
    key = os.fspath(root)
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


def _storage_mutation_thread_lock_for(root: Path, index: int) -> threading.Lock:
    # pid 是 key 的一部分：Gunicorn fork 后不会继承父进程某个
    # 恰好处于 locked 状态的 threading.Lock。
    key = (os.getpid(), os.fspath(root), int(index))
    with _STORAGE_MUTATION_THREAD_LOCKS_GUARD:
        return _STORAGE_MUTATION_THREAD_LOCKS.setdefault(key, threading.Lock())


def _storage_mutation_slot_count(value) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_STORAGE_MUTATION_SLOTS
    ):
        raise VibeHubStorageSecurityError(
            f"VibeHub 持久变更槽必须是 1–{MAX_STORAGE_MUTATION_SLOTS} 的整数"
        )
    return int(value)


def _storage_mutation_slot_wait_seconds(value) -> float:
    if isinstance(value, bool):
        raise VibeHubStorageSecurityError("VibeHub 持久变更槽等待时间无效")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise VibeHubStorageSecurityError(
            "VibeHub 持久变更槽等待时间无效"
        ) from exc
    if (
        not math.isfinite(timeout)
        or not 0 <= timeout <= MAX_STORAGE_MUTATION_SLOT_WAIT_SECONDS
    ):
        raise VibeHubStorageSecurityError(
            "VibeHub 持久变更槽等待必须在 "
            f"0–{MAX_STORAGE_MUTATION_SLOT_WAIT_SECONDS:g} 秒"
        )
    return timeout


@contextmanager
def storage_mutation_capacity_slot(
    root,
    *,
    slots: int = DEFAULT_STORAGE_MUTATION_SLOTS,
    wait_seconds: float = DEFAULT_STORAGE_MUTATION_SLOT_WAIT_SECONDS,
) -> Iterator[int]:
    """在 Web 持久变更的 DB/body/mutation lock 之前取得跨进程槽。

    每个槽同时由进程内 ``threading.Lock`` 和宿主私有目录中的
    ``flock`` 约束，因此 Gunicorn gthread 和多 worker 都不会把上限成倍
    放大。它同时约束请求体 spool 和随后进入全局存储变更锁的等待者。
    锁文件使用 ``O_NOFOLLOW`` 打开并校验类型、属主与链接数；忙时在极短
    等待后抛出 429 业务错误。
    """

    slot_count = _storage_mutation_slot_count(slots)
    timeout = _storage_mutation_slot_wait_seconds(wait_seconds)
    root_path, root_fd = _prepare_private_root(root)
    deadline = time.monotonic() + timeout
    selected_fd = -1
    selected_lock = None
    selected_index = None
    try:
        while selected_fd < 0:
            for index in range(slot_count):
                thread_lock = _storage_mutation_thread_lock_for(root_path, index)
                if not thread_lock.acquire(blocking=False):
                    continue
                fd = -1
                busy = False
                try:
                    try:
                        fd = os.open(
                            STORAGE_MUTATION_SLOT_FILENAME_TEMPLATE.format(index),
                            _LOCK_FLAGS,
                            0o600,
                            dir_fd=root_fd,
                        )
                    except OSError as exc:
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽锁无法安全打开"
                        ) from exc
                    try:
                        info = os.fstat(fd)
                    except OSError as exc:
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽锁无法复核"
                        ) from exc
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or int(info.st_uid) != int(os.geteuid())
                        or int(info.st_nlink) != 1
                    ):
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽锁类型或属主异常"
                        )
                    try:
                        os.fchmod(fd, 0o600)
                    except OSError as exc:
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽锁权限无法收紧"
                        ) from exc
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        busy = True
                    except OSError as exc:
                        if exc.errno in {errno.EACCES, errno.EAGAIN}:
                            busy = True
                        else:
                            raise VibeHubStorageSecurityError(
                                "VibeHub 持久变更槽锁无法获取"
                            ) from exc
                    if busy:
                        continue
                    try:
                        current = root_path.lstat()
                        opened = os.fstat(root_fd)
                    except OSError as exc:
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽根目录无法复核"
                        ) from exc
                    if (current.st_dev, current.st_ino) != (
                        opened.st_dev,
                        opened.st_ino,
                    ):
                        raise VibeHubStorageSecurityError(
                            "VibeHub 持久变更槽根目录已被替换"
                        )
                    selected_fd = fd
                    fd = -1
                    selected_lock = thread_lock
                    selected_index = index
                    break
                finally:
                    if fd >= 0:
                        os.close(fd)
                    if selected_lock is not thread_lock:
                        thread_lock.release()

            if selected_fd >= 0:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VibeHubStorageMutationCapacityExceeded(slots=slot_count)
            time.sleep(min(0.01, remaining))

        yield int(selected_index)
    finally:
        if selected_fd >= 0:
            try:
                fcntl.flock(selected_fd, fcntl.LOCK_UN)
            finally:
                os.close(selected_fd)
        if selected_lock is not None:
            selected_lock.release()
        os.close(root_fd)


@contextmanager
def multipart_parse_slot(
    root,
    *,
    slots: int = DEFAULT_MULTIPART_PARSE_SLOTS,
    wait_seconds: float = DEFAULT_MULTIPART_SLOT_WAIT_SECONDS,
) -> Iterator[int]:
    """兼容入口：与 :func:`storage_mutation_capacity_slot` 共用同一槽。"""

    with storage_mutation_capacity_slot(
        root,
        slots=slots,
        wait_seconds=wait_seconds,
    ) as slot:
        yield slot


def _held_mutation_roots() -> set[str]:
    roots = getattr(_LOCK_STATE, "held_roots", None)
    if roots is None:
        roots = set()
        _LOCK_STATE.held_roots = roots
    return roots


def _require_mutation_lock(root: Path) -> None:
    if os.fspath(_absolute(root)) not in _held_mutation_roots():
        raise VibeHubStorageSecurityError(
            "VibeHub 上传暂存回收必须持有全局存储变更锁"
        )


def assert_storage_mutation_lock(root) -> Path:
    """确认当前线程持有指定根目录的全局存储变更锁。"""

    root_path = _absolute(root)
    _require_mutation_lock(root_path)
    return root_path


def _prepare_private_root(root) -> tuple[Path, int]:
    path = _absolute(root)
    if path == Path(path.anchor):
        raise VibeHubStorageSecurityError("VibeHub 存储根目录不能是文件系统根目录")
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        before = path.lstat()
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 存储根目录无法创建或读取") from exc
    if not stat.S_ISDIR(before.st_mode) or path.is_symlink():
        raise VibeHubStorageSecurityError("VibeHub 存储根目录必须是真实目录")
    try:
        fd = os.open(path, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 存储根目录无法安全打开") from exc
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise VibeHubStorageSecurityError("VibeHub 存储根目录类型或属主异常")
        os.fchmod(fd, 0o700)
        return path, fd
    except Exception:
        os.close(fd)
        raise


@contextmanager
def storage_mutation_lock(root) -> Iterator[Path]:
    """用全局 ``flock`` 串行化配额检查和快照变更。

    目录及锁文件每次都分别硬化为 ``0700`` 和 ``0600``。进程内锁
    避免不同线程依赖各平台对同进程 ``flock`` 的细节差异。
    """

    absolute = _absolute(root)
    with _thread_lock_for(absolute):
        path, root_fd = _prepare_private_root(absolute)
        lock_fd = -1
        try:
            try:
                lock_fd = os.open(
                    MUTATION_LOCK_FILENAME,
                    _LOCK_FLAGS,
                    0o600,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                raise VibeHubStorageSecurityError("VibeHub 存储锁无法安全打开") from exc
            info = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
            ):
                raise VibeHubStorageSecurityError("VibeHub 存储锁类型或属主异常")
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError as exc:
                raise VibeHubStorageSecurityError("VibeHub 存储锁无法获取") from exc
            current = path.lstat()
            opened = os.fstat(root_fd)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise VibeHubStorageSecurityError("VibeHub 存储根目录在锁定时发生了替换")
            held_roots = _held_mutation_roots()
            lock_key = os.fspath(path)
            held_roots.add(lock_key)
            try:
                yield path
            finally:
                held_roots.discard(lock_key)
        finally:
            if lock_fd >= 0:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(root_fd)


def _open_child_directory(parent_fd: int, name: str, *, root_device: int) -> int:
    try:
        child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 存储目录在扫描时发生了异常") from exc
    try:
        info = os.fstat(child_fd)
    except OSError as exc:
        os.close(child_fd)
        raise VibeHubStorageSecurityError("VibeHub 存储目录在扫描时无法确认") from exc
    if not stat.S_ISDIR(info.st_mode) or int(info.st_dev) != int(root_device):
        os.close(child_fd)
        raise VibeHubStorageSecurityError("VibeHub 存储不允许嵌套挂载或异常目录")
    return child_fd


def _scan_directory_fd(
    directory_fd: int,
    *,
    root_device: int,
    max_entries: int = MAX_SCAN_ENTRIES,
    max_depth: int = MAX_SCAN_DEPTH,
) -> int:
    """从已安全打开的目录逐级 no-follow 累加逻辑文件大小。"""

    entry_limit = _positive_integer(max_entries, label="VibeHub 扫描 entry 上限")
    depth_limit = _positive_integer(max_depth, label="VibeHub 扫描深度上限")
    total = 0
    entries = 0
    frames: list[list] = []

    def push(fd: int, depth: int, *, owns_fd: bool) -> None:
        try:
            iterator = os.scandir(fd)
        except OSError as exc:
            if owns_fd:
                os.close(fd)
            raise VibeHubStorageSecurityError("VibeHub 存储目录无法扫描") from exc
        frames.append([fd, iterator, depth, owns_fd])

    push(directory_fd, 0, owns_fd=False)
    try:
        while frames:
            parent_fd, iterator, depth, owns_fd = frames[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                frames.pop()
                iterator.close()
                if owns_fd:
                    os.close(parent_fd)
                continue
            try:
                info = os.stat(entry.name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                raise VibeHubStorageSecurityError("VibeHub 存储在扫描时发生了变化") from exc
            entries += 1
            if entries > entry_limit:
                raise VibeHubStorageSecurityError("VibeHub 存储目录项过多，无法安全统计")
            if int(info.st_dev) != int(root_device):
                raise VibeHubStorageSecurityError("VibeHub 存储不允许嵌套挂载")
            if stat.S_ISDIR(info.st_mode):
                if depth + 1 > depth_limit:
                    raise VibeHubStorageSecurityError("VibeHub 存储目录层级过深")
                child_fd = _open_child_directory(
                    parent_fd,
                    entry.name,
                    root_device=root_device,
                )
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    os.close(child_fd)
                    raise VibeHubStorageSecurityError("VibeHub 存储目录在扫描时被替换")
                push(child_fd, depth + 1, owns_fd=True)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise VibeHubStorageSecurityError("VibeHub 存储中出现了符号链接或特殊节点")
            size = int(info.st_size)
            if size < 0:
                raise VibeHubStorageSecurityError("VibeHub 存储文件大小异常")
            # 硬链接按目录入口重复计数，不让它成为逻辑配额的绕过方式。
            total += size
    finally:
        while frames:
            fd, iterator, _depth, owns_fd = frames.pop()
            iterator.close()
            if owns_fd:
                os.close(fd)
    return total


def logical_tree_bytes(path, *, max_entries=MAX_SCAN_ENTRIES, max_depth=MAX_SCAN_DEPTH) -> int:
    """安全统计一棵真实目录树的逻辑字节数。"""

    absolute = _absolute(path)
    try:
        before = absolute.lstat()
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 存储目录不存在或无法读取") from exc
    if not stat.S_ISDIR(before.st_mode) or absolute.is_symlink():
        raise VibeHubStorageSecurityError("VibeHub 存储扫描目标必须是真实目录")
    try:
        fd = os.open(absolute, _DIRECTORY_FLAGS)
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 存储目录无法安全打开") from exc
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise VibeHubStorageSecurityError("VibeHub 存储目录在扫描时被替换")
        return _scan_directory_fd(
            fd,
            root_device=int(opened.st_dev),
            max_entries=max_entries,
            max_depth=max_depth,
        )
    finally:
        os.close(fd)


def _open_descendant(root_fd: int, parts: tuple[str, ...], *, root_device: int) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in parts:
            if not part or part in {".", ".."} or "/" in part:
                raise VibeHubStorageSecurityError("VibeHub 存储子路径无效")
            next_fd = _open_child_directory(current_fd, part, root_device=root_device)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _ensure_owned_child_directory(
    parent_fd: int,
    name: str,
    *,
    root_device: int,
) -> int:
    """在已绑定父目录下创建或打开一个同设备、当前用户拥有的真实目录。"""

    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录无法创建") from exc
    child_fd = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        child_fd = _open_child_directory(parent_fd, name, root_device=root_device)
        opened = os.fstat(child_fd)
    except Exception:
        if child_fd >= 0:
            os.close(child_fd)
        raise
    if (
        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or int(opened.st_uid) != int(os.geteuid())
    ):
        os.close(child_fd)
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录类型或属主异常")
    try:
        os.fchmod(child_fd, 0o700)
    except OSError as exc:
        os.close(child_fd)
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录权限无法收紧") from exc
    return child_fd


def create_upload_staging_directory(root) -> Path:
    """原子创建严格命名的受管上传暂存根目录。

    Web 业务会在 :func:`storage_mutation_lock` 内调用；目录创建本身仍使用
    ``dir_fd``、``O_NOFOLLOW`` 和 inode 复核，便于存储校验单测独立使用。
    """

    root_path, root_fd = _prepare_private_root(root)
    staging_fd = -1
    try:
        root_info = os.fstat(root_fd)
        root_device = int(root_info.st_dev)
        staging_fd = _ensure_owned_child_directory(
            root_fd,
            ".staging",
            root_device=root_device,
        )
        for _attempt in range(16):
            name = f"upload-{uuid.uuid4().hex}"
            try:
                os.mkdir(name, 0o700, dir_fd=staging_fd)
            except FileExistsError:
                continue
            except OSError as exc:
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存会话无法创建"
                ) from exc
            child_fd = -1
            try:
                child_fd = _open_child_directory(
                    staging_fd,
                    name,
                    root_device=root_device,
                )
                info = os.fstat(child_fd)
                if int(info.st_uid) != int(os.geteuid()):
                    raise VibeHubStorageSecurityError(
                        "VibeHub 上传暂存会话属主异常"
                    )
                os.fchmod(child_fd, 0o700)
            except Exception:
                if child_fd >= 0:
                    os.close(child_fd)
                try:
                    os.rmdir(name, dir_fd=staging_fd)
                except OSError:
                    pass
                raise
            else:
                os.close(child_fd)
                return root_path / ".staging" / name
        raise VibeHubStorageSecurityError("VibeHub 上传暂存会话标识冲突")
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        os.close(root_fd)


def _staged_snapshot_name(root_path: Path, staged_path) -> str:
    candidate = _absolute(staged_path)
    try:
        relative = candidate.relative_to(root_path)
    except ValueError as exc:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录越出存储根目录") from exc
    parts = relative.parts
    if (
        len(parts) != 3
        or parts[0] != ".staging"
        or not _UPLOAD_STAGING_RE.fullmatch(parts[1])
        or parts[2] != "snapshot"
    ):
        raise VibeHubStorageSecurityError(
            "staged_incoming_path 必须是 VibeHub 受管 .staging 上传快照"
        )
    return parts[1]


def _secure_clear_directory_fd(
    directory_fd: int,
    *,
    root_device: int,
    depth: int = 0,
) -> None:
    """仅删除已安全打开目录内同设备的真实目录和普通文件。"""

    if depth > MAX_SCAN_DEPTH:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录层级过深")
    try:
        entries = list(os.scandir(directory_fd))
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录无法扫描") from exc
    if len(entries) > MAX_SCAN_ENTRIES:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存目录项过多")
    for entry in entries:
        try:
            before = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise VibeHubStorageSecurityError(
                "VibeHub 上传暂存入口在回收时发生了变化"
            ) from exc
        if int(before.st_dev) != int(root_device):
            raise VibeHubStorageSecurityError("VibeHub 上传暂存不允许嵌套挂载")
        if stat.S_ISREG(before.st_mode):
            try:
                os.unlink(entry.name, dir_fd=directory_fd)
            except OSError as exc:
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存普通文件无法回收"
                ) from exc
            continue
        if not stat.S_ISDIR(before.st_mode):
            raise VibeHubStorageSecurityError(
                "VibeHub 上传暂存中出现了符号链接或特殊节点"
            )
        child_fd = _open_child_directory(
            directory_fd,
            entry.name,
            root_device=root_device,
        )
        try:
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存目录在回收时被替换"
                )
            _secure_clear_directory_fd(
                child_fd,
                root_device=root_device,
                depth=depth + 1,
            )
        finally:
            os.close(child_fd)
        try:
            current = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存目录在回收完成前被替换"
                )
            os.rmdir(entry.name, dir_fd=directory_fd)
        except VibeHubStorageSecurityError:
            raise
        except OSError as exc:
            raise VibeHubStorageSecurityError(
                "VibeHub 上传暂存目录无法回收"
            ) from exc


def _reclaim_expired_upload_staging_fd(
    root_path: Path,
    root_fd: int,
    *,
    active_staging_paths: Iterable = (),
    grace_seconds: int = DEFAULT_UPLOAD_STAGING_GRACE_SECONDS,
    now: float | None = None,
) -> UploadStagingReclaimResult:
    grace = _positive_integer(grace_seconds, label="VibeHub 上传暂存回收宽限")
    try:
        current_time = time.time() if now is None else float(now)
    except (TypeError, ValueError, OverflowError) as exc:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存回收时间无效") from exc
    if current_time < 0 or not math.isfinite(current_time):
        raise VibeHubStorageSecurityError("VibeHub 上传暂存回收时间无效")
    try:
        active_names = {
            _staged_snapshot_name(root_path, candidate)
            for candidate in active_staging_paths
        }
    except TypeError as exc:
        raise VibeHubStorageSecurityError("VibeHub 活跃上传暂存列表无效") from exc

    root_info = os.fstat(root_fd)
    root_device = int(root_info.st_dev)
    try:
        staging_before = os.stat(
            ".staging",
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        if active_names:
            raise VibeHubStorageSecurityError("VibeHub 活跃上传暂存目录不存在")
        return UploadStagingReclaimResult((), (), (), 0)
    except OSError as exc:
        raise VibeHubStorageSecurityError("VibeHub 上传暂存根无法读取") from exc
    if (
        not stat.S_ISDIR(staging_before.st_mode)
        or int(staging_before.st_dev) != root_device
        or int(staging_before.st_uid) != int(os.geteuid())
    ):
        raise VibeHubStorageSecurityError(
            "VibeHub 上传暂存根必须是同设备、当前用户拥有的真实目录"
        )
    staging_fd = _open_child_directory(root_fd, ".staging", root_device=root_device)
    try:
        staging_opened = os.fstat(staging_fd)
        if (staging_opened.st_dev, staging_opened.st_ino) != (
            staging_before.st_dev,
            staging_before.st_ino,
        ):
            raise VibeHubStorageSecurityError("VibeHub 上传暂存根在审计时被替换")
        try:
            os.fchmod(staging_fd, 0o700)
        except OSError as exc:
            raise VibeHubStorageSecurityError("VibeHub 上传暂存根权限无法收紧") from exc
        try:
            entries = list(os.scandir(staging_fd))
        except OSError as exc:
            raise VibeHubStorageSecurityError("VibeHub 上传暂存根无法扫描") from exc
        if len(entries) > MAX_SCAN_ENTRIES:
            raise VibeHubStorageSecurityError("VibeHub 上传暂存会话过多")

        # 先完整审计，再删除。这样未知入口或异常节点不会造成半清理状态。
        audited: list[tuple[str, os.stat_result, int]] = []
        for entry in entries:
            if not _UPLOAD_STAGING_RE.fullmatch(entry.name):
                raise VibeHubStorageSecurityError(
                    "VibeHub .staging 包含未知入口"
                )
            try:
                before = os.stat(entry.name, dir_fd=staging_fd, follow_symlinks=False)
            except OSError as exc:
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存会话无法读取"
                ) from exc
            if (
                not stat.S_ISDIR(before.st_mode)
                or int(before.st_dev) != root_device
                or int(before.st_uid) != int(os.geteuid())
            ):
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存会话必须是同设备、当前用户拥有的真实目录"
                )
            child_fd = _open_child_directory(
                staging_fd,
                entry.name,
                root_device=root_device,
            )
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise VibeHubStorageSecurityError(
                        "VibeHub 上传暂存会话在审计时被替换"
                    )
                logical_bytes = _scan_directory_fd(
                    child_fd,
                    root_device=root_device,
                )
            finally:
                os.close(child_fd)
            audited.append((entry.name, before, logical_bytes))

        missing_active = active_names.difference(name for name, _info, _size in audited)
        if missing_active:
            raise VibeHubStorageSecurityError("VibeHub 活跃上传暂存会话不存在")

        cutoff = current_time - grace
        expired = [
            (name, info, logical_bytes)
            for name, info, logical_bytes in audited
            if name not in active_names and float(info.st_mtime) <= cutoff
        ]
        deleted: list[str] = []
        reclaimed_bytes = 0
        for name, before, logical_bytes in expired:
            child_fd = _open_child_directory(
                staging_fd,
                name,
                root_device=root_device,
            )
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise VibeHubStorageSecurityError(
                        "VibeHub 上传暂存会话在回收时被替换"
                    )
                _secure_clear_directory_fd(child_fd, root_device=root_device)
            finally:
                os.close(child_fd)
            try:
                current = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    raise VibeHubStorageSecurityError(
                        "VibeHub 上传暂存会话在回收完成前被替换"
                    )
                os.rmdir(name, dir_fd=staging_fd)
            except VibeHubStorageSecurityError:
                raise
            except OSError as exc:
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存会话无法回收"
                ) from exc
            deleted.append(name)
            reclaimed_bytes += logical_bytes

        result = UploadStagingReclaimResult(
            inspected=tuple(sorted(name for name, _info, _size in audited)),
            active=tuple(sorted(active_names)),
            deleted_expired=tuple(sorted(deleted)),
            reclaimed_bytes=reclaimed_bytes,
        )
        if result.deleted_expired:
            _LOGGER.info(
                "VibeHub 已回收过期上传暂存：sessions=%s bytes=%d grace_seconds=%d",
                ",".join(result.deleted_expired),
                result.reclaimed_bytes,
                grace,
            )
        return result
    finally:
        os.close(staging_fd)


def reclaim_expired_upload_staging(
    root,
    *,
    active_staging_paths: Iterable = (),
    grace_seconds: int = DEFAULT_UPLOAD_STAGING_GRACE_SECONDS,
    now: float | None = None,
) -> UploadStagingReclaimResult:
    """审计并回收超过宽限期的受管上传暂存。

    调用方必须持有同一根目录的 :func:`storage_mutation_lock`。严格命名之外
    的入口、符号链接、特殊节点、嵌套挂载或属主漂移都会停止回收；活跃上传
    通过其精确 ``snapshot`` 路径排除，即使它已超过宽限也不会被误删。
    """

    root_path = _absolute(root)
    _require_mutation_lock(root_path)
    opened_path, root_fd = _prepare_private_root(root_path)
    try:
        return _reclaim_expired_upload_staging_fd(
            opened_path,
            root_fd,
            active_staging_paths=active_staging_paths,
            grace_seconds=grace_seconds,
            now=now,
        )
    finally:
        os.close(root_fd)


def remove_managed_directory(
    root,
    target,
    *,
    expected_device: int,
    expected_inode: int,
    expected_ctime_ns: int | None = None,
) -> int:
    """按已审计 inode 精确删除存储根内的一棵真实目录树。

    该原语只能在 :func:`storage_mutation_lock` 内使用。路径的每一级均通过
    ``dir_fd`` 和 ``O_NOFOLLOW`` 打开；目标必须仍与调用方记录的设备号、
    inode 完全一致；调用方提供 ``expected_ctime_ns`` 时还会拒绝 inode
    被文件系统快速复用后的同路径新目录。返回删除前安全扫描得到的逻辑字节数。
    """

    root_path = assert_storage_mutation_lock(root)
    target_path = _absolute(target)
    try:
        relative = target_path.relative_to(root_path)
    except ValueError as exc:
        raise VibeHubStorageSecurityError("VibeHub 待删除目录越出存储根目录") from exc
    parts = relative.parts
    if not parts or any(
        not part or part in {".", ".."} or "/" in part for part in parts
    ):
        raise VibeHubStorageSecurityError("VibeHub 待删除目录路径无效")
    device = _nonnegative_integer(expected_device, label="VibeHub 待删除目录设备号")
    inode = _positive_integer(expected_inode, label="VibeHub 待删除目录 inode")
    ctime_ns = None
    if expected_ctime_ns is not None:
        ctime_ns = _nonnegative_integer(
            expected_ctime_ns,
            label="VibeHub 待删除目录 ctime_ns",
        )

    opened_root, root_fd = _prepare_private_root(root_path)
    parent_fd = -1
    child_fd = -1
    try:
        if opened_root != root_path:
            raise VibeHubStorageSecurityError("VibeHub 存储根目录解析不一致")
        root_device = int(os.fstat(root_fd).st_dev)
        if device != root_device:
            raise VibeHubStorageSecurityError("VibeHub 待删除目录不在存储根设备上")
        parent_fd = _open_descendant(
            root_fd,
            tuple(parts[:-1]),
            root_device=root_device,
        )
        leaf = parts[-1]
        try:
            before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise VibeHubStorageSecurityError("VibeHub 待删除目录无法读取") from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or int(before.st_dev) != device
            or int(before.st_ino) != inode
            or (ctime_ns is not None and int(before.st_ctime_ns) != ctime_ns)
        ):
            raise VibeHubStorageSecurityError("VibeHub 待删除目录身份已变化")
        child_fd = _open_child_directory(
            parent_fd,
            leaf,
            root_device=root_device,
        )
        opened = os.fstat(child_fd)
        if (
            (int(opened.st_dev), int(opened.st_ino)) != (device, inode)
            or (ctime_ns is not None and int(opened.st_ctime_ns) != ctime_ns)
        ):
            raise VibeHubStorageSecurityError("VibeHub 待删除目录打开后身份不一致")
        logical_bytes = _scan_directory_fd(child_fd, root_device=root_device)
        _secure_clear_directory_fd(child_fd, root_device=root_device)
        os.close(child_fd)
        child_fd = -1
        try:
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (int(current.st_dev), int(current.st_ino)) != (device, inode):
                raise VibeHubStorageSecurityError("VibeHub 待删除目录在删除前被替换")
            os.rmdir(leaf, dir_fd=parent_fd)
        except VibeHubStorageSecurityError:
            raise
        except OSError as exc:
            raise VibeHubStorageSecurityError("VibeHub 待删除目录无法移除") from exc
        return logical_bytes
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def _project_snapshots_bytes(root_fd: int, root_device: int, slug: str) -> int:
    try:
        project_fd = _open_child_directory(root_fd, slug, root_device=root_device)
    except VibeHubStorageSecurityError as exc:
        # 数据库中可以存在还没有成功安装第一个快照的项目。
        try:
            os.stat(slug, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return 0
        raise exc
    try:
        try:
            versions_fd = _open_child_directory(
                project_fd,
                "versions",
                root_device=root_device,
            )
        except VibeHubStorageSecurityError as exc:
            try:
                os.stat("versions", dir_fd=project_fd, follow_symlinks=False)
            except FileNotFoundError:
                return 0
            raise exc
        try:
            return _scan_directory_fd(versions_fd, root_device=root_device)
        finally:
            os.close(versions_fd)
    finally:
        os.close(project_fd)


def project_snapshots_logical_bytes(root, slug) -> int:
    """返回单个作品 ``versions/`` 下全部快照的逻辑大小。"""

    safe_slug = _safe_slug(slug)
    _path, root_fd = _prepare_private_root(root)
    try:
        info = os.fstat(root_fd)
        return _project_snapshots_bytes(root_fd, int(info.st_dev), safe_slug)
    finally:
        os.close(root_fd)


def enforce_storage_quota(
    existing_user_slugs: Iterable[str],
    incoming_bytes: int,
    root,
    *,
    staged_incoming_path=None,
    retirement_project_states=None,
    user_limit_bytes: int = DEFAULT_USER_STORAGE_BYTES,
) -> StorageQuotaProjection:
    """校验本次新增快照的单用户配额。

    ``incoming_bytes`` 总是计入当前用户投影。已由上传流写入
    ``root/.staging`` 时，必须把该目录作为 ``staged_incoming_path``
    传入，函数会安全重算且要求其等于 ``incoming_bytes``。进入配额
    扫描前仍会审计受管 ``.staging`` 并回收超过一小时的崩溃孤儿，
    其它用户或会话的暂存数据不计入当前用户用量。

    业务层应把已用 ``FOR UPDATE`` 锁定的当前用户作品 DB 快照事实作为
    ``retirement_project_states`` 传入。函数会在正式配额扫描前先完整审计
    存储树，再按版本号、设备号、inode 和 live-set 回收过期退役快照。

    调用方应在 :func:`storage_mutation_lock` 内调用本函数，并把锁
    保持到快照原子安装或克隆完成。
    """

    incoming = _nonnegative_integer(incoming_bytes, label="VibeHub 新增字节数")
    user_limit = _positive_integer(user_limit_bytes, label="VibeHub 单用户存储上限")
    try:
        slugs = tuple(dict.fromkeys(_safe_slug(value) for value in existing_user_slugs))
    except TypeError as exc:
        raise VibeHubStorageSecurityError("VibeHub 用户作品列表无效") from exc

    root_path = _absolute(root)
    _require_mutation_lock(root_path)
    root_path, root_fd = _prepare_private_root(root_path)
    try:
        root_info = os.fstat(root_fd)
        root_device = int(root_info.st_dev)
        already_staged = staged_incoming_path is not None
        active_staging_paths = ()
        if already_staged:
            staging_name = _staged_snapshot_name(root_path, staged_incoming_path)
            parts = (".staging", staging_name, "snapshot")
            active_staging_paths = (staged_incoming_path,)

        # 崩溃遗留的完整上传会话在用户配额扫描前老化回收；当前请求的
        # 精确 snapshot 始终作为活跃项排除。
        _reclaim_expired_upload_staging_fd(
            root_path,
            root_fd,
            active_staging_paths=active_staging_paths,
        )

        if retirement_project_states is not None:
            # 局部导入避免 quotas 与负责 marker 协议的 storage 形成初始化环。
            from backend.oj_modules.vibehub import storage

            storage.reclaim_expired_retired_snapshots(
                retirement_project_states,
                upload_root=root_path,
            )

        user_existing = sum(
            _project_snapshots_bytes(root_fd, root_device, slug) for slug in slugs
        )

        if already_staged:
            staged_fd = _open_descendant(root_fd, parts, root_device=root_device)
            try:
                staged_bytes = _scan_directory_fd(staged_fd, root_device=root_device)
            finally:
                os.close(staged_fd)
            if staged_bytes != incoming:
                raise VibeHubStorageSecurityError(
                    "VibeHub 上传暂存用量与 incoming_bytes 不一致"
                )

        user_projected = user_existing + incoming
        if user_projected > user_limit:
            raise VibeHubStorageQuotaExceeded(
                scope="user",
                current_bytes=user_existing,
                incoming_bytes=incoming,
                projected_bytes=user_projected,
                limit_bytes=user_limit,
            )
        return StorageQuotaProjection(
            user_existing_bytes=user_existing,
            incoming_bytes=incoming,
            user_projected_bytes=user_projected,
            incoming_already_staged=already_staged,
        )
    finally:
        os.close(root_fd)


def _enforce_count(
    *,
    resource: str,
    current: int,
    incoming: int,
    limit: int,
) -> int:
    safe_current = _nonnegative_integer(current, label="VibeHub 当前数量")
    safe_incoming = _nonnegative_integer(incoming, label="VibeHub 新增数量")
    safe_limit = _positive_integer(limit, label="VibeHub 数量上限")
    projected = safe_current + safe_incoming
    if projected > safe_limit:
        raise VibeHubCountQuotaExceeded(
            resource=resource,
            current=safe_current,
            incoming=safe_incoming,
            projected=projected,
            limit=safe_limit,
        )
    return projected


def enforce_project_count(
    existing_projects: int,
    incoming_projects: int = 1,
    *,
    limit: int = DEFAULT_PROJECTS_PER_USER,
) -> int:
    """返回投影项目数；普通用户超过默认 2 个计数作品时抛出 409。"""

    return _enforce_count(
        resource="projects",
        current=existing_projects,
        incoming=incoming_projects,
        limit=limit,
    )


def enforce_version_count(
    existing_versions: int,
    incoming_versions: int = 1,
    *,
    limit: int = DEFAULT_VERSIONS_PER_PROJECT,
) -> int:
    """返回投影版本数；超过默认每作品 1000 个时抛出 409 错误。"""

    return _enforce_count(
        resource="versions",
        current=existing_versions,
        incoming=incoming_versions,
        limit=limit,
    )


__all__ = [
    "DEFAULT_MULTIPART_PARSE_SLOTS",
    "DEFAULT_MULTIPART_SLOT_WAIT_SECONDS",
    "DEFAULT_STORAGE_MUTATION_SLOTS",
    "DEFAULT_STORAGE_MUTATION_SLOT_WAIT_SECONDS",
    "DEFAULT_PROJECTS_PER_USER",
    "DEFAULT_UPLOAD_STAGING_GRACE_SECONDS",
    "DEFAULT_USER_STORAGE_BYTES",
    "DEFAULT_VERSIONS_PER_PROJECT",
    "MAX_MULTIPART_PARSE_SLOTS",
    "MAX_MULTIPART_SLOT_WAIT_SECONDS",
    "MAX_STORAGE_MUTATION_SLOTS",
    "MAX_STORAGE_MUTATION_SLOT_WAIT_SECONDS",
    "MULTIPART_SLOT_FILENAME_TEMPLATE",
    "MUTATION_LOCK_FILENAME",
    "STORAGE_MUTATION_SLOT_FILENAME_TEMPLATE",
    "StorageQuotaProjection",
    "UploadStagingReclaimResult",
    "VibeHubCountQuotaExceeded",
    "VibeHubMultipartCapacityExceeded",
    "VibeHubQuotaPolicyError",
    "VibeHubStorageQuotaExceeded",
    "VibeHubStorageMutationCapacityExceeded",
    "VibeHubStorageSecurityError",
    "assert_storage_mutation_lock",
    "create_upload_staging_directory",
    "enforce_project_count",
    "enforce_storage_quota",
    "enforce_version_count",
    "logical_tree_bytes",
    "multipart_parse_slot",
    "project_snapshots_logical_bytes",
    "reclaim_expired_upload_staging",
    "remove_managed_directory",
    "storage_mutation_lock",
    "storage_mutation_capacity_slot",
]
