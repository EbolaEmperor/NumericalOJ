"""通用 Agent 原生运行态的私有、不可变 checkpoint。

checkpoint 位于会话目录内、容器只挂载的 ``workspace/`` 之外。
``workspace/.runtime`` 中的目录、文件和链接按原样复制；socket、FIFO 与设备节点
属于瞬时运行态，不写入 checkpoint。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
import stat
import uuid

from backend.oj_modules.agents import workspace as workspace_store


_CHECKPOINTS_DIRECTORY = "runtime-checkpoints"
_CHECKPOINT_STAGING_DIRECTORY = ".runtime-checkpoint-staging"
_CHECKPOINT_LOCK_FILENAME = ".runtime-checkpoints.lock"
_CHECKPOINT_RUNTIME_DIRECTORY = "runtime"
_CHECKPOINT_MANIFEST_FILENAME = "manifest.json"
_CHECKPOINT_MANIFEST_VERSION = 1
_MAX_MANIFEST_BYTES = 16 * 1024
_COPY_CHUNK_BYTES = 64 * 1024


@dataclass(slots=True)
class _UsageCounter:
    max_bytes: int
    total_bytes: int = 0
    file_count: int = 0
    entry_count: int = 0

    def add_entry(self, *, size: int = 0, regular: bool = False) -> None:
        self.entry_count += 1
        self.total_bytes += max(0, int(size))
        if self.total_bytes > self.max_bytes:
            raise workspace_store.AgentWorkspaceQuotaError(
                f"Agent runtime checkpoint 总大小不能超过 {self.max_bytes} 字节"
            )
        if regular:
            self.file_count += 1

    def usage(self) -> workspace_store.AgentWorkspaceUsage:
        return workspace_store.AgentWorkspaceUsage(
            total_bytes=self.total_bytes,
            file_count=self.file_count,
            entry_count=self.entry_count,
        )


def _limit() -> int:
    return workspace_store._quota_limit()


def _safe_mode(info, *, directory: bool) -> int:
    mode = stat.S_IMODE(info.st_mode)
    if directory:
        # 受管目录始终可由服务用户遍历、恢复和清理；剥离 group/other 写位。
        return 0o700 | (mode & 0o055)
    return 0o600 | (mode & 0o155)


def _new_counter() -> _UsageCounter:
    return _UsageCounter(_limit())


def _scan_tree_fd(root_fd: int) -> tuple[workspace_store.AgentWorkspaceUsage, int]:
    root_before = os.fstat(root_fd)
    if not stat.S_ISDIR(root_before.st_mode):
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 根必须是真实目录"
        )
    counter = _new_counter()
    counted_inodes: set[tuple[int, int]] = set()

    def walk(directory_fd: int) -> None:
        try:
            raw_names = os.listdir(directory_fd)
        except OSError as exc:
            raise workspace_store.AgentWorkspaceSecurityError(
                "无法安全扫描 Agent runtime"
            ) from exc
        for raw_name in raw_names:
            name = raw_name
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(before.st_mode):
                counter.add_entry()
                try:
                    child_fd = workspace_store._open_existing_directory_at(
                        directory_fd,
                        name,
                        label="Agent runtime 子目录",
                    )
                except OSError:
                    continue
                try:
                    walk(child_fd)
                finally:
                    os.close(child_fd)
                continue
            if stat.S_ISREG(before.st_mode):
                inode_key = (int(before.st_dev), int(before.st_ino))
                counter.add_entry(
                    size=(0 if inode_key in counted_inodes else int(before.st_size)),
                    regular=True,
                )
                counted_inodes.add(inode_key)
                continue
            if stat.S_ISLNK(before.st_mode):
                counter.add_entry(size=int(before.st_size))
                continue
            # socket、FIFO、设备节点等瞬时运行期入口不参与 checkpoint，
            # 也不会成为拒绝继续会话的理由。
            continue

    walk(root_fd)
    return counter.usage(), _safe_mode(root_before, directory=True)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise workspace_store.AgentWorkspaceError(
                "写入 Agent runtime checkpoint 未取得进展"
            )
        view = view[written:]


def _copy_regular_file(
    source_directory_fd: int,
    destination_directory_fd: int,
    name: str,
    *,
    max_bytes: int,
) -> int | None:
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_fd = os.open(name, source_flags, dir_fd=source_directory_fd)
    except OSError:
        return None
    destination_fd = -1
    destination_created = False
    completed = False
    try:
        opened = os.fstat(source_fd)
        if not stat.S_ISREG(opened.st_mode):
            return None
        try:
            destination_fd = os.open(
                name,
                destination_flags,
                0o600,
                dir_fd=destination_directory_fd,
            )
        except OSError as exc:
            raise workspace_store.AgentWorkspaceError(
                "无法创建 Agent runtime checkpoint 文件"
            ) from exc
        destination_created = True
        copied = 0
        while True:
            try:
                payload = os.read(source_fd, _COPY_CHUNK_BYTES)
            except OSError:
                return None
            if not payload:
                break
            copied += len(payload)
            if copied > max_bytes:
                raise workspace_store.AgentWorkspaceQuotaError(
                    f"Agent runtime checkpoint 总大小不能超过 {_limit()} 字节"
                )
            _write_all(destination_fd, payload)
        os.fchmod(destination_fd, _safe_mode(opened, directory=False))
        os.fsync(destination_fd)
        completed = True
        return copied
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)
        if destination_created and not completed:
            try:
                os.unlink(name, dir_fd=destination_directory_fd)
            except OSError:
                pass


def _copy_tree_fd(
    source_root_fd: int,
    destination_root_fd: int,
) -> workspace_store.AgentWorkspaceUsage:
    source_root_before = os.fstat(source_root_fd)
    if not stat.S_ISDIR(source_root_before.st_mode):
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 源必须是真实目录"
        )
    counter = _new_counter()
    copied_inodes: dict[tuple[int, int], tuple[str, ...]] = {}

    def copy_directory(
        source_fd: int,
        destination_fd: int,
        parent_parts: tuple[str, ...],
    ) -> None:
        try:
            raw_names = os.listdir(source_fd)
        except OSError:
            return
        for raw_name in raw_names:
            name = raw_name
            try:
                before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(before.st_mode):
                try:
                    source_child_fd = workspace_store._open_existing_directory_at(
                        source_fd,
                        name,
                        label="Agent runtime checkpoint 源子目录",
                    )
                except OSError:
                    continue
                try:
                    os.mkdir(name, mode=0o700, dir_fd=destination_fd)
                    destination_child_fd = workspace_store._open_existing_directory_at(
                        destination_fd,
                        name,
                        label="Agent runtime checkpoint 目标子目录",
                    )
                except OSError as exc:
                    os.close(source_child_fd)
                    raise workspace_store.AgentWorkspaceError(
                        "无法创建 Agent runtime checkpoint 子目录"
                    ) from exc
                counter.add_entry()
                try:
                    opened = os.fstat(source_child_fd)
                    copy_directory(
                        source_child_fd,
                        destination_child_fd,
                        (*parent_parts, name),
                    )
                    os.fchmod(
                        destination_child_fd,
                        _safe_mode(opened, directory=True),
                    )
                    os.fsync(destination_child_fd)
                finally:
                    os.close(destination_child_fd)
                    os.close(source_child_fd)
                continue
            if stat.S_ISREG(before.st_mode):
                inode_key = (int(before.st_dev), int(before.st_ino))
                current_parts = (*parent_parts, name)
                first_parts = copied_inodes.get(inode_key)
                copied_size = int(before.st_size)
                if first_parts is None:
                    copied_size = _copy_regular_file(
                        source_fd,
                        destination_fd,
                        name,
                        max_bytes=counter.max_bytes - counter.total_bytes,
                    )
                    if copied_size is None:
                        continue
                    copied_inodes[inode_key] = current_parts
                else:
                    try:
                        os.link(
                            "/".join(first_parts),
                            "/".join(current_parts),
                            src_dir_fd=destination_root_fd,
                            dst_dir_fd=destination_root_fd,
                            follow_symlinks=False,
                        )
                        copied_size = 0
                    except OSError:
                        # 目标文件系统不支持硬链接时退化为普通复制，不影响续聊。
                        copied_size = _copy_regular_file(
                            source_fd,
                            destination_fd,
                            name,
                            max_bytes=counter.max_bytes - counter.total_bytes,
                        )
                        if copied_size is None:
                            continue
                counter.add_entry(
                    size=copied_size,
                    regular=True,
                )
                continue
            if stat.S_ISLNK(before.st_mode):
                try:
                    target = os.readlink(name, dir_fd=source_fd)
                except OSError:
                    continue
                counter.add_entry(size=int(before.st_size))
                try:
                    os.symlink(target, name, dir_fd=destination_fd)
                except OSError as exc:
                    raise workspace_store.AgentWorkspaceError(
                        "无法创建 Agent runtime checkpoint 符号链接"
                    ) from exc
                continue
            continue
        os.fsync(destination_fd)

    copy_directory(source_root_fd, destination_root_fd, ())
    os.fchmod(destination_root_fd, _safe_mode(source_root_before, directory=True))
    os.fsync(destination_root_fd)
    return counter.usage()


def _usage_document(usage: workspace_store.AgentWorkspaceUsage) -> dict:
    return {
        "bytes": int(usage.total_bytes),
        "files": int(usage.file_count),
        "entries": int(usage.entry_count),
    }


def _write_manifest(checkpoint_fd: int, usage) -> None:
    payload = json.dumps(
        {
            "version": _CHECKPOINT_MANIFEST_VERSION,
            "usage": _usage_document(usage),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(
            _CHECKPOINT_MANIFEST_FILENAME,
            flags,
            0o600,
            dir_fd=checkpoint_fd,
        )
    except OSError as exc:
        raise workspace_store.AgentWorkspaceError(
            "无法创建 Agent runtime checkpoint 清单"
        ) from exc
    try:
        _write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_manifest(checkpoint_fd: int) -> workspace_store.AgentWorkspaceUsage:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(_CHECKPOINT_MANIFEST_FILENAME, flags, dir_fd=checkpoint_fd)
    except OSError as exc:
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 清单缺失或不安全"
        ) from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_size) > _MAX_MANIFEST_BYTES
        ):
            raise workspace_store.AgentWorkspaceSecurityError(
                "Agent runtime checkpoint 清单属性无效"
            )
        payload = bytearray()
        while len(payload) <= _MAX_MANIFEST_BYTES:
            chunk = os.read(fd, min(4096, _MAX_MANIFEST_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > _MAX_MANIFEST_BYTES:
            raise workspace_store.AgentWorkspaceSecurityError(
                "Agent runtime checkpoint 清单过大"
            )
    finally:
        os.close(fd)
    try:
        document = json.loads(payload.decode("utf-8", "strict"))
        usage = document["usage"]
        raw_values = tuple(usage[key] for key in ("bytes", "files", "entries"))
    except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 清单格式无效"
        ) from exc
    if (
        not isinstance(document, dict)
        or document.get("version") != _CHECKPOINT_MANIFEST_VERSION
        or not isinstance(usage, dict)
        or any(isinstance(value, bool) or not isinstance(value, int) for value in raw_values)
        or any(value < 0 for value in raw_values)
    ):
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 清单格式无效"
        )
    return workspace_store.AgentWorkspaceUsage(
        total_bytes=raw_values[0],
        file_count=raw_values[1],
        entry_count=raw_values[2],
    )


def _remove_tree_contents_fd(
    directory_fd: int,
) -> None:
    for raw_name in os.listdir(directory_fd):
        name = raw_name
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child_fd = workspace_store._open_existing_directory_at(
                directory_fd,
                name,
                label="Agent runtime checkpoint 清理目录",
            )
            try:
                os.fchmod(child_fd, 0o700)
                _remove_tree_contents_fd(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
            continue
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _remove_directory_at(parent_fd: int, name: str) -> None:
    directory_fd = workspace_store._open_existing_directory_at(
        parent_fd,
        name,
        label="Agent runtime checkpoint 清理目标",
    )
    try:
        os.fchmod(directory_fd, 0o700)
        _remove_tree_contents_fd(directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _remove_entry_at(parent_fd: int, name: str) -> None:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
        _remove_directory_at(parent_fd, name)
        return
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


@contextmanager
def _checkpoint_lock(session_fd: int):
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(_CHECKPOINT_LOCK_FILENAME, flags, 0o600, dir_fd=session_fd)
    except OSError as exc:
        raise workspace_store.AgentWorkspaceSecurityError(
            "无法安全打开 Agent runtime checkpoint 锁"
        ) from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_uid) != os.geteuid()
        ):
            raise workspace_store.AgentWorkspaceSecurityError(
                "Agent runtime checkpoint 锁属性无效"
            )
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _checkpoint_exists(checkpoints_fd: int, checkpoint_id: str) -> bool:
    try:
        info = os.stat(
            checkpoint_id,
            dir_fd=checkpoints_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise workspace_store.AgentWorkspaceSecurityError(
            "无法安全检查 Agent runtime checkpoint"
        ) from exc
    if not stat.S_ISDIR(info.st_mode):
        raise workspace_store.AgentWorkspaceSecurityError(
            "Agent runtime checkpoint 名称已被非目录占用"
        )
    return True


def _create_checkpoint(
    session_id,
    checkpoint_id,
    *,
    empty: bool,
) -> workspace_store.AgentWorkspaceUsage:
    safe_checkpoint_id = workspace_store._normalize_identifier(
        checkpoint_id,
        label="Agent runtime checkpoint_id",
    )
    with workspace_store._open_session_directories(session_id) as (
        _safe_session_id,
        session_fd,
        workspace_fd,
    ):
        with _checkpoint_lock(session_fd):
            checkpoints_fd = workspace_store._open_managed_child_directory(
                session_fd,
                _CHECKPOINTS_DIRECTORY,
                label="Agent runtime checkpoints 目录",
            )
            staging_fd = workspace_store._open_managed_child_directory(
                session_fd,
                _CHECKPOINT_STAGING_DIRECTORY,
                label="Agent runtime checkpoint 暂存目录",
            )
            source_runtime_fd = None
            stage_fd = None
            stage_runtime_fd = None
            stage_name = f"checkpoint-{uuid.uuid4().hex}"
            reservation_created = False
            published = False
            try:
                if _checkpoint_exists(checkpoints_fd, safe_checkpoint_id):
                    raise workspace_store.AgentWorkspaceError(
                        "Agent runtime checkpoint 已存在，拒绝覆盖"
                    )
                if not empty:
                    try:
                        source_runtime_fd = workspace_store._open_existing_directory_at(
                            workspace_fd,
                            ".runtime",
                            label="Agent runtime 目录",
                        )
                    except OSError:
                        source_runtime_fd = None
                os.mkdir(stage_name, mode=0o700, dir_fd=staging_fd)
                stage_fd = workspace_store._open_existing_directory_at(
                    staging_fd,
                    stage_name,
                    label="Agent runtime checkpoint 单次暂存目录",
                )
                os.mkdir(
                    _CHECKPOINT_RUNTIME_DIRECTORY,
                    mode=0o700,
                    dir_fd=stage_fd,
                )
                stage_runtime_fd = workspace_store._open_existing_directory_at(
                    stage_fd,
                    _CHECKPOINT_RUNTIME_DIRECTORY,
                    label="Agent runtime checkpoint 暂存内容目录",
                )
                copied_usage = (
                    workspace_store.AgentWorkspaceUsage(0, 0, 0)
                    if empty or source_runtime_fd is None
                    else _copy_tree_fd(source_runtime_fd, stage_runtime_fd)
                )
                os.fsync(stage_runtime_fd)
                _write_manifest(stage_fd, copied_usage)
                os.fsync(stage_fd)

                # 先以 mkdir 原子占名，保证永不覆盖既有 checkpoint；若进程在
                # 下一步前崩溃，缺少 manifest/runtime 的空目录会被恢复入口拒绝。
                os.mkdir(
                    safe_checkpoint_id,
                    mode=0o700,
                    dir_fd=checkpoints_fd,
                )
                reservation_created = True
                os.rename(
                    stage_name,
                    safe_checkpoint_id,
                    src_dir_fd=staging_fd,
                    dst_dir_fd=checkpoints_fd,
                )
                reservation_created = False
                published = True
                os.fsync(checkpoints_fd)
                return copied_usage
            except (
                FileNotFoundError,
                workspace_store.AgentWorkspaceError,
                workspace_store.AgentWorkspacePathError,
            ):
                raise
            except OSError as exc:
                raise workspace_store.AgentWorkspaceError(
                    "无法创建 Agent runtime checkpoint"
                ) from exc
            finally:
                if stage_runtime_fd is not None:
                    os.close(stage_runtime_fd)
                if stage_fd is not None:
                    os.close(stage_fd)
                if source_runtime_fd is not None:
                    os.close(source_runtime_fd)
                if reservation_created:
                    try:
                        os.rmdir(safe_checkpoint_id, dir_fd=checkpoints_fd)
                    except OSError:
                        pass
                if not published:
                    try:
                        _remove_directory_at(staging_fd, stage_name)
                    except (FileNotFoundError, OSError, workspace_store.AgentWorkspaceError):
                        pass
                os.close(staging_fd)
                os.close(checkpoints_fd)


def create_agent_runtime_checkpoint(
    session_id,
    checkpoint_id,
) -> workspace_store.AgentWorkspaceUsage:
    """把当前 ``workspace/.runtime`` 发布为不可覆盖的私有 checkpoint。"""

    return _create_checkpoint(session_id, checkpoint_id, empty=False)


def create_empty_agent_runtime_checkpoint(
    session_id,
    checkpoint_id,
) -> workspace_store.AgentWorkspaceUsage:
    """发布一个明确的空 runtime 基线；不会读取或创建当前 ``.runtime``。"""

    return _create_checkpoint(session_id, checkpoint_id, empty=True)


@contextmanager
def _open_checkpoint(checkpoints_fd: int, checkpoint_id: str):
    try:
        checkpoint_fd = workspace_store._open_existing_directory_at(
            checkpoints_fd,
            checkpoint_id,
            label="Agent runtime checkpoint",
        )
    except FileNotFoundError:
        raise
    try:
        checkpoint_info = os.fstat(checkpoint_fd)
        if (
            not stat.S_ISDIR(checkpoint_info.st_mode)
            or int(checkpoint_info.st_uid) != os.geteuid()
            or stat.S_IMODE(checkpoint_info.st_mode) != 0o700
        ):
            raise workspace_store.AgentWorkspaceSecurityError(
                "Agent runtime checkpoint 私有目录属性无效"
            )
        manifest_usage = _read_manifest(checkpoint_fd)
        runtime_fd = workspace_store._open_existing_directory_at(
            checkpoint_fd,
            _CHECKPOINT_RUNTIME_DIRECTORY,
            label="Agent runtime checkpoint 内容目录",
        )
        try:
            actual_usage, _root_mode = _scan_tree_fd(runtime_fd)
            if actual_usage != manifest_usage:
                raise workspace_store.AgentWorkspaceSecurityError(
                    "Agent runtime checkpoint 内容与清单不一致"
                )
            yield runtime_fd, actual_usage
        finally:
            os.close(runtime_fd)
    finally:
        os.close(checkpoint_fd)


def restore_agent_runtime_checkpoint(
    session_id,
    checkpoint_id,
) -> workspace_store.AgentWorkspaceUsage:
    """仅原子替换 ``workspace/.runtime``，其它 workspace 内容保持原样。"""

    safe_checkpoint_id = workspace_store._normalize_identifier(
        checkpoint_id,
        label="Agent runtime checkpoint_id",
    )
    with workspace_store._open_existing_session_directories(session_id) as (
        _safe_session_id,
        session_fd,
        workspace_fd,
    ):
        with _checkpoint_lock(session_fd):
            checkpoints_fd = workspace_store._open_existing_directory_at(
                session_fd,
                _CHECKPOINTS_DIRECTORY,
                label="Agent runtime checkpoints 目录",
            )
            stage_name = f".runtime-restore-{uuid.uuid4().hex}"
            backup_name = f".runtime-backup-{uuid.uuid4().hex}"
            stage_fd = None
            stage_present = False
            backup_present = False
            published = False

            def rollback_published_runtime() -> None:
                nonlocal backup_present, published
                rollback_name = f".runtime-rollback-{uuid.uuid4().hex}"
                try:
                    os.rename(
                        ".runtime",
                        rollback_name,
                        src_dir_fd=workspace_fd,
                        dst_dir_fd=session_fd,
                    )
                except OSError as exc:
                    raise workspace_store.AgentWorkspaceSecurityError(
                        "Agent runtime 发布失败后无法固定新目录，拒绝猜测恢复状态"
                    ) from exc
                if backup_present:
                    try:
                        os.rename(
                            backup_name,
                            ".runtime",
                            src_dir_fd=session_fd,
                            dst_dir_fd=workspace_fd,
                        )
                        backup_present = False
                    except OSError as exc:
                        # 尽力把已完整发布的新 runtime 放回规范位置，避免
                        # 两份状态都留在容器不可见的会话私有目录。
                        try:
                            os.rename(
                                rollback_name,
                                ".runtime",
                                src_dir_fd=session_fd,
                                dst_dir_fd=workspace_fd,
                            )
                        except OSError:
                            pass
                        raise workspace_store.AgentWorkspaceSecurityError(
                            "Agent runtime 发布失败后无法恢复旧目录"
                        ) from exc
                published = False
                try:
                    os.fsync(workspace_fd)
                    os.fsync(session_fd)
                except OSError:
                    pass
                try:
                    _remove_directory_at(session_fd, rollback_name)
                except Exception:
                    # 旧 runtime 已恢复；新目录仅作为容器不可见的私有孤儿保留。
                    pass

            try:
                with _open_checkpoint(
                    checkpoints_fd,
                    safe_checkpoint_id,
                ) as (checkpoint_runtime_fd, expected_usage):
                    os.mkdir(stage_name, mode=0o700, dir_fd=session_fd)
                    stage_present = True
                    stage_fd = workspace_store._open_existing_directory_at(
                        session_fd,
                        stage_name,
                        label="Agent runtime 恢复暂存目录",
                    )
                    copied_usage = _copy_tree_fd(
                        checkpoint_runtime_fd,
                        stage_fd,
                    )
                    if copied_usage != expected_usage:
                        raise workspace_store.AgentWorkspaceSecurityError(
                            "Agent runtime checkpoint 恢复复制不完整"
                        )
                    os.fsync(stage_fd)

                try:
                    runtime_info = os.stat(
                        ".runtime",
                        dir_fd=workspace_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    runtime_info = None
                if runtime_info is not None:
                    try:
                        os.rename(
                            ".runtime",
                            backup_name,
                            src_dir_fd=workspace_fd,
                            dst_dir_fd=session_fd,
                        )
                        backup_present = True
                    except Exception:
                        if backup_present:
                            os.rename(
                                backup_name,
                                ".runtime",
                                src_dir_fd=session_fd,
                                dst_dir_fd=workspace_fd,
                            )
                            backup_present = False
                        raise

                try:
                    os.rename(
                        stage_name,
                        ".runtime",
                        src_dir_fd=session_fd,
                        dst_dir_fd=workspace_fd,
                    )
                except Exception:
                    if backup_present:
                        os.rename(
                            backup_name,
                            ".runtime",
                            src_dir_fd=session_fd,
                            dst_dir_fd=workspace_fd,
                        )
                        backup_present = False
                    raise
                stage_present = False
                published = True
                try:
                    os.fsync(workspace_fd)
                    os.fsync(session_fd)
                except Exception:
                    rollback_published_runtime()
                    raise

                if backup_present:
                    try:
                        _remove_entry_at(session_fd, backup_name)
                        backup_present = False
                    except Exception:
                        # 新 runtime 已原子发布；此时旧目录可能已被部分清理，
                        # 不能再假装可以可靠回滚。保留容器不可见的私有备份，
                        # 由维护清理处理，成功语义仍以已经发布的新 runtime 为准。
                        pass
                return expected_usage
            except (workspace_store.AgentWorkspaceError, workspace_store.AgentWorkspacePathError):
                raise
            except OSError as exc:
                raise workspace_store.AgentWorkspaceError(
                    "无法恢复 Agent runtime checkpoint"
                ) from exc
            finally:
                if stage_fd is not None:
                    os.close(stage_fd)
                if stage_present:
                    try:
                        _remove_directory_at(session_fd, stage_name)
                    except (FileNotFoundError, OSError, workspace_store.AgentWorkspaceError):
                        pass
                if backup_present and not published:
                    try:
                        os.rename(
                            backup_name,
                            ".runtime",
                            src_dir_fd=session_fd,
                            dst_dir_fd=workspace_fd,
                        )
                    except OSError:
                        pass
                os.close(checkpoints_fd)


def remove_agent_runtime_checkpoint(
    session_id,
    checkpoint_id,
    *,
    missing_ok: bool = True,
) -> bool:
    """移除一个不再被数据模型引用的私有 checkpoint。"""

    safe_checkpoint_id = workspace_store._normalize_identifier(
        checkpoint_id,
        label="Agent runtime checkpoint_id",
    )
    with workspace_store._open_existing_session_directories(session_id) as (
        _safe_session_id,
        session_fd,
        _workspace_fd,
    ):
        with _checkpoint_lock(session_fd):
            try:
                checkpoints_fd = workspace_store._open_existing_directory_at(
                    session_fd,
                    _CHECKPOINTS_DIRECTORY,
                    label="Agent runtime checkpoints 目录",
                )
            except FileNotFoundError:
                if missing_ok:
                    return False
                raise
            trash_name = f".runtime-checkpoint-trash-{uuid.uuid4().hex}"
            moved = False
            try:
                if not _checkpoint_exists(checkpoints_fd, safe_checkpoint_id):
                    if missing_ok:
                        return False
                    raise FileNotFoundError(safe_checkpoint_id)
                os.rename(
                    safe_checkpoint_id,
                    trash_name,
                    src_dir_fd=checkpoints_fd,
                    dst_dir_fd=session_fd,
                )
                moved = True
                try:
                    _remove_directory_at(session_fd, trash_name)
                    moved = False
                except Exception:
                    os.rename(
                        trash_name,
                        safe_checkpoint_id,
                        src_dir_fd=session_fd,
                        dst_dir_fd=checkpoints_fd,
                    )
                    moved = False
                    raise
                return True
            except (
                FileNotFoundError,
                workspace_store.AgentWorkspaceError,
                workspace_store.AgentWorkspacePathError,
            ):
                raise
            except OSError as exc:
                raise workspace_store.AgentWorkspaceError(
                    "无法移除 Agent runtime checkpoint"
                ) from exc
            finally:
                if moved:
                    try:
                        os.rename(
                            trash_name,
                            safe_checkpoint_id,
                            src_dir_fd=session_fd,
                            dst_dir_fd=checkpoints_fd,
                        )
                    except OSError:
                        pass
                os.close(checkpoints_fd)


__all__ = [
    "create_agent_runtime_checkpoint",
    "create_empty_agent_runtime_checkpoint",
    "restore_agent_runtime_checkpoint",
    "remove_agent_runtime_checkpoint",
]
