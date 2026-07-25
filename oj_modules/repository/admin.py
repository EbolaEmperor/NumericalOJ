#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""代码仓库存储审计服务。

doctor 只读取数据库与文件系统，不创建目录、不修复数据。所有发现都作为结构化 issue
返回；修复必须由显式恢复/清理命令完成。
"""

from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata
import uuid

from oj_modules.db_services import get_db_connection
from oj_modules.repository import storage
from oj_modules import submission_repository_snapshots as snapshot_services


def _issue(code, message, *, user_id=None, path=None, **details):
    payload = {"code": str(code), "message": str(message)}
    if user_id is not None:
        payload["user_id"] = int(user_id)
    if path is not None:
        payload["path"] = str(path)
    payload.update(details)
    return payload


def _plain_directory(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)


def _read_regular_file(path):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        remaining = storage.MAX_FILE_BYTES + 1
        chunks = []
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks), int(info.st_size)
    finally:
        os.close(fd)


def audit_tree_against_metadata(tree_root, state, entries):
    """纯文件系统/metadata 对照，便于 doctor 与无基础设施单测复用。"""
    root = Path(tree_root)
    user_id = int(state["user_id"])
    issues = []
    metadata = {str(row["relative_path"]): row for row in entries}
    metadata_ids = {int(row["id"]): row for row in entries}
    metadata_total = sum(
        int(row.get("file_size") or 0)
        for row in entries
        if row["entry_type"] == "file"
    )
    if int(state.get("entry_count") or 0) != len(entries):
        issues.append(
            _issue(
                "state_entry_count_mismatch",
                "repository_states.entry_count 与 metadata 数量不一致",
                user_id=user_id,
                expected=len(entries),
                actual=int(state.get("entry_count") or 0),
            )
        )
    if int(state.get("total_size") or 0) != metadata_total:
        issues.append(
            _issue(
                "state_total_size_mismatch",
                "repository_states.total_size 与 metadata 文件大小合计不一致",
                user_id=user_id,
                expected=metadata_total,
                actual=int(state.get("total_size") or 0),
            )
        )

    for row in entries:
        relative_path = str(row["relative_path"])
        try:
            safe_path = storage.validate_relative_path(relative_path)
            safe_name = storage.validate_entry_name(row["name"])
        except (storage.RepositoryPathError, storage.RepositoryStorageError) as exc:
            issues.append(
                _issue(
                    "metadata_path_invalid",
                    str(exc),
                    user_id=user_id,
                    path=relative_path,
                )
            )
            continue
        parent_id = row.get("parent_id")
        parent = metadata_ids.get(int(parent_id)) if parent_id is not None else None
        if parent_id is not None and (
            parent is None or parent["entry_type"] != "directory"
        ):
            issues.append(
                _issue(
                    "metadata_parent_invalid",
                    "metadata parent 不存在或不是目录",
                    user_id=user_id,
                    path=relative_path,
                )
            )
            continue
        parent_path = str(parent["relative_path"]) if parent else ""
        expected_path = storage.join_relative_path(parent_path, safe_name)
        if safe_path != expected_path:
            issues.append(
                _issue(
                    "metadata_path_parent_mismatch",
                    "relative_path 与 parent/name 不一致",
                    user_id=user_id,
                    path=relative_path,
                    expected=expected_path,
                )
            )

    if not _plain_directory(root):
        return issues + [
            _issue(
                "tree_root_missing_or_unsafe",
                "用户 tree 根不存在、不是目录或为符号链接",
                user_id=user_id,
                path=root,
            )
        ]

    actual = {}
    actual_total = 0
    for current_root, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        safe_directories = []
        for name in directory_names:
            path = current / name
            relative_path = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
            except FileNotFoundError:
                issues.append(
                    _issue(
                        "tree_entry_disappeared",
                        "doctor 扫描时目录消失",
                        user_id=user_id,
                        path=relative_path,
                    )
                )
                continue
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                issues.append(
                    _issue(
                        "tree_entry_unsafe",
                        "树中包含符号链接或非普通目录",
                        user_id=user_id,
                        path=relative_path,
                    )
                )
                continue
            safe_directories.append(name)
            actual[relative_path] = {
                "entry_type": "directory",
                "file_size": 0,
                "content_sha256": None,
            }
        directory_names[:] = safe_directories
        for name in file_names:
            path = current / name
            relative_path = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise OSError("not a regular file")
                data, size = _read_regular_file(path)
            except (FileNotFoundError, OSError) as exc:
                issues.append(
                    _issue(
                        "tree_entry_unsafe",
                        f"树中包含符号链接、非普通文件或扫描竞态：{exc}",
                        user_id=user_id,
                        path=relative_path,
                    )
                )
                continue
            actual_total += size
            digest = hashlib.sha256(data).hexdigest()
            actual[relative_path] = {
                "entry_type": "file",
                "file_size": size,
                "content_sha256": digest,
            }
            if size > storage.MAX_FILE_BYTES:
                issues.append(
                    _issue(
                        "tree_file_too_large",
                        "磁盘文件超过单文件配额",
                        user_id=user_id,
                        path=relative_path,
                        size=size,
                    )
                )
            try:
                text = data.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                issues.append(
                    _issue(
                        "tree_file_not_utf8",
                        "磁盘文件不是严格 UTF-8",
                        user_id=user_id,
                        path=relative_path,
                    )
                )
            else:
                if data.startswith(b"\xef\xbb\xbf") or "\r" in text:
                    issues.append(
                        _issue(
                            "tree_file_not_normalized",
                            "磁盘文件包含 BOM 或非 LF 换行",
                            user_id=user_id,
                            path=relative_path,
                        )
                    )
                if any(
                    unicodedata.category(character) == "Cc"
                    and character not in "\n\t\f"
                    for character in text
                ):
                    issues.append(
                        _issue(
                            "tree_file_control_character",
                            "磁盘文件包含不允许的控制字符",
                            user_id=user_id,
                            path=relative_path,
                        )
                    )

    for relative_path in sorted(set(metadata) | set(actual)):
        expected = metadata.get(relative_path)
        observed = actual.get(relative_path)
        if expected is None:
            issues.append(
                _issue(
                    "tree_orphan_entry",
                    "磁盘路径没有 metadata",
                    user_id=user_id,
                    path=relative_path,
                )
            )
            continue
        if observed is None:
            issues.append(
                _issue(
                    "tree_missing_entry",
                    "metadata 路径在磁盘中不存在",
                    user_id=user_id,
                    path=relative_path,
                )
            )
            continue
        if expected["entry_type"] != observed["entry_type"]:
            issues.append(
                _issue(
                    "tree_entry_type_mismatch",
                    "磁盘路径类型与 metadata 不一致",
                    user_id=user_id,
                    path=relative_path,
                    expected=expected["entry_type"],
                    actual=observed["entry_type"],
                )
            )
            continue
        if expected["entry_type"] == "file" and (
            int(expected.get("file_size") or 0) != observed["file_size"]
            or expected.get("content_sha256") != observed["content_sha256"]
        ):
            issues.append(
                _issue(
                    "tree_file_digest_mismatch",
                    "磁盘文件大小或 SHA-256 与 metadata 不一致",
                    user_id=user_id,
                    path=relative_path,
                    expected_size=int(expected.get("file_size") or 0),
                    actual_size=observed["file_size"],
                    expected_sha256=expected.get("content_sha256"),
                    actual_sha256=observed["content_sha256"],
                )
            )
    if len(actual) != len(entries):
        issues.append(
            _issue(
                "tree_entry_count_mismatch",
                "磁盘条目数量与 metadata 不一致",
                user_id=user_id,
                expected=len(entries),
                actual=len(actual),
            )
        )
    if actual_total != metadata_total:
        issues.append(
            _issue(
                "tree_total_size_mismatch",
                "磁盘文件大小合计与 metadata 不一致",
                user_id=user_id,
                expected=metadata_total,
                actual=actual_total,
            )
        )
    return issues


def _managed_child_directories(path, *, managed_root):
    """枚举受管根下的真实目录，并显式报告所有其他 inode 类型。"""
    directories = set()
    issues = []
    if not _plain_directory(path):
        return directories, issues
    for entry in os.scandir(path):
        try:
            info = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            issues.append(
                _issue(
                    "managed_root_entry_unsafe",
                    "doctor 扫描时受管根条目消失",
                    path=Path(path) / entry.name,
                    managed_root=managed_root,
                )
            )
            continue
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            directories.add(entry.name)
            continue
        issues.append(
            _issue(
                "managed_root_entry_unsafe",
                "受管根包含符号链接、普通文件或其他非目录条目",
                path=Path(path) / entry.name,
                managed_root=managed_root,
                mode=int(info.st_mode),
            )
        )
    return directories, issues


def audit_submission_snapshot_against_metadata(row, storage_root):
    """核验一条快照绑定；把任何损坏转换为 doctor 的结构化 issue。"""
    try:
        snapshot_services.verify_submission_repository_snapshot(
            row,
            storage_root=Path(storage_root),
        )
    except Exception as exc:
        return [
            _issue(
                "snapshot_integrity_error",
                f"提交快照完整性校验失败：{exc}",
                user_id=row["user_id"],
                path=row["snapshot_key"],
                submission_id=int(row["submission_id"]),
            )
        ]
    return []


def doctor_repository_storage():
    root = Path(storage.STORAGE_ROOT)
    issues = []
    required_roots = (
        "users", "staging", "journal", "snapshots", "locks", "quarantine",
    )
    if not _plain_directory(root):
        return {
            "ok": False,
            "storage_root": str(root),
            "states": 0,
            "entries": 0,
            "issues": [
                _issue(
                    "storage_root_missing_or_unsafe",
                    "仓库存储根不存在、不是目录或为符号链接",
                    path=root,
                )
            ],
        }
    for child in required_roots:
        if not _plain_directory(root / child):
            issues.append(
                _issue(
                    "managed_root_missing_or_unsafe",
                    "受管子目录不存在、不是目录或为符号链接",
                    path=root / child,
                )
            )
    managed_children = {}
    for child in required_roots:
        child_directories, child_issues = _managed_child_directories(
            root / child,
            managed_root=child,
        )
        managed_children[child] = child_directories
        issues.extend(child_issues)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, storage_key, structure_version,
                       repository_generation, active_index_generation,
                       index_status, entry_count, total_size
                FROM repository_states
                ORDER BY user_id ASC
                """
            )
            states = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT id, user_id, parent_id, name, relative_path, entry_type,
                       file_size, file_version, content_sha256
                FROM repository_entries
                ORDER BY user_id ASC, relative_path ASC
                """
            )
            entries = cursor.fetchall() or []
            cursor.execute(
                "SELECT id, status, expires_at FROM repository_upload_sessions"
            )
            upload_sessions = cursor.fetchall() or []
            cursor.execute(
                "SELECT operation_id, status FROM repository_fs_journal"
            )
            journal_rows = cursor.fetchall() or []
            cursor.execute(
                """
                SELECT submission_id, user_id, snapshot_key, relative_root,
                       repository_generation, manifest_sha256, entry_count,
                       total_size
                FROM submission_repository_snapshots
                ORDER BY submission_id ASC
                """
            )
            snapshot_rows = cursor.fetchall() or []
    finally:
        conn.close()

    entries_by_user = defaultdict(list)
    for row in entries:
        entries_by_user[int(row["user_id"])].append(row)
    storage_keys = set()
    for state in states:
        storage_key = str(state["storage_key"])
        storage_keys.add(storage_key)
        try:
            storage.validate_storage_key(storage_key)
        except storage.RepositoryStorageError as exc:
            issues.append(
                _issue(
                    "storage_key_invalid",
                    str(exc),
                    user_id=state["user_id"],
                )
            )
            continue
        issues.extend(
            audit_tree_against_metadata(
                root / "users" / storage_key / "tree",
                state,
                entries_by_user[int(state["user_id"])],
            )
        )

    for orphan in sorted(managed_children["users"] - storage_keys):
        issues.append(
            _issue(
                "orphan_user_storage",
                "用户存储目录没有 repository_states 记录",
                path=root / "users" / orphan,
            )
        )

    active_uploads = {
        str(row["id"])
        for row in upload_sessions
        if row["status"] in {"receiving", "needs_confirmation", "preview_ready"}
        and row["expires_at"] > datetime.now()
    }
    actual_staging = managed_children["staging"]
    for missing in sorted(active_uploads - actual_staging):
        issues.append(
            _issue(
                "upload_staging_missing",
                "活跃上传会话缺少 staging",
                path=missing,
            )
        )
    for orphan in sorted(actual_staging - active_uploads):
        issues.append(
            _issue(
                "upload_staging_orphan_or_expired",
                "staging 不属于未过期活跃上传会话",
                path=root / "staging" / orphan,
            )
        )

    active_journals = {
        str(row["operation_id"])
        for row in journal_rows
        if row["status"] in {"prepared", "fs_applied", "committed"}
    }
    actual_journals = managed_children["journal"]
    for missing in sorted(active_journals - actual_journals):
        issues.append(
            _issue(
                "journal_staging_missing",
                "未完成文件系统 journal 缺少暂存目录",
                path=missing,
            )
        )
    for orphan in sorted(actual_journals - active_journals):
        issues.append(
            _issue(
                "journal_staging_orphan",
                "journal 暂存目录没有未完成 DB journal",
                path=root / "journal" / orphan,
            )
        )

    expected_snapshots = {str(row["snapshot_key"]) for row in snapshot_rows}
    actual_snapshots = managed_children["snapshots"]
    if _plain_directory(root / "snapshots"):
        for row in snapshot_rows:
            issues.extend(audit_submission_snapshot_against_metadata(row, root))
    for missing in sorted(expected_snapshots - actual_snapshots):
        issues.append(
            _issue(
                "snapshot_missing",
                "提交快照 metadata 缺少磁盘目录",
                path=missing,
            )
        )
    for orphan in sorted(actual_snapshots - expected_snapshots):
        issues.append(
            _issue(
                "snapshot_orphan",
                "磁盘提交快照没有 metadata",
                path=root / "snapshots" / orphan,
            )
        )

    return {
        "ok": not issues,
        "storage_root": str(root),
        "states": len(states),
        "entries": len(entries),
        "issues": issues,
    }


def _path_is_within(path, root):
    try:
        Path(path).relative_to(Path(root))
        return True
    except ValueError:
        return False


def plan_repository_orphan_quarantine():
    """从 doctor 结果生成可隔离项；不会创建 quarantine 或改动源路径。"""
    doctor = doctor_repository_storage()
    root = Path(storage.STORAGE_ROOT)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, storage_key FROM repository_states")
            states = {
                int(row["user_id"]): str(row["storage_key"])
                for row in cursor.fetchall() or []
            }
            cursor.execute(
                "SELECT user_id, relative_path FROM repository_entries"
            )
            metadata_paths = defaultdict(set)
            for row in cursor.fetchall() or []:
                metadata_paths[int(row["user_id"])].add(
                    str(row["relative_path"])
                )
    finally:
        conn.close()

    raw_candidates = []
    blocked = []
    auxiliary_codes = {
        "managed_root_entry_unsafe",
        "orphan_user_storage",
        "upload_staging_orphan_or_expired",
        "journal_staging_orphan",
        "snapshot_orphan",
    }
    for issue in doctor["issues"]:
        code = issue["code"]
        source = None
        if code in {"tree_orphan_entry", "tree_entry_unsafe"}:
            user_id = issue.get("user_id")
            storage_key = states.get(int(user_id)) if user_id is not None else None
            relative_path = str(issue.get("path") or "")
            if not storage_key or not relative_path:
                continue
            source = root / "users" / storage_key / "tree" / relative_path
            if code == "tree_orphan_entry":
                try:
                    info = source.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode) and any(
                    metadata_path.startswith(relative_path + "/")
                    for metadata_path in metadata_paths[int(user_id)]
                ):
                    blocked.append(
                        {
                            "source_relative": source.relative_to(root).as_posix(),
                            "reason": "orphan_directory_contains_metadata_descendant",
                        }
                    )
                    continue
        elif code in auxiliary_codes:
            raw_path = Path(str(issue.get("path") or ""))
            if raw_path.is_absolute():
                source = raw_path
        if source is None or not _path_is_within(source, root):
            continue
        try:
            info = source.lstat()
        except FileNotFoundError:
            continue
        raw_candidates.append(
            {
                "category": code,
                "source_relative": source.relative_to(root).as_posix(),
                "device": int(info.st_dev),
                "inode": int(info.st_ino),
                "mode": int(info.st_mode),
            }
        )

    # 若整个上层目录都已是 orphan，只隔离最上层；一次原子 rename 会保留其完整内容。
    planned = []
    for item in sorted(
        raw_candidates,
        key=lambda candidate: (
            len(Path(candidate["source_relative"]).parts),
            candidate["source_relative"],
        ),
    ):
        parts = Path(item["source_relative"]).parts
        if any(
            parts[: len(Path(existing["source_relative"]).parts)]
            == Path(existing["source_relative"]).parts
            for existing in planned
        ):
            continue
        planned.append(item)
    return {
        "storage_root": str(root),
        "doctor_ok": doctor["ok"],
        "items": planned,
        "blocked": blocked,
    }


@contextmanager
def _open_managed_directory_chain(root_fd, parts):
    opened = []
    current = root_fd
    try:
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            opened.append(next_fd)
            current = next_fd
        yield current
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _atomic_write_json(path, payload):
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    temporary = path.parent / f".{path.name}-{uuid.uuid4().hex}.tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    directory_fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def quarantine_repository_orphans(
    *,
    apply=False,
    writers_stopped_confirmed=False,
):
    """把 doctor 识别的孤儿原子移入同一存储根的 quarantine，绝不删除。"""
    if apply and not writers_stopped_confirmed:
        raise RuntimeError("拒绝隔离：未确认全部应用写入者已经停止")
    plan = plan_repository_orphan_quarantine()
    if not apply:
        return {"apply": False, "batch_id": None, **plan}

    storage.ensure_repository_storage_ready()
    root = Path(storage.STORAGE_ROOT)
    batch_id = (
        datetime.now().strftime("%Y%m%dT%H%M%S")
        + "-"
        + uuid.uuid4().hex
    )
    batch_root = root / "quarantine" / batch_id
    items_root = batch_root / "items"
    batch_root.mkdir(mode=0o700)
    items_root.mkdir(mode=0o700)
    manifest_path = batch_root / "manifest.json"
    manifest = {
        "version": 1,
        "batch_id": batch_id,
        "status": "planned",
        "created_at": datetime.now().isoformat(sep=" "),
        "items": [
            {
                **item,
                "quarantine_relative": (
                    f"quarantine/{batch_id}/items/{index:06d}"
                ),
                "status": "planned",
            }
            for index, item in enumerate(plan["items"], start=1)
        ],
        "blocked": plan["blocked"],
    }
    _atomic_write_json(manifest_path, manifest)
    root_fd = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    items_fd = os.open(
        items_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        for index, item in enumerate(manifest["items"], start=1):
            source_parts = Path(item["source_relative"]).parts
            if not source_parts or any(part in {"", ".", ".."} for part in source_parts):
                raise RuntimeError("隔离计划包含非法源路径")
            with _open_managed_directory_chain(root_fd, source_parts[:-1]) as parent_fd:
                info = os.stat(
                    source_parts[-1],
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    int(info.st_dev) != int(item["device"])
                    or int(info.st_ino) != int(item["inode"])
                    or stat.S_IFMT(info.st_mode) != stat.S_IFMT(int(item["mode"]))
                ):
                    raise RuntimeError(
                        f"隔离前源路径已变化：{item['source_relative']}"
                    )
                os.rename(
                    source_parts[-1],
                    f"{index:06d}",
                    src_dir_fd=parent_fd,
                    dst_dir_fd=items_fd,
                )
                os.fsync(parent_fd)
                os.fsync(items_fd)
            item["status"] = "quarantined"
            item["quarantined_at"] = datetime.now().isoformat(sep=" ")
            _atomic_write_json(manifest_path, manifest)
        manifest["status"] = "complete"
        manifest["completed_at"] = datetime.now().isoformat(sep=" ")
        _atomic_write_json(manifest_path, manifest)
    except Exception as exc:
        manifest["status"] = "interrupted"
        manifest["error"] = str(exc)
        _atomic_write_json(manifest_path, manifest)
        raise
    finally:
        os.close(items_fd)
        os.close(root_fd)
    return {
        "apply": True,
        "batch_id": batch_id,
        "batch_root": str(batch_root),
        "items": manifest["items"],
        "blocked": plan["blocked"],
    }
