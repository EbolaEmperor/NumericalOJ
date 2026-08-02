#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""代码仓库目录树、元数据、乐观锁和上传会话领域服务。

``repository_entries`` 是树的元数据索引，真实文件与空目录位于
``REPOSITORY_STORAGE_ROOT/users/<storage_key>/tree``。所有权威读写均经过本模块；
数据库不保存仓库文件正文。
"""

from __future__ import annotations

from contextlib import contextmanager
import codecs
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import unicodedata
import uuid

import pymysql

import config
from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.repository import storage


UPLOAD_SESSION_TTL_SECONDS = int(config.REPOSITORY_UPLOAD_SESSION_TTL_SECONDS)
UPLOAD_CHUNK_MAX_BYTES = 1024 * 1024
UPLOAD_MAX_ACTIVE_SESSIONS_PER_USER = 4
# 单个原始批次最多 4× 仓库配额，规范化副本最多再占 1×；限制所有活跃会话
# 的真实暂存上界，避免利用可续传会话无界占满宿主磁盘。
UPLOAD_MAX_STAGING_BYTES_PER_USER = storage.MAX_TOTAL_BYTES * 5
UPLOAD_ORPHAN_GRACE_SECONDS = 60 * 60
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class RepositoryDomainError(RuntimeError):
    def __init__(self, message, *, code="repository_error", status=400, **details):
        self.message = str(message)
        self.code = str(code)
        self.status = int(status)
        self.details = details
        super().__init__(self.message)

    def as_payload(self):
        return {"success": False, "message": self.message, "code": self.code, **self.details}


def _domain_error(exc):
    if isinstance(exc, RepositoryDomainError):
        return exc
    if isinstance(exc, (storage.RepositoryPathError, storage.RepositoryEncodingConfirmationRequired)):
        return RepositoryDomainError(str(exc), code="validation_error", status=400)
    if isinstance(exc, storage.RepositoryStorageError):
        return RepositoryDomainError(str(exc), code="storage_error", status=503)
    return exc


def _path_hash(relative_path):
    return hashlib.sha256(str(relative_path).encode("utf-8")).digest()


def _format_datetime(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return value


def _serialize_entry(row):
    return {
        "id": int(row["id"]),
        "parent_id": int(row["parent_id"]) if row.get("parent_id") is not None else None,
        "name": row["name"],
        "path": row["relative_path"],
        "relative_path": row["relative_path"],
        "kind": row["entry_type"],
        "file_size": int(row.get("file_size") or 0),
        "file_version": int(row.get("file_version") or 0),
        "sha256": row.get("content_sha256"),
        "indexable": (
            row["entry_type"] == "file"
            and str(row["relative_path"]).lower().endswith((".h", ".hpp", ".c", ".cpp"))
        ),
        "created_at": _format_datetime(row.get("created_at")),
        "updated_at": _format_datetime(row.get("updated_at")),
    }


def _serialize_state(row):
    return {
        "storage_key": row["storage_key"],
        "structure_version": int(row.get("structure_version") or 0),
        "repository_generation": int(row.get("repository_generation") or 0),
        "active_index_generation": (
            int(row["active_index_generation"])
            if row.get("active_index_generation") is not None
            else None
        ),
        "index_status": row.get("index_status") or "stale",
        "entry_count": int(row.get("entry_count") or 0),
        "total_size": int(row.get("total_size") or 0),
    }


def _quota_payload(state):
    return {
        "file_bytes": storage.MAX_FILE_BYTES,
        "total_bytes": storage.MAX_TOTAL_BYTES,
        "entries": storage.MAX_ENTRIES,
        "depth": storage.MAX_DEPTH,
        "path_bytes": storage.MAX_PATH_BYTES,
        "used_bytes": int(state.get("total_size") or 0),
        "used_entries": int(state.get("entry_count") or 0),
    }


def _get_or_create_state(user_id):
    user_id = int(user_id)
    candidate = uuid.uuid4().hex
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO repository_states (
                    user_id, storage_key, structure_version, repository_generation,
                    active_index_generation, index_status, entry_count, total_size
                )
                VALUES (%s, %s, 1, 1, NULL, 'stale', 0, 0)
                ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)
                """,
                (user_id, candidate),
            )
            cursor.execute(
                """
                SELECT user_id, storage_key, structure_version, repository_generation,
                       active_index_generation, index_status, entry_count, total_size
                FROM repository_states
                WHERE user_id = %s
                """,
                (user_id,),
            )
            row = cursor.fetchone()
        conn.commit()
    finally:
        conn.close()
    if not row:
        raise RepositoryDomainError("无法初始化代码仓库", code="state_init_failed", status=500)
    storage.ensure_user_tree(row["storage_key"])
    return row


def _load_state(cursor, user_id, *, for_update=False):
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT user_id, storage_key, structure_version, repository_generation,
               active_index_generation, index_status, entry_count, total_size
        FROM repository_states
        WHERE user_id = %s
        """ + suffix,
        (int(user_id),),
    )
    row = cursor.fetchone()
    if not row:
        raise RepositoryDomainError("代码仓库状态不存在", code="state_missing", status=500)
    return row


def _load_entries(cursor, user_id, *, for_update=False):
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT id, user_id, parent_id, name, relative_path, entry_type,
               file_size, file_version, content_sha256, created_at, updated_at
        FROM repository_entries
        WHERE user_id = %s
        ORDER BY relative_path ASC
        """ + suffix,
        (int(user_id),),
    )
    return cursor.fetchall() or []


def _recover_locked(user_id, state):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT operation_id, status
                FROM repository_fs_journal
                WHERE user_id = %s
                  AND status IN ('prepared', 'fs_applied', 'committed')
                ORDER BY created_at ASC
                """,
                (int(user_id),),
            )
            rows = cursor.fetchall() or []
        for row in rows:
            operation_id = row["operation_id"]
            if row["status"] == "committed":
                try:
                    storage.cleanup_operation_tree(operation_id)
                except Exception:
                    continue
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        UPDATE repository_fs_journal
                        SET status = 'finalized'
                        WHERE operation_id = %s AND status = 'committed'
                        """,
                        (operation_id,),
                    )
                conn.commit()
                continue
            if row["status"] == "fs_applied":
                operation_dir = storage.operation_journal_path(operation_id)
                old_tree = operation_dir / "old-tree"
                try:
                    operation_info = operation_dir.lstat()
                    old_tree_info = old_tree.lstat()
                except FileNotFoundError as exc:
                    raise RepositoryDomainError(
                        "文件系统 journal 标记为 fs_applied，但缺少可回滚 old-tree；"
                        "已失败关闭，请先运行 doctor 并人工恢复",
                        code="journal_recovery_missing_backup",
                        status=503,
                        operation_id=operation_id,
                    ) from exc
                if (
                    stat.S_ISLNK(operation_info.st_mode)
                    or not stat.S_ISDIR(operation_info.st_mode)
                    or stat.S_ISLNK(old_tree_info.st_mode)
                    or not stat.S_ISDIR(old_tree_info.st_mode)
                ):
                    raise RepositoryDomainError(
                        "文件系统 journal 的回滚目录类型不安全；已失败关闭",
                        code="journal_recovery_unsafe_backup",
                        status=503,
                        operation_id=operation_id,
                    )
            storage.rollback_operation_tree(state["storage_key"], operation_id)
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE repository_fs_journal
                    SET status = 'rolled_back',
                        error_message = COALESCE(error_message, '启动恢复：DB 未提交，已回滚文件系统')
                    WHERE operation_id = %s AND status IN ('prepared', 'fs_applied')
                    """,
                    (operation_id,),
                )
            conn.commit()
    finally:
        conn.close()


@contextmanager
def repository_user_lock(user_id, *, exclusive=False):
    """供提交快照与其他消费者复用的用户仓库跨进程锁。"""
    state = _get_or_create_state(user_id)
    if exclusive:
        with storage.repository_user_lock(state["storage_key"], exclusive=True):
            _recover_locked(user_id, state)
            yield _serialize_state(state)
        return
    # 恢复需要独占；恢复完再降级为共享读锁。
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        _recover_locked(user_id, state)
    with storage.repository_user_lock(state["storage_key"], exclusive=False):
        yield _serialize_state(state)


def get_repository_authoritative_tree(user_id):
    state = _get_or_create_state(user_id)
    return {
        **_serialize_state(state),
        "tree_root": storage.ensure_user_tree(state["storage_key"]),
    }


def list_repository_entries(user_id):
    with repository_user_lock(user_id, exclusive=False):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                state = _load_state(cursor, user_id)
                rows = _load_entries(cursor, user_id)
        finally:
            conn.close()
    serialized_state = _serialize_state(state)
    return {
        **serialized_state,
        "quota": _quota_payload(state),
        "entries": [_serialize_entry(row) for row in rows],
    }


def get_repository_state(user_id):
    state = _get_or_create_state(user_id)
    with repository_user_lock(user_id, exclusive=False):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                state = _load_state(cursor, user_id)
        finally:
            conn.close()
    serialized = _serialize_state(state)
    serialized["quota"] = _quota_payload(state)
    return serialized


def list_repository_files(user_id, *, include_content=False):
    result = []
    with repository_user_lock(user_id, exclusive=False) as locked_state:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, user_id, parent_id, name, relative_path, entry_type,
                           file_size, file_version, content_sha256, created_at, updated_at
                    FROM repository_entries
                    WHERE user_id = %s AND entry_type = 'file'
                    ORDER BY relative_path ASC
                    """,
                    (int(user_id),),
                )
                rows = cursor.fetchall() or []
        finally:
            conn.close()
        for row in rows:
            item = _serialize_entry(row)
            if include_content:
                raw = storage.read_file(locked_state["storage_key"], row["relative_path"])
                if hashlib.sha256(raw).hexdigest() != row["content_sha256"]:
                    raise RepositoryDomainError(
                        f"仓库文件校验失败：{row['relative_path']}",
                        code="content_integrity_error",
                        status=500,
                    )
                item["content"] = raw.decode("utf-8", errors="strict")
            result.append(item)
    return result


def get_repository_tree_snapshot(user_id, *, include_content=True):
    """在一次共享仓库锁内读取同一 generation 的完整树。

    供提交快照、判题、Agent 与索引消费者使用；返回值包含空目录。调用方不得在
    此 helper 外再嵌套 ``repository_user_lock`` 后调用其他会自行加锁的读函数。
    """

    with repository_user_lock(user_id, exclusive=False) as locked_state:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                state = _load_state(cursor, user_id)
                rows = _load_entries(cursor, user_id)
        finally:
            conn.close()

        entries = []
        for row in rows:
            item = _serialize_entry(row)
            if include_content and row["entry_type"] == "file":
                raw = storage.read_file(
                    locked_state["storage_key"],
                    row["relative_path"],
                )
                if (
                    hashlib.sha256(raw).hexdigest() != row["content_sha256"]
                    or len(raw) != int(row["file_size"])
                ):
                    raise RepositoryDomainError(
                        f"仓库文件校验失败：{row['relative_path']}",
                        code="content_integrity_error",
                        status=500,
                    )
                item["content"] = raw.decode("utf-8", errors="strict")
            entries.append(item)

    return {
        **_serialize_state(state),
        "quota": _quota_payload(state),
        "entries": entries,
    }


def _find_entry(cursor, user_id, *, entry_id=None, relative_path=None, for_update=False):
    if entry_id is None and relative_path is None:
        raise ValueError("entry_id 或 relative_path 至少提供一个")
    suffix = " FOR UPDATE" if for_update else ""
    if entry_id is not None:
        cursor.execute(
            """
            SELECT id, user_id, parent_id, name, relative_path, entry_type,
                   file_size, file_version, content_sha256, created_at, updated_at
            FROM repository_entries
            WHERE user_id = %s AND id = %s
            LIMIT 1
            """ + suffix,
            (int(user_id), int(entry_id)),
        )
    else:
        safe_path = storage.validate_relative_path(relative_path)
        cursor.execute(
            """
            SELECT id, user_id, parent_id, name, relative_path, entry_type,
                   file_size, file_version, content_sha256, created_at, updated_at
            FROM repository_entries
            WHERE user_id = %s AND path_hash = %s
            LIMIT 1
            """ + suffix,
            (int(user_id), _path_hash(safe_path)),
        )
    row = cursor.fetchone()
    if row and relative_path is not None and row["relative_path"] != safe_path:
        raise RepositoryDomainError("仓库路径哈希碰撞", code="path_hash_collision", status=500)
    return row


def read_repository_file(user_id, *, entry_id=None, relative_path=None):
    with repository_user_lock(user_id, exclusive=False) as locked_state:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                row = _find_entry(
                    cursor,
                    user_id,
                    entry_id=entry_id,
                    relative_path=relative_path,
                )
        finally:
            conn.close()
        if not row or row["entry_type"] != "file":
            raise RepositoryDomainError("文件不存在", code="not_found", status=404)
        raw = storage.read_file(locked_state["storage_key"], row["relative_path"])
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row["content_sha256"] or len(raw) != int(row["file_size"]):
            raise RepositoryDomainError(
                "仓库文件与元数据不一致，已拒绝读取",
                code="content_integrity_error",
                status=500,
            )
        return {**_serialize_entry(row), "content": raw.decode("utf-8", errors="strict")}


def get_repository_snapshot_manifest(user_id):
    state = _get_or_create_state(user_id)
    files = list_repository_files(user_id, include_content=False)
    manifest = [
        {
            "entry_id": item["id"],
            "relative_path": item["relative_path"],
            "size": item["file_size"],
            "sha256": item["sha256"],
            "file_version": item["file_version"],
        }
        for item in files
    ]
    canonical = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return {
        "repository_generation": int(state["repository_generation"]),
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "entry_count": len(manifest),
        "total_size": sum(item["size"] for item in manifest),
    }


def _require_version(value, *, field):
    if value is None:
        raise RepositoryDomainError(
            f"缺少乐观锁字段 {field}",
            code="version_required",
            status=428,
            field=field,
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RepositoryDomainError(
            f"{field} 必须是整数",
            code="validation_error",
            status=400,
        ) from exc
    if parsed < 0:
        raise RepositoryDomainError(f"{field} 非法", code="validation_error", status=400)
    return parsed


def _assert_structure_version(state, expected):
    use_expected = _require_version(expected, field="expected_structure_version")
    current = int(state["structure_version"])
    if use_expected != current:
        raise RepositoryDomainError(
            "目录结构已被其他操作修改，请刷新后重试",
            code="version_conflict",
            status=409,
            structure_version=current,
            repository_generation=int(state["repository_generation"]),
        )


def _entry_models(rows):
    models = []
    for row in rows:
        item = dict(row)
        item["_key"] = f"i:{int(row['id'])}"
        item["_old_path"] = row["relative_path"]
        item["_parent_key"] = (
            f"i:{int(row['parent_id'])}" if row.get("parent_id") is not None else None
        )
        models.append(item)
    return models


def _map_entries(entries):
    return {item["_key"]: item for item in entries}


def _entry_by_id(entries, entry_id):
    if entry_id is None:
        return None
    return _map_entries(entries).get(f"i:{int(entry_id)}")


def _children(entries, parent_key):
    return [entry for entry in entries if entry.get("_parent_key") == parent_key]


def _find_sibling(entries, parent_key, name, *, excluding=None):
    for entry in entries:
        if entry["_key"] == excluding:
            continue
        if entry.get("_parent_key") == parent_key and entry["name"] == name:
            return entry
    return None


def _parent_path(parent):
    return parent["relative_path"] if parent else ""


def _join_parent_relative(parent_path, relative_path):
    safe_parent = storage.validate_relative_path(parent_path, allow_empty=True)
    safe_relative = storage.validate_relative_path(relative_path)
    return storage.validate_relative_path(
        f"{safe_parent}/{safe_relative}" if safe_parent else safe_relative
    )


def _validate_parent(entries, parent_id):
    if parent_id is None:
        return None
    parent = _entry_by_id(entries, parent_id)
    if not parent or parent["entry_type"] != "directory":
        raise RepositoryDomainError("目标目录不存在", code="not_found", status=404)
    return parent


def _repath_subtree(entries, root_key, new_parent_key, new_name):
    mapping = _map_entries(entries)
    root = mapping[root_key]
    old_prefix = root["relative_path"]
    parent = mapping.get(new_parent_key) if new_parent_key else None
    new_prefix = storage.join_relative_path(_parent_path(parent), new_name)
    root["_parent_key"] = new_parent_key
    root["name"] = new_name
    for entry in entries:
        path = entry["relative_path"]
        if entry["_key"] == root_key:
            entry["relative_path"] = new_prefix
        elif path.startswith(old_prefix + "/"):
            suffix = path[len(old_prefix) + 1:]
            entry["relative_path"] = storage.validate_relative_path(f"{new_prefix}/{suffix}")


def _collect_subtree_keys(entries, root_key):
    result = set()
    stack = [root_key]
    while stack:
        key = stack.pop()
        if key in result:
            continue
        result.add(key)
        stack.extend(child["_key"] for child in _children(entries, key))
    return result


def _delete_subtree(entries, root_key):
    doomed = _collect_subtree_keys(entries, root_key)
    entries[:] = [entry for entry in entries if entry["_key"] not in doomed]
    return doomed


def _merge_directories(entries, source_key, destination_key, *, replace_files):
    for child in list(_children(entries, source_key)):
        conflict = _find_sibling(entries, destination_key, child["name"])
        if conflict is None:
            _repath_subtree(entries, child["_key"], destination_key, child["name"])
            continue
        if child["entry_type"] == conflict["entry_type"] == "directory":
            _merge_directories(
                entries,
                child["_key"],
                conflict["_key"],
                replace_files=replace_files,
            )
            _delete_subtree(entries, child["_key"])
            continue
        if not replace_files:
            raise RepositoryDomainError(
                f"合并冲突：{conflict['relative_path']}",
                code="name_conflict",
                status=409,
                path=conflict["relative_path"],
            )
        _delete_subtree(entries, conflict["_key"])
        _repath_subtree(entries, child["_key"], destination_key, child["name"])


def _validate_final_entries(entries):
    paths = set()
    sibling_names = set()
    entry_map = _map_entries(entries)
    total_size = 0
    for entry in entries:
        path = storage.validate_relative_path(entry["relative_path"])
        if path in paths:
            raise RepositoryDomainError(
                f"目标路径重复：{path}", code="name_conflict", status=409, path=path
            )
        paths.add(path)
        sibling_key = (entry.get("_parent_key"), entry["name"])
        if sibling_key in sibling_names:
            raise RepositoryDomainError(
                f"同一目录下名称重复：{entry['name']}",
                code="name_conflict",
                status=409,
            )
        sibling_names.add(sibling_key)
        parent_key = entry.get("_parent_key")
        if parent_key:
            parent = entry_map.get(parent_key)
            if not parent or parent["entry_type"] != "directory":
                raise RepositoryDomainError("目录树父节点非法", code="tree_corrupt", status=500)
            if path != storage.join_relative_path(parent["relative_path"], entry["name"]):
                raise RepositoryDomainError("目录树路径与父节点不一致", code="tree_corrupt", status=500)
        elif path != storage.validate_relative_path(entry["name"]):
            raise RepositoryDomainError("根节点路径非法", code="tree_corrupt", status=500)
        if entry["entry_type"] == "file":
            total_size += int(entry.get("file_size") or 0)
    if len(entries) > storage.MAX_ENTRIES:
        raise RepositoryDomainError(
            f"仓库条目不能超过 {storage.MAX_ENTRIES}",
            code="quota_exceeded",
            status=413,
        )
    if total_size > storage.MAX_TOTAL_BYTES:
        raise RepositoryDomainError(
            f"仓库总大小不能超过 {storage.MAX_TOTAL_BYTES} 字节",
            code="quota_exceeded",
            status=413,
        )
    return len(entries), total_size


def _prepare_shadow_tree(state, operation_id, entries, content_overrides):
    live_tree = storage.ensure_user_tree(state["storage_key"])
    shadow = storage.prepare_operation_tree(operation_id)
    for entry in sorted(
        (item for item in entries if item["entry_type"] == "directory"),
        key=lambda item: (item["relative_path"].count("/"), item["relative_path"]),
    ):
        storage.make_directory_in_tree(shadow, entry["relative_path"])
    for entry in sorted(
        (item for item in entries if item["entry_type"] == "file"),
        key=lambda item: item["relative_path"],
    ):
        override = content_overrides.get(entry["_key"])
        if override is None:
            storage.link_file_between_trees(
                live_tree,
                entry["_old_path"],
                shadow,
                entry["relative_path"],
            )
        elif "data" in override:
            storage.atomic_write_file_in_tree(shadow, entry["relative_path"], override["data"])
        else:
            storage.link_file_between_trees(
                Path(override["source_tree"]),
                override["source_path"],
                shadow,
                entry["relative_path"],
            )
    disk_entries, disk_size = storage.tree_disk_usage(shadow)
    expected_entries, expected_size = _validate_final_entries(entries)
    if (disk_entries, disk_size) != (expected_entries, expected_size):
        raise RepositoryDomainError(
            "发布前文件系统核验失败",
            code="storage_integrity_error",
            status=500,
            expected_entries=expected_entries,
            actual_entries=disk_entries,
            expected_size=expected_size,
            actual_size=disk_size,
        )


def _persist_entries(cursor, user_id, before_rows, final_entries, operation_id):
    before_ids = {int(row["id"]) for row in before_rows}
    final_existing_ids = {
        int(item["_key"][2:]) for item in final_entries if item["_key"].startswith("i:")
    }
    changed_or_deleted = []
    before_by_id = {int(row["id"]): row for row in before_rows}
    for entry_id in before_ids:
        final = next(
            (item for item in final_entries if item["_key"] == f"i:{entry_id}"),
            None,
        )
        original_parent_key = (
            f"i:{int(before_by_id[entry_id]['parent_id'])}"
            if before_by_id[entry_id].get("parent_id") is not None
            else None
        )
        if (
            final is None
            or final.get("_parent_key") != original_parent_key
            or any(
                final.get(field) != before_by_id[entry_id].get(field)
                for field in (
                    "name", "relative_path", "entry_type",
                    "file_size", "file_version", "content_sha256",
                )
            )
        ):
            changed_or_deleted.append(entry_id)

    # 先把会变化/删除的行移出共享命名空间，避免 swap/merge 时触发瞬时唯一键冲突。
    for entry_id in changed_or_deleted:
        temporary_name = f".numoj-metadata-{operation_id}-{entry_id}"
        temporary_path = f".numoj-metadata/{operation_id}/{entry_id}"
        cursor.execute(
            """
            UPDATE repository_entries
            SET parent_id = NULL, parent_scope = 0,
                name = %s, relative_path = %s, path_hash = %s
            WHERE user_id = %s AND id = %s
            """,
            (
                temporary_name,
                temporary_path,
                _path_hash(temporary_path),
                int(user_id),
                entry_id,
            ),
        )

    resolved_ids = {f"i:{entry_id}": entry_id for entry_id in before_ids}
    new_entries = [item for item in final_entries if item["_key"].startswith("n:")]
    new_entries.sort(key=lambda item: (item["relative_path"].count("/"), item["relative_path"]))
    for item in new_entries:
        parent_id = resolved_ids.get(item.get("_parent_key")) if item.get("_parent_key") else None
        cursor.execute(
            """
            INSERT INTO repository_entries (
                user_id, parent_id, parent_scope, name, relative_path, path_hash,
                entry_type, file_size, file_version, content_sha256
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                int(user_id),
                parent_id,
                int(parent_id or 0),
                item["name"],
                item["relative_path"],
                _path_hash(item["relative_path"]),
                item["entry_type"],
                int(item.get("file_size") or 0),
                int(item.get("file_version") or 0),
                item.get("content_sha256"),
            ),
        )
        resolved_ids[item["_key"]] = int(cursor.lastrowid)

    existing_final = [item for item in final_entries if item["_key"].startswith("i:")]
    existing_final.sort(key=lambda item: (item["relative_path"].count("/"), item["relative_path"]))
    for item in existing_final:
        entry_id = int(item["_key"][2:])
        parent_id = resolved_ids.get(item.get("_parent_key")) if item.get("_parent_key") else None
        cursor.execute(
            """
            UPDATE repository_entries
            SET parent_id = %s, parent_scope = %s, name = %s,
                relative_path = %s, path_hash = %s, entry_type = %s,
                file_size = %s, file_version = %s, content_sha256 = %s
            WHERE user_id = %s AND id = %s
            """,
            (
                parent_id,
                int(parent_id or 0),
                item["name"],
                item["relative_path"],
                _path_hash(item["relative_path"]),
                item["entry_type"],
                int(item.get("file_size") or 0),
                int(item.get("file_version") or 0),
                item.get("content_sha256"),
                int(user_id),
                entry_id,
            ),
        )

    deleted_ids = before_ids - final_existing_ids
    if deleted_ids:
        placeholders = ",".join(["%s"] * len(deleted_ids))
        cursor.execute(
            f"DELETE FROM repository_entries WHERE user_id = %s AND id IN ({placeholders})",
            tuple([int(user_id), *sorted(deleted_ids)]),
        )
    return resolved_ids


def _resolved_entry_snapshots(final_entries, resolved_ids):
    """构造本次事务最终态，响应不得在释放仓库锁后重新读取更晚版本。"""
    snapshots = {}
    for item in final_entries:
        key = item["_key"]
        entry_id = resolved_ids.get(key)
        if entry_id is None:
            continue
        parent_key = item.get("_parent_key")
        row = {
            "id": int(entry_id),
            "parent_id": (
                int(resolved_ids[parent_key])
                if parent_key is not None and parent_key in resolved_ids
                else None
            ),
            "name": item["name"],
            "relative_path": item["relative_path"],
            "entry_type": item["entry_type"],
            "file_size": int(item.get("file_size") or 0),
            "file_version": int(item.get("file_version") or 0),
            "content_sha256": item.get("content_sha256"),
        }
        snapshots[key] = _serialize_entry(row)
    return snapshots


def _rollback_connection_best_effort(conn):
    try:
        conn.rollback()
    except Exception:
        # COMMIT 回包丢失时连接本身往往已经不可用。这里不能让清理连接的
        # 次生异常覆盖后续由独立连接完成的提交结果判定。
        pass


def _close_connection_best_effort(conn):
    try:
        conn.close()
    except Exception:
        return False
    return True


def _probe_mutation_commit_outcome(
    user_id,
    operation_id,
    *,
    structure_version_before,
    repository_generation_before,
    structure_version_after,
    repository_generation_after,
):
    """用独立连接的 locking read 判定最终 DB 事务是否已经提交。

    返回值只会是 ``committed``、``not_committed`` 或 ``unknown``。任何不满足
    journal 与 repository state 原子对应关系的组合都必须视为 unknown，调用方
    将保留 old/new tree 现场并失败关闭。
    """
    verification_conn = get_db_connection()
    try:
        with verification_conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT j.user_id,
                       j.status AS journal_status,
                       j.structure_version_before,
                       j.structure_version_after,
                       s.structure_version AS state_structure_version,
                       s.repository_generation AS state_repository_generation
                FROM repository_fs_journal AS j
                JOIN repository_states AS s ON s.user_id = j.user_id
                WHERE j.operation_id = %s AND j.user_id = %s
                FOR SHARE
                """,
                (operation_id, int(user_id)),
            )
            row = cursor.fetchone()
    finally:
        _rollback_connection_best_effort(verification_conn)
        _close_connection_best_effort(verification_conn)

    if not row:
        return "unknown"

    journal_status = str(row.get("journal_status") or "")
    journal_before = int(row.get("structure_version_before") or 0)
    journal_after_raw = row.get("structure_version_after")
    journal_after = int(journal_after_raw) if journal_after_raw is not None else None
    state_structure = int(row.get("state_structure_version") or 0)
    state_generation = int(row.get("state_repository_generation") or 0)

    if (
        journal_status in {"committed", "finalized"}
        and journal_before == int(structure_version_before)
        and journal_after == int(structure_version_after)
        and state_structure == int(structure_version_after)
        and state_generation == int(repository_generation_after)
    ):
        return "committed"

    if (
        journal_status in {"prepared", "fs_applied"}
        and journal_before == int(structure_version_before)
        and journal_after is None
        and state_structure == int(structure_version_before)
        and state_generation == int(repository_generation_before)
    ):
        return "not_committed"

    return "unknown"


def _mark_mutation_rolled_back(operation_id):
    try:
        marker_conn = get_db_connection()
    except Exception:
        return
    try:
        with marker_conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE repository_fs_journal
                SET status = 'rolled_back', error_message = %s
                WHERE operation_id = %s
                  AND status IN ('prepared', 'fs_applied')
                """,
                ("DB 提交失败，已回滚文件系统", operation_id),
            )
        marker_conn.commit()
    except Exception:
        _rollback_connection_best_effort(marker_conn)
        # 权威树已经恢复为旧版本。若这里只更新失败，journal 会在下一次访问
        # 失败关闭，避免把 DB/FS 不一致静默当作成功。
    finally:
        _close_connection_best_effort(marker_conn)


def _finalize_committed_operation(operation_id):
    try:
        storage.cleanup_operation_tree(operation_id)
    except Exception:
        # DB+journal 已原子提交；清理失败只能留给下一次恢复，绝不能回滚已发布树。
        return

    try:
        finalizer_conn = get_db_connection()
    except Exception:
        return
    try:
        with finalizer_conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE repository_fs_journal
                SET status = 'finalized'
                WHERE operation_id = %s AND status = 'committed'
                """,
                (operation_id,),
            )
        finalizer_conn.commit()
    except Exception:
        _rollback_connection_best_effort(finalizer_conn)
    finally:
        _close_connection_best_effort(finalizer_conn)


def _run_mutation(
    user_id,
    *,
    operation_type,
    expected_structure_version=None,
    expected_file=None,
    require_structure_version=True,
    planner,
    db_finalize=None,
):
    state = _get_or_create_state(user_id)
    operation_id = uuid.uuid4().hex
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        _recover_locked(user_id, state)
        conn = get_db_connection()
        conn_released = False
        try:
            with conn.cursor() as cursor:
                locked_state = _load_state(cursor, user_id, for_update=True)
                before_rows = _load_entries(cursor, user_id, for_update=True)
            conn.rollback()

            if require_structure_version:
                _assert_structure_version(locked_state, expected_structure_version)
            elif expected_structure_version is not None:
                _assert_structure_version(locked_state, expected_structure_version)
            if expected_file is not None:
                entry_id, expected_version = expected_file
                row = next((item for item in before_rows if int(item["id"]) == int(entry_id)), None)
                if not row:
                    raise RepositoryDomainError("文件不存在", code="not_found", status=404)
                expected_version = _require_version(
                    expected_version, field="expected_file_version"
                )
                if int(row["file_version"]) != expected_version:
                    raise RepositoryDomainError(
                        "文件已被其他操作修改，请刷新后重试",
                        code="version_conflict",
                        status=409,
                        file_id=int(entry_id),
                        file_version=int(row["file_version"]),
                        repository_generation=int(locked_state["repository_generation"]),
                    )

            entries = _entry_models(before_rows)
            plan = planner(entries, dict(locked_state))
            final_entries = plan["entries"]
            content_overrides = plan.get("content_overrides") or {}
            structure_changed = bool(plan.get("structure_changed"))
            if plan.get("no_change"):
                resolved = {
                    f"i:{int(row['id'])}": int(row["id"]) for row in before_rows
                }
                if callable(db_finalize):
                    with conn.cursor() as cursor:
                        db_finalize(
                            cursor,
                            resolved,
                            int(locked_state["structure_version"]),
                            int(locked_state["repository_generation"]),
                        )
                    conn.commit()
                result = dict(plan.get("result") or {})
                result.update(
                    {
                        "structure_version": int(locked_state["structure_version"]),
                        "repository_generation": int(locked_state["repository_generation"]),
                        "quota": _quota_payload(locked_state),
                        "_resolved_ids": resolved,
                        "_resolved_entries": _resolved_entry_snapshots(
                            final_entries,
                            resolved,
                        ),
                    }
                )
                return result
            entry_count, total_size = _validate_final_entries(final_entries)

            payload = {
                "operation_id": operation_id,
                "operation_type": operation_type,
                "storage_key": locked_state["storage_key"],
                "structure_changed": structure_changed,
            }
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO repository_fs_journal (
                        operation_id, user_id, operation_type, status,
                        structure_version_before, payload_json
                    ) VALUES (%s, %s, %s, 'prepared', %s, %s)
                    """,
                    (
                        operation_id,
                        int(user_id),
                        operation_type,
                        int(locked_state["structure_version"]),
                        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    ),
                )
            conn.commit()

            _prepare_shadow_tree(locked_state, operation_id, final_entries, content_overrides)
            published = False
            db_committed = False
            preserve_operation_artifacts = False
            storage.publish_operation_tree(locked_state["storage_key"], operation_id)
            published = True
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE repository_fs_journal SET status = 'fs_applied' WHERE operation_id = %s",
                    (operation_id,),
                )
            # 不在这里单独提交。prepared 已足够让崩溃恢复判定“DB 最终事务
            # 未提交，应回滚已发布树”；fs_applied 必须与元数据及 committed
            # 状态在下面同一个事务中提交，避免中间 COMMIT ACK 丢失窗口。

            try:
                with conn.cursor() as cursor:
                    current_state = _load_state(cursor, user_id, for_update=True)
                    if int(current_state["repository_generation"]) != int(
                        locked_state["repository_generation"]
                    ):
                        raise RepositoryDomainError(
                            "仓库已被其他操作修改",
                            code="version_conflict",
                            status=409,
                            structure_version=int(current_state["structure_version"]),
                            repository_generation=int(current_state["repository_generation"]),
                        )
                    resolved_ids = _persist_entries(
                        cursor, user_id, before_rows, final_entries, operation_id
                    )
                    next_structure = int(current_state["structure_version"]) + (
                        1 if structure_changed else 0
                    )
                    next_generation = int(current_state["repository_generation"]) + 1
                    cursor.execute(
                        """
                        UPDATE repository_states
                        SET structure_version = %s,
                            repository_generation = %s,
                            index_status = 'stale',
                            entry_count = %s,
                            total_size = %s
                        WHERE user_id = %s
                        """,
                        (
                            next_structure, next_generation, entry_count,
                            total_size, int(user_id),
                        ),
                    )
                    if callable(db_finalize):
                        db_finalize(
                            cursor,
                            resolved_ids,
                            next_structure,
                            next_generation,
                        )
                    cursor.execute(
                        """
                        UPDATE repository_fs_journal
                        SET status = 'committed', structure_version_after = %s
                        WHERE operation_id = %s
                        """,
                        (next_structure, operation_id),
                    )
            except Exception:
                _rollback_connection_best_effort(conn)
                conn_released = _close_connection_best_effort(conn)
                try:
                    storage.rollback_operation_tree(
                        locked_state["storage_key"], operation_id
                    )
                except Exception as rollback_exc:
                    preserve_operation_artifacts = True
                    raise RepositoryDomainError(
                        "数据库事务执行失败，且文件系统无法安全回滚；"
                        "已保留 journal 现场并失败关闭",
                        code="mutation_rollback_failed",
                        status=503,
                        operation_id=operation_id,
                    ) from rollback_exc
                published = False
                _mark_mutation_rolled_back(operation_id)
                raise

            try:
                conn.commit()
            except Exception as commit_exc:
                # COMMIT 可能已经由 MySQL 持久化，只是 ACK 在网络中丢失。
                # 原连接不可作为真相源，先最佳努力释放它，再由新连接做 current read。
                _rollback_connection_best_effort(conn)
                conn_released = _close_connection_best_effort(conn)
                try:
                    commit_outcome = _probe_mutation_commit_outcome(
                        user_id,
                        operation_id,
                        structure_version_before=int(
                            locked_state["structure_version"]
                        ),
                        repository_generation_before=int(
                            locked_state["repository_generation"]
                        ),
                        structure_version_after=next_structure,
                        repository_generation_after=next_generation,
                    )
                except Exception:
                    commit_outcome = "unknown"

                if commit_outcome == "committed":
                    db_committed = True
                elif commit_outcome == "not_committed":
                    try:
                        storage.rollback_operation_tree(
                            locked_state["storage_key"], operation_id
                        )
                    except Exception as rollback_exc:
                        preserve_operation_artifacts = True
                        raise RepositoryDomainError(
                            "已确认数据库事务未提交，但文件系统无法安全回滚；"
                            "已保留 journal 现场并失败关闭",
                            code="mutation_rollback_failed",
                            status=503,
                            operation_id=operation_id,
                        ) from rollback_exc
                    published = False
                    _mark_mutation_rolled_back(operation_id)
                    raise commit_exc
                else:
                    preserve_operation_artifacts = True
                    raise RepositoryDomainError(
                        "数据库提交结果无法确认；已保留 journal 的 old/new tree "
                        "现场并失败关闭，请先运行 doctor 并人工核验",
                        code="mutation_commit_outcome_unknown",
                        status=503,
                        operation_id=operation_id,
                    ) from commit_exc
            else:
                db_committed = True
                conn_released = _close_connection_best_effort(conn)

            _finalize_committed_operation(operation_id)
            published = False
            result = dict(plan.get("result") or {})
            result.update(
                {
                    "structure_version": next_structure,
                    "repository_generation": next_generation,
                    "quota": {
                        **_quota_payload(
                            {"entry_count": entry_count, "total_size": total_size}
                        )
                    },
                }
            )
            result["_resolved_ids"] = resolved_ids
            result["_resolved_entries"] = _resolved_entry_snapshots(
                final_entries,
                resolved_ids,
            )
            return result
        except Exception as exc:
            if not conn_released:
                _rollback_connection_best_effort(conn)
            if locals().get("preserve_operation_artifacts", False):
                mapped = _domain_error(exc)
                if mapped is not exc:
                    raise mapped from exc
                raise
            recovery_needed = False
            if locals().get("published", False) and not locals().get("db_committed", False):
                try:
                    storage.rollback_operation_tree(state["storage_key"], operation_id)
                except Exception:
                    # 保留 journal + old-tree，下一次受锁访问会继续恢复。
                    recovery_needed = True
            if not recovery_needed:
                # publish_operation_tree() 会先把权威树移入 old-tree，再发布新树。
                # 若“发布新树”和“即时移回旧树”连续失败，函数尚未返回，published
                # 仍是 False；此时 old-tree 是唯一可恢复副本，绝不能按普通失败清理。
                recovery_tree = (
                    storage.operation_journal_path(operation_id) / "old-tree"
                )
                try:
                    recovery_tree.lstat()
                except FileNotFoundError:
                    pass
                except OSError:
                    # 连恢复副本是否存在都无法可靠判断时同样失败关闭并保留现场。
                    recovery_needed = True
                else:
                    recovery_needed = True
            if not recovery_needed:
                try:
                    storage.cleanup_operation_tree(operation_id)
                except Exception:
                    pass
            mapped = _domain_error(exc)
            if mapped is not exc:
                raise mapped from exc
            raise
        finally:
            if not conn_released:
                _close_connection_best_effort(conn)


def create_repository_directory(user_id, *, parent_id, name, expected_structure_version):
    safe_name = storage.validate_entry_name(name)

    def planner(entries, _state):
        parent = _validate_parent(entries, parent_id)
        parent_key = parent["_key"] if parent else None
        if _find_sibling(entries, parent_key, safe_name):
            raise RepositoryDomainError(
                "同名文件或目录已存在", code="name_conflict", status=409
            )
        path = storage.join_relative_path(_parent_path(parent), safe_name)
        key = f"n:{uuid.uuid4().hex}"
        entries.append(
            {
                "_key": key,
                "_parent_key": parent_key,
                "_old_path": None,
                "name": safe_name,
                "relative_path": path,
                "entry_type": "directory",
                "file_size": 0,
                "file_version": 0,
                "content_sha256": None,
            }
        )
        return {
            "entries": entries,
            "structure_changed": True,
            "result": {"created_key": key, "path": path},
        }

    result = _run_mutation(
        user_id,
        operation_type="create_directory",
        expected_structure_version=expected_structure_version,
        planner=planner,
    )
    result["entry_id"] = result["_resolved_ids"][result.pop("created_key")]
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    return result


def save_repository_file(
    user_id,
    *,
    content,
    entry_id=None,
    parent_id=None,
    name=None,
    expected_structure_version=None,
    expected_file_version=None,
):
    normalized = storage.normalize_source_bytes(str(content or "").encode("utf-8"))

    if entry_id is not None:
        def planner(entries, _state):
            entry = _entry_by_id(entries, entry_id)
            if not entry or entry["entry_type"] != "file":
                raise RepositoryDomainError("文件不存在", code="not_found", status=404)
            if (
                int(entry.get("file_size") or 0) == len(normalized.data)
                and entry.get("content_sha256") == normalized.sha256
            ):
                return {
                    "entries": entries,
                    "structure_changed": False,
                    "no_change": True,
                    "result": {
                        "saved_key": entry["_key"],
                        "created": False,
                        "changed": False,
                    },
                }
            entry["file_size"] = len(normalized.data)
            entry["content_sha256"] = normalized.sha256
            entry["file_version"] = int(entry["file_version"]) + 1
            return {
                "entries": entries,
                "content_overrides": {
                    entry["_key"]: {
                        "data": normalized.data,
                        "size": len(normalized.data),
                        "sha256": normalized.sha256,
                    }
                },
                "structure_changed": False,
                "result": {
                    "saved_key": entry["_key"],
                    "created": False,
                    "changed": True,
                },
            }

        result = _run_mutation(
            user_id,
            operation_type="save_file",
            expected_file=(entry_id, expected_file_version),
            require_structure_version=False,
            planner=planner,
        )
    else:
        safe_name = storage.validate_entry_name(name)

        def planner(entries, _state):
            parent = _validate_parent(entries, parent_id)
            parent_key = parent["_key"] if parent else None
            if _find_sibling(entries, parent_key, safe_name):
                raise RepositoryDomainError(
                    "同名文件或目录已存在", code="name_conflict", status=409
                )
            path = storage.join_relative_path(_parent_path(parent), safe_name)
            key = f"n:{uuid.uuid4().hex}"
            entries.append(
                {
                    "_key": key,
                    "_parent_key": parent_key,
                    "_old_path": None,
                    "name": safe_name,
                    "relative_path": path,
                    "entry_type": "file",
                    "file_size": len(normalized.data),
                    "file_version": 1,
                    "content_sha256": normalized.sha256,
                }
            )
            return {
                "entries": entries,
                "content_overrides": {
                    key: {
                        "data": normalized.data,
                        "size": len(normalized.data),
                        "sha256": normalized.sha256,
                    }
                },
                "structure_changed": True,
                "result": {"saved_key": key, "created": True},
            }

        result = _run_mutation(
            user_id,
            operation_type="create_file",
            expected_structure_version=expected_structure_version,
            planner=planner,
        )

    saved_key = result.pop("saved_key")
    saved_id = result["_resolved_ids"][saved_key]
    saved = result["_resolved_entries"][saved_key]
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    return {**result, "entry": saved, "file_id": saved_id}


def upsert_repository_file_by_path(
    user_id,
    relative_path,
    content,
    *,
    expected_structure_version=None,
    expected_file_version=None,
    overwrite=False,
):
    """内部消费者使用的递归写入接口；绝不直写 legacy 表或绕过乐观锁。"""
    safe_path = storage.validate_relative_path(relative_path)
    try:
        existing = read_repository_file(user_id, relative_path=safe_path)
    except RepositoryDomainError as exc:
        if exc.code != "not_found":
            raise
        existing = None
    if existing is not None:
        if not overwrite:
            raise RepositoryDomainError(
                f"文件已存在：{safe_path}", code="name_conflict", status=409
            )
        use_file_version = (
            existing["file_version"]
            if expected_file_version is None
            else expected_file_version
        )
        return save_repository_file(
            user_id,
            entry_id=existing["id"],
            content=content,
            expected_file_version=use_file_version,
        )

    normalized = storage.normalize_source_bytes(str(content or "").encode("utf-8"))
    parts = PurePosixPath(safe_path).parts

    def planner(entries, _state):
        parent_key = None
        current_path = ""
        structure_changed = False
        for segment in parts[:-1]:
            existing_part = _find_sibling(entries, parent_key, segment)
            if existing_part:
                if existing_part["entry_type"] != "directory":
                    raise RepositoryDomainError(
                        f"路径分量不是目录：{existing_part['relative_path']}",
                        code="name_conflict",
                        status=409,
                    )
                parent_key = existing_part["_key"]
                current_path = existing_part["relative_path"]
                continue
            key = f"n:{uuid.uuid4().hex}"
            current_path = storage.join_relative_path(current_path, segment)
            entries.append(
                {
                    "_key": key,
                    "_parent_key": parent_key,
                    "_old_path": None,
                    "name": segment,
                    "relative_path": current_path,
                    "entry_type": "directory",
                    "file_size": 0,
                    "file_version": 0,
                    "content_sha256": None,
                }
            )
            parent_key = key
            structure_changed = True
        filename = parts[-1]
        if _find_sibling(entries, parent_key, filename):
            raise RepositoryDomainError(
                f"目标已存在：{safe_path}", code="name_conflict", status=409
            )
        key = f"n:{uuid.uuid4().hex}"
        entries.append(
            {
                "_key": key,
                "_parent_key": parent_key,
                "_old_path": None,
                "name": filename,
                "relative_path": safe_path,
                "entry_type": "file",
                "file_size": len(normalized.data),
                "file_version": 1,
                "content_sha256": normalized.sha256,
            }
        )
        return {
            "entries": entries,
            "content_overrides": {key: {"data": normalized.data}},
            "structure_changed": True,
            "result": {"saved_key": key, "created": True},
        }

    result = _run_mutation(
        user_id,
        operation_type="upsert_file_path",
        expected_structure_version=expected_structure_version,
        planner=planner,
    )
    saved_key = result.pop("saved_key")
    entry_id = result["_resolved_ids"][saved_key]
    entry = result["_resolved_entries"][saved_key]
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    return {**result, "entry": entry, "file_id": entry_id}


def preview_repository_delete(user_id, entry_id):
    entry_id = int(entry_id)
    state = _get_or_create_state(user_id)
    with storage.repository_user_lock(state["storage_key"], exclusive=False):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                current_state = _load_state(cursor, user_id)
                rows = _load_entries(cursor, user_id)
                entries = _entry_models(rows)
                entry = _entry_by_id(entries, entry_id)
                if not entry:
                    raise RepositoryDomainError(
                        "文件或目录不存在", code="not_found", status=404
                    )
                keys = _collect_subtree_keys(entries, entry["_key"])
                selected = [item for item in entries if item["_key"] in keys]
                file_count = sum(1 for item in selected if item["entry_type"] == "file")
                directory_count = len(selected) - file_count
                total_size = sum(
                    int(item.get("file_size") or 0)
                    for item in selected
                    if item["entry_type"] == "file"
                )
                canonical = json.dumps(
                    [
                        {
                            "id": int(item["_key"][2:]),
                            "path": item["relative_path"],
                            "kind": item["entry_type"],
                            "file_version": int(item.get("file_version") or 0),
                            "sha256": item.get("content_sha256"),
                        }
                        for item in sorted(selected, key=lambda value: value["relative_path"])
                    ],
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                manifest_sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                token = uuid.uuid4().hex
                expires_at = datetime.now() + timedelta(minutes=10)
                cursor.execute(
                    """
                    INSERT INTO repository_delete_confirmations (
                        id, user_id, entry_id, structure_version, manifest_sha256,
                        file_count, directory_count, total_size, status, expires_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending', %s)
                    """,
                    (
                        token,
                        int(user_id),
                        entry_id,
                        int(current_state["structure_version"]),
                        manifest_sha256,
                        file_count,
                        directory_count,
                        total_size,
                        expires_at,
                    ),
                )
            conn.commit()
        finally:
            conn.close()
    return {
        "confirmation_token": token,
        "entry_id": entry_id,
        "path": entry["relative_path"],
        "kind": entry["entry_type"],
        "file_count": file_count,
        "directory_count": directory_count,
        "total_size": total_size,
        "structure_version": int(current_state["structure_version"]),
        "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
    }


def delete_repository_entry(
    user_id,
    entry_id,
    *,
    confirmation_token,
):
    entry_id = int(entry_id)
    token = storage.validate_storage_key(confirmation_token)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, entry_id, structure_version, manifest_sha256,
                       file_count, directory_count, total_size, status, result_json,
                       expires_at
                FROM repository_delete_confirmations
                WHERE id = %s AND user_id = %s
                LIMIT 1
                """,
                (token, int(user_id)),
            )
            confirmation = cursor.fetchone()
    finally:
        conn.close()
    if not confirmation or int(confirmation["entry_id"]) != entry_id:
        raise RepositoryDomainError(
            "删除确认凭证不存在或不匹配",
            code="invalid_confirmation",
            status=400,
        )
    if confirmation["status"] == "committed":
        try:
            result = json.loads(confirmation.get("result_json") or "{}")
        except (TypeError, ValueError):
            result = {}
        return {**result, "idempotent": True}
    if confirmation["status"] != "pending" or confirmation["expires_at"] <= datetime.now():
        raise RepositoryDomainError(
            "删除确认凭证已失效，请重新预览",
            code="confirmation_expired",
            status=409,
        )

    def planner(entries, _state):
        entry = _entry_by_id(entries, entry_id)
        if not entry:
            raise RepositoryDomainError("文件或目录不存在", code="not_found", status=404)
        selected_keys = _collect_subtree_keys(entries, entry["_key"])
        selected = [item for item in entries if item["_key"] in selected_keys]
        canonical = json.dumps(
            [
                {
                    "id": int(item["_key"][2:]),
                    "path": item["relative_path"],
                    "kind": item["entry_type"],
                    "file_version": int(item.get("file_version") or 0),
                    "sha256": item.get("content_sha256"),
                }
                for item in sorted(selected, key=lambda value: value["relative_path"])
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if digest != confirmation["manifest_sha256"]:
            raise RepositoryDomainError(
                "待删除内容已变化，请重新预览确认",
                code="version_conflict",
                status=409,
            )
        deleted_path = entry["relative_path"]
        deleted_keys = _delete_subtree(entries, entry["_key"])
        return {
            "entries": entries,
            "structure_changed": True,
            "result": {
                "deleted": True,
                "deleted_path": deleted_path,
                "deleted_count": len(deleted_keys),
            },
        }

    stored_result = {
        "deleted": True,
        "entry_id": entry_id,
        "deleted_count": int(confirmation["file_count"]) + int(confirmation["directory_count"]),
        "file_count": int(confirmation["file_count"]),
        "directory_count": int(confirmation["directory_count"]),
        "total_size": int(confirmation["total_size"]),
    }

    def finalize_delete(cursor, _resolved_ids, next_structure, next_generation):
        payload = {
            **stored_result,
            "structure_version": int(next_structure),
            "repository_generation": int(next_generation),
        }
        cursor.execute(
            """
            UPDATE repository_delete_confirmations
            SET status = 'committed', result_json = %s, committed_at = NOW()
            WHERE id = %s AND user_id = %s AND status = 'pending'
            """,
            (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                token,
                int(user_id),
            ),
        )
        if int(cursor.rowcount) != 1:
            raise RepositoryDomainError(
                "删除确认凭证已被使用", code="confirmation_used", status=409
            )

    result = _run_mutation(
        user_id,
        operation_type="delete_entry",
        expected_structure_version=confirmation["structure_version"],
        planner=planner,
        db_finalize=finalize_delete,
    )
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    return result


def move_repository_entry(
    user_id,
    entry_id,
    *,
    destination_parent_id,
    new_name=None,
    expected_structure_version,
    conflict_policy="error",
):
    entry_id = int(entry_id)
    policy = str(conflict_policy or "error").lower()
    if policy not in {"error", "merge"}:
        raise RepositoryDomainError(
            "conflict_policy 必须是 error 或 merge",
            code="validation_error",
            status=400,
        )

    def planner(entries, _state):
        source = _entry_by_id(entries, entry_id)
        if not source:
            raise RepositoryDomainError("文件或目录不存在", code="not_found", status=404)
        destination = _validate_parent(entries, destination_parent_id)
        destination_key = destination["_key"] if destination else None
        target_name = storage.validate_entry_name(new_name or source["name"])
        source_subtree = _collect_subtree_keys(entries, source["_key"])
        if destination_key in source_subtree:
            raise RepositoryDomainError(
                "不能把目录移动到自身或其子目录",
                code="invalid_move",
                status=400,
            )
        if source.get("_parent_key") == destination_key and source["name"] == target_name:
            return {
                "entries": entries,
                "structure_changed": False,
                "no_change": True,
                "result": {"moved_key": source["_key"], "changed": False},
            }
        conflict = _find_sibling(
            entries, destination_key, target_name, excluding=source["_key"]
        )
        if conflict:
            if (
                policy == "merge"
                and source["entry_type"] == conflict["entry_type"] == "directory"
            ):
                _merge_directories(
                    entries,
                    source["_key"],
                    conflict["_key"],
                    replace_files=False,
                )
                _delete_subtree(entries, source["_key"])
                moved_key = conflict["_key"]
            else:
                raise RepositoryDomainError(
                    f"目标已存在：{conflict['relative_path']}",
                    code="name_conflict",
                    status=409,
                    path=conflict["relative_path"],
                )
        else:
            _repath_subtree(entries, source["_key"], destination_key, target_name)
            moved_key = source["_key"]
        return {
            "entries": entries,
            "structure_changed": True,
            "result": {"moved_key": moved_key, "changed": True},
        }

    result = _run_mutation(
        user_id,
        operation_type="move_entry",
        expected_structure_version=expected_structure_version,
        planner=planner,
    )
    moved_key = result.pop("moved_key")
    moved_id = result["_resolved_ids"].get(moved_key)
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    result["entry_id"] = moved_id
    return result


def _load_upload_session(cursor, user_id, session_id, *, for_update=False):
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        """
        SELECT id, user_id, parent_id, base_structure_version, status,
               manifest_json, entry_count, total_size, expires_at,
               created_at, updated_at
        FROM repository_upload_sessions
        WHERE id = %s AND user_id = %s
        LIMIT 1
        """ + suffix,
        (storage.validate_storage_key(session_id), int(user_id)),
    )
    row = cursor.fetchone()
    if not row:
        raise RepositoryDomainError(
            "上传会话不存在", code="upload_session_not_found", status=404
        )
    try:
        row["manifest"] = json.loads(row.get("manifest_json") or "{}")
    except (TypeError, ValueError) as exc:
        raise RepositoryDomainError(
            "上传会话清单损坏", code="upload_manifest_corrupt", status=500
        ) from exc
    return row


def _read_upload_session_after_commit_error(user_id, session_id):
    """用独立连接确认上传会话 INSERT 是否已经提交。

    成功查询但没有记录可明确判定为未提交；连接或查询失败则由调用方视为
    不确定并保留 staging，不能把可能已经落库的会话文件删掉。
    """
    verification_conn = get_db_connection()
    try:
        with verification_conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, parent_id, base_structure_version, status,
                       manifest_json, entry_count, total_size, expires_at,
                       created_at, updated_at
                FROM repository_upload_sessions
                WHERE id = %s AND user_id = %s
                LIMIT 1
                FOR SHARE
                """,
                (storage.validate_storage_key(session_id), int(user_id)),
            )
            row = cursor.fetchone()
    finally:
        _rollback_connection_best_effort(verification_conn)
        _close_connection_best_effort(verification_conn)

    if not row:
        return None
    try:
        row["manifest"] = json.loads(row.get("manifest_json") or "{}")
    except (TypeError, ValueError) as exc:
        raise RepositoryDomainError(
            "上传会话已提交，但权威清单损坏；已保留 staging 并失败关闭",
            code="upload_session_manifest_corrupt",
            status=503,
            session_id=session_id,
        ) from exc
    return row


def _created_upload_session_payload(session):
    manifest = session["manifest"]
    return {
        "session_id": session["id"],
        "status": session["status"],
        "parent_id": (
            int(session["parent_id"]) if session.get("parent_id") is not None else None
        ),
        "base_structure_version": int(session["base_structure_version"]),
        "files": manifest.get("files") or [],
        "directories": manifest.get("directories") or [],
        "expires_at": _format_datetime(session.get("expires_at")),
    }


def _assert_upload_session_active(session, *, allowed_statuses):
    if session["expires_at"] <= datetime.now():
        raise RepositoryDomainError(
            "上传会话已过期", code="upload_session_expired", status=410
        )
    if session["status"] not in set(allowed_statuses):
        raise RepositoryDomainError(
            f"上传会话状态不允许此操作：{session['status']}",
            code="upload_session_state",
            status=409,
            session_status=session["status"],
        )


def _session_public_payload(session):
    manifest = session["manifest"]
    files = []
    for item in manifest.get("files") or []:
        public = {
            key: item.get(key)
            for key in (
                "token",
                "relative_path",
                "raw_size",
                "received_size",
                "raw_sha256",
                "normalized_size",
                "normalized_sha256",
                "source_encoding",
                "had_bom",
                "newline_normalized",
                "indexable",
                "only_saved",
                "status",
                "candidate_encoding",
                "encoding_confidence",
                "encoding_preview",
                "encoding_preview_truncated",
                "encoding_preview_has_disallowed_control",
                "existing_entry_id",
                "existing_file_version",
                "existing_sha256",
                "path_error",
                "message",
            )
            if key in item
        }
        files.append(public)
    directories = [
        {
            key: item.get(key)
            for key in (
                "relative_path", "status", "existing_entry_id",
                "path_error", "message",
            )
            if key in item
        }
        for item in manifest.get("directories") or []
    ]
    return {
        "session_id": session["id"],
        "status": session["status"],
        "parent_id": (
            int(session["parent_id"]) if session.get("parent_id") is not None else None
        ),
        "base_structure_version": int(session["base_structure_version"]),
        "files": files,
        "directories": directories,
        "entries": [
            *({"kind": "directory", **item} for item in directories),
            *({"kind": "file", **item} for item in files),
        ],
        "entry_count": int(session.get("entry_count") or 0),
        "total_size": int(session.get("total_size") or 0),
        "expires_at": _format_datetime(session.get("expires_at")),
    }


def _upload_manifest_staging_bytes(manifest_json):
    try:
        manifest = (
            json.loads(manifest_json)
            if isinstance(manifest_json, str)
            else dict(manifest_json or {})
        )
    except (TypeError, ValueError):
        # 无法证明既有 staging 的大小时失败关闭，不再分配更多磁盘。
        return UPLOAD_MAX_STAGING_BYTES_PER_USER + 1
    total = 0
    for item in manifest.get("files") or []:
        total += max(0, int(item.get("raw_size") or 0))
        total += max(0, int(item.get("normalized_size") or 0))
    return total


def _active_upload_staging_disk_bytes(cursor, user_id):
    """在锁住同一用户全部活跃会话后汇总宿主机上的真实暂存字节。"""
    cursor.execute(
        """
        SELECT id
        FROM repository_upload_sessions
        WHERE user_id = %s
          AND status IN ('receiving', 'needs_confirmation', 'preview_ready')
        ORDER BY id ASC
        FOR UPDATE
        """,
        (int(user_id),),
    )
    total = 0
    for row in cursor.fetchall() or []:
        try:
            total += storage.upload_session_disk_usage(row["id"])
        except FileNotFoundError:
            # 缺失 staging 会由具体操作或 doctor 报出；它不占用磁盘配额。
            continue
    return total


def _assert_upload_staging_capacity(cursor, user_id, *, additional_bytes):
    additional = max(0, int(additional_bytes or 0))
    current = _active_upload_staging_disk_bytes(cursor, user_id)
    if current + additional > UPLOAD_MAX_STAGING_BYTES_PER_USER:
        raise RepositoryDomainError(
            "活跃上传暂存总量已达上限，请先完成或取消已有会话",
            code="upload_staging_quota_exceeded",
            status=413,
            staging_bytes=current,
            requested_bytes=additional,
            max_staging_bytes=UPLOAD_MAX_STAGING_BYTES_PER_USER,
        )
    return current


def _normalize_upload_manifest_path(value):
    raw_path = unicodedata.normalize("NFC", str(value or ""))
    try:
        return storage.validate_relative_path(raw_path), None
    except storage.RepositoryPathError as exc:
        # 路径只保存在会话 JSON 中，绝不拿它访问文件系统；这样用户仍能在预览中
        # 明确排除（文件也可另存为合法路径），其余条目继续原子提交。
        return raw_path, str(exc)


def _upload_preview_session_status(manifest, *, pending_confirmation=False):
    files = manifest.get("files") or []
    if any(item.get("status") == "incomplete" for item in files):
        return "receiving"
    if pending_confirmation or any(
        item.get("status") == "encoding_confirmation_required"
        for item in files
    ):
        return "needs_confirmation"
    return "preview_ready"


def _validated_upload_encoding_confirmation(item, confirmed, *, token):
    if not confirmed:
        return None
    candidate = item.get("candidate_encoding")
    if item.get("status") != "encoding_confirmation_required" or not candidate:
        raise RepositoryDomainError(
            f"文件尚未要求编码确认：{item['relative_path']}",
            code="encoding_confirmation_not_requested",
            status=409,
            token=token,
            relative_path=item["relative_path"],
        )
    try:
        confirmed_codec = codecs.lookup(str(confirmed)).name
        candidate_codec = codecs.lookup(str(candidate)).name
    except LookupError as exc:
        raise RepositoryDomainError(
            f"编码名称非法：{item['relative_path']}",
            code="validation_error",
            status=400,
            token=token,
            relative_path=item["relative_path"],
        ) from exc
    if confirmed_codec != candidate_codec:
        raise RepositoryDomainError(
            f"确认编码与预检候选不一致：{item['relative_path']}",
            code="encoding_confirmation_mismatch",
            status=409,
            candidate_encoding=candidate_codec,
            token=token,
            relative_path=item["relative_path"],
        )
    return candidate_codec


def create_repository_upload_session(
    user_id,
    *,
    parent_id,
    expected_structure_version,
    files=None,
    entries=None,
):
    requested_entries = entries if entries is not None else files
    if not isinstance(requested_entries, list) or not requested_entries:
        raise RepositoryDomainError(
            "上传清单不能为空", code="validation_error", status=400
        )
    if len(requested_entries) > storage.MAX_ENTRIES:
        raise RepositoryDomainError(
            f"单次上传条目不能超过 {storage.MAX_ENTRIES}",
            code="quota_exceeded",
            status=413,
        )

    normalized_items = []
    normalized_directories = []
    seen_paths = set()
    raw_total = 0
    for raw_item in requested_entries:
        if not isinstance(raw_item, dict):
            raise RepositoryDomainError("上传清单格式错误", code="validation_error", status=400)
        relative_path, path_error = _normalize_upload_manifest_path(
            raw_item.get("relative_path")
        )
        if relative_path in seen_paths:
            raise RepositoryDomainError(
                f"上传清单路径重复：{relative_path}",
                code="name_conflict",
                status=409,
                relative_path=relative_path,
            )
        seen_paths.add(relative_path)
        kind = str(raw_item.get("kind") or "file").strip().lower()
        if kind == "directory":
            normalized_directories.append(
                {
                    "relative_path": relative_path,
                    "status": "invalid" if path_error else "pending",
                    **(
                        {"path_error": path_error, "message": path_error}
                        if path_error
                        else {}
                    ),
                }
            )
            continue
        if kind != "file":
            raise RepositoryDomainError(
                f"上传条目类型非法：{relative_path}",
                code="validation_error",
                status=400,
            )
        try:
            raw_size = int(raw_item.get("size"))
        except (TypeError, ValueError) as exc:
            raise RepositoryDomainError(
                f"文件大小非法：{relative_path}",
                code="validation_error",
                status=400,
            ) from exc
        if raw_size < 0 or raw_size > storage.MAX_RAW_FILE_BYTES:
            raise RepositoryDomainError(
                f"文件原始大小超限：{relative_path}",
                code="quota_exceeded",
                status=413,
            )
        raw_sha256 = str(raw_item.get("sha256") or "").strip().lower()
        if not raw_sha256:
            raise RepositoryDomainError(
                f"上传清单缺少 SHA-256：{relative_path}",
                code="hash_required",
                status=400,
                relative_path=relative_path,
            )
        if not _HEX_SHA256_RE.fullmatch(raw_sha256):
            raise RepositoryDomainError(
                f"SHA-256 格式非法：{relative_path}",
                code="validation_error",
                status=400,
            )
        raw_total += raw_size
        normalized_items.append(
            {
                "token": uuid.uuid4().hex,
                "relative_path": relative_path,
                "raw_size": raw_size,
                "received_size": 0,
                "raw_sha256": raw_sha256,
                "status": "receiving",
                **({"path_error": path_error, "message": path_error} if path_error else {}),
            }
        )
    manifest_file_paths = {
        item["relative_path"]
        for item in normalized_items
        if not item.get("path_error")
    }
    for item in [*normalized_directories, *normalized_items]:
        if item.get("path_error") or item.get("status") == "invalid":
            continue
        parts = PurePosixPath(item["relative_path"]).parts
        blocking_ancestor = next(
            (
                "/".join(parts[:index])
                for index in range(1, len(parts))
                if "/".join(parts[:index]) in manifest_file_paths
            ),
            None,
        )
        if blocking_ancestor:
            raise RepositoryDomainError(
                f"上传清单中的文件 {blocking_ancestor} 同时阻挡了后代路径 "
                f"{item['relative_path']}",
                code="manifest_type_conflict",
                status=409,
                relative_path=item["relative_path"],
                blocking_path=blocking_ancestor,
            )
    if raw_total > storage.MAX_TOTAL_BYTES * 4:
        raise RepositoryDomainError(
            "单次上传原始数据总量过大",
            code="quota_exceeded",
            status=413,
        )

    state = _get_or_create_state(user_id)
    session_id = uuid.uuid4().hex
    expires_at = datetime.now() + timedelta(seconds=UPLOAD_SESSION_TTL_SECONDS)
    manifest = {
        "version": 1,
        "files": normalized_items,
        "directories": normalized_directories,
    }
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        conn = get_db_connection()
        staging_created = False
        created_session = None
        try:
            with conn.cursor() as cursor:
                locked_state = _load_state(cursor, user_id, for_update=True)
                _assert_structure_version(locked_state, expected_structure_version)
                entries = _entry_models(_load_entries(cursor, user_id))
                parent = _validate_parent(entries, parent_id)
                parent_path = _parent_path(parent)
                for item in [*normalized_directories, *normalized_items]:
                    if item.get("path_error") or item.get("status") == "invalid":
                        continue
                    try:
                        _join_parent_relative(
                            parent_path,
                            item["relative_path"],
                        )
                    except storage.RepositoryPathError as exc:
                        item["path_error"] = str(exc)
                        item["message"] = str(exc)
                        if item in normalized_directories:
                            item["status"] = "invalid"
                cursor.execute(
                    """
                    SELECT id, manifest_json
                    FROM repository_upload_sessions
                    WHERE user_id = %s
                      AND status IN ('receiving', 'needs_confirmation', 'preview_ready')
                      AND expires_at > NOW()
                    FOR UPDATE
                    """,
                    (int(user_id),),
                )
                active_sessions = cursor.fetchall() or []
                if len(active_sessions) >= UPLOAD_MAX_ACTIVE_SESSIONS_PER_USER:
                    raise RepositoryDomainError(
                        "活跃上传会话过多，请继续、取消或等待已有会话过期",
                        code="upload_session_limit",
                        status=429,
                        max_active_sessions=UPLOAD_MAX_ACTIVE_SESSIONS_PER_USER,
                    )
                active_staging_bytes = sum(
                    _upload_manifest_staging_bytes(row.get("manifest_json"))
                    for row in active_sessions
                )
                if (
                    active_staging_bytes + raw_total
                    > UPLOAD_MAX_STAGING_BYTES_PER_USER
                ):
                    raise RepositoryDomainError(
                        "活跃上传暂存总量已达上限，请先完成或取消已有会话",
                        code="upload_staging_quota_exceeded",
                        status=413,
                        staging_bytes=active_staging_bytes,
                        requested_bytes=raw_total,
                        max_staging_bytes=UPLOAD_MAX_STAGING_BYTES_PER_USER,
                    )
                storage.prepare_upload_session(session_id)
                staging_created = True
                raw_root = storage.upload_staging_path(session_id) / "raw"
                for item in normalized_items:
                    if int(item["raw_size"]) == 0:
                        storage.atomic_write_file_in_tree(
                            raw_root, item["token"], b""
                        )
                cursor.execute(
                    """
                    INSERT INTO repository_upload_sessions (
                        id, user_id, parent_id, base_structure_version, status,
                        manifest_json, entry_count, total_size, expires_at
                    ) VALUES (%s, %s, %s, %s, 'receiving', %s, %s, %s, %s)
                    """,
                    (
                        session_id,
                        int(user_id),
                        int(parent_id) if parent_id is not None else None,
                        int(locked_state["structure_version"]),
                        json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
                        len(requested_entries),
                        raw_total,
                        expires_at,
                    ),
                )
        except Exception:
            _rollback_connection_best_effort(conn)
            if staging_created:
                storage.cleanup_upload_session(session_id)
            raise
        try:
            conn.commit()
        except Exception as commit_exc:
            # INSERT 的 COMMIT 也可能仅丢失 ACK。必须由独立连接读取 session_id，
            # 不能直接删掉一个已经被 MySQL 接受的会话所对应的 staging。
            _rollback_connection_best_effort(conn)
            _close_connection_best_effort(conn)
            try:
                authoritative_session = _read_upload_session_after_commit_error(
                    user_id, session_id
                )
            except Exception as verification_exc:
                raise RepositoryDomainError(
                    "上传会话提交结果无法确认；已保留 staging 并失败关闭，"
                    "请运行 doctor 核验孤儿暂存目录",
                    code="upload_session_commit_outcome_unknown",
                    status=503,
                    session_id=session_id,
                ) from verification_exc
            if authoritative_session is None:
                if staging_created:
                    storage.cleanup_upload_session(session_id)
                raise commit_exc
            created_session = authoritative_session
        else:
            created_session = {
                "id": session_id,
                "user_id": int(user_id),
                "parent_id": int(parent_id) if parent_id is not None else None,
                "base_structure_version": int(locked_state["structure_version"]),
                "status": "receiving",
                "manifest": manifest,
                "entry_count": len(requested_entries),
                "total_size": raw_total,
                "expires_at": expires_at,
            }
        finally:
            _close_connection_best_effort(conn)
    return _created_upload_session_payload(created_session)


def get_repository_upload_session(user_id, session_id):
    state = _get_or_create_state(user_id)
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                session = _load_upload_session(
                    cursor, user_id, session_id, for_update=True
                )
                _assert_upload_session_active(
                    session,
                    allowed_statuses={
                        "receiving", "needs_confirmation", "preview_ready",
                        "committed", "cancelled",
                    },
                )
                if session["status"] not in {"committed", "cancelled"}:
                    renewed_expiry = datetime.now() + timedelta(
                        seconds=UPLOAD_SESSION_TTL_SECONDS
                    )
                    cursor.execute(
                        """
                        UPDATE repository_upload_sessions
                        SET expires_at = %s
                        WHERE id = %s AND user_id = %s
                        """,
                        (renewed_expiry, session["id"], int(user_id)),
                    )
                    session["expires_at"] = renewed_expiry
            conn.commit()
        finally:
            conn.close()
        for item in session["manifest"].get("files") or []:
            try:
                item["received_size"] = storage.upload_file_size(
                    session["id"], item["token"]
                )
            except FileNotFoundError:
                item["received_size"] = 0
    return _session_public_payload(session)


def append_repository_upload_chunk(
    user_id,
    session_id,
    token,
    *,
    offset,
    total_size,
    data,
    chunk_sha256=None,
):
    payload = bytes(data)
    if not payload:
        raise RepositoryDomainError("上传分块不能为空", code="validation_error", status=400)
    if len(payload) > UPLOAD_CHUNK_MAX_BYTES:
        raise RepositoryDomainError(
            f"单个上传分块不能超过 {UPLOAD_CHUNK_MAX_BYTES} 字节",
            code="chunk_too_large",
            status=413,
        )
    expected_chunk_hash = str(chunk_sha256 or "").strip().lower()
    if not expected_chunk_hash:
        raise RepositoryDomainError(
            "上传分块缺少 SHA-256",
            code="hash_required",
            status=400,
        )
    if not _HEX_SHA256_RE.fullmatch(expected_chunk_hash):
        raise RepositoryDomainError("分块 SHA-256 格式非法", code="validation_error", status=400)
    actual_chunk_hash = hashlib.sha256(payload).hexdigest()
    if actual_chunk_hash != expected_chunk_hash:
        raise RepositoryDomainError(
            "上传分块 SHA-256 不匹配",
            code="chunk_hash_mismatch",
            status=422,
            actual_sha256=actual_chunk_hash,
        )
    try:
        use_offset = int(offset)
        use_total = int(total_size)
    except (TypeError, ValueError) as exc:
        raise RepositoryDomainError(
            "offset/total 必须是整数", code="validation_error", status=400
        ) from exc

    state = _get_or_create_state(user_id)
    safe_token = storage.validate_storage_key(token)
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                session = _load_upload_session(
                    cursor, user_id, session_id, for_update=True
                )
                _assert_upload_session_active(session, allowed_statuses={"receiving"})
                items = session["manifest"].get("files") or []
                item = next((value for value in items if value.get("token") == safe_token), None)
                if not item:
                    raise RepositoryDomainError(
                        "上传文件 token 不存在", code="upload_file_not_found", status=404
                    )
                if use_total != int(item["raw_size"]):
                    raise RepositoryDomainError(
                        "上传 total 与清单不一致",
                        code="chunk_total_mismatch",
                        status=409,
                        expected_total=int(item["raw_size"]),
                    )
                try:
                    actual_offset = storage.upload_file_size(session["id"], safe_token)
                except FileNotFoundError:
                    actual_offset = 0
                if use_offset != actual_offset:
                    raise RepositoryDomainError(
                        "上传 offset 不匹配",
                        code="chunk_offset_mismatch",
                        status=409,
                        expected_offset=actual_offset,
                    )
                if actual_offset + len(payload) > use_total:
                    raise RepositoryDomainError(
                        "上传分块超过清单大小",
                        code="chunk_overflow",
                        status=413,
                    )
                _assert_upload_staging_capacity(
                    cursor,
                    user_id,
                    additional_bytes=len(payload),
                )
                next_offset = storage.append_upload_chunk(
                    session["id"],
                    safe_token,
                    offset=actual_offset,
                    data=payload,
                )
                item["received_size"] = next_offset
                cursor.execute(
                    """
                    UPDATE repository_upload_sessions
                    SET manifest_json = %s, expires_at = %s
                    WHERE id = %s AND user_id = %s AND status = 'receiving'
                    """,
                    (
                        json.dumps(
                            session["manifest"],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                        datetime.now() + timedelta(seconds=UPLOAD_SESSION_TTL_SECONDS),
                        session["id"],
                        int(user_id),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
    return {
        "session_id": session["id"],
        "token": safe_token,
        "offset": next_offset,
        "total": use_total,
        "complete": next_offset == use_total,
    }


def finalize_repository_upload_session(user_id, session_id, *, encodings=None):
    encodings = encodings if isinstance(encodings, dict) else {}
    state = _get_or_create_state(user_id)
    with storage.repository_user_lock(state["storage_key"], exclusive=True):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                session = _load_upload_session(
                    cursor, user_id, session_id, for_update=True
                )
                _assert_upload_session_active(
                    session, allowed_statuses={"receiving", "needs_confirmation"}
                )
                current_state = _load_state(cursor, user_id)
                rows = _load_entries(cursor, user_id)
                path_to_entry = {row["relative_path"]: row for row in rows}
                parent = next(
                    (
                        row
                        for row in rows
                        if session.get("parent_id") is not None
                        and int(row["id"]) == int(session["parent_id"])
                    ),
                    None,
                )
                if session.get("parent_id") is not None and parent is None:
                    raise RepositoryDomainError(
                        "上传目标目录不存在", code="not_found", status=404
                    )
                if parent is not None and parent["entry_type"] != "directory":
                    raise RepositoryDomainError(
                        "上传目标不是目录", code="validation_error", status=400
                    )
                parent_path = parent["relative_path"] if parent else ""
                pending_confirmation = False
                normalized_total = 0
                normalized_writes = []

                def preview_conflict(final_path, desired_kind):
                    parts = PurePosixPath(final_path).parts
                    for index in range(1, len(parts)):
                        ancestor_path = "/".join(parts[:index])
                        ancestor = path_to_entry.get(ancestor_path)
                        if ancestor and ancestor["entry_type"] != "directory":
                            return "blocking_conflict", ancestor
                    existing = path_to_entry.get(final_path)
                    if not existing:
                        return "new", None
                    if desired_kind == "directory" and existing["entry_type"] == "directory":
                        return "merge", existing
                    if desired_kind == "file" and existing["entry_type"] == "file":
                        return "conflict", existing
                    return "blocking_conflict", existing

                for directory in session["manifest"].get("directories") or []:
                    try:
                        final_path = _join_parent_relative(
                            parent_path, directory["relative_path"]
                        )
                    except storage.RepositoryPathError as exc:
                        directory.update(
                            {
                                "status": "invalid",
                                "path_error": str(exc),
                                "message": str(exc),
                            }
                        )
                        continue
                    status, existing = preview_conflict(final_path, "directory")
                    directory.update(
                        {
                            "status": status,
                            "existing_entry_id": (
                                int(existing["id"]) if existing else None
                            ),
                            "message": (
                                "路径被文件或不同类型条目阻挡"
                                if status == "blocking_conflict"
                                else None
                            ),
                        }
                    )
                for item in session["manifest"].get("files") or []:
                    token = item["token"]
                    try:
                        received = storage.upload_file_size(session["id"], token)
                    except FileNotFoundError:
                        received = 0
                    item["received_size"] = received
                    if received != int(item["raw_size"]):
                        item.update(
                            {
                                "status": "incomplete",
                                "message": (
                                    f"尚未上传完成：{received}/{int(item['raw_size'])} 字节"
                                ),
                            }
                        )
                        continue
                    raw = storage.read_upload_file(session["id"], token)
                    actual_raw_hash = hashlib.sha256(raw).hexdigest()
                    if item["raw_sha256"] != actual_raw_hash:
                        item.update(
                            {
                                "status": "invalid",
                                "message": (
                                    "文件 SHA-256 不匹配；"
                                    f"实际为 {actual_raw_hash}"
                                ),
                            }
                        )
                        continue
                    confirmed = (
                        encodings.get(token)
                        or encodings.get(item["relative_path"])
                        or None
                    )
                    confirmed = _validated_upload_encoding_confirmation(
                        item,
                        confirmed,
                        token=token,
                    )
                    try:
                        normalized = storage.normalize_source_bytes(
                            raw, confirmed_encoding=confirmed
                        )
                    except storage.RepositoryEncodingConfirmationRequired as exc:
                        pending_confirmation = True
                        item.update(
                            {
                                "status": "encoding_confirmation_required",
                                "candidate_encoding": exc.candidate_encoding,
                                "encoding_confidence": exc.confidence,
                                "encoding_preview": exc.preview,
                                "encoding_preview_truncated": exc.preview_truncated,
                                "encoding_preview_has_disallowed_control": (
                                    exc.has_disallowed_control
                                ),
                                "message": str(exc),
                            }
                        )
                        continue
                    except (storage.RepositoryPathError, storage.RepositoryStorageError) as exc:
                        item.update(
                            {
                                "status": "invalid",
                                "message": str(exc),
                            }
                        )
                        continue
                    item.pop("candidate_encoding", None)
                    item.pop("encoding_confidence", None)
                    item.pop("encoding_preview", None)
                    item.pop("encoding_preview_truncated", None)
                    item.pop("encoding_preview_has_disallowed_control", None)
                    item.pop("message", None)
                    item.update(
                        {
                            "normalized_size": len(normalized.data),
                            "normalized_sha256": normalized.sha256,
                            "source_encoding": normalized.source_encoding,
                            "had_bom": normalized.had_bom,
                            "newline_normalized": normalized.newline_normalized,
                        }
                    )
                    normalized_total += len(normalized.data)
                    existing_normalized_matches = False
                    try:
                        existing_normalized = storage.read_upload_file(
                            session["id"], token, normalized=True
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        existing_normalized_matches = (
                            hashlib.sha256(existing_normalized).hexdigest()
                            == normalized.sha256
                            and existing_normalized == normalized.data
                        )
                    if not existing_normalized_matches:
                        normalized_writes.append((token, normalized.data))
                    try:
                        final_path = _join_parent_relative(
                            parent_path, item["relative_path"]
                        )
                    except storage.RepositoryPathError as exc:
                        item.update(
                            {
                                "status": "invalid",
                                "path_error": str(exc),
                                "message": str(exc),
                            }
                        )
                        continue
                    status, existing = preview_conflict(final_path, "file")
                    indexable = final_path.lower().endswith((".h", ".hpp", ".c", ".cpp"))
                    item.update(
                        {
                            "indexable": indexable,
                            "only_saved": not indexable,
                            "status": status,
                            "existing_entry_id": int(existing["id"]) if existing else None,
                            "existing_file_version": (
                                int(existing["file_version"])
                                if existing and existing["entry_type"] == "file"
                                else None
                            ),
                            "existing_sha256": (
                                existing.get("content_sha256")
                                if existing and existing["entry_type"] == "file"
                                else None
                            ),
                            "message": (
                                "路径被目录或上级文件阻挡"
                                if status == "blocking_conflict"
                                else None
                            ),
                        }
                    )
                _assert_upload_staging_capacity(
                    cursor,
                    user_id,
                    additional_bytes=sum(
                        len(payload) for _token, payload in normalized_writes
                    ),
                )
                for token, payload in normalized_writes:
                    storage.write_normalized_upload_file(
                        session["id"], token, payload
                    )
                session_status = _upload_preview_session_status(
                    session["manifest"],
                    pending_confirmation=pending_confirmation,
                )
                cursor.execute(
                    """
                    UPDATE repository_upload_sessions
                    SET status = %s, manifest_json = %s, total_size = %s,
                        expires_at = %s
                    WHERE id = %s AND user_id = %s
                    """,
                    (
                        session_status,
                        json.dumps(
                            session["manifest"],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                        normalized_total,
                        datetime.now() + timedelta(seconds=UPLOAD_SESSION_TTL_SECONDS),
                        session["id"],
                        int(user_id),
                    ),
                )
                session["status"] = session_status
                session["total_size"] = normalized_total
                session["expires_at"] = datetime.now() + timedelta(
                    seconds=UPLOAD_SESSION_TTL_SECONDS
                )
            conn.commit()
        finally:
            conn.close()
    result = _session_public_payload(session)
    result.update(
        {
            "ready": session["status"] == "preview_ready",
            "requires_resolution": any(
                item.get("status") in {
                    "invalid", "encoding_confirmation_required",
                    "blocking_conflict", "conflict",
                }
                for item in session["manifest"].get("files") or []
            ) or any(
                item.get("status") in {"invalid", "blocking_conflict"}
                for item in session["manifest"].get("directories") or []
            ),
            "structure_version": int(current_state["structure_version"]),
            "repository_generation": int(current_state["repository_generation"]),
            "stale": int(current_state["structure_version"])
            != int(session["base_structure_version"]),
        }
    )
    return result


def commit_repository_upload_session(
    user_id,
    session_id,
    *,
    expected_structure_version,
    resolutions=None,
    rename_targets=None,
):
    resolutions = resolutions if isinstance(resolutions, dict) else {}
    rename_targets = rename_targets if isinstance(rename_targets, dict) else {}
    state = _get_or_create_state(user_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            session = _load_upload_session(cursor, user_id, session_id)
    finally:
        conn.close()
    if session["status"] == "committed":
        try:
            result = json.loads(session["manifest"].get("result_json") or "{}")
        except (TypeError, ValueError):
            result = {}
        return {**result, "idempotent": True}
    _assert_upload_session_active(session, allowed_statuses={"preview_ready"})

    committed_keys = []
    skipped_paths = []

    def planner(entries, _state):
        parent = _validate_parent(entries, session.get("parent_id"))
        root_parent_key = parent["_key"] if parent else None
        root_parent_path = _parent_path(parent)
        content_overrides = {}
        structure_changed = False
        final_seen = set()
        excluded_directory_prefixes = []

        def ensure_directory(relative_directory):
            nonlocal structure_changed
            parent_key = root_parent_key
            current_path = root_parent_path
            if not relative_directory:
                return parent_key
            for segment in PurePosixPath(relative_directory).parts:
                safe_segment = storage.validate_entry_name(segment)
                existing = _find_sibling(entries, parent_key, safe_segment)
                if existing:
                    if existing["entry_type"] != "directory":
                        raise RepositoryDomainError(
                            f"上传路径与文件冲突：{existing['relative_path']}",
                            code="name_conflict",
                            status=409,
                        )
                    parent_key = existing["_key"]
                    current_path = existing["relative_path"]
                    continue
                key = f"n:{uuid.uuid4().hex}"
                current_path = storage.join_relative_path(current_path, safe_segment)
                entries.append(
                    {
                        "_key": key,
                        "_parent_key": parent_key,
                        "_old_path": None,
                        "name": safe_segment,
                        "relative_path": current_path,
                        "entry_type": "directory",
                        "file_size": 0,
                        "file_version": 0,
                        "content_sha256": None,
                    }
                )
                parent_key = key
                structure_changed = True
            return parent_key

        for directory in sorted(
            session["manifest"].get("directories") or [],
            key=lambda item: (
                item["relative_path"].count("/"),
                item["relative_path"],
            ),
        ):
            directory_path = directory["relative_path"]
            if any(
                directory_path == prefix
                or directory_path.startswith(prefix + "/")
                for prefix in excluded_directory_prefixes
            ):
                skipped_paths.append(directory_path)
                continue
            directory_resolution = str(
                resolutions.get(directory_path) or "error"
            ).lower()
            if directory_resolution == "exclude":
                excluded_directory_prefixes.append(directory_path)
                skipped_paths.append(directory_path)
                continue
            if directory.get("status") == "invalid":
                raise RepositoryDomainError(
                    f"上传目录尚未解决：{directory_path}；只能明确 exclude",
                    code="upload_item_unresolved",
                    status=409,
                )
            if directory.get("status") == "blocking_conflict":
                raise RepositoryDomainError(
                    f"上传目录路径被文件阻挡：{directory_path}；只能明确 exclude",
                    code="name_conflict",
                    status=409,
                )
            before_count = len(entries)
            ensure_directory(directory_path)
            if len(entries) != before_count:
                structure_changed = True

        for item in session["manifest"].get("files") or []:
            original_path = item["relative_path"]
            resolution = str(resolutions.get(original_path) or "error").lower()
            if any(
                original_path == prefix or original_path.startswith(prefix + "/")
                for prefix in excluded_directory_prefixes
            ):
                skipped_paths.append(original_path)
                continue
            item_status = str(item.get("status") or "")
            if item_status in {
                "encoding_confirmation_required", "incomplete",
            }:
                if resolution == "exclude":
                    skipped_paths.append(original_path)
                    continue
                raise RepositoryDomainError(
                    f"上传条目尚未解决：{original_path}；请确认编码或明确 exclude",
                    code="upload_item_unresolved",
                    status=409,
                )
            if item_status == "invalid":
                if resolution == "exclude":
                    skipped_paths.append(original_path)
                    continue
                path_can_be_renamed = (
                    resolution == "rename"
                    and item.get("normalized_size") is not None
                    and item.get("normalized_sha256")
                )
                if not path_can_be_renamed:
                    raise RepositoryDomainError(
                        f"上传条目无效：{original_path}；"
                        "只有已完成正文校验的路径错误可另存为，其余只能 exclude",
                        code="upload_item_unresolved",
                        status=409,
                    )
            if item_status == "blocking_conflict":
                if resolution == "exclude":
                    skipped_paths.append(original_path)
                    continue
                if resolution != "rename":
                    raise RepositoryDomainError(
                        f"上传条目存在类型阻挡：{original_path}；只能 rename 或 exclude",
                        code="name_conflict",
                        status=409,
                    )
            elif resolution in {"skip", "exclude"}:
                skipped_paths.append(original_path)
                continue
            if resolution not in {"error", "overwrite", "rename"}:
                raise RepositoryDomainError(
                    f"上传冲突策略非法：{original_path}",
                    code="validation_error",
                    status=400,
                )
            target_relative = original_path
            if resolution == "rename":
                target_relative = storage.validate_relative_path(
                    rename_targets.get(original_path)
                )
            if target_relative in final_seen:
                raise RepositoryDomainError(
                    f"上传目标重复：{target_relative}",
                    code="name_conflict",
                    status=409,
                )
            final_seen.add(target_relative)
            target = PurePosixPath(target_relative)
            parent_key = ensure_directory(
                "" if str(target.parent) == "." else str(target.parent)
            )
            safe_name = storage.validate_entry_name(target.name)
            existing = _find_sibling(entries, parent_key, safe_name)
            if existing:
                if existing["entry_type"] != "file":
                    raise RepositoryDomainError(
                        f"上传文件不能覆盖目录：{existing['relative_path']}",
                        code="name_conflict",
                        status=409,
                    )
                if resolution != "overwrite":
                    raise RepositoryDomainError(
                        f"文件已存在：{existing['relative_path']}",
                        code="name_conflict",
                        status=409,
                        path=existing["relative_path"],
                    )
                if (
                    int(existing["id"]) != int(item.get("existing_entry_id") or 0)
                    or int(existing["file_version"])
                    != int(item.get("existing_file_version") or 0)
                    or existing.get("content_sha256") != item.get("existing_sha256")
                ):
                    raise RepositoryDomainError(
                        f"预览后文件已变化：{existing['relative_path']}，请重新预检",
                        code="version_conflict",
                        status=409,
                        entry_id=int(existing["id"]),
                        file_version=int(existing["file_version"]),
                    )
                key = existing["_key"]
                # 显式 upload overwrite 是一次新写入：即使字节相同也保留稳定 ID、
                # 递增 file_version/repository_generation，区别于编辑器保存的 no-op。
                existing["file_size"] = int(item["normalized_size"])
                existing["file_version"] = int(existing["file_version"]) + 1
                existing["content_sha256"] = item["normalized_sha256"]
                content_overrides[key] = {
                    "source_tree": storage.upload_staging_path(session["id"])
                    / "normalized",
                    "source_path": item["token"],
                    "size": int(item["normalized_size"]),
                    "sha256": item["normalized_sha256"],
                }
            else:
                key = f"n:{uuid.uuid4().hex}"
                parent_entry = _map_entries(entries).get(parent_key) if parent_key else None
                entries.append(
                    {
                        "_key": key,
                        "_parent_key": parent_key,
                        "_old_path": None,
                        "name": safe_name,
                        "relative_path": storage.join_relative_path(
                            _parent_path(parent_entry), safe_name
                        ),
                        "entry_type": "file",
                        "file_size": int(item["normalized_size"]),
                        "file_version": 1,
                        "content_sha256": item["normalized_sha256"],
                    }
                )
                structure_changed = True
                content_overrides[key] = {
                    "source_tree": storage.upload_staging_path(session["id"])
                    / "normalized",
                    "source_path": item["token"],
                    "size": int(item["normalized_size"]),
                    "sha256": item["normalized_sha256"],
                }
            committed_keys.append((key, target_relative))

        return {
            "entries": entries,
            "content_overrides": content_overrides,
            "structure_changed": structure_changed,
            "no_change": not content_overrides and not structure_changed,
            "result": {
                "committed_count": len(committed_keys),
                "skipped": list(skipped_paths),
            },
        }

    def finalize_session(cursor, resolved_ids, next_structure, next_generation):
        committed = [
            {"entry_id": int(resolved_ids[key]), "relative_path": relative_path}
            for key, relative_path in committed_keys
        ]
        result = {
            "session_id": session["id"],
            "committed": committed,
            "committed_count": len(committed),
            "skipped": list(skipped_paths),
            "structure_version": int(next_structure),
            "repository_generation": int(next_generation),
        }
        manifest = dict(session["manifest"])
        manifest["result_json"] = json.dumps(
            result, ensure_ascii=False, separators=(",", ":")
        )
        cursor.execute(
            """
            UPDATE repository_upload_sessions
            SET status = 'committed', manifest_json = %s
            WHERE id = %s AND user_id = %s AND status = 'preview_ready'
            """,
            (
                json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
                session["id"],
                int(user_id),
            ),
        )
        if int(cursor.rowcount) != 1:
            raise RepositoryDomainError(
                "上传会话已被提交或取消",
                code="upload_session_state",
                status=409,
            )

    result = _run_mutation(
        user_id,
        operation_type="upload_commit",
        expected_structure_version=expected_structure_version,
        planner=planner,
        db_finalize=finalize_session,
    )
    committed = [
        {
            "entry_id": int(result["_resolved_ids"][key]),
            "relative_path": relative_path,
        }
        for key, relative_path in committed_keys
    ]
    result.pop("_resolved_ids", None)
    result.pop("_resolved_entries", None)
    result.update({"session_id": session["id"], "committed": committed})
    try:
        storage.cleanup_upload_session(session["id"])
    except Exception:
        pass
    return result


def cancel_repository_upload_session(user_id, session_id):
    safe_session_id = storage.validate_storage_key(session_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            session = _load_upload_session(
                cursor, user_id, safe_session_id, for_update=True
            )
            if session["status"] == "committed":
                raise RepositoryDomainError(
                    "已提交的上传会话不能取消",
                    code="upload_session_state",
                    status=409,
                )
            cursor.execute(
                """
                UPDATE repository_upload_sessions
                SET status = 'cancelled'
                WHERE id = %s AND user_id = %s
                """,
                (safe_session_id, int(user_id)),
            )
        conn.commit()
    finally:
        conn.close()
    storage.cleanup_upload_session(safe_session_id)
    return {"session_id": safe_session_id, "cancelled": True}


def _find_orphan_upload_staging(known_session_ids, *, now):
    known = {
        storage.validate_storage_key(session_id)
        for session_id in (known_session_ids or ())
    }
    cutoff_timestamp = (
        now - timedelta(seconds=UPLOAD_ORPHAN_GRACE_SECONDS)
    ).timestamp()
    staging_root = storage.ensure_repository_storage_ready() / "staging"
    orphans = []
    for candidate in staging_root.iterdir():
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            # 类型异常交给 doctor/quarantine，自动清理绝不触碰不安全节点。
            continue
        try:
            session_id = storage.validate_storage_key(candidate.name)
        except storage.RepositoryStorageError:
            continue
        if session_id in known or float(info.st_mtime) > cutoff_timestamp:
            continue
        orphans.append(session_id)
    return sorted(orphans)


def cleanup_expired_repository_upload_sessions(*, apply=False, now=None):
    """审计或清理过期上传暂存。

    默认只返回候选清单。实际清理时会逐行加锁并再次比较 ``expires_at``，因此与会
    刷新 TTL 的上传请求并发时不会误删仍活跃会话；DB 状态提交后才移除对应 staging。
    """
    cutoff = now or datetime.now()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, status, expires_at
                FROM repository_upload_sessions
                WHERE expires_at <= %s
                ORDER BY expires_at ASC, id ASC
                """,
                (cutoff,),
            )
            candidates = cursor.fetchall() or []
            cursor.execute(
                "SELECT id FROM repository_upload_sessions ORDER BY id ASC"
            )
            known_session_ids = {
                row["id"] for row in (cursor.fetchall() or [])
            }
    finally:
        conn.close()
    orphan_candidates = _find_orphan_upload_staging(
        known_session_ids,
        now=cutoff,
    )
    report = {
        "apply": bool(apply),
        "cutoff": _format_datetime(cutoff),
        "candidates": [
            {
                "session_id": row["id"],
                "user_id": int(row["user_id"]),
                "status": row["status"],
                "expires_at": _format_datetime(row["expires_at"]),
            }
            for row in candidates
        ],
        "cleaned": [],
        "skipped": [],
        "orphan_candidates": orphan_candidates,
        "orphan_cleaned": [],
    }
    if not apply:
        return report

    for candidate in candidates:
        session_id = storage.validate_storage_key(candidate["id"])
        should_cleanup = False
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                session = _load_upload_session(
                    cursor,
                    candidate["user_id"],
                    session_id,
                    for_update=True,
                )
                if session["expires_at"] > cutoff:
                    report["skipped"].append(
                        {
                            "session_id": session_id,
                            "reason": "ttl_renewed",
                        }
                    )
                else:
                    if session["status"] in {
                        "receiving", "needs_confirmation", "preview_ready",
                    }:
                        cursor.execute(
                            """
                            UPDATE repository_upload_sessions
                            SET status = 'expired'
                            WHERE id = %s AND user_id = %s
                              AND expires_at <= %s
                              AND status IN (
                                'receiving', 'needs_confirmation', 'preview_ready'
                              )
                            """,
                            (session_id, int(candidate["user_id"]), cutoff),
                        )
                        should_cleanup = int(cursor.rowcount) == 1
                    else:
                        # committed/cancelled/expired 可能因之前的最佳努力清理失败而留有
                        # staging；过期后可以安全重试。
                        should_cleanup = True
            conn.commit()
        except RepositoryDomainError as exc:
            conn.rollback()
            if exc.code == "upload_session_not_found":
                report["skipped"].append(
                    {"session_id": session_id, "reason": "row_removed"}
                )
                continue
            raise
        finally:
            conn.close()
        if not should_cleanup:
            continue
        try:
            storage.cleanup_upload_session(session_id)
        except FileNotFoundError:
            pass
        report["cleaned"].append(session_id)
    for session_id in orphan_candidates:
        try:
            storage.cleanup_upload_session(session_id)
        except FileNotFoundError:
            pass
        report["orphan_cleaned"].append(session_id)
    return report
