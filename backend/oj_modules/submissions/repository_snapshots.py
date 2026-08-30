#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编程提交所绑定的不可变代码仓库快照。

新提交在 ``submissions`` 同一事务内写入快照绑定；快照真实树位于仓库存储根的
``snapshots/<snapshot_key>/tree``。实时仓库写文件使用 temp + ``os.replace``，
因此这里对普通文件建立硬链接后，后续保存会换 inode，不会改变历史快照。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import stat
import uuid

from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.repository import storage as repository_storage


logger = logging.getLogger(__name__)

LEGACY_BOUNDARY_SETTING = "repository_snapshot_legacy_max_submission_id"
MANIFEST_FILENAME = "manifest.json"


class RepositorySnapshotError(RuntimeError):
    """仓库快照缺失、不一致或无法安全读取。"""


class RepositorySnapshotRequiredError(RepositorySnapshotError):
    """新提交缺少强制快照绑定。"""


def _canonical_manifest_bytes(document: dict) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _assert_safe_source(tree_root: Path, relative_path: str, *, expect_directory: bool) -> Path:
    safe_path = repository_storage.validate_relative_path(relative_path)
    current = tree_root
    parts = safe_path.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise RepositorySnapshotError(f"仓库磁盘条目缺失：{safe_path}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RepositorySnapshotError(f"仓库树包含符号链接：{safe_path}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise RepositorySnapshotError(f"仓库父路径不是目录：{safe_path}")

    info = current.lstat()
    if expect_directory:
        if not stat.S_ISDIR(info.st_mode):
            raise RepositorySnapshotError(f"仓库目录元数据与磁盘不一致：{safe_path}")
    elif not stat.S_ISREG(info.st_mode):
        raise RepositorySnapshotError(f"仓库文件元数据与磁盘不一致：{safe_path}")
    return current


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_tree_directories(tree_root: Path) -> None:
    directories = []
    for current_root, dirnames, _filenames in os.walk(tree_root, followlinks=False):
        current = Path(current_root)
        directories.append(current)
        for dirname in dirnames:
            info = (current / dirname).lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RepositorySnapshotError("快照临时树包含非法目录")
    for directory in reversed(directories):
        _fsync_directory(directory)


def _load_locked_repository_manifest(cursor, user_id: int, storage_key: str) -> tuple[int, list[dict]]:
    cursor.execute(
        """
        SELECT storage_key, repository_generation, entry_count, total_size
        FROM repository_states
        WHERE user_id = %s
        FOR SHARE
        """,
        (int(user_id),),
    )
    state = cursor.fetchone()
    if not state:
        raise RepositorySnapshotError("仓库状态在快照期间消失")
    if str(state.get("storage_key") or "") != storage_key:
        raise RepositorySnapshotError("仓库存储标识在快照期间发生变化")

    cursor.execute(
        """
        SELECT id, parent_id, relative_path, entry_type, file_size,
               file_version, content_sha256
        FROM repository_entries
        WHERE user_id = %s
        ORDER BY relative_path ASC
        FOR SHARE
        """,
        (int(user_id),),
    )
    rows = sorted(
        cursor.fetchall() or [],
        key=lambda row: (
            str(row.get("relative_path") or "").count("/"),
            str(row.get("relative_path") or ""),
        ),
    )
    entries = []
    seen_paths = set()
    directory_paths = set()
    total_size = 0
    for row in rows:
        path = repository_storage.validate_relative_path(row.get("relative_path"))
        if path in seen_paths:
            raise RepositorySnapshotError(f"仓库元数据存在重复路径：{path}")
        seen_paths.add(path)
        entry_type = str(row.get("entry_type") or "")
        if entry_type not in {"file", "directory"}:
            raise RepositorySnapshotError(f"仓库条目类型非法：{path}")
        parent_path = path.rpartition("/")[0]
        if parent_path and parent_path not in directory_paths:
            # 显式按深度排序，不能依赖数据库 collation 对路径前缀的排序细节。
            raise RepositorySnapshotError(f"仓库条目缺少父目录元数据：{path}")

        item = {
            "entry_id": int(row.get("id")),
            "path": path,
            "type": entry_type,
        }
        if entry_type == "directory":
            directory_paths.add(path)
        else:
            size = int(row.get("file_size") or 0)
            version = int(row.get("file_version") or 0)
            content_sha256 = str(row.get("content_sha256") or "")
            if size < 0 or version < 1 or len(content_sha256) != 64:
                raise RepositorySnapshotError(f"仓库文件元数据非法：{path}")
            item.update({
                "size": size,
                "file_version": version,
                "sha256": content_sha256,
            })
            total_size += size
        entries.append(item)

    if int(state.get("entry_count") or 0) != len(entries):
        raise RepositorySnapshotError("仓库条目计数与状态不一致")
    if int(state.get("total_size") or 0) != total_size:
        raise RepositorySnapshotError("仓库总大小与状态不一致")
    return int(state.get("repository_generation") or 0), entries


def _load_repository_state(cursor, user_id: int, *, for_share: bool = False):
    suffix = " FOR SHARE" if for_share else ""
    cursor.execute(
        """
        SELECT storage_key, repository_generation, entry_count, total_size
        FROM repository_states
        WHERE user_id = %s
        """ + suffix,
        (int(user_id),),
    )
    return cursor.fetchone()


def capture_submission_repository_snapshot(cursor, *, submission_id: int, user_id: int) -> dict:
    """捕获并写入一条提交快照绑定。

    调用者必须处于创建 ``submissions`` 行的同一数据库事务中。任何错误都会抛出，
    由调用者回滚提交，绝不降级为实时仓库。
    """

    submission_id = int(submission_id)
    user_id = int(user_id)
    if submission_id <= 0 or user_id <= 0:
        raise RepositorySnapshotError("提交或用户标识非法")

    repository_storage.ensure_repository_storage_ready()
    # 锁前这次普通读只用于取得创建后不再变化的 storage_key；不能把这里建立的
    # REPEATABLE READ 快照用于 manifest。权威状态与 entries 必须在 FS shared lock
    # 内通过 FOR SHARE current reads 获取。
    initial_state = _load_repository_state(cursor, user_id)
    storage_key = str((initial_state or {}).get("storage_key") or "")

    # 尚未打开过仓库的用户也要有一份显式空快照。直接在当前提交事务里初始化
    # state，避免“无 state 的空仓库”和首次建仓并发时得到不明确的版本。
    if not storage_key:
        candidate = uuid.uuid4().hex
        cursor.execute(
            """
            INSERT INTO repository_states (
                user_id, storage_key, structure_version, repository_generation,
                active_index_generation, index_status, entry_count, total_size
            )
            VALUES (%s, %s, 1, 1, NULL, 'stale', 0, 0)
            """,
            (user_id, candidate),
        )
        storage_key = candidate
        initial_state = {
            "storage_key": candidate,
            "repository_generation": 1,
            "entry_count": 0,
            "total_size": 0,
        }
        repository_storage.ensure_user_tree(candidate)

    snapshot_key = uuid.uuid4().hex
    snapshots_root = repository_storage.ensure_repository_storage_ready() / "snapshots"
    temporary_base = snapshots_root / f".{snapshot_key}.tmp"
    final_base = snapshots_root / snapshot_key
    temporary_tree = temporary_base / "tree"
    manifest_entries = []
    generation = 0

    try:
        temporary_tree.mkdir(mode=0o700, parents=True, exist_ok=False)
        storage_key = repository_storage.validate_storage_key(storage_key)
        with repository_storage.repository_user_lock(storage_key, exclusive=False):
            generation, manifest_entries = _load_locked_repository_manifest(
                cursor,
                user_id,
                storage_key,
            )
            live_tree = repository_storage.ensure_user_tree(storage_key)
            for item in manifest_entries:
                relative_path = item["path"]
                destination = temporary_tree.joinpath(*relative_path.split("/"))
                if item["type"] == "directory":
                    source = _assert_safe_source(
                        live_tree,
                        relative_path,
                        expect_directory=True,
                    )
                    destination.mkdir(mode=stat.S_IMODE(source.lstat().st_mode))
                    continue

                source = _assert_safe_source(
                    live_tree,
                    relative_path,
                    expect_directory=False,
                )
                source_info = source.lstat()
                if int(source_info.st_size) != int(item["size"]):
                    raise RepositorySnapshotError(
                        f"仓库文件大小与元数据不一致：{relative_path}"
                    )
                actual_hash = _sha256_file(source)
                if actual_hash != item["sha256"]:
                    raise RepositorySnapshotError(
                        f"仓库文件摘要与元数据不一致：{relative_path}"
                    )
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.link(source, destination, follow_symlinks=False)

            # shared flock 应阻止写者；再次读取仍用于发现未遵守锁契约的实现。
            final_state = _load_repository_state(cursor, user_id, for_share=True)
            if (
                not final_state
                or str(final_state.get("storage_key") or "") != storage_key
                or int(final_state.get("repository_generation") or 0) != generation
            ):
                raise RepositorySnapshotError("仓库在快照期间发生变化，请重试提交")

        manifest = {
            "schema_version": 1,
            "submission_id": submission_id,
            "user_id": user_id,
            "repository_generation": generation,
            "entries": manifest_entries,
        }
        manifest_bytes = _canonical_manifest_bytes(manifest)
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_path = temporary_base / MANIFEST_FILENAME
        fd = os.open(
            manifest_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        try:
            view = memoryview(manifest_bytes)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)

        _fsync_tree_directories(temporary_tree)
        _fsync_directory(temporary_base)
        os.replace(temporary_base, final_base)
        _fsync_directory(snapshots_root)

        total_size = sum(
            int(item.get("size") or 0)
            for item in manifest_entries
            if item.get("type") == "file"
        )
        relative_root = f"snapshots/{snapshot_key}/tree"
        cursor.execute(
            """
            INSERT INTO submission_repository_snapshots (
                submission_id, user_id, snapshot_key, relative_root,
                repository_generation, manifest_sha256, entry_count, total_size
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                submission_id,
                user_id,
                snapshot_key,
                relative_root,
                generation,
                manifest_sha256,
                len(manifest_entries),
                total_size,
            ),
        )
        return {
            "snapshot_key": snapshot_key,
            "relative_root": relative_root,
            "repository_generation": generation,
            "manifest_sha256": manifest_sha256,
            "entry_count": len(manifest_entries),
            "total_size": total_size,
        }
    except Exception:
        if temporary_base.exists():
            shutil.rmtree(temporary_base, ignore_errors=True)
        # final_base 只有在 manifest 完整 fsync 后才出现。若随后的 DB INSERT 失败，
        # 保留这个无绑定快照比误删一次结果不确定的提交快照更安全；离线清理由
        # “无 DB 引用且超过宽限期”规则回收。
        raise


def _snapshot_base_from_row(
    row: dict,
    *,
    storage_root: Path | None = None,
) -> Path:
    snapshot_key = repository_storage.validate_storage_key(row.get("snapshot_key"))
    expected_relative = f"snapshots/{snapshot_key}/tree"
    if str(row.get("relative_root") or "") != expected_relative:
        raise RepositorySnapshotError("快照根路径元数据非法")
    root = (
        Path(storage_root)
        if storage_root is not None
        else repository_storage.ensure_repository_storage_ready()
    )
    snapshots_root = root / "snapshots"
    try:
        snapshots_root_info = snapshots_root.lstat()
    except OSError as exc:
        raise RepositorySnapshotError("提交仓库快照受管根缺失") from exc
    if (
        stat.S_ISLNK(snapshots_root_info.st_mode)
        or not stat.S_ISDIR(snapshots_root_info.st_mode)
    ):
        raise RepositorySnapshotError("提交仓库快照受管根不是安全目录")
    base = snapshots_root / snapshot_key
    try:
        info = base.lstat()
    except OSError as exc:
        raise RepositorySnapshotError("提交仓库快照根缺失") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RepositorySnapshotError("快照根不是安全目录")
    return base


def _read_regular_snapshot_file(path: Path, *, description: str) -> bytes:
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise RepositorySnapshotError(f"{description}缺失或不是安全普通文件") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RepositorySnapshotError(f"{description}不是安全普通文件")
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _snapshot_tree_inventory(tree: Path) -> dict[str, str]:
    try:
        tree_info = tree.lstat()
    except OSError as exc:
        raise RepositorySnapshotError("提交仓库快照 tree 根缺失") from exc
    if stat.S_ISLNK(tree_info.st_mode) or not stat.S_ISDIR(tree_info.st_mode):
        raise RepositorySnapshotError("提交仓库快照 tree 根不是安全目录")

    inventory = {}
    for current_root, directory_names, file_names in os.walk(
        tree,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        safe_directories = []
        for name in directory_names:
            path = current / name
            relative_path = path.relative_to(tree).as_posix()
            try:
                info = path.lstat()
                safe_path = repository_storage.validate_relative_path(relative_path)
            except (OSError, repository_storage.RepositoryPathError) as exc:
                raise RepositorySnapshotError(
                    f"提交仓库快照包含非法目录：{relative_path}"
                ) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise RepositorySnapshotError(
                    f"提交仓库快照包含符号链接或非普通目录：{safe_path}"
                )
            inventory[safe_path] = "directory"
            safe_directories.append(name)
        directory_names[:] = safe_directories

        for name in file_names:
            path = current / name
            relative_path = path.relative_to(tree).as_posix()
            try:
                info = path.lstat()
                safe_path = repository_storage.validate_relative_path(relative_path)
            except (OSError, repository_storage.RepositoryPathError) as exc:
                raise RepositorySnapshotError(
                    f"提交仓库快照包含非法文件：{relative_path}"
                ) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise RepositorySnapshotError(
                    f"提交仓库快照包含符号链接或非普通文件：{safe_path}"
                )
            inventory[safe_path] = "file"
    return inventory


def _read_snapshot_entries(
    row: dict,
    *,
    storage_root: Path | None = None,
) -> list[dict]:
    base = _snapshot_base_from_row(row, storage_root=storage_root)
    try:
        base_children = {entry.name for entry in os.scandir(base)}
    except OSError as exc:
        raise RepositorySnapshotError("无法枚举提交仓库快照根") from exc
    expected_base_children = {MANIFEST_FILENAME, "tree"}
    if base_children != expected_base_children:
        raise RepositorySnapshotError("提交仓库快照根包含缺失或未登记条目")

    manifest_path = base / MANIFEST_FILENAME
    manifest_bytes = _read_regular_snapshot_file(
        manifest_path,
        description="提交仓库快照清单",
    )
    actual_manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_manifest_hash != str(row.get("manifest_sha256") or ""):
        raise RepositorySnapshotError("提交仓库快照清单摘要不匹配")
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepositorySnapshotError("提交仓库快照清单损坏") from exc

    if int(manifest.get("schema_version") or 0) != 1:
        raise RepositorySnapshotError("提交仓库快照清单版本不受支持")
    if int(manifest.get("submission_id") or 0) != int(row.get("submission_id") or 0):
        raise RepositorySnapshotError("提交仓库快照所属提交不匹配")
    if int(manifest.get("user_id") or 0) != int(row.get("user_id") or 0):
        raise RepositorySnapshotError("提交仓库快照所属用户不匹配")

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise RepositorySnapshotError("提交仓库快照清单格式非法")
    if int(row.get("entry_count") or 0) != len(entries):
        raise RepositorySnapshotError("提交仓库快照条目计数不匹配")
    if int(manifest.get("repository_generation") or 0) != int(
        row.get("repository_generation") or 0
    ):
        raise RepositorySnapshotError("提交仓库快照代次不匹配")

    tree = base / "tree"
    result = []
    total_size = 0
    seen = set()
    expected_inventory = {}
    for item in entries:
        if not isinstance(item, dict):
            raise RepositorySnapshotError("提交仓库快照条目格式非法")
        relative_path = repository_storage.validate_relative_path(item.get("path"))
        if relative_path in seen:
            raise RepositorySnapshotError("提交仓库快照包含重复路径")
        seen.add(relative_path)
        if item.get("type") == "directory":
            _assert_safe_source(tree, relative_path, expect_directory=True)
            expected_inventory[relative_path] = "directory"
            result.append({
                "relative_path": relative_path,
                "entry_type": "directory",
                "type": "directory",
                "file_size": 0,
            })
            continue
        if item.get("type") != "file":
            raise RepositorySnapshotError("提交仓库快照包含非法条目类型")
        source = _assert_safe_source(tree, relative_path, expect_directory=False)
        expected_inventory[relative_path] = "file"
        data = _read_regular_snapshot_file(
            source,
            description=f"提交仓库快照文件 {relative_path}",
        )
        expected_size = int(item.get("size") or 0)
        expected_hash = str(item.get("sha256") or "")
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
            raise RepositorySnapshotError(f"提交仓库快照文件校验失败：{relative_path}")
        try:
            content = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RepositorySnapshotError(
                f"提交仓库快照文件不是 UTF-8：{relative_path}"
            ) from exc
        result.append({
            "relative_path": relative_path,
            "filename": relative_path,
            "entry_type": "file",
            "type": "file",
            "content": content,
            "file_size": expected_size,
            "content_sha256": expected_hash,
            "file_version": int(item.get("file_version") or 0),
        })
        total_size += expected_size
    if total_size != int(row.get("total_size") or 0):
        raise RepositorySnapshotError("提交仓库快照总大小不匹配")
    actual_inventory = _snapshot_tree_inventory(tree)
    if actual_inventory != expected_inventory:
        raise RepositorySnapshotError("提交仓库快照 tree 与清单条目集合不匹配")
    result.sort(key=lambda item: item["relative_path"])
    return result


def verify_submission_repository_snapshot(
    row: dict,
    *,
    storage_root: Path | None = None,
) -> None:
    """严格核验一条 DB 快照绑定、manifest 与不可变树的全部文件摘要。"""
    _read_snapshot_entries(row, storage_root=storage_root)


def _legacy_boundary(cursor) -> int:
    cursor.execute(
        "SELECT v FROM site_settings WHERE k = %s",
        (LEGACY_BOUNDARY_SETTING,),
    )
    row = cursor.fetchone()
    if not row:
        raise RepositorySnapshotRequiredError("缺少历史提交快照边界，拒绝读取实时仓库")
    try:
        boundary = int(row.get("v"))
    except (TypeError, ValueError) as exc:
        raise RepositorySnapshotRequiredError("历史提交快照边界配置非法") from exc
    return max(0, boundary)


def resolve_submission_repository_user_id(submission_id: int) -> int:
    """以快照绑定优先解析提交所属稳定 user_id，历史提交再按同步后的用户名解析。"""

    submission_id = int(submission_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id
                FROM submission_repository_snapshots
                WHERE submission_id = %s
                """,
                (submission_id,),
            )
            row = cursor.fetchone()
            if row:
                return int(row["user_id"])
            cursor.execute(
                """
                SELECT u.id AS user_id
                FROM submissions s
                INNER JOIN users u ON u.username = s.username
                WHERE s.id = %s
                LIMIT 1
                """,
                (submission_id,),
            )
            row = cursor.fetchone()
            if row:
                return int(row["user_id"])
    finally:
        conn.close()
    raise RepositorySnapshotRequiredError(f"提交 #{submission_id} 的仓库用户不存在")


def load_submission_repository_entries(
    submission_id: int,
    user_id: int,
    *,
    allow_legacy_fallback: bool = True,
) -> list[dict]:
    """读取提交绑定的完整不可变仓库树；仅明确历史提交可 legacy fallback。"""

    submission_id = int(submission_id)
    user_id = int(user_id)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT submission_id, user_id, snapshot_key, relative_root,
                       repository_generation, manifest_sha256, entry_count, total_size
                FROM submission_repository_snapshots
                WHERE submission_id = %s AND user_id = %s
                """,
                (submission_id, user_id),
            )
            row = cursor.fetchone()
            if row:
                return _read_snapshot_entries(row)
            if not allow_legacy_fallback:
                raise RepositorySnapshotRequiredError(
                    f"提交 #{submission_id} 没有仓库快照，禁止读取实时仓库"
                )
            boundary = _legacy_boundary(cursor)
            cursor.execute(
                """
                SELECT 1
                FROM submissions s
                INNER JOIN users u ON u.username = s.username
                WHERE s.id = %s AND u.id = %s
                LIMIT 1
                """,
                (submission_id, user_id),
            )
            if not cursor.fetchone():
                raise RepositorySnapshotRequiredError("历史提交与仓库用户不匹配")
    finally:
        conn.close()

    if submission_id > boundary:
        raise RepositorySnapshotRequiredError(
            f"提交 #{submission_id} 缺少强制仓库快照绑定"
        )

    logger.warning(
        "legacy submission %s (user %s) has no repository snapshot; "
        "falling back to the current repository",
        submission_id,
        user_id,
    )
    from backend.oj_modules.repository.tree import get_repository_tree_snapshot

    snapshot = get_repository_tree_snapshot(user_id, include_content=True)
    result = []
    for item in snapshot.get("entries") or []:
        entry_type = str(item.get("kind") or item.get("entry_type") or "")
        result.append({
            **item,
            "relative_path": item.get("relative_path") or item.get("filename"),
            "entry_type": entry_type,
            "type": entry_type,
        })
    return result


def load_submission_repository_files(
    submission_id: int,
    user_id: int,
    *,
    allow_legacy_fallback: bool = True,
) -> list[dict]:
    return [
        item
        for item in load_submission_repository_entries(
            submission_id,
            user_id,
            allow_legacy_fallback=allow_legacy_fallback,
        )
        if item.get("entry_type") == "file"
    ]


def load_submission_repository_file_map(
    submission_id: int,
    user_id: int,
    *,
    allow_legacy_fallback: bool = True,
) -> dict[str, str]:
    return {
        str(item["relative_path"]): str(item.get("content") or "")
        for item in load_submission_repository_files(
            submission_id,
            user_id,
            allow_legacy_fallback=allow_legacy_fallback,
        )
    }
