"""VibeHub 持久快照与上传暂存的周期维护。

模块导入和配置注册都不会创建目录、连接数据库或启动线程。Web worker 必须通过
``ensure_vibehub_storage_gc`` 显式启动 daemon。每轮严格沿用业务写入的锁序：先取得
全局 ``storage_mutation_lock``，再用 ``FOR UPDATE`` 锁定全部社区作品与版本 live-set，
最后调用存储层经过 inode 绑定和完整审计的回收原语。
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import logging
import math
from pathlib import Path
import re
import threading
import time

from oj_modules.infrastructure.mysql import get_db_connection
from oj_modules.project_paths import PROJECT_ROOT
from oj_modules.vibehub import quotas, storage


DEFAULT_STORAGE_GC_INTERVAL_SECONDS = 15 * 60.0
MIN_CONFIGURED_STORAGE_GC_INTERVAL_SECONDS = 60.0
MAX_STORAGE_GC_INTERVAL_SECONDS = 24 * 60 * 60.0
MIN_SERVICE_STORAGE_GC_INTERVAL_SECONDS = 0.05
MAX_GC_PROJECTS = 10_000
MAX_GC_VERSIONS = 1_000_000

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_LOGGER = logging.getLogger(__name__)


class VibeHubMaintenanceError(RuntimeError):
    """后台维护无法安全取得完整 DB live-set。"""


@dataclass(frozen=True, slots=True)
class VibeHubStorageGCResult:
    """一次完整维护循环的三类回收结果。"""

    crash_orphans: storage.CrashOrphanGCResult
    snapshots: storage.SnapshotRetirementGCResult
    upload_staging: quotas.UploadStagingReclaimResult


def _positive_id(value, *, label: str) -> int:
    if isinstance(value, bool):
        raise VibeHubMaintenanceError(f"{label} 无效")
    try:
        selected = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise VibeHubMaintenanceError(f"{label} 无效") from exc
    if selected <= 0:
        raise VibeHubMaintenanceError(f"{label} 无效")
    return selected


def _optional_positive_id(value, *, label: str) -> int | None:
    if value in (None, ""):
        return None
    return _positive_id(value, label=label)


def _locked_snapshot_gc_states(cursor) -> tuple[dict, ...]:
    """有界锁定全部社区作品与版本，并生成存储层需要的 live-set。"""

    cursor.execute(
        """
        SELECT id, slug, latest_version_id, public_version_id, review_version_id
        FROM vibehub_projects
        WHERE project_kind = 'container'
        ORDER BY id
        LIMIT %s
        FOR UPDATE
        """,
        (MAX_GC_PROJECTS + 1,),
    )
    project_rows = list(cursor.fetchall() or [])
    if len(project_rows) > MAX_GC_PROJECTS:
        raise VibeHubMaintenanceError("VibeHub 后台回收作品数量超过安全上限")

    projects: dict[int, dict] = {}
    slugs: set[str] = set()
    for row in project_rows:
        if not isinstance(row, Mapping):
            raise VibeHubMaintenanceError("VibeHub 后台回收作品元数据格式无效")
        project_id = _positive_id(row.get("id"), label="VibeHub 作品 ID")
        raw_slug = row.get("slug")
        slug = raw_slug if isinstance(raw_slug, str) else ""
        if (
            not _SLUG_RE.fullmatch(slug)
            or project_id in projects
            or slug in slugs
        ):
            raise VibeHubMaintenanceError("VibeHub 后台回收作品元数据冲突")
        projects[project_id] = {
            "slug": slug,
            "references": (
                _optional_positive_id(
                    row.get("latest_version_id"),
                    label="VibeHub latest version ID",
                ),
                _optional_positive_id(
                    row.get("public_version_id"),
                    label="VibeHub public version ID",
                ),
                _optional_positive_id(
                    row.get("review_version_id"),
                    label="VibeHub review version ID",
                ),
            ),
            "versions": {},
            "numbers": set(),
        }
        slugs.add(slug)

    cursor.execute(
        """
        SELECT v.project_id, v.id, v.version_number
        FROM vibehub_versions v
        INNER JOIN vibehub_projects p ON p.id = v.project_id
        WHERE p.project_kind = 'container'
        ORDER BY v.project_id, v.version_number
        LIMIT %s
        FOR UPDATE
        """,
        (MAX_GC_VERSIONS + 1,),
    )
    version_rows = list(cursor.fetchall() or [])
    if len(version_rows) > MAX_GC_VERSIONS:
        raise VibeHubMaintenanceError("VibeHub 后台回收版本数量超过安全上限")

    seen_version_ids: set[int] = set()
    for row in version_rows:
        if not isinstance(row, Mapping):
            raise VibeHubMaintenanceError("VibeHub 后台回收版本元数据格式无效")
        project_id = _positive_id(row.get("project_id"), label="VibeHub 版本作品 ID")
        version_id = _positive_id(row.get("id"), label="VibeHub 版本 ID")
        version_number = _positive_id(
            row.get("version_number"),
            label="VibeHub 版本号",
        )
        project = projects.get(project_id)
        if (
            project is None
            or version_id in seen_version_ids
            or version_number in project["numbers"]
        ):
            raise VibeHubMaintenanceError("VibeHub 后台回收版本元数据冲突")
        seen_version_ids.add(version_id)
        project["versions"][version_id] = version_number
        project["numbers"].add(version_number)

    states = []
    for project_id in sorted(projects):
        project = projects[project_id]
        identity_map = project["versions"]
        live = set()
        for version_id in project["references"]:
            if version_id is None:
                continue
            try:
                live.add(identity_map[version_id])
            except KeyError as exc:
                raise VibeHubMaintenanceError(
                    "VibeHub 后台回收 live-set 引用了缺失版本"
                ) from exc
        states.append(
            {
                "slug": project["slug"],
                "known_versions": set(identity_map.values()),
                "live_versions": live,
            }
        )
    return tuple(states)


def run_storage_gc_once(
    *,
    upload_root: Path | str | None = None,
    connection_factory: Callable | None = None,
    now: float | None = None,
    snapshot_grace_seconds: float = storage.SNAPSHOT_RETIREMENT_GRACE_SECONDS,
    upload_staging_grace_seconds: int = quotas.DEFAULT_UPLOAD_STAGING_GRACE_SECONDS,
) -> VibeHubStorageGCResult:
    """执行一次快照和上传暂存回收，并在整个过程保持统一锁序。"""

    root = Path(upload_root) if upload_root is not None else storage.VIBEHUB_UPLOAD_ROOT
    connect = connection_factory or get_db_connection
    with quotas.storage_mutation_lock(root):
        conn = connect()
        try:
            with conn.cursor() as cursor:
                project_states = _locked_snapshot_gc_states(cursor)
                orphan_result = storage.reclaim_expired_crash_orphans(
                    project_states,
                    upload_root=root,
                    now=now,
                    grace_seconds=storage.CRASH_ORPHAN_GRACE_SECONDS,
                )
                snapshot_result = storage.reclaim_expired_retired_snapshots(
                    project_states,
                    upload_root=root,
                    now=now,
                    grace_seconds=snapshot_grace_seconds,
                )
                # 活跃上传从创建到安装始终持有同一个 storage_mutation_lock；
                # 后台取得锁后不存在需要额外排除的在途 staging。
                staging_result = quotas.reclaim_expired_upload_staging(
                    root,
                    grace_seconds=upload_staging_grace_seconds,
                    now=now,
                )
            return VibeHubStorageGCResult(
                orphan_result,
                snapshot_result,
                staging_result,
            )
        finally:
            try:
                # SELECT ... FOR UPDATE 只建立本轮文件系统回收所需的事实快照；
                # 维护线程从不写数据库，rollback 释放行锁且不制造提交语义。
                conn.rollback()
            finally:
                conn.close()


def _validated_interval(value, *, configured: bool) -> float:
    if isinstance(value, bool):
        raise ValueError("VIBEHUB_STORAGE_GC_INTERVAL_SECONDS 必须是有限数字")
    try:
        interval = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("VIBEHUB_STORAGE_GC_INTERVAL_SECONDS 必须是有限数字") from exc
    minimum = (
        MIN_CONFIGURED_STORAGE_GC_INTERVAL_SECONDS
        if configured
        else MIN_SERVICE_STORAGE_GC_INTERVAL_SECONDS
    )
    if not math.isfinite(interval) or not minimum <= interval <= MAX_STORAGE_GC_INTERVAL_SECONDS:
        raise ValueError(
            "VIBEHUB_STORAGE_GC_INTERVAL_SECONDS 必须在 "
            f"{minimum:g}–{MAX_STORAGE_GC_INTERVAL_SECONDS:g} 秒之间"
        )
    return interval


class VibeHubStorageGC:
    """单进程幂等的周期 GC；单轮失败不会结束 daemon。"""

    def __init__(
        self,
        *,
        upload_root: Path | str = storage.VIBEHUB_UPLOAD_ROOT,
        interval_seconds: float = DEFAULT_STORAGE_GC_INTERVAL_SECONDS,
        connection_factory: Callable | None = None,
        run_once_callback: Callable[[], VibeHubStorageGCResult | object] | None = None,
    ) -> None:
        self.upload_root = Path(upload_root)
        self.interval_seconds = _validated_interval(
            interval_seconds,
            configured=False,
        )
        self.connection_factory = connection_factory
        self._run_once_callback = run_once_callback
        self._run_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def run_once(self):
        with self._run_lock:
            if self._run_once_callback is not None:
                return self._run_once_callback()
            return run_storage_gc_once(
                upload_root=self.upload_root,
                connection_factory=self.connection_factory,
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                # 维护失败只能保留待回收数据并在下一轮重试，不能终止 Web。
                _LOGGER.exception("VibeHub 后台存储回收失败，将在下一周期重试")
            if self._stop.wait(self.interval_seconds):
                return

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            thread = threading.Thread(
                target=self._loop,
                name="vibehub-storage-gc",
                daemon=True,
            )
            self._thread = thread
            try:
                thread.start()
            except Exception:
                self._thread = None
                raise

    def stop(self, *, timeout: float = 2.0) -> None:
        with self._lifecycle_lock:
            thread = self._thread
            self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        with self._lifecycle_lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None

    def is_running(self) -> bool:
        with self._lifecycle_lock:
            return self._thread is not None and self._thread.is_alive()


def _config_value(source, name: str, default):
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _maintenance_kwargs_from_config(config_source) -> dict:
    interval = _validated_interval(
        _config_value(
            config_source,
            "VIBEHUB_STORAGE_GC_INTERVAL_SECONDS",
            DEFAULT_STORAGE_GC_INTERVAL_SECONDS,
        ),
        configured=True,
    )
    raw_root = _config_value(
        config_source,
        "VIBEHUB_UPLOAD_ROOT",
        storage.VIBEHUB_UPLOAD_ROOT,
    )
    if raw_root in (None, ""):
        raw_root = storage.VIBEHUB_UPLOAD_ROOT
    selected_root = Path(raw_root)
    if not selected_root.is_absolute():
        selected_root = PROJECT_ROOT / selected_root
    resolved_root = selected_root.resolve(strict=False)
    if resolved_root in {Path("/"), PROJECT_ROOT.resolve()} or len(resolved_root.parts) < 3:
        raise ValueError("VIBEHUB_UPLOAD_ROOT 不能指向宽泛系统或项目根目录")
    return {
        "upload_root": resolved_root,
        "interval_seconds": interval,
    }


_default_gc: VibeHubStorageGC | None = None
_default_gc_lock = threading.Lock()
_registered_gc_kwargs: dict | None = None


def register_storage_gc_config(config_source) -> None:
    """注册惰性配置；不会访问数据库、文件系统或启动后台线程。"""

    global _registered_gc_kwargs
    kwargs = _maintenance_kwargs_from_config(config_source)
    with _default_gc_lock:
        if _default_gc is not None:
            raise VibeHubMaintenanceError("VibeHub storage GC 已初始化，不能重新注册配置")
        if _registered_gc_kwargs is not None and _registered_gc_kwargs != kwargs:
            raise VibeHubMaintenanceError("VibeHub storage GC 配置已注册")
        _registered_gc_kwargs = kwargs


def get_storage_gc() -> VibeHubStorageGC:
    global _default_gc
    if _default_gc is None:
        with _default_gc_lock:
            if _default_gc is None:
                _default_gc = VibeHubStorageGC(**dict(_registered_gc_kwargs or {}))
    return _default_gc


def ensure_vibehub_storage_gc() -> VibeHubStorageGC:
    """Web worker 启动时幂等确保周期维护线程存活。"""

    service = get_storage_gc()
    service.start()
    return service


def shutdown_vibehub_storage_gc(*, reset_config: bool = False) -> None:
    """停止默认后台线程，供进程关闭和测试使用。"""

    global _default_gc, _registered_gc_kwargs
    with _default_gc_lock:
        service = _default_gc
        _default_gc = None
        if reset_config:
            _registered_gc_kwargs = None
    if service is not None:
        service.stop()


__all__ = [
    "DEFAULT_STORAGE_GC_INTERVAL_SECONDS",
    "MAX_GC_PROJECTS",
    "MAX_GC_VERSIONS",
    "VibeHubMaintenanceError",
    "VibeHubStorageGC",
    "VibeHubStorageGCResult",
    "ensure_vibehub_storage_gc",
    "get_storage_gc",
    "register_storage_gc_config",
    "run_storage_gc_once",
    "shutdown_vibehub_storage_gc",
]
