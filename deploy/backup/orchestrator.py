#!/usr/bin/env python3
"""Choose, create, validate, and retain deployment database backups."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Collection, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO, Iterator, TextIO


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.mysql_admin import (  # noqa: E402
    MySQLSettings,
    connect_mysql,
    database_exists,
    settings_from_config,
)
from deploy.backup import apt as percona_apt  # noqa: E402
from deploy.backup import physical as xtrabackup  # noqa: E402
from deploy.backup.paths import (  # noqa: E402
    UnsafePathError,
    absolute_lexical_path,
    assert_no_symlink_components,
    ensure_directory,
    existing_directory,
    managed_path,
    validate_layout,
)


MANIFEST_SCHEMA = "numericaloj.mysql-backup"
MANIFEST_SCHEMA_VERSION = 1
PLAN_SCHEMA = "numericaloj.mysql-backup-plan"
PLAN_SCHEMA_VERSION = 1
COPY_CHUNK_BYTES = 1024 * 1024
PROGRESS_INTERVAL_SECONDS = 1.0
MYSQLDUMP_BINARY = Path("/usr/bin/mysqldump")
SUDO_BINARY = Path("/usr/bin/sudo")
PRIVILEGED_HELPER = ROOT / "deploy" / "backup" / "privileged.py"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GENERATION_FILE_NAME = ".deployment-generation"
MAX_DEPLOYMENT_GENERATION = 2**63 - 1
SAFE_SUBPROCESS_ENV_KEYS = (
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
)
_MISSING_DATABASE_NOTICE = (
    b"-- NumericalOJ pre-deploy state: configured database did not exist.\n"
)


@dataclass(frozen=True)
class DatabaseSnapshot:
    """The small amount of server metadata safe to persist in a manifest."""

    version: str
    version_comment: str
    database_exists: bool


@dataclass(frozen=True)
class DatabaseDiscovery:
    snapshot: DatabaseSnapshot
    estimated_bytes: int
    estimated_tables: int


class PreflightError(RuntimeError):
    """A deployment backup precondition failed before service shutdown."""


class PlanError(RuntimeError):
    """A persisted orchestration plan is malformed or no longer applicable."""


class PruneError(RuntimeError):
    """One or more old successful backup artifacts could not be removed."""


@dataclass(frozen=True)
class DumpStatistics:
    raw_bytes: int
    compressed_bytes: int
    elapsed_seconds: float

    @property
    def throughput_bytes_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.raw_bytes / self.elapsed_seconds


@dataclass(frozen=True)
class GzipValidation:
    raw_bytes: int
    sha256: str


class _DigestingReader:
    """Minimal sequential file facade used to hash gzip bytes during validation."""

    def __init__(self, source: BinaryIO) -> None:
        self._source = source
        self._digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        chunk = self._source.read(size)
        self._digest.update(chunk)
        return chunk

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        # Gzip's sequential reader may ask for the current position, but a
        # backwards seek would hash bytes twice and invalidate the artifact ID.
        if offset == 0 and whence == os.SEEK_CUR:
            return self._source.tell()
        raise OSError("gzip validation reader is intentionally non-seekable")

    def tell(self) -> int:
        return self._source.tell()

    @property
    def hexdigest(self) -> str:
        return self._digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def inspect_database(settings: MySQLSettings) -> DatabaseSnapshot:
    """Read server identity and database existence through the app connection."""

    connection = connect_mysql(settings, with_database=False, dict_rows=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT VERSION() AS version, "
                "@@version_comment AS version_comment"
            )
            row = cursor.fetchone() or {}
            return DatabaseSnapshot(
                version=str(row.get("version", "unknown")),
                version_comment=str(row.get("version_comment", "unknown")),
                database_exists=database_exists(cursor, settings.database),
            )
    finally:
        connection.close()


def discover_database(settings: MySQLSettings) -> DatabaseDiscovery:
    """Read only metadata supported by both MySQL and unsupported forks."""

    connection = connect_mysql(settings, with_database=False, dict_rows=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT VERSION() AS version, "
                "@@version_comment AS version_comment"
            )
            row = cursor.fetchone() or {}
            exists = database_exists(cursor, settings.database)
            cursor.execute(
                "SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) "
                "AS estimated_bytes, COUNT(*) AS estimated_tables "
                "FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=%s",
                (settings.database,),
            )
            size_row = cursor.fetchone() or {}
            estimated_bytes = int(size_row.get("estimated_bytes") or 0)
            estimated_tables = int(size_row.get("estimated_tables") or 0)
            if estimated_bytes < 0 or estimated_tables < 0:
                raise PreflightError("information_schema 返回了负容量")
            return DatabaseDiscovery(
                snapshot=DatabaseSnapshot(
                    version=str(row.get("version", "unknown")),
                    version_comment=str(row.get("version_comment", "unknown")),
                    database_exists=exists,
                ),
                estimated_bytes=estimated_bytes,
                estimated_tables=estimated_tables,
            )
    finally:
        connection.close()


def query_xtrabackup_metadata(settings: MySQLSettings) -> xtrabackup.ServerMetadata:
    connection = connect_mysql(settings, with_database=False, dict_rows=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(xtrabackup.SERVER_METADATA_SQL)
            row = cursor.fetchone()
            if row is None:
                raise PreflightError("MySQL 未返回 XtraBackup 元数据")
            return xtrabackup.ServerMetadata.from_query_row(row)
    finally:
        connection.close()


def _validate_run_id(run_id: str) -> str:
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise PlanError(f"run-id 无效: {run_id!r}")
    return run_id


def _assert_no_symlink_components(path: Path) -> None:
    try:
        assert_no_symlink_components(path, label="备份路径")
    except UnsafePathError as exc:
        raise PreflightError(str(exc)) from exc


def prepare_backup_layout(backup_root: Path) -> dict[str, Path]:
    try:
        root = absolute_lexical_path(backup_root, label="backup root")
    except UnsafePathError as exc:
        raise PreflightError(str(exc)) from exc
    _assert_no_symlink_components(root.parent)
    if root.is_symlink():
        raise PreflightError(f"backup root 不能是符号链接: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    _assert_no_symlink_components(root)
    metadata = root.stat()
    root_mode = stat.S_IMODE(metadata.st_mode)
    root_is_user_owned = metadata.st_uid == os.geteuid()
    root_is_hardened = metadata.st_uid == 0 and root_mode == 0o711
    if not root.is_dir() or not (root_is_user_owned or root_is_hardened):
        raise PreflightError("backup root 必须由部署用户拥有或为 root:root 0711")
    if root_is_user_owned:
        os.chmod(root, 0o700)
        if not os.access(root, os.W_OK | os.X_OK):
            raise PreflightError("backup root 不可写")

    layout = {"root": root}
    for name in ("plans", "logical", "physical", "manifests"):
        directory = root / name
        if directory.is_symlink():
            raise PreflightError(f"备份子目录不能是符号链接: {directory}")
        if not directory.exists():
            if root_is_hardened:
                raise PreflightError(f"硬化后的 backup root 缺少受管目录: {directory}")
            directory.mkdir(mode=0o700)
        child = directory.stat(follow_symlinks=False)
        child_mode = stat.S_IMODE(child.st_mode)
        if name == "physical" and child.st_uid == 0 and child_mode == 0o711:
            pass
        elif child.st_uid == os.geteuid():
            os.chmod(directory, 0o700)
        else:
            raise PreflightError(f"备份子目录 owner/mode 无效: {directory}")
        layout[name] = directory

    try:
        layout = validate_layout(
            root,
            ("plans", "logical", "physical", "manifests"),
        )
    except UnsafePathError as exc:
        raise PreflightError(str(exc)) from exc

    descriptor, probe_name = tempfile.mkstemp(
        prefix=".write-probe-", dir=layout["plans"]
    )
    probe = Path(probe_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
        probe.unlink(missing_ok=True)
    return layout


def allocate_deployment_generation(backup_root: Path) -> int:
    """Allocate a host-local causal deployment order under an advisory lock."""

    try:
        root = existing_directory(backup_root, label="backup root")
        generation_path = managed_path(
            root / "plans",
            GENERATION_FILE_NAME,
            label="deployment generation",
            allow_missing_leaf=True,
        )
    except UnsafePathError as exc:
        raise PreflightError(str(exc)) from exc
    if generation_path.is_symlink():
        raise PreflightError("deployment generation 不能是符号链接")

    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(generation_path, flags, 0o600)
    except OSError as exc:
        raise PreflightError("无法安全打开 deployment generation") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PreflightError("deployment generation 必须是普通文件")
        if metadata.st_uid != os.geteuid():
            raise PreflightError("deployment generation 不属于当前部署用户")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PreflightError("deployment generation 权限必须是 0600")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = os.read(descriptor, 128)
        if os.read(descriptor, 1):
            raise PreflightError("deployment generation 文件异常过大")
        text = payload.decode("ascii").strip()
        if text:
            if re.fullmatch(r"[0-9]+", text) is None:
                raise PreflightError("deployment generation 内容无效")
            previous = int(text)
        else:
            previous = 0
        generation = previous + 1
        if generation > MAX_DEPLOYMENT_GENERATION:
            raise PreflightError("deployment generation 已耗尽")
        encoded = f"{generation}\n".encode("ascii")
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    except UnicodeDecodeError as exc:
        raise PreflightError("deployment generation 内容无效") from exc
    finally:
        os.close(descriptor)
    _fsync_directory(root / "plans")
    return generation


def _privileged_helper_command(*arguments: str) -> list[str]:
    return [
        str(SUDO_BINARY),
        "-n",
        "--",
        sys.executable,
        "-I",
        "-B",
        str(PRIVILEGED_HELPER),
        *arguments,
    ]


def harden_physical_backup_layout(
    backup_root: Path,
    physical_directory: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Pin and harden the privileged physical-backup pathname before shutdown."""

    root_before = backup_root.lstat()
    physical_before = physical_directory.lstat()
    execute = runner or subprocess.run
    execute(
        _privileged_helper_command(
            "harden-physical-layout",
            "--backup-root",
            str(backup_root),
            "--expected-root-dev",
            str(root_before.st_dev),
            "--expected-root-ino",
            str(root_before.st_ino),
            "--expected-physical-dev",
            str(physical_before.st_dev),
            "--expected-physical-ino",
            str(physical_before.st_ino),
        ),
        check=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    root_after = backup_root.lstat()
    physical_after = physical_directory.lstat()
    for label, before, after in (
        ("backup root", root_before, root_after),
        ("physical directory", physical_before, physical_after),
    ):
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or after.st_uid != 0
            or after.st_gid != 0
            or stat.S_IMODE(after.st_mode) != 0o711
        ):
            raise PreflightError(f"{label} 特权硬化后身份或权限无效")


def _logical_capacity(
    directory: Path, *, estimated_bytes: int, estimated_inodes: int
) -> dict[str, int | None]:
    usage = os.statvfs(directory)
    block_size = usage.f_frsize or usage.f_bsize
    free_bytes = usage.f_bavail * block_size
    total_bytes = usage.f_blocks * block_size
    free_inodes = usage.f_favail if usage.f_files > 0 else None
    # --hex-blob can expand binary payloads to roughly twice their table size.
    required_bytes = max(estimated_bytes * 2 + 64 * 1024 * 1024, 64 * 1024 * 1024)
    reserved_bytes = max(total_bytes // 10, 2 * 1024 * 1024 * 1024)
    required_inodes = max(estimated_inodes * 2 + 32, 64)
    if free_bytes < required_bytes + reserved_bytes:
        raise PreflightError(
            "logical备份空间不足: "
            f"required={required_bytes}, reserve={reserved_bytes}, free={free_bytes}"
        )
    if free_inodes is not None and free_inodes < required_inodes:
        raise PreflightError(
            f"logical备份 inode 不足: required={required_inodes}, free={free_inodes}"
        )
    return {
        "estimated_bytes": estimated_bytes,
        "estimated_inodes": estimated_inodes,
        "required_bytes": required_bytes,
        "required_inodes": required_inodes,
        "reserved_bytes": reserved_bytes,
        "free_bytes": free_bytes,
        "free_inodes": free_inodes,
    }


def validate_logical_preflight(
    settings: MySQLSettings,
    discovery: DatabaseDiscovery,
    logical_directory: Path,
) -> dict[str, int | None]:
    if not MYSQLDUMP_BINARY.is_file() or not os.access(MYSQLDUMP_BINARY, os.X_OK):
        raise PreflightError(f"mysqldump 不可执行: {MYSQLDUMP_BINARY}")
    for value in (settings.host, settings.user, settings.password):
        _option_file_value(value)
    # The gzip artifact is normally smaller, but reserving the raw table size
    # prevents an incompressible dump from exhausting the deployment volume.
    return _logical_capacity(
        logical_directory,
        estimated_bytes=discovery.estimated_bytes,
        estimated_inodes=4,
    )


def _publish_new_json(path: Path, document: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"拒绝覆盖已有 JSON: {path}")
    partial = path.with_name(f".{path.name}.partial")
    if partial.exists() or partial.is_symlink():
        raise FileExistsError(f"拒绝覆盖遗留 partial: {partial}")
    try:
        _write_json_file(partial, document)
        os.replace(partial, path)
        _fsync_directory(path.parent)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def create_preflight_plan(
    plan_path: Path,
    backup_root: Path,
    run_id: str,
    config=None,
    *,
    provisioner: Callable[..., percona_apt.ProvisionResult] | None = None,
    physical_plan_preparer: Callable[..., xtrabackup.XtraBackupPlan | None] | None = None,
    capacity_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    physical_layout_hardener: Callable[[Path, Path], None] | None = None,
) -> dict[str, object]:
    run_id = _validate_run_id(run_id)
    layout = prepare_backup_layout(backup_root)
    expected_plan = layout["plans"] / f"{run_id}.json"
    if plan_path.absolute() != expected_plan:
        raise PlanError(f"plan 必须位于 {expected_plan}")

    settings = settings_from_config(config)
    discovery = discover_database(settings)
    snapshot = discovery.snapshot
    release = percona_apt.select_release(snapshot.version, snapshot.version_comment)
    strategy = "logical"
    decision_reason = "no_compatible_xtrabackup_mapping"
    physical_plan: xtrabackup.XtraBackupPlan | None = None
    capacity: dict[str, object]

    if release is not None:
        install = provisioner or percona_apt.provision_xtrabackup
        try:
            install(release, work_directory=layout["plans"])
        except percona_apt.ProvisioningError as exc:
            decision_reason = "xtrabackup_provisioning_failed"
            print(
                "[backup_database] XtraBackup 自动安装失败，本次按约定回退到 "
                f"mysqldump: {exc}",
                file=sys.stderr,
            )
        else:
            metadata = query_xtrabackup_metadata(settings)
            prepare = physical_plan_preparer or xtrabackup.prepare_plan
            with xtrabackup_option_file(
                settings, layout["plans"], metadata.socket
            ) as defaults_file:
                physical_plan = prepare(
                    metadata,
                    mysql_host=settings.host,
                    mysql_defaults_file=defaults_file,
                )
            if physical_plan is None:
                raise PreflightError("已 provision 的服务端未能生成 physical plan")
            harden = physical_layout_hardener or harden_physical_backup_layout
            harden(layout["root"], layout["physical"])
            capacity = xtrabackup.preflight_physical_capacity(
                physical_plan, layout["physical"], runner=capacity_runner
            ).to_dict()
            strategy = "physical"
            decision_reason = "compatible_xtrabackup_preflight_passed"

    if strategy == "logical":
        capacity = validate_logical_preflight(
            settings, discovery, layout["logical"]
        )
        capacity["progress_estimated_raw_bytes"] = estimate_raw_bytes(
            layout["manifests"], settings.database
        )

    artifact = (
        layout["physical"] / run_id
        if strategy == "physical"
        else layout["logical"] / f"{run_id}.sql.gz"
    )
    manifest = layout["manifests"] / f"{run_id}.manifest.json"
    generation = allocate_deployment_generation(layout["root"])
    document: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_SCHEMA_VERSION,
        "created_at": _utc_now(),
        "run_id": run_id,
        "generation": generation,
        "backup_root": str(layout["root"]),
        "strategy": strategy,
        "decision_reason": decision_reason,
        "database": settings.database,
        "server": {
            "version": snapshot.version,
            "version_comment": snapshot.version_comment,
        },
        "artifact_relative_path": os.path.relpath(artifact, layout["root"]),
        "manifest_relative_path": os.path.relpath(manifest, layout["root"]),
        "capacity": capacity,
        "xtrabackup_plan": physical_plan.to_dict() if physical_plan else None,
    }
    _publish_new_json(expected_plan, document)
    return document


def _option_file_value(value: object) -> str:
    text = str(value)
    if any(character in text for character in ("\x00", "\r", "\n")):
        raise ValueError("MySQL option-file values must not contain control lines")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


@contextmanager
def mysql_option_file(
    settings: MySQLSettings, directory: Path
) -> Iterator[Path]:
    """Create a short-lived 0600 client file so credentials never enter argv/env."""

    descriptor, raw_path = tempfile.mkstemp(
        prefix=".mysql-backup-credentials-", suffix=".cnf", dir=directory
    )
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        body = "\n".join(
            (
                "[client]",
                f"host={_option_file_value(settings.host)}",
                f"port={settings.port}",
                f"user={_option_file_value(settings.user)}",
                f"password={_option_file_value(settings.password)}",
                "protocol=TCP",
                "",
            )
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = -1
        yield path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)


@contextmanager
def xtrabackup_option_file(
    settings: MySQLSettings,
    directory: Path,
    mysql_socket: str,
) -> Iterator[Path]:
    """Create a short-lived option file for the local physical-backup client."""

    descriptor, raw_path = tempfile.mkstemp(
        prefix=".xtrabackup-credentials-", suffix=".cnf", dir=directory
    )
    path = Path(raw_path)
    try:
        os.fchmod(descriptor, 0o600)
        user = _option_file_value(settings.user)
        password = _option_file_value(settings.password)
        socket = _option_file_value(mysql_socket)
        body = "\n".join(
            (
                "[client]",
                f"user={user}",
                f"password={password}",
                f"socket={socket}",
                "protocol=SOCKET",
                "",
                "[xtrabackup]",
                f"user={user}",
                f"password={password}",
                f"socket={socket}",
                "",
            )
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        descriptor = -1
        yield path
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)


def _dump_command(settings: MySQLSettings, option_file: Path) -> list[str]:
    # MySQL requires defaults-file options to precede all other options.
    return [
        str(MYSQLDUMP_BINARY),
        f"--defaults-extra-file={option_file}",
        "--single-transaction",
        "--quick",
        "--skip-lock-tables",
        "--hex-blob",
        "--routines",
        "--triggers",
        "--events",
        "--no-tablespaces",
        "--set-gtid-purged=OFF",
        settings.database,
    ]


def _human_bytes(value: float) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    current = float(value)
    for unit in units[:-1]:
        if abs(current) < 1024:
            return f"{current:.1f} {unit}"
        current /= 1024
    return f"{current:.1f} {units[-1]}"


class ProgressReporter:
    """Rate-limited progress renderer with stable JSON for non-interactive logs."""

    def __init__(
        self,
        *,
        stream: TextIO,
        estimated_raw_bytes: int | None = None,
        clock=time.monotonic,
    ) -> None:
        self._stream = stream
        self._estimated_raw_bytes = estimated_raw_bytes
        self._clock = clock
        self._started_at = clock()
        self._last_at = self._started_at
        self._last_raw_bytes = 0
        self._last_compressed_bytes = 0
        self._is_tty = bool(getattr(stream, "isatty", lambda: False)())

    def update(
        self,
        raw_bytes: int,
        compressed_bytes: int,
        *,
        completed: bool = False,
    ) -> None:
        now = self._clock()
        interval = now - self._last_at
        if not completed and interval < PROGRESS_INTERVAL_SECONDS:
            return

        elapsed = max(0.0, now - self._started_at)
        if completed:
            measured_interval = max(elapsed, 1e-9)
            raw_rate = raw_bytes / measured_interval
            compressed_rate = compressed_bytes / measured_interval
        else:
            measured_interval = max(interval, 1e-9)
            raw_rate = (raw_bytes - self._last_raw_bytes) / measured_interval
            compressed_rate = (
                compressed_bytes - self._last_compressed_bytes
            ) / measured_interval
        payload: dict[str, object] = {
            "event": "mysql_backup_progress",
            "raw_bytes": raw_bytes,
            "compressed_bytes": compressed_bytes,
            "raw_bytes_per_second": round(raw_rate, 3),
            "compressed_bytes_per_second": round(compressed_rate, 3),
            "elapsed_seconds": round(elapsed, 3),
            "completed": completed,
        }
        if self._estimated_raw_bytes:
            if not completed:
                while raw_bytes > self._estimated_raw_bytes:
                    self._estimated_raw_bytes *= 2
            percent = raw_bytes * 100 / self._estimated_raw_bytes
            payload["estimated_percent"] = round(
                100.0 if completed else percent, 1
            )
            payload["estimated_total_raw_bytes"] = self._estimated_raw_bytes

        if self._is_tty:
            percent_text = ""
            if "estimated_percent" in payload:
                percent_text = f" progress~{payload['estimated_percent']:.1f}%"
            line = (
                f"mysqldump raw={_human_bytes(raw_bytes)} "
                f"compressed={_human_bytes(compressed_bytes)} "
                f"throughput={_human_bytes(raw_rate)}/s "
                f"elapsed={elapsed:.1f}s{percent_text}"
            )
            print(
                f"\r{line}",
                end="\n" if completed else "",
                file=self._stream,
                flush=True,
            )
        else:
            print(
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
                file=self._stream,
                flush=True,
            )

        self._last_at = now
        self._last_raw_bytes = raw_bytes
        self._last_compressed_bytes = compressed_bytes


def _stream_dump(
    source: BinaryIO,
    raw_output: BinaryIO,
    reporter: ProgressReporter,
) -> int:
    raw_bytes = 0
    with gzip.GzipFile(
        fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
    ) as compressed:
        while True:
            chunk = source.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            compressed.write(chunk)
            raw_bytes += len(chunk)
            reporter.update(raw_bytes, raw_output.tell())
    return raw_bytes


def _write_dump(
    output: Path,
    settings: MySQLSettings,
    *,
    estimated_raw_bytes: int | None,
    progress_stream: TextIO,
) -> DumpStatistics:
    started_at = time.monotonic()
    # Config may originate in the process environment.  The child needs no
    # credential-bearing variable because its sole credential source is the
    # protected option file.
    environment = {"LC_ALL": "C"}
    environment.update(
        {
            key: os.environ[key]
            for key in SAFE_SUBPROCESS_ENV_KEYS
            if key in os.environ and key != "LC_ALL"
        }
    )

    with mysql_option_file(settings, output.parent) as option_file:
        process = subprocess.Popen(
            _dump_command(settings, option_file),
            stdout=subprocess.PIPE,
            env=environment,
        )
        assert process.stdout is not None
        reporter = ProgressReporter(
            stream=progress_stream,
            estimated_raw_bytes=estimated_raw_bytes,
        )
        try:
            with output.open("xb") as raw_output:
                os.fchmod(raw_output.fileno(), 0o600)
                raw_bytes = _stream_dump(process.stdout, raw_output, reporter)
                raw_output.flush()
                os.fsync(raw_output.fileno())
                compressed_bytes = raw_output.tell()
            return_code = process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()

    if return_code:
        raise subprocess.CalledProcessError(return_code, process.args)

    elapsed = max(0.0, time.monotonic() - started_at)
    reporter.update(raw_bytes, compressed_bytes, completed=True)
    return DumpStatistics(raw_bytes, compressed_bytes, elapsed)


def _write_missing_database_backup(
    output: Path, *, progress_stream: TextIO
) -> DumpStatistics:
    started_at = time.monotonic()
    with output.open("xb") as raw_output:
        os.fchmod(raw_output.fileno(), 0o600)
        with gzip.GzipFile(
            fileobj=raw_output, mode="wb", compresslevel=1, mtime=0
        ) as compressed:
            compressed.write(_MISSING_DATABASE_NOTICE)
        raw_output.flush()
        os.fsync(raw_output.fileno())
        compressed_bytes = raw_output.tell()
    elapsed = max(0.0, time.monotonic() - started_at)
    ProgressReporter(stream=progress_stream).update(
        len(_MISSING_DATABASE_NOTICE), compressed_bytes, completed=True
    )
    return DumpStatistics(len(_MISSING_DATABASE_NOTICE), compressed_bytes, elapsed)


def validate_gzip_stream(
    path: Path, *, expected_raw_bytes: int
) -> GzipValidation:
    """Read through EOF, verifying CRC32 while hashing the gzip artifact."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OSError(f"无法安全打开 gzip artifact: {path}") from exc
    actual_raw_bytes = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"gzip artifact 不是普通文件: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as raw_input:
            digesting_input = _DigestingReader(raw_input)
            with gzip.GzipFile(fileobj=digesting_input, mode="rb") as compressed:
                while chunk := compressed.read(COPY_CHUNK_BYTES):
                    actual_raw_bytes += len(chunk)
        after_descriptor = os.fstat(descriptor)
        try:
            after_path = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise OSError(f"gzip artifact 在校验时发生变化: {path}") from exc
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after_descriptor) or identity(before) != identity(
            after_path
        ):
            raise OSError(f"gzip artifact 在校验时发生变化: {path}")
    finally:
        os.close(descriptor)
    if actual_raw_bytes != expected_raw_bytes:
        raise OSError(
            "gzip validation size mismatch: "
            f"expected {expected_raw_bytes}, read {actual_raw_bytes}"
        )
    return GzipValidation(actual_raw_bytes, digesting_input.hexdigest)


def manifest_path_for(output: Path) -> Path:
    return output.with_name(f"{output.name}.manifest.json")


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _json_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_json_file(path: Path, document: dict[str, object]) -> None:
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(_json_bytes(document))
        handle.flush()
        os.fsync(handle.fileno())


def read_manifest(path: Path) -> dict[str, object]:
    try:
        assert_no_symlink_components(path, label="backup manifest")
    except UnsafePathError as exc:
        raise ValueError(str(exc)) from exc
    document = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=lambda token: (_raise_invalid_json_constant(token)),
    )
    if document.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(f"unsupported backup manifest schema: {path}")
    if document.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"unsupported backup manifest version: {path}")
    return document


def _atomic_replace_json(path: Path, document: dict[str, object]) -> None:
    partial = path.with_name(f".{path.name}.partial")
    partial.unlink(missing_ok=True)
    try:
        _write_json_file(partial, document)
        os.replace(partial, path)
        _fsync_directory(path.parent)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def _validate_success_transition(document: Mapping[str, object]) -> None:
    if document.get("backup_status") != "complete":
        raise ValueError("只有完整备份才能标记 deployment success")
    method = document.get("backup_method")
    artifact = document.get("artifact")
    if method not in {"mysqldump", "xtrabackup"} or not isinstance(
        artifact, Mapping
    ):
        raise ValueError("完整备份清单缺少有效 method 或 artifact")
    if not isinstance(document.get("completed_at"), str):
        raise ValueError("完整备份清单缺少 completed_at")
    if method == "mysqldump":
        raw_bytes = document.get("raw_bytes")
        if (
            document.get("scope") != "database"
            or document.get("gzip_crc_verified") is not True
            or type(raw_bytes) is not int
            or raw_bytes <= 0
            or artifact.get("format") != "sql+gzip"
            or not isinstance(artifact.get("sha256"), str)
        ):
            raise ValueError("mysqldump 清单未通过完整性状态校验")
    elif (
        document.get("scope") != "full_instance"
        or document.get("prepared") is not True
        or artifact.get("format") != "xtrabackup-full-prepared"
        or not isinstance(document.get("xtrabackup"), Mapping)
        or not isinstance(document.get("tool"), Mapping)
    ):
        raise ValueError("XtraBackup 清单未通过 prepare 状态校验")


def _bound_manifest_artifact(
    path: Path,
    document: Mapping[str, object],
    *,
    plan_path: Path | None,
) -> tuple[Path, Mapping[str, object], Mapping[str, object] | None]:
    artifact_data = document.get("artifact")
    if not isinstance(artifact_data, Mapping):
        raise ValueError("backup manifest 缺少 artifact")
    relative = artifact_data.get("relative_path")
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or "\x00" in relative
    ):
        raise ValueError("backup manifest artifact 相对路径无效")
    if artifact_data.get("path_relative_to") != "manifest_directory":
        raise ValueError("backup manifest artifact 路径基准无效")

    manifest = path.absolute()
    plan: Mapping[str, object] | None = None
    if plan_path is None:
        if ".." in Path(relative).parts:
            raise ValueError("无 plan 的 artifact 路径不得离开 manifest 目录")
        artifact = manifest.parent / relative
        try:
            assert_no_symlink_components(artifact, label="backup artifact")
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc
    else:
        plan_document = read_plan(plan_path)
        root = Path(str(plan_document["backup_root"]))
        try:
            layout = validate_layout(
                root,
                ("plans", "logical", "physical", "manifests"),
            )
            expected_plan = managed_path(
                layout["root"],
                f"plans/{plan_document['run_id']}.json",
                label="success plan",
            )
            expected_manifest = managed_path(
                layout["root"],
                f"manifests/{plan_document['run_id']}.manifest.json",
                label="success manifest",
            )
            artifact = managed_path(
                layout["root"],
                str(plan_document["artifact_relative_path"]),
                label="success artifact",
            )
        except UnsafePathError as exc:
            raise ValueError(str(exc)) from exc
        if plan_path.absolute() != expected_plan or manifest != expected_manifest:
            raise ValueError("backup manifest 与 plan 路径不匹配")
        expected_method = (
            "xtrabackup"
            if plan_document["strategy"] == "physical"
            else "mysqldump"
        )
        for field in ("run_id", "generation", "database"):
            if document.get(field) != plan_document.get(field):
                raise ValueError(f"backup manifest 与 plan 的 {field} 不匹配")
        if document.get("backup_method") != expected_method:
            raise ValueError("backup manifest 与 plan 的备份策略不匹配")
        if relative != os.path.relpath(artifact, manifest.parent):
            raise ValueError("backup manifest 与 plan 的 artifact 路径不匹配")
        plan = plan_document

    if artifact_data.get("name") != artifact.name:
        raise ValueError("backup manifest artifact 名称不匹配")
    return artifact, artifact_data, plan


def _validate_logical_manifest_artifact(
    artifact: Path,
    artifact_data: Mapping[str, object],
    document: Mapping[str, object],
) -> None:
    compressed_bytes = artifact_data.get("compressed_bytes")
    expected_sha256 = artifact_data.get("sha256")
    raw_bytes = document.get("raw_bytes")
    if (
        type(compressed_bytes) is not int
        or compressed_bytes <= 0
        or type(raw_bytes) is not int
        or raw_bytes <= 0
        or not isinstance(expected_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("mysqldump artifact 完整性字段无效")
    try:
        metadata = artifact.lstat()
    except OSError as exc:
        raise ValueError(f"mysqldump artifact 不存在: {artifact}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("mysqldump artifact 必须是权限 0600 的普通文件")
    if metadata.st_uid != os.geteuid():
        raise ValueError("mysqldump artifact 不属于当前部署用户")
    if metadata.st_size != compressed_bytes:
        raise ValueError("mysqldump artifact 压缩大小不匹配")
    validation = validate_gzip_stream(artifact, expected_raw_bytes=raw_bytes)
    if validation.sha256 != expected_sha256:
        raise ValueError("mysqldump artifact SHA-256 不匹配")


def _validate_physical_manifest_artifact(
    artifact: Path,
    artifact_data: Mapping[str, object],
    document: Mapping[str, object],
    plan: Mapping[str, object] | None,
) -> None:
    if plan is None:
        raise ValueError("XtraBackup success 必须绑定 backup plan")
    raw_plan = plan.get("xtrabackup_plan")
    if not isinstance(raw_plan, Mapping):
        raise ValueError("physical plan 缺少 xtrabackup_plan")
    physical_plan = xtrabackup.XtraBackupPlan.from_dict(raw_plan)
    result = xtrabackup.inspect_prepared_backup(physical_plan, artifact)
    recorded_result = document.get("xtrabackup")
    if not isinstance(recorded_result, Mapping) or dict(recorded_result) != result.to_dict():
        raise ValueError("XtraBackup artifact 与已记录校验结果不匹配")
    if (
        artifact_data.get("file_count") != result.file_count
        or artifact_data.get("total_bytes") != result.total_bytes
    ):
        raise ValueError("XtraBackup artifact 容量清单不匹配")
    tool = document.get("tool")
    if not isinstance(tool, Mapping) or tool != {
        "name": "percona-xtrabackup",
        "package": physical_plan.package_name,
        "package_version": physical_plan.package_version,
        "upstream_version": physical_plan.upstream_version,
    }:
        raise ValueError("XtraBackup tool 信息与 plan 不匹配")


def validate_manifest_artifact(
    path: Path,
    document: Mapping[str, object],
    *,
    plan_path: Path | None = None,
) -> None:
    artifact, artifact_data, plan = _bound_manifest_artifact(
        path,
        document,
        plan_path=plan_path,
    )
    if document.get("backup_method") == "mysqldump":
        _validate_logical_manifest_artifact(artifact, artifact_data, document)
    else:
        _validate_physical_manifest_artifact(
            artifact,
            artifact_data,
            document,
            plan,
        )


def mark_manifest_success(path: Path, *, plan_path: Path | None = None) -> None:
    document = read_manifest(path)
    _validate_success_transition(document)
    validate_manifest_artifact(path, document, plan_path=plan_path)
    current = document.get("deployment_status")
    if current == "success":
        return
    if current != "pending":
        raise ValueError(f"cannot mark {current!r} backup manifest successful")
    document["deployment_status"] = "success"
    document["deployment_completed_at"] = _utc_now()
    document["retention_status"] = "active"
    _atomic_replace_json(path, document)


def mark_manifest_failed(path: Path, *, phase: str) -> bool:
    """Persist a deployment failure; a missing manifest is an intentional no-op."""

    if not path.exists():
        return False
    if not phase or len(phase) > 128 or any(c in phase for c in "\r\n\x00"):
        raise ValueError("failure phase must be a non-empty single-line label")
    document = read_manifest(path)
    current = document.get("deployment_status")
    if current == "success":
        return False
    if current not in {"pending", "failed"}:
        raise ValueError(f"cannot mark {current!r} backup manifest failed")
    document["deployment_status"] = "failed"
    document["failure_phase"] = phase
    document["deployment_completed_at"] = _utc_now()
    _atomic_replace_json(path, document)
    return True


def estimate_raw_bytes(directory: Path, database: str) -> int | None:
    """Use the newest successful logical backup as a progress denominator."""

    newest: tuple[str, int] | None = None
    for path in directory.glob("*.manifest.json"):
        try:
            manifest = read_manifest(path)
            raw_bytes = int(manifest["raw_bytes"])
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if (
            manifest.get("deployment_status") == "success"
            and manifest.get("database") == database
            and manifest.get("backup_method") == "mysqldump"
            and raw_bytes > 0
        ):
            candidate = (str(manifest.get("completed_at", "")), raw_bytes)
            if newest is None or candidate > newest:
                newest = candidate
    return newest[1] if newest is not None else None


def _build_manifest(
    *,
    output: Path,
    manifest_path: Path,
    settings: MySQLSettings,
    snapshot: DatabaseSnapshot,
    statistics: DumpStatistics,
    validation: GzipValidation,
    started_at: str,
    completed_at: str,
    estimated_raw_bytes: int | None,
    run_id: str | None,
    generation: int | None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "backup_method": "mysqldump",
        "backup_status": "complete",
        "scope": "database",
        "deployment_status": "pending",
        "database": settings.database,
        "database_existed": snapshot.database_exists,
        "server": {
            "version": snapshot.version,
            "version_comment": snapshot.version_comment,
        },
        "artifact": {
            "name": output.name,
            "relative_path": os.path.relpath(output, manifest_path.parent),
            "path_relative_to": "manifest_directory",
            "format": "sql+gzip",
            "compressed_bytes": statistics.compressed_bytes,
            "sha256": validation.sha256,
        },
        "raw_bytes": statistics.raw_bytes,
        "elapsed_seconds": round(statistics.elapsed_seconds, 6),
        "throughput_bytes_per_second": round(
            statistics.throughput_bytes_per_second, 3
        ),
        "estimated_raw_bytes": estimated_raw_bytes,
        "gzip_crc_verified": True,
        "restore_verified_at": None,
        "started_at": started_at,
        "completed_at": completed_at,
    }
    if run_id is not None:
        document["run_id"] = _validate_run_id(run_id)
    if generation is not None:
        if type(generation) is not int or generation <= 0:
            raise ValueError("deployment generation 必须是正整数")
        document["generation"] = generation
    return document


def backup_database(
    output: Path,
    config=None,
    *,
    manifest_path: Path | None = None,
    progress_stream: TextIO | None = None,
    run_id: str | None = None,
    snapshot: DatabaseSnapshot | None = None,
    estimated_raw_bytes: int | None = None,
    scan_history: bool = True,
    generation: int | None = None,
) -> Path:
    """Publish one gzip dump and its pending deployment manifest atomically."""

    settings = settings_from_config(config)
    try:
        output = absolute_lexical_path(output, label="logical backup output")
        ensure_directory(output.parent, label="logical backup directory")
        manifest = absolute_lexical_path(
            manifest_path or manifest_path_for(output),
            label="backup manifest",
        )
        ensure_directory(manifest.parent, label="backup manifest directory")
        assert_no_symlink_components(
            output,
            label="logical backup output",
            allow_missing_leaf=True,
        )
        assert_no_symlink_components(
            manifest,
            label="backup manifest",
            allow_missing_leaf=True,
        )
    except UnsafePathError as exc:
        raise PreflightError(str(exc)) from exc
    if output.exists() or output.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise FileExistsError(
            f"backup output or manifest already exists: {output}, {manifest}"
        )

    partial = output.with_name(f".{output.name}.partial")
    manifest_partial = manifest.with_name(f".{manifest.name}.partial")
    partial.unlink(missing_ok=True)
    manifest_partial.unlink(missing_ok=True)
    stream = progress_stream or sys.stderr
    started_at = _utc_now()
    snapshot = snapshot or inspect_database(settings)
    if scan_history:
        estimated_raw_bytes = estimate_raw_bytes(
            manifest.parent,
            settings.database,
        )
    output_published = False

    try:
        if snapshot.database_exists:
            statistics = _write_dump(
                partial,
                settings,
                estimated_raw_bytes=estimated_raw_bytes,
                progress_stream=stream,
            )
        else:
            statistics = _write_missing_database_backup(
                partial, progress_stream=stream
            )
        validation = validate_gzip_stream(
            partial, expected_raw_bytes=statistics.raw_bytes
        )
        document = _build_manifest(
            output=output,
            manifest_path=manifest,
            settings=settings,
            snapshot=snapshot,
            statistics=statistics,
            validation=validation,
            started_at=started_at,
            completed_at=_utc_now(),
            estimated_raw_bytes=estimated_raw_bytes,
            run_id=run_id,
            generation=generation,
        )
        _write_json_file(manifest_partial, document)

        os.replace(partial, output)
        output_published = True
        _fsync_directory(output.parent)
        os.replace(manifest_partial, manifest)
        _fsync_directory(manifest.parent)
    except BaseException:
        partial.unlink(missing_ok=True)
        manifest_partial.unlink(missing_ok=True)
        if output_published:
            output.unlink(missing_ok=True)
            _fsync_directory(output.parent)
        raise
    return output


_PLAN_FIELDS = {
    "schema",
    "schema_version",
    "created_at",
    "run_id",
    "generation",
    "backup_root",
    "strategy",
    "decision_reason",
    "database",
    "server",
    "artifact_relative_path",
    "manifest_relative_path",
    "capacity",
    "xtrabackup_plan",
}


def read_plan(path: Path) -> dict[str, object]:
    try:
        assert_no_symlink_components(path, label="backup plan")
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda token: (_raise_invalid_json_constant(token)),
        )
    except (OSError, UnsafePathError, ValueError, json.JSONDecodeError) as exc:
        raise PlanError(f"backup plan 无法读取: {path}") from exc
    if not isinstance(document, dict) or set(document) != _PLAN_FIELDS:
        raise PlanError("backup plan 字段集合无效")
    if (
        document.get("schema") != PLAN_SCHEMA
        or document.get("schema_version") != PLAN_SCHEMA_VERSION
    ):
        raise PlanError("backup plan schema 无效")
    run_id = _validate_run_id(str(document.get("run_id", "")))
    generation = document.get("generation")
    if type(generation) is not int or generation <= 0:
        raise PlanError("backup plan generation 无效")
    strategy = document.get("strategy")
    if strategy not in {"logical", "physical"}:
        raise PlanError("backup plan strategy 无效")
    root = Path(str(document.get("backup_root", "")))
    if not root.is_absolute() or ".." in root.parts:
        raise PlanError("backup plan root 必须是绝对词法路径")
    expected_artifact = (
        f"physical/{run_id}"
        if strategy == "physical"
        else f"logical/{run_id}.sql.gz"
    )
    if document.get("artifact_relative_path") != expected_artifact:
        raise PlanError("backup plan artifact 路径无效")
    if document.get("manifest_relative_path") != (
        f"manifests/{run_id}.manifest.json"
    ):
        raise PlanError("backup plan manifest 路径无效")
    physical = document.get("xtrabackup_plan")
    if strategy == "physical":
        if not isinstance(physical, dict):
            raise PlanError("physical plan 缺少 xtrabackup_plan")
        xtrabackup.XtraBackupPlan.from_dict(physical)
    elif physical is not None:
        raise PlanError("logical plan 不得包含 xtrabackup_plan")
    return document


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"重复 JSON 字段: {key}")
        document[key] = value
    return document


def _raise_invalid_json_constant(token: str) -> None:
    raise ValueError(f"不允许 JSON 常量 {token}")


def _plan_path(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str):
        raise PlanError(f"{label} 相对路径类型无效")
    try:
        return managed_path(
            root,
            relative,
            label=label,
            allow_missing_leaf=True,
        )
    except UnsafePathError as exc:
        raise PlanError(str(exc)) from exc


def _assert_server_identity(
    expected: Mapping[str, object], actual: DatabaseSnapshot
) -> None:
    if expected != {
        "version": actual.version,
        "version_comment": actual.version_comment,
    }:
        raise PlanError("停服前后 MySQL 服务端身份发生变化")


def _planned_integer(
    capacity: Mapping[str, object],
    name: str,
    *,
    minimum: int,
) -> int:
    value = capacity.get(name)
    if type(value) is not int or value < minimum:
        raise PlanError(f"backup plan capacity.{name} 无效")
    return value


def revalidate_planned_capacity(
    capacity_value: object,
    directory: Path,
    *,
    strategy: str,
) -> None:
    """Repeat only constant-time filesystem checks inside the stopped window."""

    if not isinstance(capacity_value, Mapping):
        raise PlanError("backup plan capacity 必须是对象")
    required_bytes = _planned_integer(
        capacity_value,
        "required_bytes",
        minimum=1,
    )
    reserved_bytes = _planned_integer(
        capacity_value,
        "reserved_bytes",
        minimum=0,
    )
    if strategy == "logical":
        required_inodes = _planned_integer(
            capacity_value,
            "required_inodes",
            minimum=1,
        )
    elif strategy == "physical":
        required_inodes = _planned_integer(
            capacity_value,
            "source_inode_count",
            minimum=1,
        ) + 1024
    else:
        raise PlanError(f"未知备份策略: {strategy!r}")

    try:
        target_directory = existing_directory(
            directory,
            label=f"{strategy} backup directory",
        )
    except UnsafePathError as exc:
        raise PlanError(str(exc)) from exc
    filesystem = os.statvfs(target_directory)
    block_size = filesystem.f_frsize or filesystem.f_bsize
    available_bytes = filesystem.f_bavail * block_size
    if available_bytes < required_bytes + reserved_bytes:
        raise PlanError(
            "停服后备份空间不再满足 plan: "
            f"available={available_bytes}, required={required_bytes}, "
            f"reserve={reserved_bytes}"
        )
    if filesystem.f_files > 0 and filesystem.f_favail < required_inodes:
        raise PlanError(
            "停服后备份 inode 不再满足 plan: "
            f"available={filesystem.f_favail}, required={required_inodes}"
        )


def _planned_progress_estimate(capacity_value: object) -> int | None:
    if not isinstance(capacity_value, Mapping):
        raise PlanError("backup plan capacity 必须是对象")
    value = capacity_value.get("progress_estimated_raw_bytes")
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise PlanError("backup plan progress_estimated_raw_bytes 无效")
    return value


def _build_physical_manifest(
    *,
    plan: Mapping[str, object],
    manifest: Path,
    target: Path,
    result: xtrabackup.XtraBackupResult,
    started_at: str,
    elapsed_seconds: float,
) -> dict[str, object]:
    physical = plan["xtrabackup_plan"]
    if not isinstance(physical, dict):
        raise PlanError("physical plan 缺失")
    return {
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": plan["run_id"],
        "generation": plan["generation"],
        "backup_method": "xtrabackup",
        "backup_status": "complete",
        "scope": "full_instance",
        "prepared": True,
        "restore_verified_at": None,
        "deployment_status": "pending",
        "database": plan["database"],
        "server": {
            "version": physical["server_version"],
            "version_comment": physical["server_version_comment"],
            "server_uuid": physical["server_uuid"],
        },
        "artifact": {
            "name": target.name,
            "relative_path": os.path.relpath(target, manifest.parent),
            "path_relative_to": "manifest_directory",
            "format": "xtrabackup-full-prepared",
            "total_bytes": result.total_bytes,
            "file_count": result.file_count,
        },
        "xtrabackup": result.to_dict(),
        "tool": {
            "name": "percona-xtrabackup",
            "package": physical["package_name"],
            "package_version": physical["package_version"],
            "upstream_version": physical["upstream_version"],
        },
        "elapsed_seconds": round(elapsed_seconds, 6),
        "started_at": started_at,
        "completed_at": _utc_now(),
    }


def _build_logical_failure_manifest(
    *,
    plan: Mapping[str, object],
    manifest: Path,
    target: Path,
    snapshot: DatabaseSnapshot,
    started_at: str,
    error: BaseException,
) -> dict[str, object]:
    completed_at = _utc_now()
    return {
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": plan["run_id"],
        "generation": plan["generation"],
        "backup_method": "mysqldump",
        "backup_status": "failed",
        "scope": "database",
        "gzip_crc_verified": False,
        "restore_verified_at": None,
        "deployment_status": "failed",
        "failure_phase": "logical_backup",
        "failure_type": type(error).__name__,
        "database": plan["database"],
        "database_existed": snapshot.database_exists,
        "server": {
            "version": snapshot.version,
            "version_comment": snapshot.version_comment,
        },
        "artifact": {
            "name": target.name,
            "relative_path": os.path.relpath(target, manifest.parent),
            "path_relative_to": "manifest_directory",
            "format": "sql+gzip-incomplete",
            "validation": "failed",
        },
        "started_at": started_at,
        "completed_at": completed_at,
        "deployment_completed_at": completed_at,
    }


def _build_physical_failure_manifest(
    *,
    plan: Mapping[str, object],
    manifest: Path,
    target: Path,
    started_at: str,
    error: BaseException,
) -> dict[str, object]:
    physical = plan["xtrabackup_plan"]
    if not isinstance(physical, dict):
        raise PlanError("physical plan 缺失")
    completed_at = _utc_now()
    return {
        "schema": MANIFEST_SCHEMA,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": plan["run_id"],
        "generation": plan["generation"],
        "backup_method": "xtrabackup",
        "backup_status": "failed",
        "scope": "full_instance",
        "prepared": False,
        "restore_verified_at": None,
        "deployment_status": "failed",
        "failure_phase": "physical_backup",
        "failure_type": type(error).__name__,
        "database": plan["database"],
        "server": {
            "version": physical["server_version"],
            "version_comment": physical["server_version_comment"],
            "server_uuid": physical["server_uuid"],
        },
        "artifact": {
            "name": target.name,
            "relative_path": os.path.relpath(target, manifest.parent),
            "path_relative_to": "manifest_directory",
            "format": "xtrabackup-incomplete",
            "validation": "failed",
        },
        "tool": {
            "name": "percona-xtrabackup",
            "package": physical["package_name"],
            "package_version": physical["package_version"],
            "upstream_version": physical["upstream_version"],
        },
        "started_at": started_at,
        "completed_at": completed_at,
        "deployment_completed_at": completed_at,
    }


def execute_backup_plan(
    plan_path: Path,
    manifest_path: Path,
    config=None,
    *,
    progress_stream: TextIO | None = None,
    physical_executor: Callable[..., xtrabackup.XtraBackupResult] | None = None,
) -> Path:
    document = read_plan(plan_path)
    root = Path(str(document["backup_root"]))
    try:
        layout = validate_layout(
            root,
            ("plans", "logical", "physical", "manifests"),
        )
        expected_plan_path = managed_path(
            root,
            f"plans/{document['run_id']}.json",
            label="plan",
        )
        actual_plan_path = absolute_lexical_path(plan_path, label="plan")
    except UnsafePathError as exc:
        raise PlanError(str(exc)) from exc
    root = layout["root"]
    if actual_plan_path != expected_plan_path:
        raise PlanError(f"plan 必须位于 {expected_plan_path}")
    manifest = _plan_path(root, document["manifest_relative_path"], "manifest")
    if manifest_path.absolute() != manifest:
        raise PlanError(f"manifest 必须与 plan 一致: {manifest}")
    artifact = _plan_path(root, document["artifact_relative_path"], "artifact")
    settings = settings_from_config(config)
    if settings.database != document["database"]:
        raise PlanError("当前 MYSQL_DB 与 backup plan 不一致")

    strategy = document["strategy"]
    revalidate_planned_capacity(
        document["capacity"],
        artifact.parent,
        strategy=str(strategy),
    )
    if strategy == "logical":
        current = inspect_database(settings)
        expected = document["server"]
        if not isinstance(expected, dict):
            raise PlanError("plan server 字段无效")
        _assert_server_identity(expected, current)
        started_wall = _utc_now()
        try:
            return backup_database(
                artifact,
                config,
                manifest_path=manifest,
                progress_stream=progress_stream,
                run_id=str(document["run_id"]),
                snapshot=current,
                estimated_raw_bytes=_planned_progress_estimate(
                    document["capacity"]
                ),
                scan_history=False,
                generation=int(document["generation"]),
            )
        except BaseException as exc:
            try:
                _publish_new_json(
                    manifest,
                    _build_logical_failure_manifest(
                        plan=document,
                        manifest=manifest,
                        target=artifact,
                        snapshot=current,
                        started_at=started_wall,
                        error=exc,
                    ),
                )
            except BaseException as manifest_error:
                print(
                    "[backup_database] logical backup failed and its failure "
                    f"manifest could not be published: {manifest_error}",
                    file=sys.stderr,
                )
            raise

    raw_physical = document["xtrabackup_plan"]
    if not isinstance(raw_physical, dict):
        raise PlanError("physical plan 缺失")
    physical_plan = xtrabackup.XtraBackupPlan.from_dict(raw_physical)
    current_metadata = query_xtrabackup_metadata(settings)
    expected_metadata = xtrabackup.ServerMetadata(
        version=physical_plan.server_version,
        version_comment=physical_plan.server_version_comment,
        datadir=physical_plan.datadir,
        socket=physical_plan.mysql_socket,
        server_uuid=physical_plan.server_uuid,
    )
    current_paths = xtrabackup.validate_server_environment(current_metadata)
    expected_paths = xtrabackup.validate_server_environment(expected_metadata)
    current_identity = (
        current_metadata.version,
        current_metadata.version_comment,
        current_metadata.server_uuid,
    )
    expected_identity = (
        expected_metadata.version,
        expected_metadata.version_comment,
        expected_metadata.server_uuid,
    )
    if current_identity != expected_identity or current_paths != expected_paths:
        raise PlanError("停服前后 physical MySQL 实例身份发生变化")
    started_wall = _utc_now()
    started = time.monotonic()
    execute = physical_executor or xtrabackup.execute_full_backup
    try:
        with xtrabackup_option_file(
            settings, layout["plans"], physical_plan.mysql_socket
        ) as defaults_file:
            result = execute(
                physical_plan,
                artifact,
                mysql_defaults_file=defaults_file,
            )
    except BaseException as exc:
        try:
            _publish_new_json(
                manifest,
                _build_physical_failure_manifest(
                    plan=document,
                    manifest=manifest,
                    target=artifact,
                    started_at=started_wall,
                    error=exc,
                ),
            )
        except BaseException as manifest_error:
            print(
                "[backup_database] physical backup failed and its failure "
                f"manifest could not be published: {manifest_error}",
                file=sys.stderr,
            )
        raise
    physical_manifest = _build_physical_manifest(
        plan=document,
        manifest=manifest,
        target=artifact,
        result=result,
        started_at=started_wall,
        elapsed_seconds=max(0.0, time.monotonic() - started),
    )
    _publish_new_json(manifest, physical_manifest)
    return artifact


def _valid_prune_candidate(
    manifest_path: Path, backup_root: Path
) -> tuple[str, Path, Path, dict[str, object], str] | None:
    if manifest_path.is_symlink():
        return None
    try:
        document = read_manifest(manifest_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if document.get("deployment_status") != "success":
        return None
    retention_status = document.get("retention_status", "active")
    if retention_status not in {"active", "deleting"}:
        return None
    run_id = document.get("run_id")
    generation = document.get("generation")
    method = document.get("backup_method")
    artifact_data = document.get("artifact")
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        return None
    if type(generation) is not int or generation <= 0:
        return None
    if not isinstance(artifact_data, dict):
        return None
    if artifact_data.get("path_relative_to") != "manifest_directory":
        return None
    try:
        expected_manifest = managed_path(
            backup_root,
            f"manifests/{run_id}.manifest.json",
            label="retention manifest",
        )
    except UnsafePathError:
        return None
    if manifest_path != expected_manifest:
        return None
    if method == "mysqldump":
        artifact_relative = f"logical/{run_id}.sql.gz"
    elif method == "xtrabackup":
        artifact_relative = f"physical/{run_id}"
    else:
        return None
    try:
        expected_artifact = managed_path(
            backup_root,
            artifact_relative,
            label="retention artifact",
            allow_missing_leaf=retention_status == "deleting",
        )
    except UnsafePathError:
        return None
    expected_relative = os.path.relpath(expected_artifact, manifest_path.parent)
    if artifact_data.get("relative_path") != expected_relative:
        return None
    completed = document.get("deployment_completed_at")
    if not isinstance(completed, str):
        return None
    try:
        plan_path = managed_path(
            backup_root,
            f"plans/{run_id}.json",
            label="retention plan",
            allow_missing_leaf=retention_status == "deleting",
        )
    except UnsafePathError:
        return None
    if not plan_path.exists() and retention_status == "deleting":
        return method, expected_artifact, plan_path, document, retention_status
    try:
        plan = read_plan(plan_path)
    except PlanError:
        return None
    if (
        plan.get("run_id") != run_id
        or plan.get("generation") != generation
        or plan.get("backup_root") != str(backup_root)
    ):
        return None
    return method, expected_artifact, plan_path, document, retention_status


def _remove_physical(
    path: Path,
    backup_root: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    try:
        layout = validate_layout(
            backup_root,
            ("plans", "logical", "physical", "manifests"),
        )
        expected = managed_path(
            layout["root"],
            f"physical/{path.name}",
            label="physical artifact",
            allow_missing_leaf=True,
        )
    except UnsafePathError as exc:
        raise PruneError(str(exc)) from exc
    if path != expected:
        raise PruneError(f"physical artifact 不在受管目录: {path}")
    if not path.exists():
        return
    if path.is_symlink() or not path.is_dir():
        raise PruneError(f"拒绝删除无效 physical artifact: {path}")
    parent_metadata = path.parent.lstat()
    target_metadata = path.lstat()
    execute = runner or subprocess.run
    execute(
        _privileged_helper_command(
            "remove-physical-tree",
            "--physical-directory",
            str(path.parent),
            "--run-id",
            path.name,
            "--expected-parent-dev",
            str(parent_metadata.st_dev),
            "--expected-parent-ino",
            str(parent_metadata.st_ino),
            "--expected-target-dev",
            str(target_metadata.st_dev),
            "--expected-target-ino",
            str(target_metadata.st_ino),
        ),
        check=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if path.exists() or path.is_symlink():
        raise PruneError(f"physical artifact 删除后仍存在: {path}")


def _mark_retention_deleting(path: Path) -> dict[str, object]:
    document = read_manifest(path)
    status = document.get("retention_status", "active")
    if document.get("deployment_status") != "success" or status not in {
        "active",
        "deleting",
    }:
        raise PruneError(f"备份清单不允许进入 retention deleting: {path}")
    if status == "active":
        document["retention_status"] = "deleting"
        document["retention_started_at"] = _utc_now()
        _atomic_replace_json(path, document)
    return document


def prune_successful_backups(
    backup_root: Path,
    *,
    keep_success: int = 2,
    protected_run_ids: Collection[str] = (),
    physical_remover: Callable[[Path], None] | None = None,
) -> list[Path]:
    if keep_success < 1:
        raise ValueError("keep-success 必须至少为 1")
    protected = frozenset(_validate_run_id(run_id) for run_id in protected_run_ids)
    try:
        layout = validate_layout(
            absolute_lexical_path(backup_root, label="backup root"),
            ("plans", "logical", "physical", "manifests"),
        )
    except UnsafePathError as exc:
        raise PruneError(str(exc)) from exc
    root = layout["root"]
    manifests = layout["manifests"]
    active: list[tuple[int, str, Path, str, Path, Path]] = []
    deleting: list[tuple[int, str, Path, str, Path, Path]] = []
    for manifest in manifests.glob("*.manifest.json"):
        valid = _valid_prune_candidate(manifest, root)
        if valid is None:
            continue
        method, artifact, plan_path, document, retention_status = valid
        candidate = (
            int(document["generation"]),
            str(document["run_id"]),
            manifest,
            method,
            artifact,
            plan_path,
        )
        (deleting if retention_status == "deleting" else active).append(
            candidate
        )
    active.sort(reverse=True)
    protected_active = [item for item in active if item[1] in protected]
    unprotected_active = [item for item in active if item[1] not in protected]
    remaining_slots = max(0, keep_success - len(protected_active))
    candidates = (
        [item for item in deleting if item[1] not in protected]
        + unprotected_active[remaining_slots:]
    )
    removed: list[Path] = []
    failures: list[str] = []
    for _, _, manifest, method, artifact, plan_path in candidates:
        try:
            _mark_retention_deleting(manifest)
            validate_layout(
                root,
                ("plans", "logical", "physical", "manifests"),
            )
            if method == "mysqldump":
                if artifact.exists() and (
                    artifact.is_symlink() or not artifact.is_file()
                ):
                    raise PruneError(f"logical artifact 类型无效: {artifact}")
                artifact.unlink(missing_ok=True)
                _fsync_directory(artifact.parent)
            else:
                if physical_remover is None:
                    _remove_physical(artifact, root)
                elif artifact.exists():
                    physical_remover(artifact)
            plan_path.unlink(missing_ok=True)
            _fsync_directory(layout["plans"])
            manifest.unlink()
            _fsync_directory(layout["manifests"])
            removed.append(artifact)
        except (OSError, subprocess.CalledProcessError, PruneError) as exc:
            failures.append(f"{artifact}: {exc}")
    if failures:
        raise PruneError("; ".join(failures))
    return removed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser(
        "preflight", help="choose and persist the backup strategy"
    )
    preflight_parser.add_argument("--plan", type=Path, required=True)
    preflight_parser.add_argument("--backup-root", type=Path, required=True)
    preflight_parser.add_argument("--run-id", required=True)

    backup_parser = subparsers.add_parser(
        "backup", help="execute a previously validated backup plan"
    )
    backup_parser.add_argument("--plan", type=Path, required=True)
    backup_parser.add_argument("--manifest", type=Path, required=True)

    success_parser = subparsers.add_parser(
        "mark-success", help="mark a backup's deployment successful"
    )
    success_parser.add_argument("--manifest", type=Path, required=True)
    success_parser.add_argument("--plan", type=Path, required=True)

    strategy_parser = subparsers.add_parser(
        "strategy", help="read the selected strategy from a validated plan"
    )
    strategy_parser.add_argument("--plan", type=Path, required=True)

    failed_parser = subparsers.add_parser(
        "mark-failed", help="best-effort deployment failure marker"
    )
    failed_parser.add_argument("--manifest", type=Path, required=True)
    failed_parser.add_argument("--phase", required=True)

    prune_parser = subparsers.add_parser(
        "prune", help="remove old successfully deployed backups"
    )
    prune_parser.add_argument("--backup-root", type=Path, required=True)
    prune_parser.add_argument("--keep-success", type=int, default=2)
    prune_parser.add_argument("--protect-run-id", action="append", default=[])
    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "mark-failed":
        try:
            mark_manifest_failed(args.manifest, phase=args.phase)
        except Exception as exc:
            # Cleanup callers must preserve the deployment's original exit status.
            print(f"[backup_database] unable to record failure: {exc}", file=sys.stderr)
            return 1
        return 0

    try:
        if args.command == "preflight":
            document = create_preflight_plan(
                args.plan, args.backup_root, args.run_id
            )
            print(document["strategy"])
        elif args.command == "backup":
            output = execute_backup_plan(args.plan, args.manifest)
            print(output)
        elif args.command == "mark-success":
            mark_manifest_success(args.manifest, plan_path=args.plan)
        elif args.command == "strategy":
            print(read_plan(args.plan)["strategy"])
        elif args.command == "prune":
            for removed in prune_successful_backups(
                args.backup_root,
                keep_success=args.keep_success,
                protected_run_ids=args.protect_run_id,
            ):
                print(removed)
    except Exception as exc:
        print(f"[backup_database] failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
