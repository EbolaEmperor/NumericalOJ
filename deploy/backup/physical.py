#!/usr/bin/env python3
"""Fail-closed Percona XtraBackup backend for production deployments.

This module deliberately does not decide whether a deployment may fall back to
``mysqldump``.  It either produces and validates one full physical backup, or
raises an exception and leaves the target directory in place for diagnosis.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from deploy.backup.policy import (
    ReleaseSpec,
    XTRABACKUP_RELEASES,
    detect_server_vendor,
    select_release,
)
from deploy.backup.paths import (
    UnsafePathError,
    absolute_lexical_path,
    assert_no_symlink_components,
    existing_directory,
)


PLAN_SCHEMA_VERSION = 1
SERVER_METADATA_SQL = (
    "SELECT @@version AS version, @@version_comment AS version_comment, "
    "@@datadir AS datadir, @@socket AS socket, @@server_uuid AS server_uuid"
)

SUDO_BINARY = Path("/usr/bin/sudo")
MYSQL_BINARY = Path("/usr/bin/mysql")
XTRABACKUP_BINARY = Path("/usr/bin/xtrabackup")
DPKG_QUERY_BINARY = Path("/usr/bin/dpkg-query")
DPKG_BINARY = Path("/usr/bin/dpkg")
INSTALL_BINARY = Path("/usr/bin/install")
STAT_BINARY = Path("/usr/bin/stat")
TEST_BINARY = Path("/usr/bin/test")
CAT_BINARY = Path("/usr/bin/cat")
FIND_BINARY = Path("/usr/bin/find")
DU_BINARY = Path("/usr/bin/du")

_PACKAGE_ARCH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_XTRABACKUP_VERSION_RE = re.compile(
    r"(?:^|\s)(?:/[^\s]*/)?xtrabackup\s+version\s+(?P<version>[^\s,]+)",
    re.IGNORECASE,
)
_SAFE_ENV_KEYS = ("LANG", "LANGUAGE", "LC_CTYPE", "TERM")
_REQUIRED_BACKUP_FILES = (
    "xtrabackup_checkpoints",
    "xtrabackup_info",
    "backup-my.cnf",
)
MINIMUM_FREE_RESERVE_BYTES = 2 * 1024**3


class XtraBackupError(RuntimeError):
    """Base class for an actionable XtraBackup deployment failure."""


class PlanValidationError(XtraBackupError):
    """The persisted plan is malformed or contradicts the compatibility map."""


class EnvironmentValidationError(XtraBackupError):
    """The selected server or filesystem is not provably local and safe."""


class InstallationValidationError(XtraBackupError):
    """The installed binary is not the exact package recorded in the plan."""


class RootSocketAuthenticationError(XtraBackupError):
    """Privileged local authentication cannot prove the planned MySQL instance."""


class BackupValidationError(XtraBackupError):
    """A backup did not reach the required full-prepared state."""


MYSQL_80_RELEASE = XTRABACKUP_RELEASES["8.0"]
MYSQL_84_RELEASE = XTRABACKUP_RELEASES["8.4"]


@dataclass(frozen=True)
class ServerMetadata:
    """Metadata returned by :data:`SERVER_METADATA_SQL`."""

    version: str
    version_comment: str
    datadir: str
    socket: str
    server_uuid: str

    def __post_init__(self) -> None:
        _required_text(self.version, "version")
        _required_text(self.version_comment, "version_comment")
        _required_text(self.datadir, "datadir")
        _required_text(self.socket, "socket")
        _validate_server_uuid(self.server_uuid)

    @classmethod
    def from_query_row(
        cls,
        row: Mapping[str, Any] | Sequence[Any],
    ) -> ServerMetadata:
        """Parse one cursor row without guessing missing columns or aliases."""

        if isinstance(row, Mapping):
            expected = {
                "version",
                "version_comment",
                "datadir",
                "socket",
                "server_uuid",
            }
            if set(row) != expected:
                raise PlanValidationError(
                    "MySQL 元数据字段必须精确为 version、version_comment、datadir、"
                    "socket、server_uuid"
                )
            values = tuple(row[name] for name in (
                "version",
                "version_comment",
                "datadir",
                "socket",
                "server_uuid",
            ))
        elif isinstance(row, Sequence) and not isinstance(row, (str, bytes)):
            if len(row) != 5:
                raise PlanValidationError("MySQL 元数据查询必须返回五列")
            values = tuple(row)
        else:
            raise PlanValidationError("MySQL 元数据行类型无效")
        if not all(isinstance(value, str) for value in values):
            raise PlanValidationError("MySQL 元数据五列都必须是字符串")
        return cls(*values)


@dataclass(frozen=True)
class XtraBackupPlan:
    """Serializable, self-validating instructions for one physical backup."""

    schema_version: int
    mysql_host: str
    server_version: str
    server_version_comment: str
    server_vendor: str
    server_uuid: str
    datadir: str
    mysql_socket: str
    server_series: str
    upstream_version: str
    package_name: str
    package_version: str
    apt_repository: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != PLAN_SCHEMA_VERSION:
            raise PlanValidationError(
                f"XtraBackup plan schema 必须是 {PLAN_SCHEMA_VERSION}"
            )
        for field_name in (
            "mysql_host",
            "server_version",
            "server_version_comment",
            "server_vendor",
            "server_uuid",
            "datadir",
            "mysql_socket",
            "server_series",
            "upstream_version",
            "package_name",
            "package_version",
            "apt_repository",
        ):
            _required_text(getattr(self, field_name), field_name)
        _validate_server_uuid(self.server_uuid)

        release = select_release(self.server_version, self.server_version_comment)
        if release is None:
            raise PlanValidationError("plan 中的 MySQL 版本或发行方不受支持")
        expected_vendor = detect_server_vendor(
            self.server_version,
            self.server_version_comment,
        )
        recorded = (
            self.server_series,
            self.upstream_version,
            self.package_name,
            self.apt_repository,
        )
        expected = (
            release.server_series,
            release.upstream_version,
            release.package_name,
            release.apt_repository,
        )
        if self.server_vendor != expected_vendor or recorded != expected:
            raise PlanValidationError("plan 与固定 XtraBackup 兼容矩阵不一致")
        if not release.accepts_package_version(self.package_version):
            raise PlanValidationError(
                f"dpkg 版本不属于固定上游版本 {release.upstream_version}: "
                f"{self.package_version}"
            )
        _absolute_lexical_path(self.datadir, "datadir")
        _absolute_lexical_path(self.mysql_socket, "mysql_socket")

    @property
    def release(self) -> ReleaseSpec:
        release = select_release(self.server_version, self.server_version_comment)
        if release is None:  # Guarded by __post_init__; keeps type narrowing local.
            raise PlanValidationError("plan 的服务端版本已失去兼容映射")
        return release

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mysql_host": self.mysql_host,
            "server_version": self.server_version,
            "server_version_comment": self.server_version_comment,
            "server_vendor": self.server_vendor,
            "server_uuid": self.server_uuid,
            "datadir": self.datadir,
            "mysql_socket": self.mysql_socket,
            "server_series": self.server_series,
            "upstream_version": self.upstream_version,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "apt_repository": self.apt_repository,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> XtraBackupPlan:
        if not isinstance(value, Mapping):
            raise PlanValidationError("XtraBackup plan 必须是 JSON 对象")
        expected = {
            "schema_version",
            "mysql_host",
            "server_version",
            "server_version_comment",
            "server_vendor",
            "server_uuid",
            "datadir",
            "mysql_socket",
            "server_series",
            "upstream_version",
            "package_name",
            "package_version",
            "apt_repository",
        }
        if set(value) != expected:
            missing = sorted(expected - set(value))
            extra = sorted(set(value) - expected)
            raise PlanValidationError(
                f"XtraBackup plan 字段不匹配: missing={missing}, extra={extra}"
            )
        return cls(**dict(value))

    @classmethod
    def from_json(cls, payload: str) -> XtraBackupPlan:
        if not isinstance(payload, str):
            raise PlanValidationError("XtraBackup plan JSON 必须是字符串")
        try:
            value = json.loads(
                payload,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=lambda token: (_raise_invalid_json_constant(token)),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PlanValidationError(f"XtraBackup plan JSON 无效: {exc}") from exc
        return cls.from_dict(value)


@dataclass(frozen=True)
class XtraBackupResult:
    """Validated facts suitable for inclusion in a deployment manifest."""

    target: str
    backup_type: str
    from_lsn: int
    to_lsn: int
    last_lsn: int
    file_count: int
    total_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "backup_type": self.backup_type,
            "from_lsn": self.from_lsn,
            "to_lsn": self.to_lsn,
            "last_lsn": self.last_lsn,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True)
class PhysicalCapacity:
    """Conservative capacity facts captured before the application stops."""

    apparent_bytes: int
    allocated_bytes: int
    required_bytes: int
    available_bytes: int
    reserved_bytes: int
    source_inode_count: int
    available_inodes: int | None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "apparent_bytes": self.apparent_bytes,
            "allocated_bytes": self.allocated_bytes,
            "required_bytes": self.required_bytes,
            "available_bytes": self.available_bytes,
            "reserved_bytes": self.reserved_bytes,
            "source_inode_count": self.source_inode_count,
            "available_inodes": self.available_inodes,
        }


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise PlanValidationError(f"{label} 必须是非空且不含 NUL 的字符串")
    return value.strip()


def _validate_server_uuid(value: Any) -> str:
    text = _required_text(value, "server_uuid").lower()
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        text,
    ) is None:
        raise PlanValidationError(f"server_uuid 格式无效: {value!r}")
    return text


def _raise_invalid_json_constant(token: str) -> None:
    raise ValueError(f"不允许 JSON 常量 {token}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"重复 JSON 字段 {key}")
        result[key] = value
    return result


def _absolute_lexical_path(raw_path: str | os.PathLike[str], label: str) -> Path:
    try:
        path = absolute_lexical_path(raw_path, label=label)
    except UnsafePathError as exc:
        raise EnvironmentValidationError(str(exc)) from exc
    if not Path(os.fspath(raw_path)).is_absolute():
        raise EnvironmentValidationError(f"{label} 必须是绝对路径: {raw_path}")
    return path


def _assert_no_symlink_components(
    path: Path,
    *,
    allow_missing_leaf: bool = False,
) -> None:
    try:
        assert_no_symlink_components(
            path,
            label="XtraBackup",
            allow_missing_leaf=allow_missing_leaf,
        )
    except UnsafePathError as exc:
        raise EnvironmentValidationError(str(exc)) from exc


def _validate_existing_directory(path: Path, label: str) -> Path:
    try:
        return existing_directory(path, label=label)
    except UnsafePathError as exc:
        raise EnvironmentValidationError(str(exc)) from exc


def _resolve_server_path(path: Path, label: str) -> Path:
    """Canonicalize a server-reported source path before validating its type.

    Debian exposes ``/var/run`` as a compatibility symlink to ``/run``.  Source
    paths returned by the authenticated server may therefore contain symlink
    components even though deployment-owned backup targets must not.
    """

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EnvironmentValidationError(
            f"无法解析服务端返回的 {label}: {path}"
        ) from exc
    if not resolved.is_absolute():
        raise EnvironmentValidationError(f"服务端返回的 {label} 不是绝对路径")
    return resolved


def _validate_unix_socket(path: Path) -> Path:
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode):
        raise EnvironmentValidationError(f"MySQL socket 不是 Unix socket: {path}")
    return path


def validate_server_environment(
    metadata: ServerMetadata,
) -> tuple[Path, Path]:
    """Validate the local paths supplied by the application-connected server."""

    datadir = _resolve_server_path(
        _absolute_lexical_path(metadata.datadir, "datadir"),
        "MySQL datadir",
    )
    if not stat.S_ISDIR(datadir.lstat().st_mode):
        raise EnvironmentValidationError(f"MySQL datadir 不是目录: {datadir}")
    mysql_socket = _validate_unix_socket(
        _resolve_server_path(
            _absolute_lexical_path(metadata.socket, "mysql_socket"),
            "MySQL socket",
        )
    )
    return datadir, mysql_socket


def build_plan(
    metadata: ServerMetadata,
    *,
    mysql_host: str,
    package_version: str,
) -> XtraBackupPlan:
    """Build a plan only after compatibility and local-path validation."""

    release = select_release(metadata.version, metadata.version_comment)
    if release is None:
        raise PlanValidationError("服务端版本或发行方没有受支持的 XtraBackup 映射")
    datadir, mysql_socket = validate_server_environment(metadata)
    vendor = detect_server_vendor(metadata.version, metadata.version_comment)
    if vendor is None:
        raise PlanValidationError("无法确认 MySQL 发行方")
    return XtraBackupPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        mysql_host=mysql_host,
        server_version=metadata.version,
        server_version_comment=metadata.version_comment,
        server_vendor=vendor,
        server_uuid=metadata.server_uuid,
        datadir=str(datadir),
        mysql_socket=str(mysql_socket),
        server_series=release.server_series,
        upstream_version=release.upstream_version,
        package_name=release.package_name,
        package_version=package_version,
        apt_repository=release.apt_repository,
    )


def validate_plan_environment(plan: XtraBackupPlan) -> tuple[Path, Path]:
    metadata = ServerMetadata(
        version=plan.server_version,
        version_comment=plan.server_version_comment,
        datadir=plan.datadir,
        socket=plan.mysql_socket,
        server_uuid=plan.server_uuid,
    )
    return validate_server_environment(metadata)


def _safe_subprocess_environment() -> dict[str, str]:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
    }
    for key in _SAFE_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            environment[key] = value
    return environment


def _run(
    command: Sequence[str | os.PathLike[str]],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    capture_output: bool,
) -> subprocess.CompletedProcess[str]:
    command_text = [os.fspath(argument) for argument in command]
    _assert_no_password_transport(command_text)
    execute = runner or subprocess.run
    kwargs: dict[str, Any] = {
        "check": True,
        "env": _safe_subprocess_environment(),
    }
    if capture_output:
        kwargs.update({"capture_output": True, "text": True})
    return execute(command_text, **kwargs)


def _assert_no_password_transport(command: Sequence[str]) -> None:
    for argument in command:
        lowered = argument.lower()
        if lowered == "-p" or lowered.startswith("--password"):
            raise XtraBackupError("禁止通过命令行参数传递 MySQL 密码")


def _validate_executable(path: Path, label: str) -> None:
    path = _absolute_lexical_path(path, label)
    _assert_no_symlink_components(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise InstallationValidationError(f"{label} 不是可执行普通文件: {path}")


def query_installed_package_version(
    release: ReleaseSpec,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> str:
    """Read the exact installed Debian version of the mapped package."""

    result = _run(
        [
            DPKG_QUERY_BINARY,
            "--show",
            "--showformat=${Status}\t${Version}\n",
            release.package_name,
        ],
        runner=runner,
        capture_output=True,
    )
    line = (result.stdout or "").strip()
    try:
        status, package_version = line.split("\t", 1)
    except ValueError as exc:
        raise InstallationValidationError("dpkg-query 返回格式无效") from exc
    if status != "install ok installed":
        raise InstallationValidationError(
            f"dpkg 未确认 {release.package_name} 已安装: {status}"
        )
    if not release.accepts_package_version(package_version):
        raise InstallationValidationError(
            f"已安装版本不是固定上游版本 {release.upstream_version}: {package_version}"
        )
    return package_version


def _parse_dpkg_owner(output: str, binary: Path) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise InstallationValidationError("xtrabackup 必须精确归属一个 dpkg 包")
    owner, separator, owned_path = lines[0].partition(": ")
    if not separator or owned_path != str(binary):
        raise InstallationValidationError("dpkg 返回的 xtrabackup 文件归属无效")
    if ":" in owner:
        owner, architecture = owner.split(":", 1)
        if not _PACKAGE_ARCH_RE.fullmatch(architecture):
            raise InstallationValidationError("dpkg 包架构标识无效")
    return owner


def validate_installation(
    plan: XtraBackupPlan,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Bind the fixed plan to an exact dpkg package and binary version."""

    _validate_executable(XTRABACKUP_BINARY, "xtrabackup")
    owner_result = _run(
        [DPKG_QUERY_BINARY, "--search", XTRABACKUP_BINARY],
        runner=runner,
        capture_output=True,
    )
    owner = _parse_dpkg_owner(owner_result.stdout or "", XTRABACKUP_BINARY)
    if owner != plan.package_name:
        raise InstallationValidationError(
            f"/usr/bin/xtrabackup 属于 {owner}，预期 {plan.package_name}"
        )

    installed_version = query_installed_package_version(plan.release, runner=runner)
    if installed_version != plan.package_version:
        raise InstallationValidationError(
            f"dpkg 版本与 plan 不一致: {installed_version} != {plan.package_version}"
        )
    verify_result = _run(
        [DPKG_BINARY, "--verify", plan.package_name],
        runner=runner,
        capture_output=True,
    )
    if (verify_result.stdout or "").strip():
        raise InstallationValidationError(
            f"dpkg 完整性校验失败: {plan.package_name}"
        )

    version_result = _run(
        [XTRABACKUP_BINARY, "--version"],
        runner=runner,
        capture_output=True,
    )
    version_output = f"{version_result.stdout or ''}\n{version_result.stderr or ''}"
    versions = {
        match.group("version")
        for match in _XTRABACKUP_VERSION_RE.finditer(version_output)
    }
    if versions != {plan.upstream_version}:
        raise InstallationValidationError(
            f"xtrabackup --version 不匹配固定版本 {plan.upstream_version}: "
            f"{sorted(versions)}"
        )


def prepare_plan(
    metadata: ServerMetadata,
    *,
    mysql_host: str,
    mysql_defaults_file: Path | None = None,
    installer: Callable[[ReleaseSpec], None] | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> XtraBackupPlan | None:
    """Validate/install a supported backend and preflight local socket access.

    ``None`` means that the server has no compatible fixed mapping.  Installation
    and validation failures remain exceptions so the deployment orchestrator can
    apply its explicitly agreed fallback policy.
    """

    release = select_release(metadata.version, metadata.version_comment)
    if release is None:
        return None
    validate_server_environment(metadata)

    try:
        package_version = query_installed_package_version(release, runner=runner)
        plan = build_plan(
            metadata,
            mysql_host=mysql_host,
            package_version=package_version,
        )
        validate_installation(plan, runner=runner)
    except (InstallationValidationError, FileNotFoundError, subprocess.CalledProcessError):
        if installer is None:
            raise
        installer(release)
        package_version = query_installed_package_version(release, runner=runner)
        plan = build_plan(
            metadata,
            mysql_host=mysql_host,
            package_version=package_version,
        )
        validate_installation(plan, runner=runner)

    authenticate_sudo(runner=runner)
    preflight_root_socket(
        plan,
        mysql_defaults_file=mysql_defaults_file,
        runner=runner,
    )
    return plan


def _mysql_defaults_argument(path: Path) -> str:
    path = _absolute_lexical_path(path, "MySQL defaults file")
    _assert_no_symlink_components(path)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise EnvironmentValidationError(
            "MySQL defaults file 必须是当前用户所有且权限为 0600 的普通文件"
        )
    return f"--defaults-file={path}"


def preflight_root_socket(
    plan: XtraBackupPlan,
    *,
    mysql_defaults_file: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Prove privileged socket auth reaches the application-connected instance."""

    _, mysql_socket = validate_plan_environment(plan)
    if mysql_defaults_file is None:
        defaults_arguments = ("--no-defaults", "--user=root")
    else:
        defaults_arguments = (_mysql_defaults_argument(mysql_defaults_file),)
    result = _run(
        _sudo_command(
            MYSQL_BINARY,
            *defaults_arguments,
            "--protocol=socket",
            f"--socket={mysql_socket}",
            "--batch",
            "--skip-column-names",
            "--execute=SELECT @@server_uuid",
        ),
        runner=runner,
        capture_output=True,
    )
    root_socket_uuid = (result.stdout or "").strip()
    if root_socket_uuid != plan.server_uuid:
        raise RootSocketAuthenticationError(
            "sudo 本地 socket 无法验证同一 MySQL 实例: "
            f"application_uuid={plan.server_uuid}, root_socket_uuid={root_socket_uuid!r}"
        )


def authenticate_sudo(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Refresh sudo credentials with the prompt attached to the terminal."""

    _run(
        [SUDO_BINARY, "-v"],
        runner=runner,
        capture_output=False,
    )


def validate_sudo_ticket(
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    """Fail immediately if the pre-stop interactive sudo ticket was lost."""

    _run(
        [SUDO_BINARY, "-n", "-v"],
        runner=runner,
        capture_output=False,
    )


def _parse_du_bytes(output: str, label: str) -> int:
    match = re.match(r"^([0-9]+)(?:\s|$)", output.strip())
    if match is None:
        raise EnvironmentValidationError(f"无法解析 {label} 的 du 结果")
    return int(match.group(1))


def preflight_physical_capacity(
    plan: XtraBackupPlan,
    backup_parent: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> PhysicalCapacity:
    """Fail before service stop if a full, prepared backup cannot fit safely."""

    datadir, _ = validate_plan_environment(plan)
    parent = _validate_existing_directory(
        _absolute_lexical_path(backup_parent, "backup parent"),
        "backup parent",
    )
    if _is_relative_to(parent, datadir) or _is_relative_to(datadir, parent):
        raise EnvironmentValidationError("backup parent 不能与 MySQL datadir 重叠")

    apparent_result = _run(
        _sudo_command(
            DU_BINARY,
            "--bytes",
            "--summarize",
            "--apparent-size",
            "--",
            datadir,
        ),
        runner=runner,
        capture_output=True,
    )
    allocated_result = _run(
        _sudo_command(
            DU_BINARY,
            "--block-size=1",
            "--summarize",
            "--",
            datadir,
        ),
        runner=runner,
        capture_output=True,
    )
    source_inodes = _run(
        _sudo_command(
            DU_BINARY,
            "--inodes",
            "--summarize",
            "--one-file-system",
            "--",
            datadir,
        ),
        runner=runner,
        capture_output=True,
    )
    apparent_bytes = _parse_du_bytes(
        apparent_result.stdout or "", "datadir apparent size"
    )
    allocated_bytes = _parse_du_bytes(
        allocated_result.stdout or "", "datadir allocated size"
    )
    source_inode_count = _parse_du_bytes(
        source_inodes.stdout or "", "datadir inode count"
    )
    if apparent_bytes <= 0 or allocated_bytes <= 0 or source_inode_count <= 0:
        raise EnvironmentValidationError("MySQL datadir 的容量或 inode 数异常")

    filesystem = os.statvfs(parent)
    block_size = filesystem.f_frsize or filesystem.f_bsize
    available_bytes = filesystem.f_bavail * block_size
    total_bytes = filesystem.f_blocks * block_size
    reserved_bytes = max(total_bytes // 10, MINIMUM_FREE_RESERVE_BYTES)
    source_bytes = max(apparent_bytes, allocated_bytes)
    required_bytes = (source_bytes * 5 + 3) // 4 + MINIMUM_FREE_RESERVE_BYTES
    if available_bytes < required_bytes + reserved_bytes:
        raise EnvironmentValidationError(
            "物理备份空间不足: "
            f"available={available_bytes}, required={required_bytes}, "
            f"post_backup_reserve={reserved_bytes}"
        )

    available_inodes: int | None = None
    if filesystem.f_files > 0:
        available_inodes = filesystem.f_favail
        if available_inodes < source_inode_count + 1024:
            raise EnvironmentValidationError(
                "物理备份 inode 不足: "
                f"available={available_inodes}, source_inodes={source_inode_count}"
            )
    return PhysicalCapacity(
        apparent_bytes=apparent_bytes,
        allocated_bytes=allocated_bytes,
        required_bytes=required_bytes,
        available_bytes=available_bytes,
        reserved_bytes=reserved_bytes,
        source_inode_count=source_inode_count,
        available_inodes=available_inodes,
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    return path.is_relative_to(parent)


def validate_new_target(target: Path, datadir: Path) -> Path:
    """Reject existing, linked, broad, or datadir-overlapping backup targets."""

    target = _absolute_lexical_path(target, "backup target")
    datadir = _absolute_lexical_path(datadir, "datadir")
    if target == Path(target.anchor):
        raise EnvironmentValidationError("backup target 不能是文件系统根目录")
    if _is_relative_to(target, datadir) or _is_relative_to(datadir, target):
        raise EnvironmentValidationError("backup target 不能与 MySQL datadir 重叠")
    if target.exists() or target.is_symlink():
        raise EnvironmentValidationError(f"backup target 必须尚不存在: {target}")
    _validate_existing_directory(target.parent, "backup target 父目录")
    _assert_no_symlink_components(target, allow_missing_leaf=True)
    return target


def _sudo_command(binary: Path, *arguments: str | os.PathLike[str]) -> list[str | Path]:
    command: list[str | Path] = [SUDO_BINARY, "-n", "--", binary]
    command.extend(arguments)
    if any(str(argument) == "--no-server-version-check" for argument in command):
        raise XtraBackupError("禁止绕过 XtraBackup 服务端版本检查")
    return command


def _assert_root_target(
    target: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> None:
    _validate_existing_directory(target, "backup target")
    result = _run(
        _sudo_command(STAT_BINARY, "--format=%u:%g:%a:%F", "--", target),
        runner=runner,
        capture_output=True,
    )
    if (result.stdout or "").strip() != "0:0:700:directory":
        raise BackupValidationError(
            f"backup target 必须由 root 拥有且权限为 0700: {(result.stdout or '').strip()}"
        )


def _parse_checkpoints(payload: str) -> dict[str, str]:
    checkpoints: dict[str, str] = {}
    for line_number, raw_line in enumerate(payload.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not separator or not key or not value or key in checkpoints:
            raise BackupValidationError(
                f"xtrabackup_checkpoints 第 {line_number} 行无效"
            )
        checkpoints[key] = value
    return checkpoints


def _parse_inventory(lines: Iterable[str]) -> tuple[int, int]:
    file_count = 0
    total_bytes = 0
    for raw_line in lines:
        entry_type, separator, raw_size = raw_line.rstrip("\n").partition("\t")
        if not separator or entry_type not in {"d", "f", "l"}:
            raise BackupValidationError("无法解析 XtraBackup 文件清单")
        if entry_type == "l":
            raise BackupValidationError("XtraBackup 结果中不允许符号链接")
        if entry_type == "d":
            continue
        if re.fullmatch(r"[0-9]+", raw_size) is None:
            raise BackupValidationError("XtraBackup 文件大小无效")
        file_count += 1
        total_bytes += int(raw_size)
    if file_count < len(_REQUIRED_BACKUP_FILES) or total_bytes <= 0:
        raise BackupValidationError("XtraBackup 结果文件不完整或为空")
    return file_count, total_bytes


def _inventory_backup(
    target: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[int, int]:
    command = _sudo_command(
        FIND_BINARY,
        target,
        "-xdev",
        "-printf",
        "%y\\t%s\\n",
    )
    if runner is not None:
        result = _run(command, runner=runner, capture_output=True)
        return _parse_inventory((result.stdout or "").splitlines())

    command_text = [os.fspath(argument) for argument in command]
    _assert_no_password_transport(command_text)
    process = subprocess.Popen(
        command_text,
        stdout=subprocess.PIPE,
        text=True,
        env=_safe_subprocess_environment(),
    )
    assert process.stdout is not None
    try:
        result = _parse_inventory(process.stdout)
        return_code = process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()
    if return_code:
        raise subprocess.CalledProcessError(return_code, command_text)
    return result


def inspect_prepared_backup(
    plan: XtraBackupPlan,
    target: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> XtraBackupResult:
    """Validate root ownership, required metadata and full-prepared LSNs."""

    datadir, _ = validate_plan_environment(plan)
    target = _absolute_lexical_path(target, "backup target")
    if _is_relative_to(target, datadir) or _is_relative_to(datadir, target):
        raise BackupValidationError("backup target 与 MySQL datadir 重叠")
    _assert_root_target(target, runner=runner)

    for filename in _REQUIRED_BACKUP_FILES:
        _run(
            _sudo_command(TEST_BINARY, "-f", target / filename),
            runner=runner,
            capture_output=False,
        )

    checkpoint_result = _run(
        _sudo_command(CAT_BINARY, target / "xtrabackup_checkpoints"),
        runner=runner,
        capture_output=True,
    )
    checkpoints = _parse_checkpoints(checkpoint_result.stdout or "")
    if checkpoints.get("backup_type") != "full-prepared":
        raise BackupValidationError("XtraBackup 结果不是 full-prepared")
    numeric_values: dict[str, int] = {}
    for key in ("from_lsn", "to_lsn", "last_lsn"):
        value = checkpoints.get(key, "")
        if not re.fullmatch(r"[0-9]+", value):
            raise BackupValidationError(f"XtraBackup checkpoints 缺少有效 {key}")
        numeric_values[key] = int(value)
    if numeric_values["from_lsn"] != 0:
        raise BackupValidationError("完整备份的 from_lsn 必须为 0")
    if numeric_values["last_lsn"] < numeric_values["to_lsn"]:
        raise BackupValidationError("last_lsn 不能小于 to_lsn")

    file_count, total_bytes = _inventory_backup(target, runner=runner)

    return XtraBackupResult(
        target=str(target),
        backup_type="full-prepared",
        from_lsn=numeric_values["from_lsn"],
        to_lsn=numeric_values["to_lsn"],
        last_lsn=numeric_values["last_lsn"],
        file_count=file_count,
        total_bytes=total_bytes,
    )


def execute_full_backup(
    plan: XtraBackupPlan,
    target: Path,
    *,
    mysql_defaults_file: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> XtraBackupResult:
    """Create, prepare, and validate one full instance backup.

    The caller must already have stopped every application writer.  This
    function intentionally has no fallback and never removes a failed target.
    """

    datadir, mysql_socket = validate_plan_environment(plan)
    validate_installation(plan, runner=runner)
    validate_sudo_ticket(runner=runner)
    preflight_root_socket(
        plan,
        mysql_defaults_file=mysql_defaults_file,
        runner=runner,
    )
    target = validate_new_target(target, datadir)

    _run(
        _sudo_command(
            INSTALL_BINARY,
            "-d",
            "-m",
            "0700",
            "-o",
            "root",
            "-g",
            "root",
            "--",
            target,
        ),
        runner=runner,
        capture_output=False,
    )
    _assert_root_target(target, runner=runner)

    if mysql_defaults_file is None:
        defaults_arguments = ("--no-defaults",)
        connection_arguments = ("--user=root", f"--socket={mysql_socket}")
    else:
        defaults_arguments = (_mysql_defaults_argument(mysql_defaults_file),)
        connection_arguments = (f"--socket={mysql_socket}",)
    _run(
        _sudo_command(
            XTRABACKUP_BINARY,
            *defaults_arguments,
            "--backup",
            "--strict",
            "--check-privileges",
            "--parallel=4",
            "--ftwrl-wait-timeout=60",
            f"--target-dir={target}",
            f"--datadir={datadir}",
            *connection_arguments,
        ),
        runner=runner,
        capture_output=False,
    )
    _run(
        _sudo_command(
            XTRABACKUP_BINARY,
            "--no-defaults",
            "--prepare",
            "--parallel=4",
            f"--target-dir={target}",
        ),
        runner=runner,
        capture_output=False,
    )
    return inspect_prepared_backup(plan, target, runner=runner)
