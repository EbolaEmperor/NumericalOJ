#!/usr/bin/env python3
"""Safely provision the pinned Percona XtraBackup package on Debian.

This module intentionally owns only host package provisioning.  Database
discovery, backup creation, and fallback selection remain the caller's
responsibility.  Every mutating APT transaction is preceded by a root-run
simulation whose package actions are checked against a narrow policy.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Protocol
import urllib.error
import urllib.request

from deploy.backup.policy import (
    ReleaseSpec as XtraBackupRelease,
    XTRABACKUP_RELEASES,
    select_release,
)


class ProvisioningError(RuntimeError):
    """XtraBackup could not be provisioned without violating safety policy."""


def debian_package_version(release: XtraBackupRelease, codename: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]*", codename):
        raise ProvisioningError(f"无效的 Debian codename: {codename!r}")
    return f"{release.upstream_version}-1.{codename}"


@dataclass(frozen=True)
class BootstrapPackage:
    url: str
    sha256: str
    package: str
    version: str
    architecture: str
    key_fingerprint: str


PERCONA_RELEASE = BootstrapPackage(
    # Never use the mutable ``latest`` URL in an unattended deployment.
    url=(
        "https://repo.percona.com/apt/"
        "percona-release_1.0-33.generic_all.deb"
    ),
    sha256="313ebd0fbab685bf448ff41d7d62f5ee3b2bcd8a45b0c52ed842606a2d5deeae",
    package="percona-release",
    version="1.0-33.generic",
    architecture="all",
    key_fingerprint="4D1BB29D63D98E422B2113B19334A25F8507EFA5",
)

PERCONA_KEYRING = Path("/usr/share/keyrings/percona-keyring.gpg")
PERCONA_REPO_ROOT = "https://repo.percona.com"
SUDO = "/usr/bin/sudo"
ENV = "/usr/bin/env"
APT_GET = "/usr/bin/apt-get"
APT_CACHE = "/usr/bin/apt-cache"
DPKG_QUERY = "/usr/bin/dpkg-query"
DPKG = "/usr/bin/dpkg"
DPKG_DEB = "/usr/bin/dpkg-deb"
GPG = "/usr/bin/gpg"
PERCONA_RELEASE_COMMAND = "/usr/bin/percona-release"
XTRABACKUP = "/usr/bin/xtrabackup"
SUPPORTED_ARCHITECTURES = frozenset({"amd64", "arm64"})
KNOWN_XTRABACKUP_PACKAGES = frozenset(
    release.package_name for release in XTRABACKUP_RELEASES.values()
)
PROTECTED_SERVICE_PACKAGE_PREFIXES = (
    "mysql-server",
    "mysql-community-server",
    "percona-server-server",
    "mariadb-server",
    "docker",
    "containerd",
    "runc",
    "moby-engine",
)
APT_ENVIRONMENT = {
    "LC_ALL": "C",
    "LANG": "C",
    "DEBIAN_FRONTEND": "noninteractive",
    # Installing a backup client must never let needrestart restart MySQL or
    # Docker in the pre-stop phase.  ``l`` means list-only.
    "NEEDRESTART_MODE": "l",
}
APT_SECURITY_OPTIONS = (
    "-o",
    "APT::Get::AllowUnauthenticated=false",
    "-o",
    "Acquire::AllowInsecureRepositories=false",
    "-o",
    "Acquire::AllowDowngradeToInsecureRepositories=false",
    "-o",
    "Dpkg::Lock::Timeout=120",
)
MAX_BOOTSTRAP_BYTES = 1024 * 1024


class Response(Protocol):
    def read(self, size: int = -1) -> bytes: ...

    def geturl(self) -> str: ...

    def __enter__(self) -> Response: ...

    def __exit__(self, *args: object) -> object: ...


Runner = Callable[..., subprocess.CompletedProcess[str]]
Opener = Callable[..., Response]


@dataclass(frozen=True)
class AptAction:
    operation: str
    package: str
    old_version: str | None
    new_version: str | None


@dataclass(frozen=True)
class ProvisionResult:
    release: XtraBackupRelease
    package_version: str
    installed_by_deploy: bool


def run_command(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    interactive: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=check,
        capture_output=not interactive,
        text=True,
        env=None if env is None else dict(env),
    )


def _checked(
    run: Runner,
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    purpose: str,
    interactive: bool = False,
) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, object] = {"env": env, "check": False}
    if interactive:
        # In particular, do not pipe sudo's prompt or stdin: the operator must
        # see the prompt and type the password on the controlling terminal.
        kwargs["interactive"] = True
    try:
        result = run(list(command), **kwargs)
    except OSError as exc:
        raise ProvisioningError(f"{purpose}无法执行: {command[0]}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout or "").strip()
        if len(detail) > 1000:
            detail = detail[-1000:]
        suffix = f": {detail}" if detail else ""
        raise ProvisioningError(f"{purpose}失败{suffix}")
    return result


def _sudo_command(command: Sequence[str]) -> list[str]:
    environment = [f"{name}={value}" for name, value in APT_ENVIRONMENT.items()]
    return [SUDO, ENV, *environment, *command]


def read_debian_identity(
    os_release: Path = Path("/etc/os-release"),
) -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        lines = os_release.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProvisioningError("无法读取 /etc/os-release") from exc
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name] = value.strip().strip('"').strip("'")
    if values.get("ID") != "debian":
        raise ProvisioningError("仅支持 Debian 的 APT 自动安装路径")
    codename = values.get("VERSION_CODENAME", "")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", codename):
        raise ProvisioningError("无法从 /etc/os-release 取得 Debian codename")
    return values["ID"], codename


def _safe_work_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ProvisioningError(f"无法访问 APT 临时目录: {path}") from exc
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ProvisioningError(f"APT 临时目录不是普通目录: {path}")
    if metadata.st_uid != os.geteuid():
        raise ProvisioningError(f"APT 临时目录不属于当前部署用户: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ProvisioningError(f"APT 临时目录权限必须禁止组和其他用户访问: {path}")
    return resolved


def download_bootstrap(
    work_directory: Path,
    *,
    package: BootstrapPackage = PERCONA_RELEASE,
    opener: Opener = urllib.request.urlopen,
) -> Path:
    """Download a pinned bootstrap package to a private, fsynced temp file."""
    directory = _safe_work_directory(work_directory)
    descriptor, name = tempfile.mkstemp(
        prefix="percona-release-", suffix=".deb", dir=directory
    )
    output = Path(name)
    os.fchmod(descriptor, 0o600)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(descriptor, "wb") as destination:
            request = urllib.request.Request(
                package.url,
                headers={"User-Agent": "NumericalOJ-deploy/1"},
            )
            with opener(request, timeout=30) as source:
                if source.geturl() != package.url:
                    raise ProvisioningError("Percona 引导包下载发生了未允许的重定向")
                while chunk := source.read(64 * 1024):
                    total += len(chunk)
                    if total > MAX_BOOTSTRAP_BYTES:
                        raise ProvisioningError("Percona 引导包体积异常")
                    destination.write(chunk)
                    digest.update(chunk)
            destination.flush()
            os.fsync(destination.fileno())
        if digest.hexdigest() != package.sha256:
            raise ProvisioningError("Percona 引导包 SHA-256 校验失败")
        return output
    except ProvisioningError:
        output.unlink(missing_ok=True)
        raise
    except (OSError, urllib.error.URLError) as exc:
        output.unlink(missing_ok=True)
        raise ProvisioningError("下载 Percona 引导包失败") from exc
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _verify_bootstrap_metadata(
    path: Path, package: BootstrapPackage, run: Runner
) -> None:
    result = _checked(
        run,
        [
            DPKG_DEB,
            "--show",
            "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
            str(path),
        ],
        purpose="读取 Percona 引导包元数据",
    )
    fields = result.stdout.splitlines()
    expected = [package.package, package.version, package.architecture]
    if fields != expected:
        raise ProvisioningError(
            f"Percona 引导包元数据不匹配: expected={expected!r} actual={fields!r}"
        )


def _installed_packages(run: Runner) -> dict[str, str]:
    result = _checked(
        run,
        [
            DPKG_QUERY,
            "-W",
            "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
        ],
        purpose="读取 dpkg 状态",
    )
    installed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        name, version, status = fields
        if name and version and status.startswith("ii"):
            installed[name] = version
    return installed


def _base_package_name(name: str) -> str:
    return name.split(":", 1)[0]


_APT_ACTION = re.compile(
    r"^(?P<operation>Inst|Remv|Conf)\s+"
    r"(?P<package>[A-Za-z0-9][A-Za-z0-9+.:~-]*)"
    r"(?:\s+\[(?P<old>[^]]+)\])?"
    r"(?:\s+\((?P<new>[^ )]+).*)?$"
)


def parse_apt_simulation(output: str) -> list[AptAction]:
    actions: list[AptAction] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith(("Inst ", "Remv ", "Conf ")):
            continue
        match = _APT_ACTION.fullmatch(line)
        if match is None:
            raise ProvisioningError(f"无法解析 APT 模拟操作: {line}")
        actions.append(
            AptAction(
                operation=match.group("operation"),
                package=match.group("package"),
                old_version=match.group("old"),
                new_version=match.group("new"),
            )
        )
    return actions


def validate_apt_simulation(
    output: str,
    *,
    installed_before: Mapping[str, str],
    target_package: str,
    target_version: str,
    mutable_existing: frozenset[str],
    removable: frozenset[str] = frozenset(),
) -> list[AptAction]:
    """Reject an APT plan that changes anything outside the narrow allowlist."""
    actions = parse_apt_simulation(output)
    if not actions:
        raise ProvisioningError("APT 模拟没有产生预期安装操作")

    installed_by_base = {
        _base_package_name(name): version for name, version in installed_before.items()
    }
    install_actions: dict[str, AptAction] = {
        _base_package_name(action.package): action
        for action in actions
        if action.operation == "Inst"
    }
    for action in actions:
        package = _base_package_name(action.package)
        if action.operation == "Conf":
            if package not in install_actions:
                raise ProvisioningError(
                    f"APT 模拟将配置未由本次安装引入的软件包: {package}"
                )
            continue
        if action.operation == "Remv":
            if package not in removable:
                raise ProvisioningError(f"APT 模拟将移除未授权软件包: {package}")
            continue

        assert action.operation == "Inst"
        if any(package.startswith(prefix) for prefix in PROTECTED_SERVICE_PACKAGE_PREFIXES):
            if package != target_package:
                raise ProvisioningError(f"APT 模拟将改动受保护服务软件包: {package}")
        if package in installed_by_base and (
            package not in mutable_existing or package != target_package
        ):
            old = installed_by_base[package]
            if action.new_version != old:
                raise ProvisioningError(
                    f"APT 模拟将升级或降级既有依赖: {package} "
                    f"{old} -> {action.new_version}"
                )

    target = install_actions.get(target_package)
    if target is None or target.new_version != target_version:
        actual = None if target is None else target.new_version
        raise ProvisioningError(
            f"APT 模拟未锁定目标版本: {target_package} "
            f"expected={target_version} actual={actual}"
        )
    return actions


def _apt_install_arguments(
    target: str,
    *,
    simulate: bool,
    allow_removal: bool,
    reinstall: bool,
) -> list[str]:
    command = [APT_GET]
    if simulate:
        command.append("--simulate")
    else:
        command.append("--yes")
    command.extend(APT_SECURITY_OPTIONS)
    command.extend(["--no-install-recommends", "--allow-downgrades"])
    if not allow_removal:
        command.append("--no-remove")
    if reinstall:
        command.append("--reinstall")
    command.extend(["install", target])
    return command


def _run_guarded_install(
    run: Runner,
    *,
    target: str,
    target_package: str,
    target_version: str,
    mutable_existing: frozenset[str],
    removable: frozenset[str] = frozenset(),
    reinstall: bool = False,
) -> None:
    installed_before = _installed_packages(run)
    simulated_command = _sudo_command(
        _apt_install_arguments(
            target,
            simulate=True,
            allow_removal=bool(removable),
            reinstall=reinstall,
        )
    )
    simulation = _checked(
        run,
        simulated_command,
        purpose="APT 安装模拟",
    )
    actions = validate_apt_simulation(
        simulation.stdout,
        installed_before=installed_before,
        target_package=target_package,
        target_version=target_version,
        mutable_existing=mutable_existing,
        removable=removable,
    )
    if _installed_packages(run) != installed_before:
        raise ProvisioningError("APT 模拟期间 dpkg 状态发生变化，请重试部署")

    actual_command = _sudo_command(
        _apt_install_arguments(
            target,
            simulate=False,
            allow_removal=bool(removable),
            reinstall=reinstall,
        )
    )
    _checked(run, actual_command, purpose="APT 安装")

    installed_after = _installed_packages(run)
    expected_changed = {
        _base_package_name(action.package)
        for action in actions
        if action.operation in {"Inst", "Remv"}
    }
    actual_changed = {
        _base_package_name(name)
        for name in set(installed_before) | set(installed_after)
        if installed_before.get(name) != installed_after.get(name)
    }
    if not actual_changed <= expected_changed:
        unexpected = sorted(actual_changed - expected_changed)
        raise ProvisioningError(
            "APT 实际改动超出模拟结果: " + ", ".join(unexpected)
        )


def _key_fingerprints(run: Runner) -> set[str]:
    result = _checked(
        run,
        [
            GPG,
            "--batch",
            "--with-colons",
            "--show-keys",
            str(PERCONA_KEYRING),
        ],
        purpose="校验 Percona APT 密钥",
    )
    return {
        fields[9].upper()
        for line in result.stdout.splitlines()
        if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
    }


def _bootstrap_is_valid(run: Runner, package: BootstrapPackage) -> bool:
    query = run(
        [DPKG_QUERY, "-W", "-f=${Status}\t${Version}\n", package.package],
        env=None,
        check=False,
    )
    if query.returncode or query.stdout.strip() != (
        f"install ok installed\t{package.version}"
    ):
        return False
    verify = run([DPKG, "--verify", package.package], env=None, check=False)
    if verify.returncode or verify.stdout.strip():
        return False
    try:
        return package.key_fingerprint in _key_fingerprints(run)
    except ProvisioningError:
        return False


def _ensure_bootstrap(
    work_directory: Path,
    *,
    run: Runner,
    opener: Opener,
    package: BootstrapPackage = PERCONA_RELEASE,
) -> None:
    if _bootstrap_is_valid(run, package):
        return
    downloaded = download_bootstrap(
        work_directory, package=package, opener=opener
    )
    try:
        _verify_bootstrap_metadata(downloaded, package, run)
        _run_guarded_install(
            run,
            target=str(downloaded),
            target_package=package.package,
            target_version=package.version,
            mutable_existing=frozenset({package.package}),
            reinstall=True,
        )
    finally:
        downloaded.unlink(missing_ok=True)
    if not _bootstrap_is_valid(run, package):
        raise ProvisioningError("固定版本 percona-release 安装后校验失败")


def _validate_repository_file(
    release: XtraBackupRelease,
    codename: str,
    *,
    sources_directory: Path,
) -> None:
    source = sources_directory / f"percona-{release.apt_repository}-release.list"
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProvisioningError(f"无法读取 Percona APT source: {source}") from exc
    active = [
        line.strip()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    option = f"[signed-by={PERCONA_KEYRING}]"
    base = f"{PERCONA_REPO_ROOT}/{release.apt_repository}/apt {codename} main"
    allowed = {f"deb {option} {base}", f"deb-src {option} {base}"}
    if not active or any(line not in allowed for line in active):
        raise ProvisioningError("Percona APT source 不是预期的 HTTPS + signed-by 配置")
    if f"deb {option} {base}" not in active:
        raise ProvisioningError("Percona APT source 缺少二进制仓库")


def _select_exact_package_version(
    release: XtraBackupRelease,
    codename: str,
    output: str,
) -> str:
    expected_version = debian_package_version(release, codename)
    expected_origin = (
        f"{PERCONA_REPO_ROOT}/{release.apt_repository}/apt {codename}/main "
    )
    matching_sources: list[str] = []
    for line in output.splitlines():
        fields = [field.strip() for field in line.split("|")]
        if len(fields) != 3 or fields[0] != release.package_name:
            continue
        if fields[1] == expected_version:
            matching_sources.append(fields[2])
    if len(matching_sources) != 1:
        raise ProvisioningError(
            f"APT 中固定版本来源不唯一: {release.package_name}={expected_version}"
        )
    source = matching_sources[0]
    if not source.startswith(expected_origin) or not source.endswith(" Packages"):
        raise ProvisioningError(f"固定版本不是来自预期 Percona HTTPS 仓库: {source}")
    return expected_version


def _installed_xtrabackup_is_valid(
    release: XtraBackupRelease,
    package_version: str,
    run: Runner,
) -> bool:
    query = run(
        [DPKG_QUERY, "-W", "-f=${Status}\t${Version}\n", release.package_name],
        env=None,
        check=False,
    )
    if query.returncode or query.stdout.strip() != (
        f"install ok installed\t{package_version}"
    ):
        return False
    owner = run(
        [DPKG_QUERY, "-S", XTRABACKUP], env=None, check=False
    )
    if owner.returncode or owner.stdout.strip() != (
        f"{release.package_name}: /usr/bin/xtrabackup"
    ):
        return False
    verify = run([DPKG, "--verify", release.package_name], env=None, check=False)
    if verify.returncode or verify.stdout.strip():
        return False
    version = run([XTRABACKUP, "--version"], env=None, check=False)
    combined = f"{version.stdout}\n{version.stderr}"
    match = re.search(r"\bxtrabackup version ([^\s]+)", combined)
    return (
        version.returncode == 0
        and match is not None
        and match.group(1) == release.upstream_version
    )


def _provision_xtrabackup_impl(
    release: XtraBackupRelease,
    *,
    work_directory: Path,
    run: Runner = run_command,
    opener: Opener = urllib.request.urlopen,
    os_release: Path = Path("/etc/os-release"),
    sources_directory: Path = Path("/etc/apt/sources.list.d"),
) -> ProvisionResult:
    """Ensure an exact XtraBackup package is installed before service stop.

    Expected environmental failures are reported as :class:`ProvisioningError`;
    the caller may then choose the agreed logical-backup fallback.  No fallback
    is attempted here because backup-time failures have a different policy.
    """
    _, codename = read_debian_identity(os_release)
    architecture = _checked(
        run, [DPKG, "--print-architecture"], purpose="读取 Debian 架构"
    ).stdout.strip()
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise ProvisioningError(f"Percona 不支持当前 Debian 架构: {architecture}")
    package_version = debian_package_version(release, codename)
    if _installed_xtrabackup_is_valid(release, package_version, run):
        return ProvisionResult(release, package_version, installed_by_deploy=False)

    # This is deliberately the only interactive operation in package setup.
    _checked(
        run,
        [SUDO, "-v"],
        purpose="sudo 认证",
        interactive=True,
    )
    _ensure_bootstrap(work_directory, run=run, opener=opener)
    _checked(
        run,
        _sudo_command(
            [
                PERCONA_RELEASE_COMMAND,
                "enable",
                release.apt_repository,
                "release",
                "--scheme",
                "https",
            ]
        ),
        purpose="启用 Percona XtraBackup 仓库",
    )
    _validate_repository_file(
        release, codename, sources_directory=sources_directory
    )
    repository_file = (
        sources_directory / f"percona-{release.apt_repository}-release.list"
    )
    # Unrelated third-party repositories must not decide whether the pinned
    # Percona package can be provisioned.  Preserve their cached indexes and
    # refresh only the source file whose exact contents were validated above.
    _checked(
        run,
        _sudo_command(
            [
                APT_GET,
                *APT_SECURITY_OPTIONS,
                "-o",
                f"Dir::Etc::sourcelist={repository_file}",
                "-o",
                "Dir::Etc::sourceparts=-",
                "-o",
                "APT::Get::List-Cleanup=0",
                "-o",
                "APT::Update::Error-Mode=any",
                "update",
            ]
        ),
        purpose="更新 APT 索引",
    )
    madison = _checked(
        run,
        [APT_CACHE, "madison", release.package_name],
        purpose="查询 XtraBackup 固定版本",
    )
    selected = _select_exact_package_version(release, codename, madison.stdout)

    installed = _installed_packages(run)
    installed_xtrabackup = frozenset(
        package
        for package in KNOWN_XTRABACKUP_PACKAGES
        if package in {_base_package_name(name) for name in installed}
        and package != release.package_name
    )
    _run_guarded_install(
        run,
        target=f"{release.package_name}={selected}",
        target_package=release.package_name,
        target_version=selected,
        mutable_existing=KNOWN_XTRABACKUP_PACKAGES,
        removable=installed_xtrabackup,
        reinstall=True,
    )
    if not _installed_xtrabackup_is_valid(release, selected, run):
        raise ProvisioningError("XtraBackup 安装后 dpkg/二进制版本校验失败")
    return ProvisionResult(release, selected, installed_by_deploy=True)


def provision_xtrabackup(
    release: XtraBackupRelease,
    *,
    work_directory: Path,
    run: Runner = run_command,
    opener: Opener = urllib.request.urlopen,
    os_release: Path = Path("/etc/os-release"),
    sources_directory: Path = Path("/etc/apt/sources.list.d"),
) -> ProvisionResult:
    """Provision the pinned package and classify environmental failures.

    The deployment orchestrator may fall back to ``mysqldump`` only for this
    exception type, so missing Debian tools and network failures are normalized
    here instead of leaking unrelated exception classes.
    """

    try:
        return _provision_xtrabackup_impl(
            release,
            work_directory=work_directory,
            run=run,
            opener=opener,
            os_release=os_release,
            sources_directory=sources_directory,
        )
    except ProvisioningError as exc:
        raise ProvisioningError(f"XtraBackup 自动安装失败: {exc}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisioningError(f"XtraBackup 自动安装失败: {exc}") from exc
