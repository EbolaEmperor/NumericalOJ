#!/usr/bin/env python3
"""Provision small host runtime dependencies required by the Web service."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.backup import apt as apt_services  # noqa: E402

SystemPackageError = apt_services.ProvisioningError
Runner = apt_services.Runner
run_command = apt_services.run_command
APT_GET = apt_services.APT_GET
APT_CACHE = apt_services.APT_CACHE
DPKG_QUERY = apt_services.DPKG_QUERY
SUDO = apt_services.SUDO
ENV = apt_services.ENV

CLANGD_MINIMUM_MAJOR = 17
CLANGD_APT_PACKAGE = "clangd-19"
CLANGD_EXECUTABLE_CANDIDATES = (
    "clangd-20",
    "clangd-19",
    "clangd-18",
    "clangd-17",
    "clangd",
)


def _clangd_major(version_output: str) -> int | None:
    match = re.search(
        r"\bclangd\s+version\s+([0-9]+)(?:[.\s]|$)",
        version_output,
        re.IGNORECASE,
    )
    return None if match is None else int(match.group(1))


def _clangd_works(
    command: str | None = None,
    *,
    run: Runner = run_command,
) -> bool:
    candidates = (command,) if command is not None else CLANGD_EXECUTABLE_CANDIDATES
    for candidate in candidates:
        executable = shutil.which(candidate)
        if not executable:
            continue
        try:
            result = run([executable, "--version"], check=False)
        except OSError:
            continue
        major = _clangd_major(f"{result.stdout}\n{result.stderr}")
        if (
            result.returncode == 0
            and major is not None
            and major >= CLANGD_MINIMUM_MAJOR
        ):
            return True
    return False


def _bubblewrap_works(
    command: str | None = None,
    *,
    run: Runner = run_command,
) -> bool:
    executable = command or shutil.which("bwrap")
    if not executable:
        return False
    try:
        result = run([executable, "--version"], check=False)
    except OSError:
        return False
    return result.returncode == 0


def _command_exists(path: str) -> bool:
    return Path(path).is_file()


def _candidate_version(run: Runner, package: str = "clangd") -> str:
    result = apt_services._checked(
        run,
        [APT_CACHE, "policy", package],
        env=apt_services.APT_ENVIRONMENT,
        purpose=f"读取 {package} APT candidate",
    )
    match = re.search(r"^\s*Candidate:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    if match is None or match.group(1) == "(none)":
        raise SystemPackageError(
            f"Debian APT 仓库没有可安装的 {package} candidate"
        )
    return match.group(1)


def _parse_simulation(
    output: str,
    expected_target: str,
    package: str = "clangd",
) -> set[str]:
    actions = apt_services.parse_apt_simulation(output)
    installed_before = {
        action.package.split(":", 1)[0]: action.old_version
        for action in actions
        if action.operation == "Inst" and action.old_version is not None
    }
    apt_services.validate_apt_simulation(
        output,
        installed_before=installed_before,
        target_package=package,
        target_version=expected_target,
        mutable_existing=frozenset({package}),
    )
    return {
        action.package.split(":", 1)[0]
        for action in actions
        if action.operation == "Inst"
    }


def _ensure_packages(
    packages: tuple[
        tuple[
            str,
            Callable[..., bool],
            Callable[..., bool],
        ],
        ...,
    ],
    *,
    run: Runner = run_command,
    os_release: Path = Path("/etc/os-release"),
    command_exists: Callable[[str], bool] = _command_exists,
) -> tuple[str, ...]:
    missing = [
        (package, verify_after_install)
        for package, works, verify_after_install in packages
        if not works(run=run)
    ]
    if not missing:
        return ()
    apt_services.read_debian_identity(os_release)
    for required in (APT_GET, APT_CACHE, DPKG_QUERY, SUDO, ENV):
        if not command_exists(required):
            raise SystemPackageError(f"缺少系统包安装命令: {required}")

    apt_services._checked(
        run,
        apt_services._sudo_command(
            [APT_GET, *apt_services.APT_SECURITY_OPTIONS, "update"]
        ),
        purpose="更新 Debian APT 索引",
        interactive=True,
    )
    installed_packages: list[str] = []
    for package, works in missing:
        version = _candidate_version(run, package)
        apt_services._run_guarded_install(
            run,
            target=f"{package}={version}",
            target_package=package,
            target_version=version,
            mutable_existing=frozenset({package}),
        )
        installed = apt_services._installed_packages(run).get(package)
        if installed != version or not works(run=run):
            raise SystemPackageError(
                f"{package} 安装后版本或可执行文件核验失败"
            )
        installed_packages.append(package)
    return tuple(installed_packages)


def ensure_clangd(
    *,
    run: Runner = run_command,
    os_release: Path = Path("/etc/os-release"),
    command_exists: Callable[[str], bool] = _command_exists,
) -> bool:
    """Backward-compatible single-package provisioning entrypoint."""
    return bool(
        _ensure_packages(
            (
                (
                    CLANGD_APT_PACKAGE,
                    _clangd_works,
                    lambda **kwargs: _clangd_works(
                        command=CLANGD_APT_PACKAGE,
                        **kwargs,
                    ),
                ),
            ),
            run=run,
            os_release=os_release,
            command_exists=command_exists,
        )
    )


def ensure_editor_runtime(
    *,
    run: Runner = run_command,
    os_release: Path = Path("/etc/os-release"),
    command_exists: Callable[[str], bool] = _command_exists,
) -> tuple[str, ...]:
    """Ensure clangd and its fail-closed process sandbox are installed."""
    return _ensure_packages(
        (
            (
                CLANGD_APT_PACKAGE,
                _clangd_works,
                lambda **kwargs: _clangd_works(
                    command=CLANGD_APT_PACKAGE,
                    **kwargs,
                ),
            ),
            ("bubblewrap", _bubblewrap_works, _bubblewrap_works),
        ),
        run=run,
        os_release=os_release,
        command_exists=command_exists,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("ensure-clangd", "ensure-editor-runtime"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "ensure-clangd":
            installed = (CLANGD_APT_PACKAGE,) if ensure_clangd() else ()
        else:
            installed = ensure_editor_runtime()
    except SystemPackageError as exc:
        print(f"[system_packages] {exc}", file=sys.stderr)
        return 1
    if installed:
        print(f"已通过 APT 安装: {', '.join(installed)}")
    else:
        print("编辑器宿主运行时已存在")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
