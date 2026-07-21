from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import urllib.error

import pytest

from deploy.backup import apt as percona_apt


def _result(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        command, returncode, stdout=stdout, stderr=stderr
    )


def test_server_version_mapping_is_explicit_and_rejects_incompatible_servers():
    assert percona_apt.select_release(
        "8.4.5", "MySQL Community Server - GPL"
    ) == (
        percona_apt.XTRABACKUP_RELEASES["8.4"]
    )
    assert percona_apt.select_release(
        "8.0.34-0debian", "Percona Server (GPL)"
    ) == (
        percona_apt.XTRABACKUP_RELEASES["8.0"]
    )
    assert (
        percona_apt.select_release("8.0.33", "MySQL Community Server - GPL")
        is None
    )
    assert (
        percona_apt.select_release("9.0.1", "MySQL Community Server - GPL")
        is None
    )
    assert (
        percona_apt.select_release("10.11.6-MariaDB", "MariaDB Server") is None
    )
    assert (
        percona_apt.select_release("8.0.36", "MariaDB compatibility layer")
        is None
    )
    assert percona_apt.select_release("8.0.36", "unknown vendor") is None
    assert percona_apt.select_release("8.4.5", "") is None


def test_policy_object_is_shared_with_the_physical_backend():
    from deploy.backup import physical as xtrabackup

    selected = percona_apt.select_release(
        "8.4.5", "MySQL Community Server - GPL"
    )

    assert selected is xtrabackup.select_release(
        "8.4.5", "MySQL Community Server - GPL"
    )
    assert selected is percona_apt.XTRABACKUP_RELEASES["8.4"]


def test_fixed_debian_versions_are_derived_only_from_a_valid_codename():
    assert (
        percona_apt.debian_package_version(
            percona_apt.XTRABACKUP_RELEASES["8.4"], "bookworm"
        )
        == "8.4.0-6-1.bookworm"
    )
    assert (
        percona_apt.debian_package_version(
            percona_apt.XTRABACKUP_RELEASES["8.0"], "trixie"
        )
        == "8.0.35-36-1.trixie"
    )
    with pytest.raises(percona_apt.ProvisioningError, match="codename"):
        percona_apt.debian_package_version(
            percona_apt.XTRABACKUP_RELEASES["8.4"], "../stable"
        )


def test_read_debian_identity_rejects_non_debian_and_missing_codename(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID="debian"\nVERSION_CODENAME=bookworm\n')
    assert percona_apt.read_debian_identity(os_release) == (
        "debian",
        "bookworm",
    )

    os_release.write_text("ID=ubuntu\nVERSION_CODENAME=jammy\n")
    with pytest.raises(percona_apt.ProvisioningError, match="仅支持 Debian"):
        percona_apt.read_debian_identity(os_release)

    os_release.write_text("ID=debian\n")
    with pytest.raises(percona_apt.ProvisioningError, match="codename"):
        percona_apt.read_debian_identity(os_release)


class _Response:
    def __init__(self, payload: bytes, url: str):
        self.payload = payload
        self.url = url
        self.offset = 0

    def read(self, size=-1):
        if size < 0:
            size = len(self.payload) - self.offset
        result = self.payload[self.offset : self.offset + size]
        self.offset += len(result)
        return result

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_bootstrap_download_is_private_fsynced_and_hash_pinned(tmp_path):
    tmp_path.chmod(0o700)
    payload = b"pinned percona release package"
    package = replace(
        percona_apt.PERCONA_RELEASE,
        url="https://repo.percona.com/apt/fixed.deb",
        sha256=hashlib.sha256(payload).hexdigest(),
    )

    def opener(request, *, timeout):
        assert request.full_url == package.url
        assert timeout == 30
        return _Response(payload, package.url)

    output = percona_apt.download_bootstrap(
        tmp_path, package=package, opener=opener
    )
    try:
        assert output.read_bytes() == payload
        assert output.stat().st_mode & 0o777 == 0o600
    finally:
        output.unlink()


@pytest.mark.parametrize("failure", ["hash", "redirect"])
def test_bootstrap_download_removes_untrusted_partial_file(tmp_path, failure):
    tmp_path.chmod(0o700)
    payload = b"unexpected"
    package = replace(
        percona_apt.PERCONA_RELEASE,
        url="https://repo.percona.com/apt/fixed.deb",
        sha256=(
            "0" * 64
            if failure == "hash"
            else hashlib.sha256(payload).hexdigest()
        ),
    )
    resolved_url = (
        "https://cdn.invalid/fixed.deb" if failure == "redirect" else package.url
    )

    with pytest.raises(percona_apt.ProvisioningError):
        percona_apt.download_bootstrap(
            tmp_path,
            package=package,
            opener=lambda *_args, **_kwargs: _Response(payload, resolved_url),
        )
    assert list(tmp_path.iterdir()) == []


def test_bootstrap_metadata_uses_unambiguous_dpkg_show_format(tmp_path):
    package = percona_apt.PERCONA_RELEASE
    archive = tmp_path / "percona-release.deb"
    archive.write_bytes(b"validated elsewhere")
    calls = []

    def run(command, *, env=None, check=False):
        calls.append(list(command))
        return _result(
            command,
            stdout=(
                f"{package.package}\n{package.version}\n"
                f"{package.architecture}\n"
            ),
        )

    percona_apt._verify_bootstrap_metadata(archive, package, run)

    assert calls == [[
        percona_apt.DPKG_DEB,
        "--show",
        "--showformat=${Package}\\n${Version}\\n${Architecture}\\n",
        str(archive),
    ]]


def test_bootstrap_network_error_is_normalized_for_fallback_policy(tmp_path):
    tmp_path.chmod(0o700)

    def unavailable(*_args, **_kwargs):
        raise urllib.error.URLError("offline")

    with pytest.raises(percona_apt.ProvisioningError, match="下载"):
        percona_apt.download_bootstrap(tmp_path, opener=unavailable)
    assert list(tmp_path.iterdir()) == []


def test_apt_simulation_allows_only_new_dependencies_and_known_xtrabackup_swap():
    version = "8.4.0-6-1.bookworm"
    output = "\n".join(
        [
            "Remv percona-xtrabackup-80 [8.0.35-36-1.bookworm]",
            "Inst libaio1 (0.3.113-4 Debian:12.0/stable [amd64])",
            f"Inst percona-xtrabackup-84 ({version} repo [amd64])",
            f"Conf percona-xtrabackup-84 ({version} repo [amd64])",
        ]
    )

    actions = percona_apt.validate_apt_simulation(
        output,
        installed_before={"percona-xtrabackup-80": "8.0.35-36-1.bookworm"},
        target_package="percona-xtrabackup-84",
        target_version=version,
        mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        removable=frozenset({"percona-xtrabackup-80"}),
    )

    assert [action.operation for action in actions] == [
        "Remv",
        "Inst",
        "Inst",
        "Conf",
    ]


def test_apt_simulation_rejects_upgrade_of_an_existing_dependency():
    output = "\n".join(
        [
            "Inst libcurl4:amd64 [7.88.1-10] (7.88.1-11 Debian [amd64])",
            "Inst percona-xtrabackup-84 (8.4.0-6-1.bookworm repo [amd64])",
        ]
    )
    with pytest.raises(percona_apt.ProvisioningError, match="既有依赖"):
        percona_apt.validate_apt_simulation(
            output,
            installed_before={"libcurl4:amd64": "7.88.1-10"},
            target_package="percona-xtrabackup-84",
            target_version="8.4.0-6-1.bookworm",
            mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        )


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        (
            "Inst mysql-server (8.0.36 Debian [amd64])\n"
            "Inst percona-xtrabackup-84 (8.4.0-6-1.bookworm repo [amd64])",
            "受保护服务",
        ),
        (
            "Remv redis-server [7.0]\n"
            "Inst percona-xtrabackup-84 (8.4.0-6-1.bookworm repo [amd64])",
            "移除未授权",
        ),
    ],
)
def test_apt_simulation_rejects_service_install_and_unrelated_removal(
    operation, message
):
    with pytest.raises(percona_apt.ProvisioningError, match=message):
        percona_apt.validate_apt_simulation(
            operation,
            installed_before={},
            target_package="percona-xtrabackup-84",
            target_version="8.4.0-6-1.bookworm",
            mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        )


def test_apt_simulation_requires_the_exact_target_version():
    with pytest.raises(percona_apt.ProvisioningError, match="未锁定目标版本"):
        percona_apt.validate_apt_simulation(
            "Inst percona-xtrabackup-84 (8.4.0-7-1.bookworm repo [amd64])",
            installed_before={},
            target_package="percona-xtrabackup-84",
            target_version="8.4.0-6-1.bookworm",
            mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        )


def test_apt_simulation_rejects_configuring_a_preexisting_unpacked_service():
    output = "\n".join(
        [
            "Conf mysql-server (8.0.36 Debian [amd64])",
            "Inst percona-xtrabackup-84 (8.4.0-6-1.bookworm repo [amd64])",
        ]
    )
    with pytest.raises(percona_apt.ProvisioningError, match="未由本次安装引入"):
        percona_apt.validate_apt_simulation(
            output,
            installed_before={},
            target_package="percona-xtrabackup-84",
            target_version="8.4.0-6-1.bookworm",
            mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        )


def test_repository_file_requires_https_and_dedicated_signed_by(tmp_path):
    release = percona_apt.XTRABACKUP_RELEASES["8.4"]
    source = tmp_path / "percona-pxb-84-lts-release.list"
    source.write_text(
        "deb [signed-by=/usr/share/keyrings/percona-keyring.gpg] "
        "https://repo.percona.com/pxb-84-lts/apt bookworm main\n"
        "deb-src [signed-by=/usr/share/keyrings/percona-keyring.gpg] "
        "https://repo.percona.com/pxb-84-lts/apt bookworm main\n"
    )
    percona_apt._validate_repository_file(
        release, "bookworm", sources_directory=tmp_path
    )

    source.write_text(
        "deb [trusted=yes] http://repo.percona.com/pxb-84-lts/apt bookworm main\n"
    )
    with pytest.raises(percona_apt.ProvisioningError, match="HTTPS"):
        percona_apt._validate_repository_file(
            release, "bookworm", sources_directory=tmp_path
        )


def test_madison_version_must_have_one_exact_percona_origin():
    release = percona_apt.XTRABACKUP_RELEASES["8.4"]
    output = (
        "percona-xtrabackup-84 | 8.4.0-6-1.bookworm | "
        "https://repo.percona.com/pxb-84-lts/apt bookworm/main amd64 Packages\n"
    )
    assert (
        percona_apt._select_exact_package_version(release, "bookworm", output)
        == "8.4.0-6-1.bookworm"
    )

    duplicate = output + output.replace("repo.percona.com", "mirror.invalid")
    with pytest.raises(percona_apt.ProvisioningError, match="来源不唯一"):
        percona_apt._select_exact_package_version(
            release, "bookworm", duplicate
        )


def test_guarded_install_uses_root_simulation_before_noninteractive_actual_install():
    version = "8.4.0-6-1.bookworm"
    calls = []
    snapshots = iter(
        [
            "base-files\t12.4\tii \n",
            "base-files\t12.4\tii \n",
            (
                "base-files\t12.4\tii \n"
                f"percona-xtrabackup-84\t{version}\tii \n"
            ),
        ]
    )

    def run(command, *, env=None, check=False):
        calls.append((list(command), env, check))
        if command[:2] == [percona_apt.DPKG_QUERY, "-W"]:
            return _result(command, stdout=next(snapshots))
        if "--simulate" in command:
            return _result(
                command,
                stdout=(
                    "Inst libaio1 (0.3.113 Debian [amd64])\n"
                    f"Inst percona-xtrabackup-84 ({version} repo [amd64])\n"
                ),
            )
        return _result(command)

    percona_apt._run_guarded_install(
        run,
        target=f"percona-xtrabackup-84={version}",
        target_package="percona-xtrabackup-84",
        target_version=version,
        mutable_existing=percona_apt.KNOWN_XTRABACKUP_PACKAGES,
        reinstall=True,
    )

    apt_calls = [
        command for command, _, _ in calls if percona_apt.APT_GET in command
    ]
    assert len(apt_calls) == 2
    assert "--simulate" in apt_calls[0]
    assert "--yes" in apt_calls[1]
    for command in apt_calls:
        assert command[:2] == [percona_apt.SUDO, percona_apt.ENV]
        assert "DEBIAN_FRONTEND=noninteractive" in command
        assert "NEEDRESTART_MODE=l" in command
        assert "APT::Get::AllowUnauthenticated=false" in command
        assert "--no-install-recommends" in command
        assert "--no-remove" in command
        assert "--allow-change-held-packages" not in command
        assert "--allow-remove-essential" not in command
        assert "--allow-unauthenticated" not in command


def test_sudo_validation_inherits_terminal_instead_of_capturing_password_prompt(
    monkeypatch,
):
    observed = {}

    def fake_subprocess_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return _result(command)

    monkeypatch.setattr(percona_apt.subprocess, "run", fake_subprocess_run)

    percona_apt._checked(
        percona_apt.run_command,
        [percona_apt.SUDO, "-v"],
        purpose="sudo 认证",
        interactive=True,
    )

    assert observed["command"] == ["/usr/bin/sudo", "-v"]
    assert observed["capture_output"] is False
    assert "stdin" not in observed
    assert "stdout" not in observed
    assert "stderr" not in observed


def test_all_privileged_and_package_tools_use_debian_absolute_paths():
    tools = (
        percona_apt.SUDO,
        percona_apt.ENV,
        percona_apt.APT_GET,
        percona_apt.APT_CACHE,
        percona_apt.DPKG_QUERY,
        percona_apt.DPKG,
        percona_apt.DPKG_DEB,
        percona_apt.GPG,
        percona_apt.PERCONA_RELEASE_COMMAND,
        percona_apt.XTRABACKUP,
    )
    assert all(tool.startswith("/usr/bin/") for tool in tools)


def test_post_install_validation_requires_dpkg_owner_integrity_and_exact_binary_version():
    release = percona_apt.XTRABACKUP_RELEASES["8.0"]
    version = "8.0.35-36-1.bookworm"

    def run(command, *, env=None, check=False):
        if command[0] == percona_apt.DPKG_QUERY and command[1] == "-W":
            return _result(
                command, stdout=f"install ok installed\t{version}\n"
            )
        if command[:2] == [percona_apt.DPKG_QUERY, "-S"]:
            return _result(
                command,
                stdout="percona-xtrabackup-80: /usr/bin/xtrabackup\n",
            )
        if command[:2] == [percona_apt.DPKG, "--verify"]:
            return _result(command)
        if command[0] == percona_apt.XTRABACKUP:
            return _result(
                command,
                stderr=(
                    "xtrabackup version 8.0.35-36 based on MySQL server 8.0.35\n"
                ),
            )
        raise AssertionError(command)

    assert percona_apt._installed_xtrabackup_is_valid(
        release, version, run
    )

    def wrong_version(command, *, env=None, check=False):
        result = run(command, env=env, check=check)
        if command[0] == percona_apt.XTRABACKUP:
            return _result(command, stderr="xtrabackup version 8.0.35-35\n")
        return result

    assert not percona_apt._installed_xtrabackup_is_valid(
        release, version, wrong_version
    )


def test_public_provisioner_normalizes_missing_host_tools_for_fallback(tmp_path):
    (tmp_path / "os-release").write_text(
        "ID=debian\nVERSION_CODENAME=bookworm\n", encoding="utf-8"
    )

    def missing_tool(*_args, **_kwargs):
        raise FileNotFoundError("sudo")

    with pytest.raises(percona_apt.ProvisioningError, match="自动安装失败"):
        percona_apt.provision_xtrabackup(
            percona_apt.XTRABACKUP_RELEASES["8.4"],
            work_directory=tmp_path,
            run=missing_tool,
            os_release=tmp_path / "os-release",
        )


def test_public_provisioner_runs_the_complete_pinned_install_flow(
    monkeypatch, tmp_path
):
    release = percona_apt.XTRABACKUP_RELEASES["8.4"]
    package_version = "8.4.0-6-1.bookworm"
    os_release = tmp_path / "os-release"
    sources = tmp_path / "sources.list.d"
    os_release.write_text(
        "ID=debian\nVERSION_CODENAME=bookworm\n", encoding="utf-8"
    )
    sources.mkdir()
    tmp_path.chmod(0o700)

    installed: dict[str, str] = {}
    calls: list[tuple[list[str], dict[str, object]]] = []
    bootstrap_path = tmp_path / "percona-release-test.deb"

    def fake_download(work_directory, *, package, opener):
        assert work_directory == tmp_path
        assert package is percona_apt.PERCONA_RELEASE
        bootstrap_path.write_bytes(b"validated elsewhere")
        return bootstrap_path

    monkeypatch.setattr(percona_apt, "download_bootstrap", fake_download)

    def installed_packages_output() -> str:
        return "".join(
            f"{name}\t{version}\tii \n"
            for name, version in sorted(installed.items())
        )

    def run(command, *, env=None, check=False, interactive=False):
        command = [str(argument) for argument in command]
        calls.append(
            (
                command,
                {"env": env, "check": check, "interactive": interactive},
            )
        )

        if command == [percona_apt.DPKG, "--print-architecture"]:
            return _result(command, stdout="amd64\n")
        if command == [percona_apt.SUDO, "-v"]:
            assert interactive is True
            return _result(command)
        if command[:2] == [percona_apt.DPKG_QUERY, "-W"]:
            if any("${binary:Package}" in argument for argument in command):
                return _result(command, stdout=installed_packages_output())
            package = command[-1]
            version = installed.get(package)
            if version is None:
                return _result(command, returncode=1)
            return _result(
                command, stdout=f"install ok installed\t{version}\n"
            )
        if command[:2] == [percona_apt.DPKG_QUERY, "-S"]:
            return _result(
                command,
                stdout=f"{release.package_name}: {percona_apt.XTRABACKUP}\n",
            )
        if command[:2] == [percona_apt.DPKG, "--verify"]:
            return _result(command)
        if command[0] == percona_apt.DPKG_DEB:
            bootstrap = percona_apt.PERCONA_RELEASE
            return _result(
                command,
                stdout=(
                    f"{bootstrap.package}\n{bootstrap.version}\n"
                    f"{bootstrap.architecture}\n"
                ),
            )
        if command[0] == percona_apt.GPG:
            fingerprint = percona_apt.PERCONA_RELEASE.key_fingerprint
            return _result(command, stdout=f"fpr:::::::::{fingerprint}:\n")
        if percona_apt.PERCONA_RELEASE_COMMAND in command:
            source = sources / f"percona-{release.apt_repository}-release.list"
            source.write_text(
                "deb "
                f"[signed-by={percona_apt.PERCONA_KEYRING}] "
                f"{percona_apt.PERCONA_REPO_ROOT}/"
                f"{release.apt_repository}/apt bookworm main\n",
                encoding="utf-8",
            )
            return _result(command)
        if command[0] == percona_apt.APT_CACHE:
            return _result(
                command,
                stdout=(
                    f"{release.package_name} | {package_version} | "
                    f"{percona_apt.PERCONA_REPO_ROOT}/"
                    f"{release.apt_repository}/apt bookworm/main "
                    "amd64 Packages\n"
                ),
            )
        if percona_apt.APT_GET in command:
            if "update" in command:
                return _result(command)
            target = command[-1]
            if target == str(bootstrap_path):
                package = percona_apt.PERCONA_RELEASE.package
                version = percona_apt.PERCONA_RELEASE.version
            else:
                assert target == f"{release.package_name}={package_version}"
                package = release.package_name
                version = package_version
            output = f"Inst {package} ({version} test [amd64])\n"
            output += f"Conf {package} ({version} test [amd64])\n"
            if "--simulate" in command:
                return _result(command, stdout=output)
            installed[package] = version
            return _result(command, stdout=output)
        if command == [percona_apt.XTRABACKUP, "--version"]:
            return _result(
                command,
                stderr=f"xtrabackup version {release.upstream_version}\n",
            )
        raise AssertionError(f"unexpected command: {command}")

    result = percona_apt.provision_xtrabackup(
        release,
        work_directory=tmp_path,
        run=run,
        opener=lambda *_args, **_kwargs: pytest.fail("download is stubbed"),
        os_release=os_release,
        sources_directory=sources,
    )

    assert result == percona_apt.ProvisionResult(
        release=release,
        package_version=package_version,
        installed_by_deploy=True,
    )
    assert installed[percona_apt.PERCONA_RELEASE.package] == (
        percona_apt.PERCONA_RELEASE.version
    )
    assert installed[release.package_name] == package_version
    assert not bootstrap_path.exists()
    assert sum(command == [percona_apt.SUDO, "-v"] for command, _ in calls) == 1
    assert any(
        percona_apt.PERCONA_RELEASE_COMMAND in command for command, _ in calls
    )
    assert any(
        percona_apt.APT_GET in command
        and "--simulate" not in command
        and command[-1] == f"{release.package_name}={package_version}"
        for command, _ in calls
    )
