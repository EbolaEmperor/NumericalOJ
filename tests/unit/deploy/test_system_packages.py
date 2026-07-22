from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from deploy import system_packages


def _result(command, *, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_parse_simulation_allows_only_new_clangd_dependencies():
    output = "\n".join(
        (
            "Inst libclang-common-14-dev (1:14.0.6-12 Debian:12 [all])",
            "Inst clangd (1:14.0-55.7~deb12u1 Debian:12 [amd64])",
            "Conf clangd (1:14.0-55.7~deb12u1 Debian:12 [amd64])",
        )
    )
    assert system_packages._parse_simulation(
        output, "1:14.0-55.7~deb12u1"
    ) == {"libclang-common-14-dev", "clangd"}


@pytest.mark.parametrize(
    "line, message",
    (
        ("Remv mysql-server [8.0]", "移除"),
        ("Inst python3 [3.11] (3.12 Debian:12)", "既有依赖"),
        ("Inst docker-helper (1 Debian:12)", "受保护"),
        ("Conf mysql-server (8.0 Debian:12)", "配置"),
    ),
)
def test_parse_simulation_rejects_unsafe_actions(line, message):
    with pytest.raises(system_packages.SystemPackageError, match=message):
        system_packages._parse_simulation(
            f"{line}\nInst clangd (1:14 Debian:12 [amd64])", "1:14"
        )


def test_ensure_clangd_installs_exact_apt_candidate(monkeypatch, tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID="debian"\nVERSION_CODENAME="bookworm"\n')
    works = iter((False, True))
    monkeypatch.setattr(system_packages, "_clangd_works", lambda **kwargs: next(works))
    commands = []
    state = {"installed": False}

    def run(command, **kwargs):
        interactive = bool(kwargs.get("interactive"))
        commands.append((command, interactive))
        if command[:2] == [system_packages.APT_CACHE, "policy"]:
            return _result(command, stdout="  Candidate: 1:14.0-55.7~deb12u1\n")
        if "--simulate" in command:
            return _result(
                command,
                stdout=(
                    "Inst libclang-common-14-dev (1:14.0.6-12 Debian:12 [all])\n"
                    "Inst clangd (1:14.0-55.7~deb12u1 Debian:12 [amd64])\n"
                ),
            )
        if command[:2] == [system_packages.DPKG_QUERY, "-W"]:
            output = (
                "clangd\t1:14.0-55.7~deb12u1\tii \n"
                if state["installed"]
                else ""
            )
            return _result(command, stdout=output)
        if "--yes" in command and "install" in command:
            state["installed"] = True
        return _result(command)

    assert system_packages.ensure_clangd(
        run=run,
        os_release=os_release,
        command_exists=lambda path: True,
    ) is True
    flattened = [" ".join(command) for command, _ in commands]
    assert any("apt-get --simulate" in command for command in flattened)
    assert any("clangd=1:14.0-55.7~deb12u1" in command for command in flattened)
    assert any(interactive for _, interactive in commands)


def test_deploy_calls_clangd_provisioner_before_candidate_images():
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    provision = script.index(
        "deploy/system_packages.py ensure-editor-runtime"
    )
    images = script.index("phase='构建判题镜像'")
    assert provision < images


def test_deploy_verifies_editor_runtime_after_install_and_before_images():
    script = (Path(__file__).resolve().parents[3] / "deploy.sh").read_text()
    install = script.index("--requirement requirements/production.txt")
    verify = script.index("deploy/verify_editor_runtime.py")
    images = script.index("phase='构建判题镜像'")
    assert install < verify < images


def test_system_package_cli_loads_from_script_path():
    script = Path(__file__).resolve().parents[3] / "deploy/system_packages.py"

    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "ensure-editor-runtime" in result.stdout


def test_ensure_editor_runtime_installs_clangd_and_bubblewrap_once(
    monkeypatch,
    tmp_path,
):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID="debian"\nVERSION_CODENAME="bookworm"\n')
    clangd_works = iter((False, True))
    bubblewrap_works = iter((False, True))
    monkeypatch.setattr(
        system_packages,
        "_clangd_works",
        lambda **kwargs: next(clangd_works),
    )
    monkeypatch.setattr(
        system_packages,
        "_bubblewrap_works",
        lambda **kwargs: next(bubblewrap_works),
    )
    commands = []
    installed: dict[str, str] = {}

    def run(command, **kwargs):
        commands.append(command)
        if command[:2] == [system_packages.APT_CACHE, "policy"]:
            package = command[2]
            version = "1:14.0" if package == "clangd" else "0.8.0"
            return _result(command, stdout=f"  Candidate: {version}\n")
        if "--simulate" in command:
            target = command[-1]
            package, version = target.split("=", 1)
            return _result(
                command,
                stdout=f"Inst {package} ({version} Debian:12 [amd64])\n",
            )
        if command[:2] == [system_packages.DPKG_QUERY, "-W"]:
            output = "".join(
                f"{package}\t{version}\tii \n"
                for package, version in installed.items()
            )
            return _result(command, stdout=output)
        if "--yes" in command and "install" in command:
            package, version = command[-1].split("=", 1)
            installed[package] = version
        return _result(command)

    assert system_packages.ensure_editor_runtime(
        run=run,
        os_release=os_release,
        command_exists=lambda path: True,
    ) == ("clangd", "bubblewrap")
    assert sum(
        command[:2] == [system_packages.APT_GET, "update"]
        or command[-1:] == ["update"]
        for command in commands
    ) == 1
    assert installed == {"clangd": "1:14.0", "bubblewrap": "0.8.0"}
