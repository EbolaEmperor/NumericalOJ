"""AppArmor 兼容只授予 Bubblewrap，保留网络/文件隔离和子进程能力剥夺。"""

import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from deploy import prepare_editor_sandbox as sandbox


def _result(code=0, *, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


@pytest.fixture
def restricted(tmp_path, monkeypatch):
    flag = tmp_path / "restriction"
    flag.write_text("1\n")
    parser = tmp_path / "apparmor_parser"
    parser.touch()
    monkeypatch.setattr(sandbox, "RESTRICTION", flag)
    monkeypatch.setattr(sandbox, "PARSER", str(parser))
    monkeypatch.setattr(sandbox.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda _: "/usr/bin/bwrap")
    return flag


def test_working_existing_sandbox_does_not_request_sudo_or_write_policy(restricted, monkeypatch):
    monkeypatch.setattr(sandbox, "_probe", lambda: _result())
    assert sandbox.ensure(run=lambda *_a, **_kw: pytest.fail("不应调用sudo")) is False


def test_known_restriction_uses_scoped_installer_and_rechecks_full_sandbox(restricted, monkeypatch):
    results = iter([_result(1, stderr="bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"), _result()])
    monkeypatch.setattr(sandbox, "_probe", lambda: next(results))
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return _result(stdout=json.dumps({"created": True}) if "--install-profile" in command else "")
    assert sandbox.ensure(run=run) is True
    assert calls[0][0] == [sandbox.apt.SUDO, "-v"] and calls[0][1]["interactive"]
    assert calls[1][0][-1] == "--install-profile" and "-I" in calls[1][0]
    assert restricted.read_text() == "1\n"


@pytest.mark.parametrize("created", [False, True])
def test_failed_probe_only_unloads_policy_created_by_this_invocation(restricted, monkeypatch, created):
    monkeypatch.setattr(sandbox, "_probe", lambda: _result(1, stderr="Operation not permitted"))
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        return _result(stdout=json.dumps({"created": created}) if "--install-profile" in command else "")
    with pytest.raises(sandbox.apt.ProvisioningError, match="仍不可用"):
        sandbox.ensure(run=run)
    assert any("--remove-created-profile" in command for command in calls) is created
    assert restricted.read_text() == "1\n"


def test_other_namespace_failures_never_disable_kernel_policy_or_install_profile(restricted, monkeypatch):
    restricted.write_text("0\n")
    monkeypatch.setattr(sandbox, "_probe", lambda: _result(1, stderr="Operation not permitted"))
    with pytest.raises(sandbox.apt.ProvisioningError, match="拒绝降低沙箱安全"):
        sandbox.ensure(run=lambda *_a, **_kw: pytest.fail("不得尝试sudo"))


def test_profile_keeps_unique_stacked_children_and_explicit_capability_denial():
    profile = sandbox.PROFILE_SOURCE.read_text()
    assert "profile numericaloj-editor-bwrap /usr/bin/bwrap" in profile
    assert "-> numericaloj-editor-bwrap//&numericaloj-editor-unpriv-bwrap" in profile
    assert "profile numericaloj-editor-unpriv-bwrap" in profile
    assert "audit deny capability," in profile
    assert "flags=(unconfined)" not in profile


@pytest.fixture
def privileged(tmp_path, monkeypatch):
    directory = tmp_path / "apparmor.d"
    directory.mkdir(mode=0o700)
    destination = directory / "numericaloj-editor-bwrap"
    source = tmp_path / "source-profile"
    source.write_text(sandbox.PROFILE_SOURCE.read_text())
    parser = tmp_path / "apparmor_parser"
    parser.write_text("parser")
    parser.chmod(0o755)
    monkeypatch.setattr(sandbox, "PROFILE_DESTINATION", destination)
    monkeypatch.setattr(sandbox, "PROFILE_SOURCE", source)
    monkeypatch.setattr(sandbox, "PARSER", str(parser))
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0)
    original_lstat = Path.lstat
    def metadata(path, *args, **kwargs):
        if str(path) == "/usr/bin/bwrap":
            return os.stat_result((stat.S_IFREG | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        value = original_lstat(path, *args, **kwargs)
        if path == directory or path.parent == directory or path == parser:
            fields = list(value)
            fields[4] = 0
            return os.stat_result(fields)
        return value
    monkeypatch.setattr(Path, "lstat", metadata)
    return destination, source


def test_installer_compiles_before_publishing_root_policy_and_is_idempotent(privileged):
    destination, source = privileged
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if "--skip-kernel-load" in command:
            assert not destination.exists() or destination.read_text() == source.read_text()
        return _result()
    assert sandbox.install_profile(run=run) is True
    assert destination.read_text() == source.read_text() and destination.stat().st_mode & 0o777 == 0o644
    assert sandbox.install_profile(run=run) is False
    assert len(calls) == 4
    assert "--skip-kernel-load" in calls[0] and "--replace" in calls[1]
    assert not list(destination.parent.glob(".numericaloj-editor-bwrap-*"))


@pytest.mark.parametrize("external_target", [False, True])
def test_installer_never_overwrites_external_profiles(privileged, external_target):
    destination, _source = privileged
    external = destination if external_target else destination.with_name("external")
    external.write_text("profile external /usr/bin/bwrap { userns, }\n")
    with pytest.raises(sandbox.apt.ProvisioningError, match="外部"):
        sandbox.install_profile(run=lambda *_a, **_kw: pytest.fail("不得加载或覆盖外部策略"))
    assert external.read_text().startswith("profile external")


def test_compile_failure_never_publishes_policy(privileged):
    destination, _source = privileged
    with pytest.raises(sandbox.apt.ProvisioningError, match="编译失败"):
        sandbox.install_profile(run=lambda *_a, **_kw: _result(1))
    assert not destination.exists()


def test_rollback_only_removes_unchanged_owned_policy(privileged):
    destination, source = privileged
    destination.write_text(source.read_text())
    destination.chmod(0o644)
    calls = []
    sandbox.remove_created_profile(run=lambda command, **kwargs: calls.append(command) or _result())
    assert not destination.exists() and "--remove" in calls[0]
    destination.write_text("external policy")
    with pytest.raises(sandbox.apt.ProvisioningError, match="拒绝回收"):
        sandbox.remove_created_profile(run=lambda *_a, **_kw: pytest.fail("不得卸载外部策略"))
