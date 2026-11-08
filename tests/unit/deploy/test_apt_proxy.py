"""宿主 APT 共用入口的代理文件生命周期。"""

from pathlib import Path
import subprocess

import pytest

from deploy import bootstrap
from deploy.backup import apt


@pytest.mark.parametrize("failure", [False, True])
def test_checked_apt_uses_private_proxy_file_without_exposing_credentials(monkeypatch, failure):
    secret = "http://deploy:private-apt-proxy@127.0.0.1:18080"
    monkeypatch.setattr(bootstrap, "_download_proxy_values", lambda: {"HTTPS_PROXY": secret})
    paths = []

    def run(command, **kwargs):
        index = command.index(apt.APT_GET)
        assert command[index + 1] == "-c"
        path = Path(command[index + 2])
        paths.append(path)
        assert path.stat().st_mode & 0o777 == 0o600
        assert f'Acquire::https::Proxy "{secret}";' in path.read_text()
        assert all("private-apt-proxy" not in value for value in command)
        assert not kwargs.get("env")
        if failure:
            raise OSError("无法运行 apt-get")
        return subprocess.CompletedProcess(command, 0, "", "")

    command = apt._sudo_command([apt.APT_GET, "--simulate", "install", "fresh=1"])
    if failure:
        with pytest.raises(apt.ProvisioningError, match="无法执行"):
            apt._checked(run, command, purpose="APT 模拟")
    else:
        apt._checked(run, command, purpose="APT 模拟")
    assert len(paths) == 1
    assert not paths[0].exists()
    assert command[-3:] == ["--simulate", "install", "fresh=1"]
    assert "-c" not in command


def test_checked_non_apt_command_never_loads_proxy_configuration(monkeypatch):
    def unexpected_proxy_read():
        raise AssertionError("非 APT 命令不得读取代理配置")

    monkeypatch.setattr(bootstrap, "_download_proxy_values", unexpected_proxy_read)
    command = [apt.DPKG_QUERY, "--version"]
    seen = []

    def run(arguments, **kwargs):
        seen.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "", "")

    apt._checked(run, command, purpose="读取 dpkg")
    assert seen == [command]


def test_apt_error_does_not_publish_proxy_credentials(monkeypatch):
    secret = "http://deploy:private-apt-proxy@127.0.0.1:18080"
    monkeypatch.setattr(bootstrap, "_download_proxy_values", lambda: {"HTTP_PROXY": secret})

    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, 100, "", f"无法连接代理 {secret}")

    with pytest.raises(apt.ProvisioningError, match="退出码 100") as error:
        apt._checked(run, [apt.APT_GET, "update"], purpose="刷新 APT")
    assert "private-apt-proxy" not in str(error.value)
