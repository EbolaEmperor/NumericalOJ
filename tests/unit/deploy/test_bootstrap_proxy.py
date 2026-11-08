import json
import os
from types import SimpleNamespace

import pytest

from deploy import bootstrap_proxy as proxy


def test_existing_site_does_not_reconfigure_or_restart_daemon(tmp_path):
    assert proxy.prepare_proxy(tmp_path, environ={"http_proxy": "http://127.0.0.1:18080"},
                               run=lambda *a, **k: pytest.fail("旧站点不得修改 Docker")) == {}


def test_first_site_persists_proxy_without_secrets_in_command_arguments(tmp_path):
    state = tmp_path / ".deploy"
    state.mkdir(mode=0o700)
    (state / "new-local-site.json").write_text("{}")
    calls = []
    secret_url = "http://operator:private-password@127.0.0.1:18080"
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=1 if "test" in command else 0, stdout="")
    values = proxy.prepare_proxy(tmp_path, environ={"http_proxy": secret_url, "https_proxy": secret_url}, run=run)
    assert values["HTTP_PROXY"] == secret_url
    assert all("private-password" not in str(call) for call in calls)
    saved = state / "download-proxy.json"
    assert saved.stat().st_mode & 0o777 == 0o600
    assert not list(state.glob(".docker-proxy-*"))
    settings = proxy.build_settings(tmp_path)
    assert settings["build_args"] == ["--network=host", "--build-arg", "HTTP_PROXY", "--build-arg", "HTTPS_PROXY", "--build-arg", "NO_PROXY", "--build-arg", "http_proxy", "--build-arg", "https_proxy", "--build-arg", "no_proxy"]
    for name, value in values.items():
        assert settings["environment"][name] == settings["environment"][name.lower()] == value
    assert proxy.prepare_proxy(tmp_path, environ={}, run=lambda *a, **k: pytest.fail("重复发布不得重启daemon")) == values


def test_first_site_with_existing_containers_refuses_daemon_restart(tmp_path):
    state = tmp_path / ".deploy"
    state.mkdir()
    (state / "new-local-site.json").write_text("{}")
    with pytest.raises(proxy.BootstrapProxyError, match="已有容器"):
        proxy.prepare_proxy(tmp_path, environ={"http_proxy": "http://127.0.0.1:18080"},
                            run=lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="existing-container"))


def test_symlinked_or_foreign_proxy_record_is_not_read(tmp_path):
    state = tmp_path / ".deploy"
    state.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("private")
    (state / "download-proxy.json").symlink_to(secret)
    with pytest.raises(proxy.BootstrapProxyError, match="0600"):
        proxy.build_settings(tmp_path)


def test_official_registry_mirror_preserves_existing_daemon_configuration():
    def run(command, **kwargs):
        if "test" in command:
            return SimpleNamespace(returncode=1 if "-L" in command else 0, stdout="")
        return SimpleNamespace(returncode=0, stdout=json.dumps({"data-root": "/data/docker", "registry-mirrors": ["https://existing.example"]}))
    result = proxy._daemon_settings(run, [])
    assert result["data-root"] == "/data/docker"
    assert result["registry-mirrors"] == ["https://existing.example", "https://mirror.gcr.io"]


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://localhost/\nmalicious", "ssh://proxy"])
def test_proxy_configuration_rejects_non_http_urls_and_newlines(tmp_path, url):
    with pytest.raises(proxy.BootstrapProxyError):
        proxy.prepare_proxy(tmp_path, environ={"http_proxy": url})
