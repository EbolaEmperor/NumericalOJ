import hashlib
import io
from types import SimpleNamespace

import pytest

from deploy import prepare_nvidia_cdi as cdi

UUID = 'GPU-12345678-1234-1234-1234-123456789abc'


class Response(io.BytesIO):
    def geturl(self):
        return cdi.URL


@pytest.mark.parametrize('failure', [None, 'size', 'hash', 'redirect'])
def test_download_verifies_pinned_package(tmp_path, monkeypatch, failure):
    raw = b'CDI package fixture'
    monkeypatch.setattr(cdi, 'PACKAGE_BYTES', len(raw) - (failure == 'size'))
    monkeypatch.setattr(cdi, 'SHA256', '0' * 64 if failure == 'hash' else hashlib.sha256(raw).hexdigest())
    response = Response(raw)
    if failure == 'redirect':
        response.geturl = lambda: 'https://unexpected.example/package.deb'
    if failure:
        with pytest.raises(cdi.apt.ProvisioningError):
            cdi.download(tmp_path, opener=lambda *_a, **_kw: response)
    else:
        assert cdi.download(tmp_path, opener=lambda *_a, **_kw: response).read_bytes() == raw


def setup_host(monkeypatch, installed, *, listing=None):
    commands = []
    monkeypatch.setattr(cdi.shutil, 'which', lambda _: '/usr/bin/nvidia-smi')
    monkeypatch.setattr(cdi.apt, 'read_debian_identity', lambda _: ('debian', 'bookworm'))
    monkeypatch.setattr(cdi.apt, '_installed_packages', lambda _: installed)

    def checked(_run, args, **kwargs):
        commands.append(args)
        output = ''
        if '--query-gpu=uuid' in args:
            output = UUID
        elif '--print-architecture' in args:
            output = 'amd64'
        elif args[-2:] == ['cdi', 'list']:
            output = listing if listing is not None else f'nvidia.com/gpu={UUID}\n'
        return SimpleNamespace(stdout=output, stderr='', returncode=0)
    monkeypatch.setattr(cdi.apt, '_checked', checked)
    return commands


def test_existing_component_only_refreshes_cdi_without_docker_restart(monkeypatch):
    commands = setup_host(monkeypatch, {cdi.PACKAGE: cdi.VERSION})
    cdi.ensure()
    assert ['sudo', 'systemctl', 'restart', 'docker'] not in commands
    assert not any('apt-get' in arg or 'cuda' in arg for command in commands for arg in command)
    assert any(command[-2:] == ['restart', 'nvidia-cdi-refresh.service'] for command in commands)


def test_missing_component_uses_guarded_install_with_no_mutable_existing_packages(monkeypatch):
    installed = {}
    setup_host(monkeypatch, installed)
    monkeypatch.setattr(cdi, 'download', lambda root, **_: root / 'package.deb')
    monkeypatch.setattr(cdi.apt, '_verify_bootstrap_metadata', lambda *_: None)
    calls = []
    def install(_run, **kwargs):
        calls.append(kwargs)
        installed[cdi.PACKAGE] = cdi.VERSION
    monkeypatch.setattr(cdi.apt, '_run_guarded_install', install)
    cdi.ensure()
    assert calls[0]['target_package'] == cdi.PACKAGE
    assert calls[0]['target_version'] == cdi.VERSION
    assert calls[0]['mutable_existing'] == frozenset()


def test_unexpected_installed_version_is_not_overwritten(monkeypatch):
    setup_host(monkeypatch, {cdi.PACKAGE: 'different'})
    with pytest.raises(cdi.apt.ProvisioningError, match='显式协调'):
        cdi.ensure()


def test_cdi_missing_uuid_fails_closed(monkeypatch):
    setup_host(monkeypatch, {cdi.PACKAGE: cdi.VERSION}, listing='nvidia.com/gpu=all')
    with pytest.raises(cdi.apt.ProvisioningError, match='UUID'):
        cdi.ensure()


def test_cpu_host_does_not_install_toolkit(monkeypatch):
    monkeypatch.setattr(cdi.shutil, 'which', lambda _: None)
    cdi.ensure(run=lambda *_a, **_kw: pytest.fail('CPU host must not provision GPU packages'))
