from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

from flask import Flask
import pytest

from backend.oj_modules.api import vibehub_api
from backend.oj_modules.vibehub import git_source, services


@pytest.mark.parametrize('url', ['gitea@10.72.190.121:ebola/shot-cut-llm.git', 'https://example.org/a/b.git', 'http://10.72.190.121:3000/a/b.git', 'ssh://git@example.org:2222/a/b.git'])
def test_supported_remote_urls(url):
    assert git_source.validate_source(url, 'feature/layers') == (url, 'feature/layers')


@pytest.mark.parametrize('url', ['', None, '/etc/passwd', '../repo', 'file:///tmp/repo', 'ext::sh -c x', '-uhttps://host/a', 'https://name:password@example.org/repo', 'https://example.org/a?token=secret', 'git@example.org:repo\nother', 'https://example.org:bad/repo'])
def test_unsafe_sources_rejected(url):
    with pytest.raises(git_source.GitSourceError):
        git_source.validate_source(url)


@pytest.mark.parametrize('ref', ['--upload-pack=sh', '../main', 'main:other', 'a..b', 'x.lock', 'x/', 'main\n', True])
def test_refs_are_not_git_options(ref):
    with pytest.raises(git_source.GitSourceError):
        git_source.validate_source('https://example.org/repo', ref)


def test_git_environment_does_not_inherit_git_overrides(monkeypatch):
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'protocol.ext.allow')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', 'always')
    monkeypatch.setenv('GIT_SSH_COMMAND', 'sh /untrusted')
    env = git_source._git_environment()
    assert 'GIT_CONFIG_COUNT' not in env
    assert 'BatchMode=yes' in env['GIT_SSH_COMMAND']
    assert env['GIT_TERMINAL_PROMPT'] == '0'


def test_snapshot_is_a_fixed_commit_without_git_metadata_and_is_cleaned(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    git('init', '-q')
    (source / 'Dockerfile').write_text('FROM numericaloj-vibehub-runtime:1\n')
    (source / 'app.py').write_text('print("original")\n')
    git('add', '.')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'source')
    expected = git('rev-parse', 'HEAD')
    real_run = git_source._run
    def fake_network(args, **kwargs):
        if args[0] == 'clone':
            assert '--bare' in args and '--depth' in args and '--' in args
            shutil.copytree(source / '.git', args[-1])
            (source / 'app.py').write_text('uncommitted change')
        else:
            real_run(args, **kwargs)
    monkeypatch.setattr(git_source, '_run', fake_network)
    uploads = tmp_path / 'uploads'
    with git_source.git_package('git@example.org:owner/repo.git', upload_root=uploads) as (stream, info):
        assert info['commit'] == expected
        with zipfile.ZipFile(stream) as archive:
            assert archive.read('app.py') == b'print("original")\n'
            assert not any(name.startswith('.git/') for name in archive.namelist())
        assert list((uploads / '.staging').iterdir())
    assert list((uploads / '.staging').iterdir()) == []


@pytest.mark.parametrize('updating', [False, True])
def test_git_api_uses_preflight_and_existing_version_pipeline(tmp_path, monkeypatch, updating):
    app = Flask(__name__)
    app.config['VIBEHUB_UPLOAD_ROOT'] = tmp_path
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    actor = {'id': 1, 'is_admin': 1}
    monkeypatch.setattr(vibehub_api, 'current_user', lambda: actor)
    events = []
    monkeypatch.setattr(services, 'preflight_create_project', lambda *_: events.append('preflight'))
    monkeypatch.setattr(services, 'preflight_upload_project', lambda *_: events.append('preflight'))
    source = {'kind': 'git', 'url': 'git@example.org:owner/repo.git', 'ref': 'main', 'commit': 'a' * 40}
    @contextmanager
    def package(url, ref, **kwargs):
        assert events == ['preflight']
        assert url == source['url'] and ref == 'main'
        events.append('clone')
        yield BytesIO(b'zip content'), source
        events.append('cleanup')
    monkeypatch.setattr(git_source, 'git_package', package)
    def save(*args, **kwargs):
        assert args[0] == actor
        assert args[2 if updating else 1].read() == b'zip content'
        assert kwargs['source'] == source
        events.append('save')
        return {'slug': 'demo', 'source': source}
    monkeypatch.setattr(services, 'upload_new_version' if updating else 'create_project', save)
    response = app.test_client().post('/api/vibehub/projects/demo/versions' if updating else '/api/vibehub/projects',
        json={'source_type': 'git', 'git_url': source['url'], 'git_ref': 'main', 'title': 'Demo'})
    assert response.status_code == 201
    assert response.json['project']['source']['commit'] == 'a' * 40
    assert events == ['preflight', 'clone', 'save', 'cleanup']


def test_git_api_rejects_zip_and_git_combination_before_clone(tmp_path, monkeypatch):
    app = Flask(__name__)
    app.config['VIBEHUB_UPLOAD_ROOT'] = tmp_path
    app.register_blueprint(vibehub_api.vibehub_api_bp)
    monkeypatch.setattr(vibehub_api, 'current_user', lambda: {'id': 1})
    monkeypatch.setattr(services, 'preflight_create_project', lambda *_: None)
    monkeypatch.setattr(git_source, 'git_package', lambda *_a, **_kw: pytest.fail('must not clone'))
    response = app.test_client().post('/api/vibehub/projects', data={
        'git_url': 'git@example.org:a/b.git', 'package': (BytesIO(b'zip'), 'app.zip')})
    assert response.status_code == 400


def test_git_provenance_is_private():
    row = {'slug': 'demo', 'public_version_id': 1, 'public_version': 1, 'latest_version': 1,
           'public_manifest_json': json.dumps({'source': {'kind': 'git', 'url': 'git@example.org:private/repo.git', 'commit': 'a'*40}})}
    assert 'source' not in services._serialize_project(row, audience='public')
    private = services._serialize_project(row, audience='public', include_workflow=True)
    assert private['source']['kind'] == 'git'
    assert 'source' not in services._without_private_workflow(private)


@pytest.mark.parametrize('url,ref', [('https://[bad/repo', ''), ('https://example.org/a\x7f', ''), ('https://example.org/a', 'a/.hidden')])
def test_malformed_url_and_hidden_ref_components_are_rejected(url, ref):
    with pytest.raises(git_source.GitSourceError):
        git_source.validate_source(url, ref)


def test_failed_clone_cleans_staging(tmp_path, monkeypatch):
    def fail(*_args, **_kwargs):
        raise git_source.GitSourceError('unreachable')
    monkeypatch.setattr(git_source, '_run', fail)
    with pytest.raises(git_source.GitSourceError, match='unreachable'):
        with git_source.git_package('git@example.org:a/b.git', upload_root=tmp_path):
            pytest.fail('failed clone must not yield')
    assert list((tmp_path / '.staging').iterdir()) == []


@pytest.mark.parametrize('exhausted', ['timeout', 'size'])
def test_running_git_is_killed_when_budget_is_exhausted(tmp_path, monkeypatch, exhausted):
    class Process:
        pid = 987654
        returncode = None
        waited = False
        def poll(self):
            return None
        def wait(self):
            self.waited = True
    process = Process()
    monkeypatch.setattr(git_source.subprocess, 'Popen', lambda *_a, **_kw: process)
    killed = []
    monkeypatch.setattr(git_source.os, 'killpg', lambda *args: killed.append(args))
    monkeypatch.setattr(git_source, 'GIT_TIMEOUT_SECONDS', -1 if exhausted == 'timeout' else 60)
    monkeypatch.setattr(git_source.quotas, 'logical_tree_bytes', lambda _root: 2)
    with pytest.raises(git_source.GitSourceError):
        git_source._run(['clone'], root=tmp_path, output=tmp_path / 'out', limit=1)
    assert killed == [(process.pid, git_source.signal.SIGKILL)]
    assert process.waited
