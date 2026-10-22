"""通用执行器的文件、命令、匿名产物与权限边界；不在宿主执行用户代码。"""

import base64
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from backend.oj_modules.vibehub import edu_process_runner as runner


def payload():
    return {'files': {'src/program.c': 'int main(void){return 0;}', 'bin/.keep': ''},
        'compile': {'argv': ['/usr/bin/gcc', '-I${WORKDIR}/include', '${WORKDIR}/src/program.c',
            '-o', '${WORKDIR}/bin/program'], 'seconds': 25},
        'run': {'stdin': 'opaque\ntext\x00data', 'seconds': 5}, 'executable': 'bin/program'}


def result(returncode=0, **flags):
    return {'returncode': returncode, 'stdout_b64': '', 'stderr_b64': '',
        'stdout_truncated': False, 'stderr_truncated': False, **flags}


def test_compile_failure_does_not_open_or_execute_any_artifact(monkeypatch):
    calls = []

    def build(command, **kwargs):
        calls.append((command, kwargs))
        root = Path(kwargs['workdir'])
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert (root / 'src/program.c').read_text() == payload()['files']['src/program.c']
        assert command == ['/usr/bin/gcc', f'-I{root}/include', f'{root}/src/program.c', '-o', f'{root}/bin/program']
        assert kwargs['seconds'] == 25 and kwargs['stdout_limit'] == runner.MAX_COMPILE_OUTPUT_BYTES
        return result(1)

    monkeypatch.setattr(runner, '_run', build)
    response = runner.execute(payload())
    assert response == {'compile': result(1)} and len(calls) == 1
    assert not Path(calls[0][1]['workdir']).exists()


def test_successful_build_executes_only_a_sealed_private_memory_copy(monkeypatch, tmp_path):
    calls, seals = [], []
    executable = b'fake executable, never run on host'

    def build_or_run(command, **kwargs):
        calls.append((command, kwargs))
        if len(calls) == 1:
            (Path(kwargs['workdir']) / 'bin/program').write_bytes(executable)
            return result()
        fd, = kwargs['pass_fds']
        assert command == [f'/proc/self/fd/{fd}']
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o500
        os.lseek(fd, 0, os.SEEK_SET)
        assert os.read(fd, len(executable) + 1) == executable
        assert kwargs['input_data'] == payload()['run']['stdin'].encode()
        assert kwargs['seconds'] == 5
        return result(stdout_truncated=True)

    def memory_file(_name, _flags):
        name = tmp_path / 'memory-file'
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        name.unlink()
        return fd

    monkeypatch.setattr(runner, '_run', build_or_run)
    monkeypatch.setattr(runner.os, 'memfd_create', memory_file, raising=False)
    for name, value in {'MFD_CLOEXEC': 1, 'MFD_ALLOW_SEALING': 2}.items():
        monkeypatch.setattr(runner.os, name, value, raising=False)
    for name, value in {'F_ADD_SEALS': 1033, 'F_SEAL_WRITE': 8, 'F_SEAL_GROW': 4,
                        'F_SEAL_SHRINK': 2, 'F_SEAL_SEAL': 1}.items():
        monkeypatch.setattr(runner.fcntl, name, value, raising=False)
    monkeypatch.setattr(runner.fcntl, 'fcntl', lambda *args: seals.append(args))
    response = runner.execute(payload())
    assert response['run']['stdout_truncated'] is True and len(calls) == 2
    assert seals[0][1:] == (1033, 15)
    assert not Path(calls[0][1]['workdir']).exists()


def test_artifact_open_rejects_symlink_components_and_leaf(tmp_path):
    root = tmp_path / 'work'
    outside = tmp_path / 'outside'
    root.mkdir()
    outside.mkdir()
    (outside / 'program').write_bytes(b'outside')
    (root / 'directory-link').symlink_to(outside, target_is_directory=True)
    (root / 'file-link').symlink_to(outside / 'program')
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in ('directory-link/program', 'file-link'):
            with pytest.raises(OSError):
                runner._open_artifact(root_fd, name)
    finally:
        os.close(root_fd)


@pytest.mark.parametrize('executable', ['../escape', '/absolute', 'one/../../escape', 'a\\b', 'a//b', './program'])
def test_file_names_cannot_escape_the_private_workdir(executable):
    request = payload()
    request['executable'] = executable
    with pytest.raises(ValueError):
        runner.validate_request(request)


@pytest.mark.parametrize('private_path', ['/app', '/run/vibehub', '/data'])
def test_main_refuses_readable_or_traversable_private_service_paths(monkeypatch, private_path):
    monkeypatch.setattr(runner.os, 'getuid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'getgid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'umask', lambda _value: None)
    monkeypatch.setattr(runner.os, 'access', lambda path, _mode: path == private_path)
    monkeypatch.setattr(runner.sys, 'argv', ['runner'])
    with pytest.raises(RuntimeError, match='私有目录权限未隔离'):
        runner.main()


def test_cleanup_still_runs_when_service_paths_are_not_private(monkeypatch, capsys):
    cleaned = []
    monkeypatch.setattr(runner.os, 'getuid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'getgid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'umask', lambda _value: None)
    monkeypatch.setattr(runner.os, 'access', lambda *_args: True)
    monkeypatch.setattr(runner.sys, 'argv', ['runner', '--cleanup'])
    monkeypatch.setattr(runner, 'cleanup', lambda: cleaned.append(True))
    runner.main()
    assert cleaned == [True] and capsys.readouterr().out == 'ok\n'


def test_main_rejects_oversized_input_before_execute(monkeypatch):
    monkeypatch.setattr(runner.os, 'getuid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'getgid', lambda: 100123)
    monkeypatch.setattr(runner.os, 'umask', lambda _value: None)
    monkeypatch.setattr(runner.os, 'access', lambda *_args: False)
    monkeypatch.setattr(runner.sys, 'argv', ['runner'])
    monkeypatch.setattr(runner.sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(b'x' * (runner.MAX_PAYLOAD_BYTES + 1))))
    monkeypatch.setattr(runner, 'execute', lambda *_args: pytest.fail('不得执行超限请求'))
    with pytest.raises(ValueError, match='执行请求超过限制'):
        runner.main()


def test_program_process_has_no_inherited_service_fds_or_environment(monkeypatch, tmp_path):
    resources, recorded = [], []

    def pipe_with_content(content):
        reader, writer = os.pipe()
        os.write(writer, content)
        os.close(writer)
        handle = os.fdopen(reader, 'rb', buffering=0)
        resources.append(handle)
        return handle

    read_fd, write_fd = os.pipe()
    resources.extend([os.fdopen(read_fd, 'rb', buffering=0), os.fdopen(write_fd, 'wb', buffering=0)])
    proc = SimpleNamespace(pid=123456789, stdin=resources[-1], stdout=pipe_with_content(b'hello'),
        stderr=pipe_with_content(b'error'), returncode=0, poll=lambda: 0, wait=lambda **_kwargs: 0)

    def popen(command, **kwargs):
        recorded.append((command, kwargs))
        return proc

    monkeypatch.setattr(runner.subprocess, 'Popen', popen)
    monkeypatch.setattr(runner.os, 'killpg', lambda *_args: None)
    monkeypatch.setattr(runner, '_kill_owned_processes', lambda: None)
    try:
        response = runner._run(['/proc/self/fd/123'], workdir=str(tmp_path), seconds=1, pass_fds=(123,))
    finally:
        for handle in resources:
            if not handle.closed:
                handle.close()
    kwargs = recorded[0][1]
    assert kwargs['close_fds'] is True and kwargs['pass_fds'] == (123,)
    assert kwargs['cwd'] == str(tmp_path) and kwargs['start_new_session'] is True
    assert set(kwargs['env']) == {'PATH', 'HOME', 'TMPDIR', 'LANG'}
    assert base64.b64decode(response['stdout_b64']) == b'hello'
    assert base64.b64decode(response['stderr_b64']) == b'error'
