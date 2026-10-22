"""已有作品容器的固定执行命令、随机身份和独立故障清理。"""

import base64
import json
import subprocess

import pytest

from backend.oj_modules.vibehub import edu_cpp, edu_cpp_runner, runtime


CONTAINER = "numoj-vh-" + "a" * 16 + "-" + "b" * 40


def test_execution_only_uses_existing_container_exec_and_the_platform_driver():
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[-1] == "--cleanup":
            return runtime._BinaryCommandResult(0, b"ok\n", b"")
        assert json.loads(kwargs["input_bytes"]) == {"source": "student source"}
        return runtime._BinaryCommandResult(0, b'{"compile":{}}', b"")

    docker = runtime.DockerCLI(binary_command_runner=run)
    assert docker.execute_edu_cpp(CONTAINER, {"source": "student source"}) == {"compile": {}}
    assert len(calls) == 2
    command, limits = calls[0]
    assert command[:4] == ["docker", "exec", "-i", "--user"]
    uid, gid = map(int, command[4].split(":"))
    assert uid == gid and uid >= 100_000
    assert command[5:9] == [CONTAINER, "python3", "-I", "-c"]
    assert "os.memfd_create" in command[9]
    assert "student source" not in command[9]
    assert calls[1][0] == [*command, "--cleanup"]
    assert limits["stdout_limit"] == 2 * 1024 * 1024
    assert calls[1][1]["input_bytes"] == b""
    assert calls[1][1]["timeout"] == 5


def test_each_execution_uses_a_new_uid(monkeypatch):
    values = iter([100, 200])
    monkeypatch.setattr(runtime.secrets, "randbelow", lambda _upper: next(values))
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        return runtime._BinaryCommandResult(0, b"ok\n" if command[-1] == "--cleanup" else b"{}", b"")

    docker = runtime.DockerCLI(binary_command_runner=run)
    docker.execute_edu_cpp(CONTAINER, {})
    docker.execute_edu_cpp(CONTAINER, {})
    assert calls[0][4] == "100100:100100"
    assert calls[2][4] == "100200:100200"


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "output", "invalid-json"])
def test_execution_failure_still_runs_independent_container_cleanup(failure):
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        if command[-1] == "--cleanup":
            return runtime._BinaryCommandResult(0, b"ok\n", b"")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 40)
        if failure == "nonzero":
            return runtime._BinaryCommandResult(137, b"", b"")
        if failure == "output":
            return runtime._BinaryCommandResult(0, b"{}", b"", stdout_truncated=True)
        return runtime._BinaryCommandResult(0, b"not-json", b"")

    with pytest.raises(runtime.VibeHubRuntimeError):
        runtime.DockerCLI(binary_command_runner=run).execute_edu_cpp(CONTAINER, {})
    assert len(calls) == 2 and calls[-1][-1] == "--cleanup"


def test_cleanup_failure_removes_the_existing_instance_instead_of_leaving_processes(monkeypatch):
    removed = []

    def run(command, **_kwargs):
        return runtime._BinaryCommandResult(1, b"", b"") if command[-1] == "--cleanup" else (
            runtime._BinaryCommandResult(0, b"{}", b""))

    docker = runtime.DockerCLI(binary_command_runner=run)
    monkeypatch.setattr(docker, "remove_container", removed.append)
    with pytest.raises(runtime.VibeHubRuntimeError, match="运行实例已回收"):
        docker.execute_edu_cpp(CONTAINER, {})
    assert removed == [CONTAINER]


@pytest.mark.parametrize("container_name,timeout", [("ordinary-container", 40),
    (CONTAINER + ";other", 40), (CONTAINER, True), (CONTAINER, float("nan")), (CONTAINER, 46)])
def test_invalid_container_or_limits_never_run_docker(container_name, timeout):
    def forbidden(*_args, **_kwargs):
        pytest.fail("不得调用 Docker")
    with pytest.raises(runtime.VibeHubRuntimeError):
        runtime.DockerCLI(binary_command_runner=forbidden).execute_edu_cpp(container_name, {}, timeout=timeout)


def test_compile_output_has_a_smaller_budget_without_starting_the_program(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return {"returncode": 0, "stdout_b64": "", "stderr_b64": "",
            "stdout_truncated": True, "stderr_truncated": False}

    monkeypatch.setattr(edu_cpp_runner, '_run', run)
    result = edu_cpp_runner.execute({'source': 'student source', 'api_header': 'header',
        'harness': 'driver', 'inputs': [7], 'timeout_seconds': 5})
    assert set(result) == {'compile'}
    assert len(calls) == 1
    assert calls[0][1]['stdout_limit'] == edu_cpp_runner.MAX_COMPILE_OUTPUT_BYTES == 16 * 1024


def test_combined_maximum_stage_output_fits_transport_and_remains_a_student_error():
    def stage(stdout_size, *, overflow=False):
        return {'returncode': 0, 'stdout_b64': base64.b64encode(b'x' * stdout_size).decode(),
            'stderr_b64': base64.b64encode(b'e' * edu_cpp_runner.MAX_ERROR_BYTES).decode(),
            'stdout_truncated': overflow, 'stderr_truncated': False}

    response = {'compile': stage(edu_cpp_runner.MAX_COMPILE_OUTPUT_BYTES),
        'run': stage(edu_cpp_runner.MAX_OUTPUT_BYTES, overflow=True)}
    encoded = json.dumps(response, separators=(',', ':')).encode()

    def run(command, **kwargs):
        if command[-1] == '--cleanup':
            return runtime._BinaryCommandResult(0, b'ok\n', b'')
        assert len(encoded) < kwargs['stdout_limit']
        return runtime._BinaryCommandResult(0, encoded, b'')

    docker = runtime.DockerCLI(binary_command_runner=run)
    result = edu_cpp.run_code('int step(int x){return x;}', [7], docker=docker, container_name=CONTAINER)
    assert result['compiled'] is True
    assert result['passed'] == 0
    assert result['error'] == '程序输出超过限制'


@pytest.mark.parametrize('padding_unit', ['\\\n', '\x01'])
def test_maximum_source_survives_json_expansion_and_reaches_existing_container(padding_unit):
    prefix = 'int step(int x) { A.insert(x); return A.top(); }\n/*\n'
    suffix = '\n*/\n'
    available = edu_cpp.MAX_SOURCE_BYTES - len(prefix.encode()) - len(suffix.encode())
    repeats, remainder = divmod(available, len(padding_unit.encode()))
    source = prefix + padding_unit * repeats + ' ' * remainder + suffix
    inputs = [1_000_000_000] * edu_cpp.MAX_INPUTS
    assert len(source.encode()) == edu_cpp.MAX_SOURCE_BYTES
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[-1] == '--cleanup':
            return runtime._BinaryCommandResult(0, b'ok\n', b'')
        raw = kwargs['input_bytes']
        assert 128 * 1024 < len(raw) <= runtime.EDU_CPP_REQUEST_MAX_BYTES
        assert runtime.EDU_CPP_REQUEST_MAX_BYTES == edu_cpp_runner.MAX_PAYLOAD_BYTES == 512 * 1024
        payload = json.loads(raw)
        assert payload['source'] == source and payload['inputs'] == inputs
        assert command[:4] == ['docker', 'exec', '-i', '--user']
        response = {'compile': {'returncode': 1, 'stdout_b64': '',
            'stderr_b64': base64.b64encode(b'compiler diagnostic').decode(),
            'stdout_truncated': False, 'stderr_truncated': False}}
        return runtime._BinaryCommandResult(0, json.dumps(response).encode(), b'')

    result = edu_cpp.run_code(source, inputs, docker=runtime.DockerCLI(binary_command_runner=run),
        container_name=CONTAINER)
    assert result['compiled'] is False and result['error'] == 'compiler diagnostic'
    assert len(calls) == 2


def test_request_over_512_kib_is_rejected_before_any_docker_command():
    def forbidden(*_args, **_kwargs):
        pytest.fail('超限请求不得调用 Docker')

    payload = {'source': 'x' * runtime.EDU_CPP_REQUEST_MAX_BYTES}
    with pytest.raises(runtime.VibeHubRuntimeError, match='请求超过限制'):
        runtime.DockerCLI(binary_command_runner=forbidden).execute_edu_cpp(CONTAINER, payload)
