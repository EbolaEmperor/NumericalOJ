"""通用进程请求只管资源与执行边界，不了解题目或程序输出的含义。"""

import base64
from copy import deepcopy
import json
import subprocess

import pytest

from backend.oj_modules.vibehub import edu_execution, edu_process_runner, runtime


CONTAINER = "numoj-vh-" + "a" * 16 + "-" + "b" * 40


def request():
    return {"files": {"source.c": "int main(void) { return 0; }"},
        "compile": {"argv": ["/usr/bin/gcc", "${WORKDIR}/source.c", "-o", "${WORKDIR}/program"], "seconds": 25},
        "run": {"stdin": "arbitrary input\n", "seconds": 5}, "executable": "program"}


def stage(*, returncode=0, stdout=b"", stderr=b"", **flags):
    return {"returncode": returncode, "stdout_b64": base64.b64encode(stdout).decode(),
        "stderr_b64": base64.b64encode(stderr).decode(),
        "stdout_truncated": False, "stderr_truncated": False, **flags}


def successful_response():
    return {"compile": stage(), "run": stage(stdout=b"any output, including a number: 42\n")}


def test_execution_uses_existing_container_exec_and_does_not_parse_program_output():
    calls = []
    payload, response = request(), successful_response()

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[-1] == "--cleanup":
            return runtime._BinaryCommandResult(0, b"ok\n", b"")
        assert json.loads(kwargs["input_bytes"]) == payload
        return runtime._BinaryCommandResult(0, json.dumps(response).encode(), b"")

    docker = runtime.DockerCLI(binary_command_runner=run)
    assert docker.execute_edu_process(CONTAINER, payload) == response
    assert len(calls) == 2
    command, limits = calls[0]
    assert command[:4] == ["docker", "exec", "-i", "--user"]
    uid, gid = map(int, command[4].split(":"))
    assert uid == gid and uid >= 100_000
    assert command[5:11] == ["--workdir", "/tmp", CONTAINER, "/usr/local/bin/python3", "-I", "-c"]
    assert "os.memfd_create" in command[11]
    assert payload["files"]["source.c"] not in command[11]
    assert calls[1][0] == [*command, "--cleanup"]
    assert limits["stdout_limit"] == 2 * 1024 * 1024
    assert calls[1][1]["input_bytes"] == b"" and calls[1][1]["timeout"] == 5


def test_each_execution_uses_a_new_uid(monkeypatch):
    values = iter([100, 200])
    monkeypatch.setattr(runtime.secrets, "randbelow", lambda _upper: next(values))
    calls = []

    def run(command, **_kwargs):
        calls.append(command)
        content = b"ok\n" if command[-1] == "--cleanup" else json.dumps(successful_response()).encode()
        return runtime._BinaryCommandResult(0, content, b"")

    docker = runtime.DockerCLI(binary_command_runner=run)
    docker.execute_edu_process(CONTAINER, request())
    docker.execute_edu_process(CONTAINER, request())
    assert calls[0][4] == "100100:100100" and calls[2][4] == "100200:100200"


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "output", "invalid-json", "forged-score"])
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
        if failure == "forged-score":
            return runtime._BinaryCommandResult(0, b'{"score":100,"passed":true}', b"")
        return runtime._BinaryCommandResult(0, b"not-json", b"")

    with pytest.raises(runtime.VibeHubRuntimeError):
        runtime.DockerCLI(binary_command_runner=run).execute_edu_process(CONTAINER, request())
    assert len(calls) == 2 and calls[-1][-1] == "--cleanup"


def test_cleanup_failure_removes_existing_instance_instead_of_leaving_processes(monkeypatch):
    removed = []

    def run(command, **_kwargs):
        return runtime._BinaryCommandResult(1, b"", b"") if command[-1] == "--cleanup" else (
            runtime._BinaryCommandResult(0, json.dumps(successful_response()).encode(), b""))

    docker = runtime.DockerCLI(binary_command_runner=run)
    monkeypatch.setattr(docker, "remove_container", removed.append)
    with pytest.raises(runtime.VibeHubRuntimeError, match="运行实例已回收"):
        docker.execute_edu_process(CONTAINER, request())
    assert removed == [CONTAINER]


@pytest.mark.parametrize("container_name,timeout", [("ordinary-container", 40),
    (CONTAINER + ";other", 40), (CONTAINER, True), (CONTAINER, float("nan")),
    (CONTAINER, 46), (CONTAINER, 1)])
def test_invalid_container_or_limits_never_run_docker(container_name, timeout):
    def forbidden(*_args, **_kwargs):
        pytest.fail("不得调用 Docker")
    with pytest.raises(runtime.VibeHubRuntimeError):
        runtime.DockerCLI(binary_command_runner=forbidden).execute_edu_process(container_name, request(), timeout=timeout)


def test_maximum_combined_outputs_fit_transport_and_keep_truncation_as_process_metadata():
    response = {"compile": stage(stdout=b"c" * edu_process_runner.MAX_COMPILE_OUTPUT_BYTES,
                                 stderr=b"e" * edu_process_runner.MAX_ERROR_BYTES),
        "run": stage(stdout=b"r" * edu_process_runner.MAX_OUTPUT_BYTES,
                     stderr=b"e" * edu_process_runner.MAX_ERROR_BYTES, stdout_truncated=True)}
    encoded = json.dumps(response, separators=(",", ":")).encode()

    def run(command, **kwargs):
        if command[-1] == "--cleanup":
            return runtime._BinaryCommandResult(0, b"ok\n", b"")
        assert len(encoded) < kwargs["stdout_limit"]
        return runtime._BinaryCommandResult(0, encoded, b"")

    assert runtime.DockerCLI(binary_command_runner=run).execute_edu_process(CONTAINER, request()) == response


def test_text_request_budget_includes_worst_case_json_escaping():
    payload = request()
    payload["files"] = {"anything.txt": "\x01" * edu_process_runner.MAX_TEXT_BYTES}
    payload["run"]["stdin"] = ""
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[-1] == "--cleanup":
            return runtime._BinaryCommandResult(0, b"ok\n", b"")
        raw = kwargs["input_bytes"]
        assert 1024 * 1024 < len(raw) <= edu_execution.MAX_PAYLOAD_BYTES == 2 * 1024 * 1024
        assert json.loads(raw) == payload
        return runtime._BinaryCommandResult(0, json.dumps({"compile": stage(returncode=1)}).encode(), b"")

    result = runtime.DockerCLI(binary_command_runner=run).execute_edu_process(CONTAINER, payload)
    assert result["compile"]["returncode"] == 1 and len(calls) == 2


@pytest.mark.parametrize("change", ["text", "files", "path", "conflict", "tool", "nul-argv", "uid", "container"])
def test_invalid_request_never_issues_any_docker_command(change):
    payload = request()
    if change == "text":
        payload["files"] = {"large.txt": "x" * (edu_process_runner.MAX_TEXT_BYTES + 1)}
    elif change == "files":
        payload["files"] = {str(index): "x" for index in range(edu_process_runner.MAX_FILES + 1)}
    elif change == "path":
        payload["executable"] = "../outside"
    elif change == "conflict":
        payload["files"] = {"folder": "file", "folder/child": "file"}
    elif change == "tool":
        payload["compile"]["argv"] = ["/bin/sh", "-c", "other command"]
    elif change == "nul-argv":
        payload["compile"]["argv"].append("bad\x00argument")
    else:
        payload[change] = "caller-selected"

    def forbidden(*_args, **_kwargs):
        pytest.fail("超限或越权请求不得调用 Docker")
    with pytest.raises(runtime.VibeHubRuntimeError, match="执行请求无效"):
        runtime.DockerCLI(binary_command_runner=forbidden).execute_edu_process(CONTAINER, payload)


@pytest.mark.parametrize("response", [{}, {"compile": {}}, {"compile": stage()},
    {"compile": stage(returncode=1), "run": stage()},
    {"compile": stage(), "run": stage(stdout_b64="not base64!")},
    {"compile": stage(), "run": stage(returncode=True)},
    {"compile": stage(), "run": stage(stdout=b"x" * (edu_process_runner.MAX_OUTPUT_BYTES + 1))},
])
def test_response_validation_rejects_invalid_or_unbounded_driver_metadata(response):
    with pytest.raises(ValueError):
        edu_execution.validate_response(deepcopy(response))
