"""末层教学 relay 复用稳定帧协议，且不能复用或切换到公开 socket。"""

from collections import deque
from io import BytesIO
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
from types import SimpleNamespace

import pytest

from backend.oj_modules.vibehub import runtime


ROOT = Path(__file__).resolve().parents[2]
RELAY_ROOT = ROOT / "docker" / "vibehub-runtime"


def _load(filename):
    spec = importlib.util.spec_from_file_location("relay_test_" + filename.replace(".", "_"), RELAY_ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _response_frame(body):
    metadata = json.dumps({
        "version": 1, "status": 200, "reason": "OK", "headers": [], "body_length": len(body),
    }).encode("ascii")
    return b"VHR1" + struct.pack(">I", len(metadata)) + metadata + body


def test_edu_docker_command_keeps_legacy_arguments_and_never_enters_the_public_persistent_pool():
    created, binary_calls = [], []

    class PublicRelay:
        def __init__(self, command):
            self.command = list(command)
            self.requests = 0
            self.closed = False
            created.append(self)

        def request(self, _frame, **_kwargs):
            self.requests += 1
            return _response_frame(b"public")

        def close(self):
            self.closed = True

    def binary_runner(command, **kwargs):
        binary_calls.append((list(command), kwargs))
        return runtime._BinaryCommandResult(0, _response_frame(b"education"), b"")

    docker = runtime.DockerCLI(binary_command_runner=binary_runner, relay_process_factory=PublicRelay)
    container = "numoj-vh-" + "a" * 16 + "-" + "b" * 40
    try:
        for edu, expected in ((False, b"public"), (True, b"education"), (False, b"public")):
            result = docker.relay_http(container, "GET", "/probe", {"Host": "vibehub.internal"}, b"",
                                       timeout=2, response_max_bytes=1024, edu=edu)
            assert result.body == expected
        assert len(created) == 1 and created[0].requests == 2
        assert created[0].command == [
            "docker", "exec", "-i", "--user", "65532:65532", container,
            "/usr/local/bin/vibehub-uds-relay",
        ]
        assert len(binary_calls) == 1
        command, limits = binary_calls[0]
        assert command == [
            "docker", "exec", "-i", "--user", "65532:65532", container,
            "/usr/local/bin/vibehub-uds-relay", "--edu",
        ]
        assert limits["input_bytes"].startswith(b"VHR1")
        assert limits["stdout_limit"] == 1024 + runtime._RELAY_METADATA_MAX_BYTES + 8
        assert limits["stderr_limit"] == 16 * 1024
    finally:
        docker._close_relay_pool(container)
    assert created[0].closed is True


class _HTTPTestSocket:
    """只替换连接端点，HTTPConnection、读写边界与 VHR1 编解码保持真实。"""

    def __init__(self, body, observations):
        self.body = body
        self.observations = observations
        self.request = bytearray()

    def settimeout(self, _timeout):
        pass

    def connect(self, address):
        self.observations.append((address, self.request))

    def sendall(self, data):
        self.request.extend(data)

    def makefile(self, _mode):
        return BytesIO(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(self.body)).encode("ascii")
                       + b"\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n" + self.body)

    def shutdown(self, _how):
        pass

    def close(self):
        pass


def _run_entrypoint(monkeypatch, module, request_bytes, response_bodies, *, arguments=()):
    observations, output = [], BytesIO()
    bodies = deque(response_bodies)

    def socket_factory(family, kind):
        assert family == socket.AF_UNIX and kind == socket.SOCK_STREAM
        return _HTTPTestSocket(bodies.popleft(), observations)

    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", ["trusted-relay", *arguments])
        patch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(request_bytes)))
        patch.setattr(sys, "stdout", SimpleNamespace(buffer=output))
        patch.setattr(socket, "socket", socket_factory)
        status = module.main()
    return status, output.getvalue(), observations


def _split_response_frames(value):
    source = BytesIO(value)
    frames = []
    while magic := source.read(4):
        assert magic == b"VHR1"
        length_bytes = source.read(4)
        metadata = source.read(struct.unpack(">I", length_bytes)[0])
        body = source.read(json.loads(metadata)["body_length"])
        frames.append(runtime._parse_relay_response(magic + length_bytes + metadata + body, response_max_bytes=1024))
    return frames


@pytest.mark.parametrize("arguments,socket_path,forged_path", [
    ([], "/run/vibehub/app.sock", "/run/vibehub/edu.sock"),
    (["--edu"], "/run/vibehub/edu.sock", "/run/vibehub/app.sock"),
])
def test_entrypoint_reuses_legacy_http_and_multiframe_processing_with_fixed_public_or_private_socket(
    monkeypatch, arguments, socket_path, forged_path,
):
    entrypoint = _load("relay_entrypoint.py")
    assert entrypoint.RELAY_PATH == "/usr/local/lib/vibehub_uds_relay.py"
    monkeypatch.setattr(entrypoint, "RELAY_PATH", str(RELAY_ROOT / "uds_relay.py"))
    forged_selector = json.dumps({"socket_path": forged_path}).encode("ascii")
    first = runtime._encode_relay_request("POST", "/v1/start",
        {"Host": "vibehub.internal", "X-Socket-Path": forged_path}, forged_selector,
        timeout=2, response_max_bytes=1024)
    second = runtime._encode_relay_request("GET", "/v1/grade", {}, b"", timeout=2, response_max_bytes=1024)
    status, output, observations = _run_entrypoint(monkeypatch, entrypoint, first + second,
        [b"first-response", b"second-response"], arguments=arguments)
    assert status == 0
    assert [item.body for item in _split_response_frames(output)] == [b"first-response", b"second-response"]
    assert [address for address, _request in observations] == [socket_path] * 2
    assert bytes(observations[0][1]).startswith(b"POST /v1/start HTTP/1.1\r\n")
    assert bytes(observations[0][1]).endswith(forged_selector)


def test_original_entrypoint_keeps_the_public_socket_without_education_arguments(monkeypatch):
    legacy = _load("uds_relay.py")
    frame = runtime._encode_relay_request("GET", "/healthz", {}, b"", timeout=2, response_max_bytes=1024)
    status, output, observations = _run_entrypoint(monkeypatch, legacy, frame, [b"public"])
    assert status == 0
    assert _split_response_frames(output)[0].body == b"public"
    assert [address for address, _request in observations] == ["/run/vibehub/app.sock"]


@pytest.mark.parametrize("arguments", [["--socket", "/run/vibehub/app.sock"], ["/run/vibehub/app.sock"], ["--edu", "--edu"], ["--public"]])
def test_entrypoint_rejects_unknown_arguments_before_loading_the_legacy_module(monkeypatch, arguments):
    entrypoint = _load("relay_entrypoint.py")
    monkeypatch.setattr(entrypoint, "RELAY_PATH", "/nonexistent/must-not-be-loaded")
    monkeypatch.setattr(sys, "argv", ["trusted-relay", *arguments])
    assert entrypoint.main() == 64


@pytest.mark.parametrize("arguments,socket_path", [([], "/run/vibehub/app.sock"), (["--edu"], "/run/vibehub/edu.sock")])
def test_entrypoint_keeps_the_original_bounded_response_contract(monkeypatch, arguments, socket_path):
    entrypoint = _load("relay_entrypoint.py")
    monkeypatch.setattr(entrypoint, "RELAY_PATH", str(RELAY_ROOT / "uds_relay.py"))
    frame = runtime._encode_relay_request("GET", "/v1/start", {}, b"", timeout=2, response_max_bytes=4)
    status, output, observations = _run_entrypoint(monkeypatch, entrypoint, frame, [b"oversized"], arguments=arguments)
    assert status == 70
    assert output == b""
    assert observations[0][0] == socket_path
