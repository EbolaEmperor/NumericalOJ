#!/usr/bin/env python3
"""Trusted bounded HTTP/1.1 relay for Docker Desktop Unix-socket transport."""

from __future__ import annotations

import http.client
import errno
import json
import math
import re
import socket
import struct
import sys
import threading
import time


MAGIC = b"VHR1"
SOCKET_PATH = "/run/vibehub/app.sock"
METADATA_MAX_BYTES = 64 * 1024
BODY_HARD_MAX_BYTES = 64 * 1024 * 1024
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SOCKET_CONNECT_RETRY_SECONDS = 2.0
SOCKET_CONNECT_RETRY_INTERVAL_SECONDS = 0.02


def _has_controls(value: str) -> bool:
    return any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)


def _read_exact(stream, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise ValueError("truncated frame")
        chunks.extend(chunk)
    return bytes(chunks)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, timeout: float):
        super().__init__("vibehub.internal", timeout=timeout)

    def connect(self) -> None:
        deadline = time.monotonic() + min(
            float(self.timeout), SOCKET_CONNECT_RETRY_SECONDS,
        )
        while True:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(self.timeout)
            try:
                connection.connect(SOCKET_PATH)
            except OSError as exc:
                connection.close()
                remaining = deadline - time.monotonic()
                if exc.errno not in {errno.ENOENT, errno.ECONNREFUSED} or remaining <= 0:
                    raise
                time.sleep(min(SOCKET_CONNECT_RETRY_INTERVAL_SECONDS, remaining))
                continue
            self.sock = connection
            return


def _load_request(source):
    magic = source.read(4)
    if not magic:
        return None
    if len(magic) != 4 or magic != MAGIC:
        raise ValueError("invalid magic")
    metadata_length = struct.unpack(">I", _read_exact(source, 4))[0]
    if not 1 <= metadata_length <= METADATA_MAX_BYTES:
        raise ValueError("invalid metadata length")
    metadata = json.loads(_read_exact(source, metadata_length).decode("utf-8"))
    if not isinstance(metadata, dict) or set(metadata) != {
        "version", "method", "target", "headers", "body_length",
        "timeout_seconds", "response_max_bytes",
    } or type(metadata.get("version")) is not int or metadata.get("version") != 1:
        raise ValueError("invalid metadata schema")
    method = metadata["method"]
    target = metadata["target"]
    headers = metadata["headers"]
    if method not in ALLOWED_METHODS:
        raise ValueError("invalid method")
    if (
        not isinstance(target, str)
        or not target.startswith("/")
        or target.startswith("//")
        or len(target.encode("ascii")) > 8192
        or _has_controls(target)
    ):
        raise ValueError("invalid target")
    if (
        not isinstance(headers, list)
        or len(headers) > 100
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or not all(isinstance(value, str) for value in item)
            or not HEADER_NAME_RE.fullmatch(item[0])
            or _has_controls(item[1])
            or len(item[1].encode("utf-8")) > 8192
            for item in headers
        )
    ):
        raise ValueError("invalid headers")
    body_length = metadata["body_length"]
    response_max_bytes = metadata["response_max_bytes"]
    timeout = metadata["timeout_seconds"]
    if (
        type(body_length) is not int
        or type(response_max_bytes) is not int
        or type(timeout) not in {int, float}
        or isinstance(timeout, bool)
    ):
        raise ValueError("invalid limit types")
    timeout = float(timeout)
    if (
        not 0 <= body_length <= BODY_HARD_MAX_BYTES
        or not 1 <= response_max_bytes <= BODY_HARD_MAX_BYTES
        or not math.isfinite(timeout)
        or not 0.1 <= timeout <= 120.0
    ):
        raise ValueError("invalid limits")
    body = _read_exact(source, body_length)
    return method, target, dict(headers), body, timeout, response_max_bytes


def _request(request, output):
    method, target, headers, body, timeout, response_max_bytes = request
    connection = _UnixConnection(timeout)
    deadline_reached = threading.Event()

    def abort_at_deadline() -> None:
        deadline_reached.set()
        active_socket = getattr(connection, "sock", None)
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    timer = threading.Timer(timeout, abort_at_deadline)
    timer.daemon = True
    timer.start()
    try:
        connection.request(method, target, body=body, headers=headers)
        if deadline_reached.is_set():
            raise TimeoutError("request deadline exceeded")
        response = connection.getresponse()
        if deadline_reached.is_set():
            raise TimeoutError("request deadline exceeded")
        payload = response.read(response_max_bytes + 1)
        if deadline_reached.is_set():
            raise TimeoutError("request deadline exceeded")
        if len(payload) > response_max_bytes:
            raise ValueError("response too large")
        metadata = json.dumps({
            "version": 1,
            "status": int(response.status),
            "reason": str(response.reason or ""),
            "headers": list(response.getheaders()),
            "body_length": len(payload),
        }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(metadata) > METADATA_MAX_BYTES:
            raise ValueError("response metadata too large")
        output.write(MAGIC)
        output.write(struct.pack(">I", len(metadata)))
        output.write(metadata)
        output.write(payload)
        output.flush()
    finally:
        timer.cancel()
        connection.close()


def main() -> int:
    try:
        source = sys.stdin.buffer
        output = sys.stdout.buffer
        while request := _load_request(source):
            _request(request, output)
    except Exception:
        # Host only trusts a complete framed response. Avoid traceback/source leakage.
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
