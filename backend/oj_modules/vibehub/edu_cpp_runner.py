"""通过 docker exec 在已有 VibeHub 容器中运行，不创建另一层容器。

平台把本文件作为固定 Python 命令发送给容器；不导入作品代码。每次请求使用
不同于作品服务的随机 UID，源码与编译文件只存在于该 UID 的私有 /tmp 目录。
/tmp 保持 noexec；编译产物经匿名 memfd 执行，不改变既有容器挂载和权限。
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


MAX_OUTPUT_BYTES = 1024 * 1024
MAX_COMPILE_OUTPUT_BYTES = 16 * 1024
MAX_ERROR_BYTES = 64 * 1024
MAX_EXECUTABLE_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024


def _owned_processes():
    result = []
    uid, own = os.getuid(), os.getpid()
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit() or int(entry.name) in {1, own}:
            continue
        try:
            values = Path(entry.path, "status").read_text(encoding="ascii").splitlines()
            owner = next(int(line.split()[1]) for line in values if line.startswith("Uid:"))
            state = next(line.split()[1] for line in values if line.startswith("State:"))
        except (OSError, ValueError, StopIteration):
            continue
        if owner == uid and state != "Z":
            result.append(int(entry.name))
    return result


def _kill_owned_processes():
    # 包括调用 setsid 或双重 fork 逃离最初进程组的后台进程。
    for _ in range(100):
        pids = _owned_processes()
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.005)
    raise RuntimeError("无法清除 C++ 后台进程")


def cleanup():
    _kill_owned_processes()
    # 请求使用随机 UID，且不等于作品服务 UID；仅清理本次请求创建的文件。
    for entry in os.scandir("/tmp"):
        try:
            info = entry.stat(follow_symlinks=False)
        except FileNotFoundError:
            continue
        if info.st_uid != os.getuid():
            continue
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)


def _run(command, *, workdir, input_data=b"", seconds, pass_fds=(), stdout_limit=MAX_OUTPUT_BYTES):
    environment = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": workdir, "TMPDIR": workdir, "LANG": "C.UTF-8",
    }
    proc = subprocess.Popen(command, cwd=workdir, env=environment,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, pass_fds=pass_fds)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}
    limits = {"stdout": stdout_limit, "stderr": MAX_ERROR_BYTES}
    selector = selectors.DefaultSelector()
    for pipe, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    offset = 0
    if input_data:
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE)
    else:
        proc.stdin.close()
    deadline, timed_out = time.monotonic() + seconds, False
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _mask in selector.select(timeout=0.05):
                pipe = key.fileobj
                if key.events & selectors.EVENT_WRITE:
                    try:
                        offset += os.write(pipe.fileno(), input_data[offset:offset + 65536])
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        offset = len(input_data)
                    if offset >= len(input_data):
                        selector.unregister(pipe)
                        pipe.close()
                    continue
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    name = key.data
                    available = max(0, limits[name] - len(buffers[name]))
                    buffers[name].extend(chunk[:available])
                    truncated[name] |= len(chunk) > available
                else:
                    selector.unregister(pipe)
                    pipe.close()
            if proc.poll() is not None:
                _kill_owned_processes()
        if proc.poll() is None and not timed_out:
            try:
                proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _kill_owned_processes()
        proc.wait(timeout=2)
        selector.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
    return {
        "returncode": 124 if timed_out else int(proc.returncode),
        "stdout_b64": base64.b64encode(buffers["stdout"]).decode("ascii"),
        "stderr_b64": base64.b64encode(buffers["stderr"]).decode("ascii"),
        "stdout_truncated": truncated["stdout"], "stderr_truncated": truncated["stderr"],
    }


def execute(payload):
    if set(payload) != {"source", "api_header", "harness", "inputs", "timeout_seconds"}:
        raise ValueError("执行请求字段无效")
    if any(not isinstance(payload[name], str) for name in ("source", "api_header", "harness")):
        raise ValueError("源码必须是文本")
    inputs = payload["inputs"]
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 512 or any(
        type(item) is not int or abs(item) > 1_000_000_000 for item in inputs
    ):
        raise ValueError("执行输入无效")
    timeout = payload["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 10:
        raise ValueError("运行时限无效")
    with tempfile.TemporaryDirectory(prefix="numoj-edu-cpp-", dir="/tmp") as workdir:
        root = Path(workdir)
        for name, value in (("heap_api.hpp", payload["api_header"]),
                            ("student.cpp", '#include "heap_api.hpp"\n' + payload["source"]),
                            ("harness.cpp", payload["harness"])):
            (root / name).write_text(value, encoding="utf-8")
        compiled = _run(["/usr/bin/g++", "-std=c++20", "-O2", "-pipe", "-I", workdir,
                         str(root / "student.cpp"), str(root / "harness.cpp"), "-o", str(root / "a.out")],
                        workdir=workdir, seconds=25, stdout_limit=MAX_COMPILE_OUTPUT_BYTES)
        response = {"compile": compiled}
        if compiled["returncode"] != 0 or compiled["stdout_truncated"] or compiled["stderr_truncated"]:
            return response
        executable_fd = os.open(root / "a.out", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(executable_fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_EXECUTABLE_BYTES:
                raise ValueError("编译产物超过限制")
            memory_fd = os.memfd_create("numoj-edu-cpp", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            try:
                remaining = MAX_EXECUTABLE_BYTES + 1
                while chunk := os.read(executable_fd, min(65536, remaining)):
                    remaining -= len(chunk)
                    if remaining <= 0:
                        raise ValueError("编译产物超过限制")
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(memory_fd, view):]
                os.fchmod(memory_fd, 0o500)
                fcntl.fcntl(memory_fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                response["run"] = _run([f"/proc/self/fd/{memory_fd}"], workdir=workdir,
                    input_data=(str(len(inputs)) + "\n" + "\n".join(map(str, inputs)) + "\n").encode(),
                    seconds=timeout, pass_fds=(memory_fd,))
            finally:
                os.close(memory_fd)
        finally:
            os.close(executable_fd)
        return response


def main():
    # UID 由宿主 docker exec 指定；不能与 root 或作品服务用户相同。
    if os.getuid() < 100_000 or os.getuid() != os.getgid():
        raise RuntimeError("C++ 请求 UID 无效")
    os.umask(0o077)
    if sys.argv[1:] == ["--cleanup"]:
        cleanup()
        print("ok")
        return
    if sys.argv[1:]:
        raise ValueError("未知执行参数")
    raw = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("执行请求超过限制")
    try:
        result = execute(json.loads(raw))
    finally:
        cleanup()
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
