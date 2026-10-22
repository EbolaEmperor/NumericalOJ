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
from pathlib import Path, PurePosixPath
import re
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
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
MAX_FILES = 32
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 16 * 1024
WORKDIR_PLACEHOLDER = "${WORKDIR}"
BUILD_TOOLS = frozenset({
    "/usr/bin/g++", "/usr/bin/gcc", "/usr/bin/clang", "/usr/bin/clang++",
    "/usr/bin/python3", "/usr/local/bin/python", "/usr/local/bin/python3",
})


def _relative_name(value):
    if not isinstance(value, str) or len(value.encode("utf-8")) > 240:
        raise ValueError("执行文件名无效")
    parts = value.split("/")
    if not 1 <= len(parts) <= 8 or any(
        part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts
    ):
        raise ValueError("执行文件名必须是安全相对路径")
    return value


def validate_request(payload):
    """只校验资源与文件/命令边界，不了解源代码语言、输入格式或题目规则。"""
    if not isinstance(payload, dict) or set(payload) != {"files", "compile", "run", "executable"}:
        raise ValueError("执行请求字段无效")
    files = payload["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("执行文件数量超过限制")
    normalized_files, text_bytes = {}, 0
    for name, content in files.items():
        name = _relative_name(name)
        if not isinstance(content, str):
            raise ValueError("执行文件必须是文本")
        text_bytes += len(content.encode("utf-8"))
        normalized_files[name] = content
    names = set(normalized_files)
    for name in names:
        if any(str(parent) in names for parent in PurePosixPath(name).parents):
            raise ValueError("执行文件与目录路径冲突")
    build, run = payload["compile"], payload["run"]
    if not isinstance(build, dict) or set(build) != {"argv", "seconds"}:
        raise ValueError("构建参数无效")
    if not isinstance(run, dict) or set(run) != {"stdin", "seconds"}:
        raise ValueError("运行参数无效")
    argv = build["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= MAX_ARGUMENTS or any(
        not isinstance(arg, str) or not arg or "\x00" in arg or len(arg.encode("utf-8")) > 4096 for arg in argv
    ):
        raise ValueError("构建命令参数无效")
    if argv[0] not in BUILD_TOOLS or sum(len(arg.encode("utf-8")) for arg in argv) > MAX_ARGUMENT_BYTES:
        raise ValueError("构建工具或参数超过限制")
    for seconds, maximum in ((build["seconds"], 25), (run["seconds"], 10)):
        if type(seconds) is not int or not 1 <= seconds <= maximum:
            raise ValueError("执行时限无效")
    if not isinstance(run["stdin"], str):
        raise ValueError("标准输入必须是文本")
    text_bytes += len(run["stdin"].encode("utf-8"))
    if text_bytes > MAX_TEXT_BYTES:
        raise ValueError("执行文本超过限制")
    normalized = {"files": normalized_files,
        "compile": {"argv": list(argv), "seconds": build["seconds"]},
        "run": {"stdin": run["stdin"], "seconds": run["seconds"]},
        "executable": _relative_name(payload["executable"])}
    raw = json.dumps(normalized, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_PAYLOAD_BYTES:
        raise ValueError("执行请求超过限制")
    return normalized


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
    raise RuntimeError("无法清除执行后台进程")


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
        start_new_session=True, close_fds=True, pass_fds=pass_fds)
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


def _open_artifact(root_fd, name):
    directory_fd = os.dup(root_fd)
    try:
        parts = name.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def execute(payload):
    payload = validate_request(payload)
    with tempfile.TemporaryDirectory(prefix="numoj-edu-process-", dir="/tmp") as workdir:
        root = Path(workdir)
        for name, value in payload["files"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_text(value, encoding="utf-8")
        root_fd = os.open(workdir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            build = payload["compile"]
            command = [arg.replace(WORKDIR_PLACEHOLDER, workdir) for arg in build["argv"]]
            compiled = _run(command, workdir=workdir, seconds=build["seconds"], stdout_limit=MAX_COMPILE_OUTPUT_BYTES)
            response = {"compile": compiled}
            if compiled["returncode"] != 0 or compiled["stdout_truncated"] or compiled["stderr_truncated"]:
                return response
            executable_fd = _open_artifact(root_fd, payload["executable"])
            try:
                info = os.fstat(executable_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_EXECUTABLE_BYTES:
                    raise ValueError("构建产物不是合格的可执行文件")
                memory_fd = os.memfd_create("numoj-edu-process", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                try:
                    remaining = MAX_EXECUTABLE_BYTES + 1
                    while chunk := os.read(executable_fd, min(65536, remaining)):
                        remaining -= len(chunk)
                        if remaining <= 0:
                            raise ValueError("构建产物超过限制")
                        view = memoryview(chunk)
                        while view:
                            view = view[os.write(memory_fd, view):]
                    os.fchmod(memory_fd, 0o500)
                    fcntl.fcntl(memory_fd, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
                    response["run"] = _run([f"/proc/self/fd/{memory_fd}"], workdir=workdir,
                        input_data=payload["run"]["stdin"].encode("utf-8"),
                        seconds=payload["run"]["seconds"], pass_fds=(memory_fd,))
                finally:
                    os.close(memory_fd)
            finally:
                os.close(executable_fd)
        finally:
            os.close(root_fd)
        return response


def main():
    # UID 由宿主 docker exec 指定；不能与 root 或作品服务用户相同。
    if os.getuid() < 100_000 or os.getuid() != os.getgid():
        raise RuntimeError("执行请求 UID 无效")
    os.umask(0o077)
    if sys.argv[1:] == ["--cleanup"]:
        cleanup()
        print("ok")
        return
    if sys.argv[1:]:
        raise ValueError("未知执行参数")
    for private_path in ("/app", "/run/vibehub", "/data"):
        if os.access(private_path, os.R_OK) or os.access(private_path, os.X_OK):
            raise RuntimeError("作品私有目录权限未隔离，拒绝执行")
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
