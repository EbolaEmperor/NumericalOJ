#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判题 case 容器内的可信执行与白名单产物导出器。

本文件由宿主只读挂载，并以容器 root 执行。它只把用户命令降权到固定 runner
UID/GID；用户结束后先清除仍存活的 runner 进程，再从有大小上限的 ``/case``
tmpfs 中安全读取白名单产物，复制到用户不可写的 ``/export`` tmpfs。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time


PROTOCOL_PREFIX = "__NUMOJ_CASE_RESULT_V1__"
ALLOWED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".bmp",
    ".gif",
    ".webp",
}


class _BoundedBytes:
    def __init__(self, limit: int):
        self.limit = max(0, int(limit))
        self.data = bytearray()
        self.truncated = False

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if len(chunk) > max(0, remaining):
            self.truncated = True


def _safe_leaf_name(value: str) -> str:
    name = str(value or "")
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or os.path.basename(name) != name
        or len(name.encode("utf-8")) > 255
    ):
        raise ValueError("产物名称不是安全的单级文件名")
    return name


def _safe_image_name(value: str) -> str:
    if not value:
        return ""
    name = _safe_leaf_name(value)
    if os.path.splitext(name)[1].lower() not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError("图片扩展名不受支持")
    return name


def _open_directory(path: str) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def _write_input_file(workdir: str, data: bytes) -> None:
    directory_fd = _open_directory(workdir)
    try:
        fd = os.open(
            "input.txt",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o644,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _drop_privileges(uid: int, gid: int) -> None:
    os.setgroups([])
    os.setgid(int(gid))
    os.setuid(int(uid))
    os.umask(0o022)


def _process_state_and_uid(pid: int):
    try:
        with open(
            f"/proc/{int(pid)}/status",
            "r",
            encoding="ascii",
            errors="replace",
        ) as handle:
            state = ""
            uid = None
            for line in handle:
                if line.startswith("State:"):
                    state = line.split()[1]
                elif line.startswith("Uid:"):
                    uid = int(line.split()[1])
            return state, uid
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
        return None, None


def _live_runner_pids(uid: int):
    own_pid = os.getpid()
    result = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return result
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in {1, own_pid}:
            continue
        state, process_uid = _process_state_and_uid(pid)
        if process_uid == int(uid) and state != "Z":
            result.append(pid)
    return result


def _kill_remaining_runner_processes(uid: int) -> None:
    """清除 setsid/双重 fork 等遗留进程；僵尸不再执行或持有文件描述符。"""
    for _ in range(100):
        pids = _live_runner_pids(uid)
        if not pids:
            return
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        time.sleep(0.005)
    raise RuntimeError("无法清除测试点遗留进程")


def _read_memory_events():
    """读取当前容器 cgroup v2 的内存事件计数；不可用时返回空字典。"""
    for path in (
        "/sys/fs/cgroup/memory.events.local",
        "/sys/fs/cgroup/memory.events",
    ):
        counters = {}
        try:
            with open(path, "r", encoding="ascii") as handle:
                for line in handle:
                    key, raw_value = line.split()
                    counters[key] = int(raw_value)
        except (OSError, ValueError):
            continue
        if counters:
            return counters
    return {}


def _close_pipe(selector, pipe) -> None:
    try:
        selector.unregister(pipe)
    except Exception:
        pass
    try:
        pipe.close()
    except Exception:
        pass


def _run_user_command(
    command,
    *,
    workdir: str,
    input_data: bytes,
    runner_uid: int,
    runner_gid: int,
    stdout_limit: int,
    stderr_limit: int,
):
    environment = dict(os.environ)
    environment["HOME"] = "/home/runner"
    memory_events_before = _read_memory_events()
    started_ns = time.monotonic_ns()
    proc = subprocess.Popen(
        list(command),
        cwd=workdir,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=lambda: _drop_privileges(runner_uid, runner_gid),
    )
    stdout_buffer = _BoundedBytes(stdout_limit)
    stderr_buffer = _BoundedBytes(stderr_limit)
    selector = selectors.DefaultSelector()
    os.set_blocking(proc.stdout.fileno(), False)
    os.set_blocking(proc.stderr.fileno(), False)
    selector.register(proc.stdout, selectors.EVENT_READ, ("read", stdout_buffer))
    selector.register(proc.stderr, selectors.EVENT_READ, ("read", stderr_buffer))

    input_offset = 0
    if input_data:
        os.set_blocking(proc.stdin.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, ("write", None))
    else:
        proc.stdin.close()

    returncode = None
    elapsed_ns = None
    runner_processes_killed = False
    try:
        while selector.get_map():
            for key, _mask in selector.select(timeout=0.05):
                operation, target = key.data
                pipe = key.fileobj
                if operation == "write":
                    try:
                        written = os.write(
                            pipe.fileno(),
                            input_data[input_offset : input_offset + 65536],
                        )
                        input_offset += written
                    except BlockingIOError:
                        continue
                    except (BrokenPipeError, OSError):
                        input_offset = len(input_data)
                    if input_offset >= len(input_data):
                        _close_pipe(selector, pipe)
                    continue
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if chunk:
                    target.append(chunk)
                else:
                    _close_pipe(selector, pipe)

            if returncode is None:
                polled = proc.poll()
                if polled is not None:
                    returncode = int(polled)
                    elapsed_ns = time.monotonic_ns() - started_ns
                    _kill_remaining_runner_processes(runner_uid)
                    runner_processes_killed = True
                    if proc.stdin and not proc.stdin.closed:
                        _close_pipe(selector, proc.stdin)

        if returncode is None:
            returncode = int(proc.wait())
            elapsed_ns = time.monotonic_ns() - started_ns
        if not runner_processes_killed:
            _kill_remaining_runner_processes(runner_uid)
    finally:
        selector.close()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except Exception:
                    pass

    memory_events_after = _read_memory_events()
    return {
        "returncode": returncode,
        "stdout": bytes(stdout_buffer.data),
        "stderr": bytes(stderr_buffer.data),
        "stdout_truncated": stdout_buffer.truncated,
        "stderr_truncated": stderr_buffer.truncated,
        "elapsed_ns": max(0, int(elapsed_ns or 0)),
        "oom_killed": (
            int(memory_events_after.get("oom_kill", 0))
            > int(memory_events_before.get("oom_kill", 0))
        ),
    }


def _export_regular_file(
    source_dir_fd: int,
    export_dir_fd: int,
    filename: str,
    *,
    max_bytes: int,
) -> str:
    safe_name = _safe_leaf_name(filename)
    try:
        source_fd = os.open(
            safe_name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=source_dir_fd,
        )
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "rejected"
    try:
        info = os.fstat(source_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_nlink) != 1
            or int(info.st_size) < 0
            or int(info.st_size) > int(max_bytes)
        ):
            return "rejected"
        destination_fd = os.open(
            safe_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=export_dir_fd,
        )
        try:
            remaining = int(max_bytes) + 1
            while remaining > 0:
                chunk = os.read(source_fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    view = view[written:]
                remaining -= len(chunk)
            if remaining <= 0:
                raise OSError("产物读取时超过大小上限")
            os.fsync(destination_fd)
        except Exception:
            os.close(destination_fd)
            try:
                os.unlink(safe_name, dir_fd=export_dir_fd)
            except OSError:
                pass
            return "rejected"
        os.close(destination_fd)
        return "exported"
    finally:
        os.close(source_fd)


def _emit_protocol(payload) -> None:
    encoded = base64.b64encode(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).decode("ascii")
    sys.stdout.write(PROTOCOL_PREFIX + encoded + "\n")
    sys.stdout.flush()


def _fatal_payload(message: str):
    return {
        "version": 1,
        "returncode": -1,
        "stdout_b64": "",
        "stderr_b64": base64.b64encode(
            str(message).encode("utf-8", errors="replace")[:4096]
        ).decode("ascii"),
        "stdout_truncated": False,
        "stderr_truncated": False,
        "elapsed_ns": 0,
        "oom_killed": False,
        "artifacts": [],
        "artifact_statuses": {},
    }


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--runner-uid", required=True, type=int)
    parser.add_argument("--runner-gid", required=True, type=int)
    parser.add_argument("--workdir", default="/case")
    parser.add_argument("--export-dir", default="/export")
    parser.add_argument("--input-max-bytes", required=True, type=int)
    parser.add_argument("--stdout-max-bytes", required=True, type=int)
    parser.add_argument("--stderr-max-bytes", required=True, type=int)
    parser.add_argument("--output-name", default="")
    parser.add_argument("--output-max-bytes", required=True, type=int)
    parser.add_argument("--image-max-bytes", required=True, type=int)
    parser.add_argument("--image-name", default="")
    parser.add_argument("--executable-name", default="")
    parser.add_argument("--executable-max-bytes", required=True, type=int)
    parser.add_argument("--document-name", default="")
    parser.add_argument("--document-max-bytes", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        raise ValueError("缺少用户命令")
    return args


def main(argv=None) -> int:
    try:
        args = _parse_args(argv)
        image_name = _safe_image_name(args.image_name)
        output_name = (
            _safe_leaf_name(args.output_name)
            if args.output_name
            else ""
        )
        executable_name = (
            _safe_leaf_name(args.executable_name)
            if args.executable_name
            else ""
        )
        if output_name and output_name != "output.txt":
            raise ValueError("文本产物不在白名单")
        if executable_name and executable_name != "a.out":
            raise ValueError("可执行产物不在白名单")
        document_name = (
            _safe_leaf_name(args.document_name)
            if args.document_name
            else ""
        )
        if (
            document_name
            and os.path.splitext(document_name)[1].lower() != ".pdf"
        ):
            raise ValueError("文档产物不在白名单")
        input_data = sys.stdin.buffer.read(int(args.input_max_bytes) + 1)
        if len(input_data) > int(args.input_max_bytes):
            raise ValueError("测试点输入超过容器协议上限")
        _write_input_file(args.workdir, input_data)
        result = _run_user_command(
            args.command,
            workdir=args.workdir,
            input_data=input_data,
            runner_uid=args.runner_uid,
            runner_gid=args.runner_gid,
            stdout_limit=args.stdout_max_bytes,
            stderr_limit=args.stderr_max_bytes,
        )

        workdir_fd = _open_directory(args.workdir)
        export_fd = _open_directory(args.export_dir)
        try:
            artifacts = []
            artifact_statuses = {}
            for filename, max_bytes in (
                (output_name, args.output_max_bytes),
                (image_name, args.image_max_bytes),
                (executable_name, args.executable_max_bytes),
                (document_name, args.document_max_bytes),
            ):
                if not filename:
                    continue
                export_status = _export_regular_file(
                    workdir_fd,
                    export_fd,
                    filename,
                    max_bytes=max_bytes,
                )
                artifact_statuses[filename] = export_status
                if export_status == "exported":
                    artifacts.append(filename)
        finally:
            os.close(export_fd)
            os.close(workdir_fd)

        _emit_protocol(
            {
                "version": 1,
                "returncode": result["returncode"],
                "stdout_b64": base64.b64encode(
                    result["stdout"]
                ).decode("ascii"),
                "stderr_b64": base64.b64encode(
                    result["stderr"]
                ).decode("ascii"),
                "stdout_truncated": result["stdout_truncated"],
                "stderr_truncated": result["stderr_truncated"],
                "elapsed_ns": result["elapsed_ns"],
                "oom_killed": result["oom_killed"],
                "artifacts": artifacts,
                "artifact_statuses": artifact_statuses,
            }
        )
        return 0
    except BaseException as exc:
        try:
            _emit_protocol(_fatal_payload(f"判题容器执行器失败：{exc}"))
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
