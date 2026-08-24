#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局 · 工作容器内的可信运行器（通用受监管进程）。

本文件以只读挂载进入每个工作容器（每方一个，容器断网），由宿主侧仲裁者
通过标准输入/输出上的换行分隔 JSON 帧驱动。它是工作容器内唯一可信的
进程，负责看管**由评分脚本决定如何启动的被测代码**，并在容器内强制执行
时限——计时只覆盖被测进程本身，不包含宿主↔容器的通信开销。

运行器不假定任何固定入口或语言：评分脚本通过 ``spawn`` 自由决定入口文件、
解释器/编译器、参数、环境变量与工作目录，通过 ``interact`` 按任意自定义
协议收发数据。常见的进程形态有：

  - 常驻交互进程：``spawn`` 一次，``interact`` 多轮（回合对抗）；
  - 一次性进程：``spawn``/``interact``（读到进程退出）或直接用 ``exec``；
  - 纯文件作品：只用 ``exec``（编译、静态分析）与 ``fetch``（取回文件），
    不 ``spawn`` 任何进程。

协议帧（每行一个 JSON 对象）：

宿主 → 运行器：
  {"type": "spawn", "id": N, "argv": [...], "env": {...}, "workdir": "相对路径|空"}
  {"type": "interact", "id": N, "input": "<base64|空>", "timeout_ms": T,
   "until": "newline" | "eof" | {"bytes": K}}
  {"type": "kill", "id": N}
  {"type": "status", "id": N}
  {"type": "exec", "id": N, "timeout_ms": T, "argv": [...],
   "workdir": "相对路径|空", "export_files": ["相对路径", ...]}
  {"type": "fetch", "id": N, "paths": ["相对路径", ...]}
  {"type": "ping", "id": N}
  {"type": "close"}

运行器 → 宿主：
  {"type": "ready", "ok": true}                       # 运行器自身就绪（未启动任何进程）
  {"type": "reply", "id": N, "ok": true, ...}
  {"type": "reply", "id": N, "ok": false,
   "error": "timeout|oversize|bot_exited|bot_not_running|bad_input|bad_request|exec_failed", ...}

计时语义：``interact`` 的 ``elapsed_ms`` 从 ``input`` 完整写入被测进程标准输入
之后开始，到满足 ``until`` 条件为止，由容器内单调时钟测得。超时或违规时运行器
终止被测进程，防止失控进程继续占用资源。

除协议帧外，运行器不向 stdout 写任何内容；诊断信息一律走 stderr。
只使用 Python 标准库。
"""

from __future__ import annotations

import base64
import json
import os
import select
import signal
import subprocess
import sys
import time


MAX_REQUEST_LINE_BYTES = 8 * 1024 * 1024   # 宿主请求帧上限（局面/argv 等）
MAX_INPUT_BYTES = 1024 * 1024              # interact 单次写入被测进程的上限
MAX_LINE_OUTPUT_BYTES = 16 * 1024          # until=newline 时单行输出上限
MAX_BULK_OUTPUT_BYTES = 4 * 1024 * 1024    # until=eof/bytes 时累计输出上限
DEFAULT_INTERACT_TIMEOUT_MS = 1000
DEFAULT_EXEC_STREAM_LIMIT_BYTES = 256 * 1024
MAX_EXEC_STREAM_LIMIT_BYTES = 4 * 1024 * 1024
EXEC_EXPORT_MAX_FILE_BYTES = 8 * 1024 * 1024
EXEC_EXPORT_MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_FETCH_FILES = 32
SHUTDOWN_GRACE_SECONDS = 0.5

SUBMISSION_DIR = os.environ.get("NUMOJ_ELO_SUBMISSION_DIR", "/submission")


def _log(message):
    try:
        sys.stderr.write(f"[elo-runner] {message}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _send(frame):
    data = (json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    os.write(sys.stdout.fileno(), data)


def _resolve_relative(base_dir, relative):
    """把工作目录/导出文件限制在作品目录内，拒绝越界路径。"""
    relative = str(relative or "").strip()
    if not relative or relative == ".":
        return base_dir
    candidate = os.path.normpath(os.path.join(base_dir, relative))
    base_real = os.path.realpath(base_dir)
    if os.path.realpath(candidate) != base_real and not os.path.realpath(candidate).startswith(
            base_real + os.sep):
        raise ValueError("路径越界")
    return candidate


class SupervisedProcess:
    """看管一个由评分脚本启动的被测进程。

    进程形态完全由 ``spawn`` 的 argv/env/workdir 决定；本类只负责启动、
    存活探测与超时强杀，不理解任何应用层协议。
    """

    def __init__(self):
        self.process = None
        self.exit_code = None

    def alive(self):
        if self.process is None:
            return False
        if self.process.poll() is not None:
            self.exit_code = self.process.returncode
            return False
        return True

    def spawn(self, argv, env, workdir):
        """启动被测进程；若已有进程在运行，先终止它。"""
        if self.alive():
            self.kill(graceful_first=True)
        self.exit_code = None
        merged_env = dict(os.environ)
        if isinstance(env, dict):
            for key, value in env.items():
                merged_env[str(key)] = str(value)
        self.process = subprocess.Popen(
            argv,
            cwd=workdir,
            env=merged_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            start_new_session=True,
        )

    def kill(self, graceful_first=False):
        if self.process is None:
            return
        if self.process.poll() is None:
            if graceful_first:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=SHUTDOWN_GRACE_SECONDS)
                except Exception:
                    pass
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        self.process.kill()
                    except Exception:
                        pass
                try:
                    self.process.wait(timeout=2)
                except Exception:
                    pass
        self._reap()

    def shutdown(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'{"type":"end"}\n')
                self.process.stdin.flush()
            except Exception:
                pass
        self.kill(graceful_first=True)

    def _reap(self):
        if self.process is not None and self.process.poll() is not None:
            self.exit_code = self.process.returncode


# 全局唯一的受监管进程（每方一个工作容器，对应一方作品）。
_PROC = SupervisedProcess()


def _not_running_reply():
    reply = {"ok": False, "error": "bot_not_running"}
    if _PROC.exit_code is not None:
        reply["exit_code"] = _PROC.exit_code
    return reply


def _parse_until(raw_until):
    """解析 until 条件：('newline', None) | ('eof', None) | ('bytes', K)。"""
    if raw_until is None or raw_until == "newline":
        return "newline", None
    if raw_until == "eof":
        return "eof", None
    if isinstance(raw_until, dict) and isinstance(raw_until.get("bytes"), int):
        count = max(1, int(raw_until["bytes"]))
        return "bytes", count
    raise ValueError("until 必须是 newline / eof / {\"bytes\": K}")


def _handle_spawn(request):
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        return {"ok": False, "error": "bad_request", "message": "argv 必须是非空字符串数组"}
    try:
        workdir = _resolve_relative(SUBMISSION_DIR, request.get("workdir"))
    except ValueError:
        return {"ok": False, "error": "bad_request", "message": "workdir 越界"}
    try:
        _PROC.spawn(argv, request.get("env"), workdir)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "exec_failed", "message": str(exc)}
    return {"ok": True, "pid": _PROC.process.pid}


def _handle_interact(request):
    if not _PROC.alive():
        return _not_running_reply()
    input_b64 = request.get("input")
    input_bytes = None
    if input_b64:
        try:
            input_bytes = base64.b64decode(str(input_b64), validate=True)
        except Exception:
            return {"ok": False, "error": "bad_input", "message": "input 不是合法 base64"}
        if len(input_bytes) > MAX_INPUT_BYTES:
            return {"ok": False, "error": "bad_input", "message": "input 超过 1 MiB 上限"}
    try:
        until_mode, until_count = _parse_until(request.get("until"))
    except ValueError as exc:
        return {"ok": False, "error": "bad_request", "message": str(exc)}
    timeout_ms = max(1, int(request.get("timeout_ms") or DEFAULT_INTERACT_TIMEOUT_MS))

    process = _PROC.process
    if input_bytes is not None:
        try:
            process.stdin.write(input_bytes)
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            _PROC._reap()
            return _not_running_reply()

    cap = MAX_LINE_OUTPUT_BYTES if until_mode == "newline" else MAX_BULK_OUTPUT_BYTES
    started = time.monotonic()
    deadline = started + timeout_ms / 1000.0
    buffer = bytearray()
    stdout_fd = process.stdout.fileno()

    while True:
        # 满足 until 条件即返回（计时只覆盖被测进程本身）。
        if until_mode == "newline" and b"\n" in buffer:
            line = buffer.split(b"\n", 1)[0]
            return {"ok": True,
                    "output": base64.b64encode(bytes(line)).decode("ascii"),
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
        if until_mode == "bytes" and len(buffer) >= until_count:
            return {"ok": True,
                    "output": base64.b64encode(bytes(buffer[:until_count])).decode("ascii"),
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}

        if process.poll() is not None:
            # 进程已退出：先把管道里剩余输出读完，再按 until 判定成败。
            buffer += _drain_stdout(process)
            _PROC._reap()
            if until_mode == "eof":
                return {"ok": True,
                        "output": base64.b64encode(bytes(buffer)).decode("ascii"),
                        "exit_code": _PROC.exit_code,
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
            if until_mode == "newline" and b"\n" in buffer:
                line = buffer.split(b"\n", 1)[0]
                return {"ok": True,
                        "output": base64.b64encode(bytes(line)).decode("ascii"),
                        "exit_code": _PROC.exit_code,
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
            if until_mode == "bytes" and len(buffer) >= until_count:
                return {"ok": True,
                        "output": base64.b64encode(bytes(buffer[:until_count])).decode("ascii"),
                        "exit_code": _PROC.exit_code,
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
            reply = {"ok": False, "error": "bot_exited",
                     "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
            if _PROC.exit_code is not None:
                reply["exit_code"] = _PROC.exit_code
            return reply

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _PROC.kill()
            return {"ok": False, "error": "timeout",
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
        if len(buffer) > cap:
            _PROC.kill()
            return {"ok": False, "error": "oversize",
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}

        readable, _, _ = select.select([stdout_fd], [], [], remaining)
        if not readable:
            continue
        try:
            chunk = os.read(stdout_fd, 4096)
        except OSError:
            chunk = b""
        if not chunk:
            # stdout EOF：下一轮通过 poll() 走进程退出分支。
            continue
        buffer += chunk


def _drain_stdout(process):
    data = bytearray()
    fd = process.stdout.fileno()
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_BULK_OUTPUT_BYTES * 2:
            break
    return bytes(data)


def _handle_kill(request):
    if not _PROC.alive() and _PROC.process is None:
        return {"ok": True, "was_running": False}
    was_running = _PROC.alive()
    _PROC.kill(graceful_first=True)
    reply = {"ok": True, "was_running": was_running}
    if _PROC.exit_code is not None:
        reply["exit_code"] = _PROC.exit_code
    return reply


def _handle_status(request):
    alive = _PROC.alive()
    reply = {"ok": True, "alive": alive}
    if not alive and _PROC.exit_code is not None:
        reply["exit_code"] = _PROC.exit_code
    return reply


def _handle_exec(request):
    """在作品目录内运行一条受信命令（由管理员评分脚本经仲裁者下发）。"""
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        return {"ok": False, "error": "bad_request", "message": "argv 必须是字符串数组"}
    timeout_ms = max(1, int(request.get("timeout_ms") or 30000))
    try:
        workdir = _resolve_relative(SUBMISSION_DIR, request.get("workdir"))
    except ValueError:
        return {"ok": False, "error": "bad_request", "message": "workdir 越界"}
    stream_limit = min(
        max(1024, int(request.get("stream_limit_bytes") or DEFAULT_EXEC_STREAM_LIMIT_BYTES)),
        MAX_EXEC_STREAM_LIMIT_BYTES,
    )
    export_files = request.get("export_files") or []
    if not isinstance(export_files, list):
        return {"ok": False, "error": "bad_request", "message": "export_files 必须是数组"}

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.Popen(
            argv,
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": "exec_failed", "message": str(exc)}
    try:
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout_ms / 1000.0)
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
        stdout_bytes, stderr_bytes = proc.communicate()
        exit_code = proc.returncode
    stdout_bytes = stdout_bytes or b""
    stderr_bytes = stderr_bytes or b""
    elapsed_ms = round((time.monotonic() - started) * 1000, 3)

    truncated = False
    if len(stdout_bytes) > stream_limit:
        stdout_bytes = stdout_bytes[-stream_limit:]
        truncated = True
    if len(stderr_bytes) > stream_limit:
        stderr_bytes = stderr_bytes[-stream_limit:]
        truncated = True

    files = _collect_export_files(export_files)

    reply = {
        "ok": True,
        "exit_code": exit_code,
        "stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "stderr": stderr_bytes.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
    }
    if files:
        reply["files"] = files
    return reply


def _collect_export_files(export_files):
    files = {}
    total = 0
    for relative in export_files[:MAX_FETCH_FILES]:
        try:
            path = _resolve_relative(SUBMISSION_DIR, relative)
        except ValueError:
            continue
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > EXEC_EXPORT_MAX_FILE_BYTES or total + size > EXEC_EXPORT_MAX_TOTAL_BYTES:
            continue
        try:
            with open(path, "rb") as handle:
                files[os.path.basename(str(relative))] = base64.b64encode(handle.read()).decode("ascii")
            total += size
        except OSError:
            continue
    return files


def _handle_fetch(request):
    """不执行任何命令，仅按白名单读取作品目录内的文件（base64 返回）。"""
    paths = request.get("paths")
    if not isinstance(paths, list):
        return {"ok": False, "error": "bad_request", "message": "paths 必须是数组"}
    files = _collect_export_files(paths)
    return {"ok": True, "files": files}


def _handle(request):
    kind = request.get("type")
    request_id = request.get("id")
    if kind == "ping":
        _send({"type": "reply", "id": request_id, "ok": True, "pong": True})
        return
    if kind == "spawn":
        result = _handle_spawn(request)
    elif kind == "interact":
        result = _handle_interact(request)
    elif kind == "kill":
        result = _handle_kill(request)
    elif kind == "status":
        result = _handle_status(request)
    elif kind == "exec":
        result = _handle_exec(request)
    elif kind == "fetch":
        result = _handle_fetch(request)
    elif kind == "close":
        _PROC.shutdown()
        _send({"type": "reply", "id": request_id, "ok": True})
        raise SystemExit(0)
    else:
        result = {"ok": False, "error": "bad_request", "message": f"未知帧类型：{kind!r}"}
    result = dict(result)
    result.update({"type": "reply", "id": request_id})
    _send(result)


def main():
    # 运行器自身就绪即回报；启动哪个进程、以何种协议交互，全部由评分脚本决定。
    _send({"type": "ready", "ok": True})

    stdin_fd = sys.stdin.fileno()
    buffer = b""
    try:
        while True:
            try:
                chunk = os.read(stdin_fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                if not raw.strip():
                    continue
                if len(raw) > MAX_REQUEST_LINE_BYTES:
                    _log("请求帧超过上限，忽略")
                    continue
                try:
                    request = json.loads(raw.decode("utf-8", "strict"))
                except (ValueError, UnicodeError):
                    _log("请求帧不是合法 JSON，忽略")
                    continue
                if not isinstance(request, dict):
                    continue
                _handle(request)
    finally:
        _PROC.shutdown()


if __name__ == "__main__":
    main()
