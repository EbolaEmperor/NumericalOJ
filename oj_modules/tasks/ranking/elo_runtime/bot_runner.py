#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局 · 工作容器内的可信 Bot 运行器。

本文件以只读挂载进入每个工作容器（每方一个，容器断网），由宿主侧仲裁者
通过标准输入/输出上的换行分隔 JSON 帧驱动。它是工作容器内唯一可信的
进程，负责：

  - 启动并看管被测 ``bot.py``（与旧评分脚本相同的进程形态：
    ``python3 -u bot.py``，cwd 为作品目录，stderr 丢弃）；
  - 执行启动握手（10 秒内必须收到 ``{"ready": true}``）；
  - 代理每一回合的局面下发与决策回收，并在**容器内**用单调时钟强制执行
    单回合时限——计时只覆盖 bot 本身，不包含宿主↔容器的通信开销；
  - 代理 ``exec`` 请求（为静态对比型比赛在隔离环境内运行编译等命令）；
  - 超时、协议违规时终止 bot，防止失控进程继续占用资源。

协议帧（每行一个 JSON 对象）：

宿主 → 运行器：
  {"type": "ask",  "id": N, "timeout_ms": T, "payload": {...}}
  {"type": "exec", "id": N, "timeout_ms": T, "argv": [...],
   "workdir": "相对路径|空", "export_files": ["相对路径", ...]}
  {"type": "ping", "id": N}
  {"type": "close"}

运行器 → 宿主：
  {"type": "ready", "ok": true, "handshake_ms": x}
  {"type": "ready", "ok": false, "error": "..."}
  {"type": "reply", "id": N, "ok": true, "response": {...}, "elapsed_ms": x}
  {"type": "reply", "id": N, "ok": false, "error": "timeout|bad_output|oversize|bot_exited|bot_not_running", ...}
  {"type": "reply", "id": N, "ok": true, "pong": true}
  {"type": "reply", "id": N, "ok": true, "exit_code": 0, "stdout": "...", "stderr": "...",
   "timed_out": false, "files": {"名称": "<base64>"}}

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


STARTUP_HANDSHAKE_TIMEOUT_SECONDS = 10.0
MAX_BOT_LINE_BYTES = 16 * 1024            # bot 单行输出上限（与旧评分脚本一致）
MAX_REQUEST_LINE_BYTES = 8 * 1024 * 1024  # 宿主请求帧上限（局面/argv 等）
MAX_PAYLOAD_LINE_BYTES = 1024 * 1024      # 发给 bot 的单行局面上限
DEFAULT_EXEC_STREAM_LIMIT_BYTES = 256 * 1024
MAX_EXEC_STREAM_LIMIT_BYTES = 4 * 1024 * 1024
EXEC_EXPORT_MAX_FILE_BYTES = 8 * 1024 * 1024
EXEC_EXPORT_MAX_TOTAL_BYTES = 16 * 1024 * 1024
BOT_SHUTDOWN_GRACE_SECONDS = 0.5

SUBMISSION_DIR = os.environ.get("NUMOJ_ELO_SUBMISSION_DIR", "/submission")


class BotFault(Exception):
    """bot 侧协议违规；消息即回给宿主的 error 码。"""


def _log(message):
    try:
        sys.stderr.write(f"[elo-bot-runner] {message}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _send(frame):
    data = (json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    os.write(sys.stdout.fileno(), data)


class BotProcess:
    """看管单个被测 bot 进程：握手、按回合问答、超时强杀。"""

    def __init__(self, submission_dir):
        self.submission_dir = submission_dir
        self.process = None
        self.startup_error = None
        self.exit_code = None
        self._buffer = b""

    def start(self):
        """启动 bot 并完成握手；成功返回握手耗时毫秒数，失败返回 None。"""
        bot_path = os.path.join(self.submission_dir, "bot.py")
        if not os.path.isfile(bot_path):
            self.startup_error = "作品包根目录缺少 bot.py"
            return None
        started = time.monotonic()
        try:
            self.process = subprocess.Popen(
                ["python3", "-u", bot_path],
                cwd=self.submission_dir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                start_new_session=True,
            )
        except OSError as exc:
            self.startup_error = f"无法启动 bot 进程：{exc}"
            return None
        try:
            line = self._readline(STARTUP_HANDSHAKE_TIMEOUT_SECONDS, "timeout")
        except BotFault as exc:
            self.startup_error = (
                f"启动握手失败：{exc}" if str(exc) != "timeout"
                else "启动握手超时（>10 秒）"
            )
            self._kill_bot()
            return None
        try:
            payload = json.loads(line.decode("utf-8", "strict"))
        except (ValueError, UnicodeError) as exc:
            self.startup_error = f"启动握手输出不是合法 JSON：{exc}"
            self._kill_bot()
            return None
        if not isinstance(payload, dict) or payload.get("ready") is not True:
            self.startup_error = '启动握手必须是 {"ready": true}'
            self._kill_bot()
            return None
        return round((time.monotonic() - started) * 1000, 3)

    def alive(self):
        if self.process is None or self.startup_error is not None:
            return False
        if self.process.poll() is not None:
            self.exit_code = self.process.returncode
            return False
        return True

    def ask(self, payload, timeout_ms):
        """下发一行局面并等待一行决策。

        计时从局面完整写入 bot 标准输入之后开始，到读完整行为止，即 bot 的
        可用思考时间不受宿主↔容器通信延迟影响。超时或违规时强杀 bot。
        """
        if not self.alive():
            return self._not_running_reply()
        try:
            line_out = (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return {"ok": False, "error": "bad_payload", "message": f"局面无法序列化：{exc}"}
        if len(line_out) > MAX_PAYLOAD_LINE_BYTES:
            return {"ok": False, "error": "bad_payload", "message": "局面超过 1 MiB 上限"}
        try:
            self.process.stdin.write(line_out)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError):
            self._reap()
            return self._not_running_reply()
        started = time.monotonic()
        deadline = started + max(0.0, float(timeout_ms)) / 1000.0
        try:
            line = self._readline_deadline(deadline, "timeout")
        except BotFault as exc:
            elapsed_ms = round((time.monotonic() - started) * 1000, 3)
            error = str(exc)
            self._kill_bot()
            reply = {"ok": False, "error": error, "elapsed_ms": elapsed_ms}
            if error == "bot_exited":
                reply["exit_code"] = self.exit_code
            return reply
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        try:
            response = json.loads(line.decode("utf-8", "strict"))
        except (ValueError, UnicodeError):
            self._kill_bot()
            return {"ok": False, "error": "bad_output", "elapsed_ms": elapsed_ms}
        if not isinstance(response, dict):
            self._kill_bot()
            return {"ok": False, "error": "bad_output", "elapsed_ms": elapsed_ms}
        return {"ok": True, "response": response, "elapsed_ms": elapsed_ms}

    def shutdown(self):
        """对局结束：尽力礼貌通知，然后确保进程退出。"""
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                process.stdin.write(b'{"type":"end"}\n')
                process.stdin.flush()
            except Exception:
                pass
        self._kill_bot(graceful_first=True)

    # ---------- 内部 ----------

    def _not_running_reply(self):
        reply = {"ok": False, "error": "bot_not_running"}
        if self.startup_error:
            reply["message"] = self.startup_error
        if self.exit_code is not None:
            reply["exit_code"] = self.exit_code
        return reply

    def _readline(self, timeout_seconds, timeout_label):
        return self._readline_deadline(time.monotonic() + timeout_seconds, timeout_label)

    def _readline_deadline(self, deadline, timeout_label):
        while True:
            if b"\n" in self._buffer:
                raw, self._buffer = self._buffer.split(b"\n", 1)
                if len(raw) > MAX_BOT_LINE_BYTES:
                    raise BotFault("oversize")
                return raw
            if len(self._buffer) > MAX_BOT_LINE_BYTES:
                raise BotFault("oversize")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BotFault(timeout_label)
            if self.process.poll() is not None:
                # 进程已退出：先把管道里剩余输出读完再判失败，避免误杀快速退出的合法输出。
                self._drain_after_exit()
                if b"\n" in self._buffer:
                    raw, self._buffer = self._buffer.split(b"\n", 1)
                    if len(raw) > MAX_BOT_LINE_BYTES:
                        raise BotFault("oversize")
                    return raw
                raise BotFault("bot_exited")
            readable, _, _ = select.select([self.process.stdout.fileno()], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = os.read(self.process.stdout.fileno(), 4096)
            except OSError:
                chunk = b""
            if not chunk:
                self._reap()
                raise BotFault("bot_exited")
            self._buffer += chunk

    def _drain_after_exit(self):
        fd = self.process.stdout.fileno()
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self._buffer += chunk
            if len(self._buffer) > MAX_BOT_LINE_BYTES * 2:
                break
        self._reap()

    def _reap(self):
        if self.process is not None and self.process.poll() is not None:
            self.exit_code = self.process.returncode

    def _kill_bot(self, graceful_first=False):
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            if graceful_first:
                try:
                    process.terminate()
                    process.wait(timeout=BOT_SHUTDOWN_GRACE_SECONDS)
                except Exception:
                    pass
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except Exception:
                        pass
                try:
                    process.wait(timeout=2)
                except Exception:
                    pass
        self._reap()


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


def _run_exec(request):
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

    files = {}
    total = 0
    for relative in export_files[:32]:
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
            truncated = True
            continue
        try:
            with open(path, "rb") as handle:
                files[os.path.basename(str(relative))] = base64.b64encode(handle.read()).decode("ascii")
            total += size
        except OSError:
            continue

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


def main():
    bot = BotProcess(SUBMISSION_DIR)
    handshake_ms = bot.start()
    if handshake_ms is None:
        _send({"type": "ready", "ok": False, "error": bot.startup_error or "启动失败"})
    else:
        _send({"type": "ready", "ok": True, "handshake_ms": handshake_ms})

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
                _handle(bot, request)
    finally:
        bot.shutdown()


def _handle(bot, request):
    kind = request.get("type")
    request_id = request.get("id")
    if kind == "ping":
        _send({"type": "reply", "id": request_id, "ok": True, "pong": True})
        return
    if kind == "ask":
        result = bot.ask(request.get("payload"), request.get("timeout_ms") or 1000)
        result = dict(result)
        result.update({"type": "reply", "id": request_id})
        _send(result)
        return
    if kind == "exec":
        result = dict(_run_exec(request))
        result.update({"type": "reply", "id": request_id})
        _send(result)
        return
    if kind == "close":
        bot.shutdown()
        _send({"type": "reply", "id": request_id, "ok": True})
        raise SystemExit(0)


if __name__ == "__main__":
    main()
