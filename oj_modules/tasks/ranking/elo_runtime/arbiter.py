#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局 · 宿主侧仲裁者。

把一场 ELO 对局拆成三个平级容器（不涉及嵌套容器）：

  - 两个工作容器：各挂载一方作品，``--network none``（可配置），运行可信的
    ``bot_runner.py``（通用受监管进程运行器）；被测代码看不到对手作品、评分
    脚本，也没有网络。运行哪个文件、用什么语言与协议，全部由评分脚本通过
    ``spawn``/``interact`` 等原语决定。
  - 一个裁判容器：挂载评分脚本，保持联网（沿用 Agent Judge 网络），运行管理员
    评分脚本并经 ``elo_host_api`` 通过本仲裁者调用工作容器。

仲裁者是纯消息路由 + 看门狗：

  - 交互计时在**工作容器内**执行（只覆盖被测进程本身），仲裁者另加外层宽限
    防止运行器卡死——因此宿主↔容器通信延迟不会挤占比赛规定的回合时限；
  - 裁决仍按既有协议从裁判容器 stdout 的最后一条合法 JSON 行解析；
  - 全部输出有界 drain，容器清理失败会显式报错。

命令构造与资源参数沿用 ``elo_container`` 的 Agent Judge 约定；与
``judging/sandbox.py`` 一样，清理采用“强制移除 + 确认消失”语义。
"""

from __future__ import annotations

import json
import os
import secrets
import selectors
import shutil
import subprocess
import tempfile
import time

from oj_modules import config as _cfg
from oj_modules.tasks.ranking import elo_container


def _config_value(name, default):
    env_value = os.environ.get(name)
    if env_value is not None and str(env_value).strip() != "":
        return env_value
    return getattr(_cfg, name, default)


WORKER_NETWORK = str(_config_value("ELO_ISOLATED_WORKER_NETWORK", "none"))
JUDGE_NETWORK = str(_config_value("ELO_ISOLATED_JUDGE_NETWORK", "bridge"))
WORKER_STARTUP_GRACE_SECONDS = float(
    _config_value("ELO_ISOLATED_WORKER_STARTUP_GRACE_SECONDS", 30)
)
# 外层看门狗宽限：单回合时限由工作容器内部强制执行，这里只兜底“运行器无响应”。
CALL_GRACE_MS = int(_config_value("ELO_ISOLATED_CALL_GRACE_MS", 2000))
EXEC_GRACE_MS = int(_config_value("ELO_ISOLATED_EXEC_GRACE_MS", 5000))

JUDGE_STDOUT_DRAIN_LIMIT = 16 * 1024 * 1024
VERDICT_TAIL_BYTES = 512 * 1024
STREAM_TAIL_BYTES = 64 * 1024
MAX_FRAME_LINE_BYTES = 96 * 1024 * 1024
RPC_PREFIX = "__NUMOJ_ELO_RPC_V1__"
WORKER_STDIN_CHUNK = 65536

RUNNER_HOST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bot_runner.py")
HOST_API_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "elo_host_api.py")


class EloRuntimeError(RuntimeError):
    """隔离对局运行失败（供 elo 任务按既有语义落 winner=-1 占位）。"""


class _TailBuffer:
    """只保留尾部固定字节的有界缓冲，用于裁决解析与诊断信息。"""

    def __init__(self, limit):
        self.limit = max(1, int(limit))
        self.data = bytearray()
        self.total = 0
        self.truncated = False

    def append(self, chunk):
        self.total += len(chunk)
        self.data.extend(chunk)
        overflow = len(self.data) - self.limit
        if overflow > 0:
            del self.data[:overflow]
            self.truncated = True

    def text(self):
        return bytes(self.data).decode("utf-8", errors="replace")


class _WorkerState:
    def __init__(self, side, container_name, proc):
        self.side = side
        self.container_name = container_name
        self.proc = proc
        self.buffer = b""
        self.write_queue = bytearray()
        # 就绪 = 可信运行器已启动并可接受请求；启动哪个被测进程、如何交互
        # 全部由评分脚本经原语决定，仲裁者不跟踪任何被测进程的握手状态。
        self.ready_determined = False
        self.dead = False
        self.death_reason = None
        self.stderr_tail = _TailBuffer(STREAM_TAIL_BYTES)
        # 就绪判定完成前到达的请求先暂存，判定后再转发/应答（见 _drain_held）。
        self.held = []


class _JudgeState:
    def __init__(self, container_name, proc):
        self.container_name = container_name
        self.proc = proc
        self.stdout_tail = _TailBuffer(VERDICT_TAIL_BYTES)
        self.stdout_drained = 0
        self.stdout_overflow = False
        self.stderr_tail = _TailBuffer(STREAM_TAIL_BYTES)
        self.stderr_buffer = b""
        self.write_queue = bytearray()
        self.finished = False


def worker_command(container_name, submission_dir):
    """工作容器（被测方）启动命令：断网、只挂载本方作品与可信运行器。"""
    return [
        "docker", "run", "--name", container_name, "-i",
        "--security-opt", "no-new-privileges",
        "--log-opt", "max-size=16m", "--log-opt", "max-file=1",
        "--pids-limit", str(elo_container.AGENT_JUDGE_PIDS_LIMIT),
        "--memory", str(elo_container.AGENT_JUDGE_MEM_LIMIT),
        "--cpus", str(elo_container.AGENT_JUDGE_CPU_LIMIT),
        # 被测代码断网：看不到外部世界，也无法内嵌在线 agent。
        "--network", WORKER_NETWORK,
        "-e", "IS_SANDBOX=1",
        "-e", "NUMOJ_ELO_SUBMISSION_DIR=/submission",
        "-v", f"{os.path.realpath(submission_dir)}:/submission",
        "-v", f"{RUNNER_HOST_PATH}:/opt/numoj/elo/bot_runner.py:ro",
        "-w", "/submission",
        str(elo_container.AGENT_JUDGE_IMAGE),
        "python3", "-I", "-u", "/opt/numoj/elo/bot_runner.py",
    ]


def judge_command(container_name, judge_dir):
    """裁判容器启动命令：保持联网，只挂载评分脚本目录，看不到任何作品文件。"""
    return [
        "docker", "run", "--name", container_name, "-i",
        "--security-opt", "no-new-privileges",
        "--log-opt", "max-size=16m", "--log-opt", "max-file=1",
        "--pids-limit", str(elo_container.AGENT_JUDGE_PIDS_LIMIT),
        "--memory", str(elo_container.AGENT_JUDGE_MEM_LIMIT),
        "--cpus", str(elo_container.AGENT_JUDGE_CPU_LIMIT),
        # 裁判保持联网（LLM 成对比较等评分脚本需要外网）。
        "--network", JUDGE_NETWORK,
        "-e", "IS_SANDBOX=1",
        "-e", "NUMOJ_ELO_RUNTIME=isolated",
        "-v", f"{os.path.realpath(judge_dir)}:/judge",
        "-w", "/judge",
        str(elo_container.AGENT_JUDGE_IMAGE),
        "python3", "-u", "/judge/scoring_script.py",
    ]


class IsolatedEloMatch:
    """单场隔离对局的编排器。

    ``spawner(role, command) -> Popen``、``remover(container_name)`` 可注入用于
    单元测试；生产默认分别为本地 ``subprocess.Popen`` 与强制移除容器。
    """

    def __init__(self, script_path, archive_a, archive_b, timeout_seconds,
                 spawner=None, remover=None):
        self.script_path = script_path
        self.archive_a = archive_a
        self.archive_b = archive_b
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.spawner = spawner or (lambda role, command: subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        ))
        self.remover = remover or _force_remove_container
        self.workspace = None
        self.workers = {}
        self.judge = None
        self.pending = {}
        self._request_seq = 0
        self._write_targets = {}
        self._selector = selectors.DefaultSelector()

    # ---------- 对外入口 ----------

    def run(self):
        """运行一场隔离对局，返回 (winner, details)；失败抛 EloRuntimeError。"""
        try:
            self._prepare_workspace()
            self._start_containers()
            self._event_loop()
            return self._parse_verdict()
        except subprocess.TimeoutExpired:
            raise EloRuntimeError(f"评测脚本执行超时（>{self.timeout_seconds}s）")
        finally:
            self._cleanup()

    # ---------- 工作区与容器 ----------

    def _prepare_workspace(self):
        root = os.path.abspath(os.path.join(
            elo_container.AGENT_JUDGE_WORKSPACE_ROOT, "elo"))
        os.makedirs(root, exist_ok=True)
        workspace = tempfile.mkdtemp(prefix="match-iso-", dir=root)
        try:
            judge_dir = os.path.join(workspace, "judge")
            os.makedirs(judge_dir, exist_ok=True)
            shutil.copy2(self.script_path, os.path.join(judge_dir, "scoring_script.py"))
            shutil.copy2(HOST_API_PATH, os.path.join(judge_dir, "elo_host_api.py"))
            elo_container._extract_submission(
                self.archive_a, os.path.join(workspace, "submission_a"))
            elo_container._extract_submission(
                self.archive_b, os.path.join(workspace, "submission_b"))
        except Exception:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        self.workspace = workspace

    def _start_containers(self):
        for side, subdir in (("A", "submission_a"), ("B", "submission_b")):
            name = f"numoj-elo-iso-w{side.lower()}-{secrets.token_hex(8)}"
            command = worker_command(
                name, os.path.join(self.workspace, subdir))
            proc = self.spawner(f"worker_{side.lower()}", command)
            self._register_worker(_WorkerState(side, name, proc))
        judge_name = f"numoj-elo-iso-judge-{secrets.token_hex(8)}"
        judge_proc = self.spawner(
            "judge", judge_command(judge_name, os.path.join(self.workspace, "judge")))
        self.judge = _JudgeState(judge_name, judge_proc)
        self._register_judge_pipes()

    def _register_worker(self, worker):
        self.workers[worker.side] = worker
        os.set_blocking(worker.proc.stdout.fileno(), False)
        os.set_blocking(worker.proc.stderr.fileno(), False)
        os.set_blocking(worker.proc.stdin.fileno(), False)
        self._selector.register(worker.proc.stdout, selectors.EVENT_READ, ("worker_out", worker))
        self._selector.register(worker.proc.stderr, selectors.EVENT_READ, ("worker_err", worker))

    def _register_judge_pipes(self):
        os.set_blocking(self.judge.proc.stdout.fileno(), False)
        os.set_blocking(self.judge.proc.stderr.fileno(), False)
        os.set_blocking(self.judge.proc.stdin.fileno(), False)
        self._selector.register(self.judge.proc.stdout, selectors.EVENT_READ, ("judge_out", None))
        self._selector.register(self.judge.proc.stderr, selectors.EVENT_READ, ("judge_err", None))

    # ---------- 事件循环 ----------

    def _event_loop(self):
        deadline = time.monotonic() + self.timeout_seconds
        startup_deadline = time.monotonic() + WORKER_STARTUP_GRACE_SECONDS
        judge_stdout_open = True
        judge_stderr_open = True

        while True:
            now = time.monotonic()
            if now > deadline:
                raise subprocess.TimeoutExpired("elo-isolated-match", self.timeout_seconds)
            self._expire_pending(now)
            self._mark_dead_workers(now, startup_deadline)

            if self.judge.finished and not judge_stdout_open and not judge_stderr_open:
                break
            if not self._selector.get_map():
                break

            events = self._selector.select(timeout=0.02)
            for key, mask in events:
                kind, worker = key.data
                pipe = key.fileobj
                if mask & selectors.EVENT_WRITE:
                    self._flush_write(pipe)
                    continue
                if kind == "worker_out":
                    self._read_worker_out(worker, pipe)
                elif kind == "worker_err":
                    self._read_stream(pipe, worker.stderr_tail, None)
                elif kind == "judge_out":
                    judge_stdout_open = self._read_judge_out(pipe)
                elif kind == "judge_err":
                    judge_stderr_open = self._read_judge_err(pipe)

            self._arm_write_interest()

            if self.judge.proc.poll() is not None and not self.judge.finished:
                # 裁判进程已退出：继续 drain 剩余输出到 EOF，然后结束对局。
                self.judge.finished = True
                self._enqueue_write(self.judge.proc.stdin, b"", close=True)

    def _read_stream(self, pipe, tail_buffer, on_eof):
        try:
            chunk = os.read(pipe.fileno(), WORKER_STDIN_CHUNK)
        except BlockingIOError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            self._unregister(pipe)
            if on_eof is not None:
                on_eof()
            return False
        tail_buffer.append(chunk)
        return True

    def _read_worker_out(self, worker, pipe):
        try:
            chunk = os.read(pipe.fileno(), WORKER_STDIN_CHUNK)
        except BlockingIOError:
            return
        except OSError:
            chunk = b""
        if not chunk:
            self._unregister(pipe)
            return
        worker.buffer += chunk
        if len(worker.buffer) > MAX_FRAME_LINE_BYTES:
            self._fail_worker(worker, "工作容器输出超过上限")
            worker.buffer = b""
            return
        while b"\n" in worker.buffer:
            raw, worker.buffer = worker.buffer.split(b"\n", 1)
            if not raw.strip():
                continue
            self._handle_worker_frame(worker, raw)

    def _read_judge_out(self, pipe):
        try:
            chunk = os.read(pipe.fileno(), WORKER_STDIN_CHUNK)
        except BlockingIOError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            self._unregister(pipe)
            return False
        self.judge.stdout_drained += len(chunk)
        if self.judge.stdout_drained > JUDGE_STDOUT_DRAIN_LIMIT:
            self.judge.stdout_overflow = True
        self.judge.stdout_tail.append(chunk)
        return True

    def _read_judge_err(self, pipe):
        try:
            chunk = os.read(pipe.fileno(), WORKER_STDIN_CHUNK)
        except BlockingIOError:
            return True
        except OSError:
            chunk = b""
        if not chunk:
            self._unregister(pipe)
            return False
        self.judge.stderr_tail.append(chunk)
        self.judge.stderr_buffer += chunk
        if len(self.judge.stderr_buffer) > MAX_FRAME_LINE_BYTES:
            self.judge.stderr_buffer = self.judge.stderr_buffer[-WORKER_STDIN_CHUNK:]
        while b"\n" in self.judge.stderr_buffer:
            raw, self.judge.stderr_buffer = self.judge.stderr_buffer.split(b"\n", 1)
            line = raw.decode("utf-8", errors="replace").strip()
            if line.startswith(RPC_PREFIX):
                self._handle_judge_request(line[len(RPC_PREFIX):])
        return True

    # ---------- 帧处理 ----------

    def _handle_worker_frame(self, worker, raw):
        try:
            frame = json.loads(raw.decode("utf-8", "strict"))
        except (ValueError, UnicodeError):
            return
        if not isinstance(frame, dict):
            return
        if frame.get("type") == "ready" and not worker.ready_determined:
            # 运行器自身就绪（尚未启动任何被测进程）：可以开始转发请求了。
            worker.ready_determined = True
            self._drain_held(worker)
            return
        if frame.get("type") == "reply":
            self._resolve_pending(worker, frame)

    # judge RPC 方法 → （运行器帧构造、缺省时限）。宽限统一叠加在看门狗上。
    _METHOD_DEFAULT_TIMEOUT_MS = {
        "spawn": 10000,
        "interact": 1000,
        "kill": 5000,
        "proc_status": 5000,
        "fetch_files": 10000,
        "ping": 1000,
        "run_worker": 30000,
    }

    def _build_worker_frame(self, method, request):
        if method == "spawn":
            return {"type": "spawn", "argv": request.get("argv"),
                    "env": request.get("env"), "workdir": request.get("workdir")}
        if method == "interact":
            return {"type": "interact", "input": request.get("input"),
                    "timeout_ms": max(1, int(request.get("timeout_ms") or 1000)),
                    "until": request.get("until")}
        if method == "kill":
            return {"type": "kill"}
        if method == "proc_status":
            return {"type": "status"}
        if method == "run_worker":
            return {"type": "exec", "timeout_ms": max(1, int(request.get("timeout_ms") or 30000)),
                    "argv": request.get("argv"), "workdir": request.get("workdir"),
                    "export_files": request.get("export_files"),
                    "stream_limit_bytes": request.get("stream_limit_bytes")}
        if method == "fetch_files":
            return {"type": "fetch", "paths": request.get("paths")}
        if method == "ping":
            return {"type": "ping"}
        return None

    def _handle_judge_request(self, payload_text):
        try:
            request = json.loads(payload_text)
        except (ValueError, UnicodeError):
            return
        if not isinstance(request, dict):
            return
        method = request.get("method")
        request_id = request.get("id")
        side = str(request.get("side") or "").strip().upper()
        if method not in self._METHOD_DEFAULT_TIMEOUT_MS:
            self._answer_judge(request_id, {
                "ok": False, "error": "bad_request", "message": f"未知方法：{method!r}",
            })
            return
        worker = self.workers.get(side)
        if worker is None:
            self._answer_judge(request_id, {
                "ok": False, "error": "bad_request", "message": "side 必须是 A 或 B",
            })
            return
        frame = self._build_worker_frame(method, request)
        entry = {
            "judge_id": request_id,
            "worker": worker,
            "frame": frame,
            "timeout_ms": max(1, int(
                request.get("timeout_ms") or self._METHOD_DEFAULT_TIMEOUT_MS[method])),
            "grace_ms": EXEC_GRACE_MS if method == "run_worker" else CALL_GRACE_MS,
            "deadline": None,
        }
        if worker.ready_determined:
            self._dispatch(entry)
        else:
            worker.held.append(entry)

    def _dispatch(self, entry):
        """运行器就绪后转发请求；外层看门狗截止时间从**转发时刻**起算，
        工作容器的启动耗时不会挤占评分脚本请求的时限。"""
        worker = entry["worker"]
        if worker.dead:
            self._answer_judge(entry["judge_id"], {
                "ok": False, "error": "worker_unavailable",
                "message": worker.death_reason or "工作容器不可用",
            })
            return
        self._request_seq += 1
        seq = self._request_seq
        frame = dict(entry["frame"])
        frame["id"] = seq
        entry["deadline"] = time.monotonic() + (
            entry["timeout_ms"] + entry["grace_ms"]) / 1000.0
        self.pending[seq] = entry
        self._send_to_worker(worker, frame)

    def _drain_held(self, worker):
        held, worker.held = worker.held, []
        for entry in held:
            self._dispatch(entry)

    def _resolve_pending(self, worker, frame):
        seq = frame.get("id")
        entry = self.pending.pop(seq, None)
        if entry is None:
            return
        response = {key: value for key, value in frame.items()
                    if key not in ("type", "id")}
        response.setdefault("ok", False)
        self._answer_judge(entry["judge_id"], response)

    def _expire_pending(self, now):
        expired = [seq for seq, entry in self.pending.items() if entry["deadline"] <= now]
        for seq in expired:
            entry = self.pending.pop(seq)
            worker = entry["worker"]
            self._answer_judge(entry["judge_id"], {
                "ok": False, "error": "worker_unresponsive",
                "message": "工作容器未在看门狗宽限内响应",
            })
            # 运行器已不可信：直接杀掉该工作容器，后续调用快速失败。
            self._fail_worker(worker, "看门狗超时，仲裁者终止工作容器")

    def _mark_dead_workers(self, now, startup_deadline):
        for worker in self.workers.values():
            if worker.dead:
                continue
            if worker.proc.poll() is not None:
                reason = worker.stderr_tail.text().strip()[-500:] or (
                    f"工作容器进程退出（退出码 {worker.proc.returncode}）")
                self._fail_worker(worker, reason)
                continue
            if not worker.ready_determined and now > startup_deadline:
                # 运行器未在宽限内就绪：放行暂存请求，让其快速失败。
                worker.ready_determined = True
                self._drain_held(worker)

    def _fail_worker(self, worker, reason):
        if worker.dead:
            return
        worker.dead = True
        worker.death_reason = reason
        worker.ready_determined = True
        for pipe in (worker.proc.stdout, worker.proc.stderr):
            self._unregister(pipe)
        try:
            worker.proc.kill()
        except Exception:
            pass
        self.remover(worker.container_name)
        stuck = [seq for seq, entry in self.pending.items() if entry["worker"] is worker]
        for seq in stuck:
            entry = self.pending.pop(seq)
            self._answer_judge(entry["judge_id"], {
                "ok": False, "error": "worker_unavailable", "message": reason,
            })
        self._drain_held(worker)

    # ---------- 发送 ----------

    def _send_to_worker(self, worker, frame):
        data = (json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        self._enqueue_write(worker.proc.stdin, data)

    def _answer_judge(self, request_id, payload):
        response = dict(payload)
        response["id"] = request_id
        data = (json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        self._enqueue_write(self.judge.proc.stdin, data)

    def _enqueue_write(self, pipe, data, close=False):
        entry = self._write_targets.setdefault(pipe, {"queue": bytearray(), "close": False})
        entry["queue"].extend(data)
        if close:
            entry["close"] = True

    def _arm_write_interest(self):
        for pipe, entry in list(self._write_targets.items()):
            wants_write = bool(entry["queue"]) or entry["close"]
            try:
                self._selector.get_key(pipe)
                registered = True
            except KeyError:
                registered = False
            if wants_write and not registered:
                try:
                    self._selector.register(pipe, selectors.EVENT_WRITE, ("write", None))
                except (ValueError, OSError):
                    entry["queue"].clear()
                    entry["close"] = False
            elif not wants_write and registered:
                self._unregister(pipe)

    def _flush_write(self, pipe):
        entry = self._write_targets.get(pipe)
        if entry is None:
            self._unregister(pipe)
            return
        while entry["queue"]:
            try:
                written = os.write(pipe.fileno(), bytes(entry["queue"][:WORKER_STDIN_CHUNK]))
            except BlockingIOError:
                return
            except (BrokenPipeError, OSError):
                entry["queue"].clear()
                break
            del entry["queue"][:written]
        if not entry["queue"] and entry["close"]:
            try:
                pipe.close()
            except Exception:
                pass
            self._unregister(pipe)
            self._write_targets.pop(pipe, None)

    def _unregister(self, pipe):
        try:
            self._selector.unregister(pipe)
        except (KeyError, ValueError):
            pass

    # ---------- 裁决与清理 ----------

    def _parse_verdict(self):
        if self.judge.proc.returncode not in (0, None):
            stderr_tail = self.judge.stderr_tail.text().strip()[-2000:]
            raise EloRuntimeError(
                f"评测脚本退出码 {self.judge.proc.returncode}: {stderr_tail}")
        text = self.judge.stdout_tail.text().strip()
        if not text:
            raise EloRuntimeError("评测脚本未输出任何内容")
        last_line = None
        for line in reversed(text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                last_line = line
                break
        if last_line is None:
            raise EloRuntimeError(f"评测脚本 stdout 不是合法 JSON：{text[-500:]}")
        try:
            parsed = json.loads(last_line)
        except json.JSONDecodeError as exc:
            raise EloRuntimeError(f"评测脚本输出 JSON 解析失败：{exc}")
        winner = parsed.get("winner")
        try:
            winner_int = int(winner)
        except (TypeError, ValueError):
            winner_int = None
        if winner_int not in (0, 1, 2):
            raise EloRuntimeError(
                f"评测脚本返回的 winner 非法（应为 0=平局 / 1 / 2）：{winner!r}")
        return winner_int, parsed.get("details")

    def _cleanup(self):
        try:
            self._selector.close()
        except Exception:
            pass
        # 先通知运行器优雅关闭（尽力而为），再强制移除全部容器。
        for worker in self.workers.values():
            if not worker.dead and worker.proc.poll() is None:
                try:
                    os.write(worker.proc.stdin.fileno(),
                             b'{"type":"close","id":0}\n')
                    worker.proc.stdin.flush()
                except Exception:
                    pass
        close_deadline = time.monotonic() + 2.0
        procs = [worker.proc for worker in self.workers.values()]
        if self.judge is not None:
            procs.append(self.judge.proc)
        for proc in procs:
            remaining = close_deadline - time.monotonic()
            if proc.poll() is None and remaining > 0:
                try:
                    proc.wait(timeout=remaining)
                except Exception:
                    pass
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
        names = [worker.container_name for worker in self.workers.values()]
        if self.judge is not None:
            names.append(self.judge.container_name)
        for name in names:
            try:
                self.remover(name)
            except Exception:
                pass
        if self.workspace:
            shutil.rmtree(self.workspace, ignore_errors=True)


# ---------- 容器清理（与 judging/sandbox.py 同语义：强制移除并确认消失） ----------

def _inspect_container_absence(container_name):
    try:
        result = subprocess.run(
            ["docker", "container", "inspect", str(container_name)],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except Exception:
        return None
    if result.returncode == 0:
        return False
    stderr = str(result.stderr or "").lower()
    if "no such object:" in stderr or "no such container:" in stderr:
        return True
    return None


def _force_remove_container(container_name):
    try:
        result = subprocess.run(
            ["docker", "rm", "-f", str(container_name)],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except Exception:
        result = None
    if result is not None and result.returncode == 0:
        return
    absence = _inspect_container_absence(container_name)
    if absence is True:
        return
    if absence is False:
        raise EloRuntimeError("ELO 容器强制清理失败，容器仍在运行")
    raise EloRuntimeError("无法确认 ELO 容器已经停止")


def run_isolated_elo_match(script_path, archive_a, archive_b, timeout_seconds):
    """运行一场隔离 ELO 对局，返回 (winner∈{0,1,2}, details)。"""
    match = IsolatedEloMatch(script_path, archive_a, archive_b, timeout_seconds)
    return match.run()


__all__ = [
    "IsolatedEloMatch",
    "EloRuntimeError",
    "run_isolated_elo_match",
]
