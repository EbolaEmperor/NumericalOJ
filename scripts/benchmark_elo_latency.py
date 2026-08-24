#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局运行时 · 容器通信延迟基准。

用途：验证把评分脚本与被测代码拆进三个平级容器后，宿主↔容器的通信开销
会不会挤占比赛规定的回合时限（例如线上回合赛的每回合 1 秒）。

关键设计回顾：交互计时在**工作容器内部**执行（只覆盖被测进程本身的读写），
宿主↔容器链路只影响整场对局的总时长，不进回合预算。本脚本同时量化两者：

  - ``ping``：宿主↔工作容器运行器的裸往返（不含被测进程）。
  - ``turn``：一次完整回合（spawn 起 echo bot 后，``interact`` 的宿主侧总往返
    + 运行器内测得的 ``elapsed_ms``），echo bot 立即回复，差值即纯通信/路由开销。
  - ``timing``：计时语义校验——0.95 秒的 bot 必须成功、1.05 秒的 bot 必须
    被判超时，且运行器报告的 ``elapsed_ms`` 与实际一致。
  - ``full``：经真实仲裁者跑一场由裁判容器驱动的完整对局（裁判→仲裁者→
    双工作容器全链路，走 ``elo_host_api`` 原语）。
  - ``startup``：工作容器从启动到被测进程握手就绪的耗时（容器→运行器→
    ``spawn``→读到 bot 首行）。

运行器就绪帧只表示可信运行器已启动；被测进程由 ``spawn`` 显式启动，入口与
协议由评分脚本自由决定（本基准的示例作品采用 bot.py + 换行 JSON）。

只依赖本机 Docker；镜像默认 ``python:3.12-slim``，可用 ``--image`` 换成
``numericaloj-agent-judge:latest`` 在生产同构环境复测。请勿在生产主机运行。
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DEFAULT_IMAGE = os.environ.get("ELO_BENCH_IMAGE", "python:3.12-slim")
# colima 等本地容器 VM 默认只挂载用户主目录，工作区必须放在主目录内，
# 否则容器内看不到挂载进去的 bot.py。
BENCH_BASE = os.path.expanduser("~/.cache/numericaloj-elo-bench")
os.makedirs(BENCH_BASE, exist_ok=True)


def _percentiles(values, marks=(50, 95, 99)):
    if not values:
        return {}
    ordered = sorted(values)
    result = {}
    for mark in marks:
        index = min(len(ordered) - 1, max(0, round(mark / 100.0 * (len(ordered) - 1))))
        result[f"p{mark}"] = ordered[index]
    return result


def _summary_ms(values):
    if not values:
        return "无样本"
    pct = _percentiles(values)
    return (
        f"n={len(values)} min={min(values):.2f} "
        f"p50={pct['p50']:.2f} p95={pct['p95']:.2f} p99={pct['p99']:.2f} "
        f"max={max(values):.2f} mean={statistics.fmean(values):.2f}（毫秒）"
    )


class DirectWorker:
    """直接以 docker run -i 起一个工作容器并说帧协议（等价仲裁者对 worker 的部分）。"""

    def __init__(self, image, bot_source, workspace, extra_env=None):
        from oj_modules.tasks.ranking.elo_runtime import arbiter
        self.arbiter = arbiter
        self.container_name = f"elo-bench-{os.getpid()}-{int(time.time() * 1000) % 100000}"
        submission_dir = os.path.join(workspace, "submission")
        os.makedirs(submission_dir, exist_ok=True)
        with open(os.path.join(submission_dir, "bot.py"), "w", encoding="utf-8") as handle:
            handle.write(bot_source)
        command = list(arbiter.worker_command(self.container_name, submission_dir))
        command[command.index(str(arbiter.elo_container.AGENT_JUDGE_IMAGE))] = image
        self.started = time.monotonic()
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
        self.buffer = b""
        self.ready_frame = None
        self._seq = 0

    def wait_ready(self, timeout=60.0):
        frame = self._read_frame(timeout)
        self.ready_frame = frame
        return frame

    def spawn_bot(self, bot_file="bot.py", timeout=30.0):
        reply = self.request({"type": "spawn", "argv": ["python3", "-u", bot_file]},
                             timeout=timeout)
        if not reply.get("ok"):
            raise RuntimeError(f"spawn 失败：{reply}")
        return reply

    def read_line(self, timeout_ms=10000, timeout=30.0):
        reply = self.request({"type": "interact", "timeout_ms": timeout_ms,
                              "until": "newline"}, timeout=timeout)
        if not reply.get("ok"):
            raise RuntimeError(f"interact 读行失败：{reply}")
        return base64.b64decode(reply["output"]).decode("utf-8", "replace"), reply

    def turn(self, payload, timeout_ms=1000, timeout=30.0):
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        return self.request({"type": "interact", "timeout_ms": timeout_ms,
                             "until": "newline",
                             "input": base64.b64encode(line.encode()).decode()},
                            timeout=timeout)

    def startup_elapsed_ms(self):
        return round((time.monotonic() - self.started) * 1000, 1)

    def send(self, frame):
        self._seq += 1
        frame = dict(frame)
        frame["id"] = self._seq
        data = (json.dumps(frame, separators=(",", ":")) + "\n").encode("utf-8")
        self.proc.stdin.write(data)
        self.proc.stdin.flush()
        return self._seq

    def _read_frame(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                if raw.strip():
                    return json.loads(raw.decode("utf-8"))
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("等待运行器帧超时")
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                raise EOFError(f"运行器退出：{self.proc.stderr.read(2000)!r}")
            self.buffer += chunk

    def request(self, frame, timeout=30.0):
        started = time.monotonic()
        seq = self.send(frame)
        while True:
            response = self._read_frame(timeout)
            if response.get("type") == "reply" and response.get("id") == seq:
                response["_host_ms"] = round((time.monotonic() - started) * 1000, 3)
                return response

    def close(self):
        try:
            self.send({"type": "close"})
            self.proc.wait(timeout=3)
        except Exception:
            pass
        if self.proc.poll() is None:
            self.proc.kill()
        subprocess.run(["docker", "rm", "-f", self.container_name],
                       capture_output=True, timeout=30, check=False)


ECHO_BOT = """
import json, sys
print(json.dumps({"ready": True}), flush=True)
for line in sys.stdin:
    message = json.loads(line)
    if message.get("type") == "end":
        break
    print(json.dumps({"move": "U", "echo": message.get("round")}), flush=True)
"""

SLEEPY_BOT_TEMPLATE = """
import json, sys, time
SLEEP = {sleep}
print(json.dumps({{"ready": True}}), flush=True)
for line in sys.stdin:
    message = json.loads(line)
    if message.get("type") == "end":
        break
    time.sleep(SLEEP)
    print(json.dumps({{"move": "U"}}), flush=True)
"""


def bench_startup(args):
    samples = []
    for i in range(args.samples):
        with tempfile.TemporaryDirectory(prefix="elo-bench-", dir=BENCH_BASE) as workspace:
            worker = DirectWorker(args.image, ECHO_BOT, workspace)
            try:
                worker.wait_ready(timeout=90)      # 运行器就绪
                worker.spawn_bot()                 # 启动被测进程
                worker.read_line(timeout_ms=10000, timeout=30.0)  # 读到 bot 首行
                samples.append(worker.startup_elapsed_ms())
            finally:
                worker.close()
        print(f"  启动样本 {i + 1}: {samples[-1]:.1f} ms")
    print(f"启动→就绪：{_summary_ms(samples)}")


def bench_ping(args):
    with tempfile.TemporaryDirectory(prefix="elo-bench-", dir=BENCH_BASE) as workspace:
        worker = DirectWorker(args.image, ECHO_BOT, workspace)
        try:
            worker.wait_ready(timeout=90)
            rtts = []
            for _ in range(args.samples):
                response = worker.request({"type": "ping"})
                if response.get("pong") is not True:
                    raise RuntimeError(f"ping 失败：{response}")
                rtts.append(response["_host_ms"])
            print(f"ping 往返（宿主↔容器运行器）：{_summary_ms(rtts)}")
        finally:
            worker.close()


def bench_turn(args):
    with tempfile.TemporaryDirectory(prefix="elo-bench-", dir=BENCH_BASE) as workspace:
        worker = DirectWorker(args.image, ECHO_BOT, workspace)
        try:
            worker.wait_ready(timeout=90)
            worker.spawn_bot()
            worker.read_line(timeout_ms=10000, timeout=30.0)  # bot ready 行
            host_rtts, inner = [], []
            for round_index in range(args.samples):
                response = worker.turn(
                    {"type": "turn", "round": round_index,
                     "legal_moves": [{"move": "U", "to": [0, 0]}]},
                    timeout_ms=1000)
                if not response.get("ok"):
                    raise RuntimeError(f"interact 失败：{response}")
                host_rtts.append(response["_host_ms"])
                inner.append(float(response.get("elapsed_ms") or 0.0))
            overhead = [host - bot for host, bot in zip(host_rtts, inner)]
            print(f"回合（echo bot，仲裁侧总往返）：{_summary_ms(host_rtts)}")
            print(f"回合（运行器内测得，≈思考耗时）：{_summary_ms(inner)}")
            print(f"纯通信开销 = 总往返 - 内部计时：{_summary_ms(overhead)}")
        finally:
            worker.close()


def bench_timing(args):
    cases = [
        ("0.95s 思考（应成功）", 0.95, True),
        ("1.05s 思考（应超时）", 1.05, False),
    ]
    for label, sleep_seconds, expect_ok in cases:
        bot_source = SLEEPY_BOT_TEMPLATE.format(sleep=sleep_seconds)
        with tempfile.TemporaryDirectory(prefix="elo-bench-", dir=BENCH_BASE) as workspace:
            worker = DirectWorker(args.image, bot_source, workspace)
            try:
                worker.wait_ready(timeout=90)
                worker.spawn_bot()
                worker.read_line(timeout_ms=10000, timeout=30.0)  # bot ready 行
                response = worker.turn({"round": 0}, timeout_ms=1000, timeout=10)
                ok = bool(response.get("ok"))
                elapsed = response.get("elapsed_ms")
                error = response.get("error")
                status = "符合预期" if ok == expect_ok else "!! 不符合预期"
                print(f"  {label}: ok={ok} elapsed_ms={elapsed} error={error} → {status}")
                if ok != expect_ok:
                    raise SystemExit(f"计时语义校验失败：{label}")
            finally:
                worker.close()
    print("计时语义：回合预算由运行器内部执行，通信开销未计入。")


JUDGE_BENCH_SCRIPT_TEMPLATE = """
import json, time
import elo_host_api

TURNS = {turns}

def start(side):
    spawn = elo_host_api.spawn(side, ["python3", "-u", "bot.py"], timeout_ms=15000)
    if not spawn.get("ok"):
        return spawn
    return elo_host_api.interact(side, timeout_ms=15000, until="newline")

status_a = start("A")
status_b = start("B")
host_rtts = []
inner = []
fault = None
for round_index in range(TURNS):
    started = time.monotonic()
    payload = json.dumps({{"type": "turn", "round": round_index}},
                         separators=(",", ":")) + "\\n"
    reply = elo_host_api.interact("A", data=payload, timeout_ms=1000,
                                  until="newline")
    host_ms = (time.monotonic() - started) * 1000
    if not reply.get("ok"):
        fault = reply
        break
    host_rtts.append(host_ms)
    inner.append(float(reply.get("elapsed_ms") or 0.0))
overhead = [h - i for h, i in zip(host_rtts, inner)]
stats = {{
    "status_a": status_a, "status_b": status_b,
    "turns": len(host_rtts), "fault": fault,
    "host_ms": host_rtts, "inner_ms": inner, "overhead_ms": overhead,
}}
print("__BENCH_STATS__" + json.dumps(stats, separators=(",", ":")))
print(json.dumps({{"winner": 0, "details": {{"format": "text", "content": "bench"}}}}))
"""


def bench_full(args):
    os.environ.setdefault("AGENT_JUDGE_WORKSPACE_ROOT", tempfile.mkdtemp(prefix="elo-bench-root-", dir=BENCH_BASE))
    from oj_modules.tasks.ranking.elo_runtime import arbiter
    # 镜像常量在模块导入时读取，这里直接覆盖，保证 --image 始终生效。
    arbiter.elo_container.AGENT_JUDGE_IMAGE = args.image

    with tempfile.TemporaryDirectory(prefix="elo-bench-full-", dir=BENCH_BASE) as staging:
        script_path = os.path.join(staging, "judge_script.py")
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(JUDGE_BENCH_SCRIPT_TEMPLATE.format(turns=args.samples))

        def make_zip(name):
            import zipfile
            path = os.path.join(staging, name)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bot.py", ECHO_BOT)
            return path

        started = time.monotonic()
        match = arbiter.IsolatedEloMatch(
            script_path, make_zip("a.zip"), make_zip("b.zip"),
            timeout_seconds=args.timeout,
        )
        winner, details = match.run()
        total_ms = round((time.monotonic() - started) * 1000, 1)

    print(f"完整对局：winner={winner} 总耗时={total_ms} ms（含容器启动/清理）")
    text = (details or {}).get("content", "") if isinstance(details, dict) else str(details)
    print(f"裁决详情：{text}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                        help=f"容器镜像（默认 {DEFAULT_IMAGE}）")
    parser.add_argument("--samples", type=int, default=100, help="样本数")
    parser.add_argument("--timeout", type=int, default=120, help="full 模式整场时限（秒）")
    parser.add_argument("mode", choices=["startup", "ping", "turn", "timing", "full", "all"])
    args = parser.parse_args()

    modes = ["startup", "ping", "turn", "timing", "full"] if args.mode == "all" else [args.mode]
    for mode in modes:
        print(f"[{mode}] image={args.image}")
        globals()[f"bench_{mode}"](args)
        print()


if __name__ == "__main__":
    main()
