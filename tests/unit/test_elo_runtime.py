# -*- coding: utf-8 -*-
"""ELO 隔离对局运行时（elo_runtime）单测。

隔离运行时把"如何启动被测代码、用什么协议交互"的决定权交还给评分脚本：
工作容器内的可信运行器只提供通用原语（spawn/interact/kill/status/exec/fetch）。
覆盖三层：

  - bot_runner：以真实子进程运行可信运行器，验证 spawn/interact/kill/status、
    容器内计时、超时强杀、until 条件、exec、fetch 与路径越界防护；
  - elo_host_api：以管道伪造仲裁通道，验证原语帧协议与客户端超时；
  - arbiter（IsolatedEloMatch）：注入本地进程 spawner（不起 docker）验证
    容器命令隔离参数、新 RPC 路由、裁决解析、超时与清理语义。
"""

import base64
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
import zipfile

import pytest

from backend.oj_modules.tasks.ranking import elo
from backend.oj_modules.tasks.ranking import elo_container
from backend.oj_modules.tasks.ranking.elo_runtime import arbiter, elo_host_api


RUNNER_PATH = arbiter.RUNNER_HOST_PATH


def _load_bot_runner_module():
    spec = importlib.util.spec_from_file_location("bot_runner_under_test", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_zip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return str(path)


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _unb64(value):
    return base64.b64decode(value).decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# 容器命令构造：隔离参数
# ---------------------------------------------------------------------------

def test_worker_command_disables_network_and_only_mounts_own_submission():
    command = arbiter.worker_command("c1", "/data/submission_a")
    assert command[command.index("--network") + 1] == arbiter.WORKER_NETWORK
    assert arbiter.WORKER_NETWORK == "none"
    mounts = [command[i + 1] for i, item in enumerate(command) if item == "-v"]
    assert any(m.endswith(":/submission") and "submission_a" in m for m in mounts)
    assert any(m.endswith(":/opt/numoj/elo/bot_runner.py:ro") for m in mounts)
    assert command[-4:] == ["python3", "-I", "-u", "/opt/numoj/elo/bot_runner.py"]
    assert "--cap-add" not in command and "--privileged" not in command


def test_judge_command_keeps_network_and_mounts_only_script_dir():
    command = arbiter.judge_command("c2", "/data/judge")
    assert command[command.index("--network") + 1] == arbiter.JUDGE_NETWORK
    assert arbiter.JUDGE_NETWORK == "bridge"
    mounts = [command[i + 1] for i, item in enumerate(command) if item == "-v"]
    assert len(mounts) == 1
    assert mounts[0].endswith("judge:/judge")
    assert "submission" not in mounts[0]


# ---------------------------------------------------------------------------
# bot_runner：真实子进程集成（通用原语）
# ---------------------------------------------------------------------------

class RunnerProcess:
    def __init__(self, submission_dir):
        env = dict(os.environ, NUMOJ_ELO_SUBMISSION_DIR=str(submission_dir))
        self.proc = subprocess.Popen(
            [sys.executable, "-u", RUNNER_PATH],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, bufsize=0,
        )
        self._buffer = b""
        self._seq = 0

    def read_any_frame(self, timeout=15.0):
        return self._read_frame(timeout, expected_id=None)

    def request(self, frame, timeout=15.0):
        self._seq += 1
        frame = dict(frame)
        frame["id"] = self._seq
        self.proc.stdin.write((json.dumps(frame) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        return self._read_frame(timeout, expected_id=self._seq)

    def spawn(self, argv, timeout=15.0):
        return self.request({"type": "spawn", "argv": argv}, timeout=timeout)

    def interact(self, input_text=None, timeout_ms=1000, until="newline", timeout=15.0):
        frame = {"type": "interact", "timeout_ms": timeout_ms, "until": until}
        if input_text is not None:
            frame["input"] = _b64(input_text)
        return self.request(frame, timeout=timeout)

    def _read_frame(self, timeout, expected_id):
        import select as _select
        deadline = time.monotonic() + timeout
        fd = self.proc.stdout.fileno()
        while True:
            if b"\n" in self._buffer:
                raw, self._buffer = self._buffer.split(b"\n", 1)
                if raw.strip():
                    response = json.loads(raw.decode("utf-8"))
                    if expected_id is None or response.get("id") == expected_id:
                        return response
                    continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("等待运行器响应超时")
            readable, _, _ = _select.select([fd], [], [], remaining)
            if not readable:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise EOFError(f"运行器退出：{self.proc.stderr.read(500)!r}")
            self._buffer += chunk

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def _make_submission(tmp_path, files):
    submission = tmp_path / "submission"
    submission.mkdir(exist_ok=True)
    for name, content in files.items():
        (submission / name).write_text(content, encoding="utf-8")
    return submission


ECHO_LINE_BOT = (
    "import sys\n"
    "print('HELLO', flush=True)\n"
    "for line in sys.stdin:\n"
    "    if line.strip() == 'END': break\n"
    "    print('echo:' + line.strip(), flush=True)\n"
)


def test_runner_ready_frame_has_no_bot_handshake(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        ready = runner.read_any_frame()
        assert ready["type"] == "ready" and ready["ok"] is True
        assert "handshake_ms" not in ready  # 运行器就绪不含任何 bot 握手
    finally:
        runner.close()


def test_runner_interact_without_spawn_reports_not_running(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        reply = runner.interact(input_text="x\n", timeout_ms=50)
        assert reply["ok"] is False and reply["error"] == "bot_not_running"
    finally:
        runner.close()


def test_runner_spawn_interact_round_trip_and_ping(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"my_bot.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        sp = runner.spawn([sys.executable, "-u", "my_bot.py"])
        assert sp["ok"] is True and sp["pid"] > 0
        first = runner.interact(timeout_ms=2000)
        assert first["ok"] is True and _unb64(first["output"]) == "HELLO"
        turn = runner.interact(input_text="ping-1\n", timeout_ms=1000)
        assert turn["ok"] is True and _unb64(turn["output"]) == "echo:ping-1"
        assert turn["elapsed_ms"] >= 0
        pong = runner.request({"type": "ping"})
        assert pong["ok"] is True and pong["pong"] is True
    finally:
        runner.close()


def test_runner_spawn_replaces_running_process(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "main.py"])
        first_pid = runner.request({"type": "status"})
        again = runner.spawn([sys.executable, "-u", "main.py"])
        assert again["ok"] is True
        runner.interact(timeout_ms=2000)  # 新进程的 HELLO 行
        assert runner.request({"type": "status"})["alive"] is True
        assert first_pid["alive"] is True
    finally:
        runner.close()


def test_runner_spawn_bad_entry_reports_exec_failed(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        reply = runner.spawn(["/nonexistent/binary"])
        assert reply["ok"] is False and reply["error"] == "exec_failed"
    finally:
        runner.close()


def test_runner_enforces_interact_timeout_inside_container(tmp_path):
    sleepy = (
        "import sys, time\n"
        "print('R', flush=True)\n"
        "for line in sys.stdin:\n"
        "    time.sleep(0.5)\n"
        "    print('done', flush=True)\n"
    )
    runner = RunnerProcess(_make_submission(tmp_path, {"slow.py": sleepy}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "slow.py"])
        runner.interact(timeout_ms=2000)  # R 行
        started = time.monotonic()
        reply = runner.interact(input_text="go\n", timeout_ms=150, timeout=10)
        assert reply["ok"] is False and reply["error"] == "timeout"
        # 超时应发生在 ~150ms，而不是等满被测进程的 0.5s。
        assert time.monotonic() - started < 0.45
        # 超时后被测进程被强杀：后续交互直接失败。
        reply2 = runner.interact(input_text="x\n", timeout_ms=100)
        assert reply2["ok"] is False and reply2["error"] == "bot_not_running"
    finally:
        runner.close()


def test_runner_interact_until_eof_returns_exit_code(tmp_path):
    eof_bot = "import sys\nprint('A')\nprint('B')\nsys.exit(3)\n"
    runner = RunnerProcess(_make_submission(tmp_path, {"eof.py": eof_bot}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "eof.py"])
        reply = runner.interact(timeout_ms=3000, until="eof", timeout=10)
        assert reply["ok"] is True
        assert _unb64(reply["output"]) == "A\nB\n"
        assert reply["exit_code"] == 3
    finally:
        runner.close()


def test_runner_interact_until_bytes(tmp_path):
    blob_bot = (
        "import sys, time\n"
        "sys.stdout.write('0123456789')\n"
        "sys.stdout.flush()\n"
        "time.sleep(5)\n"
    )
    runner = RunnerProcess(_make_submission(tmp_path, {"b.py": blob_bot}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "b.py"])
        reply = runner.interact(timeout_ms=3000, until={"bytes": 4}, timeout=10)
        assert reply["ok"] is True and _unb64(reply["output"]) == "0123"
    finally:
        runner.close()


def test_runner_oversize_line_kills_process(tmp_path):
    noisy = "import sys\nsys.stdout.write('x' * 70000)\nsys.stdout.flush()\nimport time\ntime.sleep(5)\n"
    runner = RunnerProcess(_make_submission(tmp_path, {"noisy.py": noisy}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "noisy.py"])
        reply = runner.interact(timeout_ms=2000, timeout=10)  # newline 模式，单行上限 16KiB
        assert reply["ok"] is False and reply["error"] == "oversize"
        status = runner.request({"type": "status"})
        assert status["alive"] is False
    finally:
        runner.close()


def test_runner_kill_and_status(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        runner.spawn([sys.executable, "-u", "main.py"])
        status = runner.request({"type": "status"})
        assert status["ok"] is True and status["alive"] is True
        kill = runner.request({"type": "kill"})
        assert kill["ok"] is True and kill["was_running"] is True
        after = runner.request({"type": "status"})
        assert after["alive"] is False and "exit_code" in after
    finally:
        runner.close()


def test_runner_fetch_files_and_skip_missing(tmp_path):
    runner = RunnerProcess(_make_submission(
        tmp_path, {"main.py": ECHO_LINE_BOT, "data.txt": "payload"}))
    try:
        runner.read_any_frame()
        reply = runner.request({"type": "fetch", "paths": ["data.txt", "nope.txt"]})
        assert reply["ok"] is True
        assert _unb64(reply["files"]["data.txt"]) == "payload"
        assert "nope.txt" not in reply["files"]
    finally:
        runner.close()


def test_runner_exec_captures_output_and_exports_files(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        reply = runner.request({
            "type": "exec",
            "timeout_ms": 10000,
            "argv": [sys.executable, "-c",
                     "open('artifact.txt', 'w').write('hello-elo')"],
            "export_files": ["artifact.txt"],
        })
        assert reply["ok"] is True and reply["exit_code"] == 0
        assert base64.b64decode(reply["files"]["artifact.txt"]).decode() == "hello-elo"
    finally:
        runner.close()


def test_runner_exec_timeout_reports_timed_out(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        reply = runner.request({
            "type": "exec", "timeout_ms": 200,
            "argv": [sys.executable, "-c", "import time; time.sleep(2)"],
        }, timeout=10)
        assert reply["ok"] is True and reply["timed_out"] is True
    finally:
        runner.close()


def test_runner_rejects_workdir_traversal(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, {"main.py": ECHO_LINE_BOT}))
    try:
        runner.read_any_frame()
        bad = runner.request({"type": "exec", "timeout_ms": 100,
                              "argv": ["true"], "workdir": "../escape"})
        assert bad["ok"] is False and bad["error"] == "bad_request"
        bad_spawn = runner.request({"type": "spawn", "argv": ["true"],
                                    "workdir": "../escape"})
        assert bad_spawn["ok"] is False and bad_spawn["error"] == "bad_request"
    finally:
        runner.close()


def test_runner_path_traversal_is_rejected():
    module = _load_bot_runner_module()
    with pytest.raises(ValueError):
        module._resolve_relative("/base", "../escape")
    with pytest.raises(ValueError):
        module._resolve_relative("/base", "a/../../escape")
    assert module._resolve_relative("/base", ".") == "/base"


# ---------------------------------------------------------------------------
# elo_host_api：原语帧协议与客户端超时
# ---------------------------------------------------------------------------

def _install_fake_channel(monkeypatch):
    """用管道伪造仲裁通道，返回 (arbiter_reads_fd, arbiter_writes_fd)。"""
    judge_stdin_r, judge_stdin_w = os.pipe()
    judge_stderr_r, judge_stderr_w = os.pipe()
    monkeypatch.setattr(elo_host_api, "_stdin_fd", judge_stdin_r)
    monkeypatch.setattr(elo_host_api, "_stdout_fd_for_rpc", judge_stderr_w)
    monkeypatch.setattr(elo_host_api, "_buffer", b"")
    monkeypatch.setattr(elo_host_api, "DEFAULT_CALL_GRACE_SECONDS", 0.3)
    return judge_stderr_r, judge_stdin_w


def _start_scripted_arbiter(arbiter_reads, arbiter_writes, handler):
    stop = {"flag": False}

    def loop():
        buffer = b""
        while not stop["flag"]:
            try:
                chunk = os.read(arbiter_reads, 4096)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                if not raw.strip():
                    continue
                request = json.loads(raw.decode().removeprefix(elo_host_api.RPC_PREFIX))
                response = dict(handler(request))
                response["id"] = request["id"]
                os.write(arbiter_writes, (json.dumps(response) + "\n").encode())

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return thread, stop


def test_host_api_interact_round_trip(monkeypatch):
    arbiter_reads, arbiter_writes = _install_fake_channel(monkeypatch)
    seen = {}

    def handler(request):
        seen["request"] = request
        return {"ok": True, "output": _b64("hello-back"), "elapsed_ms": 2.5}

    thread, stop = _start_scripted_arbiter(arbiter_reads, arbiter_writes, handler)
    reply = elo_host_api.interact("A", data="hi\n", timeout_ms=1000)
    stop["flag"] = True
    assert reply["ok"] is True and reply["output"] == "hello-back"
    assert reply["elapsed_ms"] == 2.5
    assert seen["request"]["method"] == "interact"
    assert seen["request"]["side"] == "A"
    assert base64.b64decode(seen["request"]["input"]).decode() == "hi\n"


def test_host_api_spawn_kill_status_primitives(monkeypatch):
    arbiter_reads, arbiter_writes = _install_fake_channel(monkeypatch)

    def handler(request):
        method = request["method"]
        if method == "spawn":
            return {"ok": True, "pid": 42}
        if method == "kill":
            return {"ok": True, "was_running": True}
        if method == "proc_status":
            return {"ok": True, "alive": False, "exit_code": 0}
        return {"ok": False, "error": "bad_request"}

    thread, stop = _start_scripted_arbiter(arbiter_reads, arbiter_writes, handler)
    assert elo_host_api.spawn("A", ["./main"])["pid"] == 42
    assert elo_host_api.kill("A")["was_running"] is True
    assert elo_host_api.proc_status("A")["alive"] is False
    stop["flag"] = True


def test_host_api_times_out_when_arbiter_silent(monkeypatch):
    _install_fake_channel(monkeypatch)
    started = time.monotonic()
    reply = elo_host_api.interact("B", data="x", timeout_ms=1)
    assert reply["ok"] is False and reply["error"] == "worker_unresponsive"
    assert time.monotonic() - started < 2.0


def test_host_api_rejects_bad_side(monkeypatch):
    _install_fake_channel(monkeypatch)
    assert elo_host_api.interact("C", data="x")["error"] == "bad_request"
    assert elo_host_api.spawn("C", ["true"])["error"] == "bad_request"


# ---------------------------------------------------------------------------
# 仲裁者：本地进程注入（不依赖 docker）
# ---------------------------------------------------------------------------

def _local_spawner():
    def spawner(role, command):
        mounts = [command[i + 1] for i, item in enumerate(command) if item == "-v"]
        if role == "judge":
            judge_dir = mounts[0].split(":", 1)[0]
            return subprocess.Popen(
                [sys.executable, "-u", os.path.join(judge_dir, "scoring_script.py")],
                cwd=judge_dir,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0,
            )
        submission_dir = mounts[0].split(":", 1)[0]
        env = dict(os.environ, NUMOJ_ELO_SUBMISSION_DIR=submission_dir)
        return subprocess.Popen(
            [sys.executable, "-u", RUNNER_PATH],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0, env=env,
        )
    return spawner


ECHO_JSON_BOT = (
    "import json, sys\n"
    "print(json.dumps({'ready': True}), flush=True)\n"
    "for line in sys.stdin:\n"
    "    msg = json.loads(line)\n"
    "    if msg.get('type') == 'end': break\n"
    "    print(json.dumps({'move': 'U'}), flush=True)\n"
)


def _run_isolated_match(tmp_path, judge_source, timeout_seconds=60,
                        a_files=None, b_files=None):
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text(judge_source, encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", a_files or {"bot.py": ECHO_JSON_BOT})
        archive_b = _write_zip(staging / "b.zip", b_files or {"bot.py": ECHO_JSON_BOT})
        removed = []
        match = arbiter.IsolatedEloMatch(
            str(script), archive_a, archive_b, timeout_seconds,
            spawner=_local_spawner(), remover=removed.append,
        )
        result = match.run()
        return result, removed, match
    finally:
        elo_container.AGENT_JUDGE_WORKSPACE_ROOT = old_root


BOT_PROTOCOL_JUDGE_SCRIPT = """
import json
import elo_host_api

# 用原语显式驱动"ready 握手 + 换行 JSON 回合"协议（入口/协议均由脚本自定）。
def run_side(side):
    check = elo_host_api.fetch_files(side, ["bot.py"], timeout_ms=10000)
    spawn = elo_host_api.spawn(side, ["python3", "-u", "bot.py"], timeout_ms=10000)
    ready = elo_host_api.interact(side, timeout_ms=10000, until="newline")
    turn = elo_host_api.interact(
        side, data='{"type": "turn", "round": 0}\\n', timeout_ms=1000,
        until="newline")
    elo_host_api.kill(side)
    return check, spawn, ready, turn

check_a, spawn_a, ready_a, turn_a = run_side("A")
check_b, spawn_b, ready_b, turn_b = run_side("B")
print(json.dumps({"winner": 1, "details": {"format": "text",
      "content": json.dumps({"ready_a": ready_a, "ready_b": ready_b,
                              "turn_a": turn_a, "turn_b": turn_b},
                             ensure_ascii=False)}}))
"""


def test_arbiter_runs_full_match_with_primitives(tmp_path):
    (winner, details), removed, _ = _run_isolated_match(
        tmp_path, BOT_PROTOCOL_JUDGE_SCRIPT)
    assert winner == 1
    payload = json.loads(details["content"])
    assert payload["ready_a"]["ok"] is True
    assert payload["ready_b"]["ok"] is True
    assert json.loads(payload["ready_a"]["output"]) == {"ready": True}
    assert json.loads(payload["ready_b"]["output"]) == {"ready": True}
    assert json.loads(payload["turn_a"]["output"]) == {"move": "U"}
    assert json.loads(payload["turn_b"]["output"]) == {"move": "U"}
    assert len(removed) == 3  # 两个工作容器 + 裁判容器


PRIMITIVE_JUDGE_SCRIPT = """
import json
import elo_host_api

# 完全自由的用法：入口文件/语言/协议均由评分脚本决定，不依赖 bot.py 约定。
# 这里故意用 sh 解释器跑一个 shell 脚本，验证非 Python 入口同样可行。
spawn_a = elo_host_api.spawn("A", ["sh", "player.sh"])
first = elo_host_api.interact("A", timeout_ms=5000, until="newline")
turn = elo_host_api.interact("A", data="go\\n", timeout_ms=5000, until="newline")
files = elo_host_api.fetch_files("A", ["note.txt"])
elo_host_api.kill("A")
print(json.dumps({"winner": 2, "details": {"format": "text",
      "content": json.dumps({"spawn_a": spawn_a, "first": first,
                              "turn": turn,
                              "note": files.get("files", {}).get("note.txt")},
                             ensure_ascii=False)}}))
"""

PLAYER_SH = (
    "#!/bin/sh\n"
    "echo SHELL-READY\n"
    "read line\n"
    "echo got:$line\n"
)


def test_arbiter_runs_free_form_primitives_non_python_entry(tmp_path):
    (winner, details), removed, _ = _run_isolated_match(
        tmp_path, PRIMITIVE_JUDGE_SCRIPT,
        a_files={"player.sh": PLAYER_SH, "note.txt": "hello-note"},
    )
    assert winner == 2
    payload = json.loads(details["content"])
    assert payload["spawn_a"]["ok"] is True
    assert payload["first"]["output"].strip() == "SHELL-READY"
    assert payload["turn"]["output"].strip() == "got:go"
    assert base64.b64decode(payload["note"]).decode() == "hello-note"
    assert len(removed) == 3


def test_arbiter_startup_fault_reported_to_judge(tmp_path):
    # B 方入口不存在：原语层 spawn 应报 exec_failed，评分脚本据此裁决。
    judge = (
        "import json\nimport elo_host_api\n"
        "status = elo_host_api.spawn('B', ['./no_such_entry'], timeout_ms=10000)\n"
        "print(json.dumps({'winner': 1, 'details': {'format': 'text',\n"
        "      'content': json.dumps(status, ensure_ascii=False)}}))\n"
    )
    (winner, details), removed, _ = _run_isolated_match(
        tmp_path, judge, b_files={"readme.txt": "no bot"})
    assert winner == 1
    status = json.loads(details["content"])
    assert status["ok"] is False and status["error"] == "exec_failed"


def test_arbiter_judge_failure_becomes_runtime_error(tmp_path):
    judge = "import sys\nsys.stderr.write('boom')\nsys.exit(3)\n"
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text(judge, encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_JSON_BOT})
        archive_b = _write_zip(staging / "b.zip", {"bot.py": ECHO_JSON_BOT})
        removed = []
        match = arbiter.IsolatedEloMatch(
            str(script), archive_a, archive_b, 60,
            spawner=_local_spawner(), remover=removed.append,
        )
        with pytest.raises(arbiter.EloRuntimeError) as excinfo:
            match.run()
        assert "退出码 3" in str(excinfo.value)
        assert len(removed) == 3
    finally:
        elo_container.AGENT_JUDGE_WORKSPACE_ROOT = old_root


def test_arbiter_global_timeout(tmp_path):
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_JSON_BOT})
        archive_b = _write_zip(staging / "b.zip", {"bot.py": ECHO_JSON_BOT})
        removed = []
        match = arbiter.IsolatedEloMatch(
            str(script), archive_a, archive_b, 2,
            spawner=_local_spawner(), remover=removed.append,
        )
        with pytest.raises(arbiter.EloRuntimeError) as excinfo:
            match.run()
        assert "超时" in str(excinfo.value)
        assert len(removed) == 3
    finally:
        elo_container.AGENT_JUDGE_WORKSPACE_ROOT = old_root


# ---------------------------------------------------------------------------
# elo._run_scoring_script 的运行时分流
# ---------------------------------------------------------------------------

def test_run_scoring_script_routes_isolated_mode(tmp_path, monkeypatch):
    called = {}

    def fake_isolated(script_path, path_a, path_b, timeout_seconds):
        called["args"] = (script_path, path_a, path_b, timeout_seconds)
        return 2, {"format": "text", "content": "isolated"}

    monkeypatch.setattr(
        "backend.oj_modules.tasks.ranking.elo_runtime.run_isolated_elo_match", fake_isolated)
    winner, details = elo._run_scoring_script(
        "script.py", "a.zip", "b.zip", timeout_seconds=33, runtime_mode="isolated")
    assert winner == 2
    assert called["args"] == ("script.py", "a.zip", "b.zip", 33)


def test_run_scoring_script_legacy_mode_keeps_single_container(tmp_path, monkeypatch):
    payload = json.dumps({"winner": 0})
    monkeypatch.setattr(
        elo,
        "run_elo_scoring_container",
        lambda *_a, **_k: subprocess.CompletedProcess(
            args=["docker", "run"], returncode=0, stdout=payload + "\n", stderr=""),
    )

    def _should_not_be_called(*_args, **_kwargs):
        raise AssertionError("legacy 模式不应走隔离运行时")

    monkeypatch.setattr(
        "backend.oj_modules.tasks.ranking.elo_runtime.run_isolated_elo_match",
        _should_not_be_called)
    winner, _details = elo._run_scoring_script(
        "script.py", "a.zip", "b.zip", timeout_seconds=10, runtime_mode="legacy")
    assert winner == 0
