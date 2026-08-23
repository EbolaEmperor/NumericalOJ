# -*- coding: utf-8 -*-
"""ELO 隔离对局运行时（elo_runtime）单测。

覆盖三层：
  - bot_runner：以真实子进程运行可信运行器 + 伪造 bot，验证握手、回合问答、
    容器内计时、超时强杀、协议违规处理、exec 与路径越界防护；
  - elo_host_api：以管道伪造仲裁通道，验证请求/响应帧协议与客户端超时；
  - arbiter（IsolatedEloMatch）：注入本地进程 spawner（不起 docker）验证
    容器命令隔离参数、RPC 路由、裁决解析、超时与清理语义。
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

from oj_modules.tasks.ranking import elo
from oj_modules.tasks.ranking import elo_container
from oj_modules.tasks.ranking.elo_runtime import arbiter, elo_host_api


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
# bot_runner：真实子进程集成
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
        """读取任意一个协议帧（含无 id 的 ready 帧）。"""
        return self._read_frame(timeout, expected_id=None)

    def request(self, frame, timeout=15.0):
        self._seq += 1
        frame = dict(frame)
        frame["id"] = self._seq
        self.proc.stdin.write((json.dumps(frame) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        return self._read_frame(timeout, expected_id=self._seq)

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


def _make_submission(tmp_path, bot_source):
    submission = tmp_path / "submission"
    submission.mkdir(exist_ok=True)
    (submission / "bot.py").write_text(bot_source, encoding="utf-8")
    return submission


ECHO_BOT = (
    "import json, sys\n"
    "print(json.dumps({'ready': True}), flush=True)\n"
    "for line in sys.stdin:\n"
    "    msg = json.loads(line)\n"
    "    if msg.get('type') == 'end': break\n"
    "    print(json.dumps({'move': 'U'}), flush=True)\n"
)


def test_bot_runner_reports_ready_frame(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, ECHO_BOT))
    try:
        ready = runner.read_any_frame()
        assert ready["type"] == "ready" and ready["ok"] is True
        assert ready["handshake_ms"] >= 0
    finally:
        runner.close()


def test_bot_runner_ask_round_trip_and_ping(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, ECHO_BOT))
    try:
        ready = runner.read_any_frame()
        assert ready["ok"] is True
        reply = runner.request({"type": "ask", "timeout_ms": 1000, "payload": {"round": 1}})
        assert reply["ok"] is True
        assert reply["response"] == {"move": "U"}
        assert reply["elapsed_ms"] >= 0
        pong = runner.request({"type": "ping"})
        assert pong["ok"] is True and pong["pong"] is True
    finally:
        runner.close()


def test_bot_runner_missing_bot_py_reports_startup_error(tmp_path):
    submission = tmp_path / "submission"
    submission.mkdir()
    runner = RunnerProcess(submission)
    try:
        ready = runner.read_any_frame()
        assert ready["type"] == "ready" and ready["ok"] is False
        assert "bot.py" in ready["error"]
        reply = runner.request({"type": "ask", "timeout_ms": 100, "payload": {}})
        assert reply["ok"] is False and reply["error"] == "bot_not_running"
    finally:
        runner.close()


def test_bot_runner_enforces_turn_timeout_inside_container(tmp_path):
    sleepy = (
        "import json, sys, time\n"
        "print(json.dumps({'ready': True}), flush=True)\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if msg.get('type') == 'end': break\n"
        "    time.sleep(0.5)\n"
        "    print(json.dumps({'move': 'U'}), flush=True)\n"
    )
    runner = RunnerProcess(_make_submission(tmp_path, sleepy))
    try:
        runner.proc.stdout.readline()  # ready 帧
        started = time.monotonic()
        reply = runner.request({"type": "ask", "timeout_ms": 150, "payload": {}}, timeout=10)
        assert reply["ok"] is False and reply["error"] == "timeout"
        # 超时应发生在 ~150ms，而不是等满 bot 的 0.5s
        assert time.monotonic() - started < 0.45
        # 超时后 bot 被强杀：后续 ask 直接失败
        reply2 = runner.request({"type": "ask", "timeout_ms": 100, "payload": {}})
        assert reply2["ok"] is False and reply2["error"] == "bot_not_running"
    finally:
        runner.close()


def test_bot_runner_rejects_non_json_bot_output(tmp_path):
    noisy = (
        "import json, sys\n"
        "print(json.dumps({'ready': True}), flush=True)\n"
        "for line in sys.stdin:\n"
        "    print('not-json', flush=True)\n"
    )
    runner = RunnerProcess(_make_submission(tmp_path, noisy))
    try:
        runner.proc.stdout.readline()  # ready 帧
        reply = runner.request({"type": "ask", "timeout_ms": 1000, "payload": {}})
        assert reply["ok"] is False and reply["error"] == "bad_output"
    finally:
        runner.close()


def test_bot_runner_exec_captures_output_and_exports_files(tmp_path):
    submission = _make_submission(tmp_path, ECHO_BOT)
    runner = RunnerProcess(submission)
    try:
        runner.proc.stdout.readline()  # ready 帧
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


def test_bot_runner_exec_timeout_reports_timed_out(tmp_path):
    runner = RunnerProcess(_make_submission(tmp_path, ECHO_BOT))
    try:
        runner.proc.stdout.readline()
        reply = runner.request({
            "type": "exec", "timeout_ms": 200,
            "argv": [sys.executable, "-c", "import time; time.sleep(2)"],
        }, timeout=10)
        assert reply["ok"] is True and reply["timed_out"] is True
    finally:
        runner.close()


def test_bot_runner_path_traversal_is_rejected():
    module = _load_bot_runner_module()
    with pytest.raises(ValueError):
        module._resolve_relative("/base", "../escape")
    with pytest.raises(ValueError):
        module._resolve_relative("/base", "a/../../escape")
    assert module._resolve_relative("/base", ".") == "/base"


# ---------------------------------------------------------------------------
# elo_host_api：帧协议与客户端超时
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


def test_host_api_call_bot_round_trip(monkeypatch):
    arbiter_reads, arbiter_writes = _install_fake_channel(monkeypatch)
    outcome = {}

    def fake_arbiter():
        line = b""
        while not line.endswith(b"\n"):
            line += os.read(arbiter_reads, 4096)
        request = json.loads(line.decode().removeprefix(elo_host_api.RPC_PREFIX))
        outcome["request"] = request
        response = {"id": request["id"], "ok": True,
                    "response": {"move": "D"}, "elapsed_ms": 3.5}
        os.write(arbiter_writes, (json.dumps(response) + "\n").encode())

    thread = threading.Thread(target=fake_arbiter, daemon=True)
    thread.start()
    reply = elo_host_api.call_bot("A", {"round": 7}, timeout_ms=1000)
    thread.join(timeout=5)
    assert reply["ok"] is True and reply["response"] == {"move": "D"}
    assert outcome["request"]["method"] == "call_bot"
    assert outcome["request"]["side"] == "A"
    assert outcome["request"]["payload"] == {"round": 7}


def test_host_api_times_out_when_arbiter_silent(monkeypatch):
    _install_fake_channel(monkeypatch)
    started = time.monotonic()
    reply = elo_host_api.call_bot("B", {}, timeout_ms=1)
    assert reply["ok"] is False and reply["error"] == "worker_unresponsive"
    assert time.monotonic() - started < 2.0


def test_host_api_rejects_bad_side(monkeypatch):
    _install_fake_channel(monkeypatch)
    reply = elo_host_api.call_bot("C", {}, timeout_ms=10)
    assert reply["ok"] is False and reply["error"] == "bad_request"


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


JUDGE_SCRIPT_TEMPLATE = """
import json
import elo_host_api

ready_a = elo_host_api.wait_ready("A", timeout_ms=10000)
ready_b = elo_host_api.wait_ready("B", timeout_ms=10000)
reply = elo_host_api.call_bot("A", {{"type": "turn", "round": 0}}, timeout_ms=1000)
{body}
print(json.dumps({{"winner": {winner}, "details": {{"format": "text",
      "content": json.dumps({{"ready_a": ready_a, "ready_b": ready_b,
                              "reply": reply}}, ensure_ascii=False)}}}}))
"""


def _run_isolated_match(tmp_path, judge_body, winner, timeout_seconds=60):
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text(
            JUDGE_SCRIPT_TEMPLATE.format(body=judge_body, winner=winner),
            encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_BOT})
        archive_b = _write_zip(staging / "b.zip", {"bot.py": ECHO_BOT})
        removed = []
        match = arbiter.IsolatedEloMatch(
            str(script), archive_a, archive_b, timeout_seconds,
            spawner=_local_spawner(), remover=removed.append,
        )
        result = match.run()
        return result, removed, match
    finally:
        elo_container.AGENT_JUDGE_WORKSPACE_ROOT = old_root


def test_arbiter_runs_full_match_and_cleans_up(tmp_path):
    (winner, details), removed, match = _run_isolated_match(
        tmp_path, "", 1)
    assert winner == 1
    payload = json.loads(details["content"])
    assert payload["ready_a"]["ready"] is True
    assert payload["ready_b"]["ready"] is True
    assert payload["reply"]["ok"] is True
    assert payload["reply"]["response"] == {"move": "U"}
    assert len(removed) == 3  # 两个工作容器 + 裁判容器


def test_arbiter_startup_fault_reported_to_judge(tmp_path):
    # B 方作品缺少 bot.py：wait_ready 应报 ready=False
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text(
            "import json\nimport elo_host_api\n"
            "status = elo_host_api.wait_ready('B', timeout_ms=10000)\n"
            "print(json.dumps({'winner': 1, 'details': {'format': 'text',\n"
            "      'content': json.dumps(status, ensure_ascii=False)}}))\n",
            encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_BOT})
        archive_b = _write_zip(staging / "b.zip", {"readme.txt": "no bot"})
        removed = []
        match = arbiter.IsolatedEloMatch(
            str(script), archive_a, archive_b, 60,
            spawner=_local_spawner(), remover=removed.append,
        )
        winner, details = match.run()
        assert winner == 1
        status = json.loads(details["content"])
        assert status["ok"] is True and status["ready"] is False
        assert "bot.py" in status["error"]
    finally:
        elo_container.AGENT_JUDGE_WORKSPACE_ROOT = old_root


def test_arbiter_judge_failure_becomes_runtime_error(tmp_path):
    monkey_dir = tmp_path / "wsroot"
    monkey_dir.mkdir()
    old_root = elo_container.AGENT_JUDGE_WORKSPACE_ROOT
    elo_container.AGENT_JUDGE_WORKSPACE_ROOT = str(monkey_dir)
    try:
        staging = tmp_path / "staging"
        staging.mkdir()
        script = staging / "judge_script.py"
        script.write_text("import sys\nsys.stderr.write('boom')\nsys.exit(3)\n",
                          encoding="utf-8")
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_BOT})
        archive_b = _write_zip(staging / "b.zip", {"bot.py": ECHO_BOT})
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
        archive_a = _write_zip(staging / "a.zip", {"bot.py": ECHO_BOT})
        archive_b = _write_zip(staging / "b.zip", {"bot.py": ECHO_BOT})
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
        "oj_modules.tasks.ranking.elo_runtime.run_isolated_elo_match", fake_isolated)
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
        "oj_modules.tasks.ranking.elo_runtime.run_isolated_elo_match",
        _should_not_be_called)
    winner, _details = elo._run_scoring_script(
        "script.py", "a.zip", "b.zip", timeout_seconds=10, runtime_mode="legacy")
    assert winner == 0
