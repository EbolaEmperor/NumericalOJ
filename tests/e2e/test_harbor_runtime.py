"""官方 Harbor Trial、真实 Pi CLI 和本地模型协议替身的容器集成验证。"""

from __future__ import annotations

import json
import gzip
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from backend.oj_modules import config
from backend.oj_modules.agents import workspace
from backend.oj_modules.integrations import harbor_runtime
from tests.environment_guard import DestructiveTestTarget, assert_disposable_test_target

ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.e2e, pytest.mark.timeout(180)]
_MODEL = "numoj-harbor-test"
_KEY = "harbor-local-endpoint-key"


def _image(name, fallback):
    image = os.environ.get(name) or os.environ.get("AGENT_JUDGE_DOCKER_IMAGE") or fallback
    result = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=15)
    if result.returncode:
        pytest.skip(f"需要预先构建 Harbor 测试镜像：{image}")
    return image


@pytest.fixture
def harbor_case(monkeypatch):
    assert_disposable_test_target(DestructiveTestTarget(
        test_env=os.environ.get("NUMOJ_TEST_ENV"),
        hostname=socket.gethostname(),
        checkout_path=str(ROOT.resolve()),
        mysql_host=config.MYSQL_HOST,
        mysql_db=config.MYSQL_DB,
        redis_host=config.REDIS_HOST,
        redis_db=config.REDIS_DB,
    ))
    from tests.e2e.test_reverse_judge_live_ui import _assert_local_test_docker_daemon

    _assert_local_test_docker_daemon()
    # Colima 的挂载需位于共享的仓库路径；每个测试使用独立任务和运行目录。
    temporary_root = ROOT / "tmp"
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="harbor-e2e-", dir=temporary_root) as directory:
        root = Path(directory)
        monkeypatch.setattr(harbor_runtime.config, "REVERSE_JUDGE_WORKSPACE_ROOT", str(root))
        monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", root / "workspaces")
        yield root


def _task(root, image, *, verifier="echo 1 > /logs/verifier/reward.txt"):
    task = root / "task"
    (task / "tests").mkdir(parents=True)
    (task / "solution").mkdir()
    (task / "instruction.md").write_text("Write HARBOR_TOOL_OK to /app/answer.txt, then finish.")
    (task / "task.toml").write_text(
        f'artifacts = ["/app"]\n[environment]\ndocker_image = {json.dumps(image)}\nworkdir = "/app"\n'
    )
    (task / "solution/solve.sh").write_text("#!/bin/bash\nmkdir -p /app\nprintf HARBOR_TOOL_OK > /app/answer.txt\n")
    (task / "tests/test.sh").write_text("#!/bin/bash\nset -eu\n" + verifier + "\n")
    return task


def _assert_stopped(trial_dir):
    assert harbor_runtime.harbor_trial_running({
        "task_path": str(trial_dir.parent / "task"), "trial_dir": str(trial_dir),
    }) is False


def test_official_harbor_oracle_runs_solution_and_verifier(harbor_case):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    task = _task(root, image, verifier=(
        'if [ "$(cat /app/answer.txt)" = HARBOR_TOOL_OK ]; then\n'
        '  echo 1 > /logs/verifier/reward.txt\nelse\n  echo 0 > /logs/verifier/reward.txt\nfi'
    ))
    trial_dir = root / "oracle"
    result = harbor_runtime.run_harbor_oracle(task, trial_dir, 30)
    assert result["ok"], result
    assert result["result"]["score"] == result["result"]["max_score"] == 1
    assert harbor_runtime.load_harbor_result(trial_dir)["result"]["score"] == 1
    _assert_stopped(trial_dir)


def test_oracle_failure_cannot_be_hidden_by_a_full_reward(harbor_case):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    task = _task(root, image)
    (task / "solution/solve.sh").write_text("#!/bin/bash\nexit 7\n")
    trial_dir = root / "oracle"
    result = harbor_runtime.run_harbor_oracle(task, trial_dir, 30)
    assert result["ok"] is False, result
    assert result["error"]
    _assert_stopped(trial_dir)


def test_official_in_place_oracle_accepts_empty_artifacts(harbor_case):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    task = _task(root, image, verifier=(
        '[ "$(cat /app/answer.txt)" = HARBOR_TOOL_OK ]\n'
        'echo 1 > /logs/verifier/reward.txt'
    ))
    (task / 'task.toml').write_text(
        f'artifacts = []\n[environment]\ndocker_image = {json.dumps(image)}\nworkdir = "/app"\n'
    )
    trial_dir = root / 'oracle'
    result = harbor_runtime.run_harbor_oracle(task, trial_dir, 30)
    assert result['ok'], result
    assert result['result']['score'] == 1
    assert not (Path(result['artifacts_dir']) / 'app').exists()
    _assert_stopped(trial_dir)


def test_shared_verifier_keeps_platform_container_constraints(harbor_case):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    task = _task(root, image, verifier=(
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "assert Path('/app/answer.txt').read_text() == 'HARBOR_TOOL_OK'\n"
        "status = Path('/proc/self/status').read_text().splitlines()\n"
        "assert any(line.startswith('NoNewPrivs:') and line.split()[1] == '1' for line in status)\n"
        "assert Path('/sys/fs/cgroup/memory.max').read_text().strip() == str(128 * 1024 * 1024)\n"
        "Path('/logs/verifier/reward.txt').write_text('1')\n"
        "PY"
    ))
    with (task / "task.toml").open("a") as stream:
        stream.write('memory_mb = 128\ncpus = 0.5\n')
    trial_dir = root / "oracle"
    result = harbor_runtime.run_harbor_oracle(task, trial_dir, 30)
    assert result["ok"], result
    assert result["result"]["score"] == 1
    official = json.loads((trial_dir / (trial_dir / '.run-name').read_text() / 'result.json').read_text())
    assert official['verifier_environment_mode'] == 'shared'
    _assert_stopped(trial_dir)


def test_custom_dockerfile_streams_build_logs_and_reuses_official_image(harbor_case):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    task = _task(root, image)
    (task / "environment").mkdir()
    (task / "environment/Dockerfile").write_text(
        f"FROM {image}\nWORKDIR /app\nRUN printf HARBOR_BUILD_OK_{root.name} > /app/build.txt\n"
    )
    (task / "task.toml").write_text('artifacts = ["/app"]\n[environment]\nworkdir = "/app"\n')
    first, second = [], []
    result = harbor_runtime.run_harbor_oracle(task, root / "first", 30, build_event_callback=first.append)
    assert result["ok"], result
    assert [event["event"] for event in first][0] == "start"
    assert first[-1]["event"] == "complete"
    assert any("HARBOR_BUILD_OK" in event.get("text", "") for event in first if event["event"] == "output")
    result = harbor_runtime.run_harbor_oracle(task, root / "second", 30, build_event_callback=second.append)
    assert result["ok"], result
    assert second[0]["cached"] is True
    assert not any("HARBOR_BUILD_OK" in event.get("text", "") for event in second if event["event"] == "output")
    copied = root / "another-submission"
    shutil.copytree(task, copied)
    third = []
    result = harbor_runtime.run_harbor_oracle(copied, root / "third", 30, build_event_callback=third.append)
    assert result["ok"], result
    assert third[0]["cached"] is True


def test_default_dockerfile_uses_prebuilt_common_environment_without_build(harbor_case):
    from backend.oj_modules.ranking.reverse_judge.template import DEFAULT_HARBOR_DOCKERFILE
    root = harbor_case
    image = _image("NUMOJ_HARBOR_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    subprocess.run(["docker", "tag", image, "numericaloj-harbor-base:1"], check=True, capture_output=True)
    task = _task(root, image)
    (task / "environment").mkdir()
    (task / "environment/Dockerfile").write_text(DEFAULT_HARBOR_DOCKERFILE)
    (task / "task.toml").write_text('artifacts = ["/app"]\n')
    (task / "solution/solve.sh").write_text('#!/bin/bash\nset -eu\n[ "$PWD" = /app ]\nprintf 42 > answer.txt\n')
    events = []
    result = harbor_runtime.run_harbor_oracle(task, root / "oracle", 30, build_event_callback=events.append)
    assert result["ok"], result
    assert events[0]["event"] == "start" and events[0]["cached"] is True
    assert events[-1]["event"] == "complete"
    assert not any(event["event"] == "output" for event in events)


class _ModelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = []
    slow_initial = False
    final_response_sent = False

    def log_message(self, *_args):
        return

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != f"Bearer {_KEY}":
            self.send_error(401)
            return
        type(self).requests.append(body)
        request_number = len(type(self).requests)
        if request_number == 1:
            command = "mkdir -p /app; printf HARBOR_TOOL_OK > /app/answer.txt"
            delta = {"role": "assistant", "tool_calls": [{
                "index": 0, "id": f"harbor-write-{request_number}", "type": "function",
                "function": {"name": "bash", "arguments": json.dumps({
                    "command": command,
                })},
            }]}
            reason = "tool_calls"
        else:
            time.sleep(20 if type(self).slow_initial else 3)
            delta = {"role": "assistant", "content": "HARBOR_COMPLETED"}
            reason = "stop"
        chunks = [{
            "id": "chatcmpl-harbor-test", "object": "chat.completion.chunk", "created": 1,
            "model": _MODEL, "choices": [{"index": 0, "delta": delta, "finish_reason": reason}],
            "usage": {"prompt_tokens": 24, "completion_tokens": 8, "total_tokens": 32},
        }]
        data = ("".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.wfile.flush()
        if request_number > 1:
            type(self).final_response_sent = True
        self.close_connection = True


@pytest.mark.parametrize("agent_timeout", [False, True])
def test_official_pi_trial_runs_tools_accounts_usage_and_exports_artifacts(harbor_case, agent_timeout):
    root = harbor_case
    image = _image("NUMOJ_HARBOR_PI_TEST_IMAGE", "numericaloj-agent-judge-lite:latest")
    verifier = (
        'if [ "$(cat /app/answer.txt)" = HARBOR_TOOL_OK ]; then\n'
        '  echo 0.375 > /logs/verifier/reward.txt\nelse\n  echo 0 > /logs/verifier/reward.txt\nfi'
    )
    task = _task(root, image, verifier=verifier)
    workspace.initialize_agent_task_workspace("harbor-pi", harness="pi", access_role="user", project_skill=False)
    _ModelHandler.requests = []
    _ModelHandler.slow_initial = agent_timeout
    _ModelHandler.final_response_sent = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ModelHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    traces, usage, native = [], [], []
    full_imports = []
    realtime_tools = []
    def capture(records, **_kwargs):
        if _kwargs.get('final'):
            full_imports.append(records)
        elif not _ModelHandler.final_response_sent:
            realtime_tools.extend(record for record in records if record['event']['kind'] == 'tool_call')
        traces.extend(records)
    trial_dir = root / "agent"
    try:
        result = harbor_runtime.run_harbor_agent(
            harbor_runtime={"task_path": str(task), "trial_dir": str(trial_dir),
                            "verifier_timeout_seconds": 30, "finalize_timeout_seconds": 600},
            task_id="harbor-pi-turn", session_id="harbor-pi", requested_by="test", harness="pi",
            endpoint={"source": "competition", "protocol": "openai", "model": _MODEL,
                      "base_url": f"http://127.0.0.1:{server.server_port}/v1", "api_key": _KEY},
            timeout_seconds=6 if agent_timeout else 60, reasoning_effort="off",
            trace_records_callback=capture,
            usage_callback=lambda event: usage.append(event) or {"applied": True, "hard_stop": False},
            native_session_callback=native.append,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert result.returncode == 0, result.stderr
    trial_result = harbor_runtime.load_harbor_result(trial_dir)
    assert trial_result["result"]["score"] == 0.375
    assert trial_result["agent_timed_out"] is agent_timeout
    public = workspace.get_existing_agent_workspace_path("harbor-pi")
    assert (public / "harbor-artifacts/app/answer.txt").read_text() == "HARBOR_TOOL_OK"
    with gzip.open(public / '.runtime/harbor/agent/pi.txt.gz', 'rb') as archived_stdout:
        native_output = archived_stdout.read()
    if not agent_timeout:
        assert b'HARBOR_TOOL_OK' in native_output
    elif not native_output:
        # 官方 CLI 取消时 stdout 管道可能尚未 flush；空源须完整保存为空，
        # 完整会话仍由实时写入的 Pi JSONL 与官方 ATIF 导入。
        original_stdout = trial_dir / (trial_dir / '.run-name').read_text() / 'agent/pi.txt'
        assert original_stdout.stat().st_size == 0
    assert _KEY.encode() not in native_output
    assert len(_ModelHandler.requests) == 2
    assert len(usage) == len(_ModelHandler.requests)
    assert native and result.native_session_id == native[-1]
    assert any(record["event"]["kind"] == "tool_call" for record in traces)
    assert full_imports and any(record.get('full_text') for record in full_imports[-1])
    assert realtime_tools, '官方自动日志挂载必须在模型最终回复前投影工具事件'
    if not agent_timeout:
        assert any("HARBOR_COMPLETED" in record["event"]["text"] for record in traces)
    official = json.loads((trial_dir / (trial_dir / ".run-name").read_text() / "result.json").read_text())
    assert official["config"]["agent"]["override_timeout_sec"] == (6 if agent_timeout else 60)
    assert official['config']['agent']['import_path'].endswith(':CachedPi')
    assert official['config']['environment']['kwargs']['auto_mounting'] is True
    assert official['verifier_environment_mode'] == 'shared'
    assert (trial_dir / '.harbor-cli.log').is_file()
    assert not (trial_dir / '.harbor-cli.json').exists()
    assert (official.get("exception_info") or {}).get("exception_type") == ("AgentTimeoutError" if agent_timeout else None)
    assert all("立即停止扩展功能" not in json.dumps(request, ensure_ascii=False) for request in _ModelHandler.requests)
    assert _KEY not in json.dumps(traces, ensure_ascii=False)
    _assert_stopped(trial_dir)
