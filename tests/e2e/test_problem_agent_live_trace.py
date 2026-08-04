# -*- coding: utf-8 -*-
"""真实 DeepSeek + Agent Judge lite 容器的 Problem Agent 轨迹链路。"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from oj_modules.problems import agent_runs
from oj_modules.problems.agent_runs import build_agent_execution_trace
from oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages
from oj_modules.tasks.agent import harness_runtime as runtime
from oj_modules.tasks.agent import identity_relay
from tests.e2e.live_ai import (
    DEEPSEEK_MODEL,
    DEEPSEEK_OPENAI_BASE_URL,
    ROOT,
    read_deepseek_api_key,
)


_AGENT_IMAGE = "numericaloj-agent-judge-lite:latest"
_TRACE_MARKER = "NUMOJ_PROBLEM_AGENT_LIVE_TRACE_OK"
_TOKEN_PRICING = {
    "input_price_per_million": "2",
    "cached_input_price_per_million": "0.5",
    "output_price_per_million": "8",
}

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.live_ai,
    pytest.mark.timeout(600),
]


class _RelayContext:
    def __enter__(self):
        return SimpleNamespace(
            base_url="http://host.docker.internal:9",
            created_submission_ids=(),
        )

    def __exit__(self, *_args):
        return False


@pytest.fixture
def docker_workspace_root() -> Path:
    # Colima 共享仓库所在的 /Users 路径；macOS 的 /private/var/folders 和
    # /private/tmp 都不是可靠的双向 bind mount 来源。
    temp_root = ROOT / "tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="numoj-problem-agent-e2e-",
        dir=str(temp_root),
    ) as path:
        yield Path(path)


def _container_is_running(container_name: str) -> bool:
    inspected = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return inspected.returncode == 0 and inspected.stdout.strip() == "true"


def test_problem_agent_lite_container_publishes_parseable_live_trace(
    monkeypatch: pytest.MonkeyPatch,
    docker_workspace_root: Path,
) -> None:
    """真实 harness 结束前必须已同步出公共解析器可识别的运行轨迹。"""

    if shutil.which("docker") is None:
        pytest.fail("真实 Problem Agent 轨迹 E2E 需要 Docker CLI")
    image = subprocess.run(
        ["docker", "image", "inspect", _AGENT_IMAGE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if image.returncode != 0:
        pytest.fail(f"本地缺少 Agent Judge lite 镜像 {_AGENT_IMAGE}")

    api_key = read_deepseek_api_key()
    workspace_root = docker_workspace_root / "agent-workspaces"
    task_id = f"problem-live-{uuid4().hex}"
    container_name = runtime._container_name_for_task_id(task_id)
    live_snapshots: list[dict] = []

    monkeypatch.setattr(runtime, "AGENT_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(agent_runs, "AGENT_WORKSPACE_ROOT", str(workspace_root))
    monkeypatch.setattr(
        agent_runs,
        "get_llm_endpoint",
        lambda endpoint_id, **_kwargs: (
            {"id": endpoint_id, **_TOKEN_PRICING}
        ),
    )
    monkeypatch.setattr(runtime, "AGENT_JUDGE_DOCKER_IMAGE", _AGENT_IMAGE)
    monkeypatch.setattr(runtime, "AGENT_JUDGE_DEFAULT_TIMEOUT", 300)
    monkeypatch.setattr(runtime, "AGENT_TRACE_SYNC_INTERVAL_SECONDS", 0.25)
    monkeypatch.setattr(runtime, "get_web_search_settings", lambda **_kwargs: None)
    monkeypatch.setattr(
        identity_relay,
        "run_numoj_identity_relay",
        lambda *_args, **_kwargs: _RelayContext(),
    )

    def capture_trace() -> None:
        trace = build_agent_execution_trace({
            "task_id": task_id,
            "status": "Running",
            "message": "真实容器执行中",
            "endpoint_id": 1,
        })
        if trace["trace_messages"]:
            live_snapshots.append({
                "container_running": _container_is_running(container_name),
                "trace": trace,
            })

    try:
        result = runtime.run_agent_harness(
            task_id=task_id,
            task_kind="solve",
            problem_id=1,
            requested_by="admin",
            harness="pi",
            endpoint={
                "id": 1,
                "protocol": "openai",
                "category": "text",
                "base_url": DEEPSEEK_OPENAI_BASE_URL,
                "api_key": api_key,
                "model": DEEPSEEK_MODEL,
                "thinking_enabled": False,
                "thinking_format": "none",
            },
            session_cookie="e2e-placeholder",
            prompt=(
                "不要调用任何工具。最终回复只包含这一行，不要添加 Markdown：\n"
                f"{_TRACE_MARKER}"
            ),
            trace_callback=capture_trace,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        pytest.fail(str(detail).replace(api_key, "[已脱敏]")[:2000])

    assert result.returncode == 0, result.stderr
    assert result.timed_out is False
    trace_dir = agent_runs.agent_run_trace_dir(task_id)
    final_trace = build_agent_execution_trace({
        "task_id": task_id,
        "status": "Completed",
        "endpoint_id": 1,
    })
    usage = final_trace["token_usage"]
    assert usage["source"] == "pi"
    assert usage["request_count"] >= 1
    assert usage["input_total_tokens"] > 0
    assert usage["output_tokens"] > 0
    assert float(usage["cost_rmb"]) > 0
    messages = collect_agent_trace_messages(trace_dir)
    assert any(
        message.get("kind") == "assistant"
        and _TRACE_MARKER in str(message.get("text") or "")
        for message in messages
    ), json.dumps(messages, ensure_ascii=False, indent=2)
    assert any(
        snapshot["container_running"]
        and snapshot["trace"]["trace_messages"]
        for snapshot in live_snapshots
    )
    assert not _container_is_running(container_name)
    for path in trace_dir.rglob("*"):
        if path.is_file():
            assert api_key.encode("utf-8") not in path.read_bytes()
