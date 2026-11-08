# -*- coding: utf-8 -*-
"""CLI E2E 专用 worker：保留通用 Agent 编排，只替代模型与 Harbor 执行。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import uuid

from tests.environment_guard import (
    DestructiveTestTarget,
    assert_disposable_test_target,
)


def _assert_test_environment() -> None:
    if str(os.environ.get("OJ_LIVE_AI") or "").strip().lower() in {
        "1", "true", "yes", "on",
    }:
        raise RuntimeError("OJ_LIVE_AI 真实 E2E 禁止启动模型替身 worker")
    from backend.oj_modules import config

    assert_disposable_test_target(DestructiveTestTarget(
        test_env=os.environ.get("NUMOJ_TEST_ENV"),
        hostname=socket.gethostname(),
        checkout_path=str(Path(__file__).resolve().parents[2]),
        mysql_host=str(config.MYSQL_HOST),
        mysql_db=str(config.MYSQL_DB),
        redis_host=str(config.REDIS_HOST),
        redis_db=config.REDIS_DB,
    ))


def _run_reverse_agent(**kwargs):
    from backend.oj_modules.agents.sessions import get_agent_session
    from backend.oj_modules.agents.workspace import (
        get_existing_agent_workspace_path,
        write_agent_workspace_file,
    )
    session_id = kwargs["session_id"]
    session = get_agent_session(session_id) or {}
    kind = session.get("judge_kind")
    if kwargs["task_kind"] != "judge" or kind != "reverse_quality":
        raise RuntimeError("普通 Harness 替身只支持反向评测质量门禁")
    workspace = get_existing_agent_workspace_path(session_id)
    if kind == "reverse_quality":
        rejected = (workspace / "evidence/quality_gate_reject.txt").is_file()
        result = {
            "passed": not rejected,
            "reason": (
                "命中私有审核标准：solution 和 tests 不得隐藏私有配对密码"
                if rejected else "题目包通过质量审核"
            ),
        }
        write_agent_workspace_file(
            session_id, "quality_gate_result.json",
            json.dumps(result, ensure_ascii=False),
        )
        conclusion = "已完成题目包质量审核"
    return _complete_fake_agent(kwargs, conclusion)


def _complete_fake_agent(kwargs, conclusion):
    from backend.oj_modules.tasks.agent.harness_runtime import HarnessRunResult

    native_id = kwargs.get("resume_session_id") or str(uuid.uuid4())
    kwargs["native_session_callback"](native_id)
    kwargs["trace_records_callback"]([{
        "version": 1, "type": "numoj_trace", "sequence": 1,
        "event": {"id": "e2e-conclusion", "kind": "assistant", "text": conclusion},
    }], final=True)
    return HarnessRunResult(0, False, "", "", native_session_id=native_id)


def _harbor_result(score):
    return {
        "ok": True, "returncode": 0, "stdout": "fake Harbor trial",
        "stderr": "", "error": "",
        "result": {
            "max_score": 1.0, "score": score, "rewards": {"reward": score},
            "test_points": {"fake": {
                "description": "本地 e2e Harbor 替身",
                "max_score": 1.0, "score": score,
            }},
        },
    }


def _run_harbor_oracle(task_path, trial_dir, timeout_seconds=300, build_event_callback=None):
    if callable(build_event_callback):
        build_event_callback({'event': 'output', 'text': '测试环境：复用 Harbor 通用镜像缓存\n'})
        build_event_callback({'event': 'complete', 'text': '构建完成', 'cached': True})
    return _harbor_result(1.0)


def _run_harbor_agent(**kwargs):
    from backend.oj_modules.agents.sessions import get_agent_session
    from backend.oj_modules.agents.workspace import write_agent_workspace_file
    from backend.oj_modules.integrations.harbor_results import write_harbor_result

    session_id = kwargs["session_id"]
    session = get_agent_session(session_id) or {}
    if session.get("judge_kind") != "reverse_answer":
        raise RuntimeError("Harbor 替身只支持反向评测作答")
    runtime = kwargs["harbor_runtime"]
    if not (Path(runtime["task_path"]) / "instruction.md").is_file():
        raise RuntimeError("Harbor 作答缺少任务说明")
    write_agent_workspace_file(session_id, "harbor-artifacts/app/README.md", "在此目录作答。\n")
    write_agent_workspace_file(session_id, "harbor-artifacts/app/agent-output.txt", "本地测试 Agent 的任务产物。\n")
    trial_dir = Path(runtime["trial_dir"])
    trial_dir.mkdir(parents=True, exist_ok=True)
    write_harbor_result(trial_dir, _harbor_result(0.25))
    return _complete_fake_agent(kwargs, "已在 Harbor 环境中完成可交付答案")


def main() -> None:
    # 必须先校验，backend.oj 组合根和 Celery 都在护栏之后加载。
    _assert_test_environment()
    from backend.oj import celery
    from backend.oj_modules.tasks.agent import generic
    from backend.oj_modules.tasks.ranking import reverse_judge
    from backend.oj_modules.integrations import harbor_runtime

    generic.run_agent_harness = _run_reverse_agent
    reverse_judge.run_harbor_oracle = _run_harbor_oracle
    harbor_runtime.run_harbor_agent = _run_harbor_agent
    celery.worker_main(sys.argv[1:])


if __name__ == "__main__":
    main()
