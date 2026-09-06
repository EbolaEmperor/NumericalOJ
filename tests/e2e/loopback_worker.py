# -*- coding: utf-8 -*-
"""CLI E2E 专用 worker：保留通用 Agent 编排，只替代模型和评分脚本。"""

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
    from backend.oj_modules.tasks.agent.harness_runtime import HarnessRunResult

    session_id = kwargs["session_id"]
    session = get_agent_session(session_id) or {}
    kind = session.get("judge_kind")
    if kwargs["task_kind"] != "judge" or kind not in {"reverse_quality", "reverse_answer"}:
        raise RuntimeError("本地模型替身只支持反向评测会话")
    workspace = get_existing_agent_workspace_path(session_id)
    if kind == "reverse_quality":
        rejected = (workspace / "evidence/quality_gate_reject.txt").is_file()
        result = {
            "passed": not rejected,
            "summary": (
                "命中私有审核标准：solution 和 judge 不得隐藏私有配对密码"
                if rejected else "题目包通过质量审核"
            ),
            "violations": ([{
                "rule": "solution 和 judge 不得隐藏私有配对密码",
                "reason": "发现测试用违规标记",
                "evidence": [{
                    "path": "quality_gate_reject.txt",
                    "line": 1,
                    "excerpt": "fake gate rejection marker",
                }],
            }] if rejected else []),
        }
        write_agent_workspace_file(
            session_id, "quality_gate_result.json",
            json.dumps(result, ensure_ascii=False),
        )
        conclusion = "已完成题目包质量审核"
    else:
        if not (workspace / "problem").is_dir():
            raise RuntimeError("作答会话缺少已注入的题目")
        # 保留已展开到根目录的模板，再新增产物验证完整 workspace 交付。
        write_agent_workspace_file(
            session_id, "agent-output.txt", "本地测试 Agent 的根目录交付物。\n",
        )
        conclusion = "已在 workspace 中完成可交付答案"
    native_id = kwargs.get("resume_session_id") or str(uuid.uuid4())
    kwargs["native_session_callback"](native_id)
    kwargs["trace_records_callback"]([{
        "version": 1, "type": "numoj_trace", "sequence": 1,
        "event": {"id": "e2e-conclusion", "kind": "assistant", "text": conclusion},
    }], final=True)
    return HarnessRunResult(0, False, "", "", native_session_id=native_id)


def _run_judge_script(submission_id, package_root, answer_dir, timeout_s):
    score = 100.0 if str(answer_dir).strip().rstrip("/") == "solution" else 25.0
    return {
        "ok": True, "returncode": 0, "stdout": "fake reverse judge",
        "stderr": "", "error": "",
        "result": {
            "max_score": 100.0, "score": score,
            "test_points": {"fake": {
                "description": "本地 e2e 假反向评测",
                "max_score": 100.0, "score": score,
            }},
        },
    }


def main() -> None:
    # 必须先校验，backend.oj 组合根和 Celery 都在护栏之后加载。
    _assert_test_environment()
    from backend.oj import celery
    from backend.oj_modules.tasks.agent import generic
    from backend.oj_modules.tasks.ranking import reverse_judge

    generic.run_agent_harness = _run_reverse_agent
    reverse_judge._run_judge_script = _run_judge_script
    celery.worker_main(sys.argv[1:])


if __name__ == "__main__":
    main()
