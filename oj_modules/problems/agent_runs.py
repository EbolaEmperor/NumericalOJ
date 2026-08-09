"""Agent 任务列表与执行轨迹的公开快照。"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

from config import AGENT_WORKSPACE_ROOT
from oj_modules.problems.agent_launch import token_pricing_from_endpoint
from oj_modules.ranking.reverse_judge.traces import (
    calculate_agent_token_cost_rmb,
    collect_agent_token_usage,
    collect_agent_trace_files,
    collect_agent_trace_messages,
)
from oj_modules.site_config.services import get_llm_endpoint


_TASK_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def normalize_agent_task_id(task_id):
    normalized = str(task_id or "").strip()
    if not _TASK_ID_RE.fullmatch(normalized):
        raise ValueError("Agent task_id 无效")
    return normalized


def agent_run_container_name(task_id):
    """返回普通 Agent harness 的确定性 Docker 容器名。"""

    return f"numoj-agent-{normalize_agent_task_id(task_id)}"


def agent_run_trace_dir(task_id):
    """返回服务端生成的任务级受信任轨迹目录。"""

    normalized = normalize_agent_task_id(task_id)
    root = (Path(AGENT_WORKSPACE_ROOT).expanduser().resolve() / "traces").resolve()
    target = (root / normalized).resolve()
    if target.parent != root:
        raise ValueError("Agent 轨迹目录越界")
    return target


def _execution_trace_status(status):
    normalized = str(status or "").strip().lower()
    if normalized == "running":
        return "running"
    if normalized == "pending":
        return "pending"
    if normalized == "completed":
        return "passed"
    if normalized in {
        "failed",
        "canceled",
        "cancelled",
        "cleanupfailed",
        "cleanup_failed",
    }:
        return "error"
    return "pending"


def _current_token_pricing(state):
    """按任务使用的节点 ID 读取当前人民币价格。"""

    try:
        endpoint_id = int(state.get("endpoint_id"))
    except (TypeError, ValueError):
        return None
    if endpoint_id <= 0:
        return None
    try:
        endpoint = get_llm_endpoint(endpoint_id, include_secret=False)
    except Exception:
        return None
    return token_pricing_from_endpoint(endpoint)


def build_agent_execution_trace(state):
    """按 Reverse Judge 的公共 JSONL 解析契约构造执行轨迹。"""

    state = state if isinstance(state, dict) else {}
    task_id = str(state.get("task_id") or "").strip()
    try:
        trace_dir = agent_run_trace_dir(task_id)
    except ValueError:
        trace_dir = None
    status = _execution_trace_status(state.get("status"))
    token_usage = collect_agent_token_usage(trace_dir)
    if token_usage is not None:
        token_usage = dict(token_usage)
        cost_rmb = calculate_agent_token_cost_rmb(
            token_usage,
            _current_token_pricing(state),
        )
        if cost_rmb is not None:
            token_usage["cost_rmb"] = cost_rmb
    return {
        "trace_id": (
            hashlib.sha256(task_id.encode("utf-8", "replace")).hexdigest()[:16]
            if task_id else ""
        ),
        "status": status,
        "error_message": (
            str(state.get("message") or "Agent 任务未完成")
            if status == "error" else ""
        ),
        "stdout": "",
        "stderr": "",
        "trace_files": collect_agent_trace_files(trace_dir),
        "trace_messages": collect_agent_trace_messages(trace_dir),
        "token_usage": token_usage,
    }


def hydrate_agent_run_snapshot(state):
    """从磁盘规范 JSONL 重建轨迹；不读取或兼容旧 events。"""

    if not isinstance(state, dict):
        return state
    snapshot = dict(state)
    snapshot.pop("events", None)
    snapshot.pop("token_pricing", None)
    snapshot["execution_trace"] = build_agent_execution_trace(snapshot)
    return snapshot


def decorate_agent_run_summaries(runs):
    """原地补充任务摘要展示字段，并返回原列表。"""
    for run in runs:
        run["display_problem_title"] = (
            str(run.get("problem_title") or "").strip()
            or f"Problem {run.get('problem_id') or '-'}"
        )
        run["display_status"] = str(run.get("status") or "Pending")
        run["display_best_score"] = int(run.get("best_score") or 0)
    return runs


__all__ = [
    "normalize_agent_task_id",
    "agent_run_container_name",
    "agent_run_trace_dir",
    "build_agent_execution_trace",
    "decorate_agent_run_summaries",
    "hydrate_agent_run_snapshot",
]
