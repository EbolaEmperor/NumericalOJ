"""Agent 任务列表与执行轨迹的公开快照。"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
from pathlib import Path
import re

from backend.oj_modules.agents.messages import (
    list_agent_session_messages,
)
from backend.oj_modules.agents.trace_store import (
    get_agent_trace_token_usage,
    list_agent_trace_subagents,
    list_agent_trace_timeline,
)
from backend.oj_modules.config import AGENT_WORKSPACE_ROOT
from backend.oj_modules.problems.agent_launch import token_pricing_from_endpoint
from backend.oj_modules.ranking.reverse_judge.traces import (
    calculate_agent_token_cost_rmb,
)
from backend.oj_modules.site_config.services import get_llm_endpoint


_TASK_ID_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_SESSION_USAGE_COUNTER_FIELDS = (
    "request_count",
    "input_uncached_tokens",
    "input_cached_tokens",
    "input_cache_write_tokens",
    "input_total_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "cached_fallback_request_count",
    "cached_fallback_input_tokens",
)
_CUMULATIVE_RESUME_USAGE_SOURCES = frozenset({"claude_code", "pi"})


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

    if str(state.get("endpoint_source") or "global").strip().lower() != "global":
        return None

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


def build_agent_execution_trace(state, *, steer_records=None):
    """从 v2 存储构造只含公开时间线与用量快照的执行轨迹。"""

    state = state if isinstance(state, dict) else {}
    task_id = str(state.get("task_id") or "").strip()
    status = _execution_trace_status(state.get("status"))
    token_usage = get_agent_trace_token_usage(task_id) if task_id else None
    if token_usage is not None:
        token_usage = dict(token_usage)
        cost_rmb = calculate_agent_token_cost_rmb(
            token_usage,
            _current_token_pricing(state),
        )
        if cost_rmb is not None:
            token_usage["cost_rmb"] = cost_rmb
    if steer_records is None:
        session_id = str(state.get("session_id") or "").strip()
        try:
            steer_records = (
                list_agent_session_messages(
                    session_id,
                    delivery_modes="steer",
                )
                if session_id else []
            )
        except Exception:
            steer_records = []
    trace_messages = (
        list_agent_trace_timeline(
            task_id,
            status=state.get("status"),
            steer_records=steer_records,
        )
        if task_id else []
    )
    subagents = list_agent_trace_subagents(task_id) if task_id else []
    if status in {"passed", "error"}:
        terminal_subagent_status = (
            "completed" if status == "passed" else "ended"
        )
        subagents = [
            {
                **subagent,
                "status": terminal_subagent_status,
            }
            if str(subagent.get("status") or "").strip().lower() == "running"
            else subagent
            for subagent in subagents
        ]
    trace = {
        "schema_version": 2,
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
        "trace_files": [],
        "trace_messages": trace_messages,
        "subagents": subagents,
        "token_usage": token_usage,
        "incremental": True,
    }
    return trace


def _nonnegative_usage_counter(value):
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _nonnegative_usage_cost(value):
    if value is None or isinstance(value, bool) or str(value).strip() == "":
        return None
    try:
        cost = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    if not cost.is_finite() or cost < 0:
        return None
    return cost


def _decimal_text(value):
    if value == 0:
        return "0"
    return format(value.normalize(), "f")


def aggregate_agent_session_token_usage(task_usages):
    """按会话 resume 语义汇总唯一任务的 token 与成本。

    历史 Pi 与 Claude Code 轨迹在续聊轮次中会再次包含父会话历史，因此未
    显式标记口径的 ``token_usage`` 仍按累计快照处理：同一来源取各计数器
    最大值。规范 journal 会用 ``incremental=true`` 明确表示当前任务增量，
    四种 harness 都按唯一 ``task_id`` 相加。先按 ``task_id`` 去重可避免同一
    实时快照被历史与 current overlay 重复加入。

    只有每个存在 token usage 的任务都带有合法 ``cost_rmb`` 时才返回总成本；
    否则 ``cost_rmb`` 为 ``None``，避免把部分成本误报成整场会话成本。
    """

    unique_usages = {}
    for item in task_usages or ():
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            continue
        task_id = str(item[0] or "").strip()
        usage = item[1]
        if not task_id or not isinstance(usage, dict):
            continue
        # current overlay 应放在 iterable 后部，并以最后一个同 task 快照为准。
        unique_usages[task_id] = usage
    if not unique_usages:
        return None

    incremental_totals = {field: 0 for field in _SESSION_USAGE_COUNTER_FIELDS}
    cumulative_totals_by_source = {}
    incremental_cost = Decimal("0")
    cumulative_cost_by_source = {}
    cost_complete = True
    sources = set()

    for usage in unique_usages.values():
        source = str(usage.get("source") or "unknown").strip().lower() or "unknown"
        sources.add(source)
        counters = {
            field: _nonnegative_usage_counter(usage.get(field))
            for field in _SESSION_USAGE_COUNTER_FIELDS
        }
        cost = _nonnegative_usage_cost(usage.get("cost_rmb"))
        if cost is None:
            cost_complete = False

        is_legacy_cumulative = (
            source in _CUMULATIVE_RESUME_USAGE_SOURCES
            and usage.get("incremental") is not True
        )
        if is_legacy_cumulative:
            source_totals = cumulative_totals_by_source.setdefault(
                source,
                {field: 0 for field in _SESSION_USAGE_COUNTER_FIELDS},
            )
            for field, value in counters.items():
                source_totals[field] = max(source_totals[field], value)
            if cost is not None:
                cumulative_cost_by_source[source] = max(
                    cumulative_cost_by_source.get(source, Decimal("0")),
                    cost,
                )
            continue

        for field, value in counters.items():
            incremental_totals[field] += value
        if cost is not None:
            incremental_cost += cost

    totals = dict(incremental_totals)
    for source_totals in cumulative_totals_by_source.values():
        for field, value in source_totals.items():
            totals[field] += value
    # 不独立信任累计快照里的 total：实时同步可能恰好落在不同事件边界，
    # 由三个规范输入分量重算才能始终保持口径自洽。
    totals["input_total_tokens"] = (
        totals["input_uncached_tokens"]
        + totals["input_cached_tokens"]
        + totals["input_cache_write_tokens"]
    )

    total_cost = incremental_cost + sum(
        cumulative_cost_by_source.values(),
        start=Decimal("0"),
    )
    totals.update({
        "source": "session",
        "sources": sorted(sources),
        "turn_count": len(unique_usages),
        "cost_complete": cost_complete,
        "cost_rmb": _decimal_text(total_cost) if cost_complete else None,
    })
    if totals["cached_fallback_request_count"] <= 0:
        totals.pop("cached_fallback_request_count")
        totals.pop("cached_fallback_input_tokens")
    return totals


def hydrate_agent_run_snapshot(state, *, steer_records=None):
    """从磁盘规范 JSONL 重建轨迹；不读取或兼容旧 events。"""

    if not isinstance(state, dict):
        return state
    snapshot = dict(state)
    snapshot.pop("events", None)
    snapshot.pop("token_pricing", None)
    snapshot["execution_trace"] = build_agent_execution_trace(
        snapshot,
        steer_records=steer_records,
    )
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
    "aggregate_agent_session_token_usage",
    "normalize_agent_task_id",
    "agent_run_container_name",
    "agent_run_trace_dir",
    "build_agent_execution_trace",
    "decorate_agent_run_summaries",
    "hydrate_agent_run_snapshot",
]
