#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from config import SUBMISSION_SNAPSHOT_TTL_SECONDS
from oj_modules.db_services import (
    cancel_agent_run_snapshot,
    get_agent_run_by_task_id,
    is_agent_run_canceled,
    upsert_agent_run_snapshot,
)
from oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)
from oj_modules.problems.agent_runs import hydrate_agent_run_snapshot


AGENT_SOLVE_TASK_NAME = "oj.agent.solve_problem"
AGENT_GENERATE_TESTDATA_TASK_NAME = "oj.agent.generate_testdata"
_agent_progress_rds = None
_agent_progress_blocking_rds = None
_AGENT_PROGRESS_TTL_SECONDS = int(SUBMISSION_SNAPSHOT_TTL_SECONDS)
_PUBLISH_ACTIVE_SNAPSHOT_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end
redis.call('SETEX', KEYS[2], ARGV[1], ARGV[2])
redis.call('PUBLISH', KEYS[3], ARGV[2])
return 1
"""
_PUBLISH_CANCELED_SNAPSHOT_SCRIPT = """
redis.call('SETEX', KEYS[1], ARGV[1], ARGV[2])
redis.call('SETEX', KEYS[2], ARGV[1], ARGV[3])
redis.call('PUBLISH', KEYS[3], ARGV[3])
return 1
"""


def _clamp_int(value, default, min_value=None, max_value=None):
    try:
        val = int(value)
    except Exception:
        val = int(default)
    if min_value is not None:
        val = max(int(min_value), val)
    if max_value is not None:
        val = min(int(max_value), val)
    return val


def init_agent_progress_cache(redis_client, ttl_seconds=None, blocking_client=None):
    global _agent_progress_rds, _agent_progress_blocking_rds
    global _AGENT_PROGRESS_TTL_SECONDS
    _agent_progress_rds = redis_client
    _agent_progress_blocking_rds = (
        redis_client if blocking_client is None else blocking_client
    )
    if ttl_seconds is not None:
        try:
            _AGENT_PROGRESS_TTL_SECONDS = max(300, int(ttl_seconds))
        except Exception:
            pass


def _ensure_agent_progress_redis():
    global _agent_progress_rds
    if _agent_progress_rds is not None:
        return _agent_progress_rds
    _agent_progress_rds = create_optional_redis_client()
    return _agent_progress_rds


def _ensure_agent_progress_blocking_redis():
    global _agent_progress_blocking_rds
    if _agent_progress_blocking_rds is not None:
        return _agent_progress_blocking_rds
    _agent_progress_blocking_rds = create_optional_redis_client(
        RedisClientProfile.BLOCKING,
    )
    return _agent_progress_blocking_rds


def _agent_progress_key(task_id):
    return f"agent_run:{task_id}"


def _agent_progress_channel(task_id):
    return f"agent_run_events:{task_id}"


def _agent_cancel_key(task_id):
    return f"agent_run_cancel:{task_id}"


def get_agent_run_snapshot(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_redis()
    if client is None:
        return None
    try:
        raw = client.get(_agent_progress_key(task_id))
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def subscribe_agent_run_events(task_id):
    if not task_id:
        return None
    client = _ensure_agent_progress_blocking_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_agent_progress_channel(task_id))
        return pubsub
    except Exception:
        return None


def _format_local_time(ts=None):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts or time.time()))


def _publish_agent_snapshot(state):
    """把磁盘上的规范 JSONL 实时投影进 Redis/SSE 快照。"""

    if not isinstance(state, dict):
        return
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return
    client = _ensure_agent_progress_redis()
    if client is None:
        return
    snapshot = hydrate_agent_run_snapshot(state)
    payload = json.dumps(snapshot, ensure_ascii=False)
    try:
        eval_command = getattr(client, "eval", None)
        if callable(eval_command):
            eval_command(
                _PUBLISH_ACTIVE_SNAPSHOT_SCRIPT,
                3,
                _agent_cancel_key(task_id),
                _agent_progress_key(task_id),
                _agent_progress_channel(task_id),
                _AGENT_PROGRESS_TTL_SECONDS,
                payload,
            )
        else:
            client.setex(
                _agent_progress_key(task_id),
                _AGENT_PROGRESS_TTL_SECONDS,
                payload,
            )
            client.publish(_agent_progress_channel(task_id), payload)
    except Exception:
        pass


def _publish_canceled_agent_snapshot(state):
    if not isinstance(state, dict):
        return
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return
    client = _ensure_agent_progress_redis()
    if client is None:
        return
    snapshot = hydrate_agent_run_snapshot(state)
    payload = json.dumps(snapshot, ensure_ascii=False)
    marker = json.dumps({
        "status": "Canceled",
        "message": str(snapshot.get("message") or "任务已由管理员终止"),
    }, ensure_ascii=False)
    try:
        eval_command = getattr(client, "eval", None)
        if callable(eval_command):
            eval_command(
                _PUBLISH_CANCELED_SNAPSHOT_SCRIPT,
                3,
                _agent_cancel_key(task_id),
                _agent_progress_key(task_id),
                _agent_progress_channel(task_id),
                _AGENT_PROGRESS_TTL_SECONDS,
                marker,
                payload,
            )
        else:
            client.setex(
                _agent_cancel_key(task_id),
                _AGENT_PROGRESS_TTL_SECONDS,
                marker,
            )
            client.setex(
                _agent_progress_key(task_id),
                _AGENT_PROGRESS_TTL_SECONDS,
                payload,
            )
            client.publish(_agent_progress_channel(task_id), payload)
    except Exception:
        pass


def _persist_agent_state(state):
    if not isinstance(state, dict):
        return
    attempts = state.get("attempts") if isinstance(state.get("attempts"), list) else []
    best_score = 0
    for item in attempts:
        if not isinstance(item, dict):
            continue
        summary = item.get("summary") or {}
        if not isinstance(summary, dict):
            continue
        try:
            score = int(summary.get("score") or 0)
        except Exception:
            score = 0
        if score > best_score:
            best_score = score
    try:
        current_best = int(state.get("best_score") or 0)
    except Exception:
        current_best = 0
    state["best_score"] = max(best_score, current_best)

    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return

    state.pop("events", None)
    state.pop("execution_trace", None)
    state["updated_at"] = _format_local_time()
    persisted = upsert_agent_run_snapshot(state)
    if (
        isinstance(persisted, dict)
        and str(persisted.get("status") or "").strip().lower()
        in {"canceled", "cancelled"}
    ):
        state["status"] = persisted.get("status") or "Canceled"
        state["message"] = (
            persisted.get("message") or "任务已由管理员终止"
        )
        state["stage"] = "finished"
        state["harness_status"] = "canceled"
    _publish_agent_snapshot(state)


def _update_agent_state(state, message=None, **updates):
    """更新业务状态；运行轨迹只来自 harness 的真实 JSONL。"""

    if not isinstance(state, dict):
        return
    for key, value in updates.items():
        state[key] = value
    if message is not None:
        state["message"] = str(message or "").strip()
    _persist_agent_state(state)


def _publish_agent_trace(state):
    """轨迹 tick 只发布 Redis/SSE，不以约 2 秒频率写数据库。"""

    _publish_agent_snapshot(state)


def agent_run_is_canceled(task_id):
    """以 MySQL 持久态为准，阻止撤销消息重投后再次执行任务。"""

    return is_agent_run_canceled(task_id)


def canceled_agent_task_result(task_id):
    return {
        "success": False,
        "canceled": True,
        "message": "任务已由管理员终止",
        "task_id": str(task_id or ""),
    }


def existing_agent_terminal_result(task_id):
    """为 broker 恢复出的重复消息返回已有终态，避免再次启动 harness。"""

    state = get_agent_run_by_task_id(task_id)
    if not isinstance(state, dict):
        return None
    status = str(state.get("status") or "").strip().lower()
    if status not in {"completed", "failed", "canceled", "cancelled"}:
        return None
    if status in {"canceled", "cancelled"}:
        return canceled_agent_task_result(task_id)
    return {
        "success": status == "completed",
        "message": str(state.get("message") or "任务已结束"),
        "task_id": str(task_id or ""),
        "final_submission_id": state.get("final_submission_id"),
        "latest_submission_id": state.get("latest_submission_id"),
        "attempts": state.get("attempts") or [],
    }


def cancel_agent_run(task_id, message="任务已由管理员终止"):
    """先持久化终止标记，再将终态原子发布到 Redis/SSE。"""

    persisted, changed = cancel_agent_run_snapshot(task_id, message)
    if not isinstance(persisted, dict):
        return {
            "exists": False,
            "changed": False,
            "canceled": False,
            "state": None,
        }

    cached = get_agent_run_snapshot(task_id)
    state = dict(cached) if isinstance(cached, dict) else {}
    state.update(persisted)
    normalized_status = str(state.get("status") or "").strip().lower()
    canceled = normalized_status in {"canceled", "cancelled"}
    if canceled:
        state["status"] = "Canceled"
        state["message"] = str(
            persisted.get("message") or message or "任务已由管理员终止"
        )
        state["stage"] = "finished"
        state["harness_status"] = "canceled"
        _publish_canceled_agent_snapshot(state)

    return {
        "exists": True,
        "changed": bool(changed),
        "canceled": canceled,
        "state": hydrate_agent_run_snapshot(state),
    }


__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
    "agent_run_is_canceled",
    "canceled_agent_task_result",
    "existing_agent_terminal_result",
    "cancel_agent_run",
]
