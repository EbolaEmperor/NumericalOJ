#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from config import SUBMISSION_SNAPSHOT_TTL_SECONDS
from oj_modules.db_services import upsert_agent_run_snapshot
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
        client.setex(_agent_progress_key(task_id), _AGENT_PROGRESS_TTL_SECONDS, payload)
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
    upsert_agent_run_snapshot(state)
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


__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
]
