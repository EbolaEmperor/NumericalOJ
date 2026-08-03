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


def _safe_json_copy(value, default=None):
    fallback = {} if default is None else default
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except Exception:
        return fallback


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

    client = _ensure_agent_progress_redis()
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return

    state["updated_at"] = _format_local_time()
    upsert_agent_run_snapshot(state)

    if client is None:
        return
    payload = json.dumps(state, ensure_ascii=False)
    try:
        client.setex(_agent_progress_key(task_id), _AGENT_PROGRESS_TTL_SECONDS, payload)
        client.publish(_agent_progress_channel(task_id), payload)
    except Exception:
        pass


def _push_agent_event(
    state,
    event_message,
    level="info",
    event_type=None,
    details=None,
    **updates,
):
    if not isinstance(state, dict):
        return
    for key, value in updates.items():
        state[key] = value

    state["message"] = updates.get("message", event_message)
    events = state.get("events") or []
    event_item = {
        "time": _format_local_time(),
        "level": level,
        "message": str(event_message or "").strip(),
    }
    if event_type:
        event_item["event_type"] = str(event_type)
    if details is not None:
        event_item["details"] = _safe_json_copy(details, default={})
    events.append(event_item)
    if len(events) > 120:
        events = events[-120:]
    state["events"] = events
    _persist_agent_state(state)


__all__ = [
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "init_agent_progress_cache",
    "get_agent_run_snapshot",
    "subscribe_agent_run_events",
]
