#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis-based task state tracker for AI detection tasks.

Each task run is stored as a JSON hash in Redis with a TTL of 48h.
A sorted set keyed by submit-timestamp keeps the 50 most recent task IDs.
"""

import json
import time

try:
    import redis as _redis_mod
except ImportError:
    _redis_mod = None

from config import REDIS_HOST, REDIS_PORT, REDIS_DB

_TASK_KEY_PREFIX = "ai_detection:task:"
_RECENT_TASKS_KEY = "ai_detection:recent_tasks"  # sorted set: score=submitted_ts
_RECENT_TASKS_MAX = 50
_TASK_TTL_SECONDS = 48 * 3600

_rds = None


def _get_redis():
    global _rds
    if _rds is not None:
        return _rds
    if _redis_mod is None:
        return None
    try:
        _rds = _redis_mod.StrictRedis(
            host=REDIS_HOST,
            port=int(REDIS_PORT),
            db=int(REDIS_DB),
            decode_responses=True,
        )
        _rds.ping()
    except Exception:
        _rds = None
    return _rds


def _now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _task_key(task_id):
    return f"{_TASK_KEY_PREFIX}{task_id}"


def _save(task_id, data):
    rds = _get_redis()
    if rds is None:
        return
    try:
        rds.setex(_task_key(task_id), _TASK_TTL_SECONDS, json.dumps(data, ensure_ascii=False))
    except Exception:
        pass


def _load(task_id):
    rds = _get_redis()
    if rds is None:
        return None
    try:
        raw = rds.get(_task_key(task_id))
        return json.loads(raw) if raw else None
    except Exception:
        return None


def record_task_submitted(task_id, task_type, params_summary=""):
    """Called from the route after .delay(), before the worker picks it up."""
    rds = _get_redis()
    if rds is None:
        return
    ts = time.time()
    data = {
        "task_id": task_id,
        "task_type": task_type,       # filtered / batch / user / single
        "params_summary": params_summary,
        "status": "pending",
        "submitted_at": _now_str(),
        "started_at": None,
        "finished_at": None,
        "total": None,
        "processed": 0,
        "result": None,
        "error": None,
    }
    _save(task_id, data)
    try:
        rds.zadd(_RECENT_TASKS_KEY, {task_id: ts})
        # Keep only the most recent N tasks in the sorted set
        count = rds.zcard(_RECENT_TASKS_KEY)
        if count > _RECENT_TASKS_MAX:
            rds.zremrangebyrank(_RECENT_TASKS_KEY, 0, count - _RECENT_TASKS_MAX - 1)
        rds.expire(_RECENT_TASKS_KEY, _TASK_TTL_SECONDS)
    except Exception:
        pass


def record_task_running(task_id, total=None):
    """Called at the very start of the Celery task body."""
    data = _load(task_id) or {"task_id": task_id}
    data["status"] = "running"
    data["started_at"] = _now_str()
    if total is not None:
        data["total"] = total
    data["processed"] = 0
    _save(task_id, data)


def record_task_progress(task_id, processed, total=None):
    """Called periodically inside the task loop."""
    data = _load(task_id)
    if data is None:
        return
    data["processed"] = processed
    if total is not None:
        data["total"] = total
    _save(task_id, data)


def record_task_done(task_id, processed, total):
    """Called when the task completes successfully."""
    data = _load(task_id) or {"task_id": task_id}
    data["status"] = "done"
    data["finished_at"] = _now_str()
    data["processed"] = processed
    data["total"] = total
    _save(task_id, data)


def record_task_failed(task_id, error_msg):
    """Called in the task's except handler."""
    data = _load(task_id) or {"task_id": task_id}
    data["status"] = "failed"
    data["finished_at"] = _now_str()
    data["error"] = str(error_msg)[:500]
    _save(task_id, data)


def get_recent_tasks(limit=20):
    """Return up to `limit` most recent task dicts, newest first."""
    rds = _get_redis()
    if rds is None:
        return []
    try:
        # Highest scores (most recent timestamps) first
        task_ids = rds.zrevrange(_RECENT_TASKS_KEY, 0, limit - 1)
    except Exception:
        return []
    tasks = []
    for tid in task_ids:
        data = _load(tid)
        if data:
            tasks.append(data)
    return tasks


# Human-readable labels for task types
TASK_TYPE_LABELS = {
    "filtered": "筛选检测",
    "batch":    "按题检测",
    "user":     "按用户检测",
    "single":   "单条检测",
}
