#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time

from backend.oj_modules.config import SUBMISSION_SNAPSHOT_TTL_SECONDS
from backend.oj_modules.agents.trace_store import (
    ingest_agent_trace_records,
    save_agent_trace_token_usage,
)
from backend.oj_modules.db_services import (
    cancel_agent_run_snapshot,
    get_agent_run_by_task_id,
    is_agent_run_canceled,
    upsert_agent_run_snapshot,
)
from backend.oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)
from backend.oj_modules.problems.agent_runs import (
    agent_run_trace_dir,
    hydrate_agent_run_snapshot,
)
from backend.oj_modules.ranking.reverse_judge.traces import collect_agent_token_usage


AGENT_SOLVE_TASK_NAME = "oj.agent.solve_problem"
AGENT_GENERATE_TESTDATA_TASK_NAME = "oj.agent.generate_testdata"
AGENT_RUN_TURN_TASK_NAME = "oj.agent.run_turn"
_agent_progress_rds = None
_agent_progress_blocking_rds = None
_agent_queue_dispatch_task = None
_AGENT_PROGRESS_TTL_SECONDS = int(SUBMISSION_SNAPSHOT_TTL_SECONDS)
_STICKY_AGENT_RUN_STATUSES = frozenset({
    "completed",
    "failed",
    "canceled",
    "cancelled",
    "cleanupfailed",
    "cleanup_failed",
})
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


def init_agent_queue_dispatcher(dispatch_task):
    """注入会话 FIFO 调度任务，避免执行任务反向导入应用组合根。"""

    global _agent_queue_dispatch_task
    _agent_queue_dispatch_task = dispatch_task


def _dispatch_completed_agent_session(state):
    if _agent_queue_dispatch_task is None or not isinstance(state, dict):
        return
    if str(state.get("status") or "").strip().lower() != "completed":
        return
    session_id = str(state.get("session_id") or "").strip()
    if not session_id:
        return
    try:
        _agent_queue_dispatch_task.apply_async(args=(session_id,))
    except Exception:
        # MySQL 中 queued/dispatching 消息仍是事实来源；周期恢复会以固定
        # task_id 重投，不把一次 broker 瞬时故障改写为业务失败。
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


def _agent_billing_channel(session_id):
    return f"agent_session_billing:{session_id}"


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


def publish_agent_billing_revision(session_id, task_id, billing_revision):
    """结算提交后发布会话级 revision；Redis 失败不反向影响账本。"""

    normalized_session_id = str(session_id or "").strip()
    normalized_task_id = str(task_id or "").strip()
    try:
        revision = int(billing_revision)
    except (TypeError, ValueError):
        return False
    if (
        not normalized_session_id
        or len(normalized_session_id) > 64
        or not normalized_task_id
        or len(normalized_task_id) > 64
        or revision <= 0
    ):
        return False
    client = _ensure_agent_progress_redis()
    if client is None:
        return False
    payload = json.dumps({
        "version": 1,
        "session_id": normalized_session_id,
        "task_id": normalized_task_id,
        "billing_revision": revision,
    }, ensure_ascii=False, sort_keys=True)
    try:
        client.publish(_agent_billing_channel(normalized_session_id), payload)
        return True
    except Exception:
        return False


def subscribe_agent_billing_events(session_id):
    """订阅会话结算通知；账本 revision 才是断线后的持久事实来源。"""

    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id or len(normalized_session_id) > 64:
        return None
    client = _ensure_agent_progress_blocking_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_agent_billing_channel(normalized_session_id))
        return pubsub
    except Exception:
        return None


def _format_local_time(ts=None):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts or time.time()))


def _publish_agent_snapshot(state, *, hydrate_trace=True):
    """把磁盘上的规范 JSONL 实时投影进 Redis/SSE 快照。"""

    if not isinstance(state, dict):
        return
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return
    client = _ensure_agent_progress_redis()
    if client is None:
        return
    snapshot = (
        hydrate_agent_run_snapshot(state)
        if hydrate_trace
        else dict(state)
    )
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


def publish_agent_run_snapshot(state):
    """发布已有状态，不触发轨迹重扫；供请求级计费投影低延迟使用。"""

    _publish_agent_snapshot(state, hydrate_trace=False)


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
        "message": str(snapshot.get("message") or "任务已被手动终止"),
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
    persisted_status = (
        str(persisted.get("status") or "").strip().lower()
        if isinstance(persisted, dict)
        else ""
    )
    if persisted_status in _STICKY_AGENT_RUN_STATUSES:
        state["status"] = persisted.get("status") or "Canceled"
        state["message"] = (
            persisted.get("message") or state.get("message") or ""
        )
        state["stage"] = "finished"
        if persisted_status in {"canceled", "cancelled"}:
            state["harness_status"] = "canceled"
        elif persisted_status in {"cleanupfailed", "cleanup_failed"}:
            state["harness_status"] = "cleanup_failed"
        elif persisted_status == "completed":
            state["harness_status"] = "completed"
        else:
            state["harness_status"] = "error"
    # 带 session_id 的状态已由 upsert_agent_run_snapshot 在同一 MySQL 事务
    # 原子投影；旧任务没有 session_id，继续只写兼容表。
    _publish_agent_snapshot(state)
    _dispatch_completed_agent_session(state)


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
    """在 worker 侧刷新 v2 用量快照，再发布公开状态到 Redis/SSE。"""

    task_id = str((state or {}).get("task_id") or "").strip()
    if task_id:
        usage = collect_agent_token_usage(agent_run_trace_dir(task_id))
        if usage is not None:
            save_agent_trace_token_usage(task_id, usage)
    _publish_agent_snapshot(state)


def _persist_agent_trace_records(state, records, *, final=False):
    """把 observer 新增事件写入 v2 轨迹表；失败由 harness tick 重试。"""

    task_id = str((state or {}).get("task_id") or "").strip()
    if not task_id:
        return 0
    return ingest_agent_trace_records(task_id, records, final=final)


def agent_run_is_canceled(task_id):
    """以 MySQL 持久态为准，阻止撤销消息重投后再次执行任务。"""

    return is_agent_run_canceled(task_id)


def canceled_agent_task_result(task_id):
    return {
        "success": False,
        "canceled": True,
        "message": "任务已被手动终止",
        "task_id": str(task_id or ""),
    }


def _repair_terminal_agent_session(task_id, state):
    """late-ack 重投入口幂等修复已提交 run 与会话之间的历史崩溃窗口。"""

    from backend.oj_modules.agents.sessions import (
        get_agent_session_by_task_id,
        sync_agent_session_state,
    )

    session = get_agent_session_by_task_id(task_id)
    if not isinstance(session, dict) or session.get("is_legacy"):
        return False
    return sync_agent_session_state({
        "task_id": str(task_id or ""),
        "session_id": session.get("session_id"),
        "status": state.get("status"),
        "message": state.get("message"),
        "_preserve_conclusion": True,
    })


def existing_agent_terminal_result(task_id):
    """为 broker 恢复出的重复消息返回已有终态，避免再次启动 harness。"""

    state = get_agent_run_by_task_id(task_id)
    if not isinstance(state, dict):
        return None
    status = str(state.get("status") or "").strip().lower()
    if status not in {
        "completed",
        "failed",
        "canceled",
        "cancelled",
        "cleanupfailed",
        "cleanup_failed",
    }:
        return None
    _repair_terminal_agent_session(task_id, state)
    if status in {"canceled", "cancelled"}:
        return canceled_agent_task_result(task_id)
    if status in {"cleanupfailed", "cleanup_failed"}:
        return {
            "success": False,
            "cleanup_failed": True,
            "message": str(
                state.get("message") or "Agent 运行时清理失败，需管理员处理"
            ),
            "task_id": str(task_id or ""),
        }
    return {
        "success": status == "completed",
        "message": str(state.get("message") or "任务已结束"),
        "task_id": str(task_id or ""),
        "final_submission_id": state.get("final_submission_id"),
        "latest_submission_id": state.get("latest_submission_id"),
        "attempts": state.get("attempts") or [],
    }


def finalize_unhandled_agent_failure(
    state,
    exc,
    *,
    task_label="Agent",
    update_state=None,
    terminal_result_reader=None,
    cancellation_check=None,
    canceled_result_factory=None,
):
    """尽最大努力把 Celery 入口未处理异常投影为会话失败终态。"""

    state = state if isinstance(state, dict) else {}
    task_id = str(state.get("task_id") or "")
    read_terminal = terminal_result_reader or existing_agent_terminal_result
    is_canceled = cancellation_check or agent_run_is_canceled
    canceled_result = canceled_result_factory or canceled_agent_task_result
    persist = update_state or _update_agent_state

    try:
        existing = read_terminal(task_id)
    except Exception:
        existing = None
    if existing is not None:
        return existing
    try:
        if is_canceled(task_id):
            return canceled_result(task_id)
    except Exception:
        pass

    detail = str(exc).strip() or exc.__class__.__name__
    message = f"{str(task_label or 'Agent')} worker 异常：{detail[:800]}"
    conclusion = str(state.get("conclusion") or "")
    for _attempt in range(2):
        try:
            persist(
                state,
                message,
                status="Failed",
                stage="finished",
                harness_status="error",
                conclusion=conclusion,
            )
        except Exception:
            continue
        try:
            existing = read_terminal(task_id)
        except Exception:
            existing = None
        if existing is not None:
            return existing
        return {
            "success": False,
            "message": message,
            "task_id": task_id,
        }

    # 快照表持续不可写时仍独立尝试会话 CAS，避免当前轮永久保持 Running。
    state.update({
        "status": "Failed",
        "message": message,
        "stage": "finished",
        "harness_status": "error",
        "conclusion": conclusion,
    })
    try:
        from backend.oj_modules.agents.sessions import sync_agent_session_state

        sync_agent_session_state(state)
    except Exception:
        pass
    return {
        "success": False,
        "message": message,
        "task_id": task_id,
    }


def cancel_agent_run(task_id, message="任务已被手动终止"):
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
            persisted.get("message") or message or "任务已被手动终止"
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
    "AGENT_RUN_TURN_TASK_NAME",
    "AGENT_SOLVE_TASK_NAME",
    "AGENT_GENERATE_TESTDATA_TASK_NAME",
    "init_agent_progress_cache",
    "init_agent_queue_dispatcher",
    "get_agent_run_snapshot",
    "publish_agent_billing_revision",
    "publish_agent_run_snapshot",
    "subscribe_agent_billing_events",
    "subscribe_agent_run_events",
    "agent_run_is_canceled",
    "canceled_agent_task_result",
    "existing_agent_terminal_result",
    "finalize_unhandled_agent_failure",
    "cancel_agent_run",
]
