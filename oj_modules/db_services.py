#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import logging
import os
import time

from flask import session

from oj_modules.config import SUBMISSION_SNAPSHOT_TTL_SECONDS
from oj_modules.ai.code_feedback import _normalize_ai_code_issues
from oj_modules.forum.identity import (
    assert_identity_name_available,
    run_identity_namespace_transaction,
)
from oj_modules.infrastructure.mysql import (
    _MySQLConnectionPool,
    _PooledConnectionProxy,
    _create_raw_mysql_connection,
    _get_db_pool,
    get_db_connection,
    safe_table_name,
)
from oj_modules.observability import (
    content_fingerprint,
    current_context,
    emit_audit,
    safe_file_fingerprint,
)
from oj_modules.problems.llm_bindings import (
    deserialize_problem_llm_bindings,
    normalize_problem_llm_bindings,
    serialize_problem_llm_bindings,
)
from oj_modules.infrastructure.redis import (
    RedisClientProfile,
    create_optional_redis_client,
)


logger = logging.getLogger(__name__)


_UNSET = object()


_PROGRAMMING_OUTPUT_IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp",
})


CLASS_ADJUST_FLAG_KEY = 'class_adjust_enabled'


class SubmissionLimitExceeded(RuntimeError):
    """用户在一道普通题上的可计费提交次数已用尽。"""

    def __init__(self, username, problem_id, limit, current_count):
        self.username = username
        self.problem_id = int(problem_id)
        self.limit = int(limit)
        self.current_count = int(current_count)
        super().__init__(
            f"submission limit exceeded: user={username!r}, "
            f"problem_id={problem_id}, count={current_count}, limit={limit}"
        )


_settings_table_ready = False
_agent_runs_table_ready = False
_submission_snapshot_rds = None
_submission_snapshot_blocking_rds = None
_submission_snapshot_ttl_seconds = int(SUBMISSION_SNAPSHOT_TTL_SECONDS)
# problems 表惰性补列的「已补加」缓存改用 _ensured_problem_columns 集合（见 _ensure_problem_column）。
_daily_submission_stats_table_ready = False

# Schema synchronization is owned by the explicit deploy/bootstrap workflow in
# scripts/init_db_schema.py. Process startup and runtime data paths must not
# issue DDL.


def _schema_is_managed_at_startup(*args, **kwargs):
    return None


def _ensure_problem_column(column, add_column_sql):
    return _schema_is_managed_at_startup(column, add_column_sql)


def _ensure_submission_column(column, add_column_sql):
    return _schema_is_managed_at_startup(column, add_column_sql)


def ensure_submission_code_longtext_column():
    return _schema_is_managed_at_startup()


def ensure_problem_written_grading_mode_column():
    return _schema_is_managed_at_startup()


def ensure_problem_written_grading_model_column():
    return _schema_is_managed_at_startup()


def ensure_problem_written_grading_prompt_column():
    return _schema_is_managed_at_startup()


def ensure_problem_written_grading_columns():
    ensure_problem_written_grading_mode_column()
    ensure_problem_written_grading_model_column()
    ensure_problem_written_grading_prompt_column()


def normalize_output_image_filename(value, default="output.png"):
    text = str(value or "").strip().replace("\\", "/")
    if "/" in text:
        text = text.rsplit("/", 1)[-1].strip()
    if not text:
        text = str(default or "output.png").strip().replace("\\", "/")
        if "/" in text:
            text = text.rsplit("/", 1)[-1].strip()
    if "\x00" in text:
        raise ValueError("输出图片文件名不能包含空字符")
    stem, extension = os.path.splitext(text)
    if extension.lower() not in _PROGRAMMING_OUTPUT_IMAGE_EXTENSIONS:
        raise ValueError(
            "输出图片文件名必须使用 png、jpg、jpeg、bmp、gif 或 webp 扩展名"
        )
    if len(text) > 255:
        text = stem[:255 - len(extension)] + extension
    return text


def ensure_problem_programming_grading_mode_column():
    return _schema_is_managed_at_startup()


def ensure_problem_programming_grading_model_column():
    return _schema_is_managed_at_startup()


def ensure_problem_output_image_filename_column():
    return _schema_is_managed_at_startup()


def ensure_problem_programming_grading_prompt_column():
    return _schema_is_managed_at_startup()


def ensure_problem_programming_grading_columns():
    ensure_problem_programming_grading_mode_column()
    ensure_problem_programming_grading_model_column()
    ensure_problem_output_image_filename_column()
    ensure_problem_programming_grading_prompt_column()


def ensure_problem_grading_columns():
    ensure_problem_written_grading_columns()
    ensure_problem_programming_grading_columns()


def ensure_submission_prompt_columns():
    return _schema_is_managed_at_startup()


def ensure_submission_prompt_text_column():
    return _schema_is_managed_at_startup()


def ensure_submission_generated_from_prompt_column():
    return _schema_is_managed_at_startup()


def ensure_submission_prompt_generation_error_column():
    return _schema_is_managed_at_startup()


def init_submission_snapshot_cache(redis_client, ttl_seconds=None, blocking_client=None):
    global _submission_snapshot_rds, _submission_snapshot_blocking_rds
    global _submission_snapshot_ttl_seconds
    _submission_snapshot_rds = redis_client
    _submission_snapshot_blocking_rds = (
        redis_client if blocking_client is None else blocking_client
    )
    if ttl_seconds is not None:
        try:
            _submission_snapshot_ttl_seconds = max(60, int(ttl_seconds))
        except Exception:
            pass


def _ensure_submission_snapshot_redis():
    global _submission_snapshot_rds
    if _submission_snapshot_rds is not None:
        return _submission_snapshot_rds
    _submission_snapshot_rds = create_optional_redis_client()
    return _submission_snapshot_rds


def _ensure_submission_snapshot_blocking_redis():
    global _submission_snapshot_blocking_rds
    if _submission_snapshot_blocking_rds is not None:
        return _submission_snapshot_blocking_rds
    _submission_snapshot_blocking_rds = create_optional_redis_client(
        RedisClientProfile.BLOCKING,
    )
    return _submission_snapshot_blocking_rds


def _submission_snapshot_key(submission_id):
    return f"submission:{submission_id}"


def _submission_snapshot_channel(submission_id):
    return f"submission_events:{submission_id}"


def _format_snapshot_time():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


def _count_test_points_from_raw(raw):
    if raw is None:
        return 0
    if isinstance(raw, list):
        return len(raw)
    text = str(raw).strip()
    if not text:
        return 0
    return len([line for line in text.split('\n') if line.strip()])


def _parse_test_points(raw):
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    text = str(raw).strip()
    if not text:
        return []
    points = []
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        try:
            points.append(json.loads(line))
        except Exception:
            pass
    return points


def _build_submission_status_snapshot_from_row(row, last_updated=None):
    if not row:
        return None
    test_points = _parse_test_points(row.get("test_points"))
    prompt_generation_error = str(row.get("prompt_generation_error") or "").strip()
    return {
        "id": int(row["id"]),
        "username": row.get("username"),
        "problem_id": row.get("problem_id"),
        "problem_type": row.get("problem_type"),
        "status": row.get("status"),
        "score": row.get("score"),
        "generated_from_prompt": bool(row.get("generated_from_prompt")),
        "prompt_generation_error": prompt_generation_error,
        "promptly_review_reply": prompt_generation_error,
        "test_points": test_points,
        "test_points_count": len(test_points),
        "last_updated": last_updated or _format_snapshot_time(),
    }


def _save_submission_status_snapshot(snapshot):
    if not snapshot:
        return
    client = _ensure_submission_snapshot_redis()
    if client is None:
        return
    key = _submission_snapshot_key(snapshot["id"])
    try:
        payload = json.dumps(snapshot, ensure_ascii=False)
        client.setex(key, _submission_snapshot_ttl_seconds, payload)
        client.publish(_submission_snapshot_channel(snapshot["id"]), payload)
    except Exception:
        pass


def set_submission_status_snapshot(
    submission_id,
    username,
    problem_id,
    problem_type,
    status,
    score,
    test_points,
):
    points = test_points if isinstance(test_points, list) else []
    snapshot = {
        "id": int(submission_id),
        "username": username,
        "problem_id": problem_id,
        "problem_type": problem_type,
        "status": status,
        "score": score,
        "test_points": points,
        "test_points_count": len(points),
        "last_updated": _format_snapshot_time(),
    }
    _save_submission_status_snapshot(snapshot)
    return snapshot


def refresh_submission_status_snapshot(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, problem_id, problem_type, status, score, test_points,
                       generated_from_prompt, prompt_generation_error
                FROM submissions
                WHERE id=%s
                """,
                (submission_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()

    snapshot = _build_submission_status_snapshot_from_row(row)
    _save_submission_status_snapshot(snapshot)
    return snapshot


def get_submission_status_snapshot(submission_id, prefer_cache=True):
    if prefer_cache:
        client = _ensure_submission_snapshot_redis()
    else:
        client = None
    if client is not None:
        try:
            raw = client.get(_submission_snapshot_key(submission_id))
            if raw:
                data = json.loads(raw)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return refresh_submission_status_snapshot(submission_id)


def subscribe_submission_status_events(submission_id):
    client = _ensure_submission_snapshot_blocking_redis()
    if client is None:
        return None
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(_submission_snapshot_channel(submission_id))
        return pubsub
    except Exception:
        return None


def ensure_agent_runs_table():
    global _agent_runs_table_ready
    if _agent_runs_table_ready:
        return
    _agent_runs_table_ready = True


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _to_json_text(value, default):
    raw = value if value is not None else default
    try:
        return json.dumps(raw, ensure_ascii=False)
    except Exception:
        return json.dumps(default, ensure_ascii=False)


def _parse_json_text(value, default):
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    try:
        parsed = json.loads(text)
        return parsed if parsed is not None else default
    except Exception:
        return default


def _format_datetime_value(value):
    if value is None:
        return None
    if hasattr(value, "strftime"):
        try:
            return value.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    return str(value)


def _best_score_from_attempts(attempts):
    if not isinstance(attempts, list):
        return 0
    best = 0
    for item in attempts:
        if not isinstance(item, dict):
            continue
        summary = item.get("summary") or {}
        if not isinstance(summary, dict):
            continue
        score = _safe_int(summary.get("score"), 0)
        if score > best:
            best = score
    return best


def upsert_agent_run_snapshot(state):
    if not isinstance(state, dict):
        return
    task_id = str(state.get("task_id") or "").strip()
    if not task_id:
        return

    ensure_agent_runs_table()
    attempts = state.get("attempts") if isinstance(state.get("attempts"), list) else []
    best_score = max(
        _safe_int(state.get("best_score"), 0),
        _best_score_from_attempts(attempts),
    )

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # MySQL 按书写顺序计算 ON DUPLICATE KEY UPDATE；status 必须放在
            # 最后，前面的列才能根据“写入前状态”判断终态是否已经提交。
            cursor.execute(
                """
                INSERT INTO agent_task_runs (
                    task_id, problem_id, problem_title, requested_by,
                    harness, endpoint_id, endpoint_model,
                    context_window_tokens, max_output_tokens,
                    status, message,
                    best_score, final_submission_id, latest_submission_id,
                    attempts_json
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s
                )
                ON DUPLICATE KEY UPDATE
                    problem_id=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        problem_id,
                        VALUES(problem_id)
                    ),
                    problem_title=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        problem_title,
                        VALUES(problem_title)
                    ),
                    requested_by=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        requested_by,
                        VALUES(requested_by)
                    ),
                    harness=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        harness,
                        COALESCE(NULLIF(VALUES(harness), ''), harness)
                    ),
                    endpoint_id=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        endpoint_id,
                        COALESCE(VALUES(endpoint_id), endpoint_id)
                    ),
                    endpoint_model=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        endpoint_model,
                        COALESCE(NULLIF(VALUES(endpoint_model), ''), endpoint_model)
                    ),
                    context_window_tokens=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        context_window_tokens,
                        COALESCE(VALUES(context_window_tokens), context_window_tokens)
                    ),
                    max_output_tokens=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        max_output_tokens,
                        COALESCE(VALUES(max_output_tokens), max_output_tokens)
                    ),
                    message=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        message,
                        VALUES(message)
                    ),
                    best_score=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        best_score,
                        VALUES(best_score)
                    ),
                    final_submission_id=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        final_submission_id,
                        VALUES(final_submission_id)
                    ),
                    latest_submission_id=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        latest_submission_id,
                        VALUES(latest_submission_id)
                    ),
                    attempts_json=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        attempts_json,
                        VALUES(attempts_json)
                    ),
                    status=IF(
                        LOWER(status) IN (
                            'completed', 'failed', 'canceled', 'cancelled',
                            'cleanupfailed', 'cleanup_failed'
                        ),
                        status,
                        VALUES(status)
                    )
                """,
                (
                    task_id,
                    state.get("problem_id"),
                    str(state.get("problem_title") or "")[:255] if state.get("problem_title") is not None else None,
                    state.get("requested_by"),
                    str(state.get("harness") or "")[:32] if state.get("harness") is not None else None,
                    state.get("endpoint_id"),
                    str(state.get("endpoint_model") or "")[:255] if state.get("endpoint_model") is not None else None,
                    (
                        _safe_int(state.get("context_window_tokens"), 0) or None
                        if state.get("context_window_tokens") is not None
                        else None
                    ),
                    (
                        _safe_int(state.get("max_output_tokens"), 0) or None
                        if state.get("max_output_tokens") is not None
                        else None
                    ),
                    str(state.get("status") or "Pending")[:32],
                    state.get("message"),
                    best_score,
                    state.get("final_submission_id"),
                    state.get("latest_submission_id"),
                    _to_json_text(attempts, []),
                ),
            )
            cursor.execute(
                "SELECT status, message FROM agent_task_runs WHERE task_id=%s LIMIT 1",
                (task_id,),
            )
            persisted = cursor.fetchone() or {}
            if str(state.get("session_id") or "").strip():
                # 通用会话与兼容 agent_task_runs 必须在同一事务进入同一状态；
                # 否则 worker-lost 或最后一次瞬时写故障会留下永久 Running 会话。
                from oj_modules.agents.sessions import (
                    sync_agent_session_state_in_transaction,
                )

                session_state = dict(state)
                session_state["status"] = (
                    persisted.get("status") or session_state.get("status")
                )
                session_state["message"] = (
                    persisted.get("message") or session_state.get("message")
                )
                sync_agent_session_state_in_transaction(cursor, session_state)
        conn.commit()
        return {
            "status": persisted.get("status"),
            "message": persisted.get("message"),
        }
    finally:
        conn.close()


def cancel_agent_run_snapshot(task_id, message="任务已被手动终止"):
    """原子终止 Pending/Running 任务，并返回 ``(当前快照, 是否新终止)``。"""

    normalized_task_id = str(task_id or "").strip()
    if not normalized_task_id:
        return None, False

    ensure_agent_runs_table()
    cancel_message = str(message or "任务已被手动终止")[:1000]
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE agent_task_runs
                SET status='Canceled', message=%s
                WHERE task_id=%s
                  AND LOWER(status) IN ('pending', 'running')
                """,
                (cancel_message, normalized_task_id),
            )
            changed = cursor.rowcount > 0
            cursor.execute(
                """
                SELECT r.task_id, t.session_id, r.problem_id,
                       r.problem_title, r.requested_by, r.harness,
                       r.endpoint_id, r.endpoint_model,
                       r.context_window_tokens, r.max_output_tokens,
                       r.status, r.message,
                       r.best_score, r.final_submission_id,
                       r.latest_submission_id, r.attempts_json,
                       r.created_at, r.updated_at
                FROM agent_task_runs AS r
                LEFT JOIN agent_session_turns AS t ON t.task_id=r.task_id
                WHERE r.task_id=%s
                LIMIT 1
                """,
                (normalized_task_id,),
            )
            row = cursor.fetchone()
            if row is None:
                # create/begin/queue claim 会先原子提交 session、turn 与 outbox，
                # 再建立兼容的 agent_task_runs 快照。停止请求若恰好落在这个
                # 窗口，不能把“不存在 run 行”误判成“不存在任务”，否则后续
                # dispatcher 仍会投递。先从当前非终态会话读取冻结元数据，再
                # 用 sticky upsert 抢占 task_id；迟到的 Pending/Running 快照
                # 会被现有 upsert 终态规则挡住。
                cursor.execute(
                    """
                    SELECT s.session_id, s.problem_id, s.problem_title,
                           s.requested_by, s.harness, s.endpoint_id,
                           s.endpoint_model,
                           CASE
                               WHEN s.endpoint_source='user'
                               THEN ue.context_window_tokens
                               ELSE ge.context_window_tokens
                           END AS context_window_tokens,
                           CASE
                               WHEN s.endpoint_source='user'
                               THEN ue.max_output_tokens
                               ELSE ge.max_output_tokens
                           END AS max_output_tokens
                    FROM agent_sessions AS s
                    JOIN agent_session_turns AS t
                      ON t.session_id=s.session_id
                     AND t.task_id=s.current_task_id
                    LEFT JOIN llm_endpoints AS ge
                      ON s.endpoint_source='global'
                     AND ge.id=s.endpoint_id
                     AND ge.revision=s.endpoint_revision
                    LEFT JOIN agent_user_endpoints AS ue
                      ON s.endpoint_source='user'
                     AND ue.id=s.endpoint_id
                     AND ue.revision=s.endpoint_revision
                    WHERE t.task_id=%s
                      AND LOWER(s.status) IN ('pending', 'running')
                    LIMIT 1
                    """,
                    (normalized_task_id,),
                )
                pending_session = cursor.fetchone()
                if pending_session:
                    # message 必须先于 status 赋值；MySQL 按书写顺序计算
                    # ON DUPLICATE KEY UPDATE，二者都需要看写入前状态。
                    cursor.execute(
                        """
                        INSERT INTO agent_task_runs (
                            task_id, problem_id, problem_title, requested_by,
                            harness, endpoint_id, endpoint_model,
                            context_window_tokens, max_output_tokens,
                            status, message, best_score, attempts_json
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            'Canceled', %s, 0, '[]'
                        )
                        ON DUPLICATE KEY UPDATE
                            message=IF(
                                LOWER(status) IN ('pending', 'running'),
                                VALUES(message),
                                message
                            ),
                            status=IF(
                                LOWER(status) IN ('pending', 'running'),
                                VALUES(status),
                                status
                            )
                        """,
                        (
                            normalized_task_id,
                            pending_session.get("problem_id"),
                            pending_session.get("problem_title"),
                            pending_session.get("requested_by"),
                            pending_session.get("harness"),
                            pending_session.get("endpoint_id"),
                            pending_session.get("endpoint_model"),
                            pending_session.get("context_window_tokens"),
                            pending_session.get("max_output_tokens"),
                            cancel_message,
                        ),
                    )
                    changed = cursor.rowcount > 0
                    cursor.execute(
                        """
                        SELECT r.task_id, t.session_id, r.problem_id,
                               r.problem_title, r.requested_by, r.harness,
                               r.endpoint_id, r.endpoint_model,
                               r.context_window_tokens, r.max_output_tokens,
                               r.status,
                               r.message, r.best_score,
                               r.final_submission_id,
                               r.latest_submission_id, r.attempts_json,
                               r.created_at, r.updated_at
                        FROM agent_task_runs AS r
                        LEFT JOIN agent_session_turns AS t
                          ON t.task_id=r.task_id
                        WHERE r.task_id=%s
                        LIMIT 1
                        """,
                        (normalized_task_id,),
                    )
                    row = cursor.fetchone()
            if changed and row and str(row.get("session_id") or "").strip():
                # 取消 run、当前 turn、会话终态和 FIFO 暂停必须共享一次提交。
                # 后续协议级 interrupt/容器清理仍可把 Canceled 升级成
                # CleanupFailed，但 Web 进程不能在这两个阶段之间留下永久
                # Running 会话。
                from oj_modules.agents.sessions import (
                    sync_agent_session_state_in_transaction,
                )

                sync_agent_session_state_in_transaction(cursor, {
                    "task_id": normalized_task_id,
                    "session_id": row.get("session_id"),
                    "status": "Canceled",
                    "message": row.get("message") or "任务已被手动终止",
                    "_preserve_conclusion": True,
                })
        conn.commit()
    finally:
        conn.close()

    return (_agent_run_from_row(row) if row else None), changed


def is_agent_run_canceled(task_id):
    normalized_task_id = str(task_id or "").strip()
    if not normalized_task_id:
        return False
    ensure_agent_runs_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT 1 AS canceled
                FROM agent_task_runs
                WHERE task_id=%s
                  AND LOWER(status) IN ('canceled', 'cancelled')
                LIMIT 1
                """,
                (normalized_task_id,),
            )
            return cursor.fetchone() is not None
    finally:
        conn.close()


def _agent_run_from_row(row):
    if not row:
        return None
    attempts = _parse_json_text(row.get("attempts_json"), [])
    return {
        "task_id": row.get("task_id"),
        "session_id": row.get("session_id"),
        "problem_id": row.get("problem_id"),
        "problem_title": row.get("problem_title"),
        "requested_by": row.get("requested_by"),
        "harness": row.get("harness"),
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_model": row.get("endpoint_model"),
        "context_window_tokens": row.get("context_window_tokens"),
        "max_output_tokens": row.get("max_output_tokens"),
        "status": row.get("status"),
        "message": row.get("message"),
        "best_score": _safe_int(row.get("best_score"), 0),
        "final_submission_id": row.get("final_submission_id"),
        "latest_submission_id": row.get("latest_submission_id"),
        "attempts": attempts if isinstance(attempts, list) else [],
        "created_at": _format_datetime_value(row.get("created_at")),
        "updated_at": _format_datetime_value(row.get("updated_at")),
    }


def get_agent_run_by_task_id(task_id):
    if not task_id:
        return None
    ensure_agent_runs_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT r.task_id, t.session_id, r.problem_id,
                       r.problem_title, r.requested_by, r.harness,
                       r.endpoint_id, r.endpoint_model,
                       r.context_window_tokens, r.max_output_tokens,
                       r.status, r.message,
                       r.best_score, r.final_submission_id,
                       r.latest_submission_id, r.attempts_json,
                       r.created_at, r.updated_at
                FROM agent_task_runs AS r
                LEFT JOIN agent_session_turns AS t ON t.task_id=r.task_id
                WHERE r.task_id=%s
                LIMIT 1
                """,
                (task_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()

    return _agent_run_from_row(row)


def get_agent_runs_paginated(page=1, per_page=20):
    ensure_agent_runs_table()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM agent_task_runs")
            total = int((cursor.fetchone() or {}).get("total") or 0)
            total_pages = (total + per_page - 1) // per_page if total > 0 else 1
            offset = (max(1, int(page)) - 1) * int(per_page)
            cursor.execute(
                """
                SELECT r.task_id, r.problem_id, r.problem_title, r.requested_by,
                       r.harness, r.endpoint_id, r.endpoint_model,
                       r.context_window_tokens, r.max_output_tokens,
                       r.status, r.message, r.best_score, r.final_submission_id,
                       r.latest_submission_id, p.max_score AS problem_max_score,
                       r.created_at, r.updated_at
                FROM agent_task_runs AS r
                LEFT JOIN problems AS p ON p.id = r.problem_id
                ORDER BY r.id DESC
                LIMIT %s OFFSET %s
                """,
                (int(per_page), int(offset)),
            )
            rows = cursor.fetchall()
            return rows, total_pages
    finally:
        conn.close()


def ensure_settings_table():
    global _settings_table_ready
    _settings_table_ready = True


def get_setting(key, default=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT v FROM site_settings WHERE k=%s", (key,))
            row = cursor.fetchone()
            return (row and row.get('v')) if row else default
    finally:
        conn.close()


def set_setting(key, value):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO site_settings (k, v) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE v=VALUES(v)
                """,
                (key, str(value))
            )
        conn.commit()
    finally:
        conn.close()


def is_class_adjust_enabled():
    val = get_setting(CLASS_ADJUST_FLAG_KEY, default='1')
    return str(val) == '1'


def get_user_by_username(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (username,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE id=%s"
            cursor.execute(sql, (user_id,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_current_user():
    if 'username' not in session:
        return None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE username=%s"
            cursor.execute(sql, (session['username'],))
            user = cursor.fetchone()
    finally:
        conn.close()
    return user


def get_user_by_email(email):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM users WHERE email=%s"
            cursor.execute(sql, (email,))
            return cursor.fetchone()
    finally:
        conn.close()


# 用户名仍是部分历史表的业务键。改名时必须在同一事务里同步这些列，否则用户会丢失
# 提交记录、提交配额或功能模块中的历史归属。核心表缺失说明 schema 已损坏，必须中止；
# 可选功能表允许整表不存在，但只要表存在，约定的身份列就必须存在，避免 schema 漂移时
# 静默完成一半改名。
_RENAME_USER_REQUIRED_COLUMNS = (
    ('users', 'username'),
    ('submissions', 'username'),
    ('submission_limits', 'username'),
)

_RENAME_USER_OPTIONAL_COLUMNS = (
    # 成绩导入以登录用户名作为 student_id 查询。
    ('final_exam_scores', 'student_id'),
    ('plagiarism_records', 'username'),
    ('agent_task_runs', 'requested_by'),
    ('agent_sessions', 'requested_by'),
    ('ai_detection_results', 'username'),
    ('ranking_competitions', 'created_by'),
    ('ranking_submissions', 'username'),
    ('ranking_appeals', 'username'),
    ('ranking_appeals', 'admin_username'),
)


def _get_rename_user_columns(cursor):
    """返回当前 schema 中可安全同步的用户名列，并在 schema 漂移时 fail closed。"""
    expected_columns = _RENAME_USER_REQUIRED_COLUMNS + _RENAME_USER_OPTIONAL_COLUMNS
    expected_by_table = {}
    for table_name, column_name in expected_columns:
        expected_by_table.setdefault(table_name, set()).add(column_name)

    table_names = tuple(expected_by_table)
    placeholders = ', '.join(['%s'] * len(table_names))
    cursor.execute(
        f"""
        SELECT TABLE_NAME, COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA=DATABASE()
          AND TABLE_NAME IN ({placeholders})
        """,
        table_names,
    )
    rows = cursor.fetchall()
    actual_by_table = {}
    for row in rows:
        table_name = row.get('TABLE_NAME') or row.get('table_name')
        column_name = row.get('COLUMN_NAME') or row.get('column_name')
        if table_name and column_name:
            actual_by_table.setdefault(table_name, set()).add(column_name)

    missing_required = [
        f'{table_name}.{column_name}'
        for table_name, column_name in _RENAME_USER_REQUIRED_COLUMNS
        if column_name not in actual_by_table.get(table_name, set())
    ]
    if missing_required:
        raise RuntimeError(
            '用户名改名所需的核心数据列不存在: ' + ', '.join(missing_required)
        )

    for table_name, expected in expected_by_table.items():
        if table_name not in actual_by_table:
            # 可选功能未安装时允许整表不存在；核心表已在上面拦截。
            continue
        missing_columns = expected - actual_by_table[table_name]
        if missing_columns:
            missing = ', '.join(
                f'{table_name}.{column_name}' for column_name in sorted(missing_columns)
            )
            raise RuntimeError('用户名改名遇到不完整的数据表: ' + missing)

    return tuple(
        (table_name, column_name)
        for table_name, column_name in expected_columns
        if table_name != 'users'
        and column_name in actual_by_table.get(table_name, set())
    )


def _replace_plagiarism_matched_usernames(cursor, old_username, new_username):
    """精确替换查重记录中反规范化保存的用户名列表。"""
    cursor.execute(
        """SELECT id, matched_usernames
           FROM plagiarism_records
           WHERE matched_usernames LIKE %s
           FOR UPDATE""",
        (f'%{old_username}%',),
    )
    changed_rows = []
    for row in cursor.fetchall() or ():
        raw_value = row.get('matched_usernames')
        raw_text = str(raw_value or '')
        json_encoded = False
        names = None
        try:
            decoded = json.loads(raw_text)
            if isinstance(decoded, list):
                names = [str(item) for item in decoded]
                json_encoded = True
        except (TypeError, ValueError):
            pass
        if names is None:
            names = [part.strip() for part in raw_text.split(',') if part.strip()]

        if old_username not in names:
            continue

        replaced = []
        seen = set()
        for name in names:
            current = new_username if name == old_username else name
            if current in seen:
                continue
            seen.add(current)
            replaced.append(current)
        serialized = (
            json.dumps(replaced, ensure_ascii=False)
            if json_encoded
            else ','.join(replaced)
        )
        changed_rows.append((serialized, row['id']))

    for serialized, row_id in changed_rows:
        cursor.execute(
            'UPDATE plagiarism_records SET matched_usernames=%s WHERE id=%s',
            (serialized, row_id),
        )
    return len(changed_rows)


def create_user(username, password_hash, email, user_class):
    def operation(cursor):
        assert_identity_name_available(cursor, username)
        sql = (
            'INSERT INTO users (username, password_hash, email) '
            'VALUES (%s, %s, %s)'
        )
        cursor.execute(sql, (username, password_hash, email))
        user_id = cursor.lastrowid

        sql = 'UPDATE class_table SET class_cnt=class_cnt+1 WHERE class_en=%s'
        cursor.execute(sql, (user_class['class_en'],))

        sql = (
            'INSERT INTO user_class_map (user_id, class_en) '
            'VALUES (%s, %s)'
        )
        cursor.execute(sql, (user_id, user_class['class_en']))
        return int(user_id)

    return run_identity_namespace_transaction(
        operation,
        connection_factory=get_db_connection,
    )


def rename_user(user_id, new_username):
    """原子地修改用户名及所有仍以用户名作为用户身份的历史数据。

    返回原用户名。用户不存在时抛 ``LookupError``，新用户名已被占用时抛
    ``ValueError``；schema 不完整或任意数据更新失败都会回滚整个事务。
    """
    new_username = str(new_username or '').strip()
    if not new_username:
        raise ValueError('新用户名不能为空')

    def operation(cursor):
        cursor.execute(
            'SELECT id, username FROM users WHERE id=%s FOR UPDATE',
            (user_id,),
        )
        user = cursor.fetchone()
        if not user:
            raise LookupError('用户不存在')

        old_username = user['username']
        if old_username == new_username:
            return old_username

        assert_identity_name_available(
            cursor,
            new_username,
            exclude_user_id=int(user_id),
        )

        reference_columns = _get_rename_user_columns(cursor)
        if ('plagiarism_records', 'username') in reference_columns:
            _replace_plagiarism_matched_usernames(
                cursor, old_username, new_username,
            )
        for table_name, column_name in reference_columns:
            # 表名和列名只来自上面的模块级常量，不包含外部输入。
            cursor.execute(
                f'UPDATE `{table_name}` SET `{column_name}`=%s WHERE `{column_name}`=%s',
                (new_username, old_username),
            )

        cursor.execute(
            'UPDATE users SET username=%s WHERE id=%s',
            (new_username, user_id),
        )
        return old_username

    return run_identity_namespace_transaction(
        operation,
        connection_factory=get_db_connection,
    )


def get_user_classes(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
              SELECT m.class_en, ct.class_cn, ct.logo_seed
              FROM user_class_map m
              JOIN class_table ct ON m.class_en = ct.class_en
              WHERE m.user_id=%s
              ORDER BY m.class_en ASC
            """
            cursor.execute(sql, (user_id,))
            return cursor.fetchall() or []
    finally:
        conn.close()


def get_all_classes():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT class_en, class_cn, logo_seed "
                "FROM class_table ORDER BY class_cn ASC"
            )
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def get_users_in_classes(class_en_list):
    """返回选定班级（``class_en`` 列表）中的全部非管理员用户，按用户去重。

    一名学生即便同时属于多个被选班级，也只返回一行；``classes`` 保留全部
    匹配班级，``classes_display`` 按 ``class_en`` 稳定拼接。
    ``class_en_list`` 为空或全部非法时返回 ``[]``。
    """
    cleaned = [str(c).strip() for c in (class_en_list or []) if str(c).strip()]
    if not cleaned:
        return []
    placeholders = ','.join(['%s'] * len(cleaned))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT u.id AS user_id, u.username AS username, "
                "       ucm.class_en AS class_en, ct.class_cn AS class_cn "
                "FROM users u "
                "JOIN user_class_map ucm ON ucm.user_id = u.id "
                "JOIN class_table ct ON ct.class_en = ucm.class_en "
                f"WHERE ucm.class_en IN ({placeholders}) AND u.is_admin = 0 "
                "ORDER BY u.username ASC, ucm.class_en ASC"
            )
            cursor.execute(sql, tuple(cleaned))
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    users = {}
    for row in rows:
        user_id = int(row["user_id"])
        item = users.setdefault(
            user_id,
            {
                "user_id": user_id,
                "username": row["username"],
                "classes": [],
            },
        )
        item["classes"].append({
            "class_en": row["class_en"],
            "class_cn": row.get("class_cn") or row["class_en"],
        })

    result = []
    for item in users.values():
        display = " / ".join(cls["class_cn"] for cls in item["classes"])
        item["classes_display"] = display
        result.append(item)
    return result


def ensure_class_homework_columns(class_en):
    return _schema_is_managed_at_startup(class_en)


def get_class_by_en(class_en):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT class_en, class_cn, logo_seed "
                "FROM class_table WHERE class_en=%s"
            )
            cursor.execute(sql, (class_en,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_class_by_cn(class_cn):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT class_en, class_cn, logo_seed "
                "FROM class_table WHERE class_cn=%s"
            )
            cursor.execute(sql, (class_cn,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_all_problems():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT id,title,cnt,type,lang,max_score,time_limit_ms,"
                "written_grading_mode,written_grading_prompt,"
                "programming_grading_mode,output_image_filename,programming_grading_prompt,"
                "llm_endpoint_bindings "
                "FROM problems ORDER BY id ASC"
            )
            cursor.execute(sql)
            rows = cursor.fetchall()
            for row in rows:
                row["llm_endpoint_bindings"] = deserialize_problem_llm_bindings(
                    row.get("llm_endpoint_bindings")
                )
            return rows
    finally:
        conn.close()


def get_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT id,title,content,initial_code,test_code,cnt,forbidden_func,type,lang,max_score,"
                "time_limit_ms,submission_limit,written_grading_mode,written_grading_prompt,"
                "programming_grading_mode,output_image_filename,programming_grading_prompt,"
                "llm_endpoint_bindings "
                "FROM problems WHERE id=%s"
            )
            cursor.execute(sql, (problem_id,))
            row = cursor.fetchone()
            if row:
                row["llm_endpoint_bindings"] = deserialize_problem_llm_bindings(
                    row.get("llm_endpoint_bindings")
                )
            return row
    finally:
        conn.close()


def get_problem_title(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT id,title,cnt,type,lang,max_score,time_limit_ms,submission_limit,"
                "written_grading_mode,written_grading_prompt,"
                "programming_grading_mode,output_image_filename,programming_grading_prompt,"
                "llm_endpoint_bindings "
                "FROM problems WHERE id=%s"
            )
            cursor.execute(sql, (problem_id,))
            row = cursor.fetchone()
            if row:
                row["llm_endpoint_bindings"] = deserialize_problem_llm_bindings(
                    row.get("llm_endpoint_bindings")
                )
            return row
    finally:
        conn.close()


def create_problem(
    title,
    content,
    initial_code='',
    test_code='',
    forbidden_func='',
    type=1,
    lang='matlab',
    time_limit_ms=2000,
    submission_limit=10,
    programming_grading_mode=1,
    output_image_filename='output.png',
    programming_grading_prompt='',
    written_grading_mode=1,
    written_grading_prompt='',
    llm_endpoint_bindings=None,
):
    conn = get_db_connection()
    try:
        max_score = (
            1
            if int(type) == 1 and str(lang or '').strip().lower() == 'lean4'
            else (0 if int(type) == 1 else 5)
        )
        use_programming_mode = 1
        use_output_image_filename = "output.png"
        use_programming_prompt = ""
        use_written_mode = 1
        use_written_prompt = ""
        if int(type) == 1:
            try:
                use_programming_mode = int(programming_grading_mode)
            except Exception:
                use_programming_mode = 1
            if use_programming_mode not in (1, 2, 3):
                use_programming_mode = 1
            use_output_image_filename = normalize_output_image_filename(output_image_filename)
            use_programming_prompt = str(programming_grading_prompt or "").strip()
        elif int(type) == 2:
            try:
                use_written_mode = int(written_grading_mode)
            except Exception:
                use_written_mode = 1
            if use_written_mode not in (1, 2, 3, 4):
                use_written_mode = 1
            use_written_prompt = str(written_grading_prompt or "").strip()
        normalized_llm_bindings = normalize_problem_llm_bindings(
            llm_endpoint_bindings,
            problem_type=type,
            programming_grading_mode=use_programming_mode,
        )
        with conn.cursor() as cursor:
            sql = """INSERT INTO problems
                     (title, content, initial_code, test_code, forbidden_func, type, lang, max_score, time_limit_ms, submission_limit,
                      programming_grading_mode, output_image_filename, programming_grading_prompt,
                      written_grading_mode, written_grading_prompt, llm_endpoint_bindings)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(
                sql,
                (
                    title,
                    content,
                    initial_code,
                    test_code,
                    forbidden_func,
                    type,
                    lang,
                    max_score,
                    time_limit_ms,
                    submission_limit,
                    use_programming_mode,
                    use_output_image_filename,
                    use_programming_prompt,
                    use_written_mode,
                    use_written_prompt,
                    serialize_problem_llm_bindings(normalized_llm_bindings),
                ),
            )
            problem_id = cursor.lastrowid
        conn.commit()
        return problem_id
    finally:
        conn.close()


def upsert_user_problem_max_score(user_id, problem_id, score):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO max_score (userid, problem_id, score)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE score=VALUES(score)
                """,
                (user_id, problem_id, score),
            )
        conn.commit()
    finally:
        conn.close()


def upsert_user_problem_max_score_if_higher(user_id, problem_id, score):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO max_score (userid, problem_id, score)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                score = IF(score < VALUES(score), VALUES(score), score)
                """,
                (user_id, problem_id, score),
            )
        conn.commit()
    finally:
        conn.close()


def delete_user_problem_max_score(user_id, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM max_score WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
        conn.commit()
    finally:
        conn.close()


def insert_user_problem_ac_record_if_absent(user_id, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT IGNORE INTO ac_record (userid, problem_id, is_ac)
                VALUES (%s, %s, 1)
                """,
                (user_id, problem_id),
            )
            inserted = cursor.rowcount > 0
        conn.commit()
        return inserted
    finally:
        conn.close()


def update_problem(
    problem_id,
    new_title,
    new_content,
    new_initial_code='',
    new_test_code='',
    new_forbidden_func='',
    new_lang='matlab',
    new_time_limit_ms=None,
    new_submission_limit=None,
    new_programming_grading_mode=None,
    new_output_image_filename=None,
    new_programming_grading_prompt=None,
    new_written_grading_mode=None,
    new_written_grading_prompt=None,
    new_llm_endpoint_bindings=_UNSET,
):
    conn = get_db_connection()
    try:
        programming_mode_val = None
        if new_programming_grading_mode is not None:
            try:
                programming_mode_val = int(new_programming_grading_mode)
            except Exception:
                programming_mode_val = 1
            if programming_mode_val not in (1, 2, 3):
                programming_mode_val = 1
        output_image_filename_val = None
        if new_output_image_filename is not None:
            output_image_filename_val = normalize_output_image_filename(new_output_image_filename)
        programming_prompt_val = None
        if new_programming_grading_prompt is not None:
            programming_prompt_val = str(new_programming_grading_prompt or "").strip()
        mode_val = None
        if new_written_grading_mode is not None:
            try:
                mode_val = int(new_written_grading_mode)
            except Exception:
                mode_val = 1
            if mode_val not in (1, 2, 3, 4):
                mode_val = 1
        prompt_val = None
        if new_written_grading_prompt is not None:
            prompt_val = str(new_written_grading_prompt or "").strip()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT lang, max_score FROM problems WHERE id=%s",
                (problem_id,),
            )
            current_score_row = cursor.fetchone()
            if not current_score_row:
                raise LookupError("题目不存在")
            old_lang = str(current_score_row.get("lang") or '').strip().lower()
            normalized_new_lang = str(new_lang or '').strip().lower()
            if normalized_new_lang == 'lean4':
                next_max_score = 1
            elif old_lang == 'lean4':
                next_max_score = 0
            else:
                next_max_score = current_score_row.get("max_score")

            assignments = [
                "title=%s",
                "content=%s",
                "initial_code=%s",
                "test_code=%s",
                "forbidden_func=%s",
                "lang=%s",
                "time_limit_ms=%s",
                "submission_limit=%s",
                "programming_grading_mode=%s",
                "output_image_filename=%s",
                "programming_grading_prompt=%s",
                "written_grading_mode=%s",
                "written_grading_prompt=%s",
                "max_score=%s",
            ]
            values = [
                new_title,
                new_content,
                new_initial_code,
                new_test_code,
                new_forbidden_func,
                new_lang,
                new_time_limit_ms,
                new_submission_limit,
                programming_mode_val if programming_mode_val is not None else 1,
                output_image_filename_val if output_image_filename_val is not None else "output.png",
                programming_prompt_val if programming_prompt_val is not None else "",
                mode_val if mode_val is not None else 1,
                prompt_val if prompt_val is not None else "",
                next_max_score,
            ]
            if new_llm_endpoint_bindings is not _UNSET:
                cursor.execute(
                    "SELECT type, programming_grading_mode FROM problems WHERE id=%s",
                    (problem_id,),
                )
                current_problem = cursor.fetchone()
                if not current_problem:
                    raise LookupError("题目不存在")
                normalized_llm_bindings = normalize_problem_llm_bindings(
                    new_llm_endpoint_bindings,
                    problem_type=current_problem.get("type"),
                    programming_grading_mode=(
                        programming_mode_val
                        if programming_mode_val is not None
                        else current_problem.get("programming_grading_mode")
                    ),
                )
                assignments.append("llm_endpoint_bindings=%s")
                values.append(serialize_problem_llm_bindings(normalized_llm_bindings))

            values.append(problem_id)
            cursor.execute(
                f"UPDATE problems SET {', '.join(assignments)} WHERE id=%s",
                tuple(values),
            )
        conn.commit()
    finally:
        conn.close()


def _lock_submission_user_with_cursor(cursor, *, username, user_id=None):
    """共享锁定提交用户并返回当前规范身份，防止改名与提交交错产生孤儿记录。

    这里不能取得排他锁：编程提交随后会进入仓库快照的文件系统共享锁，而仓库写者
    按相反方向先取得文件系统排他锁、再通过外键取得 ``users`` 父行共享锁。若这里
    使用 ``FOR UPDATE``，两个锁域会形成 InnoDB 无法检测的环。``FOR SHARE`` 仍会
    阻止用户行被改名或删除，并与仓库写入所需的外键共享锁兼容；提交配额继续由
    ``submission_limits`` 自己的排他行锁串行化。
    """
    if user_id is not None:
        try:
            normalized_user_id = int(user_id)
        except (TypeError, ValueError) as exc:
            raise ValueError('user_id must be an integer') from exc
        cursor.execute(
            """SELECT id, username, is_admin
               FROM users WHERE id=%s FOR SHARE""",
            (normalized_user_id,),
        )
    else:
        normalized_username = str(username or '').strip()
        if not normalized_username:
            raise ValueError('username must not be empty')
        cursor.execute(
            """SELECT id, username, is_admin
               FROM users WHERE username=%s FOR SHARE""",
            (normalized_username,),
        )

    user = cursor.fetchone()
    if not user:
        raise LookupError('提交用户不存在或用户名已变更')
    return user


def create_submission(
    problem_id,
    problem_title,
    username,
    code,
    score,
    test_points,
    status="Pending",
    prompt_text=None,
    generated_from_prompt=False,
    prompt_generation_error=None,
    submission_limit=None,
    user_id=None,
    lean_workspace=None,
):
    """创建提交，并在同一事务内锁定用户身份及可选提交配额。"""
    # 先在获取连接前查好题目，避免占着连接再去 get_db_connection() 形成嵌套占用、放大连接池压力。
    problem = get_problem(problem_id)
    problem_type = problem['type']
    subid = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = _lock_submission_user_with_cursor(
                cursor, username=username, user_id=user_id,
            )
            effective_username = user['username']

            if submission_limit is not None:
                _reserve_submission_quota_with_cursor(
                    cursor,
                    username=effective_username,
                    problem_id=problem_id,
                    max_submissions=submission_limit,
                )

            if problem_type == 2:
                # 书面题首次提交会更新题目/班级计数。先锁题目行，使同一题目的
                # 并发首次提交串行化，且计数与 submissions INSERT 同事务提交。
                cursor.execute("SELECT id FROM problems WHERE id=%s FOR UPDATE", (problem_id,))
                sql = "SELECT COUNT(*) FROM submissions WHERE username=%s AND problem_id=%s"
                cursor.execute(sql, (effective_username, problem_id))
                total_submissions = cursor.fetchone()['COUNT(*)']
                if total_submissions == 0:
                    if user["is_admin"] != 1:
                        # user_class_map 是班级关系的唯一事实源。对学生所在、且包含本题
                        # 的班级表各自 complete_cnt+1（不含本题的班级表 0 行命中）。
                        cursor.execute(
                            "SELECT class_en FROM user_class_map WHERE user_id=%s", (user["id"],))
                        class_list = [r["class_en"] for r in (cursor.fetchall() or []) if r.get("class_en")]
                        for cen in class_list:
                            try:
                                tbl = safe_table_name(cen)
                                cursor.execute(
                                    f"UPDATE {tbl} SET complete_cnt=complete_cnt+1 WHERE problem_id=%s",
                                    (problem_id,))
                            except Exception:
                                pass   # 班级名异常/班级表缺失不影响提交本身
                    sql = "UPDATE problems SET cnt=cnt+1 WHERE id=%s"
                    cursor.execute(sql, (problem_id,))

            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_points])
            sql = """INSERT INTO submissions
                     (problem_id, username, code, score, test_points, status, problem_title, problem_type,
                      prompt_text, generated_from_prompt, prompt_generation_error)
                     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            cursor.execute(sql, (
                problem_id,
                effective_username,
                code,
                score,
                test_points_str,
                status,
                problem_title,
                problem_type,
                prompt_text,
                1 if generated_from_prompt else 0,
                prompt_generation_error,
            ))
            # 需要在 cursor 生命周期内读取 lastrowid，避免偶发拿到无效 id
            subid = cursor.lastrowid
            if not subid:
                raise RuntimeError("create_submission: failed to get valid submission id")

            if lean_workspace is not None:
                from oj_modules.problems.lean_workspace import (
                    bind_submission_workspace_with_cursor,
                )
                bind_submission_workspace_with_cursor(
                    cursor,
                    submission_id=int(subid),
                    problem_id=int(problem_id),
                    revision=str(lean_workspace.get("revision") or ""),
                    files=lean_workspace.get("files"),
                )

            # 编程提交必须在返回、入队前绑定不可变仓库快照。捕获与 submissions
            # INSERT 共用事务；快照失败会让整个提交回滚，禁止悄悄改用之后可能变化的
            # 实时仓库。书面题不使用代码仓库，不创建无意义快照。
            try:
                is_programming_submission = int(problem_type) == 1
            except (TypeError, ValueError):
                is_programming_submission = False
            if is_programming_submission:
                from oj_modules.submissions.repository_snapshots import (
                    capture_submission_repository_snapshot,
                )
                capture_submission_repository_snapshot(
                    cursor,
                    submission_id=int(subid),
                    user_id=int(user["id"]),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    task_name = str(current_context().get('task_name') or '')
    if generated_from_prompt:
        origin = 'promptly'
    elif task_name.startswith('oj.agent.'):
        origin = 'agent'
    elif str(problem_type).strip() == '2':
        origin = 'written'
    else:
        origin = 'web'
    emit_audit(
        'submissions',
        action='submission.created',
        outcome='success',
        message='题目提交已创建',
        submission={
            'id': int(subid),
            'kind': 'problem',
            'origin': origin,
            'initial_status': status,
            'generated_from_prompt': bool(generated_from_prompt),
            'score': score,
            'test_point_count': len(test_points or ()),
            'submission_limit': submission_limit,
        },
        problem={'id': problem_id, 'type': problem_type},
        user={'id': user.get('id'), 'name': effective_username},
        content={
            'code': content_fingerprint(code),
            'prompt': content_fingerprint(prompt_text),
        },
    )

    # 缓存和统计不属于提交事务；主记录已成功持久化后，不应因派生路径
    # 短暂失败向用户返回 500，否则用户重试会产生实际已提交的重复记录。
    try:
        refresh_submission_status_snapshot(subid)
    except Exception:
        logger.exception('提交状态快照刷新失败', extra={'submission_id': subid})
    bump_daily_submission_count()
    return subid


def get_latest_written_submission(username, problem_id):
    """Return the most recent submission row for a user+problem, or None."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM submissions WHERE username=%s AND problem_id=%s ORDER BY id DESC LIMIT 1",
                (username, problem_id),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def _written_submission_snapshot_matches(current, expected):
    """比较人工覆盖依赖的并发控制字段。"""
    if not isinstance(expected, dict):
        return False
    for field in (
        'id', 'username', 'problem_id', 'test_points',
        'score', 'status', 'created_at',
    ):
        current_value = current.get(field)
        expected_value = expected.get(field)
        if current_value == expected_value:
            continue
        if str(current_value) != str(expected_value):
            return False
    return True


def overwrite_written_submission(
    submission_id,
    new_filename,
    *,
    submission_limit=None,
    username=None,
    problem_id=None,
    user_id=None,
    expected_submission=None,
):
    """CAS 更新人工书面提交，并在同一事务预占配额。

    文件发布层必须先把不可变 generation 完整落盘，再传入它在文件锁内读取的
    ``expected_submission``。本函数在 ``FOR UPDATE`` 下重新读取权威快照；任一字段已
    被评分或其他请求推进时整笔事务回滚，绝不靠事后盲写旧快照补偿。
    """
    if not isinstance(expected_submission, dict):
        raise ValueError('人工书面作业覆盖必须提供预期提交快照')
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            effective_username = None
            if submission_limit is not None:
                if problem_id is None:
                    raise ValueError('预占提交配额时必须提供 problem_id')
                user = _lock_submission_user_with_cursor(
                    cursor, username=username, user_id=user_id,
                )
                effective_username = user['username']
            cursor.execute(
                """SELECT id, username, problem_id, test_points,
                          score, status, created_at
                   FROM submissions WHERE id=%s FOR UPDATE""",
                (submission_id,),
            )
            submission = cursor.fetchone()
            if not submission:
                raise LookupError('待覆盖的书面作业提交不存在')
            if problem_id is not None and int(submission['problem_id']) != int(problem_id):
                raise ValueError('待覆盖提交与题目不匹配')
            if effective_username is not None and submission['username'] != effective_username:
                raise ValueError('待覆盖提交与当前用户不匹配')
            if not _written_submission_snapshot_matches(
                    submission, expected_submission,
            ):
                raise RuntimeError('待覆盖的书面作业已被其他流程更新')

            if submission_limit is not None:
                _reserve_submission_quota_with_cursor(
                    cursor,
                    effective_username,
                    problem_id,
                    submission_limit,
                )

            test_points_str = json.dumps(new_filename, ensure_ascii=False)
            cursor.execute(
                """UPDATE submissions
                      SET test_points=%s, score=0, status='Pending',
                          created_at=NOW()
                    WHERE id=%s""",
                (test_points_str, submission_id),
            )
            if int(cursor.rowcount or 0) != 1:
                raise RuntimeError('书面作业提交指针更新失败')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    try:
        refresh_submission_status_snapshot(submission_id)
    except Exception:
        # 数据库事务已成功；派生快照不可让调用方误判为需要回滚。
        logger.exception(
            '书面作业覆盖后状态快照刷新失败',
            extra={'submission_id': submission_id},
        )
    emit_audit(
        'submissions',
        action='submission.revision.committed',
        outcome='success',
        message='人工书面提交的新版本已切换',
        submission={
            'id': int(submission_id),
            'kind': 'written',
            'origin': 'manual_overwrite',
            'initial_status': 'Pending',
            'previous_status': submission.get('status'),
        },
        problem={'id': submission.get('problem_id')},
        user={'id': user_id, 'name': submission.get('username')},
    )
    return submission


def get_submissions_by_user_and_problem(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s AND problem_id=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username, problem_id))
            submissions = cursor.fetchall()
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
                submission['problem_type'] = submission['problem_type']
            return submissions
    finally:
        conn.close()


def get_submission_summaries_by_user_and_problem(username, problem_id, limit=None):
    """
    仅返回列表页展示所需字段，避免把 code/test_points 大字段拉出。
    limit 不为空时只取最近 N 条（题目详情页只展示最近几条，无需拉全部）。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, problem_id, username, score, status, problem_title, created_at
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
            """
            params = (username, problem_id)
            if limit is not None:
                sql += " LIMIT %s"
                params = (username, problem_id, int(limit))
            cursor.execute(sql, params)
            return cursor.fetchall()
    finally:
        conn.close()


def get_submission_summaries_by_user_and_problem_paginated(username, problem_id, page=1, per_page=30):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = """
                SELECT COUNT(*) AS total
                FROM submissions
                WHERE username=%s AND problem_id=%s
            """
            cursor.execute(count_sql, (username, problem_id))
            total = cursor.fetchone()['total']
            total_pages = (total + per_page - 1) // per_page

            data_sql = """
                SELECT id, problem_id, username, score, status, problem_title, created_at
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """
            offset = (page - 1) * per_page
            cursor.execute(data_sql, (username, problem_id, per_page, offset))
            return cursor.fetchall(), total_pages
    finally:
        conn.close()


_SUBMISSION_LIST_STATUS_FILTERS = {
    "accepted": ("s.status = %s", ("Accepted",)),
    "wrong_answer": ("s.status = %s", ("Wrong Answer",)),
    "unaccepted": ("s.status = %s", ("Unaccepted",)),
    "compile_error": ("s.status = %s", ("Compile Error",)),
    "output_limit": (
        "s.status = %s",
        ("Output Limit Exceeded",),
    ),
    "in_progress": (
        "s.status IN (%s, %s, %s, %s)",
        ("Pending", "Waiting", "Running", "Generating"),
    ),
    "other": (
        """
        (
            s.status IS NULL
            OR s.status NOT IN (
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        )
        """,
        (
            "Accepted",
            "Wrong Answer",
            "Unaccepted",
            "Compile Error",
            "Output Limit Exceeded",
            "Pending",
            "Waiting",
            "Running",
            "Generating",
        ),
    ),
}


def normalize_submission_list_status_filter(value):
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _SUBMISSION_LIST_STATUS_FILTERS else ""


def _build_submission_list_where(
    *,
    username=None,
    query="",
    status_filter="",
    problem_id=None,
):
    clauses = []
    params = []

    if username:
        clauses.append("s.username = %s")
        params.append(str(username))

    normalized_status = normalize_submission_list_status_filter(status_filter)
    if normalized_status:
        status_sql, status_params = _SUBMISSION_LIST_STATUS_FILTERS[normalized_status]
        clauses.append(status_sql)
        params.extend(status_params)

    try:
        normalized_problem_id = int(problem_id) if problem_id not in (None, "") else None
    except (TypeError, ValueError):
        normalized_problem_id = None
    if normalized_problem_id is not None and normalized_problem_id > 0:
        clauses.append("s.problem_id = %s")
        params.append(normalized_problem_id)

    search_text = str(query or "").strip()
    if search_text:
        search_clauses = ["s.problem_title LIKE %s"]
        search_params = [f"%{search_text}%"]
        if search_text.isdigit():
            search_clauses.extend(("s.id = %s", "s.problem_id = %s"))
            search_params.extend((int(search_text), int(search_text)))
        if username is None:
            search_clauses.append("s.username LIKE %s")
            search_params.append(f"%{search_text}%")
        clauses.append("(" + " OR ".join(search_clauses) + ")")
        params.extend(search_params)

    where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where_sql, tuple(params)


def get_filtered_submissions_paginated(
    *,
    username=None,
    page=1,
    per_page=30,
    query="",
    status_filter="",
    problem_id=None,
    include_test_points=True,
):
    """按权限范围筛选提交列表，并在同一次分页查询中带出列表展示字段。"""
    page = max(1, int(page or 1))
    per_page = max(1, min(100, int(per_page or 30)))
    where_sql, params = _build_submission_list_where(
        username=username,
        query=query,
        status_filter=status_filter,
        problem_id=problem_id,
    )
    test_points_column = ", s.test_points" if include_test_points else ""

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS total FROM submissions s" + where_sql,
                params,
            )
            total = int((cursor.fetchone() or {}).get("total") or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = min(page, total_pages)
            offset = (page - 1) * per_page

            cursor.execute(
                f"""
                SELECT
                    s.id,
                    s.problem_id,
                    s.username,
                    s.status,
                    s.score,
                    s.problem_title,
                    s.problem_type,
                    s.created_at
                    {test_points_column},
                    p.lang,
                    p.max_score
                FROM submissions s
                LEFT JOIN problems p ON p.id = s.problem_id
                {where_sql}
                ORDER BY s.id DESC
                LIMIT %s OFFSET %s
                """,
                params + (per_page, offset),
            )
            rows = cursor.fetchall()
    finally:
        conn.close()

    if include_test_points:
        for row in rows:
            points = _parse_test_points(row.get("test_points"))
            row["test_points"] = [
                point for point in points
                if isinstance(point, dict)
            ]
            row["test_points_count"] = len(row["test_points"])

    return rows, page, total_pages


def get_submission_problem_options(*, username=None):
    """返回当前权限范围内确实出现过提交的题目，供统一提交页筛选。"""
    where_sql = " WHERE s.username = %s" if username else ""
    params = (str(username),) if username else ()
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT
                    s.problem_id,
                    COALESCE(
                        MAX(NULLIF(p.title, '')),
                        MAX(NULLIF(s.problem_title, '')),
                        CONCAT('Problem ', s.problem_id)
                    ) AS problem_title,
                    MAX(s.id) AS latest_submission_id
                FROM submissions s
                LEFT JOIN problems p ON p.id = s.problem_id
                {where_sql}
                GROUP BY s.problem_id
                ORDER BY latest_submission_id DESC
                """,
                params,
            )
            return cursor.fetchall()
    finally:
        conn.close()


def get_submissions_by_user(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """SELECT * FROM submissions
                     WHERE username=%s
                     ORDER BY id DESC"""
            cursor.execute(sql, (username,))
            submissions = cursor.fetchall()
            for submission in submissions:
                if submission['test_points']:
                    submission['test_points'] = [
                        json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                    ]
            return submissions
    finally:
        conn.close()


def get_latest_submission_code_by_user_and_problem(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, code, score
                FROM submissions
                WHERE username=%s AND problem_id=%s
                ORDER BY id DESC
                LIMIT 1
            """
            cursor.execute(sql, (username, problem_id))
            return cursor.fetchone()
    finally:
        conn.close()


def get_submission_by_id(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM submissions WHERE id=%s"
            cursor.execute(sql, (submission_id,))
            submission = cursor.fetchone()
            if submission and submission['test_points']:
                submission['test_points'] = [
                    json.loads(line) for line in submission['test_points'].strip().split('\n') if line.strip()
                ]
            return submission
    finally:
        conn.close()


def get_submission_panel_by_id(submission_id):
    """读取详情面板所需的最小提交字段，避免加载源码与 Prompt。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    username,
                    problem_id,
                    problem_title,
                    problem_type,
                    status,
                    score,
                    created_at,
                    test_points
                FROM submissions
                WHERE id=%s
                """,
                (submission_id,),
            )
            submission = cursor.fetchone()
            if submission:
                submission["test_points"] = _parse_test_points(
                    submission.get("test_points")
                )
            return submission
    finally:
        conn.close()


def archive_submission_by_id(submission_id, raise_errors=False):
    """Archive a submission and its DB metadata."""
    try:
        submission = get_submission_by_id(submission_id)
        if not submission:
            return None
        problem = get_problem(submission.get('problem_id'))
        user = get_user_by_username(submission.get('username'))
        classes = []
        if user and user.get('id') is not None:
            classes = get_user_classes(user['id'])
        from oj_modules.submissions.archive import archive_submission_record
        return archive_submission_record(submission, problem, user, classes)
    except Exception as e:
        if raise_errors:
            raise
        print(f"[SubmissionArchive] failed to archive submission {submission_id}: {e}")
        return None


def archive_submission_file_by_id(submission_id, source_path, preferred_filename=None, raise_errors=False):
    """Archive an uploaded submission file."""
    try:
        archive_submission_by_id(submission_id, raise_errors=raise_errors)
        from oj_modules.submissions.archive import archive_uploaded_submission_file
        archived_path = archive_uploaded_submission_file(
            submission_id, source_path, preferred_filename,
        )
        if archived_path:
            artifact = safe_file_fingerprint(
                source_path,
                artifact_type='written',
            )
            emit_audit(
                'submissions',
                action='submission.artifact.archived',
                outcome='success',
                message='题目提交文件已归档',
                submission={'id': int(submission_id), 'kind': 'written'},
                artifact=artifact,
            )
        return archived_path
    except Exception as e:
        if raise_errors:
            raise
        print(f"[SubmissionArchive] failed to archive file for submission {submission_id}: {e}")
        return None


def get_incomplete_submissions():
    """返回所有尚未完成评测的提交（程序题 + 书面作业），用于进程启动时重新入队。

    status ∈ ('Pending', 'Waiting', 'Running', 'Generating')：
      - Pending/Waiting：已创建但从未开始评测（队列在重启时丢失）；
      - Running：重启那一刻正评测到一半、被杀掉的任务。
    返回每行的 id / problem_type / status / created_at，按 id 升序（早提交先评）。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT id, problem_type, status, created_at FROM submissions "
                "WHERE status IN ('Pending', 'Waiting', 'Running', 'Generating') "
                "ORDER BY id ASC"
            )
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def get_submissions_in_time_range(start, end):
    """返回 created_at 落在 [start, end] 内的所有提交（用于按时间范围重测）。

    返回每行的 id / problem_type / status / created_at，按 id 升序。
    start/end 为 'YYYY-MM-DD HH:MM:SS' 字符串。
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT id, problem_type, status, created_at FROM submissions "
                "WHERE created_at BETWEEN %s AND %s "
                "ORDER BY id ASC"
            )
            cursor.execute(sql, (start, end))
            return cursor.fetchall()
    finally:
        conn.close()


def get_cached_ai_code_marks_for_submission(submission):
    if not submission or not isinstance(submission, dict):
        return None

    raw = submission.get('ai_code_marks_json')
    if not raw:
        return None

    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as e:
        print(f"[AI Code Marks] 缓存 JSON 解析失败(submission_id={submission.get('id')}): {e}")
        return None

    if not isinstance(data, dict):
        return None

    code_used_raw = data.get('code_used')
    if code_used_raw is None:
        code_used_raw = submission.get('code') or ''
    code_used = str(code_used_raw).replace('\r\n', '\n').replace('\r', '\n')
    issues = _normalize_ai_code_issues(data.get('issues') or [], code_used, max_issues=8)
    summary = str(data.get('summary') or '').strip()
    image_mismatch_analysis = str(data.get('image_mismatch_analysis') or '').strip()
    image_analysis_test_index = data.get('image_analysis_test_index')
    cached_at = str(data.get('generated_at') or '').strip()

    return {
        "success": True,
        "issues": issues,
        "summary": summary,
        "code_used": code_used,
        "image_mismatch_analysis": image_mismatch_analysis,
        "image_analysis_test_index": image_analysis_test_index,
        "cached": True,
        "cached_at": cached_at,
    }


def save_submission_ai_code_marks_json(submission_id, payload):
    if not payload or not isinstance(payload, dict):
        return False

    payload_text = json.dumps(payload, ensure_ascii=False)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET ai_code_marks_json=%s WHERE id=%s"
            cursor.execute(sql, (payload_text, submission_id))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_user_submission_count(username, problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT submission_count FROM submission_limits WHERE username=%s AND problem_id=%s"
            cursor.execute(sql, (username, problem_id))
            result = cursor.fetchone()
            return result['submission_count'] if result else 0
    finally:
        conn.close()


def _normalize_submission_limit(max_submissions):
    try:
        return max(0, int(max_submissions))
    except (TypeError, ValueError) as exc:
        raise ValueError("max_submissions must be an integer") from exc


def _reserve_submission_quota_with_cursor(cursor, username, problem_id, max_submissions):
    """在调用方事务内锁定并递增配额；唯一键负责序列化首次并发创建。"""
    limit = _normalize_submission_limit(max_submissions)
    cursor.execute(
        """INSERT INTO submission_limits (username, problem_id, submission_count)
           VALUES (%s, %s, 0)
           ON DUPLICATE KEY UPDATE problem_id=VALUES(problem_id)""",
        (username, problem_id),
    )
    cursor.execute(
        """SELECT submission_count FROM submission_limits
           WHERE username=%s AND problem_id=%s FOR UPDATE""",
        (username, problem_id),
    )
    row = cursor.fetchone() or {}
    current_count = int(row.get('submission_count') or 0)
    if current_count >= limit:
        raise SubmissionLimitExceeded(username, problem_id, limit, current_count)
    cursor.execute(
        """UPDATE submission_limits
           SET submission_count=submission_count+1, updated_at=CURRENT_TIMESTAMP
           WHERE username=%s AND problem_id=%s""",
        (username, problem_id),
    )
    return current_count + 1


def reserve_submission_quota(
    username,
    problem_id,
    max_submissions=10,
    *,
    user_id=None,
):
    """锁定当前用户身份后原子预占一次提交配额。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            user = _lock_submission_user_with_cursor(
                cursor, username=username, user_id=user_id,
            )
            count = _reserve_submission_quota_with_cursor(
                cursor, user['username'], problem_id, max_submissions,
            )
        conn.commit()
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _release_submission_quota_with_cursor(cursor, username, problem_id):
    cursor.execute(
        """UPDATE submission_limits
           SET submission_count=GREATEST(submission_count-1, 0),
               updated_at=CURRENT_TIMESTAMP
           WHERE username=%s AND problem_id=%s AND submission_count>0""",
        (username, problem_id),
    )
    return cursor.rowcount > 0


def release_submission_quota(username, problem_id):
    """补偿一次已预占但未形成有效提交的配额；计数不会降到零以下。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            released = _release_submission_quota_with_cursor(
                cursor, username, problem_id,
            )
        conn.commit()
        return released
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_submission_archive_failed(submission_id, *, release_quota=False):
    """原子标记归档失败，并按需归还该提交实际身份对应的配额。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT id, username, problem_id
                   FROM submissions WHERE id=%s FOR UPDATE""",
                (submission_id,),
            )
            submission = cursor.fetchone()
            if not submission:
                raise LookupError('提交不存在')

            released = False
            if release_quota:
                released = _release_submission_quota_with_cursor(
                    cursor,
                    submission['username'],
                    submission['problem_id'],
                )
            cursor.execute(
                "UPDATE submissions SET status='Error' WHERE id=%s",
                (submission_id,),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    try:
        refresh_submission_status_snapshot(submission_id)
    except Exception:
        logger.exception(
            '归档失败状态快照刷新失败',
            extra={'submission_id': submission_id},
        )
    return released


def can_submit(username, problem_id, max_submissions=10):
    current_count = get_user_submission_count(username, problem_id)
    return current_count < max_submissions


def get_remaining_submissions(username, problem_id, max_submissions=10):
    current_count = get_user_submission_count(username, problem_id)
    return max(0, max_submissions - current_count)


def update_submission_status(submission_id, new_status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE submissions SET status=%s WHERE id=%s"
            cursor.execute(sql, (new_status, submission_id))
        conn.commit()
    finally:
        conn.close()
    refresh_submission_status_snapshot(submission_id)


def reset_submission_for_rejudge(submission_id, problem_type=None):
    """Reset a submission before enqueueing a rejudge.

    Programming submissions must drop stale test-point rows so the detail page
    enters its live judging path. Written submissions keep test_points because
    it stores the original uploaded filename used by the grading worker.
    """
    try:
        ptype = int(problem_type) if problem_type is not None else None
    except (TypeError, ValueError):
        ptype = None
    clear_test_points = ptype != 2

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if clear_test_points:
                sql = """
                    UPDATE submissions
                       SET status='Pending', score=0, test_points=''
                     WHERE id=%s
                """
                cursor.execute(sql, (submission_id,))
            else:
                sql = """
                    UPDATE submissions
                       SET status='Pending', score=0
                     WHERE id=%s
                """
                cursor.execute(sql, (submission_id,))
        conn.commit()
    finally:
        conn.close()
    refresh_submission_status_snapshot(submission_id)


def update_submission_evaluation(submission_id, test_point_statuses, score, status):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            test_points_str = '\n'.join([json.dumps(tp, ensure_ascii=False) for tp in test_point_statuses])
            sql = """UPDATE submissions
                     SET test_points=%s, score=%s, status=%s
                     WHERE id=%s"""
            cursor.execute(sql, (test_points_str, score, status, submission_id))
        conn.commit()
    finally:
        conn.close()
    refresh_submission_status_snapshot(submission_id)


def update_submission_generated_code(submission_id, generated_code, status="Pending"):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE submissions
                   SET code=%s,
                       generated_from_prompt=1,
                       prompt_generation_error=NULL,
                       status=%s,
                       score=0,
                       test_points=''
                 WHERE id=%s
                """,
                (generated_code, status, submission_id),
            )
        conn.commit()
    finally:
        conn.close()
    refresh_submission_status_snapshot(submission_id)


def update_submission_prompt_generation_error(submission_id, error_message, status="Error"):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE submissions
                   SET prompt_generation_error=%s,
                       status=%s,
                       score=0
                 WHERE id=%s
                """,
                (str(error_message or "").strip()[:12000], status, submission_id),
            )
        conn.commit()
    finally:
        conn.close()
    refresh_submission_status_snapshot(submission_id)


###############################################################################
#  AI Detection Results
###############################################################################

def upsert_ai_detection_result(result):
    """Insert or update an AI detection result. Uses REPLACE INTO on unique submission_id."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "REPLACE INTO ai_detection_results "
                "(submission_id, username, problem_id, "
                " llm_score, llm_evidence, behavior_score, behavior_detail, "
                " final_score, risk_level, task_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    result["submission_id"],
                    result["username"],
                    result["problem_id"],
                    result.get("llm_score"),
                    result.get("llm_evidence"),
                    result.get("behavior_score"),
                    result.get("behavior_detail"),
                    result["final_score"],
                    result["risk_level"],
                    result.get("task_id"),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def delete_ai_detection_results_by_task(task_id):
    """Delete all ai_detection_results rows produced by the given task. Returns deleted count."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM ai_detection_results WHERE task_id = %s",
                (task_id,),
            )
            deleted = cursor.rowcount
        conn.commit()
        return deleted
    finally:
        conn.close()


def delete_ai_detection_task(task_id):
    """Delete a task record from ai_detection_tasks."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM ai_detection_tasks WHERE task_id = %s",
                (task_id,),
            )
        conn.commit()
    finally:
        conn.close()


def get_ai_detection_result_by_submission(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM ai_detection_results WHERE submission_id=%s",
                (submission_id,),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def get_ai_detection_results_for_problem(problem_id, risk_level=None):
    """Get all detection results for a problem, optionally filtered by risk level."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if risk_level:
                cursor.execute(
                    "SELECT d.*, s.code, s.status AS submission_status, s.score AS submission_score "
                    "FROM ai_detection_results d "
                    "LEFT JOIN submissions s ON d.submission_id = s.id "
                    "WHERE d.problem_id=%s AND d.risk_level=%s "
                    "ORDER BY d.final_score DESC",
                    (problem_id, risk_level),
                )
            else:
                cursor.execute(
                    "SELECT d.*, s.code, s.status AS submission_status, s.score AS submission_score "
                    "FROM ai_detection_results d "
                    "LEFT JOIN submissions s ON d.submission_id = s.id "
                    "WHERE d.problem_id=%s "
                    "ORDER BY d.final_score DESC",
                    (problem_id,),
                )
            return cursor.fetchall()
    finally:
        conn.close()


def get_ai_detection_results_for_user(username):
    """Get all detection results for a user."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT d.*, s.status AS submission_status, s.score AS submission_score, "
                "       p.title AS problem_title "
                "FROM ai_detection_results d "
                "LEFT JOIN submissions s ON d.submission_id = s.id "
                "LEFT JOIN problems p ON d.problem_id = p.id "
                "WHERE d.username=%s "
                "ORDER BY d.created_at DESC",
                (username,),
            )
            return cursor.fetchall()
    finally:
        conn.close()


def get_ai_detection_dashboard_summary():
    """Get summary statistics for the detection dashboard."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT risk_level, COUNT(*) AS cnt "
                "FROM ai_detection_results "
                "GROUP BY risk_level"
            )
            level_counts = {row["risk_level"]: row["cnt"] for row in cursor.fetchall()}

            cursor.execute(
                "SELECT d.username, "
                "       COUNT(*) AS total_detections, "
                "       SUM(CASE WHEN d.risk_level='high' THEN 1 ELSE 0 END) AS high_count, "
                "       SUM(CASE WHEN d.risk_level='medium' THEN 1 ELSE 0 END) AS medium_count, "
                "       MAX(d.final_score) AS max_score, "
                "       AVG(d.final_score) AS avg_score "
                "FROM ai_detection_results d "
                "GROUP BY d.username "
                "HAVING high_count > 0 OR medium_count > 0 "
                "ORDER BY high_count DESC, avg_score DESC"
            )
            flagged_users = cursor.fetchall()

            cursor.execute(
                "SELECT d.problem_id, p.title AS problem_title, "
                "       COUNT(*) AS total_detections, "
                "       SUM(CASE WHEN d.risk_level='high' THEN 1 ELSE 0 END) AS high_count, "
                "       SUM(CASE WHEN d.risk_level='medium' THEN 1 ELSE 0 END) AS medium_count, "
                "       AVG(d.final_score) AS avg_score "
                "FROM ai_detection_results d "
                "LEFT JOIN problems p ON d.problem_id = p.id "
                "GROUP BY d.problem_id, p.title "
                "ORDER BY high_count DESC, avg_score DESC"
            )
            problem_stats = cursor.fetchall()

            return {
                "level_counts": level_counts,
                "flagged_users": flagged_users,
                "problem_stats": problem_stats,
            }
    finally:
        conn.close()


def _representative_submission_sql():
    """
    Sub-query that selects one representative submission per (username, problem_id):
    the *last* submission among those with the *highest* score.
    """
    return (
        "SELECT s.id, s.problem_id, s.username, s.code, s.score, "
        "       s.status, s.created_at "
        "FROM submissions s "
        "INNER JOIN ("
        "  SELECT username, problem_id, MAX(score) AS max_score "
        "  FROM submissions "
        "  WHERE problem_type=1 "
        "  GROUP BY username, problem_id"
        ") ms ON s.username = ms.username "
        "        AND s.problem_id = ms.problem_id "
        "        AND s.score = ms.max_score "
        "INNER JOIN ("
        "  SELECT MAX(sub.id) AS rep_id "
        "  FROM submissions sub "
        "  INNER JOIN ("
        "    SELECT username, problem_id, MAX(score) AS max_score "
        "    FROM submissions "
        "    WHERE problem_type=1 "
        "    GROUP BY username, problem_id"
        "  ) ms2 ON sub.username = ms2.username "
        "           AND sub.problem_id = ms2.problem_id "
        "           AND sub.score = ms2.max_score "
        "  GROUP BY sub.username, sub.problem_id"
        ") rep ON s.id = rep.rep_id"
    )


def get_undetected_submissions_for_problem(problem_id):
    """
    Per user, pick the representative submission (last among max-score)
    that hasn't been analyzed yet.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT r.id, r.problem_id, r.username, r.code, r.score, "
                "       r.status, r.created_at "
                "FROM (" + _representative_submission_sql() + ") r "
                "LEFT JOIN ai_detection_results d ON r.id = d.submission_id "
                "WHERE r.problem_id=%s AND d.id IS NULL "
                "ORDER BY r.id ASC"
            )
            cursor.execute(sql, (problem_id,))
            return cursor.fetchall()
    finally:
        conn.close()


def get_undetected_submissions_for_user(username):
    """
    For a given user, across all programming problems, pick the representative
    submission per problem that hasn't been analyzed yet.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = (
                "SELECT r.id, r.problem_id, r.username, r.code, r.score, "
                "       r.status, r.created_at "
                "FROM (" + _representative_submission_sql() + ") r "
                "LEFT JOIN ai_detection_results d ON r.id = d.submission_id "
                "WHERE r.username=%s AND d.id IS NULL "
                "ORDER BY r.id ASC"
            )
            cursor.execute(sql, (username,))
            return cursor.fetchall()
    finally:
        conn.close()


def get_filtered_submissions_for_detection(
    class_en=None, username=None, problem_id=None,
    submission_id=None, score_min=None, score_max=None,
    deduplicate=True, lang=None,
):
    """
    Flexibly filter submissions for AI detection.

    Parameters
    ----------
    class_en      : only submissions from users in this class
    username      : exact username match
    problem_id    : specific problem
    submission_id : specific submission ID
    score_min/max : score range (inclusive)
    deduplicate   : if True, per (username, problem_id) keep only the
                    last submission among those with the highest score
    lang          : optional problem language filter; omitted means all languages
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            need_class = bool(class_en)
            joins = "JOIN problems p ON s.problem_id = p.id "
            if need_class:
                joins += (
                    "JOIN users _u ON _u.username = s.username "
                    "JOIN user_class_map _ucm ON _ucm.user_id = _u.id "
                )

            conditions = ["s.problem_type = 1"]
            params = []

            if lang is not None and str(lang).strip():
                conditions.append("p.lang = %s")
                params.append(str(lang).strip().lower())

            if need_class:
                conditions.append("_ucm.class_en = %s")
                params.append(class_en)
                conditions.append("_u.is_admin = 0")
            if username:
                conditions.append("s.username = %s")
                params.append(username)
            if problem_id:
                conditions.append("s.problem_id = %s")
                params.append(int(problem_id))
            if submission_id:
                conditions.append("s.id = %s")
                params.append(int(submission_id))
            if score_min is not None:
                conditions.append("s.score >= %s")
                params.append(int(score_min))
            if score_max is not None:
                conditions.append("s.score <= %s")
                params.append(int(score_max))

            sql = (
                "SELECT s.id, s.problem_id, s.username, s.code, s.score, "
                "       s.status, s.created_at, p.title AS problem_title "
                "FROM submissions s " + joins +
                "WHERE " + " AND ".join(conditions) +
                " ORDER BY s.id ASC"
            )
            cursor.execute(sql, params)
            rows = cursor.fetchall()
    finally:
        conn.close()

    if not deduplicate:
        return rows

    # Python-side dedup: per (username, problem_id) keep max score then latest id
    best = {}
    for row in rows:
        key = (row['username'], row['problem_id'])
        prev = best.get(key)
        if prev is None:
            best[key] = row
        elif row['score'] > prev['score'] or (
            row['score'] == prev['score'] and row['id'] > prev['id']
        ):
            best[key] = row

    return list(best.values())


# ──────────────────────────────────────────────────────────────────────────────
#  AI Detection Task persistence (MySQL)
# ──────────────────────────────────────────────────────────────────────────────

def upsert_ai_detection_task(data: dict):
    """Insert or update a task record. data keys mirror the Redis task dict."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO ai_detection_tasks
                    (task_id, task_type, params_summary, status,
                     submitted_at, started_at, finished_at, total, processed, error)
                VALUES
                    (%(task_id)s, %(task_type)s, %(params_summary)s, %(status)s,
                     %(submitted_at)s, %(started_at)s, %(finished_at)s,
                     %(total)s, %(processed)s, %(error)s)
                ON DUPLICATE KEY UPDATE
                    status        = VALUES(status),
                    started_at    = VALUES(started_at),
                    finished_at   = VALUES(finished_at),
                    total         = VALUES(total),
                    processed     = VALUES(processed),
                    error         = VALUES(error)
            """, {
                'task_id':        data.get('task_id'),
                'task_type':      data.get('task_type'),
                'params_summary': data.get('params_summary'),
                'status':         data.get('status', 'pending'),
                'submitted_at':   data.get('submitted_at'),
                'started_at':     data.get('started_at'),
                'finished_at':    data.get('finished_at'),
                'total':          data.get('total'),
                'processed':      data.get('processed') or 0,
                'error':          data.get('error'),
            })
        conn.commit()
    except Exception as e:
        print(f'[AI Detection] upsert_ai_detection_task error: {e}')
    finally:
        conn.close()


def get_ai_detection_tasks(limit=20):
    """Return the most recent `limit` task rows from MySQL, newest first."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM ai_detection_tasks "
                "ORDER BY submitted_at DESC LIMIT %s",
                (limit,)
            )
            rows = cursor.fetchall()
        for r in rows:
            # Convert datetime objects to strings for JSON compatibility
            for col in ('submitted_at', 'started_at', 'finished_at'):
                if r.get(col) and not isinstance(r[col], str):
                    r[col] = r[col].strftime('%Y-%m-%d %H:%M:%S')
        return rows
    finally:
        conn.close()


def truncate_ai_detection_tasks():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE ai_detection_tasks")
        conn.commit()
    finally:
        conn.close()


# ---------- 每日提交计数器 ----------
# 首页 "数据统计" 用的按日聚合表，避免每次都全表扫 submissions/ranking_submissions。
# 写入路径：每条 programming / ranking 提交在 INSERT 之后调用 bump_daily_submission_count()。

def ensure_daily_submission_stats_table():
    global _daily_submission_stats_table_ready
    _daily_submission_stats_table_ready = True


def bump_daily_submission_count():
    """Best-effort：记录异常但不阻塞提交写入。"""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO daily_submission_stats (day, submissions_count) "
                    "VALUES (CURDATE(), 1) "
                    "ON DUPLICATE KEY UPDATE submissions_count = submissions_count + 1"
                )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        logger.exception('每日提交计数更新失败')


def get_today_submission_total_from_counter():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT submissions_count FROM daily_submission_stats WHERE day = CURDATE()"
            )
            row = cursor.fetchone()
            return int((row or {}).get('submissions_count') or 0)
    finally:
        conn.close()


def get_last_10_days_counts_from_counter():
    """返回 ``(labels, counts)``：'YYYY-MM-DD' 字符串列表 + 对应整数；缺日补 0。"""
    from datetime import date, timedelta

    today = date.today()
    days = [today + timedelta(days=i) for i in range(-9, 1)]
    labels = [d.strftime('%Y-%m-%d') for d in days]
    counts_map = {label: 0 for label in labels}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT day, submissions_count FROM daily_submission_stats "
                "WHERE day >= %s AND day <= %s",
                (days[0], days[-1]),
            )
            for row in cursor.fetchall() or []:
                day_obj = row.get('day')
                key = day_obj.strftime('%Y-%m-%d') if hasattr(day_obj, 'strftime') else str(day_obj)
                if key in counts_map:
                    counts_map[key] = int(row.get('submissions_count') or 0)
    finally:
        conn.close()

    return labels, [counts_map[label] for label in labels]
