"""FaithSieve 手动书面题评测的持久队列与结果协议。"""

from __future__ import annotations

import json
from uuid import uuid4

from backend.oj_modules.infrastructure.mysql import get_db_connection


ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "inconclusive"})
MAX_CONCURRENT_RUNS = 20
RESULT_FILENAME = "faithsieve_result.json"
_DISPATCH_LOCK = "faithsieve-grading-dispatch"
_QUEUE_LOCK = "faithsieve-grading-queue"


def latest_submissions_for_problem(problem_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT s.*
                FROM submissions AS s
                INNER JOIN (
                    SELECT username, MAX(id) AS submission_id
                    FROM submissions
                    WHERE problem_id=%s
                    GROUP BY username
                ) AS latest ON latest.submission_id=s.id
                ORDER BY s.id ASC
                """,
                (int(problem_id),),
            )
            return list(cursor.fetchall() or [])
    finally:
        conn.close()


def queue_runs(submissions, *, requested_by, harness, endpoint_id):
    """为提交建立持久请求；同一提交已有活动请求时不重复排队。"""

    queued = []
    skipped = []
    conn = get_db_connection()
    acquired = False
    try:
        with conn.cursor() as cursor:
            # 对同一提交的“检查后插入”必须串行；仅靠不存在行上的 FOR UPDATE
            # 无法在所有隔离级别下阻止两个管理员同时创建活动请求。
            cursor.execute("SELECT GET_LOCK(%s, 10) AS acquired", (_QUEUE_LOCK,))
            acquired = bool((cursor.fetchone() or {}).get("acquired"))
            if not acquired:
                raise RuntimeError("FaithSieve 排队锁繁忙，请稍后重试")
            for submission in submissions:
                submission_id = int(submission["id"])
                cursor.execute(
                    """
                    SELECT attempt_id, status
                    FROM faithsieve_grading_runs
                    WHERE submission_id=%s
                    ORDER BY id DESC
                    LIMIT 1 FOR UPDATE
                    """,
                    (submission_id,),
                )
                latest = cursor.fetchone()
                if latest and str(latest.get("status") or "") in ACTIVE_STATUSES:
                    skipped.append(submission_id)
                    continue
                attempt_id = uuid4().hex
                cursor.execute(
                    """
                    INSERT INTO faithsieve_grading_runs (
                        attempt_id, submission_id, problem_id, requested_by,
                        harness, endpoint_id, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, 'queued')
                    """,
                    (
                        attempt_id,
                        submission_id,
                        int(submission["problem_id"]),
                        str(requested_by or "")[:50],
                        str(harness or "")[:32],
                        int(endpoint_id),
                    ),
                )
                queued.append({"attempt_id": attempt_id, "submission_id": submission_id})
        conn.commit()
        return queued, skipped
    except Exception:
        conn.rollback()
        raise
    finally:
        if acquired:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (_QUEUE_LOCK,))
            except Exception:
                pass
        conn.close()


def set_run_task_id(attempt_id, task_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE faithsieve_grading_runs SET task_id=%s WHERE attempt_id=%s",
                (str(task_id or "")[:64], str(attempt_id)),
            )
        conn.commit()
    finally:
        conn.close()


def get_run(attempt_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM faithsieve_grading_runs WHERE attempt_id=%s",
                (str(attempt_id),),
            )
            return cursor.fetchone()
    finally:
        conn.close()


def claim_run_slot(attempt_id, *, task_id, session_id):
    """在 MySQL 命名锁下领取全站 20 个 FaithSieve 运行名额之一。"""

    conn = get_db_connection()
    acquired = False
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 10) AS acquired", (_DISPATCH_LOCK,))
            acquired = bool((cursor.fetchone() or {}).get("acquired"))
            if not acquired:
                return False
            cursor.execute(
                "SELECT status FROM faithsieve_grading_runs WHERE attempt_id=%s FOR UPDATE",
                (str(attempt_id),),
            )
            row = cursor.fetchone()
            if not row:
                return False
            if row.get("status") == "running":
                return True
            if row.get("status") != "queued":
                return False
            cursor.execute(
                "SELECT COUNT(*) AS total FROM faithsieve_grading_runs WHERE status='running'"
            )
            if int((cursor.fetchone() or {}).get("total") or 0) >= MAX_CONCURRENT_RUNS:
                return False
            cursor.execute(
                """
                UPDATE faithsieve_grading_runs
                SET status='running', task_id=%s, session_id=%s,
                    started_at=COALESCE(started_at, NOW()), message='正在启动 Judge Agent'
                WHERE attempt_id=%s AND status='queued'
                """,
                (str(task_id or "")[:64], str(session_id or "")[:64], str(attempt_id)),
            )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        if acquired:
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT RELEASE_LOCK(%s)", (_DISPATCH_LOCK,))
            except Exception:
                pass
        conn.close()


def finish_run(attempt_id, status, message, *, result=None):
    if status not in TERMINAL_STATUSES:
        raise ValueError("FaithSieve 终态无效")
    result_json = (
        json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        if result is not None
        else None
    )
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE faithsieve_grading_runs
                SET status=%s, message=%s, result_json=%s, finished_at=NOW()
                WHERE attempt_id=%s AND status IN ('queued','running')
                """,
                (status, str(message or "")[:4000], result_json, str(attempt_id)),
            )
        conn.commit()
    finally:
        conn.close()


def parse_result(payload):
    if not isinstance(payload, dict) or set(payload) != {"verdict", "score", "comment"}:
        raise ValueError("FaithSieve 回传必须且只能包含 verdict、score、comment")
    verdict = str(payload.get("verdict") or "").strip().lower()
    if verdict not in {"correct", "incorrect", "inconclusive"}:
        raise ValueError("FaithSieve verdict 无效")
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 5:
        raise ValueError("FaithSieve score 必须是 0 到 5 的整数")
    comment = str(payload.get("comment") or "").strip()
    if not comment:
        raise ValueError("FaithSieve comment 不能为空")
    if len(comment) > 20000:
        raise ValueError("FaithSieve comment 过长")
    return {"verdict": verdict, "score": score, "comment": comment}


__all__ = [
    "MAX_CONCURRENT_RUNS",
    "RESULT_FILENAME",
    "claim_run_slot",
    "finish_run",
    "get_run",
    "latest_submissions_for_problem",
    "parse_result",
    "queue_runs",
    "set_run_task_id",
]
