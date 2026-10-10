"""FaithSieve 手动书面题评测的持久队列与结果协议。"""

from __future__ import annotations

import json
import logging
from uuid import uuid4

from backend.oj_modules.db_services import (
    get_user_by_username,
    insert_user_problem_ac_record_if_absent,
    refresh_submission_status_snapshot,
    upsert_user_problem_max_score_if_higher,
)
from backend.oj_modules.infrastructure.mysql import get_db_connection


ACTIVE_STATUSES = frozenset({"queued", "running"})
TERMINAL_STATUSES = frozenset({"completed", "failed", "inconclusive"})
MAX_CONCURRENT_RUNS = 20
# 完整评测包含原稿核对、多轮结构审计和多个独立证明任务；总预算覆盖
# Judge 排队与等待，但不重置单个任务或重试的上限。
RUN_TIMEOUT_SECONDS = 2 * 60 * 60
RESULT_FILENAME = "faithsieve_result.json"
EXECUTION_MODES = frozenset({"workflow", "skill"})
_DISPATCH_LOCK = "faithsieve-grading-dispatch"
_QUEUE_LOCK = "faithsieve-grading-queue"
logger = logging.getLogger(__name__)


def normalize_execution_mode(value, *, default="workflow"):
    """新请求默认 workflow；读取历史 NULL 时由调用方明确传 default='skill'。"""
    if default not in EXECUTION_MODES:
        raise ValueError("FaithSieve 默认执行方式无效")
    if value is None:
        return default
    if not isinstance(value, str) or value.strip().lower() not in EXECUTION_MODES:
        raise ValueError("FaithSieve 执行方式必须为 workflow 或 skill")
    return value.strip().lower()


class FaithSieveCompletionError(ValueError):
    """回写前置条件不成立；成绩和 run 终态均未提交。"""


class FaithSieveRunNotRunningError(FaithSieveCompletionError):
    pass


class FaithSieveRunTimedOutError(FaithSieveCompletionError):
    pass


class FaithSieveCommitOutcomeUnknownError(RuntimeError):
    """COMMIT 响应丢失，调用者必须重读持久状态，不能断言未写入成绩。"""


def _refresh_completed_grading(attempt_id, submission, score):
    """沿用既有派生统计工具；提交后的刷新失败不能改写持久结论。"""
    identifiers = {"attempt_id": str(attempt_id), "submission_id": submission["id"]}
    try:
        refresh_submission_status_snapshot(submission["id"])
    except Exception:
        logger.exception("FaithSieve 成绩已提交，状态快照刷新失败", extra=identifiers)
    try:
        user = get_user_by_username(submission["username"])
        if not user or not user.get("id"):
            raise LookupError("提交用户不存在")
        user_id = int(user["id"])
    except Exception:
        logger.exception("FaithSieve 成绩已提交，派生统计用户读取失败", extra=identifiers)
        return
    try:
        upsert_user_problem_max_score_if_higher(user_id, submission["problem_id"], score)
    except Exception:
        logger.exception("FaithSieve 成绩已提交，最高分统计刷新失败", extra=identifiers)
    try:
        maximum = submission.get("max_score") or 0
        if maximum > 0 and score >= maximum:
            insert_user_problem_ac_record_if_absent(user_id, submission["problem_id"])
    except Exception:
        logger.exception("FaithSieve 成绩已提交，通过记录刷新失败", extra=identifiers)


def complete_run(attempt_id, result):
    """将书面成绩、提交状态和 FaithSieve 成功终态原子提交。

    时限在持有 run 行锁时用数据库时钟检查，并在最后一次 UPDATE 再次验证，
    避免长事务越过整体时限。COMMIT 的响应不明必须交由宿主重读/重试；
    不能调用 finish_run 把这种情况解释为失败或声称成绩未覆盖。
    """
    result = parse_result(result)
    if result["verdict"] == "inconclusive":
        raise FaithSieveCompletionError("FaithSieve 不确定结果不能覆盖人工成绩")
    if (result["verdict"] == "incorrect" and result["score"] == 5) or (
        result["verdict"] == "correct" and result["score"] < 4
    ):
        raise FaithSieveCompletionError("FaithSieve 分数与原评分量表的正确性判断不一致")
    result_json = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    conn = get_db_connection()
    commit_started = False
    committed = False
    submission = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT submission_id, problem_id, status,
                       TIMESTAMPDIFF(SECOND, started_at, NOW()) AS elapsed_seconds
                FROM faithsieve_grading_runs
                WHERE attempt_id=%s FOR UPDATE
                """,
                (str(attempt_id),),
            )
            run = cursor.fetchone()
            if not run or run.get("status") != "running":
                raise FaithSieveRunNotRunningError("FaithSieve 请求不在运行状态，未写入成绩")
            elapsed = run.get("elapsed_seconds")
            if elapsed is None or isinstance(elapsed, bool):
                raise FaithSieveCompletionError("FaithSieve 运行起点无法确认，未写入成绩")
            try:
                elapsed = int(elapsed)
            except (ValueError, TypeError, OverflowError):
                raise FaithSieveCompletionError("FaithSieve 运行时长无效，未写入成绩") from None
            if elapsed < 0:
                raise FaithSieveCompletionError("FaithSieve 运行起点无效，未写入成绩")
            if elapsed >= RUN_TIMEOUT_SECONDS:
                raise FaithSieveRunTimedOutError("FaithSieve 评测已超过整体时限，未写入成绩")
            cursor.execute(
                """
                SELECT s.id, s.username, s.problem_id,
                       p.type AS problem_type, p.written_grading_mode, p.max_score
                FROM submissions AS s
                INNER JOIN problems AS p ON p.id=s.problem_id
                WHERE s.id=%s FOR UPDATE
                """,
                (int(run["submission_id"]),),
            )
            submission = cursor.fetchone()
            if not submission or int(submission["problem_id"]) != int(run["problem_id"]):
                raise FaithSieveCompletionError("FaithSieve 提交与题目不存在或不匹配，未写入成绩")
            if int(submission.get("problem_type") or 0) != 2 or int(
                submission.get("written_grading_mode") or 1
            ) != 4:
                raise FaithSieveCompletionError("FaithSieve 仅能回写纯人工批改的书面题")
            cursor.execute(
                "UPDATE submissions SET score=%s, code=%s, status=%s WHERE id=%s",
                (
                    result["score"], result["comment"],
                    "Accepted" if result["score"] == 5 else "Unaccepted",
                    int(submission["id"]),
                ),
            )
            cursor.execute(
                """
                UPDATE faithsieve_grading_runs
                SET status='completed', message=%s, result_json=%s, finished_at=NOW()
                WHERE attempt_id=%s AND status='running' AND started_at IS NOT NULL
                      AND TIMESTAMPDIFF(SECOND, started_at, NOW()) < %s
                """,
                (f"评测完成，得分 {result['score']}/5", result_json, str(attempt_id), RUN_TIMEOUT_SECONDS),
            )
            if cursor.rowcount == 0:
                raise FaithSieveRunTimedOutError("FaithSieve 成绩提交前已超过整体时限，事务未写入成绩")
            if cursor.rowcount != 1:
                raise FaithSieveCompletionError("FaithSieve 终态回写行数异常，事务未写入成绩")
        commit_started = True
        conn.commit()
        committed = True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            logger.exception("FaithSieve 成绩事务回滚失败", extra={"attempt_id": str(attempt_id)})
        if commit_started and not committed:
            raise FaithSieveCommitOutcomeUnknownError(
                "FaithSieve 成绩事务提交结果尚未确认，请重读持久状态",
            ) from None
        raise
    finally:
        try:
            conn.close()
        except Exception:
            logger.exception("FaithSieve 成绩事务连接关闭失败", extra={"attempt_id": str(attempt_id)})
    try:
        _refresh_completed_grading(attempt_id, submission, result["score"])
    except Exception:
        logger.exception("FaithSieve 成绩已提交，派生数据刷新失败", extra={
            "attempt_id": str(attempt_id), "submission_id": submission["id"],
        })
    return result


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


def queue_runs(submissions, *, requested_by, harness, endpoint_id, execution_mode="workflow"):
    """为提交建立持久请求；同一提交已有活动请求时不重复排队。"""

    execution_mode = normalize_execution_mode(execution_mode)
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
                        harness, endpoint_id, execution_mode, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued')
                    """,
                    (
                        attempt_id,
                        submission_id,
                        int(submission["problem_id"]),
                        str(requested_by or "")[:50],
                        str(harness or "")[:32],
                        int(endpoint_id),
                        execution_mode,
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
                "SELECT *, TIMESTAMPDIFF(SECOND, started_at, NOW()) AS elapsed_seconds "
                "FROM faithsieve_grading_runs WHERE attempt_id=%s",
                (str(attempt_id),),
            )
            row = cursor.fetchone()
            if row:
                row = {**row, "execution_mode": normalize_execution_mode(row.get("execution_mode"), default="skill")}
            return row
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
                return False
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
                    started_at=COALESCE(started_at, NOW()), message='正在启动 FaithSieve'
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


def update_run_progress(attempt_id, message):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE faithsieve_grading_runs SET message=%s WHERE attempt_id=%s AND status='running'",
                (str(message or "正在评测")[:4000], str(attempt_id)),
            )
        conn.commit()
    finally:
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
    "FaithSieveCommitOutcomeUnknownError",
    "FaithSieveCompletionError",
    "FaithSieveRunNotRunningError",
    "FaithSieveRunTimedOutError",
    "MAX_CONCURRENT_RUNS",
    "EXECUTION_MODES",
    "RESULT_FILENAME",
    "RUN_TIMEOUT_SECONDS",
    "claim_run_slot",
    "complete_run",
    "finish_run",
    "get_run",
    "latest_submissions_for_problem",
    "parse_result",
    "normalize_execution_mode",
    "queue_runs",
    "set_run_task_id",
    "update_run_progress",
]
