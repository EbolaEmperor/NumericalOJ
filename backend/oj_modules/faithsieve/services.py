"""FaithSieve 显式失败恢复的领域事务与规范控制任务调度。"""

import logging
import re
from uuid import uuid4

from backend.oj_modules.agents.workspace import get_existing_agent_workspace_path
from backend.oj_modules.db_services import get_problem, get_submission_by_id
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.infrastructure.redis import create_redis_client
from backend.oj_modules.problems.agent_launch import resolve_launch_endpoint
from backend.oj_modules.submissions.faithsieve import RUN_TIMEOUT_SECONDS, get_run

from .inputs import problem_material, submission_pdf
from .recovery import (
    FaithSieveRecoveryConflict, FaithSieveRecoveryDispatchError, FaithSieveRecoveryError, prepare_recovery,
    validate_recovery_inputs,
)


logger = logging.getLogger(__name__)
_dispatcher = None
_QUEUE_LOCK = "faithsieve-grading-queue"
_TERMINAL_JUDGE = "('completed','failed','error','canceled','cancelled','timeout','quotaexhausted')"


def init_retry_dispatcher(task):
    global _dispatcher
    _dispatcher = task


def _validate_run(run):
    if (not run or run.get("status") != "failed" or run.get("execution_mode") != "workflow"
            or run.get("result_json") not in (None, "")
            or type(run.get("elapsed_seconds")) is not int
            or not 0 <= run["elapsed_seconds"] < RUN_TIMEOUT_SECONDS):
        raise FaithSieveRecoveryError("仅能恢复仍在整体时限内的 workflow 端点失败或局部 Judge 超时")


def _no_active_judge(cursor, run):
    cursor.execute(f"""
        SELECT COUNT(*) AS total FROM agent_sessions AS s
        LEFT JOIN agent_task_runs AS r ON r.task_id=s.current_task_id
        WHERE s.attempt_id=%s AND s.task_kind='judge' AND s.judge_kind='faithsieve'
        AND (LOWER(REPLACE(s.status,'_','')) NOT IN {_TERMINAL_JUDGE}
             OR (r.task_id IS NOT NULL AND LOWER(REPLACE(r.status,'_','')) NOT IN {_TERMINAL_JUDGE})
             OR EXISTS (SELECT 1 FROM agent_session_turns AS t WHERE t.session_id=s.session_id
                        AND LOWER(REPLACE(t.status,'_','')) NOT IN {_TERMINAL_JUDGE}))
        """, (run["attempt_id"],))
    if int((cursor.fetchone() or {}).get("total") or 0):
        raise FaithSieveRecoveryConflict("关联 Judge 尚未确认结束，不能恢复")


def _no_other_active_run(cursor, run):
    cursor.execute("SELECT COUNT(*) AS total FROM faithsieve_grading_runs "
                   "WHERE submission_id=%s AND status IN ('queued','running')", (run["submission_id"],))
    if int((cursor.fetchone() or {}).get("total") or 0):
        raise FaithSieveRecoveryConflict("这份提交已有活动评测")


def _validate_inputs(run):
    workspace = get_existing_agent_workspace_path(f"faithsieve-{run['attempt_id']}")
    problem = get_problem(int(run["problem_id"]))
    submission = get_submission_by_id(int(run["submission_id"]))
    if (not problem or not submission or int(problem.get("type") or 0) != 2
            or int(problem.get("written_grading_mode") or 0) != 4
            or int(submission.get("problem_id") or 0) != int(run["problem_id"])):
        raise FaithSieveRecoveryError("原提交或题目已变化，不能恢复")
    endpoint = resolve_launch_endpoint(run["harness"], int(run["endpoint_id"]), include_secret=True)
    validate_recovery_inputs(workspace, run, problem_text=problem_material(problem),
                             submission_pdf=submission_pdf(int(run["submission_id"])), endpoint=endpoint)
    return workspace


def can_retry_failed_run(attempt_id):
    """GET 只读资格：同样核对真实输入与传输，不能显示确定无法续跑的按钮。"""
    try:
        run = get_run(attempt_id)
        _validate_run(run)
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                _no_other_active_run(cursor, run)
                _no_active_judge(cursor, run)
        finally:
            connection.close()
        _validate_inputs(run)
        return True
    except Exception:
        return False


def retry_failed_run(attempt_id, *, actor, dispatcher=None):
    """保留原始预算和身份，显式重试或续聊由已有控制任务领取名额。"""
    if type(attempt_id) is not str or not re.fullmatch(r"[a-f0-9]{32}", attempt_id):
        raise FaithSieveRecoveryError("FaithSieve 评测记录不存在")
    if type(actor) is not str or not actor.strip() or len(actor) > 50:
        raise FaithSieveRecoveryError("FaithSieve 恢复操作人无效")
    task = dispatcher or _dispatcher
    if task is None:
        raise FaithSieveRecoveryError("FaithSieve 恢复任务未初始化")
    lock = create_redis_client().lock(f"faithsieve:workflow:{attempt_id}", timeout=RUN_TIMEOUT_SECONDS + 300, blocking=False)
    if not lock.acquire(blocking=False):
        raise FaithSieveRecoveryConflict("原编排任务尚未结束，不能恢复")
    connection, acquired, committed = None, False, False
    task_id = f"fs-recovery-{uuid4().hex}"
    run = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK(%s, 10) AS acquired", (_QUEUE_LOCK,))
            acquired = bool((cursor.fetchone() or {}).get("acquired"))
            if not acquired:
                raise FaithSieveRecoveryConflict("FaithSieve 排队锁繁忙")
            cursor.execute("SELECT *, TIMESTAMPDIFF(SECOND, started_at, NOW()) AS elapsed_seconds "
                           "FROM faithsieve_grading_runs WHERE attempt_id=%s FOR UPDATE", (attempt_id,))
            run = cursor.fetchone()
            if run and run.get("status") in {"queued", "running"}:
                raise FaithSieveRecoveryConflict("FaithSieve 已在排队或运行")
            _validate_run(run)
            _no_other_active_run(cursor, run)
            _no_active_judge(cursor, run)
            workspace = _validate_inputs(run)
            permission = prepare_recovery(workspace, run, actor)
            cursor.execute("UPDATE faithsieve_grading_runs SET status='queued', task_id=%s, finished_at=NULL, "
                           "message='已授权继续 FaithSieve 评测' WHERE attempt_id=%s AND status='failed' "
                           "AND TIMESTAMPDIFF(SECOND, started_at, NOW()) < %s", (task_id, attempt_id, RUN_TIMEOUT_SECONDS))
            if cursor.rowcount != 1:
                raise FaithSieveRecoveryConflict("FaithSieve 状态或整体时限已变化")
        try:
            connection.commit()
            committed = True
        except Exception:
            current = get_run(attempt_id)
            if not current or current.get("status") != "queued" or current.get("task_id") != task_id:
                raise FaithSieveRecoveryDispatchError("FaithSieve 恢复提交结果尚未确认，请重新读取记录") from None
            committed = True
        logger.info("FaithSieve 显式恢复已授权", extra={"attempt_id": attempt_id, "requested_by": actor,
                    "invocation_key": permission["target_key"], "task_id": task_id})
        try:
            task.apply_async(args=(attempt_id,), queue="celery", task_id=task_id)
        except Exception:
            # broker 可能已接收：只回滚仍 queued 且属于本次调度的状态；
            # 已领取名额的 running 不能反写 failed，更不能删掉恢复授权。
            with connection.cursor() as cursor:
                cursor.execute("UPDATE faithsieve_grading_runs SET status='failed', finished_at=NOW(), "
                               "message='恢复任务调度未确认，请重试' WHERE attempt_id=%s AND status='queued' AND task_id=%s",
                               (attempt_id, task_id))
                rolled_back = cursor.rowcount == 1
            connection.commit()
            logger.warning("FaithSieve 恢复调度结果未确认", extra={"attempt_id": attempt_id, "task_id": task_id})
            if rolled_back:
                raise FaithSieveRecoveryDispatchError("恢复任务调度未确认，请重新读取记录后重试") from None
            current = get_run(attempt_id)
            if not current or current.get("status") not in {"running", "completed"}:
                raise FaithSieveRecoveryDispatchError("恢复任务调度结果尚未确认，请重新读取记录") from None
            return {"attempt_id": attempt_id, "status": current["status"]}
        return {"attempt_id": attempt_id, "status": "queued"}
    except Exception:
        if connection is not None and not committed:
            connection.rollback()
        raise
    finally:
        if connection is not None:
            if acquired:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT RELEASE_LOCK(%s)", (_QUEUE_LOCK,))
                except Exception:
                    pass
            connection.close()
        lock.release()
