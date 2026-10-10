"""FaithSieve 短流程入场及 skill / workflow 两种执行模式。"""

from __future__ import annotations

import logging

from celery.exceptions import Retry

from backend.oj_modules.agents.workspace import ensure_agent_workspace
from backend.oj_modules.faithsieve.inputs import problem_material as _problem_material, submission_pdf as _submission_pdf
from backend.oj_modules.db_services import (
    get_problem,
    get_submission_by_id,
)
from backend.oj_modules.infrastructure.redis import create_redis_client
from backend.oj_modules.problems.agent_launch import resolve_launch_endpoint
from backend.oj_modules.submissions.faithsieve import (
    FaithSieveCommitOutcomeUnknownError,
    RUN_TIMEOUT_SECONDS,
    claim_run_slot,
    complete_run,
    finish_run,
    get_run,
    normalize_execution_mode,
    parse_result,
    update_run_progress,
)

FAITHSIEVE_TASK_NAME = "oj.faithsieve_grade_submission"
FAITHSIEVE_WORKFLOW_TASK_NAME = "oj.faithsieve_run_workflow"
FAITHSIEVE_SKILL_TASK_NAME = "oj.faithsieve_run_skill"
FAITHSIEVE_TIMEOUT_SECONDS = RUN_TIMEOUT_SECONDS
_POLL_SECONDS = 5
logger = logging.getLogger(__name__)


def _update_progress(attempt_id, message):
    try:
        update_run_progress(attempt_id, message)
    except Exception:
        # 进度文案不是续跑依据。数据库临时不可用时仍须保留 Judge
        # 等待重试，不能因刷新文案失败而 ACK 掉唯一的恢复消息。
        pass


def _finish_run_or_retry(task, attempt_id, status, message, **options):
    try:
        finish_run(attempt_id, status, message, **options)
    except Exception:
        # 持久终态保存失败时续跑，不能 ACK 后永久占住运行名额。
        raise task.retry(countdown=10, max_retries=None)


def _execute_workflow(run, problem, celery_app=None):
    # 编排只派发或读取通用 Judge，等待时由专用异常交回 Celery 续跑。
    from backend.oj_modules.faithsieve.judge import FaithSieveJudgeAgent
    from backend.oj_modules.faithsieve.runtime_snapshot import freeze_initial_reasoning_effort
    from backend.oj_modules.faithsieve.recovery import validate_recovery_inputs, validate_recovery_run
    from backend.oj_modules.faithsieve.workflow import run_faithsieve_workflow
    from backend.oj_modules.faithsieve.costs import WorkflowUsageRecorder

    endpoint = resolve_launch_endpoint(run["harness"], int(run["endpoint_id"]), include_secret=True)
    workspace = ensure_agent_workspace(f"faithsieve-{run['attempt_id']}")
    permission = validate_recovery_run(workspace, run)
    initial_reasoning_effort = freeze_initial_reasoning_effort(workspace, int(run["endpoint_id"]))
    problem_text, pdf = _problem_material(problem), _submission_pdf(int(run["submission_id"]))
    if permission:
        # queued 后配置或题面再次变化也只能失败，不能在重放前改历史工件。
        validate_recovery_inputs(workspace, run, problem_text=problem_text,
                                 submission_pdf=pdf, endpoint=endpoint, target_key=permission["target_key"])
    judge = FaithSieveJudgeAgent(
        run=run, endpoint=endpoint, workspace=workspace,
        celery_app=celery_app, problem=problem,
    )
    usage_recorder = WorkflowUsageRecorder(run=run, endpoint=endpoint, workspace=workspace)
    return run_faithsieve_workflow(
        problem_text=problem_text,
        submission_pdf=pdf,
        endpoint=endpoint,
        verification_agent=judge,
        workspace=workspace,
        initial_reasoning_effort=initial_reasoning_effort,
        usage_recorder=usage_recorder,
        progress=lambda event: _update_progress(
            run["attempt_id"], str(event.get("message") or event.get("role") or "正在评测"),
        ),
    )


def _execution_mode(run):
    return normalize_execution_mode(run.get("execution_mode"), default="skill")


def _execution_session_id(run):
    if _execution_mode(run) == "skill":
        from backend.oj_modules.faithsieve.skill import skill_identity
        return skill_identity(run)[0]
    return f"faithsieve-{run['attempt_id']}"


def _execute_skill(run, problem, celery_app=None):
    from backend.oj_modules.faithsieve.skill import FaithSieveSkillAgent
    submission = get_submission_by_id(int(run["submission_id"]))
    return FaithSieveSkillAgent(
        run=run, submission=submission, problem=problem, celery_app=celery_app,
    ).execute(
        endpoint_loader=lambda: resolve_launch_endpoint(run["harness"], int(run["endpoint_id"]), include_secret=False),
        pdf_loader=lambda: _submission_pdf(int(run["submission_id"])),
    )


def _cancel_workflow_judges(run, celery_app):
    from backend.oj_modules.faithsieve.judge import FaithSieveJudgeAgent

    FaithSieveJudgeAgent(
        run=run, endpoint={"id": run["endpoint_id"]},
        workspace=ensure_agent_workspace(f"faithsieve-{run['attempt_id']}"),
        celery_app=celery_app,
    ).cancel_pending()


def _cancel_skill_judge(run, celery_app):
    from backend.oj_modules.faithsieve.skill import FaithSieveSkillAgent
    FaithSieveSkillAgent(
        run=run, submission=get_submission_by_id(int(run["submission_id"])), celery_app=celery_app,
    ).cancel_pending()


def _finish_message_after_cancel(run, celery_app, message):
    if run:
        try:
            if _execution_mode(run) == "workflow":
                _cancel_workflow_judges(run, celery_app)
            else:
                _cancel_skill_judge(run, celery_app)
        except Exception:
            # 保留失败现场和 Judge 持久关联，不能把未确认终止当成清理成功。
            return message + "；未能确认 Judge 已终止，请管理员检查关联任务"
    return message


def _workflow_lock(attempt_id):
    # 同一持久请求被 broker 重投时不得并行调用模型或重复回写成绩。
    return create_redis_client().lock(
        f"faithsieve:workflow:{attempt_id}",
        timeout=FAITHSIEVE_TIMEOUT_SECONDS + 300,
        blocking=False,
    )


def register_faithsieve_grading_task(celery_app):
    from backend.oj_modules.faithsieve.judge import FaithSievePending

    def _run_execution(self, attempt_id, expected_mode):
        lock = None
        acquired = False
        run = None
        try:
            lock = _workflow_lock(attempt_id)
            acquired = lock.acquire(blocking=False)
            if not acquired:
                # acks_late 下 worker 丢失会立即重投，原锁可能尚未到期；
                # 必须保留重试消息，不能 ACK 掉唯一的恢复机会。
                raise self.retry(countdown=_POLL_SECONDS, max_retries=None)
            try:
                run = get_run(attempt_id)
            except Exception:
                # 数据库不可达时仍保留重投消息，不能将运行记录遗留为 running。
                raise self.retry(countdown=10, max_retries=None)
            if not run or run.get("status") != "running":
                return {
                    "success": bool(run and run.get("status") == "completed"),
                    "message": str((run or {}).get("message") or "FaithSieve 请求不在运行状态"),
                }
            mode = _execution_mode(run)
            if mode != expected_mode:
                # 队列名称或重投参数不能覆盖数据库中冻结的执行模式。
                return {"success": False, "message": "FaithSieve 持久执行模式与执行任务不一致，未执行"}
            # 使用数据库时钟计算从领取名额至今的总时长，Celery 续跑不会
            # 重置此上限。超时先终止已有 Judge，避免编排结束后继续消费。
            if int(run.get("elapsed_seconds") or 0) >= FAITHSIEVE_TIMEOUT_SECONDS:
                raise ValueError("FaithSieve 评测已超过整体时限，未覆盖原人工成绩")
            submission_id = int(run["submission_id"])
            submission = get_submission_by_id(submission_id)
            problem = get_problem(int(run["problem_id"]))
            if not submission or not problem:
                raise ValueError("提交或题目不存在")
            if int(problem.get("type") or 0) != 2 or int(
                problem.get("written_grading_mode") or 1
            ) != 4:
                raise ValueError("FaithSieve 仅支持纯人工批改的书面题")
            if int(submission.get("problem_id") or 0) != int(problem["id"]):
                raise ValueError("提交与题目不匹配")

            executor = _execute_workflow if mode == "workflow" else _execute_skill
            result = parse_result(executor(run, problem, self.app))
            if result["verdict"] == "inconclusive":
                _finish_run_or_retry(
                    self, attempt_id, "inconclusive",
                    _finish_message_after_cancel(run, self.app, "证据不足，未覆盖原人工成绩"),
                    result=result,
                )
                return {"success": False, "message": "FaithSieve 无法得出可靠结论"}
            if (result["verdict"] == "incorrect" and result["score"] == 5) or (
                result["verdict"] == "correct" and result["score"] < 4
            ):
                raise ValueError("FaithSieve 分数与原评分量表的正确性判断不一致")
            # 领域入口锁定仍在运行的请求，按数据库时钟再次检查整体时限，
            # 将成绩、提交状态和运行终态放在同一事务中保存。
            complete_run(attempt_id, result)
            return {"success": True, "score": result["score"]}
        except FaithSieveCommitOutcomeUnknownError:
            # COMMIT 可能已成功。续跑先读 run 终态，避免反写 failed 或重做模型请求。
            raise self.retry(countdown=10, max_retries=None)
        except FaithSievePending as pending:
            _update_progress(attempt_id, "正在等待 FaithSieve skill 主 Judge 完成评测" if expected_mode == "skill" else "正在等待通用 Judge 完成验证")
            # 不在 agent worker 内同步等待同队列的子任务；释放 worker 和
            # 执行锁后重入，成功阶段由 workflow checkpoint 原样复用。
            raise self.retry(countdown=pending.countdown, max_retries=None)
        except Retry:
            raise
        except ValueError as exc:
            message = _finish_message_after_cancel(run, self.app, str(exc))
            _finish_run_or_retry(self, attempt_id, "failed", message)
            return {"success": False, "message": message}
        except Exception:
            # 模型与执行器异常可能包含鉴权数据，不写进学生可见状态。
            # 内部异常交由统一日志框架记录和脱敏，避免只有泛化失败状态。
            logger.exception("FaithSieve 执行异常", extra={
                "attempt_id": str(attempt_id), "execution_mode": expected_mode,
            })
            _finish_run_or_retry(self, attempt_id, "failed", _finish_message_after_cancel(
                run, self.app, f"FaithSieve {expected_mode} 执行失败，未覆盖原人工成绩",
            ))
            return {"success": False, "message": f"FaithSieve {expected_mode} 执行失败"}
        finally:
            if acquired:
                lock.release()

    @celery_app.task(
        bind=True, name=FAITHSIEVE_WORKFLOW_TASK_NAME, max_retries=None,
        soft_time_limit=FAITHSIEVE_TIMEOUT_SECONDS, time_limit=FAITHSIEVE_TIMEOUT_SECONDS + 60,
    )
    def faithsieve_run_workflow(self, attempt_id):
        return _run_execution(self, attempt_id, "workflow")

    @celery_app.task(
        bind=True, name=FAITHSIEVE_SKILL_TASK_NAME, max_retries=None,
        soft_time_limit=FAITHSIEVE_TIMEOUT_SECONDS, time_limit=FAITHSIEVE_TIMEOUT_SECONDS + 60,
    )
    def faithsieve_run_skill(self, attempt_id):
        return _run_execution(self, attempt_id, "skill")

    @celery_app.task(bind=True, name=FAITHSIEVE_TASK_NAME, max_retries=None)
    def faithsieve_grade_submission(self, attempt_id):
        try:
            run = get_run(attempt_id)
        except Exception:
            raise self.retry(countdown=10, max_retries=None)
        if not run:
            return {"success": False, "message": "FaithSieve 请求不存在"}
        if run.get("status") not in {"queued", "running"}:
            return {
                "success": run.get("status") in {"running", "completed"},
                "message": str(run.get("message") or ""),
            }
        try:
            run = {**run, "attempt_id": attempt_id}
            if run.get("status") == "queued" and not claim_run_slot(
                attempt_id,
                task_id=self.request.id,
                session_id=_execution_session_id(run),
            ):
                raise self.retry(countdown=_POLL_SECONDS, max_retries=None)
            # 领取名额后重新读持久模式；调用参数只携带 attempt，不决定执行方式。
            current = get_run(attempt_id)
            if not current:
                raise self.retry(countdown=10, max_retries=None)
            mode = _execution_mode(current)
            executor = faithsieve_run_workflow if mode == "workflow" else faithsieve_run_skill
            executor.apply_async(
                args=(attempt_id,), queue="agent", task_id=f"fs-{mode}-{attempt_id}",
            )
            return {"success": True, "message": f"FaithSieve {mode} 已入队"}
        except Retry:
            raise
        except Exception:
            # 名额已持久化但派发结果未知时保留重试；重投交由 workflow 的
            # 执行锁和终态检查去重，避免进程丢失后永久占用名额。
            raise self.retry(countdown=10, max_retries=None)

    from backend.oj_modules.faithsieve.services import init_retry_dispatcher
    init_retry_dispatcher(faithsieve_grade_submission)
    return faithsieve_grade_submission


__all__ = [
    "FAITHSIEVE_TASK_NAME", "FAITHSIEVE_WORKFLOW_TASK_NAME", "FAITHSIEVE_SKILL_TASK_NAME", "register_faithsieve_grading_task",
]
