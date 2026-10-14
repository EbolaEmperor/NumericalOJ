#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""重测 Celery 适配层。"""

import logging

from backend.oj_modules.db_services import get_submission_by_id
from backend.oj_modules.observability import redact_text
from backend.oj_modules.submissions.rejudge_dispatch import dispatch_rejudge_submissions


REJUDGE_TASK_NAME = "oj.rejudge.evaluate_submission_and_update"
BULK_REJUDGE_TASK_NAME = "oj.rejudge.dispatch_batch"
_CLAIM_BATCH = (
    "if redis.call('hget', KEYS[1], 'dispatch_status') == 'queued' then "
    "redis.call('hset', KEYS[1], 'dispatch_status', 'dispatching'); "
    "return 1 else return 0 end"
)
logger = logging.getLogger(__name__)


def register_rejudge_task(
    celery_app,
    redis_client,
    evaluate_submission_task,
    transcribe_written_task=None,
):
    """注册按题型分派的单条重测任务，并返回稳定 task handle。"""

    existing = celery_app.tasks.get(REJUDGE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(name=REJUDGE_TASK_NAME)
    def evaluate_submission_and_update(submission_id, progress_key):
        # 按 problem_type 分派：书面作业(type 2) 走转写评分任务，其余走程序题评测。
        try:
            submission = get_submission_by_id(submission_id)
            if submission and submission.get("problem_type") == 2:
                if transcribe_written_task is not None:
                    transcribe_written_task(submission_id)
            else:
                evaluate_submission_task(submission_id)
        finally:
            if redis_client is not None and progress_key:
                redis_client.hincrby(progress_key, "done", 1)

    return evaluate_submission_and_update


def register_bulk_rejudge_task(celery_app, redis_client, rejudge_task):
    """批次调度不自动重试；部分失败保留进度，不重复重置已投递的记录。"""
    existing = celery_app.tasks.get(BULK_REJUDGE_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(
        name=BULK_REJUDGE_TASK_NAME,
        queue="celery",
        acks_late=False,
        reject_on_worker_lost=False,
    )
    def dispatch_batch(submissions, progress_key):
        try:
            claimed = redis_client.eval(_CLAIM_BATCH, 1, progress_key)
            if not claimed:
                return
            dispatch_rejudge_submissions(submissions, progress_key, rejudge_task, redis_client)
            redis_client.hset(progress_key, mapping={"dispatch_status": "dispatched"})
        except Exception as exc:
            try:
                redis_client.hset(progress_key, mapping={
                    "dispatch_status": "failed",
                    "error": redact_text(str(exc)),
                })
            except Exception:
                logger.exception("批量重测调度失败后写入进度失败")
            raise

    return dispatch_batch


__all__ = ["REJUDGE_TASK_NAME", "BULK_REJUDGE_TASK_NAME", "register_rejudge_task", "register_bulk_rejudge_task"]
