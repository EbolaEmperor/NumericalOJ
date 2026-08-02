#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""重测 Celery 适配层。"""

from oj_modules.db_services import get_submission_by_id


REJUDGE_TASK_NAME = "oj.rejudge.evaluate_submission_and_update"


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


__all__ = ["REJUDGE_TASK_NAME", "register_rejudge_task"]
