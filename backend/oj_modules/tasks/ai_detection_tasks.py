#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Celery tasks for AI code detection.
"""

from backend.oj_modules.ai_detection.detector import run_detection
from backend.oj_modules.ai.client import resolve_llm_endpoint_snapshot
from backend.oj_modules.ai_detection.task_tracker import (
    record_task_done,
    record_task_failed,
    record_task_progress,
    record_task_running,
)
from backend.oj_modules.db_services import (
    get_filtered_submissions_for_detection,
    get_problem,
    get_submission_by_id,
    get_undetected_submissions_for_problem,
    get_undetected_submissions_for_user,
    upsert_ai_detection_result,
)


import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

DETECT_SINGLE_TASK_NAME   = "oj.ai_detection.detect_single"
DETECT_BATCH_TASK_NAME    = "oj.ai_detection.detect_batch"
DETECT_USER_TASK_NAME     = "oj.ai_detection.detect_user"
DETECT_FILTERED_TASK_NAME = "oj.ai_detection.detect_filtered"

# 远程大模型 API 是 IO-bound，高并发以最大化吞吐
_MAX_WORKERS_REMOTE = 20


def _resolve_detection_endpoint(endpoint_id):
    return resolve_llm_endpoint_snapshot(
        None,
        endpoint_id=endpoint_id,
        allowed_categories={"omni", "text"},
        purpose="AI 检测",
    )


def _run_batch(task_id, submissions, get_problem_fn, endpoint):
    """Run detections in parallel, updating Redis on each completion.

    ``endpoint`` 是任务启动时读取的一次性快照，所有并发子任务共享该不可变对象。
    """
    total = len(submissions)
    record_task_running(task_id, total=total)

    processed = 0
    lock = threading.Lock()

    def _detect_one(sub):
        problem = get_problem_fn(sub["problem_id"])
        if not problem:
            return None
        result = run_detection(sub, problem, endpoint=endpoint, task_id=task_id)
        upsert_ai_detection_result(result)
        return result

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS_REMOTE, total or 1)) as executor:
        futures = {executor.submit(_detect_one, sub): sub for sub in submissions}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                future.result()
                with lock:
                    processed += 1
                    record_task_progress(task_id, processed, total)
            except Exception as e:
                print(f"[AI Detection] Error submission {sub['id']}: {e}")

    record_task_done(task_id, processed, total)
    return {"total": total, "processed": processed}


def register_ai_detection_tasks(celery_app):
    existing = {name: celery_app.tasks.get(name) for name in [
        DETECT_SINGLE_TASK_NAME, DETECT_BATCH_TASK_NAME,
        DETECT_USER_TASK_NAME, DETECT_FILTERED_TASK_NAME,
    ]}
    if all(existing.values()):
        return tuple(existing.values())

    @celery_app.task(name=DETECT_SINGLE_TASK_NAME, bind=True, time_limit=120, soft_time_limit=90)
    def detect_single_submission(self, submission_id, endpoint_id=None):
        task_id = self.request.id
        record_task_running(task_id, total=1)
        try:
            endpoint = _resolve_detection_endpoint(endpoint_id)
            submission = get_submission_by_id(submission_id)
            if not submission:
                record_task_failed(task_id, f"Submission {submission_id} not found")
                return

            problem = get_problem(submission["problem_id"])
            if not problem:
                record_task_failed(task_id, f"Problem {submission['problem_id']} not found")
                return

            if submission.get("problem_type") and int(submission["problem_type"]) != 1:
                record_task_done(task_id, 0, 1)
                return

            result = run_detection(submission, problem, endpoint=endpoint, task_id=task_id)
            upsert_ai_detection_result(result)
            record_task_done(task_id, 1, 1)
            print(
                f"[AI Detection] submission={submission_id} endpoint={endpoint.id} "
                f"final={result['final_score']} risk={result['risk_level']}"
            )
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_BATCH_TASK_NAME, bind=True, time_limit=1800, soft_time_limit=1700)
    def detect_batch_for_problem(self, problem_id, endpoint_id=None):
        task_id = self.request.id
        try:
            endpoint = _resolve_detection_endpoint(endpoint_id)
            problem = get_problem(problem_id)
            if not problem:
                record_task_failed(task_id, f"Problem {problem_id} not found")
                return {"total": 0, "processed": 0}

            if int(problem.get("type") or 1) != 1:
                record_task_done(task_id, 0, 0)
                return {"total": 0, "processed": 0}

            submissions = get_undetected_submissions_for_problem(problem_id)
            return _run_batch(task_id, submissions, get_problem, endpoint)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_USER_TASK_NAME, bind=True, time_limit=7200, soft_time_limit=7100)
    def detect_batch_for_user(self, username, endpoint_id=None):
        task_id = self.request.id
        try:
            endpoint = _resolve_detection_endpoint(endpoint_id)
            submissions = get_undetected_submissions_for_user(username)
            return _run_batch(task_id, submissions, get_problem, endpoint)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_FILTERED_TASK_NAME, bind=True, time_limit=7200, soft_time_limit=7100)
    def detect_filtered_submissions(self, filters, endpoint_id=None):
        task_id = self.request.id
        try:
            endpoint = _resolve_detection_endpoint(endpoint_id)
            submissions = get_filtered_submissions_for_detection(**filters)
            return _run_batch(task_id, submissions, get_problem, endpoint)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    return detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions
