#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Celery tasks for AI code detection.
"""

from oj_modules.ai_detection.detector import run_detection
from oj_modules.ai_detection.task_tracker import (
    record_task_done,
    record_task_failed,
    record_task_progress,
    record_task_running,
)
from oj_modules.db_services import (
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

# 远程大模型 API（Qwen 等）是 IO-bound，高并发以最大化吞吐
_MAX_WORKERS_REMOTE = 20
# 本地 vLLM 推理：让 vLLM 做连续批处理，并发数控制在合理范围
# RTX 3090 Ti 24GB，Qwen3-1.7B 约 3.5GB，一次可跑多个并发请求
# 8 个并发请求可充分利用 GPU 批处理，不会造成 VRAM 压力
_MAX_WORKERS_LOCAL = 8

_MAX_WORKERS_BY_MODEL = {
    "qwen": _MAX_WORKERS_REMOTE,
    "matlab_ai_detect": _MAX_WORKERS_LOCAL,
}


def _run_batch(task_id, submissions, get_problem_fn, model_id="qwen"):
    """Run detections in parallel, updating Redis on each completion.

    Concurrency is tuned per model:
      - Remote API models (qwen): high concurrency, IO-bound
      - Local vLLM models (matlab_ai_detect): moderate concurrency,
        lets vLLM continuous batching do the heavy lifting
    """
    max_workers = _MAX_WORKERS_BY_MODEL.get(model_id, _MAX_WORKERS_REMOTE)
    total = len(submissions)
    record_task_running(task_id, total=total)

    processed = 0
    lock = threading.Lock()

    def _detect_one(sub):
        problem = get_problem_fn(sub["problem_id"])
        if not problem:
            return None
        result = run_detection(sub, problem, model_id=model_id, task_id=task_id)
        upsert_ai_detection_result(result)
        return result

    with ThreadPoolExecutor(max_workers=min(max_workers, total or 1)) as executor:
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
    def detect_single_submission(self, submission_id, model_id="qwen"):
        task_id = self.request.id
        record_task_running(task_id, total=1)
        try:
            submission = get_submission_by_id(submission_id)
            if not submission:
                record_task_failed(task_id, f"Submission {submission_id} not found")
                return

            problem = get_problem(submission["problem_id"])
            if not problem:
                record_task_failed(task_id, f"Problem {submission['problem_id']} not found")
                return

            lang = (problem.get("lang") or "matlab").strip().lower()
            if lang != "matlab" or (
                submission.get("problem_type") and int(submission["problem_type"]) != 1
            ):
                record_task_done(task_id, 0, 1)
                return

            result = run_detection(submission, problem, model_id=model_id, task_id=task_id)
            upsert_ai_detection_result(result)
            record_task_done(task_id, 1, 1)
            print(
                f"[AI Detection] submission={submission_id} model={model_id} "
                f"final={result['final_score']} risk={result['risk_level']}"
            )
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_BATCH_TASK_NAME, bind=True, time_limit=1800, soft_time_limit=1700)
    def detect_batch_for_problem(self, problem_id, model_id="qwen"):
        task_id = self.request.id
        try:
            problem = get_problem(problem_id)
            if not problem:
                record_task_failed(task_id, f"Problem {problem_id} not found")
                return {"total": 0, "processed": 0}

            lang = (problem.get("lang") or "matlab").strip().lower()
            if lang != "matlab":
                record_task_done(task_id, 0, 0)
                return {"total": 0, "processed": 0}

            submissions = get_undetected_submissions_for_problem(problem_id, lang)
            return _run_batch(task_id, submissions, get_problem, model_id=model_id)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_USER_TASK_NAME, bind=True, time_limit=7200, soft_time_limit=7100)
    def detect_batch_for_user(self, username, model_id="qwen"):
        task_id = self.request.id
        try:
            submissions = get_undetected_submissions_for_user(username)
            return _run_batch(task_id, submissions, get_problem, model_id=model_id)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    @celery_app.task(name=DETECT_FILTERED_TASK_NAME, bind=True, time_limit=7200, soft_time_limit=7100)
    def detect_filtered_submissions(self, filters, model_id="qwen"):
        task_id = self.request.id
        try:
            submissions = get_filtered_submissions_for_detection(**filters)
            return _run_batch(task_id, submissions, get_problem, model_id=model_id)
        except Exception as e:
            record_task_failed(task_id, str(e))
            raise

    return detect_single_submission, detect_batch_for_problem, detect_batch_for_user, detect_filtered_submissions
