#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Promptly 模式：学生 prompt 生成代码后进入普通评测流水线。"""

from celery.exceptions import SoftTimeLimitExceeded

from oj_modules.ai_utils import generate_promptly_code, review_promptly_student_prompt
from oj_modules.db_services import (
    archive_submission_by_id,
    get_problem,
    get_submission_by_id,
    set_submission_status_snapshot,
    update_submission_generated_code,
    update_submission_prompt_generation_error,
    update_submission_status,
)


PROMPTLY_GENERATE_TASK_NAME = "oj.promptly.generate_submission"


def _normalize_promptly_mode(problem):
    try:
        return int((problem or {}).get("programming_grading_mode") or 1) == 3
    except Exception:
        return False


def register_promptly_generate_submission_task(celery_app, evaluate_submission_task):
    @celery_app.task(
        bind=True,
        name=PROMPTLY_GENERATE_TASK_NAME,
        soft_time_limit=420,
        time_limit=480,
    )
    def promptly_generate_submission(self, submission_id):
        submission = get_submission_by_id(submission_id)
        if not submission:
            return {"success": False, "message": "提交不存在"}

        status = str(submission.get("status") or "").strip()
        if status != "Generating":
            return {"success": False, "message": f"提交状态不可生成：{status}"}

        problem = get_problem(submission.get("problem_id"))
        if not problem or int(problem.get("type") or 0) != 1 or not _normalize_promptly_mode(problem):
            update_submission_prompt_generation_error(submission_id, "该提交不是 Promptly 编程题。")
            return {"success": False, "message": "该提交不是 Promptly 编程题"}

        prompt_text = str(submission.get("prompt_text") or submission.get("code") or "").strip()
        if not prompt_text:
            update_submission_prompt_generation_error(submission_id, "prompt 不能为空。")
            return {"success": False, "message": "prompt 不能为空"}
        archive_submission_by_id(submission_id)

        try:
            update_submission_status(submission_id, "Generating")
            set_submission_status_snapshot(
                submission_id=submission_id,
                username=submission.get("username"),
                problem_id=submission.get("problem_id"),
                problem_type=submission.get("problem_type"),
                status="Generating",
                score=0,
                test_points=[],
            )
            nice, reply = review_promptly_student_prompt(
                problem=problem,
                student_prompt=prompt_text,
                model_spec=problem.get("programming_grading_model"),
            )
            if not nice:
                message = reply or "请补充更具体的算法思路。"
                update_submission_prompt_generation_error(submission_id, message, status="Unaccepted")
                return {"success": False, "message": message}

            generated_code = generate_promptly_code(
                problem=problem,
                student_prompt=prompt_text,
                model_spec=problem.get("programming_grading_model"),
            )
            update_submission_generated_code(submission_id, generated_code, status="Pending")
            archive_submission_by_id(submission_id)
            if evaluate_submission_task is not None:
                try:
                    evaluate_submission_task.delay(submission_id)
                except Exception as exc:
                    return {
                        "success": False,
                        "message": f"Promptly 代码已生成，但评测任务入队失败：{exc}",
                    }
            return {"success": True, "submission_id": submission_id}
        except SoftTimeLimitExceeded:
            update_submission_prompt_generation_error(submission_id, "Promptly 代码生成超时。")
            return {"success": False, "message": "Promptly 代码生成超时"}
        except Exception as exc:
            update_submission_prompt_generation_error(submission_id, f"Promptly 代码生成失败：{exc}")
            raise

    return promptly_generate_submission
