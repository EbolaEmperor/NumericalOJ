#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

from oj_modules.ai_utils import (
    evaluate_written_homework_with_ai,
    evaluate_written_homework_with_ai_from_images,
    render_pdf_to_images,
    save_transcribed_latex,
)
from oj_modules.db_services import (
    get_problem,
    get_submission_by_id,
    refresh_submission_status_snapshot,
    update_submission_status,
)
from oj_modules.grading_services import (
    get_file_path_for_submission,
    update_submission_comment,
    update_submission_score_and_comment,
)


WRITTEN_TASK_NAME = "oj.transcribe_written_homework_to_latex"


def register_written_homework_task(celery_app):
    existing = celery_app.tasks.get(WRITTEN_TASK_NAME)
    if existing:
        return existing

    @celery_app.task(name=WRITTEN_TASK_NAME, time_limit=900, soft_time_limit=840)
    def transcribe_written_homework_to_latex(submission_id):
        """
        书面作业 LaTeX 转写 + AI 评分任务（异步）。
        """
        submission = get_submission_by_id(submission_id)
        if not submission or submission.get('problem_type') != 2:
            return

        update_submission_status(submission_id, 'Running')

        file_path = get_file_path_for_submission(submission_id)
        if not file_path or not os.path.exists(file_path):
            print(f"[LaTeX OCR] submission={submission_id} 文件不存在: {file_path}")
            update_submission_status(submission_id, 'Pending')
            return

        upload_folder = os.path.dirname(file_path)
        uploaded_filename = os.path.basename(file_path)

        try:
            problem = get_problem(submission['problem_id'])
            if not problem:
                raise RuntimeError("题目不存在，无法自动评分。")
            try:
                written_mode = int(problem.get('written_grading_mode') or 1)
            except Exception:
                written_mode = 1
            written_model = str(problem.get('written_grading_model') or 'qwen3.5-plus-thinking').strip().lower()

            if written_mode == 2:
                image_paths = render_pdf_to_images(file_path, upload_folder)
                score, ai_comment = evaluate_written_homework_with_ai_from_images(
                    problem,
                    image_paths,
                    grading_model_spec=written_model,
                )
            else:
                def _on_partial_latex(_partial_text, _markdown_path):
                    # 每次 OCR 增量写盘后发布一次快照，驱动前端 SSE 即时刷新。
                    refresh_submission_status_snapshot(submission_id)

                markdown_path = save_transcribed_latex(
                    pdf_path=file_path,
                    upload_folder=upload_folder,
                    uploaded_filename=uploaded_filename,
                    on_partial_latex=_on_partial_latex,
                )
                with open(markdown_path, 'r', encoding='utf-8') as f:
                    latex_text = f.read()
                if not latex_text.strip():
                    raise RuntimeError("转写得到的 LaTeX 为空。")
                # OCR 已完成，立即发布一次实时状态，供前端渲染 LaTeX 转写结果。
                refresh_submission_status_snapshot(submission_id)
                score, ai_comment = evaluate_written_homework_with_ai(
                    problem,
                    latex_text,
                    grading_model_spec=written_model,
                )

            update_submission_score_and_comment(submission_id, score, ai_comment)
            new_status = 'Accepted' if score == 5 else 'Unaccepted'
            update_submission_status(submission_id, new_status)
            if written_mode == 2:
                print(
                    f"[Image Grade] submission={submission_id} 图片直评完成: "
                    f"score={score}, status={new_status}"
                )
            else:
                print(
                    f"[LaTeX OCR] submission={submission_id} 转写+评分完成: "
                    f"score={score}, status={new_status}, markdown={markdown_path}"
                )
        except Exception as e:
            error_filename = f"{os.path.splitext(uploaded_filename)[0]}_latex_error.txt"
            error_path = os.path.join(upload_folder, error_filename)
            try:
                with open(error_path, 'w', encoding='utf-8') as f:
                    f.write(f"LaTeX 转写/自动评分失败（submission_id={submission_id}）\n")
                    f.write(str(e))
            except Exception:
                pass
            try:
                update_submission_comment(submission_id, f"AI 自动评分失败：{str(e)}")
                update_submission_status(submission_id, 'Pending')
            except Exception:
                pass
            print(f"[LaTeX OCR] submission={submission_id} 转写或评分失败: {e}")

    return transcribe_written_homework_to_latex
