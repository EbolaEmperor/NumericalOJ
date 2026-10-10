"""任务启动和显式恢复共同读取的题面与原始 PDF。"""

import json
import os

from backend.oj_modules.submissions.grading import get_file_path_for_submission


def problem_material(problem):
    return (f"# {str(problem.get('title') or '').strip()}\n\n"
            f"{str(problem.get('content') or '').strip()}\n\n"
            "## 评分\n\n满分 5 分。请按 FaithSieve 的原评分量表评分。\n")


def submission_pdf(submission_id):
    try:
        path = get_file_path_for_submission(submission_id)
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("书面提交的上传记录无效") from exc
    if not path or not os.path.isfile(path):
        raise ValueError("书面提交 PDF 不存在")
    with open(path, "rb") as stream:
        data = stream.read(20 * 1024 * 1024 + 1)
    if not data.startswith(b"%PDF-") or len(data) > 20 * 1024 * 1024:
        raise ValueError("书面提交文件不是有效 PDF 或超过大小限制")
    return data
