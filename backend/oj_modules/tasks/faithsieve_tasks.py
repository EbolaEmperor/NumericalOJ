"""用通用 Judge Agent 执行 FaithSieve，并把终态回写书面提交。"""

from __future__ import annotations

import json
import os

from celery.exceptions import Retry

from backend.oj_modules.agents.judge import judge_session_id, submit_judge_turn
from backend.oj_modules.agents.sessions import get_agent_session, get_agent_session_turns
from backend.oj_modules.agents.workspace import open_agent_workspace_file
from backend.oj_modules.db_services import (
    get_problem,
    get_submission_by_id,
    update_submission_status,
)
from backend.oj_modules.problems.agent_launch import resolve_launch_endpoint
from backend.oj_modules.submissions.faithsieve import (
    RESULT_FILENAME,
    claim_run_slot,
    finish_run,
    get_run,
    parse_result,
)
from backend.oj_modules.submissions.grading import (
    get_file_path_for_submission,
    update_submission_score_and_comment,
)


FAITHSIEVE_TASK_NAME = "oj.faithsieve_grade_submission"
FAITHSIEVE_TIMEOUT_SECONDS = 60 * 60
_POLL_SECONDS = 5
_MAX_RESULT_BYTES = 256 * 1024


def _problem_material(problem):
    return (
        f"# {str(problem.get('title') or '').strip()}\n\n"
        f"{str(problem.get('content') or '').strip()}\n\n"
        "## 评分\n\n满分 5 分。请按 FaithSieve skill 的量表评分。\n"
    ).encode("utf-8")


def _submission_pdf(submission_id):
    try:
        path = get_file_path_for_submission(submission_id)
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("书面提交的上传记录无效") from exc
    if not path or not os.path.isfile(path):
        raise ValueError("书面提交 PDF 不存在")
    with open(path, "rb") as stream:
        data = stream.read()
    if not data.startswith(b"%PDF-"):
        raise ValueError("书面提交文件不是有效 PDF")
    return data


def _read_result(session_id):
    try:
        stream, _metadata = open_agent_workspace_file(session_id, RESULT_FILENAME)
        with stream:
            raw = stream.read(_MAX_RESULT_BYTES + 1)
    except (OSError, ValueError) as exc:
        raise ValueError("Agent 未写入 FaithSieve 结果文件") from exc
    if len(raw) > _MAX_RESULT_BYTES:
        raise ValueError("FaithSieve 结果文件过大")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("FaithSieve 结果不是有效 JSON") from exc
    return parse_result(payload)


def _current_turn_status(session):
    turns = {row["task_id"]: row for row in get_agent_session_turns(session["session_id"])}
    current = turns.get(session.get("current_task_id")) or {}
    return str(current.get("status") or session.get("status") or "").strip().lower()


def register_faithsieve_grading_task(celery_app):
    @celery_app.task(bind=True, name=FAITHSIEVE_TASK_NAME, max_retries=None)
    def faithsieve_grade_submission(self, attempt_id):
        run = get_run(attempt_id)
        if not run:
            return {"success": False, "message": "FaithSieve 请求不存在"}
        if str(run.get("status") or "") in {"completed", "failed", "inconclusive"}:
            return {
                "success": run.get("status") == "completed",
                "message": str(run.get("message") or ""),
            }

        submission_id = int(run["submission_id"])
        session_id = judge_session_id(submission_id, attempt_id, "faithsieve")
        try:
            if run.get("status") == "queued" and not claim_run_slot(
                attempt_id,
                task_id=self.request.id,
                session_id=session_id,
            ):
                raise self.retry(countdown=_POLL_SECONDS, max_retries=None)

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

            session = get_agent_session(session_id)
            if not session:
                endpoint = resolve_launch_endpoint(
                    run["harness"], run["endpoint_id"], include_secret=False,
                )
                template = {
                    "verdict": "inconclusive",
                    "score": 0,
                    "comment": "请按 faithsieve skill 完成评测后覆盖本文件。",
                }
                submit_judge_turn(
                    session_id=session_id,
                    task_id=f"fs-{attempt_id}",
                    requested_by=submission["username"],
                    judge_kind="faithsieve",
                    submission_id=submission_id,
                    attempt_id=attempt_id,
                    competition_id=None,
                    harness=run["harness"],
                    endpoint=endpoint,
                    prompt=(
                        "请使用 faithsieve skill 批改 problem.md 中的题目与 "
                        "submission.pdf 中的学生证明，并严格按 skill 规定覆盖写入 "
                        "faithsieve_result.json。"
                    ),
                    files={
                        "problem.md": _problem_material(problem),
                        "submission.pdf": _submission_pdf(submission_id),
                        RESULT_FILENAME: json.dumps(
                            template, ensure_ascii=False, indent=2,
                        ).encode("utf-8"),
                    },
                    title=f"FaithSieve · {problem.get('title') or submission_id}"[:64],
                    timeout_seconds=FAITHSIEVE_TIMEOUT_SECONDS,
                    celery_app=self.app,
                    problem_id=int(problem["id"]),
                    problem_title=problem.get("title"),
                )
                raise self.retry(countdown=_POLL_SECONDS, max_retries=None)

            status = _current_turn_status(session)
            if status not in {
                "completed",
                "failed",
                "canceled",
                "cancelled",
                "cleanupfailed",
                "cleanup_failed",
            }:
                raise self.retry(countdown=_POLL_SECONDS, max_retries=None)
            if status != "completed":
                finish_run(
                    attempt_id,
                    "failed",
                    f"Judge Agent 未完成：{session.get('message') or status}",
                )
                return {"success": False, "message": "Judge Agent 未完成"}

            result = _read_result(session_id)
            if result["verdict"] == "inconclusive":
                finish_run(
                    attempt_id,
                    "inconclusive",
                    "证据不足，未覆盖原人工成绩",
                    result=result,
                )
                return {"success": False, "message": "FaithSieve 无法得出可靠结论"}

            update_submission_score_and_comment(
                submission_id,
                result["score"],
                result["comment"],
            )
            update_submission_status(
                submission_id,
                "Accepted" if result["score"] == 5 else "Unaccepted",
            )
            finish_run(
                attempt_id,
                "completed",
                f"评测完成，得分 {result['score']}/5",
                result=result,
            )
            return {"success": True, "score": result["score"]}
        except Retry:
            raise
        except ValueError as exc:
            finish_run(attempt_id, "failed", str(exc))
            return {"success": False, "message": str(exc)}
        except Exception as exc:
            raise self.retry(exc=exc, countdown=10, max_retries=None)

    return faithsieve_grade_submission


__all__ = ["FAITHSIEVE_TASK_NAME", "register_faithsieve_grading_task"]
