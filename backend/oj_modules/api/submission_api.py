#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request, url_for

from backend.oj_modules.api.helpers import (
    apply_limit,
    clamp_limit,
    clamp_page,
    json_error,
    json_success,
    page_numbers,
    public_problem,
    public_user,
)
from backend.oj_modules.security.auth import current_user, is_admin
from backend.oj_modules.db_services import (
    get_filtered_submissions_paginated,
    get_cached_ai_code_marks_for_submission,
    get_problem,
    get_submission_by_id,
    get_submission_panel_by_id,
    get_submission_problem_options,
    get_submission_summaries_by_user_and_problem_paginated,
    normalize_submission_list_status_filter,
)
from backend.oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from backend.oj_modules.problems.lean_workspace import get_submission_lean_workspace
from backend.oj_modules.submissions.presentation import (
    build_submission_panel_payload as _build_submission_panel_payload,
    load_written_submission_latex_and_error as _load_written_submission_latex_and_error,
    render_written_markdown_to_html as _render_written_markdown_to_html,
)
from backend.oj_modules.submissions.written_voting import (
    get_latest_attempt as get_latest_written_vote_attempt,
    public_attempt_payload,
)
from backend.oj_modules.submissions.visibility import (
    project_submission_grading,
    submission_is_judging,
)


submission_api_bp = Blueprint("submission_api", __name__, url_prefix="/api")


def _private_json_success(**payload):
    response = json_success(**payload)
    response.headers["Cache-Control"] = "no-store"
    return response


def _project_summary(row, user, problem=None):
    # 列表查询直接联查题目当前配置，避免逐行查题和读取旧快照配置。
    if problem is None:
        problem = {
            "type": row.get("current_problem_type") or row.get("problem_type"),
            "written_grading_mode": row.get("written_grading_mode"),
            "written_score_public": row.get("written_score_public"),
        }
        if "current_problem_type" in row and row["current_problem_type"] is None:
            problem["written_score_public"] = 0
    return project_submission_grading(row, problem, user)


def _submission_problem_payload(problem, user):
    payload = public_problem(problem)
    # 书面批改模式不属于公开题面契约；仅管理员详情页需要它决定是否展示
    # FaithSieve 的人工操作入口。
    if payload is not None and is_admin(user):
        payload["written_grading_mode"] = int(
            (problem or {}).get("written_grading_mode") or 1
        )
    return payload


def _decorate_submission_summary(row):
    out = dict(row or {})
    out["display_problem_title"] = _strip_problem_title_tags(out.get("problem_title"))
    out["is_ac"] = out.get("status") == "Accepted"
    out["display_language"] = str(out.get("lang") or "—").upper()
    try:
        max_score = int(out.get("max_score")) if out.get("max_score") is not None else None
    except (TypeError, ValueError):
        max_score = None
    out["display_max_score"] = (
        max_score
        if max_score is not None and max_score > 0
        else (out.get("test_points_count") or None)
    )
    out["detail_url"] = f"/submissions/{out.get('id')}"
    return out


def _submission_detail_payload(submission):
    prompt_generation_error = submission.get("prompt_generation_error") or ""
    return {
        "id": submission.get("id"),
        "username": submission.get("username"),
        "problem_id": submission.get("problem_id"),
        "problem_title": _strip_problem_title_tags(submission.get("problem_title")),
        "problem_type": submission.get("problem_type"),
        "code": submission.get("code") or "",
        "prompt_text": submission.get("prompt_text") or "",
        "generated_from_prompt": bool(submission.get("generated_from_prompt")),
        "prompt_generation_error": prompt_generation_error,
        "promptly_review_reply": prompt_generation_error,
        "status": submission.get("status"),
        "score": submission.get("score"),
        "result_visible": submission.get("result_visible", True),
        "is_judging": submission.get("is_judging"),
        "created_at": submission.get("created_at"),
        "test_points": submission.get("test_points") if isinstance(submission.get("test_points"), list) else [],
    }


def _submission_panel_payload(submission, raw_problem, user):
    vote_attempt = (
        get_latest_written_vote_attempt(int(submission["id"]))
        if int((raw_problem or {}).get("type") or submission.get("problem_type") or 0) == 2
        else None
    )
    is_judging = submission_is_judging(submission, vote_attempt)
    submission = project_submission_grading(submission, raw_problem, user)
    submission_id = int(submission["id"])
    panel_submission = dict(submission)
    panel_submission["problem_title"] = _strip_problem_title_tags(
        submission.get("problem_title")
    )
    panel_problem = dict(raw_problem or {})
    panel_problem["title"] = _strip_problem_title_tags(
        panel_problem.get("title")
    )
    payload = _build_submission_panel_payload(
        panel_submission,
        panel_problem,
        detail_url=f"/submissions/{submission_id}",
        status_stream_url=(
            f"/api/submissions/{submission_id}/events?view=panel"
        ),
        rejudge_url=(
            url_for(
                "rejudge.rejudge_submission",
                submission_id=submission_id,
            )
            if is_admin(user)
            else None
        ),
    )
    payload["result_visible"] = submission["result_visible"]
    payload["submission"]["result_visible"] = submission["result_visible"]
    payload["submission"]["is_judging"] = is_judging
    payload["problem"]["type"] = (raw_problem or {}).get("type") or submission.get("problem_type")
    payload["problem"]["written_grading_mode"] = int((raw_problem or {}).get("written_grading_mode") or 1)
    return payload


@submission_api_bp.route("/submissions", methods=["GET"])
def submissions():
    user = current_user()
    if not user:
        return json_error("请先登录", 401)

    page = clamp_page(request.args.get("page", 1))
    limit = clamp_limit(request.args.get("limit"), default=None)
    requested_per_page = clamp_limit(
        request.args.get("per_page"),
        default=20,
        max_limit=100,
    )
    per_page = max(1, int(requested_per_page or 20))
    query = str(request.args.get("q") or "").strip()[:120]
    status_filter = normalize_submission_list_status_filter(
        request.args.get("status")
    )
    problem_id = request.args.get("problem_id", type=int)
    if not problem_id or problem_id < 1:
        problem_id = None

    scope = "all" if user.get("is_admin") else "mine"
    scope_username = None if user.get("is_admin") else user["username"]
    rows, page, total_pages = get_filtered_submissions_paginated(
        username=scope_username,
        page=page,
        per_page=per_page,
        query=query,
        status_filter=status_filter,
        problem_id=problem_id,
        include_test_points=True,
        respect_grading_visibility=not is_admin(user),
    )

    decorated = [
        _decorate_submission_summary(_project_summary(row, user)) for row in rows
    ]
    visible = apply_limit(decorated, limit)
    problem_options = get_submission_problem_options(username=scope_username)
    current_problem_label = ""
    for option in problem_options:
        option["display_problem_title"] = _strip_problem_title_tags(
            option.get("problem_title")
        )
        option["filter_label"] = (
            f"P{int(option['problem_id']):04d} · "
            f"{option['display_problem_title']}"
        )
        if int(option["problem_id"]) == int(problem_id or 0):
            current_problem_label = option["filter_label"]
    return _private_json_success(
        user=public_user(user),
        scope=scope,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        page_numbers=page_numbers(page, total_pages, radius=10),
        submission_ids=[row["id"] for row in visible],
        submissions=visible,
        problem_options=problem_options,
        current_problem_label=current_problem_label,
        count=len(visible),
        filters={
            "q": query,
            "status": status_filter,
            "problem_id": problem_id,
        },
    )


@submission_api_bp.route("/problems/<int:problem_id>/submissions", methods=["GET"])
def problem_submissions(problem_id):
    user = current_user()
    if not user:
        return json_error("请先登录", 401)

    page = clamp_page(request.args.get("page", 1))
    limit = clamp_limit(request.args.get("limit"), default=None)
    per_page = 30
    rows, total_pages = get_submission_summaries_by_user_and_problem_paginated(
        user["username"], problem_id, page=page, per_page=per_page
    )
    problem = (
        get_problem(problem_id)
        if rows and not is_admin(user)
        else None
    )
    if rows and not is_admin(user) and problem is None:
        problem = {"type": 2, "written_score_public": 0}
    decorated = [
        _decorate_submission_summary(_project_summary(row, user, problem))
        for row in rows
    ]
    visible = apply_limit(decorated, limit)
    return _private_json_success(
        user=public_user(user),
        problem_id=problem_id,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        page_numbers=page_numbers(page, total_pages, radius=8),
        submission_ids=[row["id"] for row in visible],
        submissions=visible,
        count=len(visible),
    )


@submission_api_bp.route("/submissions/<int:submission_id>", methods=["GET"])
def submission_detail(submission_id):
    user = current_user()
    if not user:
        return json_error("请先登录", 401)

    panel_view = str(request.args.get("view") or "").strip().lower() == "panel"
    submission = (
        get_submission_panel_by_id(submission_id)
        if panel_view
        else get_submission_by_id(submission_id)
    )
    if not submission:
        return json_error("提交记录不存在", 404)
    if submission.get("username") != user.get("username") and not is_admin(user):
        return json_error("无权查看他人提交", 403)

    raw_problem = get_problem(submission.get("problem_id"))
    if panel_view:
        return _private_json_success(
            **_submission_panel_payload(submission, raw_problem, user)
        )

    problem = _submission_problem_payload(raw_problem, user)
    vote_attempt = (
        get_latest_written_vote_attempt(submission_id)
        if int((raw_problem or {}).get("type") or submission.get("problem_type") or 0) == 2
        else None
    )
    is_judging = submission_is_judging(submission, vote_attempt)
    submission = project_submission_grading(submission, raw_problem, user)
    submission["is_judging"] = is_judging
    plang = ((raw_problem or {}).get("lang") or "matlab").lower()
    lean_workspace = (
        get_submission_lean_workspace(submission_id)
        if plang in {"lean", "lean4"}
        else None
    )
    cached_ai_code_marks = None
    if (
        submission["result_visible"]
        and submission.get("problem_type") == 1
        and (raw_problem or {}).get("type") in {None, 1}
    ):
        cached_ai_code_marks = get_cached_ai_code_marks_for_submission(submission)

    submission_latex_text = ""
    submission_latex_error = ""
    submission_latex_html = ""
    written_grading_mode = 1
    written_vote = None
    if raw_problem and raw_problem.get("type") == 2:
        try:
            written_grading_mode = int(raw_problem.get("written_grading_mode") or 1)
        except Exception:
            written_grading_mode = 1
        if written_grading_mode == 1:
            submission_latex_text, submission_latex_error = _load_written_submission_latex_and_error(submission)
            submission_latex_html = _render_written_markdown_to_html(submission_latex_text)
            if not submission["result_visible"]:
                submission_latex_error = ""
        if submission["result_visible"]:
            written_vote = public_attempt_payload(
                vote_attempt
            )

    return _private_json_success(
        user=public_user(user),
        result_visible=submission["result_visible"],
        submission=_submission_detail_payload(submission),
        test_points=submission.get("test_points") or [],
        problem=problem,
        plang=plang,
        lean_workspace=lean_workspace,
        cached_ai_code_marks=cached_ai_code_marks,
        submission_latex_text=submission_latex_text,
        submission_latex_error=submission_latex_error,
        submission_latex_html=submission_latex_html,
        written_submission={
            "show_latex_transcription": bool(raw_problem and raw_problem.get("type") == 2 and written_grading_mode == 1),
            "vote": written_vote,
        },
    )
