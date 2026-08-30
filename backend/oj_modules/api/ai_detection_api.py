#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request

from backend.oj_modules.ai_detection.task_tracker import TASK_TYPE_LABELS, get_recent_tasks
from backend.oj_modules.ai_detection.presentation import serialize_detection_result
from backend.oj_modules.ai_detection.llm_detector import get_available_endpoints
from backend.oj_modules.api.helpers import json_error, json_success, public_user
from backend.oj_modules.security.auth import current_user, is_admin
from backend.oj_modules.db_services import (
    get_ai_detection_dashboard_summary,
    get_ai_detection_results_for_problem,
    get_ai_detection_results_for_user,
    get_all_classes,
    get_all_problems,
    get_problem,
)
from backend.oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)


ai_detection_api_bp = Blueprint("ai_detection_api", __name__, url_prefix="/api/admin/ai-detection")


def _require_admin():
    user = current_user()
    if not user:
        return None, json_error("未登录", 401)
    if not is_admin(user):
        return None, json_error("无权限", 403)
    return user, None


@ai_detection_api_bp.route("/dashboard", methods=["GET"])
def dashboard():
    user, error = _require_admin()
    if error is not None:
        return error
    summary = get_ai_detection_dashboard_summary()
    classes = get_all_classes()
    problems = [
        p for p in get_all_problems()
        if int(p.get("type") or 1) == 1
    ]
    problems.sort(key=lambda p: p["id"])
    for p in problems:
        p["display_title"] = _strip_problem_title_tags(p.get("title") or "")
    return json_success(
        user=public_user(user),
        summary=summary,
        classes=classes,
        problems=problems,
        endpoints=get_available_endpoints(),
        view="dashboard",
    )


@ai_detection_api_bp.route("/problem/<int:problem_id>", methods=["GET"])
def problem(problem_id):
    user, error = _require_admin()
    if error is not None:
        return error
    problem_row = get_problem(problem_id)
    if not problem_row:
        return json_error("题目不存在", 404)
    risk_filter = (request.args.get("risk") or "").strip() or None
    results = [
        serialize_detection_result(r)
        for r in get_ai_detection_results_for_problem(
            problem_id,
            risk_level=risk_filter,
        )
    ]
    return json_success(
        user=public_user(user),
        view="problem",
        problem=problem_row,
        risk_filter=risk_filter,
        results=results,
        count=len(results),
    )


@ai_detection_api_bp.route("/student/<username>", methods=["GET"])
def student(username):
    user, error = _require_admin()
    if error is not None:
        return error
    results = [
        serialize_detection_result(r)
        for r in get_ai_detection_results_for_user(username)
    ]
    return json_success(
        user=public_user(user),
        view="student",
        target_username=username,
        results=results,
        count=len(results),
    )


@ai_detection_api_bp.route("/tasks", methods=["GET"])
def tasks():
    user, error = _require_admin()
    if error is not None:
        return error
    rows = get_recent_tasks(limit=20)
    for row in rows:
        row["type_label"] = TASK_TYPE_LABELS.get(row.get("task_type", ""), row.get("task_type", ""))
    return json_success(user=public_user(user), tasks=rows)
