#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

from flask import Blueprint, request

from oj_modules.ai_detection.task_tracker import TASK_TYPE_LABELS, get_recent_tasks
from oj_modules.api.helpers import json_error, json_success, public_user
from oj_modules.auth_helpers import current_user, is_admin
from oj_modules.db_services import (
    get_ai_detection_dashboard_summary,
    get_ai_detection_results_for_problem,
    get_ai_detection_results_for_user,
    get_all_classes,
    get_all_problems,
    get_problem,
)
from oj_modules.routes.ai_detection_routes import _strip_problem_title_tags


ai_detection_api_bp = Blueprint("ai_detection_api", __name__, url_prefix="/api/admin/ai-detection")


def _require_admin():
    user = current_user()
    if not user:
        return None, json_error("未登录", 401)
    if not is_admin(user):
        return None, json_error("无权限", 403)
    return user, None


def _decorate_result(row):
    out = dict(row or {})
    out["problem_title"] = _strip_problem_title_tags(out.get("problem_title") or "")
    for src, dst in (("llm_evidence", "_evidence"), ("behavior_detail", "_signals")):
        try:
            out[dst] = json.loads(out.get(src) or "[]")
        except Exception:
            out[dst] = []
    return out


@ai_detection_api_bp.route("/dashboard", methods=["GET"])
def dashboard():
    user, error = _require_admin()
    if error is not None:
        return error
    summary = get_ai_detection_dashboard_summary()
    classes = get_all_classes()
    problems = [
        p for p in get_all_problems()
        if (p.get("lang") or "matlab").strip().lower() == "matlab"
        and int(p.get("type") or 1) == 1
    ]
    problems.sort(key=lambda p: p["id"])
    for p in problems:
        p["display_title"] = _strip_problem_title_tags(p.get("title") or "")
    return json_success(
        user=public_user(user),
        summary=summary,
        classes=classes,
        problems=problems,
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
    results = [_decorate_result(r) for r in get_ai_detection_results_for_problem(problem_id, risk_level=risk_filter)]
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
    results = [_decorate_result(r) for r in get_ai_detection_results_for_user(username)]
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
