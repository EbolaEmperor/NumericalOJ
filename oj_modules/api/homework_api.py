#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request

from oj_modules.api.helpers import json_error, json_success, public_user
from oj_modules.auth_helpers import current_user, is_admin
from oj_modules.db_services import (
    ensure_class_homework_columns,
    get_all_classes_except_admin,
    get_all_problems,
    get_class_by_en,
    get_db_connection,
    get_problem,
    safe_table_name,
)
from oj_modules.ranking_db import list_competitions


homework_api_bp = Blueprint("homework_api", __name__, url_prefix="/api/admin")


@homework_api_bp.route("/homework", methods=["GET"])
def homework_list():
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    selected_class = (request.args.get("sclass") or request.args.get("class_en") or "").strip()
    classes = get_all_classes_except_admin()
    valid_classes = [cls["class_en"] for cls in classes]
    if selected_class and selected_class not in valid_classes:
        return json_error("无效的班级选择", 400, selected_class=selected_class)

    homework_rows = []
    if selected_class:
        if not get_class_by_en(selected_class):
            return json_error("班级不存在", 404, selected_class=selected_class)
        ensure_class_homework_columns(selected_class)
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(f"SELECT * FROM {safe_table_name(selected_class)} ORDER BY id ASC")
                homework_rows = cursor.fetchall() or []
        finally:
            conn.close()

        for hw in homework_rows:
            if hw.get("ranking_competition_id"):
                hw["kind"] = "ranking"
                hw["is_ranking"] = True
                hw["competition_id"] = hw.get("ranking_competition_id")
                hw["problem_title"] = hw.get("problem_title") or "未知打榜赛"
            else:
                hw["kind"] = "problem"
                hw["is_ranking"] = False
                problem = get_problem(hw.get("problem_id"))
                hw["problem_title"] = problem["title"] if problem else "未知题目"
            hw["homework_id"] = hw.get("id")
            hw["title"] = hw.get("problem_title")
            hw["complete_count"] = hw.get("complete_cnt")

    all_problems = [{"id": p["id"], "title": p["title"]} for p in (get_all_problems() or [])]
    try:
        all_competitions = [
            {"id": c["id"], "title": c["title"], "scoring_mode": c.get("scoring_mode")}
            for c in (list_competitions(include_inactive=True) or [])
        ]
    except Exception:
        all_competitions = []

    return json_success(
        user=public_user(user),
        classes=classes,
        selected_class=selected_class,
        homeworks=homework_rows,
        homework_list=homework_rows,
        all_problems=all_problems,
        all_competitions=all_competitions,
    )
