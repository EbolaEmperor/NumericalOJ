#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pymysql
from flask import Blueprint, request

from oj_modules.api.helpers import json_error, json_success, public_user
from oj_modules.auth_helpers import current_user, is_admin
from oj_modules.db_services import (
    get_all_classes_except_admin,
    get_all_problems,
    get_class_by_en,
    get_db_connection,
    get_problem,
    safe_table_name,
)
from oj_modules.ranking_db import list_competitions
from oj_modules.routes.homework_routes import (
    build_plagiarism_records_csv_response,
    delete_plagiarism_records_for_class,
    get_plagiarism_progress_payload,
    parse_plagiarism_mark_payload,
    start_plagiarism_mark_task,
    _load_plagiarism_records_for_class,
)


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


@homework_api_bp.route("/homework/plagiarism/start", methods=["POST"])
def plagiarism_start():
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    data = request.get_json(silent=True) or {}
    try:
        payload = parse_plagiarism_mark_payload(data)
    except ValueError as exc:
        return json_error(str(exc), 400)

    try:
        task_id = start_plagiarism_mark_task(
            payload["class_en"],
            payload["mode"],
            payload["threshold"],
            payload["targets"],
        )
    except RuntimeError as exc:
        return json_error(str(exc), 500)
    except Exception as exc:
        return json_error(f"启动失败: {exc}", 500)

    return json_success(message="查重任务已启动", task_id=task_id)


@homework_api_bp.route("/homework/plagiarism/progress/<task_id>", methods=["GET"])
def plagiarism_progress(task_id):
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    progress = get_plagiarism_progress_payload(task_id)
    if not progress:
        return json_error("任务不存在或已过期", 404)
    return json_success(progress=progress)


@homework_api_bp.route("/homework/plagiarism/records", methods=["GET"])
def plagiarism_records():
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    class_en = (request.args.get("sclass") or request.args.get("class_en") or "").strip()
    if not get_class_by_en(class_en):
        return json_error("班级不存在", 400)

    try:
        records = _load_plagiarism_records_for_class(class_en)
    except pymysql.Error:
        return json_error("数据库操作失败，请稍后再试", 500)
    return json_success(records=records, count=len(records))


@homework_api_bp.route("/homework/plagiarism/download", methods=["GET"])
def plagiarism_download():
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    class_en = (request.args.get("sclass") or request.args.get("class_en") or "").strip()
    if not get_class_by_en(class_en):
        return json_error("班级不存在", 400)

    try:
        return build_plagiarism_records_csv_response(class_en)
    except pymysql.Error:
        return json_error("数据库操作失败，请稍后再试", 500)


@homework_api_bp.route("/homework/plagiarism/delete", methods=["POST"])
def plagiarism_delete():
    user = current_user()
    if not is_admin(user):
        return json_error("无权限", 403)

    data = request.get_json(silent=True) or {}
    class_en = str(data.get("class_en") or "").strip()
    if not get_class_by_en(class_en):
        return json_error("班级不存在", 400)

    try:
        record_ids = [int(rid) for rid in (data.get("record_ids") or [])]
    except (TypeError, ValueError):
        return json_error("记录 ID 非法", 400)
    record_ids = list(dict.fromkeys(record_ids))
    if not record_ids:
        return json_error("请选择要删除的记录", 400)

    try:
        deleted = delete_plagiarism_records_for_class(class_en, record_ids)
    except pymysql.Error:
        return json_error("数据库操作失败，请稍后再试", 500)
    return json_success(message=f"已删除 {deleted} 条记录", deleted=deleted)
