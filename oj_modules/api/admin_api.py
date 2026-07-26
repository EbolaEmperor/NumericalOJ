#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, request

from oj_modules.api.helpers import clamp_page, json_error, json_success, page_numbers, public_user
from oj_modules.auth_helpers import current_user, is_admin
from oj_modules.db_services import get_all_classes, get_db_connection
from oj_modules.routes.problem_core_routes import get_agent_runs_paginated


admin_api_bp = Blueprint("admin_api", __name__, url_prefix="/api/admin")


def _require_admin_user():
    user = current_user()
    if not is_admin(user):
        return None, json_error("无权限", 403)
    return user, None


@admin_api_bp.route("/users", methods=["GET"])
def users():
    admin, error = _require_admin_user()
    if error is not None:
        return error

    page = clamp_page(request.args.get("page", 1))
    search_username = (request.args.get("username") or "").strip()
    search_class = (request.args.get("class") or "").strip()
    per_page = 50

    user_where_clauses = []
    user_where_params = []

    if search_username:
        user_where_clauses.append("u.username LIKE %s")
        user_where_params.append(f"%{search_username}%")

    if search_class:
        user_where_clauses.append(
            "u.id IN (SELECT user_id FROM user_class_map WHERE class_en = %s)"
        )
        user_where_params.append(search_class)

    user_where_sql = ""
    if user_where_clauses:
        user_where_sql = "WHERE " + " AND ".join(user_where_clauses)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            count_sql = f"""
                SELECT COUNT(*) AS total
                FROM (
                    SELECT u.id
                    FROM users u
                    {user_where_sql}
                    ORDER BY u.id ASC
                ) t
            """
            cursor.execute(count_sql, user_where_params)
            total = int((cursor.fetchone() or {}).get("total") or 0)
            total_pages = max(1, (total + per_page - 1) // per_page)
            if page > total_pages:
                page = total_pages

            data_sql = f"""
                SELECT u.id, u.username, u.email, u.is_admin
                FROM users u
                {user_where_sql}
                ORDER BY u.id ASC
                LIMIT %s OFFSET %s
            """
            params = user_where_params + [per_page, (page - 1) * per_page]
            cursor.execute(data_sql, params)
            rows = cursor.fetchall() or []

        if rows:
            uid_list = [u["id"] for u in rows]
            placeholders = ",".join(["%s"] * len(uid_list))
            with conn.cursor() as cursor:
                map_sql = f"""
                    SELECT m.user_id, m.class_en, ct.class_cn
                    FROM user_class_map m
                    JOIN class_table ct ON ct.class_en = m.class_en
                    WHERE m.user_id IN ({placeholders})
                    ORDER BY m.user_id ASC, m.class_en ASC
                """
                cursor.execute(map_sql, uid_list)
                mapping_rows = cursor.fetchall() or []
        else:
            mapping_rows = []
    finally:
        conn.close()

    class_map = {row["id"]: [] for row in rows}
    for row in mapping_rows:
        class_map.setdefault(row["user_id"], []).append({
            "class_en": row["class_en"],
            "class_cn": row["class_cn"],
        })

    out = []
    for row in rows:
        classes = class_map.get(row["id"], [])
        out.append({
            "id": row["id"],
            "username": row["username"],
            "email": row.get("email") or "",
            "is_admin": row.get("is_admin"),
            "classes": classes,
            "classes_display": " / ".join(
                f"{c.get('class_cn') or c.get('class_en')}({c.get('class_en')})"
                for c in classes
            ),
        })

    return json_success(
        user=public_user(admin),
        params={"page": page, "username": search_username, "class": search_class},
        users=out,
        classes=get_all_classes(),
        page=page,
        per_page=per_page,
        total=total,
        total_pages=total_pages,
        page_numbers=page_numbers(page, total_pages),
    )


@admin_api_bp.route("/agent-tasks", methods=["GET"])
def agent_tasks():
    admin, error = _require_admin_user()
    if error is not None:
        return error

    page = clamp_page(request.args.get("page", 1))
    per_page = 20
    runs, total_pages = get_agent_runs_paginated(page=page, per_page=per_page)
    for run in runs:
        run["display_problem_title"] = (
            str(run.get("problem_title") or "").strip()
            or f"Problem {run.get('problem_id') or '-'}"
        )
        run["display_status"] = str(run.get("status") or "Pending")
        run["display_rounds"] = f"{int(run.get('rounds_run') or 0)}"
        run["display_best_score"] = int(run.get("best_score") or 0)

    return json_success(
        user=public_user(admin),
        agent_runs=runs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        page_numbers=page_numbers(page, total_pages),
    )
