#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import date, datetime
from decimal import Decimal

from flask import jsonify


_USER_PUBLIC_FIELDS = (
    "id",
    "username",
    "email",
    "class",
    "class_cn",
    "is_admin",
)

_PROBLEM_PUBLIC_FIELDS = (
    "id",
    "title",
    "content",
    "type",
    "lang",
    "max_score",
    "time_limit_ms",
    "submission_limit",
)


def to_jsonable(value):
    """把 DB row / datetime / Decimal 递归转成可读 JSON 值。"""
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        as_float = float(value)
        return int(as_float) if as_float.is_integer() else as_float
    return value


def public_user(user):
    if not user:
        return None
    return {key: to_jsonable(user.get(key)) for key in _USER_PUBLIC_FIELDS if key in user}


def public_problem(problem):
    if not problem:
        return None
    out = {key: to_jsonable(problem.get(key)) for key in _PROBLEM_PUBLIC_FIELDS if key in problem}
    if "cnt" in problem:
        out["submission_count"] = to_jsonable(problem.get("cnt"))
    return out


def json_success(**payload):
    data = {"success": True}
    data.update(payload)
    return jsonify(to_jsonable(data))


def json_error(message, status=400, **payload):
    data = {"success": False, "message": message}
    data.update(payload)
    return jsonify(to_jsonable(data)), status


def clamp_page(value, default=1):
    try:
        page = int(value)
    except Exception:
        page = default
    return max(1, page)


def clamp_limit(value, default=None, max_limit=500):
    if value is None or value == "":
        return default
    try:
        limit = int(value)
    except Exception:
        return default
    if limit < 0:
        return 0
    return min(limit, max_limit)


def apply_limit(rows, limit):
    if limit is None:
        return rows
    return list(rows or [])[:max(0, int(limit))]


def page_numbers(current_page, total_pages, radius=8):
    start = max(1, int(current_page) - int(radius))
    end = min(int(total_pages or 1), int(current_page) + int(radius))
    return list(range(start, end + 1))
