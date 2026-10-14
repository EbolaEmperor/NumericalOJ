"""管理员批量重测的筛选、只读预览与一次性确认。"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from datetime import datetime

from backend.oj_modules.db_services import get_submission_problem_options
from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.presentation import strip_problem_title_tags


CONFIRMATION_TTL_SECONDS = 15 * 60
LATEST_REJUDGE_BATCH_KEY = "rejudge:latest-batch"
LEGACY_REJUDGE_PROGRESS_KEY = "rejudge:timerange"
_CONFIRMATION_PREFIX = "rejudge:confirmation:"
_CONSUME_CONFIRMATION = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


class RejudgeConfirmationUnavailable(RuntimeError):
    """确认存储不可用时拒绝投递，不能退回仅核对数量。"""


def _confirmation_command(redis_client, command, *args):
    try:
        return getattr(redis_client, command)(*args)
    except Exception as exc:
        raise RejudgeConfirmationUnavailable("重测确认暂不可用，请稍后重试") from exc


def _string_choices(value, label, max_length):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label}筛选必须是列表")
    choices = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item.strip()) > max_length:
            raise ValueError(f"{label}筛选无效")
        choices.append(item.strip())
    return sorted(set(choices))


def _problem_choices(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("题目筛选必须是列表")
    choices = []
    for item in value:
        if isinstance(item, bool) or not re.fullmatch(r"[0-9]{1,10}", str(item)):
            raise ValueError("题目 ID 必须是正整数")
        parsed = int(item)
        if not 1 <= parsed <= 2_147_483_647:
            raise ValueError("题目 ID 必须是有效的正整数")
        choices.append(parsed)
    return sorted(set(choices))


def _normalize_datetime(raw, *, inclusive_end=False):
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ValueError("请提供有效的起始与结束时间")
    text = raw.strip().replace("T", " ")
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
            if inclusive_end and fmt == "%Y-%m-%d %H:%M":
                parsed = parsed.replace(second=59)
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    raise ValueError("请提供有效的起始与结束时间")


def normalize_rejudge_filters(payload):
    """空选项表示全选；维度之间取交集，同一维度内取并集。"""
    if not isinstance(payload, Mapping):
        raise ValueError("重测筛选参数无效")
    start = _normalize_datetime(payload.get("start"))
    end = _normalize_datetime(payload.get("end"), inclusive_end=True)
    if bool(start) != bool(end):
        raise ValueError("请提供有效的起始与结束时间")
    if start and start > end:
        raise ValueError("起始时间不能晚于结束时间")
    return {
        "usernames": _string_choices(payload.get("usernames"), "用户名", 50),
        "problem_ids": _problem_choices(payload.get("problem_ids")),
        "statuses": _string_choices(payload.get("statuses"), "状态", 50),
        "start": start,
        "end": end,
    }


def get_filtered_rejudge_submissions(filters):
    """只读取将被重测的提交，不重置状态或投递任务。"""
    conditions, params = [], []
    for field, column in (
        ("usernames", "username"),
        ("problem_ids", "problem_id"),
        ("statuses", "status"),
    ):
        choices = filters[field]
        if choices:
            placeholders = ",".join(["%s"] * len(choices))
            conditions.append(f"{column} IN ({placeholders})")
            params.extend(choices)
    if filters["start"]:
        conditions.append("created_at BETWEEN %s AND %s")
        params.extend([filters["start"], filters["end"]])
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, problem_type, status, created_at FROM submissions"
                + where + " ORDER BY id ASC",
                tuple(params),
            )
            return cursor.fetchall()
    finally:
        conn.close()


def get_rejudge_filter_options():
    """只公开管理员筛选需要的用户名、题目标签和原始状态。"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT DISTINCT username FROM submissions ORDER BY username ASC")
            usernames = [row["username"] for row in cursor.fetchall() if row.get("username")]
            cursor.execute("SELECT DISTINCT status FROM submissions ORDER BY status ASC")
            statuses = [row["status"] for row in cursor.fetchall() if row.get("status")]
    finally:
        conn.close()
    problems = get_submission_problem_options()
    return {
        "usernames": usernames,
        "problem_options": [
            {
                "problem_id": int(row["problem_id"]),
                "filter_label": (
                    f"P{int(row['problem_id']):04d} · "
                    f"{strip_problem_title_tags(row.get('problem_title')) or ''}"
                ),
            }
            for row in problems
        ],
        "statuses": statuses,
    }


def _format_datetime(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if isinstance(value, datetime) else str(value or "")


def _snapshot(username, filters, rows):
    return {
        "username": username,
        "filters": filters,
        "submission_ids": [int(row["id"]) for row in rows],
    }


def batch_progress_key(batch_id):
    """每批使用独立进度键，避免并发重测互相覆盖 done/total。"""
    if not isinstance(batch_id, str):
        raise ValueError("重测批次无效")
    try:
        valid = str(uuid.UUID(batch_id)) == batch_id
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("重测批次无效")
    return "rejudge:batch:" + batch_id


def resolve_rejudge_progress_key(redis_client, batch_id=None):
    if batch_id is not None:
        return batch_progress_key(batch_id)
    latest_batch = redis_client.get(LATEST_REJUDGE_BATCH_KEY)
    return batch_progress_key(latest_batch) if latest_batch else LEGACY_REJUDGE_PROGRESS_KEY


def build_rejudge_preview(redis_client, username, filters, rows):
    created = [_format_datetime(row.get("created_at")) for row in rows if row.get("created_at")]
    preview = {
        "preview": True,
        "total": len(rows),
        "min_created_at": min(created) if created else "",
        "max_created_at": max(created) if created else "",
        **filters,
    }
    if rows:
        token = str(uuid.uuid4())
        _confirmation_command(
            redis_client,
            "setex",
            _CONFIRMATION_PREFIX + token,
            CONFIRMATION_TTL_SECONDS,
            json.dumps(_snapshot(username, filters, rows), ensure_ascii=False),
        )
        preview["confirmation_token"] = token
    return preview


def consume_rejudge_confirmation(redis_client, username, filters, rows, payload):
    """确认须对应预览的实际提交；原子消费令牌后才能投递，避免重复点击。"""
    if not rows:
        return False
    raw_total = payload.get("confirm_total")
    if isinstance(raw_total, bool) or not re.fullmatch(r"[0-9]{1,10}", str(raw_total)):
        return False
    if int(raw_total) != len(rows):
        return False
    token = payload.get("confirmation_token")
    if not isinstance(token, str):
        return False
    try:
        if str(uuid.UUID(token)) != token:
            return False
    except ValueError:
        return False
    key = _CONFIRMATION_PREFIX + token
    raw_snapshot = _confirmation_command(redis_client, "get", key)
    if not raw_snapshot:
        return False
    try:
        snapshot = json.loads(raw_snapshot)
    except (ValueError, TypeError):
        return False
    if snapshot != _snapshot(username, filters, rows):
        return False
    return bool(_confirmation_command(redis_client, "eval", _CONSUME_CONFIRMATION, 1, key, raw_snapshot))
