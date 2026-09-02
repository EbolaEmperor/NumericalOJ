"""桌面工作台所需的聚合数据。

本模块只负责可缓存的只读查询与纯数据整形，不依赖 Flask request/session。
提交历史按“用户当前班级关系”归属，这是产品已确认的统计口径。
"""

from __future__ import annotations

import json
import math
import threading
import time
import uuid
from datetime import date, datetime, time as datetime_time, timedelta
from zoneinfo import ZoneInfo

from backend.oj_modules.db_services import (
    get_all_classes,
    get_user_classes,
)
from backend.oj_modules.infrastructure.mysql import get_db_connection, safe_table_name


ACTIVITY_DAYS = 12 * 7
SHANGHAI_TZ = ZoneInfo("Asia/Shanghai")
CLASS_ACTIVITY_CACHE_KEY = "numoj:class-activity:v1"
CLASS_ACTIVITY_CACHE_STAGING_PREFIX = f"{CLASS_ACTIVITY_CACHE_KEY}:staging"
CLASS_ACTIVITY_CACHE_META_FIELD = "__meta__"
_class_activity_redis = None
_CACHE_TTL_SECONDS = 30
_CACHE_MAX_ENTRIES = 512
_cache_lock = threading.RLock()
_cache: dict[tuple, dict] = {}
_cache_loads: dict[tuple, threading.Event] = {}
_cache_generation = 0

_NON_TERMINAL_STATUSES = (
    "Pending",
    "Queued",
    "Running",
    "Judging",
    "Processing",
    "Waiting",
    "Generating",
)


def clear_dashboard_cache():
    """清空短时聚合缓存，供写路径显式失效和单元测试使用。"""
    global _cache_generation
    with _cache_lock:
        _cache.clear()
        _cache_generation += 1


def init_class_activity_cache(redis_client):
    """注入班级活跃度 Redis 客户端；组合根负责调用。"""
    global _class_activity_redis
    _class_activity_redis = redis_client


def _cached(key, loader, *, now_monotonic=None):
    current = time.monotonic() if now_monotonic is None else now_monotonic
    while True:
        with _cache_lock:
            expired = [
                cache_key
                for cache_key, item in _cache.items()
                if current >= item["expires_at"]
            ]
            for cache_key in expired:
                _cache.pop(cache_key, None)

            item = _cache.get(key)
            if item:
                return item["value"]

            pending = _cache_loads.get(key)
            if pending is None:
                pending = threading.Event()
                _cache_loads[key] = pending
                load_generation = _cache_generation
                break
        pending.wait()

    try:
        value = loader()
    except Exception:
        with _cache_lock:
            _cache_loads.pop(key, None)
            pending.set()
        raise

    with _cache_lock:
        if load_generation == _cache_generation:
            if len(_cache) >= _CACHE_MAX_ENTRIES:
                oldest = min(
                    _cache,
                    key=lambda cache_key: _cache[cache_key]["expires_at"],
                )
                _cache.pop(oldest, None)
            _cache[key] = {
                "expires_at": current + _CACHE_TTL_SECONDS,
                "value": value,
            }
        _cache_loads.pop(key, None)
        pending.set()
        return value


def visible_classes_for_user(user):
    """返回用户可见班级；管理员可见全部班级。"""
    if not user:
        return []
    if int(user.get("is_admin") or 0) == 1:
        return get_all_classes() or []
    return get_user_classes(user["id"]) or []


def visible_classes_for_user_cached(user):
    """短时缓存可见班级，供同一页面的业务上下文和导航共同复用。"""
    if not user:
        return []
    cache_key = (
        "visible-classes",
        int(user.get("id") or 0),
        int(user.get("is_admin") or 0),
    )
    return _cached(cache_key, lambda: visible_classes_for_user(user))


def select_visible_class(classes, requested_class_en=None):
    """在可见班级中解析 URL 选择，否则按班级代码稳定选择第一项。

    这里的选择仅是当前请求的查看上下文，不写入用户资料或会话。
    """
    if not classes:
        return None
    if requested_class_en:
        for item in classes:
            if item.get("class_en") == requested_class_en:
                return item
    return min(classes, key=lambda item: str(item.get("class_en") or ""))


def _membership_predicate(alias):
    return (
        f"EXISTS (SELECT 1 FROM users u "
        f"WHERE u.username = {alias}.username AND u.is_admin = 0 "
        f"AND EXISTS (SELECT 1 FROM user_class_map ucm "
        f"WHERE ucm.user_id = u.id AND ucm.class_en = %s))"
    )


def _activity_intensities(counts):
    """把非零计数按当前 12 周峰值映射到 1..4，零保持 0。"""
    peak = max(counts, default=0)
    if peak <= 0:
        return [0 for _ in counts]
    return [0 if count <= 0 else min(4, max(1, math.ceil(count * 4 / peak))) for count in counts]


def build_activity_calendar(counts_by_day, *, today=None, days=ACTIVITY_DAYS):
    """按自然周补齐热力图；当前周未来的日期作为空白占位。"""
    current_day = today or datetime.now(SHANGHAI_TZ).date()
    weeks = max(1, math.ceil(days / 7))
    start_day = current_day - timedelta(days=current_day.weekday() + (weeks - 1) * 7)
    raw_counts = [
        0
        if start_day + timedelta(days=offset) > current_day
        else int(counts_by_day.get(start_day + timedelta(days=offset), 0) or 0)
        for offset in range(weeks * 7)
    ]
    intensities = _activity_intensities(raw_counts)
    return [
        {
            "day": start_day + timedelta(days=offset),
            "count": raw_counts[offset],
            "intensity": intensities[offset],
            "weekday": (start_day + timedelta(days=offset)).weekday(),
            "future": start_day + timedelta(days=offset) > current_day,
        }
        for offset in range(weeks * 7)
    ]


def load_all_class_activity(*, today=None, days=ACTIVITY_DAYS):
    """从 MySQL 批量生成所有班级活跃度快照，仅供后台刷新任务调用。"""
    end_day = today or datetime.now(SHANGHAI_TZ).date()
    weeks = max(1, math.ceil(days / 7))
    start_day = end_day - timedelta(
        days=end_day.weekday() + (weeks - 1) * 7
    )
    start_at = datetime.combine(start_day, datetime_time.min)
    end_at = datetime.combine(end_day + timedelta(days=1), datetime_time.min)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SET time_zone = '+08:00'")
            cursor.execute("SELECT class_en FROM class_table ORDER BY class_en ASC")
            class_codes = [
                str(row.get("class_en") or "")
                for row in (cursor.fetchall() or [])
                if row.get("class_en")
            ]
            cursor.execute(
                """
                SELECT activity.class_en,
                       activity.activity_day,
                       SUM(activity.submission_count) AS submission_count
                FROM (
                    SELECT ucm.class_en,
                           DATE(s.created_at) AS activity_day,
                           COUNT(*) AS submission_count
                    FROM submissions s
                    JOIN users u
                      ON u.username = s.username AND u.is_admin = 0
                    JOIN user_class_map ucm ON ucm.user_id = u.id
                    WHERE s.created_at >= %s AND s.created_at < %s
                    GROUP BY ucm.class_en, DATE(s.created_at)
                    UNION ALL
                    SELECT ucm.class_en,
                           DATE(rs.created_at) AS activity_day,
                           COUNT(*) AS submission_count
                    FROM ranking_submissions rs
                    JOIN users u
                      ON u.username = rs.username AND u.is_admin = 0
                    JOIN user_class_map ucm ON ucm.user_id = u.id
                    WHERE rs.created_at >= %s AND rs.created_at < %s
                      AND rs.source = 'self'
                    GROUP BY ucm.class_en, DATE(rs.created_at)
                ) activity
                GROUP BY activity.class_en, activity.activity_day
                ORDER BY activity.class_en ASC, activity.activity_day ASC
                """,
                (start_at, end_at, start_at, end_at),
            )
            counts_by_class = {class_en: {} for class_en in class_codes}
            for row in cursor.fetchall() or []:
                class_en = str(row.get("class_en") or "")
                if not class_en:
                    continue
                raw_day = row.get("activity_day")
                if isinstance(raw_day, datetime):
                    raw_day = raw_day.date()
                if isinstance(raw_day, date):
                    counts_by_class.setdefault(class_en, {})[raw_day] = int(
                        row.get("submission_count") or 0
                    )
            return {
                class_en: build_activity_calendar(
                    counts,
                    today=end_day,
                    days=days,
                )
                for class_en, counts in counts_by_class.items()
            }
    finally:
        conn.close()


def _serialize_activity(activity):
    return json.dumps(
        [
            {
                **item,
                "day": item["day"].isoformat(),
            }
            for item in activity
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _deserialize_activity(payload):
    if not payload:
        return []
    decoded = json.loads(payload)
    if not isinstance(decoded, list):
        raise ValueError("班级活跃度缓存格式错误")
    activity = []
    for item in decoded:
        if not isinstance(item, dict):
            raise ValueError("班级活跃度缓存条目格式错误")
        restored = dict(item)
        restored["day"] = date.fromisoformat(str(item.get("day") or ""))
        activity.append(restored)
    return activity


def publish_class_activity_snapshot(
    redis_client,
    snapshot,
    *,
    generated_at=None,
    days=ACTIVITY_DAYS,
):
    """写入临时 hash 后原子替换正式快照，失败时保留上一版。"""
    generated_at = generated_at or datetime.now(SHANGHAI_TZ)
    staging_key = f"{CLASS_ACTIVITY_CACHE_STAGING_PREFIX}:{uuid.uuid4().hex}"
    mapping = {
        str(class_en): _serialize_activity(activity)
        for class_en, activity in snapshot.items()
    }
    mapping[CLASS_ACTIVITY_CACHE_META_FIELD] = json.dumps(
        {
            "generated_at": generated_at.isoformat(),
            "class_count": len(snapshot),
            "days": int(days),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        redis_client.hset(staging_key, mapping=mapping)
        # 临时键异常残留时自动回收；RENAME 后正式快照不设置过期时间，刷新失败
        # 也能持续提供最后一次成功数据。
        redis_client.expire(staging_key, 60 * 60)
        pipe = redis_client.pipeline(transaction=True)
        pipe.rename(staging_key, CLASS_ACTIVITY_CACHE_KEY)
        pipe.persist(CLASS_ACTIVITY_CACHE_KEY)
        pipe.execute()
    except Exception:
        try:
            redis_client.delete(staging_key)
        except Exception:
            pass
        raise
    return {
        "class_count": len(snapshot),
        "generated_at": generated_at.isoformat(),
    }


def refresh_class_activity_snapshot(redis_client, *, today=None, days=ACTIVITY_DAYS):
    """刷新全部班级快照；数据库查询与 Redis 发布不在用户请求路径。"""
    snapshot = load_all_class_activity(today=today, days=days)
    return publish_class_activity_snapshot(redis_client, snapshot, days=days)


def get_class_activity(class_en, *, redis_client=None):
    """只从 Redis 快照读取班级活跃度，不在请求路径回退查询 MySQL。"""
    if not class_en:
        return []
    client = redis_client or _class_activity_redis
    if client is None:
        raise RuntimeError("班级活跃度 Redis 缓存尚未初始化")
    payload = client.hget(CLASS_ACTIVITY_CACHE_KEY, str(class_en))
    # 首次部署任务尚未完成，或班级刚创建尚未进入下一次快照时，短暂展示空图。
    return _deserialize_activity(payload)


def _metric_rows(query, params):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall() or []
    finally:
        conn.close()


def _get_submission_metrics(
    entity_ids,
    *,
    table,
    alias,
    entity_column,
    class_en=None,
    self_only=False,
):
    ids = tuple(sorted({int(value) for value in entity_ids if value is not None}))
    if not ids:
        return {}
    placeholders = ",".join(["%s"] * len(ids))
    excluded = ",".join(["%s"] * len(_NON_TERMINAL_STATUSES))
    membership_sql = ""
    params = list(ids) + list(_NON_TERMINAL_STATUSES)
    if class_en:
        membership_sql = f" AND {_membership_predicate(alias)}"
        params.append(class_en)
    source_sql = f"AND {alias}.source = 'self'" if self_only else ""
    cache_key = (
        "submission-metrics",
        table,
        entity_column,
        ids,
        class_en or "",
        self_only,
    )

    def load():
        rows = _metric_rows(
            f"""
            SELECT {alias}.{entity_column} AS entity_id,
                   COUNT(*) AS submission_count,
                   SUM(CASE WHEN {alias}.status = 'Accepted' THEN 1 ELSE 0 END) AS accepted_count
            FROM {table} {alias}
            WHERE {alias}.{entity_column} IN ({placeholders})
              {source_sql}
              AND {alias}.status NOT IN ({excluded})
              {membership_sql}
            GROUP BY {alias}.{entity_column}
            """,
            tuple(params),
        )
        result = {}
        for row in rows:
            total = int(row.get("submission_count") or 0)
            accepted = int(row.get("accepted_count") or 0)
            result[int(row["entity_id"])] = {
                "submission_count": total,
                "accepted_count": accepted,
                "pass_rate": (accepted / total) if total else None,
            }
        return result

    return _cached(cache_key, load)


def get_problem_submission_metrics(problem_ids, *, class_en=None):
    """返回普通题目的终态提交数与通过率，键为 problem id。"""
    return _get_submission_metrics(
        problem_ids,
        table="submissions",
        alias="s",
        entity_column="problem_id",
        class_en=class_en,
    )


def get_ranking_submission_metrics(competition_ids, *, class_en=None):
    """返回打榜赛终态提交数与通过率，键为 competition id。"""
    return _get_submission_metrics(
        competition_ids,
        table="ranking_submissions",
        alias="rs",
        entity_column="competition_id",
        class_en=class_en,
        self_only=True,
    )


def attach_submission_metrics(homeworks, *, class_en=None):
    """返回带聚合指标的副本，保持作业缓存值不可变。"""
    enriched = [dict(item) for item in homeworks]
    problem_ids = [item.get("problem_id") for item in enriched if item.get("problem_id")]
    competition_ids = [
        item.get("competition_id") or item.get("ranking_competition_id")
        for item in enriched
        if item.get("competition_id") or item.get("ranking_competition_id")
        if str(item.get("scoring_mode") or "absolute").lower() != "elo"
    ]
    problem_metrics = get_problem_submission_metrics(problem_ids, class_en=class_en)
    ranking_metrics = get_ranking_submission_metrics(competition_ids, class_en=class_en)
    for item in enriched:
        if item.get("problem_id"):
            item["submission_metrics"] = problem_metrics.get(int(item["problem_id"]))
        else:
            competition_id = item.get("competition_id") or item.get("ranking_competition_id")
            if str(item.get("scoring_mode") or "absolute").lower() == "elo":
                item["submission_metrics"] = None
            else:
                item["submission_metrics"] = (
                    ranking_metrics.get(int(competition_id))
                    if competition_id
                    else None
                )
    return enriched


def get_layout_navigation_context(user, *, selected_class_en=None):
    """返回桌面侧栏的真实计数；查询失败由调用方降级为空上下文。"""
    if not user:
        return {"counts": {}, "agent_active": False}
    classes = visible_classes_for_user_cached(user)
    selected = select_visible_class(classes, selected_class_en)
    class_en = selected.get("class_en") if selected else None
    cache_key = (
        "layout-navigation",
        int(user.get("id") or 0),
        int(user.get("is_admin") or 0),
        class_en or "",
    )

    def load():
        counts = {"homeworks": 0}
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                if class_en:
                    cursor.execute(
                        f"SELECT COUNT(*) AS total FROM {safe_table_name(class_en)}"
                    )
                    counts["homeworks"] = int((cursor.fetchone() or {}).get("total") or 0)

                if int(user.get("is_admin") or 0) == 1:
                    cursor.execute("SELECT COUNT(*) AS total FROM submissions")
                    counts["submissions"] = int((cursor.fetchone() or {}).get("total") or 0)
                    cursor.execute("SELECT COUNT(*) AS total FROM problems")
                    counts["problems"] = int((cursor.fetchone() or {}).get("total") or 0)
                    cursor.execute("SELECT COUNT(*) AS total FROM users")
                    counts["users"] = int((cursor.fetchone() or {}).get("total") or 0)
                    cursor.execute(
                        "SELECT 1 AS active FROM agent_task_runs "
                        "WHERE status IN ('Pending', 'Running') LIMIT 1"
                    )
                    agent_active = bool(cursor.fetchone())
                else:
                    cursor.execute(
                        "SELECT COUNT(*) AS total FROM submissions WHERE username=%s",
                        (user.get("username"),),
                    )
                    counts["submissions"] = int((cursor.fetchone() or {}).get("total") or 0)
                    cursor.execute("SELECT COUNT(*) AS total FROM problems")
                    counts["problems"] = int((cursor.fetchone() or {}).get("total") or 0)
                    cursor.execute(
                        "SELECT 1 AS active FROM agent_task_runs "
                        "WHERE requested_by=%s "
                        "AND status IN ('Pending', 'Running') LIMIT 1",
                        (user.get("username"),),
                    )
                    agent_active = bool(cursor.fetchone())
        finally:
            conn.close()
        return {"counts": counts, "agent_active": agent_active}

    payload = _cached(cache_key, load)
    return {**payload, "selected_class_en": class_en}
