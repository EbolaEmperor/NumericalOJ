#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""题目目录、作业可见性与题目列表缓存。"""

import json
import time
from datetime import datetime, timedelta

from oj_modules.classroom.dashboard import (
    clear_dashboard_cache,
    visible_classes_for_user_cached,
)
from oj_modules.db_services import (
    get_db_connection,
    get_today_submission_total_from_counter,
)
from oj_modules.problems.presentation import (
    strip_problem_title_tags as _strip_problem_title_tags,
)
from oj_modules.homework.scores import homework_score_snapshot


__all__ = (
    "get_class_grades_map",
    "get_homeworks",
    "get_homeworks_and_grades_map",
    "get_homeworks_for_class",
    "get_today_submission_counts",
    "get_user_classes_cached",
    "invalidate_problem_list_cache_all",
    "invalidate_problem_list_cache_for_class",
    "invalidate_problem_list_cache_for_user",
)


_HOMEWORKS_CACHE_TTL_SECONDS = 10
_CLASS_GRADES_CACHE_TTL_SECONDS = 20
_homeworks_cache = {}
_class_grades_cache = {}

def _attach_user_homework_scores(result, username, cursor):
    """按每条作业自己的 DDL 回填用户成绩，禁止全局 max_score 污染作业成绩。"""
    if not username:
        return

    problem_ids = sorted({
        int(hw["problem_id"])
        for rows in result.values()
        for hw in rows
        if hw.get("kind") == "problem" and hw.get("problem_id") is not None
    })
    problem_submissions = {}
    if problem_ids:
        placeholders = ",".join(["%s"] * len(problem_ids))
        cursor.execute(
            f"""
            SELECT id, problem_id, score, status, created_at
            FROM submissions
            WHERE username=%s AND problem_id IN ({placeholders})
            """,
            tuple([username] + problem_ids),
        )
        for submission in cursor.fetchall() or []:
            problem_submissions.setdefault(int(submission["problem_id"]), []).append(submission)

    competition_ids = sorted({
        int(hw["competition_id"])
        for rows in result.values()
        for hw in rows
        if hw.get("kind") == "ranking" and hw.get("competition_id") is not None
    })
    ranking_submissions = {}
    if competition_ids:
        placeholders = ",".join(["%s"] * len(competition_ids))
        cursor.execute(
            f"""
            SELECT id, competition_id, score, status, created_at
            FROM ranking_submissions
            WHERE username=%s AND competition_id IN ({placeholders})
              AND score IS NOT NULL
            """,
            tuple([username] + competition_ids),
        )
        for submission in cursor.fetchall() or []:
            ranking_submissions.setdefault(
                int(submission["competition_id"]), []
            ).append(submission)

    for rows in result.values():
        for homework in rows:
            if homework.get("kind") == "ranking":
                submissions = ranking_submissions.get(
                    int(homework["competition_id"]), []
                )
                snapshot = homework_score_snapshot(
                    submissions, homework.get("ddl"), require_terminal=False,
                )
            else:
                submissions = problem_submissions.get(
                    int(homework["problem_id"]), []
                )
                snapshot = homework_score_snapshot(
                    submissions, homework.get("ddl"),
                )

            eligible = snapshot["eligible"]
            best = snapshot["best"]
            practice_best = snapshot["practice_best"]

            homework["max_score"] = best.get("score") if best else None
            homework["best_submission_id"] = best.get("id") if best else None
            homework["best_submission_at"] = best.get("created_at") if best else None
            homework["practice_max_score"] = (
                practice_best.get("score") if practice_best else None
            )
            homework["has_submission"] = bool(eligible)
            homework["has_pending_submission"] = snapshot["has_pending"]
            if homework.get("kind") == "ranking":
                homework["is_completed"] = best is not None
            else:
                total_score = homework.get("total_score")
                homework["is_completed"] = bool(
                    best is not None
                    and total_score is not None
                    and float(best.get("score") or 0) >= float(total_score or 0)
                )


def invalidate_problem_list_cache_for_user(user_id=None, username=None):
    """
    失效指定用户在 problem list 相关路径上的缓存。
    """
    if user_id is not None:
        clear_dashboard_cache()
        for cache_key in list(_homeworks_cache.keys()):
            if cache_key[0] == user_id:
                _homeworks_cache.pop(cache_key, None)

    if username:
        for cache_key in list(_class_grades_cache.keys()):
            if cache_key[0] == username:
                _class_grades_cache.pop(cache_key, None)


def invalidate_problem_list_cache_for_class(class_en):
    """
    失效包含指定班级的作业/成绩缓存。
    """
    if not class_en:
        return

    clear_dashboard_cache()

    for cache_key in list(_homeworks_cache.keys()):
        class_list = cache_key[1]
        if class_en in class_list:
            _homeworks_cache.pop(cache_key, None)

    for cache_key in list(_class_grades_cache.keys()):
        class_list = cache_key[1]
        if class_en in class_list:
            _class_grades_cache.pop(cache_key, None)


def invalidate_problem_list_cache_all():
    """
    全量失效 problem list 相关缓存。
    """
    clear_dashboard_cache()
    _homeworks_cache.clear()
    _class_grades_cache.clear()


def _decode_plagiarism_usernames(raw_value):
    if not raw_value:
        return []
    try:
        value = json.loads(raw_value)
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
    except Exception:
        pass
    return [part.strip() for part in str(raw_value).split(',') if part.strip()]


def _format_plagiarism_notice(record):
    if not record:
        return None
    names = _decode_plagiarism_usernames(record.get("matched_usernames"))
    names_text = "、".join(names) if names else "其他同学"
    rule = str(record.get("comparison_rule") or "").strip()
    if rule == "byte-identical":
        return f"经查，您本题代码与 {names_text} 完全一致"

    try:
        pct = float(rule) * 100
        pct_text = str(int(pct)) if pct.is_integer() else f"{pct:.1f}".rstrip("0").rstrip(".")
    except ValueError:
        pct_text = rule
    return f"经查，您本题代码与 {names_text} 的相似度达到 {pct_text}% 以上"


def _load_plagiarism_notice_map(username, class_en_list, cursor):
    if not username or not class_en_list:
        return {}

    placeholders = ",".join(["%s"] * len(class_en_list))
    try:
        cursor.execute(
            f"""
            SELECT pr.class_en, pr.problem_id, pr.comparison_rule, pr.matched_usernames
            FROM plagiarism_records pr
            JOIN (
                SELECT class_en, problem_id, MAX(id) AS latest_id
                FROM plagiarism_records
                WHERE username=%s AND class_en IN ({placeholders})
                GROUP BY class_en, problem_id
            ) latest ON latest.latest_id = pr.id
            """,
            tuple([username] + list(class_en_list)),
        )
        return {
            (row["class_en"], int(row["problem_id"])): row
            for row in cursor.fetchall()
            if row.get("problem_id") is not None
        }
    except Exception:
        return {}


def get_user_classes_cached(user_id):
    return visible_classes_for_user_cached({"id": user_id, "is_admin": 0})


def _get_homeworks_for_classes(user_id, class_en_list, cursor=None, username=None):
    """
    批量读取多个班级作业，并一次性补齐题目标题、AC 状态、最高分。
    支持两类作业：题目（problem_id）与打榜赛（ranking_competition_id）。
    返回: {class_en: [hw, ...]}
    """
    result = {cls: [] for cls in class_en_list}
    if not class_en_list:
        return result

    cache_key = (user_id, tuple(class_en_list))
    now_ts = time.time()
    cached = _homeworks_cache.get(cache_key)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    db_cursor = cursor
    conn = None
    try:
        if db_cursor is None:
            conn = get_db_connection()
            db_cursor = conn.cursor()

        union_parts = []
        union_params = []
        for cls in class_en_list:
            union_parts.append(
                f"SELECT %s AS class_en, id, problem_id, ranking_competition_id, ddl, complete_cnt FROM `{cls}`"
            )
            union_params.append(cls)
        if not union_parts:
            return result

        union_sql = " UNION ALL ".join(union_parts)
        db_cursor.execute(
            f"""
            SELECT t.class_en, t.id, t.problem_id, t.ranking_competition_id, t.ddl, t.complete_cnt,
                   p.title AS problem_title, p.max_score AS total_score,
                   p.type AS problem_type, p.lang AS problem_lang,
                   rc.title AS rk_title, rc.max_score AS rk_total, rc.scoring_mode AS rk_mode
            FROM ({union_sql}) t
            LEFT JOIN problems p ON p.id = t.problem_id
            LEFT JOIN ranking_competitions rc ON rc.id = t.ranking_competition_id
            ORDER BY t.class_en ASC, t.id ASC
            """,
            tuple(union_params),
        )
        homework_rows = db_cursor.fetchall()
        plagiarism_notice_map = _load_plagiarism_notice_map(username, class_en_list, db_cursor)

        for row in homework_rows:
            cls = row["class_en"]
            if cls not in result:
                continue
            rcid = row.get("ranking_competition_id")
            if rcid:
                is_elo = (row.get("rk_mode") == "elo")
                hw = {
                    "id": row["id"],
                    "kind": "ranking",
                    "competition_id": int(rcid),
                    "problem_id": None,
                    "ddl": row["ddl"],
                    "complete_cnt": row["complete_cnt"],
                    "problem_title": row.get("rk_title") or row.get("problem_title") or f"打榜赛 {rcid}",
                    "problem_type": None,
                    "problem_lang": None,
                    "scoring_mode": row.get("rk_mode") or "absolute",
                    "total_score": (None if is_elo else row.get("rk_total")),
                    "is_completed": False,
                    "max_score": None,
                    "has_submission": False,
                }
            else:
                pid = row["problem_id"]
                try:
                    pid = int(pid)
                except Exception:
                    pass
                hw = {
                    "id": row["id"],
                    "kind": "problem",
                    "problem_id": pid,
                    "ddl": row["ddl"],
                    "complete_cnt": row["complete_cnt"],
                    "problem_title": row.get("problem_title"),
                    "problem_type": row.get("problem_type"),
                    "problem_lang": row.get("problem_lang"),
                    "total_score": row.get("total_score"),
                    "is_completed": False,
                    "max_score": None,
                    "plagiarism_notice": _format_plagiarism_notice(plagiarism_notice_map.get((cls, pid))),
                }
            result[cls].append(hw)

        _attach_user_homework_scores(result, username, db_cursor)

        for cls, hw_list in result.items():
            for hw in hw_list:
                if hw.get("kind") == "ranking":
                    continue
                pid = hw["problem_id"]
                hw["problem_title"] = (
                    hw.get("problem_title") if hw.get("problem_title") else f"Problem {pid}"
                )
                hw["problem_title"] = _strip_problem_title_tags(hw["problem_title"])
                hw["total_score"] = (
                    hw.get("total_score") if hw.get("total_score") is not None else 0
                )
                hw["has_submission"] = bool(hw.get("has_submission"))
        _homeworks_cache[cache_key] = {
            "expires_at": now_ts + _HOMEWORKS_CACHE_TTL_SECONDS,
            "value": result,
        }
        return result
    finally:
        if conn is not None:
            conn.close()


def get_class_grades_map(student_id, class_en_list, cursor=None):
    if not class_en_list:
        return {}

    cache_key = (student_id, tuple(class_en_list))
    now_ts = time.time()
    cached = _class_grades_cache.get(cache_key)
    if cached and now_ts < cached["expires_at"]:
        return cached["value"]

    db_cursor = cursor
    conn = None
    try:
        if db_cursor is None:
            conn = get_db_connection()
            db_cursor = conn.cursor()

        placeholders = ",".join(["%s"] * len(class_en_list))
        db_cursor.execute(
            f"""
            SELECT class_en, regular_score, final_score
            FROM final_exam_scores
            WHERE student_id=%s AND class_en IN ({placeholders})
            """,
            tuple([student_id] + class_en_list),
        )
        rows = db_cursor.fetchall()
    except Exception:
        return {}
    finally:
        if conn is not None:
            conn.close()

    grades_map = {}
    for row in rows:
        grades_map[row["class_en"]] = {
            "regular_score": (
                round(row["regular_score"], 1) if row["regular_score"] is not None else None
            ),
            "final_score": (
                round(row["final_score"], 1) if row["final_score"] is not None else None
            ),
        }
    _class_grades_cache[cache_key] = {
        "expires_at": now_ts + _CLASS_GRADES_CACHE_TTL_SECONDS,
        "value": grades_map,
    }
    return grades_map


def get_homeworks_and_grades_map(user_id, student_id, class_en_list):
    """
    在缓存未命中时复用同一连接拿到作业数据与班级成绩，减少 problem_list 路径连接数。
    """
    if not class_en_list:
        return {}, {}

    class_key = tuple(class_en_list)
    now_ts = time.time()
    h_cached = _homeworks_cache.get((user_id, class_key))
    g_cached = _class_grades_cache.get((student_id, class_key))
    if (
        h_cached and g_cached
        and now_ts < h_cached["expires_at"]
        and now_ts < g_cached["expires_at"]
    ):
        return h_cached["value"], g_cached["value"]

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            homeworks_map = _get_homeworks_for_classes(user_id, class_en_list, cursor=cursor, username=student_id)
            grades_map = get_class_grades_map(student_id, class_en_list, cursor=cursor)
    finally:
        conn.close()
    return homeworks_map, grades_map


def get_homeworks(user):
    classes = get_user_classes_cached(user['id'])
    class_tables = [c['class_en'] for c in classes]
    if not class_tables:
        return []

    homeworks_by_class = _get_homeworks_for_classes(user['id'], class_tables, username=user.get('username'))
    merged = {}
    for cls in class_tables:
        for hw in homeworks_by_class.get(cls, []):
            # 本函数仅用于题目访问/DDL 判定，跳过打榜赛作业行
            if hw.get('kind') == 'ranking' or hw.get('problem_id') is None:
                continue
            pid = hw['problem_id']
            existing = merged.get(pid)
            if existing is None:
                merged[pid] = {
                    "problem_id": pid,
                    "ddl": hw.get("ddl"),
                    "problem_title": hw.get("problem_title", f"Problem {pid}"),
                    "complete_cnt": 1 if hw.get("is_completed") else 0,
                }
                continue

            old_ddl = existing.get("ddl")
            new_ddl = hw.get("ddl")
            if old_ddl is None or (new_ddl is not None and new_ddl > old_ddl):
                existing["ddl"] = new_ddl
                existing["problem_title"] = hw.get("problem_title", existing["problem_title"])
            if hw.get("is_completed"):
                existing["complete_cnt"] = 1

    return [merged[pid] for pid in sorted(merged.keys())]


def get_homeworks_for_class(user_id, class_en):
    return _get_homeworks_for_classes(user_id, [class_en]).get(class_en, [])


def get_today_submission_counts():
    """返回 (total_submissions, total_accepted)。

    total_submissions 走 daily_submission_stats 计数表（含 programming + ranking 两类提交）。
    total_accepted 仍直接查 submissions 表（仅 programming），单日范围 + idx_submissions_created_status，
    本身已经很快，没必要也搬到计数表。
    """
    total_submissions = get_today_submission_total_from_counter()

    today_start = datetime.combine(datetime.today().date(), datetime.min.time())
    tomorrow_start = today_start + timedelta(days=1)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) AS total_accepted
                FROM submissions
                WHERE created_at >= %s AND created_at < %s
                  AND status = 'Accepted'
                """,
                (today_start, tomorrow_start),
            )
            row = cursor.fetchone() or {}
            total_accepted = int(row.get('total_accepted') or 0)
    finally:
        conn.close()
    return total_submissions, total_accepted
