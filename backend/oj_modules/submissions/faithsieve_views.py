"""FaithSieve 管理页的只读查询与公开字段投影。"""

from __future__ import annotations

import json
import re

from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.presentation import strip_problem_title_tags
from backend.oj_modules.shared.markdown import render_rich_markdown
from backend.oj_modules.submissions.faithsieve import normalize_execution_mode, parse_result


PER_PAGE = 20
STATUSES = ("queued", "running", "completed", "failed", "inconclusive")
_ATTEMPT_ID = re.compile(r"[a-f0-9]{32}\Z")
_FILTER_FROM = "FROM faithsieve_grading_runs AS r LEFT JOIN submissions AS s ON s.id=r.submission_id"
_RUN_FROM = _FILTER_FROM + """
    LEFT JOIN problems AS p ON p.id=r.problem_id
    LEFT JOIN users AS u ON u.username=s.username
    LEFT JOIN llm_endpoints AS e ON e.id=r.endpoint_id
    LEFT JOIN agent_sessions AS a ON a.id=(
        SELECT MIN(a2.id) FROM agent_sessions AS a2
        WHERE a2.task_kind='judge' AND a2.judge_kind='faithsieve'
          AND a2.attempt_id=r.attempt_id AND a2.submission_id=r.submission_id
          AND a2.problem_id=r.problem_id
          AND ((r.execution_mode='workflow' AND a2.requested_by=r.requested_by)
               OR ((r.execution_mode='skill' OR r.execution_mode IS NULL)
                   AND a2.requested_by=s.username AND a2.session_id=r.session_id))
          AND a2.harness=r.harness AND a2.endpoint_source='global'
          AND a2.endpoint_id=r.endpoint_id
    )
"""
_RUN_COLUMNS = """
    r.id, r.attempt_id, r.submission_id, r.problem_id, r.requested_by,
    r.harness, r.endpoint_id, r.execution_mode, r.session_id, r.task_id, r.status, r.message, r.result_json,
    r.created_at, r.updated_at, r.started_at, r.finished_at,
    s.username, u.id AS user_id, s.created_at AS submission_created_at,
    COALESCE(NULLIF(p.title,''),s.problem_title,'') AS problem_title,
    COALESCE(NULLIF(a.endpoint_model,''),e.model) AS endpoint_model,
    CASE WHEN NULLIF(a.endpoint_model,'') IS NOT NULL THEN a.endpoint_revision
         ELSE e.revision END AS endpoint_revision,
    CASE WHEN NULLIF(a.endpoint_model,'') IS NOT NULL THEN 'judge'
         WHEN e.model IS NOT NULL THEN 'configured' ELSE NULL END AS model_source
"""


def valid_attempt_id(value):
    return isinstance(value, str) and _ATTEMPT_ID.fullmatch(value) is not None


def _positive_id(value, label):
    if value is None or value == "":
        return None
    if isinstance(value, bool) or len(str(value)) > 10 or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError(f"{label}必须是正整数")
    parsed = int(value)
    if not 1 <= parsed <= 2_147_483_647:
        raise ValueError(f"{label}必须是有效的正整数")
    return parsed


def normalize_filters(*, status=None, username=None, problem_id=None, submission_id=None):
    status = str(status or "").strip().lower()
    if status and status not in STATUSES:
        raise ValueError("评测状态无效")
    username = str(username or "").strip()
    if len(username) > 50:
        raise ValueError("用户名筛选不能超过 50 个字符")
    return {
        "status": status or None,
        "username": username,
        "problem_id": _positive_id(problem_id, "题目 ID"),
        "submission_id": _positive_id(submission_id, "提交 ID"),
    }


def _where(filters):
    clauses, values = [], []
    if filters["status"]:
        clauses.append("r.status=%s")
        values.append(filters["status"])
    if filters["username"]:
        clauses.append("s.username LIKE %s ESCAPE '\\\\'")
        literal = filters["username"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        values.append(f"%{literal}%")
    for key in ("problem_id", "submission_id"):
        if filters[key] is not None:
            clauses.append(f"r.{key}=%s")
            values.append(filters[key])
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), tuple(values)


def _result(value):
    try:
        loaded = json.loads(value) if isinstance(value, (str, bytes)) else value
        return parse_result(loaded)
    except (TypeError, ValueError):
        return None


def public_run(row):
    """只复制页面所需字段，不把凭据、请求或 DB 内部列带到 API。"""
    out = {key: row.get(key) for key in (
        "id", "attempt_id", "submission_id", "problem_id", "requested_by", "session_id", "task_id",
        "status", "message", "created_at", "updated_at", "started_at", "finished_at",
        "username", "user_id", "submission_created_at",
    )}
    out["problem_title"] = strip_problem_title_tags(row.get("problem_title")) or ""
    out["execution_mode"] = normalize_execution_mode(row.get("execution_mode"), default="skill")
    # users 只存用户名，没有独立姓名列；保持实际身份，不推断学生姓名。
    out["student_name"] = row.get("username") or ""
    out["result"] = _result(row.get("result_json"))
    out["runtime"] = {
        "harness": row.get("harness"), "endpoint_id": row.get("endpoint_id"),
        "model": row.get("endpoint_model"), "endpoint_revision": row.get("endpoint_revision"),
        "model_source": row.get("model_source"),
    }
    out["detail_url"] = f"/admin/faithsieve/{out['attempt_id']}"
    return out


def list_faithsieve_runs(*, page=1, status=None, username=None, problem_id=None, submission_id=None):
    filters = normalize_filters(status=status, username=username, problem_id=problem_id, submission_id=submission_id)
    where, params = _where(filters)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            counts = ", ".join(f"SUM(r.status='{status}') AS {status}" for status in STATUSES)
            cursor.execute(f"SELECT COUNT(*) AS total, {counts} {_FILTER_FROM} {where}", params)
            counts = cursor.fetchone() or {}
            summary = {key: int(counts.get(key) or 0) for key in ("total", *STATUSES)}
            total_pages = max(1, (summary["total"] + PER_PAGE - 1) // PER_PAGE)
            page = min(max(1, int(page)), total_pages)
            cursor.execute(
                f"SELECT {_RUN_COLUMNS} {_RUN_FROM} {where} ORDER BY r.created_at DESC, r.id DESC LIMIT %s OFFSET %s",
                (*params, PER_PAGE, (page - 1) * PER_PAGE),
            )
            rows = cursor.fetchall() or []
        return {
            "runs": [public_run(row) for row in rows], "page": page, "per_page": PER_PAGE,
            "total": summary["total"], "total_pages": total_pages,
            "summary": summary, "filters": filters,
        }
    finally:
        conn.close()


def _fetch_run(attempt_id, *, details=False):
    if not valid_attempt_id(attempt_id):
        return None
    columns = _RUN_COLUMNS
    if details:
        columns += """, s.id AS existing_submission_id, s.status AS submission_status,
            s.score AS submission_score, s.code AS submission_comment,
            p.id AS existing_problem_id, p.content AS problem_content,
            p.type AS problem_type, p.max_score AS problem_max_score"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT {columns} {_RUN_FROM} WHERE r.attempt_id=%s", (attempt_id,))
            return cursor.fetchone()
    finally:
        conn.close()


def get_faithsieve_run(attempt_id):
    row = _fetch_run(attempt_id)
    return public_run(row) if row else None


def get_faithsieve_detail(attempt_id):
    row = _fetch_run(attempt_id, details=True)
    if not row:
        return None
    run = public_run(row)
    submission = None
    if row.get("existing_submission_id") is not None:
        sid = int(row["existing_submission_id"])
        comment = str(row.get("submission_comment") or "")
        submission = {
            "id": sid, "username": row.get("username"), "student_name": run["student_name"],
            "user_id": row.get("user_id"), "problem_id": row.get("problem_id"),
            "created_at": row.get("submission_created_at"), "status": row.get("submission_status"),
            "score": row.get("submission_score"), "comment": comment,
            "comment_html": render_rich_markdown(comment),
            "pdf_url": f"/api/submissions/{sid}/file", "detail_url": f"/submissions/{sid}",
        }
    problem = None
    if row.get("existing_problem_id") is not None:
        content = str(row.get("problem_content") or "")
        problem = {
            "id": row["existing_problem_id"], "title": run["problem_title"],
            "content": content, "content_html": render_rich_markdown(content),
            "type": row.get("problem_type"), "max_score": row.get("problem_max_score"),
        }
    return {"run": run, "submission": submission, "problem": problem, "result": run["result"]}
