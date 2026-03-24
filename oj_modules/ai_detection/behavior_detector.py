#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral signal analysis for AI code detection.

Analyzes submission patterns to identify suspicious behavior:
- First-submission AC on non-trivial problems
- Very few attempts before AC
- Sudden quality jumps compared to historical submissions
- Abnormally short time between submissions
"""

from oj_modules.db_services import get_db_connection


def _get_user_submission_history(username, problem_id):
    """Get all submissions by this user for this problem, ordered by time."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, score, status, created_at "
                "FROM submissions "
                "WHERE username=%s AND problem_id=%s "
                "ORDER BY created_at ASC",
                (username, problem_id),
            )
            return cursor.fetchall()
    finally:
        conn.close()


def _get_user_all_problem_stats(username):
    """Get per-problem AC attempt counts for the user across all problems."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT problem_id, "
                "       COUNT(*) AS total_submissions, "
                "       SUM(CASE WHEN status='Accepted' THEN 1 ELSE 0 END) AS ac_count, "
                "       MIN(CASE WHEN status='Accepted' THEN id END) AS first_ac_id, "
                "       MIN(id) AS first_submission_id "
                "FROM submissions "
                "WHERE username=%s AND problem_type=1 "
                "GROUP BY problem_id",
                (username,),
            )
            return cursor.fetchall()
    finally:
        conn.close()


def _get_problem_global_stats(problem_id):
    """Get global stats for a problem: average attempts before AC."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # For each user who AC'd this problem, count submissions before first AC
            cursor.execute(
                "SELECT AVG(attempt_count) AS avg_attempts, COUNT(*) AS ac_user_count "
                "FROM ("
                "  SELECT s.username, COUNT(*) AS attempt_count "
                "  FROM submissions s "
                "  INNER JOIN ("
                "    SELECT username, MIN(id) AS first_ac_id "
                "    FROM submissions "
                "    WHERE problem_id=%s AND status='Accepted' "
                "    GROUP BY username"
                "  ) ac ON s.username = ac.username AND s.id <= ac.first_ac_id "
                "  WHERE s.problem_id=%s "
                "  GROUP BY s.username"
                ") sub",
                (problem_id, problem_id),
            )
            row = cursor.fetchone()
            if row and row.get("avg_attempts") is not None:
                row["avg_attempts"] = float(row["avg_attempts"])
            return row if row else {"avg_attempts": None, "ac_user_count": 0}
    finally:
        conn.close()


def detect_behavior(username, problem_id, submission_id):
    """
    Analyze behavioral signals for a submission.

    Returns:
        dict with keys:
            score (float 0~1): behavioral suspicion score
            signals (list[dict]): detected signals with name, value, weight
    """
    signals = []
    history = _get_user_submission_history(username, problem_id)

    if not history:
        return {"score": 0.0, "signals": []}

    # Find the target submission's position in history
    target_idx = None
    for i, sub in enumerate(history):
        if sub["id"] == submission_id:
            target_idx = i
            break

    if target_idx is None:
        return {"score": 0.0, "signals": []}

    target_sub = history[target_idx]

    # Signal 1: First-submission AC
    # If the student AC'd on their very first submission for this problem
    if target_sub["status"] == "Accepted" and target_idx == 0:
        global_stats = _get_problem_global_stats(problem_id)
        avg_attempts = global_stats.get("avg_attempts")
        ac_user_count = global_stats.get("ac_user_count") or 0

        if avg_attempts is not None and avg_attempts > 1.5 and ac_user_count >= 3:
            # Non-trivial problem (average > 1.5 attempts), first-try AC is suspicious
            weight = min(0.8, (avg_attempts - 1.0) / 4.0)
            signals.append({
                "name": "first_submission_ac",
                "description": f"首次提交即AC（该题平均需要{avg_attempts:.1f}次尝试）",
                "value": 1.0,
                "weight": weight,
            })
        elif avg_attempts is None or ac_user_count < 3:
            # Not enough data, give mild signal
            signals.append({
                "name": "first_submission_ac",
                "description": "首次提交即AC（数据不足以对比）",
                "value": 1.0,
                "weight": 0.2,
            })

    # Signal 2: Very few attempts before AC
    if target_sub["status"] == "Accepted" and target_idx > 0:
        attempts_before_ac = target_idx + 1
        global_stats = _get_problem_global_stats(problem_id)
        avg_attempts = global_stats.get("avg_attempts")

        if avg_attempts is not None and avg_attempts > 3.0 and attempts_before_ac <= 2:
            weight = min(0.5, (avg_attempts - attempts_before_ac) / 6.0)
            signals.append({
                "name": "few_attempts",
                "description": f"仅{attempts_before_ac}次提交即AC（该题平均{avg_attempts:.1f}次）",
                "value": 1.0,
                "weight": weight,
            })

    # Signal 3: No wrong attempts at all (across all problems)
    user_stats = _get_user_all_problem_stats(username)
    if user_stats and len(user_stats) >= 3:
        perfect_count = sum(
            1 for s in user_stats
            if s["ac_count"] and s["ac_count"] > 0
            and s["first_ac_id"] == s["first_submission_id"]
        )
        perfect_ratio = perfect_count / len(user_stats)
        if perfect_ratio > 0.7 and len(user_stats) >= 5:
            signals.append({
                "name": "consistently_perfect",
                "description": f"该学生{len(user_stats)}道题中{perfect_count}道首次即AC（{perfect_ratio:.0%}）",
                "value": perfect_ratio,
                "weight": 0.5,
            })

    # Signal 4: Submission time gap analysis
    if target_idx > 0:
        prev_time = history[target_idx - 1]["created_at"]
        curr_time = target_sub["created_at"]
        gap_seconds = (curr_time - prev_time).total_seconds()
        # If resubmission within 30 seconds with perfect score, suspicious
        if gap_seconds < 30 and target_sub["status"] == "Accepted":
            signals.append({
                "name": "rapid_resubmit_ac",
                "description": f"距上次提交仅{gap_seconds:.0f}秒即AC（可能是粘贴AI生成代码）",
                "value": 1.0,
                "weight": 0.3,
            })

    # Compute weighted score
    if not signals:
        return {"score": 0.0, "signals": signals}

    total_weight = sum(s["weight"] for s in signals)
    if total_weight == 0:
        return {"score": 0.0, "signals": signals}

    weighted_sum = sum(s["value"] * s["weight"] for s in signals)
    # Normalize: cap at 1.0
    score = min(1.0, weighted_sum / max(total_weight, 1.0) * min(total_weight / 0.5, 1.0))

    return {"score": round(score, 4), "signals": signals}
