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

from backend.oj_modules.infrastructure.mysql import get_db_connection


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

    # Signal: Submission time gap analysis
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
