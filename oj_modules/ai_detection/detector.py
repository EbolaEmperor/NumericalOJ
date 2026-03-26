#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI code detection orchestrator.

Combines LLM detection and behavioral analysis into a final risk score.
"""

import json

from oj_modules.ai_detection.llm_detector import detect_with_llm
from oj_modules.ai_detection.behavior_detector import detect_behavior


# Behavior is an additive bonus on top of LLM score, not a diluting factor.
# final = min(1.0, llm_score + behavior_score * W_BEHAVIOR_BONUS)
W_BEHAVIOR_BONUS = 0.3

# Risk level thresholds
RISK_HIGH = 0.7
RISK_MEDIUM = 0.4


def _compute_risk_level(score):
    if score >= RISK_HIGH:
        return "high"
    elif score >= RISK_MEDIUM:
        return "medium"
    return "low"


def run_detection(submission, problem, model_id="qwen", task_id=None):
    """
    Run AI detection on a single submission.

    Args:
        submission: dict with keys id, username, problem_id, code, status, score, created_at
        problem: dict with keys id, title, content, lang
        model_id: LLM model to use ("qwen" or "matlab_ai_detect")
        task_id: Celery task ID — stored in the result row so the task's records
                 can be deleted cleanly without touching other tasks' results.

    Returns:
        dict with detection results ready for database insertion:
            submission_id, username, problem_id,
            llm_score, llm_evidence,
            behavior_score, behavior_detail,
            final_score, risk_level, task_id
    """
    submission_id = submission["id"]
    username = submission["username"]
    problem_id = submission["problem_id"]
    code = submission.get("code", "")
    problem_content = problem.get("content", "")

    result = {
        "submission_id": submission_id,
        "username": username,
        "problem_id": problem_id,
        "llm_score": None,
        "llm_evidence": None,
        "behavior_score": None,
        "behavior_detail": None,
        "final_score": 0.0,
        "risk_level": "low",
        "task_id": task_id,
    }

    # --- LLM Detection ---
    # Let LLMDetectionFailed propagate — caller should not upsert a 0.0 record.
    llm_result = detect_with_llm(code, problem_content, model_id=model_id)

    if llm_result:
        result["llm_score"] = round(llm_result["score"], 4)
        result["llm_evidence"] = json.dumps(
            llm_result["evidence"], ensure_ascii=False
        )[:4000]

    # --- Behavior Detection ---
    behavior_result = None
    try:
        behavior_result = detect_behavior(username, problem_id, submission_id)
    except Exception as e:
        print(f"[AI Detection] Behavior detection error for submission {submission_id}: {e}")
        traceback.print_exc()

    if behavior_result:
        result["behavior_score"] = round(behavior_result["score"], 4)
        result["behavior_detail"] = json.dumps(
            behavior_result["signals"], ensure_ascii=False
        )[:4000]

    # --- Score Fusion ---
    # LLM score is the base; behavior is an additive bonus (never dilutes).
    llm = result["llm_score"]
    beh = result["behavior_score"] or 0.0

    if llm is not None:
        final = min(1.0, llm + beh * W_BEHAVIOR_BONUS)
    elif beh > 0:
        final = beh * W_BEHAVIOR_BONUS
    else:
        final = 0.0

    result["final_score"] = round(final, 4)
    result["risk_level"] = _compute_risk_level(final)

    return result
