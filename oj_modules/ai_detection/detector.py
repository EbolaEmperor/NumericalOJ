#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI code detection orchestrator.

Combines LLM detection and behavioral analysis into a final risk score.
"""

import json
import traceback

from oj_modules.ai_detection.llm_detector import detect_with_llm
from oj_modules.ai_detection.behavior_detector import detect_behavior


# Weights for combining signals
W_LLM = 0.65
W_BEHAVIOR = 0.35

# Risk level thresholds
RISK_HIGH = 0.7
RISK_MEDIUM = 0.4


def _compute_risk_level(score):
    if score >= RISK_HIGH:
        return "high"
    elif score >= RISK_MEDIUM:
        return "medium"
    return "low"


def run_detection(submission, problem):
    """
    Run AI detection on a single submission.

    Args:
        submission: dict with keys id, username, problem_id, code, status, score, created_at
        problem: dict with keys id, title, content, lang

    Returns:
        dict with detection results ready for database insertion:
            submission_id, username, problem_id,
            llm_score, llm_evidence,
            behavior_score, behavior_detail,
            final_score, risk_level
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
    }

    # --- LLM Detection ---
    llm_result = None
    try:
        llm_result = detect_with_llm(code, problem_content)
    except Exception as e:
        print(f"[AI Detection] LLM detection error for submission {submission_id}: {e}")
        traceback.print_exc()

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
    scores = []
    weights = []

    if result["llm_score"] is not None:
        scores.append(result["llm_score"])
        weights.append(W_LLM)

    if result["behavior_score"] is not None:
        scores.append(result["behavior_score"])
        weights.append(W_BEHAVIOR)

    if weights:
        total_w = sum(weights)
        final = sum(s * w for s, w in zip(scores, weights)) / total_w
    else:
        final = 0.0

    result["final_score"] = round(final, 4)
    result["risk_level"] = _compute_risk_level(final)

    return result
