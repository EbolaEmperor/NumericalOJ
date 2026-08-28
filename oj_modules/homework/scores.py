#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按作业截止时间计算提交成绩的纯函数。"""

from datetime import datetime


NON_TERMINAL_SUBMISSION_STATUSES = frozenset({
    "Pending",
    "Queued",
    "Running",
    "Judging",
    "Processing",
    "Waiting",
    "Generating",
})


def as_datetime(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def submission_is_within_deadline(submission, deadline):
    deadline_value = as_datetime(deadline)
    if deadline_value is None:
        return True
    submitted_at = as_datetime(submission.get("created_at"))
    if submitted_at is None:
        return False
    if deadline_value.tzinfo and submitted_at.tzinfo is None:
        submitted_at = submitted_at.replace(tzinfo=deadline_value.tzinfo)
    elif submitted_at.tzinfo and deadline_value.tzinfo is None:
        deadline_value = deadline_value.replace(tzinfo=submitted_at.tzinfo)
    return submitted_at <= deadline_value


def best_scored_submission(submissions, *, require_terminal=True):
    candidates = []
    for submission in submissions or []:
        if submission.get("score") is None:
            continue
        if (
            require_terminal
            and str(submission.get("status") or "")
            in NON_TERMINAL_SUBMISSION_STATUSES
        ):
            continue
        candidates.append(submission)
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda item: (
            float(item.get("score") or 0),
            as_datetime(item.get("created_at")) or datetime.min,
            int(item.get("id") or 0),
        ),
    )


def homework_score_snapshot(submissions, deadline, *, require_terminal=True):
    eligible = [
        submission for submission in submissions or []
        if submission_is_within_deadline(submission, deadline)
    ]
    best = best_scored_submission(
        eligible, require_terminal=require_terminal,
    )
    practice_best = best_scored_submission(
        submissions, require_terminal=require_terminal,
    )
    return {
        "eligible": eligible,
        "best": best,
        "practice_best": practice_best,
        "has_pending": any(
            str(item.get("status") or "") in NON_TERMINAL_SUBMISSION_STATUSES
            for item in eligible
        ),
    }


__all__ = [
    "NON_TERMINAL_SUBMISSION_STATUSES",
    "as_datetime",
    "best_scored_submission",
    "homework_score_snapshot",
    "submission_is_within_deadline",
]
