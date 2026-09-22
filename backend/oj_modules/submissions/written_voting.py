#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""书面题一致性投票的持久化与展示投影。"""

from __future__ import annotations

import json
import secrets

from backend.oj_modules.infrastructure.mysql import get_db_connection


REVIEW_REQUIRED_STATES = frozenset({"needs_manual_review", "failed"})


def create_attempt(submission_id, grading_mode, config, votes):
    token = secrets.token_hex(16)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO written_grading_attempts
                   (submission_id, attempt_token, grading_mode, status, config_json)
                   VALUES (%s, %s, %s, 'running', %s)""",
                (
                    int(submission_id), token, int(grading_mode),
                    json.dumps(config, ensure_ascii=False, separators=(",", ":")),
                ),
            )
            attempt_id = int(cursor.lastrowid)
            for vote in votes:
                cursor.execute(
                    """INSERT INTO written_grading_votes
                       (attempt_id, vote_index, endpoint_id, endpoint_revision,
                        model, status)
                       VALUES (%s, %s, %s, %s, %s, 'queued')""",
                    (
                        attempt_id, int(vote["vote_index"]),
                        int(vote["endpoint_id"]),
                        max(1, int(vote.get("endpoint_revision") or 1)),
                        str(vote.get("model") or "未知模型")[:255],
                    ),
                )
                vote["id"] = int(cursor.lastrowid)
        conn.commit()
        return {"id": attempt_id, "attempt_token": token, "votes": votes}
    finally:
        conn.close()


def update_vote(vote_id, *, status, score=None, comment=None, error_message=None, call_attempts=0):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE written_grading_votes
                   SET status=%s, score=%s, comment=%s, error_message=%s,
                       call_attempts=%s
                   WHERE id=%s""",
                (
                    str(status), score, comment,
                    str(error_message or "")[:4000] or None,
                    int(call_attempts), int(vote_id),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def finish_attempt(attempt_id, *, status, consensus_score=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE written_grading_attempts
                   SET status=%s, consensus_score=%s, completed_at=NOW()
                   WHERE id=%s""",
                (str(status), consensus_score, int(attempt_id)),
            )
        conn.commit()
    finally:
        conn.close()


def mark_latest_attempt_manual(submission_id, score):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE written_grading_attempts
                   SET manual_override=1, manual_score=%s, updated_at=NOW()
                   WHERE id=(
                       SELECT id FROM (
                           SELECT id FROM written_grading_attempts
                           WHERE submission_id=%s ORDER BY id DESC LIMIT 1
                       ) latest
                   )""",
                (int(score), int(submission_id)),
            )
        conn.commit()
    finally:
        conn.close()


def supersede_latest_attempt(submission_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """UPDATE written_grading_attempts
                   SET status='superseded', updated_at=NOW()
                   WHERE id=(
                       SELECT id FROM (
                           SELECT id FROM written_grading_attempts
                           WHERE submission_id=%s ORDER BY id DESC LIMIT 1
                       ) latest
                   )""",
                (int(submission_id),),
            )
        conn.commit()
    finally:
        conn.close()


def get_latest_attempt(submission_id, *, include_votes=True):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT id, submission_id, attempt_token, grading_mode, status,
                          config_json, consensus_score, manual_override, manual_score,
                          created_at, updated_at, completed_at
                   FROM written_grading_attempts
                   WHERE submission_id=%s ORDER BY id DESC LIMIT 1""",
                (int(submission_id),),
            )
            attempt = cursor.fetchone()
            if not attempt:
                return None
            if include_votes:
                cursor.execute(
                    """SELECT vote_index, endpoint_id, endpoint_revision, model,
                              status, score, comment, error_message, call_attempts
                       FROM written_grading_votes
                       WHERE attempt_id=%s ORDER BY vote_index ASC""",
                    (int(attempt["id"]),),
                )
                attempt["votes"] = cursor.fetchall() or []
            return attempt
    finally:
        conn.close()


def public_attempt_payload(attempt):
    if not attempt:
        return None
    status = str(attempt.get("status") or "")
    return {
        "id": int(attempt["id"]),
        "status": status,
        "needs_manual_review": status in REVIEW_REQUIRED_STATES,
        "consensus_score": attempt.get("consensus_score"),
        "manual_override": bool(attempt.get("manual_override")),
        "manual_score": attempt.get("manual_score"),
        "votes": [
            {
                "index": int(vote.get("vote_index") or 0),
                "model": str(vote.get("model") or "未知模型"),
                "status": str(vote.get("status") or "queued"),
                "score": vote.get("score"),
                "comment": str(vote.get("comment") or ""),
            }
            for vote in attempt.get("votes") or []
        ],
    }


__all__ = [
    "REVIEW_REQUIRED_STATES",
    "create_attempt",
    "finish_attempt",
    "get_latest_attempt",
    "mark_latest_attempt_manual",
    "public_attempt_payload",
    "supersede_latest_attempt",
    "update_vote",
]
