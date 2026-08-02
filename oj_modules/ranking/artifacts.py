"""打榜赛附件展示与反向评测答案归档下载。"""

import os

from flask import send_file

from oj_modules.ranking.db import get_competition, get_ranking_submission
from oj_modules.ranking.presentation import competition_scoring_mode
from oj_modules.ranking.reverse_judge.db import (
    available_reverse_agent_answer_archive_path,
)


INLINE_MEDIA_MIME = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".mp4": "video/mp4", ".webm": "video/webm", ".ogv": "video/ogg",
    ".ogg": "video/ogg", ".mov": "video/quicktime", ".m4v": "video/x-m4v",
}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


def attachment_media_kind(filename):
    ext = os.path.splitext((filename or "").lower())[1]
    if ext in IMAGE_EXTS:
        return "image"
    if ext in INLINE_MEDIA_MIME:
        return "video"
    return None


def can_access_submission(user, submission):
    if not submission:
        return False
    if user.get("is_admin") == 1:
        return True
    return submission.get("username") == user.get("username")


def resolve_reverse_agent_answer_archive(user, submission_id, competition_id=None):
    submission = get_ranking_submission(submission_id)
    if not submission or not can_access_submission(user, submission):
        return None
    try:
        actual_competition_id = int(submission.get("competition_id"))
        if competition_id is not None and actual_competition_id != int(competition_id):
            return None
    except (TypeError, ValueError):
        return None
    competition = get_competition(actual_competition_id)
    if not competition or competition_scoring_mode(competition) != "reverse_judge":
        return None
    return available_reverse_agent_answer_archive_path(
        submission_id,
        submission.get("judge_attempt_id"),
        submission.get("status"),
    )


def send_reverse_agent_answer_archive(archive_path, submission_id):
    response = send_file(
        archive_path,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"reverse_ai_answer_{int(submission_id)}.zip",
        conditional=True,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


__all__ = [
    "INLINE_MEDIA_MIME",
    "IMAGE_EXTS",
    "attachment_media_kind",
    "can_access_submission",
    "resolve_reverse_agent_answer_archive",
    "send_reverse_agent_answer_archive",
]
