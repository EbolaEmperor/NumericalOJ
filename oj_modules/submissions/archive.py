#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Filesystem backup for original submission payloads."""

import datetime as _dt
import json
import os
import re
import shutil

from oj_modules.judging import core as judger_core


ARCHIVE_DIRNAME = "submission_archive"
SAFE_ARCHIVE_FILENAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _json_default(value):
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat(sep=" ") if isinstance(value, _dt.datetime) else value.isoformat()
    return str(value)


def _safe_text(value):
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _safe_submission_id(submission_id):
    raw = str(submission_id or "").strip()
    return raw if raw.isdigit() else judger_core.sanitize_sid(raw)


def _safe_archive_filename(filename, fallback="artifact.txt"):
    raw = os.path.basename(str(filename or "").replace("\\", "/").strip())
    if not raw or raw in (".", ".."):
        raw = fallback
    raw = SAFE_ARCHIVE_FILENAME_RE.sub("_", raw)
    raw = raw.strip("._")
    return raw[:255] or fallback


def archive_dir_for_submission(submission_id):
    sid = _safe_submission_id(submission_id)
    return os.path.join(judger_core.JUDGER_RUN_ROOT, ARCHIVE_DIRNAME, f"submission_{sid}")


def _ensure_archive_dir(submission_id, archive_dir=None):
    archive_dir = archive_dir or archive_dir_for_submission(submission_id)
    os.makedirs(archive_dir, exist_ok=True)
    return archive_dir


def _atomic_write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(_safe_text(text))
    os.replace(tmp_path, path)


def _source_ext_for_problem(problem):
    lang = str((problem or {}).get("lang") or "").strip().lower()
    if lang == "cpp":
        return ".cpp"
    if lang == "c":
        return ".c"
    if lang in ("python", "py"):
        return ".py"
    if lang in ("lean", "lean4"):
        return ".lean"
    return ".m"


def _normalize_classes(classes):
    normalized = []
    for item in classes or []:
        if not isinstance(item, dict):
            continue
        normalized.append({
            "class_en": _safe_text(item.get("class_en")),
            "class_cn": _safe_text(item.get("class_cn")),
        })
    return normalized


def build_submission_meta(submission, problem, user, classes):
    submission = submission or {}
    problem = problem or {}
    user = user or {}
    return {
        "submission_id": submission.get("id"),
        "problem_id": problem.get("id") or submission.get("problem_id"),
        "problem_title": _safe_text(problem.get("title") or submission.get("problem_title")),
        "problem_content": _safe_text(problem.get("content")),
        "username": _safe_text(submission.get("username")),
        "email": _safe_text(user.get("email")),
        "submitted_at": submission.get("created_at"),
        "classes": _normalize_classes(classes),
        "problem_type": submission.get("problem_type") or problem.get("type"),
        "status_at_archive": _safe_text(submission.get("status")),
        "archived_at": _dt.datetime.now().isoformat(sep=" ", timespec="seconds"),
    }


def archive_text_artifact(submission_id, filename, content, *, archive_dir=None):
    archive_dir = _ensure_archive_dir(submission_id, archive_dir)
    safe_name = _safe_archive_filename(filename)
    target_path = os.path.join(archive_dir, safe_name)
    _atomic_write_text(target_path, _safe_text(content))
    return target_path


def archive_uploaded_submission_file(
    submission_id,
    source_path,
    preferred_filename=None,
    *,
    archive_dir=None,
):
    if not source_path or not os.path.isfile(source_path):
        return None
    archive_dir = _ensure_archive_dir(submission_id, archive_dir)
    source_name = preferred_filename or os.path.basename(source_path)
    _, ext = os.path.splitext(str(source_name or source_path))
    ext = ext.lower()
    if ext:
        target_name = f"submitted{ext}"
    else:
        target_name = "submitted_file"
    target_path = os.path.join(archive_dir, _safe_archive_filename(target_name))
    if os.path.abspath(source_path) != os.path.abspath(target_path):
        shutil.copyfile(source_path, target_path)
    return target_path


def archive_submission_record(
    submission,
    problem,
    user,
    classes,
    *,
    archive_dir=None,
):
    submission = submission or {}
    problem = problem or {}
    submission_id = submission.get("id")
    if not submission_id:
        return None

    archive_dir = _ensure_archive_dir(submission_id, archive_dir)
    meta = build_submission_meta(submission, problem, user, classes)
    _atomic_write_text(
        os.path.join(archive_dir, "meta.json"),
        json.dumps(meta, ensure_ascii=False, indent=2, default=_json_default) + "\n",
    )

    prompt_text = _safe_text(submission.get("prompt_text"))
    code = _safe_text(submission.get("code"))
    problem_type = int(submission.get("problem_type") or problem.get("type") or 0)

    if prompt_text.strip():
        archive_text_artifact(
            submission_id, "prompt.txt", prompt_text, archive_dir=archive_dir,
        )
    elif problem_type == 1 and code.strip():
        ext = _source_ext_for_problem(problem)
        archive_text_artifact(
            submission_id, f"code{ext}", code, archive_dir=archive_dir,
        )

    return archive_dir
