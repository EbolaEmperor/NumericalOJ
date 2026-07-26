# -*- coding: utf-8 -*-
"""Every public CLI command exposes help text."""

from __future__ import annotations

import subprocess
import sys

import pytest

from tests.e2e.conftest import ADMIN_CLI, ROOT, USER_CLI, normalize_ws


USER_COMMAND_PATHS = [
    [],
    ["init"],
    ["auth"],
    ["auth", "login"],
    ["auth", "logout"],
    ["auth", "status"],
    ["auth", "send-password-code"],
    ["auth", "change-password"],
    ["me"],
    ["me", "classes"],
    ["me", "join-class"],
    ["me", "leave-class"],
    ["me", "submissions"],
    ["me", "grades"],
    ["problem"],
    ["problem", "list"],
    ["problem", "detail"],
    ["problem", "submit-page"],
    ["problem", "submit"],
    ["submission"],
    ["submission", "list"],
    ["submission", "problem"],
    ["submission", "status"],
    ["submission", "stream"],
    ["submission", "detail"],
    ["submission", "last-code"],
    ["submission", "output-image"],
    ["forum"],
    ["forum", "list"],
    ["forum", "thread"],
    ["forum", "new-page"],
    ["forum", "new"],
    ["forum", "reply"],
    ["forum", "reply-thread"],
    ["repository"],
    ["repository", "page"],
    ["repository", "files"],
    ["repository", "get"],
    ["repository", "save"],
    ["repository", "delete"],
    ["repository", "upload"],
    ["repository", "build-index"],
    ["repository", "rebuild-file"],
    ["repository", "index-status"],
    ["repository", "active-status"],
    ["repository", "search"],
    ["repository", "classes"],
    ["ai"],
    ["ai", "marks"],
    ["ranking"],
    ["ranking", "list"],
    ["ranking", "detail"],
    ["ranking", "matches"],
    ["ranking", "match-detail"],
    ["ranking", "submit"],
    ["ranking", "git"],
    ["ranking", "my-submissions"],
    ["ranking", "leaderboard"],
    ["ranking", "download-submission"],
    ["ranking", "judge-stream"],
    ["ranking", "reverse-stream"],
    ["ranking", "appeal"],
    ["ranking", "appeal-status"],
]


ADMIN_EXTRA_COMMAND_PATHS = [
    ["ai-detection"],
    ["ai-detection", "dashboard"],
    ["ai-detection", "problem-page"],
    ["ai-detection", "student-page"],
    ["ai-detection", "preview"],
    ["ai-detection", "run-filtered"],
    ["ai-detection", "run-problem"],
    ["ai-detection", "run-single"],
    ["ai-detection", "run-user"],
    ["ai-detection", "summary"],
    ["ai-detection", "tasks"],
    ["ai-detection", "models"],
    ["ai-detection", "task"],
    ["problem", "create-form"],
    ["problem", "create"],
    ["problem", "edit-form"],
    ["problem", "edit"],
    ["problem", "delete"],
    ["problem", "upload-testdata"],
    ["problem", "rejudge"],
    ["problem", "rejudge-status"],
    ["problem", "rejudge-time-range"],
    ["problem", "rejudge-time-range-status"],
    ["problem", "agent-run-status"],
    ["problem", "agent-run"],
    ["problem", "agent-run-stream"],
    ["problem", "agent-tasks"],
    ["problem", "agent-solve"],
    ["problem", "agent-generate-data"],
    ["problem", "scores"],
    ["homework"],
    ["homework", "list"],
    ["homework", "add"],
    ["homework", "update-ddl"],
    ["homework", "delete"],
    ["homework", "export-scores"],
    ["homework", "export-codes"],
    ["homework", "export-progress"],
    ["homework", "download-export"],
    ["homework", "plagiarism-start"],
    ["homework", "plagiarism-progress"],
    ["homework", "plagiarism-records"],
    ["homework", "plagiarism-download"],
    ["homework", "plagiarism-delete"],
    ["homework", "upload-exam"],
    ["homework", "class-adjust"],
    ["user"],
    ["user", "list"],
    ["user", "add-class-type"],
    ["user", "grant-admin"],
    ["user", "rename"],
    ["user", "add-to-class"],
    ["user", "remove-from-class"],
    ["user", "grades"],
    ["user", "update-grade"],
    ["grading"],
    ["grading", "submit"],
    ["grading", "next-pending"],
    ["grading", "invalidate-invalid"],
    ["submission", "download-file"],
    ["ranking", "create"],
    ["ranking", "copy"],
    ["ranking", "edit"],
    ["ranking", "delete"],
    ["ranking", "upload-attachment"],
    ["ranking", "delete-attachment"],
    ["ranking", "download-attachment"],
    ["ranking", "upload-reference"],
    ["ranking", "upload-script"],
    ["ranking", "clear-script"],
    ["ranking", "reset-limit"],
    ["ranking", "save-config"],
    ["ranking", "save-rules"],
    ["ranking", "save-endpoints"],
    ["ranking", "save-endpoint"],
    ["ranking", "save-quality-gate"],
    ["ranking", "save-quality-gate-endpoints"],
    ["ranking", "save-quality-gate-endpoint"],
    ["ranking", "batch-probe"],
    ["ranking", "batch-status"],
    ["ranking", "batch-create"],
    ["ranking", "bulk-filter"],
    ["ranking", "bulk-start"],
    ["ranking", "bulk-status"],
    ["ranking", "rejudge-agent"],
    ["ranking", "appeals"],
    ["ranking", "appeal-review"],
    ["ranking", "appeal-handle"],
    ["ranking", "elo-start"],
    ["ranking", "elo-stop"],
    ["ranking", "elo-reset"],
    ["ranking", "elo-delete-match"],
    ["ranking", "elo-rebuild"],
    ["ranking", "delete-submission"],
    ["ranking", "submissions"],
    ["ranking", "submit-zip"],
]


ADMIN_COMMAND_PATHS = USER_COMMAND_PATHS + ADMIN_EXTRA_COMMAND_PATHS


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("script", "paths"),
    [(USER_CLI, USER_COMMAND_PATHS), (ADMIN_CLI, ADMIN_COMMAND_PATHS)],
)
def test_every_cli_command_has_help(script, paths):
    for path in paths:
        cmd = [sys.executable, str(script), *path, "--help"]
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0, f"{' '.join(cmd)}\n{completed.stderr}"
        assert "usage:" in completed.stdout


@pytest.mark.e2e
def test_git_ranking_help_tells_users_to_check_first():
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ranking", "git", "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0
        assert "check first" in normalize_ws(completed.stdout)


@pytest.mark.e2e
@pytest.mark.parametrize("action", ["create", "edit"])
def test_admin_problem_help_explains_user_code_placeholder(action):
    completed = subprocess.run(
        [sys.executable, str(ADMIN_CLI), "problem", action, "--help"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    assert completed.returncode == 0
    help_text = normalize_ws(completed.stdout)
    assert "%%user_code_here" in help_text
    assert "student's submitted code is pasted at that marker" in help_text


@pytest.mark.e2e
def test_ai_marks_help_only_accepts_submission_id():
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ai", "marks", "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0
        assert "--submission-id" in completed.stdout
        assert "--force-refresh" in completed.stdout
        assert "--problem-id" not in completed.stdout
        assert "--code" not in completed.stdout
        assert "--code-file" not in completed.stdout


@pytest.mark.e2e
@pytest.mark.parametrize("command", ["ask", "ac"])
def test_retired_ai_commands_are_unavailable(command):
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ai", command, "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode != 0
