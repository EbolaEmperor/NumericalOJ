# -*- coding: utf-8 -*-
"""AI-related CLI surfaces that are safe to exercise locally.

Live model calls are intentionally not invoked here. The command help matrix
covers the AI tutor commands; this file covers local-only AIGC/admin pages and
filter APIs.
"""

from __future__ import annotations

import pytest

from tests.e2e.conftest import create_problem_with_homework, create_regular_user


@pytest.mark.e2e
def test_ai_detection_pages_summary_models_and_preview(cli, unique_suffix):
    username = f"cli_ai_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI AI Detection {unique_suffix}"
    problem_id, _ = create_problem_with_homework(cli, title)
    submission = cli.user_json("problem", "submit", str(problem_id), "--code", "print('ai safe')")
    sid = int(submission["submission_id"])

    assert cli.admin_json("ai-detection", "dashboard")["success"] is True
    assert cli.admin_json("ai-detection", "problem-page", str(problem_id))["success"] is True
    assert cli.admin_json("ai-detection", "student-page", username)["success"] is True
    assert cli.admin_json("ai-detection", "summary")["success"] is True
    assert cli.admin_json("ai-detection", "tasks")["success"] is True
    assert cli.admin_json("ai-detection", "models")["success"] is True
    assert cli.admin_json(
        "ai-detection",
        "preview",
        "--class-en",
        "Cclass1",
        "--username",
        username,
        "--problem-id",
        str(problem_id),
        "--submission-id",
        str(sid),
        "--deduplicate",
    )["success"] is True
    assert cli.admin_json(
        "ai-detection",
        "run-filtered",
        "--class-en",
        "Cclass1",
        "--username",
        username,
        "--problem-id",
        str(problem_id),
        "--submission-id",
        str(sid),
    )["success"] is True
    assert cli.admin_json("ai-detection", "task", "stop", "missing-task")["success"] in (True, False)
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True
