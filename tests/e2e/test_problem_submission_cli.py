# -*- coding: utf-8 -*-
"""Problem, submission, grading, and rejudge CLI flows."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import (
    add_problem_homework,
    create_problem,
    create_problem_with_homework,
    create_regular_user,
    get_user_id,
    write_testdata_zip,
)


@pytest.mark.e2e
def test_problem_create_edit_testdata_submit_and_submission_views(cli, unique_suffix, tmp_path):
    username = f"cli_problem_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Problem {unique_suffix}"
    problem_id, _ = create_problem_with_homework(cli, title, submission_limit=5)

    assert cli.admin_json("problem", "create-form")["success"] is True
    assert title in cli.admin_json("problem", "detail", str(problem_id))["text"]
    assert title in cli.user_json("problem", "detail", str(problem_id))["text"]
    assert cli.user_json("problem", "submit-page", str(problem_id))["success"] is True

    edited_title = f"{title} Edited"
    assert cli.admin_json(
        "problem",
        "edit",
        str(problem_id),
        "--title",
        edited_title,
        "--content",
        "Edited by CLI e2e.",
        "--lang",
        "python",
        "--submission-limit",
        "5",
    )["success"] is True
    assert edited_title in cli.admin_json("problem", "detail", str(problem_id), "--max-chars", "5000")["text"]
    assert cli.admin_json("problem", "edit-form", str(problem_id))["success"] is True

    testdata_zip = write_testdata_zip(tmp_path / "testdata.zip")
    assert cli.admin_json("problem", "upload-testdata", str(problem_id), str(testdata_zip))["success"] is True

    code_file = tmp_path / "solution.py"
    code_file.write_text("print('hello')\n", encoding="utf-8")
    submission_one = cli.user_json("problem", "submit", str(problem_id), "--code", "print('hello')")
    submission_two = cli.user_json("problem", "submit", str(problem_id), "--code-file", str(code_file))
    sid = int(submission_two["submission_id"])

    assert cli.user_json("submission", "status", str(sid)).get("id") in (None, sid)
    assert cli.user_json("submission", "detail", str(sid)).get("id") == sid
    assert cli.user_json("submission", "list", "--limit", "5")["count"] >= 2
    assert cli.user_json("submission", "problem", str(problem_id), "--limit", "5")["count"] >= 2
    assert cli.user_json("submission", "last-code", str(problem_id))["success"] is True
    assert cli.user_json("me", "submissions", "--limit", "5")["count"] >= 2
    stream = cli.user_json("submission", "stream", str(sid), "--max-lines", "1", timeout=10)
    assert stream["success"] is True
    assert stream["lines"]

    admin_status = cli.admin_json("submission", "status", str(submission_one["submission_id"]))
    assert "status" in admin_status
    admin_submission = cli.admin_json("problem", "submit", str(problem_id), "--code", "print('admin')")
    assert "submission_id" in admin_submission
    assert cli.admin_json("submission", "detail", str(sid)).get("id") == sid
    assert cli.admin_json("submission", "list", "--limit", "5")["count"] >= 2
    assert cli.admin_json("submission", "problem", str(problem_id), "--limit", "5")["count"] >= 1
    assert cli.admin_json("submission", "last-code", str(problem_id))["success"] is True

    assert cli.admin_json("problem", "scores", str(problem_id))["success"] is True
    assert cli.admin_json("problem", "rejudge", str(problem_id))["success"] is True
    assert cli.admin_json("problem", "rejudge-status", str(problem_id))["success"] is True
    assert cli.admin_json(
        "problem",
        "rejudge-time-range",
        "--start",
        "2000-01-01T00:00",
        "--end",
        "2099-01-01T00:00",
    )["success"] is True
    assert cli.admin_json("problem", "rejudge-time-range-status")["success"] in (True, False)

    user_id = get_user_id(username)
    assert cli.admin_json("user", "update-grade", str(user_id), str(problem_id), "--score", "1")["success"] is True
    grades = cli.admin_json("user", "grades", str(user_id))
    assert grades["success"] is True
    assert any(g["problem_id"] == problem_id for g in grades["grades"])
    assert cli.admin_json("user", "update-grade", str(user_id), str(problem_id), "--clear")["success"] is True

    assert cli.admin_json("grading", "next-pending", str(sid))["success"] in (True, False)
    assert cli.admin_json("grading", "invalidate-invalid", str(problem_id))["success"] in (True, False)
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True


@pytest.mark.e2e
def test_written_homework_file_submission_and_admin_download(cli, unique_suffix, tmp_path):
    username = f"cli_written_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Written {unique_suffix}"
    problem_id = create_problem(
        cli,
        title,
        problem_type="2",
        submission_limit=3,
        content="Upload a PDF.",
        extra=["--written-grading-mode", "4"],
    )
    add_problem_homework(cli, problem_id, title)

    pdf = tmp_path / "answer.pdf"
    pdf.write_bytes(b"%PDF-1.4\n% cli e2e\n")
    submission = cli.user_json("problem", "submit", str(problem_id), "--file", str(pdf))
    sid = int(submission["submission_id"])
    status = cli.user_json("submission", "status", str(sid))
    assert status.get("id") in (None, sid)
    assert "status" in status

    out_dir = tmp_path / "download"
    downloaded = cli.admin_json("submission", "download-file", str(sid), "-o", str(out_dir))
    assert downloaded["success"] is True
    assert Path(downloaded["path"]).exists()
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True


@pytest.mark.e2e
def test_problem_submission_limit_blocks_extra_user_submission(cli, unique_suffix):
    username = f"cli_limit_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Limit {unique_suffix}"
    problem_id, _ = create_problem_with_homework(cli, title, submission_limit=3)

    accepted_ids = []
    for idx in range(3):
        payload = cli.user_json("problem", "submit", str(problem_id), "--code", f"print({idx})")
        accepted_ids.append(int(payload["submission_id"]))

    blocked = cli.user_json("problem", "submit", str(problem_id), "--code", "print('blocked')")
    assert "submission_id" not in blocked
    assert f"/problem/{problem_id}" in blocked.get("location", "")

    submissions = cli.user_json("submission", "problem", str(problem_id), "--limit", "10")
    assert submissions["count"] == 3
    assert set(submissions["submission_ids"]) == set(accepted_ids)
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True
