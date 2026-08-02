# -*- coding: utf-8 -*-
"""Problem, submission, grading, and rejudge CLI flows."""

from __future__ import annotations

from pathlib import Path
import time

import pytest

from tests.e2e.conftest import (
    add_problem_homework,
    assert_no_json_leaks,
    create_problem,
    create_problem_with_homework,
    create_regular_user,
    get_user_id,
    write_testdata_zip,
    write_zip,
)


PROBLEM_SECRET_KEYS = {
    "programming_grading_prompt",
    "programming_output_filename",
    "written_grading_mode",
    "written_grading_prompt",
    "test_code",
    "testdata",
    "forbidden_func",
    "ai_code_marks_json",
}


@pytest.mark.e2e
def test_problem_create_edit_testdata_submit_and_submission_views(cli, unique_suffix, tmp_path):
    username = f"cli_problem_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Problem {unique_suffix}"
    endpoint_id = int(unique_suffix[-8:]) + 1000
    secret_terms = (f"secret-output-{unique_suffix}.png", f"secret-prompt-{unique_suffix}")
    problem_id, _ = create_problem_with_homework(
        cli,
        title,
        submission_limit=5,
        extra=[
            "--programming-output-filename",
            secret_terms[0],
            "--programming-grading-prompt",
            secret_terms[1],
            "--output-image-grading-endpoint-id",
            str(endpoint_id),
            "--test-code",
            f"secret-test-code-{unique_suffix}",
            "--forbidden-func",
            f"secret-forbidden-{unique_suffix}",
        ],
    )

    assert cli.admin_json("problem", "create-form")["success"] is True
    assert cli.admin_json("problem", "detail", str(problem_id))["problem"]["title"] == title
    user_problem_detail = cli.user_json("problem", "detail", str(problem_id))
    assert user_problem_detail["problem"]["title"] == title
    assert_no_json_leaks(
        user_problem_detail,
        forbidden_keys=PROBLEM_SECRET_KEYS,
        forbidden_terms=secret_terms,
    )
    cli.user_json("problem", "submit-page", str(problem_id))

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
    assert cli.admin_json("problem", "detail", str(problem_id))["problem"]["title"] == edited_title
    edit_form = cli.admin_json("problem", "edit-form", str(problem_id))
    assert edit_form["form"]["llm_endpoint_bindings"] == {
        "output_image_grading_endpoint_id": endpoint_id,
    }
    assert cli.admin_json(
        "problem",
        "edit",
        str(problem_id),
        "--output-image-grading-endpoint-id",
        "none",
    )["success"] is True
    cleared_form = cli.admin_json("problem", "edit-form", str(problem_id))
    assert cleared_form["form"]["llm_endpoint_bindings"] == {}

    testdata_zip = write_testdata_zip(tmp_path / "testdata.zip")
    assert cli.admin_json("problem", "upload-testdata", str(problem_id), str(testdata_zip))["success"] is True

    code_file = tmp_path / "solution.py"
    code_file.write_text("print('hello')\n", encoding="utf-8")
    submission_one = cli.user_json("problem", "submit", str(problem_id), "--code", "print('hello')")
    submission_two = cli.user_json("problem", "submit", str(problem_id), "--code-file", str(code_file))
    sid = int(submission_two["submission_id"])

    assert cli.user_json("submission", "status", str(sid)).get("id") in (None, sid)
    user_submission_detail = cli.user_json("submission", "detail", str(sid))
    assert user_submission_detail["submission"]["id"] == sid
    assert_no_json_leaks(
        user_submission_detail,
        forbidden_keys=PROBLEM_SECRET_KEYS,
        forbidden_terms=secret_terms,
    )
    from oj_modules.db_services import save_submission_ai_code_marks_json

    assert save_submission_ai_code_marks_json(
        sid,
        {
            "issues": [],
            "summary": "cached marks",
            "code_used": "print('hello')",
            "generated_at": "2026-01-01T00:00:00Z",
        },
    )
    marks = cli.user_json("ai", "marks", "--submission-id", str(sid))
    assert marks["success"] is True
    assert marks["source"] == "cache"
    assert cli.user_json("submission", "list", "--limit", "5")["count"] >= 2
    assert cli.user_json("submission", "problem", str(problem_id), "--limit", "5")["count"] >= 2
    assert cli.user_json("submission", "last-code", str(problem_id))["success"] is True
    last_code_file = tmp_path / "last_solution.py"
    exported_last_code = cli.user_json("submission", "last-code", str(problem_id), "-o", str(last_code_file))
    assert exported_last_code["submission_id"] == sid
    assert last_code_file.read_text(encoding="utf-8") == "print('hello')\n"
    assert cli.user_json("me", "submissions", "--limit", "5")["count"] >= 2
    stream = cli.user_json("submission", "stream", str(sid), "--max-lines", "1", timeout=10)
    assert stream["success"] is True
    assert stream["lines"]

    admin_status = cli.admin_json("submission", "status", str(submission_one["submission_id"]))
    assert "status" in admin_status
    admin_submission = cli.admin_json("problem", "submit", str(problem_id), "--code", "print('admin')")
    assert "submission_id" in admin_submission
    assert cli.admin_json("submission", "detail", str(sid))["submission"]["id"] == sid
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

    for idx in range(3):
        payload = cli.user_json("problem", "submit", str(problem_id), "--code", f"print({idx})")
        assert "submission_id" in payload

    blocked = cli.user_json("problem", "submit", str(problem_id), "--code", "print('blocked')")
    assert "submission_id" not in blocked

    submissions = cli.user_json("submission", "problem", str(problem_id), "--limit", "10")
    assert submissions["count"] == 3
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True


@pytest.mark.e2e
def test_promptly_problem_submit_generates_code(cli, unique_suffix, tmp_path):
    username = f"cli_promptly_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Promptly {unique_suffix}"
    problem_id, _ = create_problem_with_homework(
        cli,
        title,
        submission_limit=3,
        extra=["--programming-grading-mode", "3"],
    )
    testdata_zip = write_testdata_zip(tmp_path / "promptly_testdata.zip")
    assert cli.admin_json("problem", "upload-testdata", str(problem_id), str(testdata_zip))["success"] is True

    context = cli.user_json("problem", "submit-page", str(problem_id))
    assert context["submit"]["input_kind"] == "prompt"
    prompt_text = "Use a monotonic deque and describe expired index handling, then print exactly hello."
    submission = cli.user_json("problem", "submit", str(problem_id), "--prompt", prompt_text)
    sid = int(submission["submission_id"])

    detail = None
    for _ in range(40):
        detail = cli.user_json("submission", "detail", str(sid))
        if detail["submission"]["code"].strip():
            break
        time.sleep(0.25)

    assert detail is not None
    assert detail["submission"]["generated_from_prompt"] is True
    assert detail["submission"]["prompt_text"] == prompt_text
    assert detail["submission"]["code"].strip() == "print('hello')"
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True


@pytest.mark.e2e
def test_promptly_review_cli_submit_accepts_and_rejects_prompts(cli, unique_suffix, tmp_path):
    username = f"cli_promptly_review_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Promptly Review {unique_suffix}"
    review_reply = "Please explain the monotonic deque and expired index handling."
    problem_id, _ = create_problem_with_homework(
        cli,
        title,
        submission_limit=6,
        extra=[
            "--programming-grading-mode",
            "3",
            "--promptly-brief",
            "Submit a prompt that describes the required algorithm before generated code prints hello.",
            "--promptly-requirements",
            "The prompt must mention monotonic deque and expired index handling.",
            "--promptly-example-reply",
            review_reply,
        ],
    )
    admin_problem_form = cli.admin_json("problem", "edit-form", str(problem_id))
    assert admin_problem_form["form"]["programming_grading_mode"] == 3
    assert "programming_grading_model" not in admin_problem_form["form"]
    testdata_zip = write_testdata_zip(tmp_path / "promptly_review_testdata.zip")
    assert cli.admin_json("problem", "upload-testdata", str(problem_id), str(testdata_zip))["success"] is True

    context = cli.user_json("problem", "submit-page", str(problem_id))
    assert context["submit"]["input_kind"] == "prompt"

    good_prompt = "Use a monotonic deque, and explicitly remove each expired index before using the window."
    bad_prompt = "Please write an O(n) algorithm."

    admin_good = cli.admin_json(
        "problem",
        "submit",
        str(problem_id),
        "--prompt",
        good_prompt,
        "--wait-timeout",
        "20",
        "--poll-interval",
        "0.2",
        timeout=30,
    )
    assert admin_good["success"] is True
    assert admin_good["promptly_review"]["accepted"] is True
    assert not admin_good.get("reply")
    admin_good_sid = int(admin_good["submission_id"])
    admin_good_detail = cli.admin_json("submission", "detail", str(admin_good_sid))
    assert admin_good_detail["submission"]["prompt_text"] == good_prompt
    assert admin_good_detail["submission"]["code"].strip() == "print('hello')"

    admin_bad = cli.admin_json(
        "problem",
        "submit",
        str(problem_id),
        "--prompt",
        bad_prompt,
        "--wait-timeout",
        "20",
        "--poll-interval",
        "0.2",
        timeout=30,
    )
    assert admin_bad["success"] is True
    assert admin_bad["reply"] == review_reply
    assert admin_bad["promptly_review"]["accepted"] is False
    assert admin_bad["promptly_review"]["status"] == "Unaccepted"
    admin_bad_status = cli.admin_json("submission", "status", str(admin_bad["submission_id"]))
    assert admin_bad_status["status"] == "Unaccepted"
    assert admin_bad_status["promptly_review_reply"] == review_reply

    user_good = cli.user_json(
        "problem",
        "submit",
        str(problem_id),
        "--prompt",
        good_prompt,
        "--wait-timeout",
        "20",
        "--poll-interval",
        "0.2",
        timeout=30,
    )
    assert user_good["success"] is True
    assert user_good["promptly_review"]["accepted"] is True
    assert not user_good.get("reply")
    user_good_detail = cli.user_json("submission", "detail", str(user_good["submission_id"]))
    assert user_good_detail["submission"]["prompt_text"] == good_prompt
    assert user_good_detail["submission"]["code"].strip() == "print('hello')"

    user_bad = cli.user_json(
        "problem",
        "submit",
        str(problem_id),
        "--prompt",
        bad_prompt,
        "--wait-timeout",
        "20",
        "--poll-interval",
        "0.2",
        timeout=30,
    )
    assert user_bad["success"] is True
    assert user_bad["reply"] == review_reply
    assert user_bad["promptly_review"]["accepted"] is False
    assert user_bad["promptly_review"]["status"] == "Unaccepted"
    user_bad_status = cli.user_json("submission", "status", str(user_bad["submission_id"]))
    assert user_bad_status["status"] == "Unaccepted"
    assert user_bad_status["prompt_generation_error"] == review_reply
    assert user_bad_status["promptly_review_reply"] == review_reply
    user_bad_detail = cli.user_json("submission", "detail", str(user_bad["submission_id"]))
    assert user_bad_detail["submission"]["promptly_review_reply"] == review_reply
    assert user_bad_detail["submission"]["prompt_generation_error"] == review_reply

    wrong_title = f"CLI Promptly Review WA {unique_suffix}"
    wrong_problem_id, _ = create_problem_with_homework(
        cli,
        wrong_title,
        submission_limit=2,
        extra=[
            "--programming-grading-mode",
            "3",
            "--promptly-brief",
            "Submit a prompt that describes the required algorithm before generated code is judged.",
            "--promptly-requirements",
            "The prompt must mention monotonic deque and expired index handling.",
            "--promptly-example-reply",
            review_reply,
        ],
    )
    wrong_testdata_zip = write_zip(tmp_path / "promptly_review_wa_testdata.zip", {"1.in": "", "1.out": "goodbye"})
    assert cli.admin_json("problem", "upload-testdata", str(wrong_problem_id), str(wrong_testdata_zip))["success"] is True
    user_wrong = cli.user_json(
        "problem",
        "submit",
        str(wrong_problem_id),
        "--prompt",
        good_prompt,
        "--wait-timeout",
        "20",
        "--poll-interval",
        "1.0",
        timeout=30,
    )
    assert user_wrong["success"] is True
    assert user_wrong["promptly_review"]["accepted"] is True
    assert not user_wrong.get("reply")
    user_wrong_status = None
    for _ in range(40):
        user_wrong_status = cli.user_json("submission", "status", str(user_wrong["submission_id"]))
        if user_wrong_status["status"] == "Unaccepted":
            break
        time.sleep(0.25)
    assert user_wrong_status is not None
    assert user_wrong_status["status"] == "Unaccepted"
    assert not user_wrong_status.get("prompt_generation_error")
    assert not user_wrong_status.get("promptly_review_reply")

    assert cli.admin_json("problem", "delete", str(wrong_problem_id))["success"] is True
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True
