# -*- coding: utf-8 -*-
"""Extended homework plagiarism flows across non-traditional submission types."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    add_problem_homework,
    create_problem,
    create_regular_user,
    ranking_id_from_create,
    require_docker_judger_image,
    write_testdata_zip,
    write_zip,
)


def _create_users(prefix: str, suffix: str, count: int) -> list[str]:
    usernames = [f"{prefix}_{idx}_{suffix}" for idx in range(count)]
    for username in usernames:
        create_regular_user(username=username, password="pw123456")
    return usernames


def _run_plagiarism(cli, target: str, *, mode: str, threshold: str | None = None) -> dict:
    args = [
        "homework",
        "plagiarism-start",
        "--class-en",
        "Cclass1",
        "--mode",
        mode,
        "--targets",
        target,
        "--wait",
        "--timeout",
        "120",
    ]
    if threshold is not None:
        args.extend(["--threshold", threshold])
    payload = cli.admin_json(*args, timeout=140)
    assert payload["success"] is True
    progress = payload["progress"]
    assert progress["stage"] == "completed"
    return progress["result"]


def _records_for_target(cli, *, target_kind: str, target_id: int, comparison_rule: str) -> list[dict]:
    payload = cli.admin_json("homework", "plagiarism-records", "--class-en", "Cclass1")
    assert payload["success"] is True
    return [
        row
        for row in payload["records"]
        if row.get("target_kind") == target_kind
        and int(row.get("problem_id") or 0) == int(target_id)
        and row.get("comparison_rule") == comparison_rule
    ]


def _assert_plagiarism_group(
    cli,
    *,
    target_kind: str,
    target_id: int,
    comparison_rule: str,
    expected_users: set[str],
) -> None:
    rows = _records_for_target(
        cli,
        target_kind=target_kind,
        target_id=target_id,
        comparison_rule=comparison_rule,
    )
    assert {row["username"] for row in rows} == expected_users
    for row in rows:
        assert set(row["matched_usernames"]) == expected_users - {row["username"]}


def _wait_problem_submission_status(cli, submission_id: int, expected: set[str], *, timeout_s: float = 45.0) -> dict:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = cli.admin_json("submission", "status", str(submission_id))
        if last.get("status") in expected:
            return last
        time.sleep(0.5)
    pytest.fail(f"Submission {submission_id} did not reach {expected}: {last}")


def _wait_ranking_submission_status(
    cli,
    competition_id: int,
    submission_id: int,
    expected: set[str],
    *,
    timeout_s: float = 60.0,
) -> dict:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        payload = cli.admin_json("ranking", "submissions", str(competition_id))
        for row in payload.get("submissions") or []:
            if int(row.get("id") or 0) == int(submission_id):
                last = row
                if row.get("status") in expected:
                    return row
        time.sleep(0.5)
    pytest.fail(f"Ranking submission {submission_id} did not reach {expected}: {last}")


def _create_ranking(cli, title: str) -> int:
    payload = cli.admin_json(
        "ranking",
        "create",
        "--title",
        title,
        "--summary",
        "cli e2e",
        "--description",
        "cli e2e",
        "--max-score",
        "100",
    )
    assert payload["success"] is True
    return ranking_id_from_create(payload)


def _assign_ranking_homework(cli, competition_id: int) -> None:
    assert cli.admin_json(
        "homework",
        "add",
        "--class-en",
        "Cclass1",
        "--ranking-competition-id",
        str(competition_id),
        "--ddl",
        "2099-01-01T00:00",
    )["success"] is True


def _submit_ranking_zip(
    cli,
    username: str,
    competition_id: int,
    *,
    code_zip: Path,
    answer_file: Path | None = None,
) -> int:
    assert cli.init_user(username)["success"] is True
    args = [
        "ranking",
        "submit",
        str(competition_id),
        "--base-model",
        "baseline",
        "--code-zip",
        str(code_zip),
    ]
    if answer_file is not None:
        args.extend(["--answer-file", str(answer_file)])
    payload = cli.user_json(*args, timeout=90)
    assert payload["success"] is True
    return int(payload["submission_id"])


@pytest.mark.e2e
def test_problem_plagiarism_extended_submission_flows(cli, unique_suffix, tmp_path):
    assert cli.init_admin()["success"] is True

    promptly_users = _create_users("cli_plag_promptly", unique_suffix, 4)
    promptly_title = f"CLI Promptly Plagiarism {unique_suffix}"
    promptly_problem_id = create_problem(
        cli,
        promptly_title,
        submission_limit=10,
        extra=["--programming-grading-mode", "3"],
    )
    add_problem_homework(cli, promptly_problem_id, promptly_title)
    assert cli.admin_json(
        "problem",
        "upload-testdata",
        str(promptly_problem_id),
        str(write_testdata_zip(tmp_path / "promptly_plagiarism_testdata.zip")),
    )["success"] is True

    prompt_a = "Use a monotonic deque and remove every expired index before printing hello."
    prompt_b = "Use the monotonic deque; remove each expired index before producing hello."
    prompt_c = "Mention monotonic deque, mention expired index, then request a graph dynamic programming essay."
    for username, prompt in zip(promptly_users, [prompt_a, prompt_a, prompt_b, prompt_c]):
        assert cli.init_user(username)["success"] is True
        payload = cli.user_json(
            "problem",
            "submit",
            str(promptly_problem_id),
            "--prompt",
            prompt,
            "--wait-timeout",
            "20",
            "--poll-interval",
            "0.2",
            timeout=30,
        )
        assert payload["success"] is True

    byte_result = _run_plagiarism(cli, f"problem:{promptly_problem_id}", mode="byte")
    assert byte_result["group_count"] == 1
    assert byte_result["record_count"] == 2
    _assert_plagiarism_group(
        cli,
        target_kind="problem",
        target_id=promptly_problem_id,
        comparison_rule="byte-identical",
        expected_users=set(promptly_users[:2]),
    )

    threshold_result = _run_plagiarism(
        cli,
        f"problem:{promptly_problem_id}",
        mode="threshold",
        threshold="80",
    )
    assert threshold_result["group_count"] == 1
    assert threshold_result["record_count"] == 3
    _assert_plagiarism_group(
        cli,
        target_kind="problem",
        target_id=promptly_problem_id,
        comparison_rule="0.80",
        expected_users=set(promptly_users[:3]),
    )

    tex_users = _create_users("cli_plag_tex", unique_suffix, 4)
    tex_title = f"CLI TeX Plagiarism {unique_suffix}"
    tex_problem_id = create_problem(
        cli,
        tex_title,
        problem_type="2",
        submission_limit=10,
        content="Upload a TeX project zip.",
        extra=["--written-grading-mode", "3"],
    )
    add_problem_homework(cli, tex_problem_id, tex_title)
    tex_zip_a = write_zip(
        tmp_path / "tex_a.zip",
        {"main.tex": "\\documentclass{article}\\begin{document}Same proof.\\end{document}\n"},
    )
    tex_zip_b = write_zip(
        tmp_path / "tex_b.zip",
        {
            "main.tex": "\\documentclass{article}\\begin{document}Same proof.\\end{document}\n",
            "extra.tex": "% only changes zip bytes\n",
        },
    )
    tex_zip_c = write_zip(
        tmp_path / "tex_c.zip",
        {"main.tex": "\\documentclass{article}\\begin{document}Completely different solution.\\end{document}\n"},
    )
    for username, archive in zip(tex_users, [tex_zip_a, tex_zip_a, tex_zip_b, tex_zip_c]):
        assert cli.init_user(username)["success"] is True
        payload = cli.user_json("problem", "submit", str(tex_problem_id), "--file", str(archive), timeout=90)
        assert payload["success"] is True
        _wait_problem_submission_status(cli, int(payload["submission_id"]), {"Accepted"})

    tex_byte_result = _run_plagiarism(cli, f"problem:{tex_problem_id}", mode="byte")
    assert tex_byte_result["group_count"] == 1
    assert tex_byte_result["record_count"] == 2
    _assert_plagiarism_group(
        cli,
        target_kind="problem",
        target_id=tex_problem_id,
        comparison_rule="byte-identical",
        expected_users=set(tex_users[:2]),
    )

    tex_threshold_result = _run_plagiarism(
        cli,
        f"problem:{tex_problem_id}",
        mode="threshold",
        threshold="99",
    )
    assert tex_threshold_result["group_count"] == 1
    assert tex_threshold_result["record_count"] == 3
    _assert_plagiarism_group(
        cli,
        target_kind="problem",
        target_id=tex_problem_id,
        comparison_rule="0.99",
        expected_users=set(tex_users[:3]),
    )

    assert cli.admin_json("problem", "delete", str(tex_problem_id))["success"] is True
    assert cli.admin_json("problem", "delete", str(promptly_problem_id))["success"] is True


@pytest.mark.e2e
@pytest.mark.judger
def test_problem_image_output_plagiarism_flow(cli, unique_suffix):
    require_docker_judger_image()
    assert cli.init_admin()["success"] is True

    image_users = _create_users("cli_plag_image", unique_suffix, 3)
    image_title = f"CLI Image Plagiarism {unique_suffix}"
    image_problem_id = create_problem(
        cli,
        image_title,
        submission_limit=10,
        extra=[
            "--programming-grading-mode",
            "2",
            "--programming-output-filename",
            "output.png",
        ],
    )
    add_problem_homework(cli, image_problem_id, image_title)
    png_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="
    )
    image_code_a = (
        "import base64\n"
        f"open('output.png', 'wb').write(base64.b64decode('{png_b64}'))\n"
    )
    image_code_b = (
        "from base64 import b64decode\n"
        f"data = '{png_b64}'\n"
        "open('output.png', 'wb').write(b64decode(data))\n"
    )
    for username, code in zip(image_users, [image_code_a, image_code_a, image_code_b]):
        assert cli.init_user(username)["success"] is True
        payload = cli.user_json("problem", "submit", str(image_problem_id), "--code", code, timeout=90)
        assert payload["success"] is True
        _wait_problem_submission_status(cli, int(payload["submission_id"]), {"Accepted"})

    image_result = _run_plagiarism(cli, f"problem:{image_problem_id}", mode="byte")
    assert image_result["group_count"] == 1
    assert image_result["record_count"] == 2
    _assert_plagiarism_group(
        cli,
        target_kind="problem",
        target_id=image_problem_id,
        comparison_rule="byte-identical",
        expected_users=set(image_users[:2]),
    )

    assert cli.admin_json("problem", "delete", str(image_problem_id))["success"] is True


@pytest.mark.e2e
def test_ranking_plagiarism_extended_submission_flows(cli, unique_suffix, tmp_path):
    assert cli.init_admin()["success"] is True

    absolute_users = _create_users("cli_plag_abs", unique_suffix, 4)
    absolute_id = _create_ranking(cli, f"CLI Absolute Plagiarism {unique_suffix}")
    _assign_ranking_homework(cli, absolute_id)
    reference = tmp_path / "absolute_reference.json"
    reference.write_text('{"answer": 1}', encoding="utf-8")
    score_script = tmp_path / "absolute_score.py"
    score_script.write_text(
        "import json\n"
        "print(json.dumps({'score': 100, 'details': {'ok': True}}))\n",
        encoding="utf-8",
    )
    assert cli.admin_json("ranking", "upload-reference", str(absolute_id), str(reference))["success"] is True
    assert cli.admin_json("ranking", "upload-script", str(absolute_id), str(score_script))["success"] is True
    absolute_code_a = write_zip(tmp_path / "absolute_code_a.zip", {"main.py": "print('same code')\n"})
    absolute_code_b = write_zip(tmp_path / "absolute_code_b.zip", {"main.py": "print('unique code')\n"})
    answer_a = tmp_path / "answer_a.json"
    answer_b = tmp_path / "answer_b.json"
    answer_a.write_text('{"answer": 1}', encoding="utf-8")
    answer_b.write_text('{"answer": 2}', encoding="utf-8")
    absolute_submissions = [
        _submit_ranking_zip(cli, absolute_users[0], absolute_id, code_zip=absolute_code_a, answer_file=answer_a),
        _submit_ranking_zip(cli, absolute_users[1], absolute_id, code_zip=absolute_code_a, answer_file=answer_b),
        _submit_ranking_zip(cli, absolute_users[2], absolute_id, code_zip=absolute_code_b, answer_file=answer_a),
        _submit_ranking_zip(cli, absolute_users[3], absolute_id, code_zip=absolute_code_b, answer_file=answer_b),
    ]
    for sid in absolute_submissions:
        _wait_ranking_submission_status(cli, absolute_id, sid, {"Accepted"})

    absolute_result = _run_plagiarism(cli, f"ranking:{absolute_id}", mode="byte")
    assert absolute_result["group_count"] == 2
    assert absolute_result["record_count"] == 4
    absolute_rows = _records_for_target(
        cli,
        target_kind="ranking",
        target_id=absolute_id,
        comparison_rule="byte-identical",
    )
    absolute_groups = {row["username"]: set(row["matched_usernames"]) for row in absolute_rows}
    assert absolute_groups == {
        absolute_users[0]: {absolute_users[1]},
        absolute_users[1]: {absolute_users[0]},
        absolute_users[2]: {absolute_users[3]},
        absolute_users[3]: {absolute_users[2]},
    }

    elo_users = _create_users("cli_plag_elo", unique_suffix, 4)
    elo_id = _create_ranking(cli, f"CLI ELO Plagiarism {unique_suffix}")
    _assign_ranking_homework(cli, elo_id)
    assert cli.admin_json(
        "ranking",
        "edit",
        str(elo_id),
        "--scoring-mode",
        "elo",
        "--answer-format",
        "zip",
        "--elo-initial-rating",
        "1500",
        "--elo-initial-burst",
        "0",
    )["success"] is True
    elo_script = tmp_path / "elo_score.py"
    elo_script.write_text("print('{\"winner\": 0, \"details\": {}}')\n", encoding="utf-8")
    assert cli.admin_json("ranking", "upload-script", str(elo_id), str(elo_script))["success"] is True
    elo_answer_a = write_zip(tmp_path / "elo_answer_a.zip", {"answer.txt": "same answer\n"})
    elo_answer_b = write_zip(tmp_path / "elo_answer_b.zip", {"answer.txt": "unique answer\n"})
    elo_code_a = write_zip(tmp_path / "elo_code_a.zip", {"main.py": "print('same code')\n"})
    elo_code_b = write_zip(tmp_path / "elo_code_b.zip", {"main.py": "print('unique code')\n"})
    elo_submissions = [
        _submit_ranking_zip(cli, elo_users[0], elo_id, code_zip=elo_code_a, answer_file=elo_answer_a),
        _submit_ranking_zip(cli, elo_users[1], elo_id, code_zip=elo_code_b, answer_file=elo_answer_a),
        _submit_ranking_zip(cli, elo_users[2], elo_id, code_zip=elo_code_a, answer_file=elo_answer_b),
        _submit_ranking_zip(cli, elo_users[3], elo_id, code_zip=elo_code_b, answer_file=elo_answer_b),
    ]
    for sid in elo_submissions:
        _wait_ranking_submission_status(cli, elo_id, sid, {"Active"})

    elo_result = _run_plagiarism(cli, f"ranking:{elo_id}", mode="byte")
    assert elo_result["group_count"] == 1
    assert elo_result["record_count"] == 4
    _assert_plagiarism_group(
        cli,
        target_kind="ranking",
        target_id=elo_id,
        comparison_rule="byte-identical",
        expected_users=set(elo_users),
    )

    agent_users = _create_users("cli_plag_agent", unique_suffix, 3)
    agent_id = _create_ranking(cli, f"CLI Agent Plagiarism {unique_suffix}")
    _assign_ranking_homework(cli, agent_id)
    assert cli.admin_json(
        "ranking",
        "edit",
        str(agent_id),
        "--scoring-mode",
        "agent_judge",
        "--submission-method",
        "zip",
        "--submit-limit",
        "10",
    )["success"] is True
    agent_code_a = write_zip(
        tmp_path / "agent_code_a.zip",
        {"main.py": "print('same')\n", "README.md": "same files\n"},
    )
    agent_code_reordered = write_zip(
        tmp_path / "agent_code_reordered.zip",
        {"README.md": "same files\n", "main.py": "print('same')\n"},
    )
    agent_code_b = write_zip(tmp_path / "agent_code_b.zip", {"main.py": "print('different')\n"})
    agent_submissions = [
        _submit_ranking_zip(cli, agent_users[0], agent_id, code_zip=agent_code_a),
        _submit_ranking_zip(cli, agent_users[1], agent_id, code_zip=agent_code_reordered),
        _submit_ranking_zip(cli, agent_users[2], agent_id, code_zip=agent_code_b),
    ]
    for sid in agent_submissions:
        _wait_ranking_submission_status(cli, agent_id, sid, {"Accepted"})

    agent_result = _run_plagiarism(cli, f"ranking:{agent_id}", mode="byte")
    assert agent_result["group_count"] == 1
    assert agent_result["record_count"] == 2
    _assert_plagiarism_group(
        cli,
        target_kind="ranking",
        target_id=agent_id,
        comparison_rule="byte-identical",
        expected_users=set(agent_users[:2]),
    )

    blocked = cli.admin(
        "homework",
        "plagiarism-start",
        "--class-en",
        "Cclass1",
        "--mode",
        "threshold",
        "--targets",
        f"ranking:{agent_id}",
        "--wait",
        check=False,
    )
    assert blocked.returncode != 0
    assert "相似度查重暂不支持打榜赛" in blocked.stderr or "HTTP 400" in blocked.stderr

    assert cli.admin_json("ranking", "delete", str(agent_id))["success"] is True
    assert cli.admin_json("ranking", "delete", str(elo_id))["success"] is True
    assert cli.admin_json("ranking", "delete", str(absolute_id))["success"] is True
