# -*- coding: utf-8 -*-
"""Class, homework, grade export, and admin user-management CLI flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    create_problem,
    create_problem_with_homework,
    create_regular_user,
    find_homework_id,
    get_user_id,
)


@pytest.mark.e2e
def test_admin_user_class_management_and_homework_lifecycle(cli, unique_suffix):
    username = f"cli_class_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    user_id = get_user_id(username)
    class_token = f"E2EClass{unique_suffix}"
    class_en = f"C{class_token}"
    assert cli.admin_json("user", "add-class-type", "--class-en", class_token, "--class-cn", "CLI 管理班")["success"] is True
    assert any(u["username"] == username for u in cli.admin_json("user", "list", "--username", username)["users"])

    assert cli.admin_json("user", "add-to-class", str(user_id), class_en)["success"] is True
    assert cli.admin_json("user", "set-primary-class", str(user_id), class_en)["success"] is True
    assert cli.admin_json("homework", "class-adjust", "false")["success"] is True
    blocked_join = cli.user("me", "join-class", "Cclass1", check=False)
    assert blocked_join.returncode != 0
    assert "HTTP 403" in blocked_join.stderr
    assert cli.admin_json("homework", "class-adjust", "true")["success"] is True

    renamed = f"{username}_renamed"
    assert cli.admin_json("user", "rename", str(user_id), renamed)["success"] is True
    assert any(u["username"] == renamed for u in cli.admin_json("user", "list", "--username", renamed)["users"])
    assert cli.admin_json("user", "remove-from-class", str(user_id), "Cclass1")["success"] is True

    title = f"CLI Homework {unique_suffix}"
    problem_id = create_problem(cli, title)
    assert cli.admin_json(
        "homework",
        "add",
        "--class-en",
        class_en,
        "--problem-id",
        str(problem_id),
        "--ddl",
        "2099-01-01T00:00",
    )["success"] is True
    homework_id = find_homework_id(cli.admin_json("homework", "list", "--class-en", class_en), title)
    assert cli.admin_json(
        "homework",
        "update-ddl",
        "--class-en",
        class_en,
        "--homework-id",
        homework_id,
        "--ddl",
        "2099-02-01T00:00",
    )["success"] is True

    assert cli.admin_json(
        "homework",
        "delete",
        "--class-en",
        class_en,
        "--homework-id",
        homework_id,
    )["success"] is True
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True


@pytest.mark.e2e
def test_homework_score_exports_exam_upload_and_export_artifact(cli, unique_suffix, tmp_path):
    import openpyxl
    import redis
    import config

    username = f"cli_export_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    title = f"CLI Export Problem {unique_suffix}"
    problem_id, _ = create_problem_with_homework(cli, title)
    user_id = get_user_id(username)
    assert cli.admin_json("user", "update-grade", str(user_id), str(problem_id), "--score", "0")["success"] is True

    scores_path = tmp_path / "scores.csv"
    scores = cli.admin_json("homework", "export-scores", "--class-en", "Cclass1", "-o", str(scores_path))
    assert scores["success"] is True
    assert scores_path.exists()
    assert title in scores_path.read_text(encoding="gb18030")

    workbook_path = tmp_path / "exam.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["student_id", "regular", "final"])
    ws.append([username, 88, 92])
    wb.save(workbook_path)
    assert cli.admin_json("homework", "upload-exam", "--class-en", "Cclass1", str(workbook_path))["success"] is True

    export_job = cli.admin_json("homework", "export-codes", "--class-en", "Cclass1")
    assert export_job["success"] is True

    rds = redis.StrictRedis(
        host=config.REDIS_HOST,
        port=int(config.REDIS_PORT),
        db=int(config.REDIS_DB),
        decode_responses=True,
    )
    rds_bin = redis.StrictRedis(
        host=config.REDIS_HOST,
        port=int(config.REDIS_PORT),
        db=int(config.REDIS_DB),
        decode_responses=False,
    )
    task_id = "cli-e2e-export"
    rds.set(f"export_progress:{task_id}", json.dumps({"status": "done", "progress": 100}, ensure_ascii=False), ex=60)
    rds_bin.set(f"export_zip:{task_id}", b"PK\x05\x06" + b"\x00" * 18, ex=60)
    assert cli.admin_json("homework", "export-progress", task_id)["success"] is True
    download = cli.admin_json("homework", "download-export", task_id, "-o", str(tmp_path))
    assert download["success"] is True
    assert Path(download["path"]).exists()

    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True
