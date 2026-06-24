# -*- coding: utf-8 -*-
"""Ranking competition CLI flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    assert_no_json_leaks,
    create_local_git_repo,
    create_regular_user,
    get_ranking_appeal_id,
    ranking_id_from_create,
    write_zip,
)


RANKING_SECRET_KEYS = {
    "agent_judge_api_key",
    "agent_judge_api_key_set",
    "agent_judge_base_url",
    "agent_judge_model",
    "agent_judge_timeout_seconds",
    "reference_answer_path",
    "reference_answer_name",
    "scoring_script_path",
    "scoring_script_name",
    "git_format",
    "judge_rules",
    "aj_endpoints",
    "batch_default_template",
    "api_key",
    "elo_initial_rating",
    "elo_k_factor",
    "elo_max_matches",
    "elo_match_interval_seconds",
    "elo_initial_burst",
    "elo_max_pairs_per_round",
    "elo_running",
    "elo_rating",
    "elo_match_count",
    "elo_in_pool",
}


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


def _ranking_submission_ids(payload: dict) -> list[int]:
    return [int(row["id"]) for row in payload.get("submissions") or [] if row.get("id")]


@pytest.mark.e2e
def test_ranking_absolute_zip_submission_appeal_and_admin_files(cli, unique_suffix, tmp_path):
    username = f"cli_rank_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    ranking_id = _create_ranking(cli, f"CLI Ranking {unique_suffix}")
    assert cli.admin_json("ranking", "detail", str(ranking_id), "--tab", "edit")["success"] is True
    user_detail = cli.user_json("ranking", "detail", str(ranking_id))
    assert user_detail["success"] is True
    assert_no_json_leaks(user_detail, forbidden_keys=RANKING_SECRET_KEYS)
    user_list = cli.user_json("ranking", "list", "--limit", "10")
    assert user_list["count"] >= 1
    assert_no_json_leaks(user_list, forbidden_keys=RANKING_SECRET_KEYS)

    attachment = tmp_path / "attachment.txt"
    attachment.write_text("attachment", encoding="utf-8")
    assert cli.admin_json("ranking", "upload-attachment", str(ranking_id), str(attachment))["success"] is True
    download = cli.admin_json("ranking", "download-attachment", str(ranking_id), "1", "-o", str(tmp_path))
    assert download["success"] is True
    assert Path(download["path"]).exists()
    assert cli.admin_json("ranking", "delete-attachment", str(ranking_id), "1")["success"] is True

    reference = tmp_path / "reference.json"
    reference.write_text('{"answer": 1}', encoding="utf-8")
    script = tmp_path / "score.py"
    script.write_text("print('score')\n", encoding="utf-8")
    assert cli.admin_json("ranking", "upload-reference", str(ranking_id), str(reference))["success"] is True
    assert cli.admin_json("ranking", "upload-script", str(ranking_id), str(script))["success"] is True
    assert cli.admin_json("ranking", "clear-script", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "reset-limit", str(ranking_id))["success"] is True

    answer = tmp_path / "answer.json"
    answer.write_text('{"answer": 1}', encoding="utf-8")
    code_zip = write_zip(tmp_path / "code.zip", {"main.py": "print(1)\n"})
    submit_payload = cli.user_json(
        "ranking",
        "submit",
        str(ranking_id),
        "--base-model",
        "baseline",
        "--code-zip",
        str(code_zip),
        "--answer-file",
        str(answer),
    )
    assert submit_payload["success"] is True
    assert "submission_id" in submit_payload

    mine = cli.user_json("ranking", "my-submissions", str(ranking_id), "--limit", "5")
    assert_no_json_leaks(mine, forbidden_keys=RANKING_SECRET_KEYS)
    submission_ids = _ranking_submission_ids(mine)
    assert len(submission_ids) == 1
    sid = submission_ids[0]
    assert cli.admin_json("ranking", "submissions", str(ranking_id), "--username", username)["count"] == 1
    assert cli.admin_json("ranking", "bulk-filter", str(ranking_id), "--username", username)["success"] is True
    assert cli.admin_json("ranking", "bulk-start", str(ranking_id), "--submission-ids", str(sid))["success"] is True
    leaderboard = cli.user_json("ranking", "leaderboard", str(ranking_id))
    assert leaderboard["success"] is True
    assert_no_json_leaks(leaderboard, forbidden_keys=RANKING_SECRET_KEYS)
    matches = cli.user_json("ranking", "matches", str(ranking_id))
    assert matches["total"] == 0
    assert_no_json_leaks(matches, forbidden_keys=RANKING_SECRET_KEYS)

    downloaded_answer = cli.user_json("ranking", "download-submission", str(sid), "answer", "-o", str(tmp_path))
    downloaded_code = cli.admin_json("ranking", "download-submission", str(sid), "code", "-o", str(tmp_path))
    assert Path(downloaded_answer["path"]).exists()
    assert Path(downloaded_code["path"]).exists()

    assert cli.user_json("ranking", "appeal", str(ranking_id), str(sid), "--reason", "please check")["ok"] is True
    assert cli.user_json("ranking", "appeal-status", str(ranking_id), str(sid))["has_appeal"] is True
    appeal_id = get_ranking_appeal_id(sid)
    appeals = cli.admin_json("ranking", "appeals", str(ranking_id))
    assert any(int(row["id"]) == appeal_id for row in appeals["appeals"])
    assert cli.admin_json("ranking", "appeal-review", str(ranking_id), str(appeal_id))["success"] is True
    assert cli.admin_json(
        "ranking",
        "appeal-handle",
        str(ranking_id),
        str(appeal_id),
        "--decision",
        "resolved",
        "--response",
        "handled",
        "--overrides",
        "{}",
    )["ok"] is True

    assert cli.admin_json("ranking", "delete-submission", str(ranking_id), str(sid))["success"] is True
    assert cli.admin_json("ranking", "delete", str(ranking_id))["success"] is True


@pytest.mark.e2e
def test_ranking_elo_admin_controls(cli, unique_suffix):
    username = f"cli_elo_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    ranking_id = _create_ranking(cli, f"CLI ELO {unique_suffix}")
    assert cli.admin_json(
        "ranking",
        "edit",
        str(ranking_id),
        "--scoring-mode",
        "elo",
        "--elo-initial-rating",
        "1500",
        "--elo-k-factor",
        "32",
        "--elo-max-matches",
        "10",
        "--elo-match-interval",
        "30",
        "--elo-initial-burst",
        "0",
        "--elo-max-pairs-per-round",
        "1",
    )["success"] is True
    assert cli.admin_json("ranking", "elo-start", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "elo-stop", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "elo-reset", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "elo-rebuild", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "matches", str(ranking_id))["total"] == 0
    assert cli.admin_json("ranking", "delete", str(ranking_id))["success"] is True


@pytest.mark.e2e
def test_ranking_agent_judge_git_check_submit_and_batch_admin(cli, unique_suffix, tmp_path):
    username = f"cli_git_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    ranking_id = _create_ranking(cli, f"CLI Agent Git {unique_suffix}")
    repo_root = tmp_path / "repos"
    user_repo = create_local_git_repo(repo_root / username)
    template = f"file://{repo_root}/<username>"

    assert cli.admin_json(
        "ranking",
        "edit",
        str(ranking_id),
        "--scoring-mode",
        "agent_judge",
        "--submission-method",
        "git",
        "--git-format",
        template,
        "--submit-limit",
        "3",
        "--agent-timeout",
        "60",
    )["success"] is True
    assert cli.admin_json(
        "ranking",
        "save-rules",
        str(ranking_id),
        json.dumps([{"rule_id": 1, "rule_text": "Works", "value": 100}], ensure_ascii=False),
    )["success"] is True
    assert cli.admin_json(
        "ranking",
        "save-endpoints",
        str(ranking_id),
        json.dumps(
            [
                {
                    "harness": "codex",
                    "base_url": "http://127.0.0.1:9",
                    "api_key": "local-only",
                    "model": "fake",
                    "concurrency_limit": 1,
                    "enabled": True,
                }
            ],
            ensure_ascii=False,
        ),
        "--timeout-seconds",
        "60",
    )["success"] is True
    assert cli.admin_json(
        "ranking",
        "save-config",
        str(ranking_id),
        "--agent-base-url",
        "http://127.0.0.1:9",
        "--api-key",
        "local-only",
        "--model",
        "fake",
        "--timeout-seconds",
        "60",
    )["success"] is True
    admin_detail = cli.admin_json("ranking", "detail", str(ranking_id), "--tab", "edit")
    assert admin_detail["success"] is True
    assert admin_detail["aj_endpoints"]
    assert admin_detail["judge_rules"]

    user_detail = cli.user_json("ranking", "detail", str(ranking_id), "--tab", "submit")
    assert user_detail["success"] is True
    assert user_detail["git_repo_url"] == f"file://{user_repo}"
    assert_no_json_leaks(
        user_detail,
        forbidden_keys=RANKING_SECRET_KEYS,
        forbidden_terms=("http://127.0.0.1:9", "local-only", "fake", "Works", "<username>"),
    )
    rejected_zip = cli.user_json(
        "ranking",
        "submit",
        str(ranking_id),
        "--base-model",
        "baseline",
        "--code-zip",
        str(write_zip(tmp_path / "git_rejected.zip", {"main.py": "print(1)\n"})),
    )
    assert rejected_zip["success"] is False

    git_help = cli.user("ranking", "git", "--help").text
    assert "check" in git_help and "submit" in git_help
    check = cli.user_json("ranking", "git", str(ranking_id), "check", timeout=30)
    assert check["success"] is True
    assert check["exists"] is True
    assert check["url"] == f"file://{user_repo}"
    assert cli.user_json("ranking", "git", str(ranking_id), "submit")["success"] is True

    probe = cli.admin_json("ranking", "batch-probe", str(ranking_id), "--classes", "Cclass1", "--template", template)
    assert probe["success"] is True
    assert cli.admin_json("ranking", "batch-status", str(ranking_id), probe["job_id"])["success"] is True
    assert cli.admin_json("ranking", "batch-create", str(ranking_id), "--template", template, "--usernames", username)["success"] is True
    assert cli.admin_json("ranking", "bulk-filter", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "delete", str(ranking_id))["success"] is True


@pytest.mark.e2e
def test_ranking_agent_judge_48h_submission_limit(cli, unique_suffix, tmp_path):
    username = f"cli_rank_limit_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    ranking_id = _create_ranking(cli, f"CLI Agent Limit {unique_suffix}")
    assert cli.admin_json(
        "ranking",
        "edit",
        str(ranking_id),
        "--scoring-mode",
        "agent_judge",
        "--submission-method",
        "zip",
        "--submit-limit",
        "3",
    )["success"] is True

    code_zip = write_zip(tmp_path / "agent_code.zip", {"main.py": "print('agent')\n"})
    for _ in range(3):
        assert cli.user_json(
            "ranking",
            "submit",
            str(ranking_id),
            "--base-model",
            "baseline",
            "--code-zip",
            str(code_zip),
        )["success"] is True

    blocked = cli.user_json(
        "ranking",
        "submit",
        str(ranking_id),
        "--base-model",
        "baseline",
        "--code-zip",
        str(code_zip),
    )
    assert blocked["success"] is False
    mine = cli.user_json("ranking", "my-submissions", str(ranking_id), "--limit", "10")
    assert mine["count"] == 3
    assert cli.admin_json("ranking", "reset-limit", str(ranking_id))["success"] is True
    assert cli.admin_json("ranking", "delete", str(ranking_id))["success"] is True
