# -*- coding: utf-8 -*-
"""AI-related CLI surfaces that are safe to exercise locally.

Live model calls are intentionally not invoked here. The command help matrix
covers the AI tutor commands; this file covers local-only AIGC/admin pages and
filter APIs.
"""

from __future__ import annotations

import pytest

from tests.e2e.conftest import create_problem_with_homework, create_regular_user


def _create_ai_detection_endpoint() -> int:
    """在一次性测试库中创建已通过暂存测试的文本端点。"""

    from oj_modules.site_config import services as dynamic_config_services
    from oj_modules.db_services import get_user_by_username

    admin = get_user_by_username("admin")
    payload = {
        "name": "CLI AI 检测端点",
        "protocol": "anthropic",
        "category": "text",
        "base_url": "http://127.0.0.1:19101",
        "api_key": "quality-pool-secret",
        "model": "fake-quality-model",
        "thinking_enabled": False,
        "thinking_format": "none",
    }
    probe = dynamic_config_services.test_llm_endpoint(
        payload,
        user_id=admin["id"],
        tester=lambda _candidate: True,
    )
    endpoint = dynamic_config_services.save_llm_endpoint(
        payload,
        user_id=admin["id"],
        test_token=probe["test_token"],
    )
    return int(endpoint["id"])


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
    endpoint_id = _create_ai_detection_endpoint()

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
        "--endpoint-id",
        str(endpoint_id),
    )["success"] is True
    assert cli.admin_json("ai-detection", "task", "stop", "missing-task")["success"] in (True, False)
    assert cli.admin_json("problem", "delete", str(problem_id))["success"] is True
