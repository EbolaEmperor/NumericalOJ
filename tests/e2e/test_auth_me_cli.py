# -*- coding: utf-8 -*-
"""Authentication, account, and current-user CLI flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    USER_CLI,
    create_regular_user,
    seed_verification_code,
)


@pytest.mark.e2e
def test_admin_and_user_login_status_logout_and_login_gate(cli, unique_suffix, tmp_path):
    username = f"cli_auth_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")

    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    assert cli.admin_json("auth", "status")["admin"] is True
    assert cli.user_json("auth", "status")["authenticated"] is True
    assert cli.admin_json("site", "home")["success"] is True
    cli.user_json("me", "classes")

    anonymous_cfg = tmp_path / "anonymous.json"
    anonymous_cfg.write_text(json.dumps({"base_url": cli.base_url}), encoding="utf-8")
    gated = cli.run(USER_CLI, anonymous_cfg, "me", "classes", check=False)
    assert gated.returncode == 2
    assert "CLI requires login" in gated.stderr

    assert cli.user_json("auth", "logout")["success"] is True
    saved = json.loads(Path(cli.user_config).read_text(encoding="utf-8"))
    assert "cookies" not in saved


@pytest.mark.e2e
def test_logged_in_change_password(cli, unique_suffix, tmp_path):
    assert cli.init_admin()["success"] is True

    username = f"cli_change_{unique_suffix}"
    email = f"{username}@example.com"
    create_regular_user(username=username, password="oldpass123", email=email)
    user_cfg = tmp_path / "change.json"
    assert cli.run(
        USER_CLI,
        user_cfg,
        "init",
        "--base-url",
        cli.base_url,
        "-u",
        username,
        "-p",
        "oldpass123",
    ).json()["success"] is True

    seed_verification_code(email, "888888")
    assert cli.run(
        USER_CLI,
        user_cfg,
        "auth",
        "change-password",
        "--code",
        "888888",
        "--new-password",
        "finalpass123",
    ).json()["success"] is True
    assert cli.run(
        USER_CLI,
        tmp_path / "final.json",
        "init",
        "--base-url",
        cli.base_url,
        "-u",
        username,
        "-p",
        "finalpass123",
    ).json()["success"] is True


@pytest.mark.e2e
def test_me_class_and_grade_commands(cli, unique_suffix):
    username = f"cli_me_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    class_token = f"E2EMe{unique_suffix}"
    class_en = f"C{class_token}"
    assert cli.admin_json("user", "add-class-type", "--class-en", class_token, "--class-cn", "CLI Me 班")["success"] is True

    classes = cli.user_json("me", "classes")
    assert any(c["class_en"] == class_en for c in classes["all_classes"])

    assert cli.user_json("me", "join-class", class_en)["success"] is True
    assert cli.user_json("me", "leave-class", "Cclass1")["success"] is True
    cli.user_json("me", "submissions", "--limit", "5")
    cli.user_json("me", "grades")

    admin_classes = cli.admin_json("me", "classes")
    assert admin_classes["success"] is True
    assert cli.admin_json("me", "submissions", "--limit", "5")["success"] is True
