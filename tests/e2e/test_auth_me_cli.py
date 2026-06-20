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
def test_admin_and_user_auth_pages_login_status_and_logout(cli, unique_suffix):
    username = f"cli_auth_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")

    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    assert cli.admin_json("auth", "status")["admin"] is True
    assert cli.user_json("auth", "status")["authenticated"] is True
    assert cli.admin_json("site", "home")["success"] is True
    assert cli.user_json("site", "home")["success"] is True

    for command in (
        ("auth", "login-page"),
        ("auth", "register-page"),
        ("auth", "forgot-page"),
        ("auth", "forgot-page", "--step", "verify", "--email", f"{username}@example.com"),
    ):
        assert cli.user_json(*command)["success"] is True

    assert cli.user_json("auth", "send-code", "--email", f"{username}@example.com")["success"] is False
    assert cli.user_json("auth", "forgot-request", "--email", f"missing_{unique_suffix}@example.com")["success"] is True

    assert cli.user_json("auth", "logout")["success"] is True
    saved = json.loads(Path(cli.user_config).read_text(encoding="utf-8"))
    assert "cookies" not in saved


@pytest.mark.e2e
def test_register_forgot_reset_and_change_password(cli, unique_suffix, tmp_path):
    assert cli.init_admin()["success"] is True

    registered = f"cli_registered_{unique_suffix}"
    registered_email = f"{registered}@example.com"
    seed_verification_code(registered_email, "654321")
    register_cfg = tmp_path / "register.json"
    assert cli.run(
        USER_CLI,
        register_cfg,
        "--base-url",
        cli.base_url,
        "auth",
        "register",
        "--username",
        registered,
        "--password",
        "oldpass123",
        "--email",
        registered_email,
        "--code",
        "654321",
        "--class-en",
        "Cclass1",
    ).json()["success"] is True

    assert cli.run(
        USER_CLI,
        tmp_path / "registered.json",
        "init",
        "--base-url",
        cli.base_url,
        "-u",
        registered,
        "-p",
        "oldpass123",
    ).json()["success"] is True

    seed_verification_code(registered_email, "777777")
    assert cli.run(
        USER_CLI,
        register_cfg,
        "--base-url",
        cli.base_url,
        "auth",
        "forgot-reset",
        "--email",
        registered_email,
        "--code",
        "777777",
        "--new-password",
        "newpass123",
    ).json()["success"] is True

    reset_cfg = tmp_path / "reset.json"
    assert cli.run(
        USER_CLI,
        reset_cfg,
        "init",
        "--base-url",
        cli.base_url,
        "-u",
        registered,
        "-p",
        "newpass123",
    ).json()["success"] is True

    seed_verification_code(registered_email, "888888")
    assert cli.run(
        USER_CLI,
        reset_cfg,
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
        registered,
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
    assert classes["success"] is True
    assert any(c["class_en"] == class_en for c in classes["all_classes"])

    assert cli.user_json("me", "join-class", class_en)["success"] is True
    assert cli.user_json("me", "set-primary-class", class_en)["success"] is True
    assert cli.user_json("me", "leave-class", "Cclass1")["success"] is True
    assert cli.user_json("me", "submissions", "--limit", "5")["success"] is True
    assert cli.user_json("me", "grades")["success"] is True

    admin_classes = cli.admin_json("me", "classes")
    assert admin_classes["success"] is True
    assert cli.admin_json("me", "submissions", "--limit", "5")["success"] is True
