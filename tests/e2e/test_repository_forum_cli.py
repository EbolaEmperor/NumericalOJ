# -*- coding: utf-8 -*-
"""Code repository and forum CLI flows."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e.conftest import (
    create_regular_user,
    find_forum_thread_id,
    find_repository_file_id,
)


@pytest.mark.e2e
def test_repository_file_upload_index_and_search_commands(cli, unique_suffix, tmp_path):
    username = f"cli_repo_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    assert cli.user_json("repository", "page")["success"] is True
    filename = f"helper_{unique_suffix}.hpp"
    assert cli.user_json(
        "repository",
        "save",
        "--filename",
        filename,
        "--content",
        "int helper(){return 1;}",
    )["success"] is True
    repo_files = cli.user_json("repository", "files")
    file_id = find_repository_file_id(repo_files, filename)
    assert "helper" in cli.user_json("repository", "get", str(file_id))["content"]

    output_file = tmp_path / "downloaded.hpp"
    saved = cli.user_json("repository", "get", str(file_id), "-o", str(output_file))
    assert saved["success"] is True
    assert output_file.read_text(encoding="utf-8") == "int helper(){return 1;}"

    content_file = tmp_path / "updated.hpp"
    content_file.write_text("int helper(){return 2;}", encoding="utf-8")
    assert cli.user_json(
        "repository",
        "save",
        "--filename",
        filename,
        "--content-file",
        str(content_file),
        "--file-id",
        str(file_id),
    )["success"] is True

    upload_file = tmp_path / f"uploaded_{unique_suffix}.h"
    upload_file.write_text("#pragma once\n", encoding="utf-8")
    assert cli.user_json("repository", "upload", str(upload_file))["success"] is True

    build = cli.user_json("repository", "build-index")
    assert build["success"] is True
    assert cli.user_json("repository", "index-status", str(build["job_id"]))["success"] is True
    assert cli.user_json("repository", "active-status")["success"] is True

    rebuild = cli.user_json("repository", "rebuild-file", str(file_id), "--force-restart")
    assert rebuild["success"] is True
    assert cli.user_json("repository", "classes")["success"] is True
    search = cli.user("repository", "search", "--query", "helper", "--top-k", "3", check=False)
    if search.returncode == 0:
        assert search.json()["success"] is True
    else:
        assert "faiss" in search.stderr.lower()

    assert cli.user_json("repository", "delete", str(file_id))["success"] is True
    admin_files = cli.admin_json("repository", "files")
    assert admin_files["success"] is True


@pytest.mark.e2e
def test_forum_pages_threads_and_replies(cli, unique_suffix):
    username = f"cli_forum_{unique_suffix}"
    create_regular_user(username=username, password="pw123456")
    assert cli.init_admin()["success"] is True
    assert cli.init_user(username)["success"] is True

    assert cli.user_json("forum", "new-page")["success"] is True
    title = f"CLI Forum {unique_suffix}"
    created = cli.user_json("forum", "new", "--title", title, "--content", "created by e2e")
    assert created["success"] is True
    thread_id = find_forum_thread_id(cli, title)

    forum_list = cli.user_json("forum", "list")
    assert any(thread["title"] == title for thread in forum_list["threads"])
    assert cli.user_json("forum", "thread", str(thread_id))["thread"]["title"] == title
    assert cli.user_json("forum", "reply", str(thread_id), "--content", "reply by user")["success"] is True
    assert cli.user_json("forum", "reply-thread", str(thread_id), "--content", "reply on thread")["success"] is True

    assert cli.admin_json("forum", "new-page")["success"] is True
    admin_forum_list = cli.admin_json("forum", "list")
    assert any(thread["title"] == title for thread in admin_forum_list["threads"])
    assert cli.admin_json("forum", "reply", str(thread_id), "--content", "reply by admin")["success"] is True
