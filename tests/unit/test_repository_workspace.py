#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from oj_modules import judger_core
from oj_modules.repository.workspace import (
    InvalidRepositoryPath,
    materialize_repository_tree,
    normalize_repository_relative_path,
)


def test_repository_relative_path_preserves_directories_and_unicode():
    assert normalize_repository_relative_path("include/数值 工具/vector.ipp") == (
        "include/数值 工具/vector.ipp"
    )
    assert normalize_repository_relative_path(" leading/name.h") == " leading/name.h"


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "../secret.h",
        "include/../secret.h",
        "include//secret.h",
        "include\\secret.h",
        "include/trailing ",
        "include/trailing.",
        "CON/file.h",
    ],
)
def test_repository_relative_path_rejects_unsafe_paths(path):
    with pytest.raises(InvalidRepositoryPath):
        normalize_repository_relative_path(path)


def test_materialize_repository_tree_keeps_empty_dirs_and_duplicate_basenames(tmp_path):
    created = materialize_repository_tree(
        tmp_path,
        [
            {"relative_path": "empty", "entry_type": "directory"},
            {"relative_path": "a/common.h", "entry_type": "file", "content": "A"},
            {"relative_path": "b/common.h", "entry_type": "file", "content": "B"},
            {"relative_path": "notes/read me.txt", "entry_type": "file", "content": "中文"},
        ],
    )

    root = tmp_path / "repository"
    assert (root / "empty").is_dir()
    assert (root / "a" / "common.h").read_text(encoding="utf-8") == "A"
    assert (root / "b" / "common.h").read_text(encoding="utf-8") == "B"
    assert (root / "notes" / "read me.txt").read_text(encoding="utf-8") == "中文"
    assert created == ["empty", "a/common.h", "b/common.h", "notes/read me.txt"]


def test_materialize_repository_tree_replaces_stale_subtree(tmp_path):
    stale_root = tmp_path / "repository"
    stale_root.mkdir()
    (stale_root / "stale.h").write_text("old", encoding="utf-8")

    materialize_repository_tree(
        tmp_path,
        {"fresh/path.h": "new"},
    )

    assert not (stale_root / "stale.h").exists()
    assert (stale_root / "fresh" / "path.h").read_text(encoding="utf-8") == "new"


def test_judger_compile_uses_repository_include_root_without_compiling_repo_sources(monkeypatch):
    monkeypatch.setenv("JUDGER_NUMERIC_BACKEND", "none")
    command = judger_core.build_compile_cmd("cpp")

    repository_flag = command.index("/sandbox/repository")
    shared_flag = command.index("/opt/library")
    assert repository_flag < shared_flag
    assert "main.cpp" in command
    assert not any(
        value.startswith("/sandbox/repository/") and value.endswith((".c", ".cpp"))
        for value in command
    )


def test_judger_writes_repository_under_isolated_subroot(tmp_path):
    judger_core._write_user_files(
        str(tmp_path),
        [
            {"relative_path": "lib/detail/helper.inc", "entry_type": "file", "content": "x"},
            {"relative_path": "empty", "entry_type": "directory"},
        ],
    )

    assert (tmp_path / "repository" / "lib" / "detail" / "helper.inc").is_file()
    assert (tmp_path / "repository" / "empty").is_dir()
    assert not (tmp_path / "helper.inc").exists()
