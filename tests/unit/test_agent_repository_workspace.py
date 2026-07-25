#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from oj_modules.repository import tree as repository_tree
from oj_modules.tasks import agent_solve_helpers


def test_agent_header_sync_preserves_paths_and_prefers_repository_subtree(
    tmp_path,
    monkeypatch,
):
    repository_root = tmp_path / "repository"
    (repository_root / "lib").mkdir(parents=True)
    (tmp_path / "new").mkdir()
    (tmp_path / "common.h").write_text("root copy", encoding="utf-8")
    (repository_root / "common.h").write_text("repository copy", encoding="utf-8")
    (repository_root / "lib" / "x.hpp").write_text("x", encoding="utf-8")
    (tmp_path / "new" / "工具.ipp").write_text("unicode", encoding="utf-8")

    writes = []
    monkeypatch.setattr(
        repository_tree,
        "get_repository_state",
        lambda _user_id: {"structure_version": 5},
    )

    def fake_upsert(
        user_id,
        relative_path,
        content,
        *,
        expected_structure_version,
        overwrite,
    ):
        writes.append({
            "user_id": user_id,
            "path": relative_path,
            "content": content,
            "expected_structure_version": expected_structure_version,
            "overwrite": overwrite,
        })
        return {"structure_version": expected_structure_version + 1}

    monkeypatch.setattr(
        repository_tree,
        "upsert_repository_file_by_path",
        fake_upsert,
    )

    result = agent_solve_helpers._tool_sync_workspace_headers_to_repository(
        17,
        str(tmp_path),
    )

    assert [(item["path"], item["content"]) for item in writes] == [
        ("common.h", "repository copy"),
        ("lib/x.hpp", "x"),
        ("new/工具.ipp", "unicode"),
    ]
    assert [item["expected_structure_version"] for item in writes] == [5, 6, 7]
    assert all(item["overwrite"] is True for item in writes)
    assert result["structure_version"] == 8
    assert any(
        item["filename"] == "common.h" and "仓库子树版本" in item["reason"]
        for item in result["skipped_files"]
    )
