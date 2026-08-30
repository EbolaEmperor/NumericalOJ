#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""作业导出所需的学生代码仓库只读视图。"""


def get_student_repository_entries(user_id):
    from backend.oj_modules.repository.tree import get_repository_tree_snapshot

    snapshot = get_repository_tree_snapshot(int(user_id), include_content=True)
    return [
        {
            "filename": item.get("relative_path") or item.get("filename"),
            "entry_type": item.get("kind") or item.get("entry_type"),
            "content": item.get("content") or "",
        }
        for item in snapshot.get("entries") or []
    ]


def get_student_repository_files(user_id):
    return [
        item
        for item in get_student_repository_entries(user_id)
        if item.get("entry_type") == "file"
    ]


__all__ = ["get_student_repository_entries", "get_student_repository_files"]
