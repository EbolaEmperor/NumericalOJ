#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from oj_modules.repository.storage import RepositoryPathError, validate_relative_path


def extract_includes_from_code(code):
    """
    从代码中提取双引号形式的仓库 include 路径。

    不按扩展名筛选（仓库允许 .inc/.ipp/.tpp 等任意文本文件）；尖括号系统头
    不属于用户仓库。路径安全校验由读取函数统一执行。
    """
    pattern = r'^[ \t]*#[ \t]*include[ \t]*"([^"\r\n]+)"'
    matches = re.findall(pattern, str(code or ""), flags=re.MULTILINE)
    return matches


def get_user_repository_files_by_names(user_id, filenames, submission_id=None):
    """
    根据文件名列表获取用户代码仓库中的文件内容
    返回 {filename: content} 字典

    ``submission_id`` 存在时优先读取该提交的不可变快照。只有显式迁移边界内、
    本来就不可能拥有快照的历史提交，才由统一 helper 记录警告并兼容实时仓库；
    边界后的新提交缺少快照仍然 fail-closed。
    """
    if not filenames:
        return {}

    requested = []
    for filename in filenames:
        try:
            path = validate_relative_path(filename)
        except RepositoryPathError:
            continue
        if path not in requested:
            requested.append(path)
    if not requested:
        return {}

    if submission_id is not None:
        from oj_modules.submissions.repository_snapshots import (
            load_submission_repository_files,
        )
        files = load_submission_repository_files(
            int(submission_id),
            int(user_id),
            allow_legacy_fallback=True,
        )
    else:
        from oj_modules.repository.tree import list_repository_files
        files = list_repository_files(int(user_id), include_content=True)

    by_path = {
        str(item.get("relative_path") or item.get("filename") or ""):
        str(item.get("content") or item.get("file_content") or "")
        for item in files
    }
    return {path: by_path[path] for path in requested if path in by_path}
