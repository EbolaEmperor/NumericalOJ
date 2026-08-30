#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lean 4 题目版本与提交工作区的数据库服务。"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.oj_modules.infrastructure.mysql import get_db_connection
from backend.oj_modules.problems.lean_package import (
    MAX_LEAN_FILE_BYTES,
    MAX_LEAN_TOTAL_BYTES,
    LeanPackage,
)


class LeanWorkspaceError(ValueError):
    """Lean 工作区请求无效。"""


class LeanWorkspaceStaleError(LeanWorkspaceError):
    """客户端所编辑的题目包已不是当前版本。"""


def _json_object(value: Any) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise LeanWorkspaceError("Lean 工作区 manifest 已损坏") from exc
    if not isinstance(parsed, dict):
        raise LeanWorkspaceError("Lean 工作区 manifest 已损坏")
    return parsed


def _workspace_from_rows(revision: dict, rows: list[dict]) -> dict:
    manifest = _json_object(revision.get("manifest_json"))
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        raise LeanWorkspaceError("Lean 工作区验证配置已损坏")
    files = [
        {
            "path": str(row.get("relative_path") or ""),
            "mode": str(row.get("access_mode") or ""),
            "build_order": int(row.get("order_index") or 0),
            "content": str(row.get("content") or ""),
            "content_sha256": str(row.get("content_sha256") or ""),
            "size_bytes": int(row.get("size_bytes") or 0),
        }
        for row in rows
    ]
    files.sort(key=lambda item: item["build_order"])
    return {
        "revision_id": int(revision["id"]),
        "revision_number": int(revision.get("revision_number") or 0),
        "revision": str(revision.get("package_sha256") or ""),
        "schema_version": int(revision.get("schema_version") or 1),
        "default_file": str(revision.get("default_file") or ""),
        "verification": dict(verification),
        "files": files,
        "created_at": revision.get("created_at"),
    }


def _load_revision_with_cursor(cursor, *, revision_id: int | None = None, problem_id: int | None = None):
    if revision_id is not None:
        cursor.execute(
            """SELECT * FROM lean_problem_revisions WHERE id=%s""",
            (int(revision_id),),
        )
    elif problem_id is not None:
        cursor.execute(
            """SELECT * FROM lean_problem_revisions
               WHERE problem_id=%s ORDER BY revision_number DESC LIMIT 1""",
            (int(problem_id),),
        )
    else:
        raise ValueError("revision_id or problem_id is required")
    revision = cursor.fetchone()
    if not revision:
        return None
    cursor.execute(
        """SELECT relative_path, access_mode, order_index, content,
                  content_sha256, size_bytes
           FROM lean_problem_revision_files
           WHERE revision_id=%s ORDER BY order_index""",
        (revision["id"],),
    )
    rows = list(cursor.fetchall() or [])
    if len(rows) != int(revision.get("file_count") or 0):
        raise LeanWorkspaceError("Lean 工作区文件记录不完整")
    return _workspace_from_rows(revision, rows)


def get_current_lean_workspace(problem_id: int) -> dict | None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            return _load_revision_with_cursor(cursor, problem_id=int(problem_id))
    finally:
        conn.close()


def get_lean_workspace_revision(revision_id: int) -> dict | None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            return _load_revision_with_cursor(cursor, revision_id=int(revision_id))
    finally:
        conn.close()


def insert_problem_revision_with_cursor(
    cursor,
    *,
    problem_id: int,
    package: LeanPackage,
    created_by_user_id: int | None,
) -> tuple[int, bool]:
    """锁住题目并发布一个不可变版本；相同当前内容保持幂等。"""

    cursor.execute(
        "SELECT id, type, lang FROM problems WHERE id=%s FOR UPDATE",
        (int(problem_id),),
    )
    problem = cursor.fetchone()
    if not problem:
        raise LookupError("题目不存在")
    if int(problem.get("type") or 0) != 1 or str(problem.get("lang") or "").lower() not in {"lean", "lean4"}:
        raise LeanWorkspaceError("只有 Lean 4 编程题可以上传 Lean 工作区")

    cursor.execute(
        """SELECT id, revision_number, package_sha256
           FROM lean_problem_revisions
           WHERE problem_id=%s ORDER BY revision_number DESC LIMIT 1""",
        (int(problem_id),),
    )
    current = cursor.fetchone()
    if current and str(current.get("package_sha256") or "") == package.package_sha256:
        return int(current["id"]), False
    revision_number = int((current or {}).get("revision_number") or 0) + 1
    manifest_json = json.dumps(
        package.manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    cursor.execute(
        """INSERT INTO lean_problem_revisions
           (problem_id, revision_number, schema_version, default_file,
            manifest_json, package_sha256, file_count, total_size,
            created_by_user_id)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (
            int(problem_id),
            revision_number,
            package.schema_version,
            package.default_file,
            manifest_json,
            package.package_sha256,
            len(package.files),
            package.total_size,
            int(created_by_user_id) if created_by_user_id is not None else None,
        ),
    )
    revision_id = int(cursor.lastrowid)
    cursor.executemany(
        """INSERT INTO lean_problem_revision_files
           (revision_id, relative_path, access_mode, order_index, content,
            content_sha256, size_bytes)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        [
            (
                revision_id,
                item.path,
                item.mode,
                item.order,
                item.content,
                item.content_sha256,
                item.size_bytes,
            )
            for item in package.files
        ],
    )
    return revision_id, True


def create_problem_revision(
    *, problem_id: int, package: LeanPackage, created_by_user_id: int | None
) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            revision_id, created = insert_problem_revision_with_cursor(
                cursor,
                problem_id=int(problem_id),
                package=package,
                created_by_user_id=created_by_user_id,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    workspace = get_lean_workspace_revision(revision_id)
    assert workspace is not None
    workspace["created"] = created
    return workspace


def _normalize_submitted_files(workspace: dict, raw_files: object) -> dict[str, str]:
    if not isinstance(raw_files, dict):
        raise LeanWorkspaceError("Lean 提交的 files 必须是 JSON 对象")
    expected = {
        str(item.get("path") or "")
        for item in workspace.get("files") or []
        if item.get("mode") == "writable"
    }
    received = set(raw_files)
    if received != expected:
        missing = sorted(expected.difference(received))
        extra = sorted(received.difference(expected))
        details = []
        if missing:
            details.append("缺少 " + ", ".join(missing))
        if extra:
            details.append("包含不可提交文件 " + ", ".join(extra))
        raise LeanWorkspaceError("Lean 提交文件集合不正确：" + "；".join(details))
    normalized: dict[str, str] = {}
    total_size = sum(
        int(item.get("size_bytes") or 0)
        for item in workspace.get("files") or []
        if item.get("mode") == "readonly"
    )
    for path in sorted(expected):
        content = raw_files[path]
        if not isinstance(content, str):
            raise LeanWorkspaceError(f"Lean 文件内容必须是字符串：{path}")
        size = len(content.encode("utf-8"))
        if size > MAX_LEAN_FILE_BYTES:
            raise LeanWorkspaceError(f"Lean 文件超过 1 MiB：{path}")
        total_size += size
        if total_size > MAX_LEAN_TOTAL_BYTES:
            raise LeanWorkspaceError("Lean 工作区源码总大小超过 8 MiB")
        normalized[path] = content
    return normalized


def normalize_lean_submission_payload(
    *, problem_id: int, revision: object, files: object
) -> tuple[dict, dict[str, str]]:
    workspace = get_current_lean_workspace(int(problem_id))
    if not workspace:
        raise LeanWorkspaceError("该 Lean 4 题尚未配置工作区")
    revision_text = str(revision or "").strip()
    if revision_text != workspace["revision"]:
        raise LeanWorkspaceStaleError("题目文件已经更新，请刷新页面后重新提交")
    return workspace, _normalize_submitted_files(workspace, files)


def _source_digest(files: dict[str, str]) -> str:
    payload = [
        {
            "path": path,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for path, content in sorted(files.items())
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def bind_submission_workspace_with_cursor(
    cursor,
    *,
    submission_id: int,
    problem_id: int,
    revision: str,
    files: object,
) -> dict[str, str]:
    """在 submissions INSERT 的同一事务内绑定当前题目版本。"""

    cursor.execute(
        "SELECT id FROM problems WHERE id=%s FOR SHARE",
        (int(problem_id),),
    )
    if not cursor.fetchone():
        raise LookupError("题目不存在")
    cursor.execute(
        """SELECT * FROM lean_problem_revisions
           WHERE problem_id=%s ORDER BY revision_number DESC LIMIT 1""",
        (int(problem_id),),
    )
    revision_row = cursor.fetchone()
    if not revision_row:
        raise LeanWorkspaceError("该 Lean 4 题尚未配置工作区")
    if str(revision_row.get("package_sha256") or "") != str(revision or ""):
        raise LeanWorkspaceStaleError("题目文件已经更新，请刷新页面后重新提交")
    cursor.execute(
        """SELECT relative_path, access_mode, order_index, content,
                  content_sha256, size_bytes
           FROM lean_problem_revision_files
           WHERE revision_id=%s ORDER BY order_index""",
        (revision_row["id"],),
    )
    file_rows = list(cursor.fetchall() or [])
    workspace = _workspace_from_rows(revision_row, file_rows)
    normalized = _normalize_submitted_files(workspace, files)
    total_size = sum(len(value.encode("utf-8")) for value in normalized.values())
    cursor.execute(
        """INSERT INTO lean_submission_workspaces
           (submission_id, problem_revision_id, source_sha256, file_count,
            total_size)
           VALUES (%s,%s,%s,%s,%s)""",
        (
            int(submission_id),
            int(revision_row["id"]),
            _source_digest(normalized),
            len(normalized),
            total_size,
        ),
    )
    cursor.executemany(
        """INSERT INTO lean_submission_files
           (submission_id, relative_path, content, content_sha256, size_bytes)
           VALUES (%s,%s,%s,%s,%s)""",
        [
            (
                int(submission_id),
                path,
                content,
                hashlib.sha256(content.encode("utf-8")).hexdigest(),
                len(content.encode("utf-8")),
            )
            for path, content in sorted(normalized.items())
        ],
    )
    return normalized


def get_submission_lean_workspace(submission_id: int) -> dict | None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT problem_revision_id
                   FROM lean_submission_workspaces WHERE submission_id=%s""",
                (int(submission_id),),
            )
            binding = cursor.fetchone()
            if not binding:
                return None
            workspace = _load_revision_with_cursor(
                cursor, revision_id=int(binding["problem_revision_id"])
            )
            assert workspace is not None
            cursor.execute(
                """SELECT relative_path, content FROM lean_submission_files
                   WHERE submission_id=%s ORDER BY relative_path""",
                (int(submission_id),),
            )
            submitted = {
                str(row["relative_path"]): str(row.get("content") or "")
                for row in cursor.fetchall() or []
            }
            for item in workspace["files"]:
                if item["mode"] == "writable":
                    if item["path"] not in submitted:
                        raise LeanWorkspaceError("Lean 提交文件记录不完整")
                    item["content"] = submitted[item["path"]]
            workspace["submission_id"] = int(submission_id)
            workspace["submitted_files"] = submitted
            return workspace
    finally:
        conn.close()


def get_latest_submission_lean_workspace(
    *, username: str, problem_id: int
) -> dict | None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT s.id
                   FROM submissions s
                   JOIN lean_submission_workspaces lsw ON lsw.submission_id=s.id
                   WHERE s.username=%s AND s.problem_id=%s
                   ORDER BY s.id DESC LIMIT 1""",
                (str(username), int(problem_id)),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return get_submission_lean_workspace(int(row["id"]))


def merge_workspace_sources(workspace: dict, writable_files: dict[str, str]) -> dict[str, str]:
    """把服务端只读文件与已经校验的可写内容合成完整源码树。"""

    return {
        item["path"]: (
            writable_files[item["path"]]
            if item["mode"] == "writable"
            else str(item.get("content") or "")
        )
        for item in workspace.get("files") or []
    }


__all__ = [
    "LeanWorkspaceError",
    "LeanWorkspaceStaleError",
    "bind_submission_workspace_with_cursor",
    "create_problem_revision",
    "get_current_lean_workspace",
    "get_latest_submission_lean_workspace",
    "get_lean_workspace_revision",
    "get_submission_lean_workspace",
    "insert_problem_revision_with_cursor",
    "merge_workspace_sources",
    "normalize_lean_submission_payload",
]
