#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""讨论区的数据访问、事务与公开序列化。

匿名只是一种公开展示身份：作者的真实 ``user_id`` 始终留在数据库中用于权限判断，
但本模块返回给 HTTP 层的对象只经过显式白名单序列化，绝不暴露作者 ID、匿名身份记录
ID 或两者之间的映射。
"""

from __future__ import annotations

import html
import math
import re
import secrets
from dataclasses import dataclass
from typing import Any

import pymysql
from pygments.formatters import HtmlFormatter

from oj_modules.db_services import get_db_connection
from oj_modules.forum_identity_services import avatar_presentation, resolve_posting_identity
from oj_modules.idempotency_utils import (
    InvalidClientRequestId,
    normalize_client_request_id as _normalize_client_request_id,
    request_fingerprint,
)
from oj_modules.markdown_utils import render_markdown, sanitize_html


DEFAULT_PAGE_SIZE = 30
MAX_PAGE_SIZE = 100
DEFAULT_REPLY_PAGE_SIZE = 50
MAX_REPLY_PAGE_SIZE = 100
MAX_TITLE_LENGTH = 255
MAX_CONTENT_LENGTH = 100_000

_MARKDOWN_EXTENSIONS = [
    "extra",
    "fenced_code",
    "codehilite",
    "tables",
    "sane_lists",
]
_LANGUAGE_CLASS_RE = re.compile(r"^language-[A-Za-z0-9_+#.-]+$")
_FENCE_OPEN_RE = re.compile(r"^[ ]{0,3}(?P<fence>`{3,}|~{3,})")
_WHITESPACE_RE = re.compile(r"\s+")
_MATH_RE = re.compile(
    r"(?s)"
    r"(\$\$.*?\$\$"
    r"|\\\[.*?\\\]"
    r"|\\\(.*?\\\)"
    r"|(?<!\$)\$(?!\$)(?:\\.|[^$\n])+?(?<!\\)\$(?!\$))"
)


class _ForumCodeHtmlFormatter(HtmlFormatter):
    """保留 fenced code 的语言类，供样式、Mermaid 与自动化测试识别。"""

    def __init__(self, **options):
        language_class = str(options.get("lang_str") or "").strip()
        if _LANGUAGE_CLASS_RE.fullmatch(language_class):
            css_class = str(options.get("cssclass") or "codehilite").strip()
            options["cssclass"] = f"{css_class} {language_class.lower()}"
        super().__init__(**options)


_MARKDOWN_EXTENSION_CONFIGS = {
    "codehilite": {
        "css_class": "codehilite",
        "guess_lang": False,
        "linenums": False,
        "noclasses": False,
        "pygments_formatter": _ForumCodeHtmlFormatter,
        "pygments_style": "github-dark",
        "use_pygments": True,
    },
}


class ForumError(Exception):
    """讨论区可安全展示给调用者的领域错误。"""

    status_code = 400

    def __init__(self, message: str, **payload: Any):
        super().__init__(message)
        self.message = message
        self.payload = payload


class ForumNotFoundError(ForumError):
    status_code = 404


class ForumPermissionError(ForumError):
    status_code = 403


class ForumConflictError(ForumError):
    status_code = 409


class ForumValidationError(ForumError):
    status_code = 400


@dataclass(frozen=True)
class Page:
    number: int
    limit: int

    @property
    def offset(self) -> int:
        return (self.number - 1) * self.limit


def parse_page(page: Any, limit: Any, *, default_limit: int = DEFAULT_PAGE_SIZE) -> Page:
    try:
        page_number = int(page)
    except (TypeError, ValueError):
        page_number = 1
    try:
        page_limit = int(limit)
    except (TypeError, ValueError):
        page_limit = default_limit
    return Page(max(1, page_number), min(MAX_PAGE_SIZE, max(1, page_limit)))


def parse_reply_limit(limit: Any) -> int:
    try:
        parsed = int(limit)
    except (TypeError, ValueError):
        parsed = DEFAULT_REPLY_PAGE_SIZE
    return min(MAX_REPLY_PAGE_SIZE, max(1, parsed))


def normalize_client_request_id(value: Any) -> str:
    """校验并规范化幂等键。

    客户端使用 ``crypto.randomUUID()`` / ``uuid.uuid4()`` 生成键；服务端接受所有
    RFC 4122 UUID 版本，统一保存为小写连字符形式。
    """

    try:
        return _normalize_client_request_id(value)
    except InvalidClientRequestId as exc:
        raise ForumValidationError(str(exc)) from exc


def validate_title(value: Any) -> str:
    title = str(value or "").strip()
    if not title:
        raise ForumValidationError("标题不能为空")
    if len(title) > MAX_TITLE_LENGTH:
        raise ForumValidationError(f"标题不能超过 {MAX_TITLE_LENGTH} 个字符")
    return title


def validate_content(value: Any) -> str:
    content = str(value or "").strip()
    if not content:
        raise ForumValidationError("内容不能为空")
    if len(content) > MAX_CONTENT_LENGTH:
        raise ForumValidationError(f"内容不能超过 {MAX_CONTENT_LENGTH} 个字符")
    return content


def validate_edit_version(value: Any) -> int:
    try:
        version = int(value)
    except (TypeError, ValueError) as exc:
        raise ForumValidationError("edit_version 必须是正整数") from exc
    if version < 1:
        raise ForumValidationError("edit_version 必须是正整数")
    return version


def _replace_math_outside_fences(raw: str, replacer) -> str:
    """只保护正文公式，避免把 Bash/PHP 等代码里的 ``$`` 当成 LaTeX。"""

    output: list[str] = []
    prose: list[str] = []
    closing_fence = None

    def flush_prose() -> None:
        if prose:
            output.append(_MATH_RE.sub(replacer, "".join(prose)))
            prose.clear()

    for line in raw.splitlines(keepends=True):
        line_without_ending = line.rstrip("\r\n")
        if closing_fence is None:
            opening = _FENCE_OPEN_RE.match(line_without_ending)
            if opening is None:
                prose.append(line)
                continue
            flush_prose()
            fence = opening.group("fence")
            closing_fence = re.compile(
                rf"^[ ]{{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$"
            )
            output.append(line)
            continue

        output.append(line)
        if closing_fence.fullmatch(line_without_ending):
            closing_fence = None

    flush_prose()
    return "".join(output)


def render_forum_markdown(content: Any) -> str:
    # LaTeX 的 ``\(...\)`` / ``\[...\]`` 会被 Markdown 当作普通反斜杠转义而吃掉
    # 分隔符；渲染前先以不可预测占位符保护，恢复时对公式正文做 HTML 转义。
    raw = str(content or "")
    token_prefix = f"NUMOJFORUMMATH{secrets.token_hex(8)}"
    protected: dict[str, str] = {}

    def protect_math(match):
        token = f"{token_prefix}{len(protected)}TOKEN"
        protected[token] = html.escape(match.group(0), quote=False)
        return token

    markdown_source = _replace_math_outside_fences(raw, protect_math)
    rendered = render_markdown(
        markdown_source,
        extensions=_MARKDOWN_EXTENSIONS,
        extension_configs=_MARKDOWN_EXTENSION_CONFIGS,
    )
    for token, formula in protected.items():
        rendered = rendered.replace(token, formula)
    # 占位符必须在最终一次 HTML 清洗之前恢复；否则公式若出现在链接属性中，
    # 恢复出的引号可能绕过第一次清洗并重新形成事件属性。
    return sanitize_html(rendered)


def _public_excerpt(content: Any, length: int = 150) -> str:
    compact = _WHITESPACE_RE.sub(" ", str(content or "")).strip()
    if len(compact) <= length:
        return compact
    return f"{compact[:length].rstrip()}…"


def _public_author(row: dict, viewer_user_id: int) -> dict:
    display_name = str(row.get("display_name") or "未知用户")
    return {
        "display_name": display_name,
        "is_anonymous": bool(row.get("anonymous_identity_id")),
        "avatar": avatar_presentation(display_name),
        "is_owner": int(row.get("author_user_id") or 0) == int(viewer_user_id or 0),
    }


def serialize_thread(row: dict, viewer_user_id: int, *, include_content: bool) -> dict:
    """把内部主题行转换成公开 DTO；该白名单是隐私边界。"""

    out = {
        "id": row.get("id"),
        "title": row.get("title") or "",
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "last_activity_at": row.get("last_activity_at") or row.get("created_at"),
        "reply_count": int(row.get("reply_count") or 0),
        "edit_version": int(row.get("edit_version") or 1),
        "is_edited": int(row.get("edit_version") or 1) > 1,
        "url": f"/forum/thread/{row.get('id')}",
    }
    out.update(_public_author(row, viewer_user_id))
    if include_content:
        content = str(row.get("content") or "")
        out["content"] = content
        out["rendered_content"] = render_forum_markdown(content)
    else:
        matching_reply = row.get("matching_reply_content")
        if matching_reply is not None:
            out["excerpt"] = _public_excerpt(matching_reply)
            out["match_source"] = "reply"
        else:
            out["excerpt"] = _public_excerpt(row.get("content"))
            out["match_source"] = "thread"
    return out


def serialize_reply(row: dict, viewer_user_id: int) -> dict:
    """把内部回复行转换成公开 DTO；不返回 ``thread_id`` 以外的关联键。"""

    content = str(row.get("content") or "")
    out = {
        "id": row.get("id"),
        "thread_id": row.get("thread_id"),
        "content": content,
        "rendered_content": render_forum_markdown(content),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "edit_version": int(row.get("edit_version") or 1),
        "is_edited": int(row.get("edit_version") or 1) > 1,
    }
    out.update(_public_author(row, viewer_user_id))
    return out


def _like_pattern(query: str) -> str:
    escaped = str(query or "").replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _list_where(scope: str, query: str, viewer_user_id: int) -> tuple[str, list]:
    clauses = []
    params: list[Any] = []

    if scope == "mine":
        clauses.append(
            """
            (
              t.user_id = %s
              OR EXISTS (
                SELECT 1
                FROM forum_replies mine_reply
                WHERE mine_reply.thread_id = t.id
                  AND mine_reply.user_id = %s
              )
            )
            """
        )
        params.extend((viewer_user_id, viewer_user_id))
    elif scope != "all":
        raise ForumValidationError("scope 只能是 all 或 mine")

    normalized_query = str(query or "").strip()
    if len(normalized_query) > 100:
        raise ForumValidationError("搜索关键词不能超过 100 个字符")
    if normalized_query:
        pattern = _like_pattern(normalized_query)
        clauses.append(
            """
            (
              t.title LIKE %s ESCAPE '\\\\'
              OR t.content LIKE %s ESCAPE '\\\\'
              OR (
                t.anonymous_identity_id IS NULL
                AND thread_user.username LIKE %s ESCAPE '\\\\'
              )
              OR (
                t.anonymous_identity_id IS NOT NULL
                AND thread_identity.display_name LIKE %s ESCAPE '\\\\'
              )
              OR EXISTS (
                SELECT 1
                FROM forum_replies search_reply
                JOIN users search_user ON search_user.id = search_reply.user_id
                LEFT JOIN forum_anonymous_identities search_identity
                  ON search_identity.id = search_reply.anonymous_identity_id
                 AND search_identity.user_id = search_reply.user_id
                WHERE search_reply.thread_id = t.id
                  AND (
                    search_reply.content LIKE %s ESCAPE '\\\\'
                    OR (
                      search_reply.anonymous_identity_id IS NULL
                      AND search_user.username LIKE %s ESCAPE '\\\\'
                    )
                    OR (
                      search_reply.anonymous_identity_id IS NOT NULL
                      AND search_identity.display_name LIKE %s ESCAPE '\\\\'
                    )
                  )
              )
            )
            """
        )
        params.extend((pattern,) * 7)

    if not clauses:
        return "", params
    return " WHERE " + " AND ".join(f"({clause.strip()})" for clause in clauses), params


def _matching_reply_select(query: str) -> tuple[str, list]:
    normalized_query = str(query or "").strip()
    if not normalized_query:
        return "NULL AS matching_reply_content", []
    pattern = _like_pattern(normalized_query)
    return (
        """
        (
          SELECT matching_reply.content
          FROM forum_replies matching_reply
          JOIN users matching_user ON matching_user.id = matching_reply.user_id
          LEFT JOIN forum_anonymous_identities matching_identity
            ON matching_identity.id = matching_reply.anonymous_identity_id
           AND matching_identity.user_id = matching_reply.user_id
          WHERE matching_reply.thread_id = t.id
            AND (
              matching_reply.content LIKE %s ESCAPE '\\\\'
              OR (
                matching_reply.anonymous_identity_id IS NULL
                AND matching_user.username LIKE %s ESCAPE '\\\\'
              )
              OR (
                matching_reply.anonymous_identity_id IS NOT NULL
                AND matching_identity.display_name LIKE %s ESCAPE '\\\\'
              )
            )
          ORDER BY matching_reply.created_at DESC, matching_reply.id DESC
          LIMIT 1
        ) AS matching_reply_content
        """,
        [pattern, pattern, pattern],
    )


def list_threads(
    viewer_user_id: int,
    *,
    scope: str = "all",
    query: str = "",
    page: Any = 1,
    limit: Any = DEFAULT_PAGE_SIZE,
) -> dict:
    page_spec = parse_page(page, limit)
    where_sql, where_params = _list_where(str(scope or "all"), str(query or ""), viewer_user_id)
    matching_reply_sql, matching_reply_params = _matching_reply_select(query)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM forum_threads t
                JOIN users thread_user ON thread_user.id = t.user_id
                LEFT JOIN forum_anonymous_identities thread_identity
                  ON thread_identity.id = t.anonymous_identity_id
                 AND thread_identity.user_id = t.user_id
                {where_sql}
                """,
                tuple(where_params),
            )
            total = int((cursor.fetchone() or {}).get("total") or 0)
            cursor.execute("SELECT COUNT(*) AS total_replies FROM forum_replies")
            total_replies = int(
                (cursor.fetchone() or {}).get("total_replies") or 0
            )
            cursor.execute(
                f"""
                SELECT
                  t.id,
                  t.title,
                  t.content,
                  t.created_at,
                  t.updated_at,
                  t.edit_version,
                  t.user_id AS author_user_id,
                  t.anonymous_identity_id,
                  CASE
                    WHEN t.anonymous_identity_id IS NULL THEN thread_user.username
                    ELSE thread_identity.display_name
                  END AS display_name,
                  {matching_reply_sql},
                  (
                    SELECT COUNT(*)
                    FROM forum_replies reply_count
                    WHERE reply_count.thread_id = t.id
                  ) AS reply_count,
                  COALESCE(
                    (
                      SELECT MAX(last_reply.created_at)
                      FROM forum_replies last_reply
                      WHERE last_reply.thread_id = t.id
                    ),
                    t.created_at
                  ) AS last_activity_at
                FROM forum_threads t
                JOIN users thread_user ON thread_user.id = t.user_id
                LEFT JOIN forum_anonymous_identities thread_identity
                  ON thread_identity.id = t.anonymous_identity_id
                 AND thread_identity.user_id = t.user_id
                {where_sql}
                ORDER BY last_activity_at DESC, t.id DESC
                LIMIT %s OFFSET %s
                """,
                tuple([
                    *matching_reply_params,
                    *where_params,
                    page_spec.limit,
                    page_spec.offset,
                ]),
            )
            rows = cursor.fetchall() or []
    finally:
        conn.close()

    return {
        "threads": [
            serialize_thread(dict(row), viewer_user_id, include_content=False)
            for row in rows
        ],
        "count": len(rows),
        "total": total,
        "total_replies": total_replies,
        "page": page_spec.number,
        "limit": page_spec.limit,
        "total_pages": math.ceil(total / page_spec.limit) if total else 0,
    }


_THREAD_SELECT = """
    SELECT
      t.id,
      t.title,
      t.content,
      t.created_at,
      t.updated_at,
      t.edit_version,
      t.user_id AS author_user_id,
      t.anonymous_identity_id,
      CASE
        WHEN t.anonymous_identity_id IS NULL THEN thread_user.username
        ELSE thread_identity.display_name
      END AS display_name,
      (
        SELECT COUNT(*)
        FROM forum_replies reply_count
        WHERE reply_count.thread_id = t.id
      ) AS reply_count,
      COALESCE(
        (
          SELECT MAX(last_reply.created_at)
          FROM forum_replies last_reply
          WHERE last_reply.thread_id = t.id
        ),
        t.created_at
      ) AS last_activity_at
    FROM forum_threads t
    JOIN users thread_user ON thread_user.id = t.user_id
    LEFT JOIN forum_anonymous_identities thread_identity
      ON thread_identity.id = t.anonymous_identity_id
     AND thread_identity.user_id = t.user_id
    WHERE t.id = %s
"""

_REPLY_SELECT_BASE = """
    SELECT
      r.id,
      r.thread_id,
      r.content,
      r.created_at,
      r.updated_at,
      r.edit_version,
      r.user_id AS author_user_id,
      r.anonymous_identity_id,
      CASE
        WHEN r.anonymous_identity_id IS NULL THEN reply_user.username
        ELSE reply_identity.display_name
      END AS display_name
    FROM forum_replies r
    JOIN users reply_user ON reply_user.id = r.user_id
    LEFT JOIN forum_anonymous_identities reply_identity
      ON reply_identity.id = r.anonymous_identity_id
     AND reply_identity.user_id = r.user_id
"""


def _fetch_thread_row(cursor, thread_id: int) -> dict | None:
    cursor.execute(_THREAD_SELECT, (thread_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def _reply_page_with_cursor(cursor, thread_id: int, *, before: int | None, limit: int) -> tuple[list, bool, int | None]:
    conditions = ["r.thread_id = %s"]
    params: list[Any] = [thread_id]
    if before is not None:
        cursor.execute(
            """
            SELECT created_at
            FROM forum_replies
            WHERE id = %s AND thread_id = %s
            """,
            (before, thread_id),
        )
        anchor = cursor.fetchone()
        if not anchor:
            raise ForumValidationError("before 不是该讨论中的有效回复 ID")
        conditions.append(
            "(r.created_at < %s OR (r.created_at = %s AND r.id < %s))"
        )
        params.extend((anchor.get("created_at"), anchor.get("created_at"), before))
    cursor.execute(
        f"""
        {_REPLY_SELECT_BASE}
        WHERE {" AND ".join(conditions)}
        ORDER BY r.created_at DESC, r.id DESC
        LIMIT %s
        """,
        tuple([*params, limit + 1]),
    )
    descending_rows = list(cursor.fetchall() or [])
    has_earlier = len(descending_rows) > limit
    selected = descending_rows[:limit]
    selected.reverse()
    before_reply_id = int(selected[0]["id"]) if selected and has_earlier else None
    return selected, has_earlier, before_reply_id


def get_thread_detail(viewer_user_id: int, thread_id: int, *, reply_limit: Any = DEFAULT_REPLY_PAGE_SIZE) -> dict:
    limit = parse_reply_limit(reply_limit)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            thread = _fetch_thread_row(cursor, thread_id)
            if not thread:
                raise ForumNotFoundError("帖子不存在")
            replies, has_earlier, before_reply_id = _reply_page_with_cursor(
                cursor,
                thread_id,
                before=None,
                limit=limit,
            )
    finally:
        conn.close()

    return {
        "thread": serialize_thread(thread, viewer_user_id, include_content=True),
        "replies": [serialize_reply(dict(row), viewer_user_id) for row in replies],
        "reply_count": int(thread.get("reply_count") or 0),
        "has_earlier_replies": has_earlier,
        "before_reply_id": before_reply_id,
    }


def get_replies_before(
    viewer_user_id: int,
    thread_id: int,
    *,
    before: Any,
    limit: Any = DEFAULT_REPLY_PAGE_SIZE,
) -> dict:
    try:
        before_id = int(before)
    except (TypeError, ValueError) as exc:
        raise ForumValidationError("before 必须是有效的回复 ID") from exc
    if before_id < 1:
        raise ForumValidationError("before 必须是有效的回复 ID")
    page_limit = parse_reply_limit(limit)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 AS found FROM forum_threads WHERE id = %s", (thread_id,))
            if not cursor.fetchone():
                raise ForumNotFoundError("帖子不存在")
            replies, has_earlier, before_reply_id = _reply_page_with_cursor(
                cursor,
                thread_id,
                before=before_id,
                limit=page_limit,
            )
    finally:
        conn.close()

    return {
        "replies": [serialize_reply(dict(row), viewer_user_id) for row in replies],
        "count": len(replies),
        "has_earlier_replies": has_earlier,
        "before_reply_id": before_reply_id,
    }


def _existing_thread_by_request(
    cursor,
    user_id: int,
    client_request_id: str,
    *,
    for_update: bool = False,
) -> dict | None:
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        f"""
        SELECT id
        FROM forum_threads
        WHERE user_id = %s AND client_request_id = %s
        LIMIT 1{suffix}
        """,
        (user_id, client_request_id),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def _existing_reply_by_request(
    cursor,
    user_id: int,
    client_request_id: str,
    *,
    for_update: bool = False,
) -> dict | None:
    suffix = " FOR UPDATE" if for_update else ""
    cursor.execute(
        f"""
        SELECT id
        FROM forum_replies
        WHERE user_id = %s AND client_request_id = %s
        LIMIT 1{suffix}
        """,
        (user_id, client_request_id),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def _validate_create_receipt(receipt: dict, *, fingerprint: str) -> dict:
    if receipt.get("request_fingerprint") != fingerprint:
        raise ForumConflictError("该幂等键已用于另一项发布")
    if receipt.get("result_id") is None:
        raise ForumConflictError("该发布请求仍在处理中，请稍后重试")
    return receipt


def _claim_create_receipt(
    cursor,
    *,
    user_id: int,
    operation_kind: str,
    client_request_id: str,
    fingerprint: str,
) -> dict | None:
    params = (user_id, operation_kind, client_request_id)
    cursor.execute(
        """
        SELECT request_fingerprint, result_id, result_created_at
        FROM forum_create_operation_receipts
        WHERE user_id=%s
          AND operation_kind=%s
          AND client_request_id=%s
        LIMIT 1
        """,
        params,
    )
    receipt = cursor.fetchone()
    if receipt:
        return _validate_create_receipt(dict(receipt), fingerprint=fingerprint)
    try:
        cursor.execute(
            """
            INSERT INTO forum_create_operation_receipts (
              user_id,
              operation_kind,
              client_request_id,
              request_fingerprint,
              created_at
            )
            VALUES (%s, %s, %s, %s, NOW())
            """,
            (user_id, operation_kind, client_request_id, fingerprint),
        )
    except pymysql.err.IntegrityError as exc:
        if int(exc.args[0] if exc.args else 0) != 1062:
            raise
        cursor.execute(
            """
            SELECT request_fingerprint, result_id, result_created_at
            FROM forum_create_operation_receipts
            WHERE user_id=%s
              AND operation_kind=%s
              AND client_request_id=%s
            LIMIT 1
            FOR UPDATE
            """,
            params,
        )
        receipt = cursor.fetchone()
        if not receipt:
            raise
        return _validate_create_receipt(dict(receipt), fingerprint=fingerprint)
    return None


def _complete_create_receipt(
    cursor,
    *,
    user_id: int,
    operation_kind: str,
    client_request_id: str,
    result_id: int,
    result_created_at,
) -> None:
    cursor.execute(
        """
        UPDATE forum_create_operation_receipts
        SET result_id=%s,
            result_created_at=%s,
            completed_at=NOW()
        WHERE user_id=%s
          AND operation_kind=%s
          AND client_request_id=%s
          AND result_id IS NULL
        """,
        (
            result_id,
            result_created_at,
            user_id,
            operation_kind,
            client_request_id,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise RuntimeError("论坛发布幂等收据未能完成")


def _thread_result_for_create(
    user_id: int,
    thread_id: int,
    *,
    title: str,
    content: str,
    receipt: dict,
) -> dict:
    result = get_thread_detail(user_id, thread_id)["thread"]
    created_at = receipt.get("result_created_at") or result.get("created_at")
    result.update(
        title=title,
        content=content,
        rendered_content=render_forum_markdown(content),
        created_at=created_at,
        updated_at=created_at,
        last_activity_at=created_at,
        reply_count=0,
        edit_version=1,
        is_edited=False,
    )
    return result


def _reply_result_for_create(
    user_id: int,
    reply_id: int,
    *,
    content: str,
    receipt: dict,
) -> dict:
    result = get_reply(user_id, reply_id)
    created_at = receipt.get("result_created_at") or result.get("created_at")
    result.update(
        content=content,
        rendered_content=render_forum_markdown(content),
        created_at=created_at,
        updated_at=created_at,
        edit_version=1,
        is_edited=False,
    )
    return result


def create_thread(
    user_id: int,
    *,
    title: Any,
    content: Any,
    client_request_id: Any,
    expected_identity_token: Any,
    token_secret: Any,
) -> tuple[dict, bool]:
    clean_title = validate_title(title)
    clean_content = validate_content(content)
    request_id = normalize_client_request_id(client_request_id)
    identity_token = str(expected_identity_token or "").strip()
    if not identity_token:
        raise ForumValidationError("expected_identity_token 不能为空")
    fingerprint = request_fingerprint(
        {
            "title": clean_title,
            "content": clean_content,
            "expected_identity_token": identity_token,
        }
    )
    completed_receipt = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            completed_receipt = _claim_create_receipt(
                cursor,
                user_id=user_id,
                operation_kind="thread",
                client_request_id=request_id,
                fingerprint=fingerprint,
            )
            if completed_receipt is None:
                anonymous_identity_id = resolve_posting_identity(
                    cursor,
                    user_id,
                    expected_identity_token=identity_token,
                    token_secret=token_secret,
                )
                try:
                    cursor.execute(
                        """
                        INSERT INTO forum_threads (
                          title,
                          content,
                          user_id,
                          anonymous_identity_id,
                          client_request_id,
                          edit_version,
                          created_at,
                          updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, 1, NOW(), NOW())
                        """,
                        (
                            clean_title,
                            clean_content,
                            user_id,
                            anonymous_identity_id,
                            request_id,
                        ),
                    )
                    thread_id = int(cursor.lastrowid)
                except pymysql.err.IntegrityError as exc:
                    if int(exc.args[0] if exc.args else 0) != 1062:
                        raise
                    existing = _existing_thread_by_request(
                        cursor,
                        user_id,
                        request_id,
                        for_update=True,
                    )
                    if not existing:
                        raise
                    raise ForumConflictError(
                        "该历史幂等键缺少不可变操作收据，请使用新的 UUID 重试"
                    ) from exc
                cursor.execute(
                    "SELECT created_at FROM forum_threads WHERE id=%s",
                    (thread_id,),
                )
                result_created_at = (cursor.fetchone() or {}).get("created_at")
                _complete_create_receipt(
                    cursor,
                    user_id=user_id,
                    operation_kind="thread",
                    client_request_id=request_id,
                    result_id=thread_id,
                    result_created_at=result_created_at,
                )
                completed_receipt = {
                    "result_id": thread_id,
                    "result_created_at": result_created_at,
                }
                created = True
            else:
                thread_id = int(completed_receipt["result_id"])
                created = False
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return (
        _thread_result_for_create(
            user_id,
            thread_id,
            title=clean_title,
            content=clean_content,
            receipt=completed_receipt,
        ),
        created,
    )


def create_reply(
    user_id: int,
    thread_id: int,
    *,
    content: Any,
    client_request_id: Any,
    expected_identity_token: Any,
    token_secret: Any,
) -> tuple[dict, bool]:
    clean_content = validate_content(content)
    request_id = normalize_client_request_id(client_request_id)
    identity_token = str(expected_identity_token or "").strip()
    if not identity_token:
        raise ForumValidationError("expected_identity_token 不能为空")
    fingerprint = request_fingerprint(
        {
            "thread_id": int(thread_id),
            "content": clean_content,
            "expected_identity_token": identity_token,
        }
    )
    completed_receipt = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            completed_receipt = _claim_create_receipt(
                cursor,
                user_id=user_id,
                operation_kind="reply",
                client_request_id=request_id,
                fingerprint=fingerprint,
            )
            if completed_receipt is None:
                cursor.execute(
                    "SELECT id FROM forum_threads WHERE id = %s FOR UPDATE",
                    (thread_id,),
                )
                if not cursor.fetchone():
                    raise ForumNotFoundError("帖子不存在")
                anonymous_identity_id = resolve_posting_identity(
                    cursor,
                    user_id,
                    expected_identity_token=identity_token,
                    token_secret=token_secret,
                )
                try:
                    cursor.execute(
                        """
                        INSERT INTO forum_replies (
                          thread_id,
                          content,
                          user_id,
                          anonymous_identity_id,
                          client_request_id,
                          edit_version,
                          created_at,
                          updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, 1, NOW(), NOW())
                        """,
                        (
                            thread_id,
                            clean_content,
                            user_id,
                            anonymous_identity_id,
                            request_id,
                        ),
                    )
                    reply_id = int(cursor.lastrowid)
                except pymysql.err.IntegrityError as exc:
                    if int(exc.args[0] if exc.args else 0) != 1062:
                        raise
                    existing = _existing_reply_by_request(
                        cursor,
                        user_id,
                        request_id,
                        for_update=True,
                    )
                    if not existing:
                        raise
                    raise ForumConflictError(
                        "该历史幂等键缺少不可变操作收据，请使用新的 UUID 重试"
                    ) from exc
                cursor.execute(
                    "SELECT created_at FROM forum_replies WHERE id=%s",
                    (reply_id,),
                )
                result_created_at = (cursor.fetchone() or {}).get("created_at")
                _complete_create_receipt(
                    cursor,
                    user_id=user_id,
                    operation_kind="reply",
                    client_request_id=request_id,
                    result_id=reply_id,
                    result_created_at=result_created_at,
                )
                completed_receipt = {
                    "result_id": reply_id,
                    "result_created_at": result_created_at,
                }
                created = True
            else:
                reply_id = int(completed_receipt["result_id"])
                created = False
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return (
        _reply_result_for_create(
            user_id,
            reply_id,
            content=clean_content,
            receipt=completed_receipt,
        ),
        created,
    )


def get_reply(viewer_user_id: int, reply_id: int) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                {_REPLY_SELECT_BASE}
                WHERE r.id = %s
                """,
                (reply_id,),
            )
            row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        raise ForumNotFoundError("回复不存在")
    return serialize_reply(dict(row), viewer_user_id)


def count_thread_replies(thread_id: int) -> int:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS reply_count FROM forum_replies WHERE thread_id = %s",
                (thread_id,),
            )
            return int((cursor.fetchone() or {}).get("reply_count") or 0)
    finally:
        conn.close()


def _validate_edit_receipt(
    receipt: dict,
    *,
    target_id: int,
    fingerprint: str,
) -> dict:
    if (
        int(receipt.get("target_id") or 0) != int(target_id)
        or receipt.get("request_fingerprint") != fingerprint
    ):
        raise ForumConflictError("该幂等键已用于另一项编辑")
    if receipt.get("result_version") is None:
        raise ForumConflictError("该编辑请求仍在处理中，请稍后重试")
    return receipt


def _claim_edit_receipt(
    cursor,
    *,
    user_id: int,
    operation_kind: str,
    client_request_id: str,
    target_id: int,
    fingerprint: str,
) -> dict | None:
    params = (user_id, operation_kind, client_request_id)
    cursor.execute(
        """
        SELECT
          target_id,
          request_fingerprint,
          result_version,
          result_updated_at,
          result_changed
        FROM forum_edit_operation_receipts
        WHERE user_id = %s
          AND operation_kind = %s
          AND client_request_id = %s
        LIMIT 1
        """,
        params,
    )
    receipt = cursor.fetchone()
    if receipt:
        return _validate_edit_receipt(
            dict(receipt),
            target_id=target_id,
            fingerprint=fingerprint,
        )

    try:
        cursor.execute(
            """
            INSERT INTO forum_edit_operation_receipts (
              user_id,
              operation_kind,
              client_request_id,
              target_id,
              request_fingerprint,
              created_at
            )
            VALUES (%s, %s, %s, %s, %s, NOW())
            """,
            (
                user_id,
                operation_kind,
                client_request_id,
                target_id,
                fingerprint,
            ),
        )
    except pymysql.err.IntegrityError as exc:
        if int(exc.args[0] if exc.args else 0) != 1062:
            raise
        # 唯一键冲突可能来自另一个刚提交的事务。必须使用锁定当前读，不能
        # 继续沿用 REPEATABLE READ 下 INSERT 前建立的旧快照。
        cursor.execute(
            """
            SELECT
              target_id,
              request_fingerprint,
              result_version,
              result_updated_at,
              result_changed
            FROM forum_edit_operation_receipts
            WHERE user_id = %s
              AND operation_kind = %s
              AND client_request_id = %s
            LIMIT 1
            FOR UPDATE
            """,
            params,
        )
        receipt = cursor.fetchone()
        if not receipt:
            raise
        return _validate_edit_receipt(
            dict(receipt),
            target_id=target_id,
            fingerprint=fingerprint,
        )
    return None


def _complete_edit_receipt(
    cursor,
    *,
    user_id: int,
    operation_kind: str,
    client_request_id: str,
    result_version: int,
    result_updated_at,
    changed: bool,
) -> None:
    cursor.execute(
        """
        UPDATE forum_edit_operation_receipts
        SET result_version = %s,
            result_updated_at = %s,
            result_changed = %s,
            completed_at = NOW()
        WHERE user_id = %s
          AND operation_kind = %s
          AND client_request_id = %s
          AND result_version IS NULL
        """,
        (
            result_version,
            result_updated_at,
            1 if changed else 0,
            user_id,
            operation_kind,
            client_request_id,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise RuntimeError("论坛编辑幂等收据未能完成")


def _thread_result_for_edit(
    user_id: int,
    thread_id: int,
    *,
    title: str,
    content: str,
    receipt: dict,
) -> dict:
    result = get_thread_detail(user_id, thread_id)["thread"]
    version = int(receipt["result_version"])
    result.update(
        title=title,
        content=content,
        rendered_content=render_forum_markdown(content),
        edit_version=version,
        is_edited=version > 1,
        updated_at=receipt.get("result_updated_at"),
        unchanged=not bool(receipt.get("result_changed")),
    )
    return result


def _reply_result_for_edit(
    user_id: int,
    reply_id: int,
    *,
    content: str,
    receipt: dict,
) -> dict:
    result = get_reply(user_id, reply_id)
    version = int(receipt["result_version"])
    result.update(
        content=content,
        rendered_content=render_forum_markdown(content),
        edit_version=version,
        is_edited=version > 1,
        updated_at=receipt.get("result_updated_at"),
        unchanged=not bool(receipt.get("result_changed")),
    )
    return result


def edit_thread(
    user_id: int,
    thread_id: int,
    *,
    title: Any,
    content: Any,
    edit_version: Any,
    client_request_id: Any,
) -> dict:
    clean_title = validate_title(title)
    clean_content = validate_content(content)
    expected_version = validate_edit_version(edit_version)
    request_id = normalize_client_request_id(client_request_id)
    fingerprint = request_fingerprint(
        {
            "target_id": int(thread_id),
            "title": clean_title,
            "content": clean_content,
            "edit_version": expected_version,
        }
    )
    completed_receipt = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            completed_receipt = _claim_edit_receipt(
                cursor,
                user_id=user_id,
                operation_kind="thread",
                client_request_id=request_id,
                target_id=thread_id,
                fingerprint=fingerprint,
            )
            if completed_receipt is None:
                cursor.execute(
                    """
                    SELECT id, user_id, title, content, edit_version, updated_at
                    FROM forum_threads
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (thread_id,),
                )
                current = cursor.fetchone()
                if not current:
                    raise ForumNotFoundError("帖子不存在")
                if int(current.get("user_id") or 0) != int(user_id):
                    raise ForumPermissionError("只能编辑自己发布的讨论")
                current_version = int(current.get("edit_version") or 1)
                if current_version != expected_version:
                    raise ForumConflictError(
                        "内容已在其他页面更新，请刷新后重试",
                        current_version=current_version,
                    )
                changed = not (
                    current.get("title") == clean_title
                    and current.get("content") == clean_content
                )
                if changed:
                    cursor.execute(
                        """
                        INSERT INTO forum_thread_revisions (
                          thread_id,
                          editor_user_id,
                          title,
                          content,
                          source_version,
                          created_at
                        )
                        VALUES (%s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            thread_id,
                            user_id,
                            current.get("title") or "",
                            current.get("content") or "",
                            current_version,
                        ),
                    )
                    cursor.execute(
                        """
                        UPDATE forum_threads
                        SET title = %s,
                            content = %s,
                            edit_version = edit_version + 1,
                            updated_at = NOW()
                        WHERE id = %s AND edit_version = %s
                        """,
                        (clean_title, clean_content, thread_id, current_version),
                    )
                    if int(cursor.rowcount or 0) != 1:
                        raise ForumConflictError("内容已在其他页面更新，请刷新后重试")
                    cursor.execute(
                        "SELECT edit_version, updated_at FROM forum_threads WHERE id = %s",
                        (thread_id,),
                    )
                    result_row = cursor.fetchone() or {}
                    result_version = int(result_row.get("edit_version") or 0)
                    result_updated_at = result_row.get("updated_at")
                else:
                    result_version = current_version
                    result_updated_at = current.get("updated_at")
                _complete_edit_receipt(
                    cursor,
                    user_id=user_id,
                    operation_kind="thread",
                    client_request_id=request_id,
                    result_version=result_version,
                    result_updated_at=result_updated_at,
                    changed=changed,
                )
                completed_receipt = {
                    "result_version": result_version,
                    "result_updated_at": result_updated_at,
                    "result_changed": 1 if changed else 0,
                }
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _thread_result_for_edit(
        user_id,
        thread_id,
        title=clean_title,
        content=clean_content,
        receipt=completed_receipt,
    )


def edit_reply(
    user_id: int,
    reply_id: int,
    *,
    content: Any,
    edit_version: Any,
    client_request_id: Any,
) -> dict:
    clean_content = validate_content(content)
    expected_version = validate_edit_version(edit_version)
    request_id = normalize_client_request_id(client_request_id)
    fingerprint = request_fingerprint(
        {
            "target_id": int(reply_id),
            "content": clean_content,
            "edit_version": expected_version,
        }
    )
    completed_receipt = None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            completed_receipt = _claim_edit_receipt(
                cursor,
                user_id=user_id,
                operation_kind="reply",
                client_request_id=request_id,
                target_id=reply_id,
                fingerprint=fingerprint,
            )
            if completed_receipt is None:
                cursor.execute(
                    """
                    SELECT id, user_id, content, edit_version, updated_at
                    FROM forum_replies
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (reply_id,),
                )
                current = cursor.fetchone()
                if not current:
                    raise ForumNotFoundError("回复不存在")
                if int(current.get("user_id") or 0) != int(user_id):
                    raise ForumPermissionError("只能编辑自己发布的回复")
                current_version = int(current.get("edit_version") or 1)
                if current_version != expected_version:
                    raise ForumConflictError(
                        "内容已在其他页面更新，请刷新后重试",
                        current_version=current_version,
                    )
                changed = current.get("content") != clean_content
                if changed:
                    cursor.execute(
                        """
                        INSERT INTO forum_reply_revisions (
                          reply_id,
                          editor_user_id,
                          content,
                          source_version,
                          created_at
                        )
                        VALUES (%s, %s, %s, %s, NOW())
                        """,
                        (
                            reply_id,
                            user_id,
                            current.get("content") or "",
                            current_version,
                        ),
                    )
                    cursor.execute(
                        """
                        UPDATE forum_replies
                        SET content = %s,
                            edit_version = edit_version + 1,
                            updated_at = NOW()
                        WHERE id = %s AND edit_version = %s
                        """,
                        (clean_content, reply_id, current_version),
                    )
                    if int(cursor.rowcount or 0) != 1:
                        raise ForumConflictError("内容已在其他页面更新，请刷新后重试")
                    cursor.execute(
                        "SELECT edit_version, updated_at FROM forum_replies WHERE id = %s",
                        (reply_id,),
                    )
                    result_row = cursor.fetchone() or {}
                    result_version = int(result_row.get("edit_version") or 0)
                    result_updated_at = result_row.get("updated_at")
                else:
                    result_version = current_version
                    result_updated_at = current.get("updated_at")
                _complete_edit_receipt(
                    cursor,
                    user_id=user_id,
                    operation_kind="reply",
                    client_request_id=request_id,
                    result_version=result_version,
                    result_updated_at=result_updated_at,
                    changed=changed,
                )
                completed_receipt = {
                    "result_version": result_version,
                    "result_updated_at": result_updated_at,
                    "result_changed": 1 if changed else 0,
                }
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return _reply_result_for_edit(
        user_id,
        reply_id,
        content=clean_content,
        receipt=completed_receipt,
    )
