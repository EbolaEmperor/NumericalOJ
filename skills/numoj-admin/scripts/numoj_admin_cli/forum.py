from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from . import common
from .common import *  # noqa: F401,F403 - command modules share the CLI helper surface.


def _necessary_forum_thread_row(row: Any, *, include_content: bool) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    keys = [
        "id",
        "title",
        "display_name",
        "is_anonymous",
        "created_at",
        "updated_at",
        "last_activity_at",
        "reply_count",
        "edit_version",
        "url",
    ]
    if include_content:
        keys.insert(2, "content")
    return {key: row[key] for key in keys if key in row}


def _necessary_forum_reply_row(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        key: row[key]
        for key in (
            "id",
            "content",
            "display_name",
            "is_anonymous",
            "created_at",
            "updated_at",
            "edit_version",
        )
        if key in row
    }


def necessary_forum_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    out = {
        "success": payload.get("success", True),
        "count": payload.get("count", 0),
        "threads": [_necessary_forum_thread_row(row, include_content=False) for row in payload.get("threads") or []],
    }
    for key in ("total", "page", "limit", "total_pages"):
        if key in payload:
            out[key] = payload[key]
    return out


def necessary_forum_thread_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "success": payload.get("success", True),
        "thread": _necessary_forum_thread_row(payload.get("thread"), include_content=True),
        "replies": [_necessary_forum_reply_row(row) for row in payload.get("replies") or []],
        "reply_count": payload.get("reply_count", 0),
    }


def necessary_forum_new_context_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {"success": payload.get("success", True), "fields": payload.get("fields") or []}


def forum_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/forum", params={"page": getattr(args, "page", 1), "limit": getattr(args, "limit", 50)})
    common.output_projected_json_response(resp, necessary_forum_list_payload)


def forum_thread(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/forum/threads/{args.thread_id}")
    common.output_projected_json_response(resp, necessary_forum_thread_payload)


def forum_new_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/forum/new-context")
    common.output_projected_json_response(resp, necessary_forum_new_context_payload)


def _posting_token(client) -> str:
    resp = client.request("GET", "/api/forum/identity")
    ensure_ok(resp, allow_redirect=False)
    if not response_is_json(resp):
        raise common.CliError("Forum identity endpoint did not return JSON.")
    payload = resp.json()
    identity = payload.get("identity") if isinstance(payload, dict) else None
    token = identity.get("posting_token") if isinstance(identity, dict) else None
    if not token:
        raise common.CliError("Forum posting identity is unavailable.")
    return str(token)


def forum_new(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/api/forum/threads",
        json={
            "title": args.title,
            "content": read_text_value(args.content),
            "client_request_id": str(uuid.uuid4()),
            "expected_identity_token": _posting_token(client),
        },
    )
    common.output_projected_json_response(resp, lambda payload: payload)


def forum_reply(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/api/forum/threads/{args.thread_id}/replies",
        json={
            "content": read_text_value(args.content),
            "client_request_id": str(uuid.uuid4()),
            "expected_identity_token": _posting_token(client),
        },
    )
    common.output_projected_json_response(resp, lambda payload: payload)


def forum_reply_thread(args: argparse.Namespace) -> None:
    # 兼容旧命令名；服务器不再提供 HTML form 写入降级路径。
    forum_reply(args)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    forum = add_cli_parser(sub, "forum", "Inspect and create forum threads and replies.")
    fs = forum.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(fs, "list", "List forum threads.")
    pa.add_argument("--page", type=int, default=1, help="Result page to fetch.")
    pa.add_argument("--limit", type=int, default=50, help="Maximum threads to return, capped by the server.")
    pa.set_defaults(func=forum_list)
    pa = add_cli_parser(fs, "thread", "Fetch one forum thread and its replies.")
    pa.add_argument("thread_id", type=int, help="Forum thread ID to fetch.")
    pa.set_defaults(func=forum_thread)
    pa = add_cli_parser(fs, "new-page", "Fetch the new-thread form metadata as JSON.")
    pa.set_defaults(func=forum_new_page)
    pa = add_cli_parser(fs, "new", "Create a new forum thread.")
    pa.add_argument("--title", required=True, help="Thread title.")
    pa.add_argument("--content", required=True, help="Thread body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_new)
    pa = add_cli_parser(fs, "reply", "Post a reply to a forum thread.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply)
    pa = add_cli_parser(fs, "reply-thread", "Post a reply using the thread-reply route.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply_thread)
