from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common


def _necessary_forum_thread_row(row: Any, *, include_content: bool) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    keys = ["id", "title", "username", "created_at", "updated_at", "url"]
    if include_content:
        keys.insert(2, "content")
    return {key: row[key] for key in keys if key in row}


def _necessary_forum_reply_row(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {key: row[key] for key in ("id", "content", "username", "created_at", "updated_at") if key in row}


def necessary_forum_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "count": payload.get("count", 0),
        "threads": [_necessary_forum_thread_row(row, include_content=False) for row in payload.get("threads") or []],
    }


def necessary_forum_thread_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "thread": _necessary_forum_thread_row(payload.get("thread"), include_content=True),
        "replies": [_necessary_forum_reply_row(row) for row in payload.get("replies") or []],
        "reply_count": payload.get("reply_count", 0),
    }


def necessary_forum_new_context_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {"fields": payload.get("fields") or []}


def forum_list(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/forum")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_forum_list_payload(resp.json()))
        return
    print(resp.text.strip())


def forum_thread(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/forum/threads/{args.thread_id}")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_forum_thread_payload(resp.json()))
        return
    print(resp.text.strip())


def forum_new_page(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/forum/new-context")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_forum_new_context_payload(resp.json()))
        return
    print(resp.text.strip())


def forum_new(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/forum/new", data={"title": args.title, "content": common.read_text_value(args.content)})
    common.print_redirect_response(resp, id_pattern=r"/forum/thread/(\d+)", id_name="thread_id")


def _reply_content(args: argparse.Namespace) -> str:
    content = common.read_text_value(args.content)
    if not content.strip():
        raise common.CliError("Reply content cannot be empty.")
    return content


def forum_reply(args: argparse.Namespace) -> None:
    content = _reply_content(args)
    resp = common.client_from_args(args).request("POST", f"/forum/reply/{args.thread_id}", data={"content": content})
    common.print_redirect_response(resp)


def forum_reply_thread(args: argparse.Namespace) -> None:
    content = _reply_content(args)
    resp = common.client_from_args(args).request("POST", f"/forum/thread/{args.thread_id}", data={"content": content})
    common.print_redirect_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:
    forum = common.add_cli_parser(subparsers, "forum", "Inspect and create forum threads and replies.")
    forum_sub = forum.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(forum_sub, "list", "List forum threads.")
    pa.set_defaults(func=forum_list)
    pa = common.add_cli_parser(forum_sub, "thread", "Fetch one forum thread and its replies.")
    pa.add_argument("thread_id", type=int, help="Forum thread ID to fetch.")
    pa.set_defaults(func=forum_thread)
    pa = common.add_cli_parser(forum_sub, "new-page", "Fetch the new-thread form metadata as JSON.")
    pa.set_defaults(func=forum_new_page)
    pa = common.add_cli_parser(forum_sub, "new", "Create a new forum thread.")
    pa.add_argument("--title", required=True, help="Thread title.")
    pa.add_argument("--content", required=True, help="Thread body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_new)
    pa = common.add_cli_parser(forum_sub, "reply", "Post a reply to a forum thread.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply)
    pa = common.add_cli_parser(forum_sub, "reply-thread", "Post a reply using the thread-reply route.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply_thread)
