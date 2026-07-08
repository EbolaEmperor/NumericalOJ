from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from . import common
from .common import *  # noqa: F401,F403 - command modules share the CLI helper surface.

from .submission import submission_list


def me_classes(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/me/classes")
    print_or_save_response(resp)


def me_join_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/join_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_leave_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/leave_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_set_primary_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/set_primary_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    cfg = load_config(args.config)
    username = args.username or cfg.get("username")
    if args.user_id is not None:
        resp = client.request("GET", "/admin/get_user_grades", params={"user_id": args.user_id})
        print_or_save_response(resp)
        return
    if not username:
        raise CliError("Missing username. Pass --user-id or run init first.")
    users_resp = client.request("GET", "/api/admin/users", params={"username": username})
    ensure_ok(users_resp, allow_redirect=False)
    payload = users_resp.json() if response_is_json(users_resp) else {}
    matches = [u for u in (payload.get("users") or []) if u.get("username") == username]
    if not matches:
        raise CliError("Cannot find current user id from /api/admin/users. Pass --user-id explicitly.")
    resp = client.request("GET", "/admin/get_user_grades", params={"user_id": matches[0]["id"]})
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    me = add_cli_parser(sub, "me", "Inspect and update data for the currently configured account.")
    mes = me.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(mes, "classes", "List classes visible to the current account.")
    pa.set_defaults(func=me_classes)
    pa = add_cli_parser(mes, "join-class", "Join a class as the current account.")
    pa.add_argument("class_en", help="English class identifier, e.g. C2026A.")
    pa.set_defaults(func=me_join_class)
    pa = add_cli_parser(mes, "leave-class", "Leave a class as the current account.")
    pa.add_argument("class_en", help="English class identifier to leave, e.g. C2026A.")
    pa.set_defaults(func=me_leave_class)
    pa = add_cli_parser(mes, "set-primary-class", "Set the current account's primary class.")
    pa.add_argument("class_en", help="English class identifier to make primary, e.g. C2026A.")
    pa.set_defaults(func=me_set_primary_class)
    pa = add_cli_parser(mes, "grades", "Show grades for the current account or another user visible to the administrator.")
    pa.add_argument("--user-id", type=int, help="Admin-visible user ID. If omitted, the initialized username is used.")
    pa.add_argument("--username", help="Admin-visible username. Defaults to the initialized username.")
    pa.set_defaults(func=me_grades)
    pa = add_cli_parser(mes, "submissions", "List submissions visible to the current account.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
