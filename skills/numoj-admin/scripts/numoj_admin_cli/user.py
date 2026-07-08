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


def necessary_user_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("page", "per_page", "total", "total_pages", "classes", "users"):
        if key in payload:
            necessary[key] = payload[key]
    return necessary


def user_add_class_type(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/add_class_ajax",
        data={"class_en": args.class_en, "class_cn": args.class_cn},
    )
    print_or_save_response(resp)


def user_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.username:
        params["username"] = args.username
    if args.class_en:
        params["class"] = args.class_en
    resp = client.request("GET", "/api/admin/users", params=params)
    common.output_projected_json_response(resp, necessary_user_list_payload, allow_redirect=True)


def user_set_primary_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/edit_user_ajax",
        data={"user_id": args.user_id, "class": args.class_en},
    )
    print_or_save_response(resp)


def user_rename(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/edit_username_ajax",
        data={"user_id": args.user_id, "new_username": args.username},
    )
    print_or_save_response(resp)


def user_add_to_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/add_user_to_class",
        data={"user_id": args.user_id, "class_en": args.class_en},
    )
    print_or_save_response(resp)


def user_remove_from_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/remove_user_from_class",
        data={"user_id": args.user_id, "class_en": args.class_en},
    )
    print_or_save_response(resp)


def user_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/get_user_grades", params={"user_id": args.user_id})
    print_or_save_response(resp)


def user_update_grade(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    score = "" if args.clear else str(args.score)
    resp = client.request(
        "POST",
        "/admin/update_user_grade",
        data={"user_id": args.user_id, "problem_id": args.problem_id, "score": score},
    )
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    user = add_cli_parser(sub, "user", "Manage users, classes, memberships, names, and grade overrides.")
    us = user.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(us, "list", "List users with optional username or class filters.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--username", help="Filter by username substring or exact username, depending on server behavior.")
    pa.add_argument("--class-en", help="Filter by English class identifier.")
    pa.set_defaults(func=user_list)
    pa = add_cli_parser(us, "add-class-type", "Create a class type entry available for user membership.")
    pa.add_argument("--class-en", required=True, help="English class code without the leading C, matching the web form behavior.")
    pa.add_argument("--class-cn", required=True, help="Chinese display name for the class.")
    pa.set_defaults(func=user_add_class_type)
    pa = add_cli_parser(us, "set-primary-class", "Set a user's primary class.")
    pa.add_argument("user_id", type=int, help="User ID to update.")
    pa.add_argument("class_en", help="English class identifier to set as primary.")
    pa.set_defaults(func=user_set_primary_class)
    pa = add_cli_parser(us, "rename", "Rename a user account.")
    pa.add_argument("user_id", type=int, help="User ID to rename.")
    pa.add_argument("username", help="New username.")
    pa.set_defaults(func=user_rename)
    pa = add_cli_parser(us, "add-to-class", "Add a user to a class.")
    pa.add_argument("user_id", type=int, help="User ID to add.")
    pa.add_argument("class_en", help="English class identifier to add the user to.")
    pa.set_defaults(func=user_add_to_class)
    pa = add_cli_parser(us, "remove-from-class", "Remove a user from a class.")
    pa.add_argument("user_id", type=int, help="User ID to remove.")
    pa.add_argument("class_en", help="English class identifier to remove from the user.")
    pa.set_defaults(func=user_remove_from_class)
    pa = add_cli_parser(us, "grades", "List all visible grades for a user.")
    pa.add_argument("user_id", type=int, help="User ID whose grades should be listed.")
    pa.set_defaults(func=user_grades)
    pa = add_cli_parser(us, "update-grade", "Set or clear a manual grade override for a user and problem.")
    pa.add_argument("user_id", type=int, help="User ID whose grade should be updated.")
    pa.add_argument("problem_id", type=int, help="Problem ID for the grade update.")
    g = pa.add_mutually_exclusive_group(required=True)
    g.add_argument("--score", type=int, help="Score value to set.")
    g.add_argument("--clear", action="store_true", help="Clear the existing manual grade override.")
    pa.set_defaults(func=user_update_grade)
