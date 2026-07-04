from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common
from .submission import _necessary_submission_rows, necessary_submission_list_payload


def necessary_classes_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("primary_en", "memberships", "all_classes"):
        if key in payload:
            necessary[key] = payload[key]
    return necessary


def me_classes(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/me/classes")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_classes_payload(resp.json()))
        return
    print(resp.text.strip())


def me_join_class(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/me/join_class", data={"class_en": args.class_en})
    common.print_or_save_response(resp)


def me_leave_class(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/me/leave_class", data={"class_en": args.class_en})
    common.print_or_save_response(resp)


def me_set_primary_class(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/me/set_primary_class", data={"class_en": args.class_en})
    common.print_or_save_response(resp)


def me_submissions(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = common.client_from_args(args).request("GET", "/api/submissions", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_submission_list_payload(resp.json()))
        return
    print(resp.text.strip())


def me_grades(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    best: Dict[str, Dict[str, Any]] = {}
    for page in range(1, args.pages + 1):
        resp = client.request("GET", "/api/submissions", params={"page": page})
        common.ensure_ok(resp, allow_redirect=False)
        payload = resp.json() if common.response_is_json(resp) else {}
        rows = payload.get("submissions") or []
        if not rows:
            break
        for row in rows:
            problem = row.get("display_problem_title") or row.get("problem_title") or f"submission:{row['id']}"
            try:
                score_value = float(str(row.get("score") or "0"))
            except ValueError:
                score_value = 0.0
            if problem not in best or score_value > float(best[problem].get("score_value") or 0):
                row["score_value"] = score_value
                best[problem] = row
    common.output_json({"grades": _necessary_submission_rows(list(best.values()), include_problem_id=True)})


def register(subparsers: argparse._SubParsersAction) -> None:
    me = common.add_cli_parser(subparsers, "me", "Inspect and update data for the currently configured account.")
    me_sub = me.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(me_sub, "classes", "List classes visible to the current account.")
    pa.set_defaults(func=me_classes)
    pa = common.add_cli_parser(me_sub, "join-class", "Join a class as the current account.")
    pa.add_argument("class_en", help="English class identifier, e.g. C2026A.")
    pa.set_defaults(func=me_join_class)
    pa = common.add_cli_parser(me_sub, "leave-class", "Leave a class as the current account.")
    pa.add_argument("class_en", help="English class identifier to leave, e.g. C2026A.")
    pa.set_defaults(func=me_leave_class)
    pa = common.add_cli_parser(me_sub, "set-primary-class", "Set the current account's primary class.")
    pa.add_argument("class_en", help="English class identifier to make primary, e.g. C2026A.")
    pa.set_defaults(func=me_set_primary_class)
    pa = common.add_cli_parser(me_sub, "submissions", "List submissions for the current account.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=me_submissions)
    pa = common.add_cli_parser(me_sub, "grades", "Summarize visible grades from recent submission history.")
    pa.add_argument("--pages", type=int, default=5, help="Number of submission-history pages to summarize.")
    pa.set_defaults(func=me_grades)
