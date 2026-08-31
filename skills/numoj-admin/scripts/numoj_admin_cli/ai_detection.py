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


def positive_endpoint_id(raw: str) -> int:
    try:
        endpoint_id = int(raw)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("endpoint ID must be a positive integer") from exc
    if endpoint_id <= 0 or str(endpoint_id) != str(raw).strip():
        raise argparse.ArgumentTypeError("endpoint ID must be a positive integer")
    return endpoint_id


def necessary_ai_detection_page_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("success", "summary", "classes", "problems")
        if key in payload
    }


def necessary_ai_detection_problem_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("success", "problem", "summary", "students", "submissions", "results")
        if key in payload
    }


def necessary_ai_detection_student_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("success", "student", "summary", "problems", "submissions", "results")
        if key in payload
    }


def ai_filter_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for key in ("class_en", "username", "problem_id", "submission_id", "score_min", "score_max"):
        value = getattr(args, key, None)
        if value is not None:
            payload[key] = value
    if getattr(args, "deduplicate", None) is not None:
        payload["deduplicate"] = bool(args.deduplicate)
    if getattr(args, "endpoint_id", None) is not None:
        payload["endpoint_id"] = args.endpoint_id
    return payload


def ai_preview(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/api/admin/ai-detection/preview", json=ai_filter_payload(args))
    print_or_save_response(resp)


def ai_run_filtered(args: argparse.Namespace) -> None:
    filter_keys = ("class_en", "username", "problem_id", "submission_id", "score_min", "score_max")
    has_filter = any(getattr(args, key, None) is not None for key in filter_keys)
    if getattr(args, "all", False) and has_filter:
        raise CliError("Use either --all or specific filters, not both.")
    if not getattr(args, "all", False) and not has_filter:
        raise CliError("run-filtered requires at least one filter; pass --all to scan all submissions.")
    client = client_from_args(args)
    resp = client.request("POST", "/api/admin/ai-detection/runs", json=ai_filter_payload(args))
    print_or_save_response(resp)


def ai_run_problem(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/api/admin/ai-detection/problems/{args.problem_id}/runs",
        json={"endpoint_id": args.endpoint_id},
    )
    print_or_save_response(resp)


def ai_run_single(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/api/admin/ai-detection/submissions/{args.submission_id}/runs",
        json={"endpoint_id": args.endpoint_id},
    )
    print_or_save_response(resp)


def ai_run_user(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/api/admin/ai-detection/users/{args.username}/runs",
        json={"endpoint_id": args.endpoint_id},
    )
    print_or_save_response(resp)


def ai_api_get(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", args.path)
    print_or_save_response(resp)


def ai_detection_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/ai-detection/dashboard")
    common.output_projected_json_response(resp, necessary_ai_detection_page_payload)


def ai_detection_problem_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/admin/ai-detection/problems/{args.problem_id}")
    common.output_projected_json_response(resp, necessary_ai_detection_problem_payload)


def ai_detection_student_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/admin/ai-detection/students/{args.username}")
    common.output_projected_json_response(resp, necessary_ai_detection_student_payload)


def ai_task_post(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    method = "DELETE" if args.action == "delete" else "POST"
    suffix = "" if args.action == "delete" else "/stop"
    resp = client.request(method, f"/api/admin/ai-detection/tasks/{args.task_id}{suffix}")
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    ai = add_cli_parser(sub, "ai-detection", "Inspect and run AI-generated-code detection tasks.")
    ais = ai.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ais, "dashboard", "Fetch the administrator AI-detection dashboard context as JSON.")
    pa.set_defaults(func=ai_detection_page)
    pa = add_cli_parser(ais, "problem-page", "Fetch the AI-detection problem context as JSON.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.set_defaults(func=ai_detection_problem_page)
    pa = add_cli_parser(ais, "student-page", "Fetch the AI-detection student context as JSON.")
    pa.add_argument("username", help="Username to inspect.")
    pa.set_defaults(func=ai_detection_student_page)
    for name, func, description in (
        ("preview", ai_preview, "Preview submissions matching AI-detection filters without starting a detection task."),
        ("run-filtered", ai_run_filtered, "Start an AI-detection task for submissions matching filters."),
    ):
        pa = add_cli_parser(ais, name, description)
        pa.add_argument("--class-en", help="Filter by English class identifier.")
        pa.add_argument("--username", help="Filter by username.")
        pa.add_argument("--problem-id", type=int, help="Filter by problem ID.")
        pa.add_argument("--submission-id", type=int, help="Filter by a single submission ID.")
        pa.add_argument("--score-min", type=float, help="Minimum existing AI-detection score to include.")
        pa.add_argument("--score-max", type=float, help="Maximum existing AI-detection score to include.")
        pa.add_argument("--deduplicate", action="store_true", default=None, help="Ask the server to keep only one candidate per user/problem when supported.")
        if name == "run-filtered":
            pa.add_argument("--all", action="store_true", help="Explicitly scan all submissions without narrowing filters.")
            pa.add_argument(
                "--endpoint-id",
                type=positive_endpoint_id,
                required=True,
                help="Global text or omni LLM endpoint ID to use for this detection run.",
            )
        pa.set_defaults(func=func)
    pa = add_cli_parser(ais, "run-problem", "Start AI-detection for all relevant submissions of one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to scan.")
    pa.add_argument("--endpoint-id", type=positive_endpoint_id, required=True, help="Global text or omni LLM endpoint ID to use for this detection run.")
    pa.set_defaults(func=ai_run_problem)
    pa = add_cli_parser(ais, "run-single", "Start AI-detection for one submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to scan.")
    pa.add_argument("--endpoint-id", type=positive_endpoint_id, required=True, help="Global text or omni LLM endpoint ID to use for this detection run.")
    pa.set_defaults(func=ai_run_single)
    pa = add_cli_parser(ais, "run-user", "Start AI-detection for submissions from one user.")
    pa.add_argument("username", help="Username whose submissions should be scanned.")
    pa.add_argument("--endpoint-id", type=positive_endpoint_id, required=True, help="Global text or omni LLM endpoint ID to use for this detection run.")
    pa.set_defaults(func=ai_run_user)
    for name, path, description in (
        ("summary", "/api/admin/ai-detection/summary", "Fetch AI-detection summary metrics."),
        ("tasks", "/api/admin/ai-detection/tasks", "List recent AI-detection tasks."),
        ("models", "/api/admin/ai-detection/models", "List AI-detection models available on the server."),
    ):
        pa = add_cli_parser(ais, name, description)
        pa.set_defaults(func=ai_api_get, path=path)
    pa = add_cli_parser(ais, "task", "Stop or delete an AI-detection task.")
    pa.add_argument("action", choices=["stop", "delete"], help="Task operation to perform.")
    pa.add_argument("task_id", help="AI-detection task ID.")
    pa.set_defaults(func=ai_task_post)
