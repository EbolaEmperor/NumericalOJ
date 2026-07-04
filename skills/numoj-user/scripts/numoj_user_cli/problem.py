from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any, Dict

from . import common


def wait_promptly_review_result(
    client: common.NumOJClient,
    submission_id: int,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float,
) -> Dict[str, Any]:
    deadline = time.time() + max(0.0, float(timeout_seconds))
    interval = max(0.1, float(poll_interval_seconds))
    last_status: Dict[str, Any] = {}

    while True:
        resp = client.request("GET", f"/submission_status/{submission_id}")
        common.ensure_ok(resp, allow_redirect=False)
        payload = resp.json() if common.response_is_json(resp) else {}
        last_status = payload if isinstance(payload, dict) else {}

        status = str(last_status.get("status") or "").strip()
        reply = str(
            last_status.get("promptly_review_reply")
            or last_status.get("prompt_generation_error")
            or ""
        ).strip()
        if reply:
            return {
                "waited": True,
                "done": True,
                "accepted": False,
                "status": status,
                "reply": reply,
                "submission_status": last_status,
            }
        if status and status != "Generating":
            return {
                "waited": True,
                "done": True,
                "accepted": True,
                "status": status,
                "reply": "",
                "submission_status": last_status,
            }
        if time.time() >= deadline:
            return {
                "waited": True,
                "done": False,
                "accepted": None,
                "timed_out": True,
                "status": status or None,
                "reply": "",
                "submission_status": last_status,
            }
        time.sleep(interval)


def necessary_problem_list_payload(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {"homeworks": []}
    homeworks = payload.get("homeworks")
    return {"homeworks": homeworks if isinstance(homeworks, list) else []}


def necessary_problem_detail_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary = dict(payload)
    necessary.pop("success", None)
    necessary.pop("user", None)
    necessary.pop("rendered_content", None)
    problem = necessary.get("problem")
    if isinstance(problem, dict):
        necessary_problem = dict(problem)
        necessary_problem.pop("user", None)
        necessary_problem.pop("rendered_content", None)
        necessary["problem"] = necessary_problem
    submit = necessary.get("submit")
    if isinstance(submit, dict):
        necessary_submit = {
            key: submit[key]
            for key in ("input_kind", "accept", "help_text")
            if submit.get(key) is not None
        }
        necessary["submit"] = necessary_submit
    return necessary


def problem_list(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/problems", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_problem_list_payload(resp.json()))
        return
    print(resp.text.strip())


def problem_detail(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_problem_detail_payload(resp.json()))
        return
    print(resp.text.strip())


def problem_submit_page(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_problem_detail_payload(resp.json()))
        return
    print(resp.text.strip())


def problem_submit(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    context_resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    common.ensure_ok(context_resp, allow_redirect=False)
    context = context_resp.json() if common.response_is_json(context_resp) else {}
    input_kind = ((context.get("submit") or {}).get("input_kind") or "").strip().lower()

    if input_kind == "file":
        if not args.file:
            raise common.CliError("This problem requires --file.")
        if args.code or args.code_file or args.prompt or args.prompt_file:
            raise common.CliError("This problem accepts a file submission, not code or prompt.")
        files = {"file": common.require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            common.close_files(files)
    elif input_kind == "prompt":
        if not (args.prompt or args.prompt_file):
            raise common.CliError("This Promptly problem requires --prompt or --prompt-file.")
        if args.file or args.code or args.code_file:
            raise common.CliError("This Promptly problem accepts prompt text, not code or file.")
        prompt = Path(args.prompt_file).expanduser().read_text(encoding="utf-8") if args.prompt_file else common.read_text_value(args.prompt)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"prompt": prompt})
    else:
        if not (args.code or args.code_file):
            raise common.CliError("This programming problem requires --code or --code-file.")
        if args.file or args.prompt or args.prompt_file:
            raise common.CliError("This programming problem accepts code, not prompt or file.")
        code = Path(args.code_file).expanduser().read_text(encoding="utf-8") if args.code_file else common.read_text_value(args.code)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"code": code})
    payload = common.redirect_response_payload(resp, id_pattern=r"/submission_detail/(\d+)", id_name="submission_id")
    if input_kind == "prompt" and payload.get("success") and payload.get("submission_id") and getattr(args, "wait_promptly", True):
        promptly_review = wait_promptly_review_result(
            client,
            int(payload["submission_id"]),
            timeout_seconds=args.wait_timeout,
            poll_interval_seconds=args.poll_interval,
        )
        payload["promptly_review"] = promptly_review
        if promptly_review.get("reply"):
            payload["reply"] = promptly_review["reply"]
    payload.pop("status", None)
    payload.pop("location", None)
    common.output_json(payload)


def register(subparsers: argparse._SubParsersAction) -> None:
    problem = common.add_cli_parser(subparsers, "problem", "Browse problems and submit code, Promptly prompts, or written-homework files.")
    problem_sub = problem.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(problem_sub, "list", "List assigned homework/problem rows as JSON.")
    pa.add_argument("--limit", type=int, help="Maximum number of homework/problem rows to request.")
    pa.set_defaults(func=problem_list)
    pa = common.add_cli_parser(problem_sub, "detail", "Fetch problem detail JSON.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.set_defaults(func=problem_detail)
    pa = common.add_cli_parser(problem_sub, "submit-page", "Fetch the submit-context metadata for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submit context should be fetched.")
    pa.set_defaults(func=problem_submit_page)
    pa = common.add_cli_parser(problem_sub, "submit", "Submit source code, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    sg = pa.add_mutually_exclusive_group(required=True)
    sg.add_argument("--code", help="Source code text, or @file to read code from a file.")
    sg.add_argument("--code-file", help="Source code file path.")
    sg.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    sg.add_argument("--prompt-file", help="Promptly submission file path.")
    sg.add_argument("--file", help="Written-homework PDF or ZIP file path.")
    pa.add_argument(
        "--no-wait-promptly",
        dest="wait_promptly",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Return immediately after creating a Promptly submission instead of waiting for prompt review/generation status.",
    )
    pa.add_argument("--wait-timeout", type=float, default=60.0, help="Maximum seconds to wait for Promptly review/generation status after a prompt submission.")
    pa.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between Promptly status polling requests.")
    pa.set_defaults(func=problem_submit)
