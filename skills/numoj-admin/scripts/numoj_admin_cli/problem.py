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


def parse_promptly_review_config_value(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        obj = raw
    else:
        text = str(raw or "").strip()
        if not text:
            obj = {}
        else:
            try:
                parsed = json.loads(text)
                obj = parsed if isinstance(parsed, dict) else {}
            except Exception:
                obj = {"brief": text}
    examples = obj.get("example_replies")
    if not isinstance(examples, list):
        examples = obj.get("examples") if isinstance(obj.get("examples"), list) else []
    return {
        "brief": str(obj.get("brief") or obj.get("problem_brief") or obj.get("summary") or obj.get("context") or "").strip(),
        "prompt_requirements": str(obj.get("prompt_requirements") or obj.get("requirements") or obj.get("prompt_rules") or "").strip(),
        "example_replies": [str(item or "").strip() for item in examples if str(item or "").strip()],
    }


def _promptly_structured_args_present(args: argparse.Namespace) -> bool:
    return any([
        getattr(args, "promptly_brief", None) is not None,
        getattr(args, "promptly_requirements", None) is not None,
        getattr(args, "promptly_example_reply", None) is not None,
        getattr(args, "promptly_example_replies_json", None) is not None,
        bool(getattr(args, "clear_promptly_example_replies", False)),
    ])


def _read_promptly_examples_json(value: str) -> List[str]:
    parsed = parse_json_value(value)
    if isinstance(parsed, list):
        return [str(item or "").strip() for item in parsed if str(item or "").strip()]
    if isinstance(parsed, str):
        return [line.strip() for line in parsed.splitlines() if line.strip()]
    raise CliError("--promptly-example-replies-json must be a JSON array of strings.")


def build_promptly_grading_prompt_arg(args: argparse.Namespace, current: Optional[Dict[str, Any]] = None) -> Optional[str]:
    raw = getattr(args, "programming_grading_prompt", None)
    has_structured = _promptly_structured_args_present(args)
    if raw is not None and has_structured:
        raise CliError("Use either --programming-grading-prompt or structured Promptly options, not both.")
    if raw is not None:
        return read_text_value(raw)
    if not has_structured:
        return None

    current = current or {}
    base = current.get("promptly_review_config")
    if not isinstance(base, dict):
        base = parse_promptly_review_config_value(current.get("programming_grading_prompt"))
    config = parse_promptly_review_config_value(base)

    if getattr(args, "promptly_brief", None) is not None:
        config["brief"] = read_text_value(args.promptly_brief).strip()
    if getattr(args, "promptly_requirements", None) is not None:
        config["prompt_requirements"] = read_text_value(args.promptly_requirements).strip()

    if getattr(args, "promptly_example_replies_json", None) is not None:
        config["example_replies"] = _read_promptly_examples_json(args.promptly_example_replies_json)
    elif getattr(args, "promptly_example_reply", None) is not None:
        config["example_replies"] = [
            read_text_value(item).strip()
            for item in (args.promptly_example_reply or [])
            if read_text_value(item).strip()
        ]
    elif getattr(args, "clear_promptly_example_replies", False):
        config["example_replies"] = []

    return json.dumps(
        {
            "brief": config.get("brief") or "",
            "prompt_requirements": config.get("prompt_requirements") or "",
            "example_replies": config.get("example_replies") or [],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


def wait_promptly_review_result(
    client: NumOJClient,
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
        ensure_ok(resp, allow_redirect=False)
        payload = resp.json() if response_is_json(resp) else {}
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


def _problem_row(row: Any, *, include_content: bool = False) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    keys = [
        "id",
        "kind",
        "problem_id",
        "title",
        "lang",
        "type",
        "max_score",
        "submission_count",
        "submission_limit",
        "time_limit_ms",
        "url",
    ]
    if include_content:
        keys.insert(4, "content")
    return {key: row[key] for key in keys if key in row}


def necessary_problem_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    if isinstance(payload.get("problems"), list):
        return {
            "count": payload.get("count", len(payload.get("problems") or [])),
            "problems": [_problem_row(row) for row in payload.get("problems") or []],
        }
    if isinstance(payload.get("homeworks"), list):
        return {
            "count": payload.get("count", len(payload.get("homeworks") or [])),
            "homeworks": payload.get("homeworks") or [],
        }
    return {"count": payload.get("count", 0)}


def necessary_problem_detail_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    problem = payload.get("problem")
    if isinstance(problem, dict):
        necessary["problem"] = _problem_row(problem, include_content=True)
    for key in ("initial_code", "last_submissions", "remaining_submissions", "can_submit"):
        if key in payload:
            necessary[key] = payload[key]
    submit = payload.get("submit")
    if isinstance(submit, dict):
        necessary_submit = {
            key: submit[key]
            for key in ("input_kind", "accept", "help_text", "problem_type", "programming_grading_mode")
            if key in submit and submit.get(key) is not None
        }
        necessary["submit"] = necessary_submit
    return necessary


def _omit_text_fields(row: Any, fields: Iterable[str]) -> Any:
    if not isinstance(row, dict):
        return row
    out = dict(row)
    omitted: Dict[str, Dict[str, int]] = {}
    for key in fields:
        value = out.pop(key, None)
        if value not in (None, ""):
            omitted[key] = {"chars": len(str(value))}
    if omitted:
        out["omitted_text_fields"] = omitted
    return out


def necessary_problem_form_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "action", "method"):
        if key in payload:
            necessary[key] = payload[key]
    large_fields = (
        "content",
        "initial_code",
        "test_code",
        "programming_grading_prompt",
        "written_grading_prompt",
    )
    if "defaults" in payload:
        necessary["defaults"] = _omit_text_fields(payload.get("defaults"), large_fields)
    if "form" in payload:
        necessary["form"] = _omit_text_fields(payload.get("form"), large_fields)
    if "problem" in payload:
        necessary["problem"] = _omit_text_fields(payload.get("problem"), large_fields)
    options = payload.get("options")
    if isinstance(options, dict):
        necessary_options = dict(options)
        for key in ("default_written_grading_prompt",):
            value = necessary_options.pop(key, None)
            if value:
                necessary_options.setdefault("omitted_text_fields", {})[key] = {"chars": len(str(value))}
        necessary["options"] = necessary_options
    return necessary


def problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/problems", params=params)
    common.output_projected_json_response(resp, necessary_problem_list_payload)


def problem_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    common.output_projected_json_response(resp, necessary_problem_detail_payload)


def problem_submit_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    common.output_projected_json_response(resp, necessary_problem_detail_payload)


def problem_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    context_resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    ensure_ok(context_resp, allow_redirect=False)
    context = context_resp.json() if response_is_json(context_resp) else {}
    input_kind = ((context.get("submit") or {}).get("input_kind") or "").strip().lower()

    if input_kind == "file":
        if not args.file:
            raise CliError("This problem requires --file.")
        if args.code or args.code_file or args.prompt or args.prompt_file:
            raise CliError("This problem accepts a file submission, not code or prompt.")
        files = {"file": require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            close_files(files)
    elif input_kind == "prompt":
        if not (args.prompt or args.prompt_file):
            raise CliError("This Promptly problem requires --prompt or --prompt-file.")
        if args.file or args.code or args.code_file:
            raise CliError("This Promptly problem accepts prompt text, not code or file.")
        prompt = Path(args.prompt_file).expanduser().read_text(encoding="utf-8") if args.prompt_file else read_text_value(args.prompt)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"prompt": prompt})
    else:
        if not (args.code or args.code_file):
            raise CliError("This programming problem requires --code or --code-file.")
        if args.file or args.prompt or args.prompt_file:
            raise CliError("This programming problem accepts code, not prompt or file.")
        code = Path(args.code_file).expanduser().read_text(encoding="utf-8") if args.code_file else read_text_value(args.code)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"code": code})
    payload = redirect_response_payload(resp, id_pattern=r"/submission_detail/(\d+)", id_name="submission_id")
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
    output_json(payload)


def problem_create_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/problems/create-form")
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    common.output_projected_json_response(resp, necessary_problem_form_payload)


def problem_create(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    programming_grading_prompt = build_promptly_grading_prompt_arg(args)
    if programming_grading_prompt is None:
        programming_grading_prompt = ""
    data = form_from_pairs(
        [
            ("title", args.title),
            ("content", read_text_value(args.content)),
            ("initial_code", read_text_value(args.initial_code)),
            ("test_code", read_text_value(args.test_code)),
            ("forbidden_func", args.forbidden_func),
            ("type", args.type),
            ("lang", args.lang),
            ("time_limit", args.time_limit),
            ("submission_limit", args.submission_limit),
            ("programming_grading_mode", args.programming_grading_mode),
            ("programming_grading_model", args.programming_grading_model),
            ("programming_output_filename", args.programming_output_filename),
            ("programming_grading_prompt", programming_grading_prompt),
            ("written_grading_mode", args.written_grading_mode),
            ("written_grading_model", args.written_grading_model),
            ("written_grading_prompt", read_text_value(args.written_grading_prompt)),
        ]
    )
    resp = client.request("POST", "/admin/add_problem", data=data, headers={"Accept": "application/json"})
    print_or_save_response(resp)


def problem_edit_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/admin/problems/{args.problem_id}/edit-form")
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    common.output_projected_json_response(resp, necessary_problem_form_payload)


def problem_edit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    form_resp = client.request("GET", f"/api/admin/problems/{args.problem_id}/edit-form")
    ensure_ok(form_resp, allow_redirect=False)
    current = (form_resp.json() if response_is_json(form_resp) else {}).get("form") or {}
    programming_grading_prompt = build_promptly_grading_prompt_arg(args, current)
    data = form_from_pairs(
        [
            ("title", current_or_arg(current, "title", args.title)),
            ("content", current_or_arg(current, "content", args.content)),
            ("initial_code", current_or_arg(current, "initial_code", args.initial_code)),
            ("test_code", current_or_arg(current, "test_code", args.test_code)),
            ("forbidden_func", current_or_arg(current, "forbidden_func", args.forbidden_func)),
            ("lang", current_or_arg(current, "lang", args.lang)),
            ("time_limit", current_or_arg(current, "time_limit", args.time_limit)),
            ("submission_limit", current_or_arg(current, "submission_limit", args.submission_limit)),
            ("programming_grading_mode", current_or_arg(current, "programming_grading_mode", args.programming_grading_mode)),
            ("programming_grading_model", current_or_arg(current, "programming_grading_model", args.programming_grading_model)),
            ("programming_output_filename", current_or_arg(current, "programming_output_filename", args.programming_output_filename)),
            ("programming_grading_prompt", programming_grading_prompt if programming_grading_prompt is not None else current.get("programming_grading_prompt", "")),
            ("written_grading_mode", current_or_arg(current, "written_grading_mode", args.written_grading_mode)),
            ("written_grading_model", current_or_arg(current, "written_grading_model", args.written_grading_model)),
            ("written_grading_prompt", current_or_arg(current, "written_grading_prompt", args.written_grading_prompt)),
        ]
    )
    resp = client.request("POST", f"/admin/edit_problem/{args.problem_id}", data=data)
    print_or_save_response(resp)


def problem_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("DELETE", f"/admin/delete_problem/{args.problem_id}")
    print_or_save_response(resp)


def problem_upload_testdata(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"testdata_zip": require_file(args.zip)}
    try:
        resp = client.request("POST", f"/admin/upload_testdata/{args.problem_id}", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def problem_rejudge(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/admin/rejudge_problem/{args.problem_id}")
    print_or_save_response(resp)


def problem_rejudge_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/rejudge_status/{args.problem_id}")
    print_or_save_response(resp, fail_on_business_error=False)


def problem_rejudge_time_range(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload: Dict[str, Any] = {"start": args.start, "end": args.end}
    if args.confirm_total is not None:
        payload["confirm_total"] = args.confirm_total
    resp = client.request("POST", "/admin/rejudge_time_range", json=payload)
    print_or_save_response(resp)


def problem_rejudge_time_range_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/rejudge_time_range_status")
    print_or_save_response(resp, fail_on_business_error=False)


def problem_agent_run_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_status/{args.task_id}")
    print_or_save_response(resp)


def problem_agent_run_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_status/{args.task_id}")
    print_or_save_response(resp, allow_redirect=False)


def necessary_agent_stream_event_payload(event: Any) -> Any:
    if not isinstance(event, dict):
        text = str(event or "")
        if len(text) <= 500:
            return text
        return {"text": text[:500], "chars": len(text), "truncated": True}

    necessary: Dict[str, Any] = {}
    for key in (
        "success",
        "task_id",
        "id",
        "problem_id",
        "status",
        "stage",
        "message",
        "error",
        "best_score",
        "rounds_run",
        "created_at",
        "updated_at",
        "completed_at",
    ):
        if key in event and event.get(key) not in (None, ""):
            necessary[key] = event[key]

    for key in ("events", "logs", "rounds", "submissions", "messages"):
        value = event.get(key)
        if isinstance(value, list):
            necessary[f"{key}_count"] = len(value)

    for key in ("result", "progress"):
        value = event.get(key)
        if isinstance(value, dict):
            necessary[key] = common.necessary_response_payload(value)
    return necessary or common.necessary_response_payload(event)


def problem_agent_run_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_stream/{args.task_id}", stream=True)
    if getattr(args, "full", False):
        print_stream_lines(resp, max_lines=args.max_lines)
        return
    stream_payload = common.read_stream_events(resp, max_lines=args.max_lines)
    latest = None
    for event in stream_payload.get("events") or []:
        latest = event
    output_json({
        "success": True,
        "events_count": len(stream_payload.get("events") or []),
        "latest": necessary_agent_stream_event_payload(latest) if latest is not None else None,
        "truncated": bool(stream_payload.get("truncated")),
    })


def problem_agent_tasks(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/agent-tasks")
    print_or_save_response(resp, allow_redirect=False)


def problem_agent_solve(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"extra_prompt": read_text_value(args.extra_prompt)}
    resp = client.request("POST", f"/admin/agent_solve_problem/{args.problem_id}", json=payload)
    print_or_save_response(resp)


def problem_agent_generate_data(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "test_point_count": args.count,
        "standard_code": read_text_value(args.standard_code),
        "data_requirement": read_text_value(args.data_requirement),
    }
    resp = client.request("POST", f"/admin/agent_generate_testdata/{args.problem_id}", json=payload)
    print_or_save_response(resp)


def problem_scores(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/problem_scores/{args.problem_id}")
    print_or_save_response(resp)


def add_promptly_review_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--promptly-brief",
        help=(
            "Brief problem description for Promptly prompt review, or @file. "
            "Only the review model sees this; it is used to judge whether the student's idea matches the problem."
        ),
    )
    parser.add_argument(
        "--promptly-requirements",
        help=(
            "Detailed requirements for Promptly prompt review, or @file. "
            "Use this to require algorithm choices, data structures, state updates, boundary handling, and similar details."
        ),
    )
    parser.add_argument(
        "--promptly-example-reply",
        action="append",
        help=(
            "Example rejection reply for the Promptly review model to imitate. "
            "Repeat this option to provide multiple examples; each value may also be @file."
        ),
    )
    parser.add_argument(
        "--promptly-example-replies-json",
        help="JSON array of Promptly example rejection replies, or @file. Replaces the current example list.",
    )
    parser.add_argument(
        "--clear-promptly-example-replies",
        action="store_true",
        help="When editing, clear Promptly example replies. This only applies when no replacement example list is passed.",
    )


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    problem = add_cli_parser(sub, "problem", "Manage problems, submissions, test data, rejudging, and problem-solving agents.")
    ps = problem.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ps, "list", "List available problems from the problem-list API.")
    pa.add_argument("--limit", type=int, help="Maximum number of problems to return.")
    pa.set_defaults(func=problem_list)
    pa = add_cli_parser(ps, "detail", "Fetch problem detail metadata as JSON.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.add_argument("--full", action="store_true", help="Print the raw detail payload, including rendered HTML and page context.")
    pa.set_defaults(func=problem_detail)
    pa = add_cli_parser(ps, "submit-page", "Fetch the submit-context metadata for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submit context should be fetched.")
    pa.add_argument("--full", action="store_true", help="Print the raw submit-context payload.")
    pa.set_defaults(func=problem_submit_page)
    pa = add_cli_parser(ps, "submit", "Submit source code, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    submit_group = pa.add_mutually_exclusive_group(required=True)
    submit_group.add_argument("--code", help="Source code text, or @file to read code from a file.")
    submit_group.add_argument("--code-file", help="Source code file path.")
    submit_group.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    submit_group.add_argument("--prompt-file", help="Promptly submission file path.")
    submit_group.add_argument("--file", help="Written-homework PDF or ZIP file path.")
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
    pa = add_cli_parser(ps, "create-form", "Fetch the administrator problem-creation form metadata.")
    pa.add_argument("--full", action="store_true", help="Print the raw form payload, including long default prompts.")
    pa.set_defaults(func=problem_create_form)
    pa = add_cli_parser(ps, "create", "Create a programming or written-homework problem.")
    pa.add_argument("--title", required=True, help="Problem title.")
    pa.add_argument("--content", required=True, help="Problem statement Markdown text, or @markdown-file.")
    pa.add_argument("--type", choices=["1", "2"], default="1", help="Problem type: 1=programming, 2=written homework.")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"], default="matlab", help="Programming language for programming problems.")
    pa.add_argument(
        "--time-limit-ms", "--time-limit",
        dest="time_limit",
        type=int,
        default=2000,
        help="Per-test-case time limit for programming problems, in milliseconds.",
    )
    pa.add_argument("--submission-limit", type=int, default=10, help="Maximum number of submissions allowed per regular student.")
    pa.add_argument("--initial-code", default="", help="Initial code prefilled on the submit page, or @file.")
    pa.add_argument(
        "--test-code",
        default="",
        help=(
            "Helper code for interactive or special judging, or @file. If it contains %%%%user_code_here, "
            "the student's submitted code is pasted at that marker before judging. Usually empty for standard problems."
        ),
    )
    pa.add_argument("--forbidden-func", default="", help="Comma-separated forbidden function names. Matching submissions are judged Forbidden.")
    pa.add_argument(
        "--programming-grading-mode",
        type=int,
        default=1,
        help="Programming grading mode: 1=standard code judging, 2=program-output image grading, 3=Promptly prompt judging.",
    )
    pa.add_argument("--programming-grading-model", help="Model identifier for programming image grading or Promptly review/code generation.")
    pa.add_argument("--programming-output-filename", help="Expected output image filename in programming image-grading mode.")
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, default=1, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-model", help="Model identifier for AI grading of written homework.")
    pa.add_argument("--written-grading-prompt", default="", help="Rubric for AI grading of written homework, or @file.")
    pa.set_defaults(func=problem_create)
    pa = add_cli_parser(ps, "edit-form", "Fetch administrator edit-form metadata for an existing problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose edit form should be fetched.")
    pa.add_argument("--full", action="store_true", help="Print the raw edit form payload, including long text fields.")
    pa.set_defaults(func=problem_edit_form)
    pa = add_cli_parser(ps, "edit", "Edit an existing programming or written-homework problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to edit.")
    pa.add_argument("--title", help="Problem title. Omit to keep the current value.")
    pa.add_argument("--content", help="Problem statement Markdown text, or @markdown-file. Omit to keep the current value.")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"], help="Programming language. Omit to keep the current value.")
    pa.add_argument(
        "--time-limit-ms", "--time-limit",
        dest="time_limit",
        type=int,
        help="Per-test-case time limit for programming problems, in milliseconds. Omit to keep the current value.",
    )
    pa.add_argument("--submission-limit", type=int, help="Maximum submissions allowed per regular student. Omit to keep the current value.")
    pa.add_argument("--initial-code", help="Initial code prefilled on the submit page, or @file. Omit to keep the current value.")
    pa.add_argument(
        "--test-code",
        help=(
            "Helper code for interactive or special judging, or @file. If it contains %%%%user_code_here, "
            "the student's submitted code is pasted at that marker before judging. Omit to keep the current value."
        ),
    )
    pa.add_argument("--forbidden-func", help="Comma-separated forbidden function names. Pass an empty string to clear.")
    pa.add_argument(
        "--programming-grading-mode",
        type=int,
        help="Programming grading mode: 1=standard code judging, 2=program-output image grading, 3=Promptly prompt judging.",
    )
    pa.add_argument("--programming-grading-model", help="Model identifier for programming image grading or Promptly review/code generation.")
    pa.add_argument("--programming-output-filename", help="Expected output image filename in programming image-grading mode.")
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-model", help="Model identifier for AI grading of written homework.")
    pa.add_argument("--written-grading-prompt", help="Rubric for AI grading of written homework, or @file.")
    pa.set_defaults(func=problem_edit)
    pa = add_cli_parser(ps, "delete", "Delete a problem by ID.")
    pa.add_argument("problem_id", type=int, help="Problem ID to delete.")
    pa.set_defaults(func=problem_delete)
    pa = add_cli_parser(ps, "upload-testdata", "Upload a ZIP archive of test data for a programming problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose test data should be replaced or uploaded.")
    pa.add_argument("zip", help="Path to the ZIP archive containing test data files.")
    pa.set_defaults(func=problem_upload_testdata)
    pa = add_cli_parser(ps, "rejudge", "Start a rejudge task for all submissions of one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to rejudge.")
    pa.set_defaults(func=problem_rejudge)
    pa = add_cli_parser(ps, "rejudge-status", "Check rejudge progress for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose rejudge status should be checked.")
    pa.set_defaults(func=problem_rejudge_status)
    pa = add_cli_parser(ps, "rejudge-time-range", "Start a rejudge task for submissions created within a time range.")
    pa.add_argument("--start", required=True, help="Inclusive start time, formatted as YYYY-MM-DDTHH:MM.")
    pa.add_argument("--end", required=True, help="Exclusive end time, formatted as YYYY-MM-DDTHH:MM.")
    pa.add_argument("--confirm-total", type=int, help="Expected number of affected submissions; the server may require this safety confirmation.")
    pa.set_defaults(func=problem_rejudge_time_range)
    pa = add_cli_parser(ps, "rejudge-time-range-status", "Check progress for the most recent time-range rejudge task.")
    pa.set_defaults(func=problem_rejudge_time_range_status)
    pa = add_cli_parser(ps, "agent-run-status", "Fetch JSON status for a problem-solving or test-data-generation agent task.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.set_defaults(func=problem_agent_run_status)
    pa = add_cli_parser(ps, "agent-run", "Fetch JSON status for an agent task run.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.set_defaults(func=problem_agent_run_page)
    pa = add_cli_parser(ps, "agent-run-stream", "Fetch recent stream lines for an agent task run.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.add_argument("--full", action="store_true", help="Print raw stream lines instead of the default agent-status summary.")
    pa.set_defaults(func=problem_agent_run_stream)
    pa = add_cli_parser(ps, "agent-tasks", "List recent problem-solving and test-data-generation agent tasks.")
    pa.set_defaults(func=problem_agent_tasks)
    pa = add_cli_parser(ps, "agent-solve", "Start an AI agent task to solve a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for the agent to solve.")
    pa.add_argument("--extra-prompt", default="", help="Additional instruction text to pass to the problem-solving agent.")
    pa.set_defaults(func=problem_agent_solve)
    pa = add_cli_parser(ps, "agent-generate-data", "Start an AI agent task to generate test data for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for which test data should be generated.")
    pa.add_argument("--count", type=int, required=True, help="Number of test cases or data files to request from the agent.")
    pa.add_argument("--standard-code", required=True, help="Reference solution code text, or @file to read it from a file.")
    pa.add_argument("--data-requirement", default="", help="Additional natural-language requirements for generated test data.")
    pa.set_defaults(func=problem_agent_generate_data)
    pa = add_cli_parser(ps, "scores", "Fetch score records for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose scores should be returned.")
    pa.set_defaults(func=problem_scores)
