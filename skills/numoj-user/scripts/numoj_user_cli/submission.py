from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from . import common


def _necessary_submission_rows(rows: Any, *, include_problem_id: bool = False) -> List[Dict[str, Any]]:
    necessary_rows: List[Dict[str, Any]] = []
    if not isinstance(rows, list):
        return necessary_rows
    for row in rows:
        if not isinstance(row, dict):
            continue
        necessary_row: Dict[str, Any] = {}
        for key in ("id", "created_at"):
            if key in row:
                necessary_row[key] = row[key]
        if include_problem_id and "problem_id" in row:
            necessary_row["problem_id"] = row["problem_id"]
        if "problem_title" in row or "display_problem_title" in row:
            necessary_row["problem_title"] = row.get("problem_title") or row.get("display_problem_title")
        for key in ("status", "score", "is_ac"):
            if key in row:
                necessary_row[key] = row[key]
        necessary_rows.append(necessary_row)
    return necessary_rows


def necessary_submission_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("count", "page", "per_page", "total_pages"):
        if key in payload:
            necessary[key] = payload[key]
    necessary["submissions"] = _necessary_submission_rows(payload.get("submissions"), include_problem_id=True)
    return necessary


def necessary_submission_problem_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("problem_id", "count", "page", "per_page", "total_pages"):
        if key in payload:
            necessary[key] = payload[key]
    necessary["submissions"] = _necessary_submission_rows(payload.get("submissions"))
    return necessary


def necessary_submission_detail_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    submission = payload.get("submission")
    if isinstance(submission, dict):
        necessary_submission: Dict[str, Any] = {}
        for key in (
            "id",
            "problem_id",
            "problem_title",
            "problem_type",
            "code",
            "prompt_text",
            "generated_from_prompt",
            "prompt_generation_error",
            "promptly_review_reply",
            "status",
            "score",
            "created_at",
        ):
            if key in submission:
                necessary_submission[key] = submission[key]
        necessary["submission"] = necessary_submission
    test_points = payload.get("test_points")
    if isinstance(test_points, list):
        necessary["test_points"] = test_points
    for key in ("submission_latex_text", "submission_latex_error"):
        value = payload.get(key)
        if value:
            necessary[key] = value
    return necessary


def necessary_last_code_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "code", "submission_id"):
        if key in payload:
            necessary[key] = payload[key]
    return necessary


def submission_list(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = common.client_from_args(args).request("GET", "/api/submissions", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_submission_list_payload(resp.json()))
        return
    print(resp.text.strip())


def submission_problem_list(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = common.client_from_args(args).request("GET", f"/api/problems/{args.problem_id}/submissions", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_submission_problem_payload(resp.json()))
        return
    print(resp.text.strip())


def submission_status_cmd(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/submissions/{args.submission_id}/status")
    common.print_or_save_response(resp)


def submission_stream(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/submissions/{args.submission_id}/events", stream=True)
    common.print_stream_lines(resp, max_lines=args.max_lines)


def submission_detail(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/submissions/{args.submission_id}")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_submission_detail_payload(resp.json()))
        return
    print(resp.text.strip())


def submission_last_code(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/problems/{args.problem_id}/last-submission-code")
    if not getattr(args, "output", None):
        common.ensure_ok(resp, allow_redirect=False)
        if common.response_is_json(resp):
            common.output_json(necessary_last_code_payload(resp.json()))
            return
        print(resp.text.strip())
        return
    common.ensure_ok(resp, allow_redirect=False)
    if not common.response_is_json(resp):
        raise common.CliError("Expected JSON response with a code field.")
    payload = resp.json()
    if not isinstance(payload, dict) or "code" not in payload:
        raise common.CliError("Response does not contain a code field.")
    code = str(payload.get("code") or "")
    target = Path(args.output).expanduser()
    if target.is_dir():
        target = target / f"problem_{args.problem_id}_last_code.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(code, encoding="utf-8")
    output: Dict[str, Any] = {
        "success": True,
        "path": str(target),
        "bytes": len(code.encode("utf-8")),
    }
    if "submission_id" in payload:
        output["submission_id"] = payload["submission_id"]
    common.output_json(output)


def submission_output_image(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/submissions/{args.submission_id}/outputs/{args.test_index}/image")
    common.print_or_save_response(resp, output=args.output or ".")


def register(subparsers: argparse._SubParsersAction) -> None:
    submission = common.add_cli_parser(subparsers, "submission", "Inspect personal submissions, status snapshots, output files, and saved source code.")
    sub_sub = submission.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(sub_sub, "list", "List submissions visible to the current user.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
    pa = common.add_cli_parser(sub_sub, "problem", "List submissions for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submissions should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_problem_list)
    pa = common.add_cli_parser(sub_sub, "status", "Fetch the current JSON status snapshot for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_status_cmd)
    pa = common.add_cli_parser(sub_sub, "stream", "Fetch recent live evaluation stream lines for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=submission_stream)
    pa = common.add_cli_parser(sub_sub, "detail", "Fetch submission details as JSON.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_detail)
    pa = common.add_cli_parser(sub_sub, "last-code", "Fetch the current user's last submitted code for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose latest code should be returned.")
    pa.add_argument("-o", "--output", help="Write only the response code field to this file. If a directory is given, a default filename is used.")
    pa.set_defaults(func=submission_last_code)
    pa = common.add_cli_parser(sub_sub, "output-image", "Download an output image produced by an image-grading submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID that produced the image.")
    pa.add_argument("test_index", type=int, help="Zero-based or server-defined test-point index of the image to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded image. If omitted, a default filename is used.")
    pa.set_defaults(func=submission_output_image)
