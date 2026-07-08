from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import common
from .common import *  # noqa: F401,F403 - command modules share the CLI helper surface.


def _necessary_submission_rows(rows: Any, *, include_problem_id: bool = False) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        item: Dict[str, Any] = {}
        for key in ("id", "username", "created_at"):
            if key in row:
                item[key] = row[key]
        if include_problem_id and "problem_id" in row:
            item["problem_id"] = row["problem_id"]
        if "problem_title" in row or "display_problem_title" in row:
            item["problem_title"] = row.get("problem_title") or row.get("display_problem_title")
        for key in ("status", "score", "is_ac", "detail_url"):
            if key in row:
                item[key] = row[key]
        out.append(item)
    return out


def necessary_submission_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "count", "page", "per_page", "scope", "total_pages"):
        if key in payload:
            necessary[key] = payload[key]
    necessary["submissions"] = _necessary_submission_rows(payload.get("submissions"), include_problem_id=True)
    return necessary


def add_limit_metadata(payload: Any, limit: Optional[int]) -> Any:
    if isinstance(payload, dict) and limit is not None:
        payload["limit"] = limit
        rows = payload.get("submissions")
        if isinstance(rows, list):
            payload["returned_count"] = len(rows)
    return payload


def necessary_submission_problem_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "problem_id", "count", "page", "per_page", "total_pages"):
        if key in payload:
            necessary[key] = payload[key]
    necessary["submissions"] = _necessary_submission_rows(payload.get("submissions"))
    return necessary


def submission_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/submissions", params=params)
    common.output_projected_json_response(
        resp,
        lambda payload: add_limit_metadata(necessary_submission_list_payload(payload), args.limit),
    )


def submission_problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/problems/{args.problem_id}/submissions", params=params)
    common.output_projected_json_response(
        resp,
        lambda payload: add_limit_metadata(necessary_submission_problem_payload(payload), args.limit),
    )


def submission_status_cmd(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_status/{args.submission_id}")
    print_or_save_response(resp, project_json=False)


def submission_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_status_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def submission_detail_cmd(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/submissions/{args.submission_id}")
    print_or_save_response(resp, allow_redirect=False, project_json=False)


def submission_last_code(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/get_last_submission_code/{args.problem_id}")
    ensure_ok(resp, allow_redirect=False)
    if args.output:
        if not response_is_json(resp):
            raise CliError("Server did not return JSON for last-code.")
        payload = resp.json()
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(payload.get("code") or ""), encoding="utf-8")
        output_json({
            "success": True,
            "path": str(target),
            "bytes": target.stat().st_size,
            "submission_id": payload.get("submission_id"),
        })
        return
    print_or_save_response(resp, allow_redirect=False, project_json=False)


def submission_output_image(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_output_image/{args.submission_id}/{args.test_index}")
    print_or_save_response(resp, output=args.output or ".")


def submission_download_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/download_submission_file/{args.submission_id}")
    print_or_save_response(resp, output=args.output or ".")


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    submission = add_cli_parser(sub, "submission", "Inspect submissions, status snapshots, generated output files, and saved source code.")
    ss = submission.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ss, "list", "List submissions visible to the current administrator session.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
    pa = add_cli_parser(ss, "problem", "List submissions for one programming or written problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submissions should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_problem_list)
    pa = add_cli_parser(ss, "status", "Fetch the current JSON status snapshot for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_status_cmd)
    pa = add_cli_parser(ss, "stream", "Fetch recent live evaluation stream lines for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=submission_stream)
    pa = add_cli_parser(ss, "detail", "Fetch submission details as JSON.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_detail_cmd)
    pa = add_cli_parser(ss, "last-code", "Fetch the current user's last submitted code for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose latest code should be returned.")
    pa.add_argument("-o", "--output", help="Write the source code to this path.")
    pa.set_defaults(func=submission_last_code)
    pa = add_cli_parser(ss, "output-image", "Download an output image produced by an image-grading submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID that produced the image.")
    pa.add_argument("test_index", type=int, help="One-based test-point index of the image to download, matching the server route.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded image. If omitted, a default filename is used.")
    pa.set_defaults(func=submission_output_image)
    pa = add_cli_parser(ss, "download-file", "Download the original file attached to a written-homework submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose uploaded file should be downloaded.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded file. If omitted, a server-provided filename is used.")
    pa.set_defaults(func=submission_download_file)
