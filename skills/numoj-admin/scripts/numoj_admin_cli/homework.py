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


def necessary_homework_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("selected_class", "classes"):
        if key in payload:
            necessary[key] = payload[key]
    homeworks = payload.get("homeworks")
    if homeworks is None:
        homeworks = payload.get("homework_list")
    if homeworks is not None:
        necessary["homeworks"] = homeworks
    return necessary


def necessary_plagiarism_records_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    records: List[Dict[str, Any]] = []
    for row in payload.get("records") or []:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        item.pop("matched_usernames_text", None)
        records.append(item)
    return {"success": payload.get("success", True), "count": payload.get("count", len(records)), "records": records}


def homework_add(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data = {"class_en": args.class_en, "ddl": args.ddl}
    if args.problem_id is not None:
        data["problem_id"] = str(args.problem_id)
    if args.ranking_competition_id is not None:
        data["ranking_competition_id"] = str(args.ranking_competition_id)
    resp = client.request("POST", "/admin/add_homework", data=data)
    print_or_save_response(resp)


def homework_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/homework", params={"sclass": args.class_en} if args.class_en else None)
    common.output_projected_json_response(resp, necessary_homework_list_payload, allow_redirect=True)


def homework_update_ddl(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"class_en": args.class_en, "homework_id": args.homework_id, "new_ddl": args.ddl}
    resp = client.request("POST", "/admin/update_ddl", json=payload)
    print_or_save_response(resp)


def homework_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"class_en": args.class_en, "homework_id": args.homework_id}
    resp = client.request("POST", "/admin/delete_homework", json=payload)
    print_or_save_response(resp)


def homework_export_scores(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    output = args.output or f"{args.class_en}_scores.csv"
    resp = client.request("GET", "/export_scores", params={"sclass": args.class_en})
    print_or_save_response(resp, output=output)


def homework_export_codes(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/export_student_codes", json={"sclass": args.class_en})
    print_or_save_response(resp)


def homework_export_progress(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/export_progress/{args.task_id}")
    print_or_save_response(resp)


def homework_download_export(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    output = args.output or "student_codes.zip"
    resp = client.request("GET", f"/download_export/{args.task_id}")
    print_or_save_response(resp, output=output)


def homework_plagiarism_start(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    problem_ids = parse_int_csv(args.problem_ids) if args.problem_ids else []
    targets = [item.strip() for item in str(args.targets or "").split(",") if item.strip()]
    if not problem_ids and not targets:
        raise CliError("Provide --problem-ids or --targets.")
    payload = {
        "class_en": args.class_en,
        "mode": args.mode,
        "threshold": args.threshold,
    }
    if targets:
        payload["targets"] = targets
    else:
        payload["problem_ids"] = problem_ids
    resp = client.request("POST", "/api/admin/homework/plagiarism/start", json=payload)
    ensure_ok(resp)
    if not response_is_json(resp):
        raise CliError("Server did not return JSON for plagiarism-start.")
    start_payload = resp.json()
    if not args.wait:
        output_json(common.necessary_response_payload(start_payload))
        return

    if not start_payload.get("success"):
        output_json(common.necessary_response_payload(start_payload))
        return

    task_id = start_payload.get("task_id")
    if not task_id:
        raise CliError(f"Missing task_id in response: {start_payload}")

    deadline = time.time() + float(args.timeout)
    last_payload: Dict[str, Any] = start_payload
    while time.time() < deadline:
        progress_resp = client.request("GET", f"/api/admin/homework/plagiarism/progress/{task_id}")
        if progress_resp.status_code == 404:
            last_payload = {
                "success": False,
                "task_id": task_id,
                "start": start_payload,
                "progress": None,
                "message": "Progress is not visible yet.",
            }
            time.sleep(max(0.1, float(args.poll_interval)))
            continue
        ensure_ok(progress_resp)
        if not response_is_json(progress_resp):
            raise CliError("Server did not return JSON for plagiarism progress.")
        progress_payload = progress_resp.json()
        last_payload = {
            "success": bool(progress_payload.get("success")),
            "task_id": task_id,
            "start": start_payload,
            "progress": progress_payload.get("progress"),
        }
        progress = progress_payload.get("progress") or {}
        stage = progress.get("stage")
        if stage == "completed":
            output_json(common.necessary_response_payload(last_payload))
            return
        if stage == "error":
            output_json(common.necessary_response_payload(last_payload))
            return
        time.sleep(max(0.1, float(args.poll_interval)))

    raise CliError(f"Timed out waiting for plagiarism task {task_id}: {last_payload}")


def homework_plagiarism_progress(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/admin/homework/plagiarism/progress/{args.task_id}")
    print_or_save_response(resp)


def homework_plagiarism_records(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/homework/plagiarism/records", params={"class_en": args.class_en})
    common.output_projected_json_response(resp, necessary_plagiarism_records_payload, allow_redirect=True)


def homework_plagiarism_download(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    output = args.output or f"{args.class_en}_plagiarism_records.csv"
    resp = client.request("GET", "/api/admin/homework/plagiarism/download", params={"class_en": args.class_en})
    print_or_save_response(resp, output=output)


def homework_plagiarism_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"class_en": args.class_en, "record_ids": parse_int_csv(args.record_ids)}
    resp = client.request("POST", "/api/admin/homework/plagiarism/delete", json=payload)
    print_or_save_response(resp)


def homework_upload_exam(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"file": require_file(args.file)}
    try:
        resp = client.request(
            "POST",
            "/admin/upload_exam_scores",
            data={"class_en": args.class_en},
            files=files,
        )
    finally:
        close_files(files)
    print_or_save_response(resp)


def class_adjust(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/admin/class_adjust", data={"enabled": "1" if args.enabled else "0"})
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    hw = add_cli_parser(sub, "homework", "Manage class homework assignments, exports, exam scores, and class adjustment settings.")
    hs = hw.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(hs, "list", "List homework assigned to a class or visible classes.")
    pa.add_argument("--class-en", help="English class identifier to filter by, e.g. C2026A.")
    pa.set_defaults(func=homework_list)
    pa = add_cli_parser(hs, "add", "Assign a problem or ranking competition as homework for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier receiving the homework, e.g. C2026A.")
    pa.add_argument("--ddl", required=True, help="Homework deadline, formatted as YYYY-MM-DDTHH:MM or a MySQL datetime string.")
    group = pa.add_mutually_exclusive_group(required=True)
    group.add_argument("--problem-id", type=int, help="Problem ID to assign as homework.")
    group.add_argument("--ranking-competition-id", type=int, help="Ranking competition ID to assign as homework.")
    pa.set_defaults(func=homework_add)
    pa = add_cli_parser(hs, "update-ddl", "Update the deadline for one homework assignment.")
    pa.add_argument("--class-en", required=True, help="English class identifier that owns the homework.")
    pa.add_argument("--homework-id", required=True, help="Homework assignment ID to update.")
    pa.add_argument("--ddl", required=True, help="New deadline, formatted as YYYY-MM-DDTHH:MM or a MySQL datetime string.")
    pa.set_defaults(func=homework_update_ddl)
    pa = add_cli_parser(hs, "delete", "Delete one homework assignment from a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier that owns the homework.")
    pa.add_argument("--homework-id", required=True, help="Homework assignment ID to delete.")
    pa.set_defaults(func=homework_delete)
    pa = add_cli_parser(hs, "export-scores", "Export homework scores for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose scores should be exported.")
    pa.add_argument("-o", "--output", help="Path to write the exported score file.")
    pa.set_defaults(func=homework_export_scores)
    pa = add_cli_parser(hs, "export-codes", "Start an asynchronous export of submitted code for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose submitted code should be exported.")
    pa.set_defaults(func=homework_export_codes)
    pa = add_cli_parser(hs, "export-progress", "Check progress for a class code-export task.")
    pa.add_argument("task_id", help="Export task ID returned by export-codes.")
    pa.set_defaults(func=homework_export_progress)
    pa = add_cli_parser(hs, "download-export", "Download the archive generated by a class code-export task.")
    pa.add_argument("task_id", help="Export task ID returned by export-codes.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded archive.")
    pa.set_defaults(func=homework_download_export)
    pa = add_cli_parser(hs, "plagiarism-start", "Start an asynchronous plagiarism check for selected class homework targets.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose homework submissions should be checked.")
    pa.add_argument("--mode", choices=("threshold", "byte"), default="threshold", help="Comparison mode: normalized threshold or byte-identical.")
    pa.add_argument("--threshold", type=float, default=90, help="Threshold percentage or ratio for threshold mode.")
    pa.add_argument("--problem-ids", help="Comma-separated homework problem IDs to compare.")
    pa.add_argument("--targets", help="Comma-separated targets such as problem:42,ranking:3.")
    pa.add_argument("--wait", action="store_true", help="Poll until the plagiarism task finishes.")
    pa.add_argument("--poll-interval", type=float, default=0.5, help="Seconds between progress polls when --wait is used.")
    pa.add_argument("--timeout", type=float, default=120.0, help="Maximum seconds to wait when --wait is used.")
    pa.set_defaults(func=homework_plagiarism_start)
    pa = add_cli_parser(hs, "plagiarism-progress", "Check progress for a plagiarism task.")
    pa.add_argument("task_id", help="Plagiarism task ID returned by plagiarism-start.")
    pa.set_defaults(func=homework_plagiarism_progress)
    pa = add_cli_parser(hs, "plagiarism-records", "List plagiarism records for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose records should be listed.")
    pa.set_defaults(func=homework_plagiarism_records)
    pa = add_cli_parser(hs, "plagiarism-download", "Download plagiarism records for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose records should be downloaded.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded CSV.")
    pa.set_defaults(func=homework_plagiarism_download)
    pa = add_cli_parser(hs, "plagiarism-delete", "Delete selected plagiarism records for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose records should be deleted.")
    pa.add_argument("--record-ids", required=True, help="Comma-separated plagiarism record IDs to delete.")
    pa.set_defaults(func=homework_plagiarism_delete)
    pa = add_cli_parser(hs, "upload-exam", "Upload a final-exam score file for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose exam scores should be uploaded.")
    pa.add_argument("file", help="Path to the exam-score file to upload.")
    pa.set_defaults(func=homework_upload_exam)
    pa = add_cli_parser(hs, "class-adjust", "Enable or disable class adjustment mode.")
    pa.add_argument("enabled", type=lambda x: str(x).lower() in ("1", "true", "yes", "on"), help="Boolean switch: one of 1/0, true/false, yes/no, or on/off.")
    pa.set_defaults(func=class_adjust)
