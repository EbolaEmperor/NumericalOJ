from __future__ import annotations

import argparse
import json
import time
from pathlib import Path, PurePosixPath
from typing import Any, Dict

from . import common


PROBLEM_SNAPSHOT_FILENAME = "numoj-problem.json"
LEGACY_LEAN_MANIFEST_FILENAME = "numoj-lean.json"

_SOURCE_FILENAMES = {
    "matlab": "solution.m",
    "octave": "solution.m",
    "c": "solution.c",
    "cpp": "solution.cpp",
    "c++": "solution.cpp",
    "python": "solution.py",
    "python3": "solution.py",
    "lean": "solution.lean",
    "lean4": "solution.lean",
}


def _lean_workspace_from_payload(payload: Any) -> Dict[str, Any]:
    workspace = payload.get("lean_workspace") if isinstance(payload, dict) else None
    if not isinstance(workspace, dict) or not workspace.get("revision"):
        raise common.CliError("This problem does not have a Lean 4 workspace.")
    if not isinstance(workspace.get("files"), list):
        raise common.CliError("The server returned an invalid Lean 4 workspace.")
    return workspace


def _lean_relative_path(raw_path: Any) -> PurePosixPath:
    path = PurePosixPath(str(raw_path or ""))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise common.CliError(f"Invalid Lean workspace path: {raw_path!r}")
    return path


def _lean_snapshot(workspace: Dict[str, Any]) -> Dict[str, Any]:
    ordered = sorted(
        workspace.get("files") or [],
        key=lambda item: int(item.get("build_order") or 0),
    )
    return {
        "schema_version": int(workspace.get("schema_version") or 1),
        "revision": str(workspace["revision"]),
        "default_file": str(workspace.get("default_file") or ""),
        "files": [
            {
                "path": str(item.get("path") or ""),
                "mode": str(item.get("mode") or ""),
                "build_order": int(item.get("build_order") or 0),
            }
            for item in ordered
        ],
        "build_order": [str(item.get("path") or "") for item in ordered],
        "verification": dict(workspace.get("verification") or {}),
    }


def _problem_snapshot(problem_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    problem = payload.get("problem")
    if not isinstance(problem, dict):
        raise common.CliError("The server returned an invalid problem.")
    submit = payload.get("submit")
    submit_kind = (
        str(submit.get("input_kind") or "").strip()
        if isinstance(submit, dict)
        else ""
    )
    snapshot = {
        "schema_version": 1,
        "problem_id": int(problem_id),
        "submit_kind": submit_kind,
        "problem": {
            "title": str(problem.get("title") or ""),
            "lang": str(problem.get("lang") or ""),
            "type": int(problem.get("type") or 0),
        },
    }
    workspace = payload.get("lean_workspace")
    if isinstance(workspace, dict) and workspace.get("revision"):
        snapshot["lean_workspace"] = _lean_snapshot(workspace)
    return snapshot


def _initial_code_filename(problem: Dict[str, Any]) -> str:
    language = str(problem.get("lang") or "").strip().lower()
    return _SOURCE_FILENAMES.get(language, "solution.txt")


def _write_problem_download(
    *, problem_id: int, payload: Dict[str, Any], directory: str, force: bool
) -> Dict[str, Any]:
    root = Path(directory).expanduser().resolve()
    snapshot = _problem_snapshot(problem_id, payload)
    problem = payload["problem"]
    files: Dict[PurePosixPath, str] = {
        PurePosixPath("PROBLEM.md"): str(problem.get("content") or ""),
    }

    workspace = payload.get("lean_workspace")
    if isinstance(workspace, dict) and workspace.get("revision"):
        workspace = _lean_workspace_from_payload(payload)
        for item in workspace.get("files") or []:
            relative = _lean_relative_path(item.get("path"))
            files[relative] = str(item.get("content") or "")
    else:
        initial_code = str(payload.get("initial_code") or "")
        if initial_code:
            files[PurePosixPath(_initial_code_filename(problem))] = initial_code

    snapshot["resources"] = [path.as_posix() for path in files]
    files[PurePosixPath(PROBLEM_SNAPSHOT_FILENAME)] = (
        json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"
    )
    outputs = [root.joinpath(*relative.parts) for relative in files]
    existing = [path for path in outputs if path.exists()]
    if existing and not force:
        raise common.CliError(
            f"Refusing to overwrite {existing[0]}; pass --force to replace downloaded files."
        )
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        target = root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return {
        "success": True,
        "problem_id": int(problem_id),
        "path": str(root),
        "files": [relative.as_posix() for relative in files],
    }


def _read_lean_submission(directory: str, *, problem_id: int) -> Dict[str, Any]:
    root = Path(directory).expanduser().resolve()
    manifest_path = root / PROBLEM_SNAPSHOT_FILENAME
    legacy = False
    if not manifest_path.exists():
        manifest_path = root / LEGACY_LEAN_MANIFEST_FILENAME
        legacy = True
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise common.CliError(
            f"Problem workspace is missing {root / PROBLEM_SNAPSHOT_FILENAME}. "
            "Run problem download first."
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise common.CliError(f"Cannot read problem snapshot {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise common.CliError(f"Problem snapshot {manifest_path} is invalid.")
    if legacy:
        workspace = manifest
    else:
        if str(manifest.get("submit_kind") or "") != "lean_workspace":
            raise common.CliError("This downloaded problem is not a Lean 4 workspace.")
        workspace = manifest.get("lean_workspace")
        if not isinstance(workspace, dict):
            raise common.CliError("The problem snapshot has no Lean 4 workspace metadata.")
    if not str(workspace.get("revision") or "").strip():
        raise common.CliError("The problem snapshot has no server revision.")
    manifest_problem_id = manifest.get("problem_id")
    if manifest_problem_id is not None and int(manifest_problem_id) != int(problem_id):
        raise common.CliError(
            f"This workspace belongs to problem {manifest_problem_id}, not problem {problem_id}."
        )
    descriptors = workspace.get("files")
    if not isinstance(descriptors, list):
        raise common.CliError("Lean workspace metadata.files must be an array.")
    files: Dict[str, str] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or descriptor.get("mode") != "writable":
            continue
        relative = _lean_relative_path(descriptor.get("path"))
        source = root.joinpath(*relative.parts)
        try:
            files[relative.as_posix()] = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise common.CliError(f"Cannot read writable Lean file {source}: {exc}") from exc
    if not files:
        raise common.CliError("Lean workspace metadata does not declare any writable files.")
    return {"revision": str(workspace["revision"]), "files": files}


def _lean_workspace_summary(workspace: Dict[str, Any]) -> Dict[str, Any]:
    summary = {
        key: workspace[key]
        for key in ("revision_number", "revision", "default_file")
        if key in workspace
    }
    summary["files"] = [
        {"path": item.get("path"), "mode": item.get("mode")}
        for item in workspace.get("files") or []
    ]
    return summary


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
    if isinstance(homeworks, list):
        return {"homeworks": homeworks}
    problems = payload.get("problems")
    if isinstance(problems, list):
        return {"homeworks": problems}
    merged_homeworks = []
    for class_block in payload.get("homeworks_by_class") or []:
        if not isinstance(class_block, dict):
            continue
        for row in class_block.get("hw_list") or []:
            if isinstance(row, dict):
                merged_homeworks.append(row)
    return {"homeworks": merged_homeworks}


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
    if isinstance(necessary.get("lean_workspace"), dict):
        necessary["lean_workspace"] = _lean_workspace_summary(necessary["lean_workspace"])
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


def problem_download(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    common.ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if common.response_is_json(resp) else {}
    if not isinstance(payload, dict):
        raise common.CliError("The server returned an invalid problem.")
    common.output_json(_write_problem_download(
        problem_id=args.problem_id,
        payload=payload,
        directory=args.output,
        force=args.force,
    ))


def problem_submit(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    context_resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    common.ensure_ok(context_resp, allow_redirect=False)
    context = context_resp.json() if common.response_is_json(context_resp) else {}
    input_kind = ((context.get("submit") or {}).get("input_kind") or "").strip().lower()

    workspace_directory = getattr(args, "workspace", None)
    if input_kind == "lean_workspace":
        if not workspace_directory:
            raise common.CliError("This Lean 4 problem requires --workspace.")
        if any(
            getattr(args, key, None)
            for key in ("file", "code", "code_file", "prompt", "prompt_file")
        ):
            raise common.CliError("This Lean 4 problem accepts a workspace directory, not code, prompt, or a file upload.")
        submission = _read_lean_submission(
            workspace_directory,
            problem_id=args.problem_id,
        )
        resp = client.request(
            "POST",
            f"/submit/{args.problem_id}",
            data={
                "lean_workspace": json.dumps(
                    submission,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            },
        )
    elif input_kind == "file":
        if not args.file:
            raise common.CliError("This problem requires --file.")
        if workspace_directory or args.code or args.code_file or args.prompt or args.prompt_file:
            raise common.CliError("This problem accepts a file submission, not code or prompt.")
        files = {"file": common.require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            common.close_files(files)
    elif input_kind == "prompt":
        if not (args.prompt or args.prompt_file):
            raise common.CliError("This Promptly problem requires --prompt or --prompt-file.")
        if workspace_directory or args.file or args.code or args.code_file:
            raise common.CliError("This Promptly problem accepts prompt text, not code or file.")
        prompt = Path(args.prompt_file).expanduser().read_text(encoding="utf-8") if args.prompt_file else common.read_text_value(args.prompt)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"prompt": prompt})
    else:
        if not (args.code or args.code_file):
            raise common.CliError("This programming problem requires --code or --code-file.")
        if workspace_directory or args.file or args.prompt or args.prompt_file:
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
    problem = common.add_cli_parser(subparsers, "problem", "Browse or download problems and submit code, Lean workspaces, Promptly prompts, or written-homework files.")
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
    pa = common.add_cli_parser(problem_sub, "download", "Download a visible problem statement and provided source files.")
    pa.add_argument("problem_id", type=int, help="Problem ID to download.")
    pa.add_argument("-o", "--output", required=True, help="Directory that receives PROBLEM.md, provided source files, and numoj-problem.json.")
    pa.add_argument("--force", action="store_true", help="Replace files that this download writes when they already exist.")
    pa.set_defaults(func=problem_download)
    pa = common.add_cli_parser(problem_sub, "submit", "Submit source code, a Lean workspace, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    sg = pa.add_mutually_exclusive_group(required=True)
    sg.add_argument("--code", help="Source code text, or @file to read code from a file.")
    sg.add_argument("--code-file", help="Source code file path.")
    sg.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    sg.add_argument("--prompt-file", help="Promptly submission file path.")
    sg.add_argument("--file", help="Written-homework PDF or ZIP file path.")
    sg.add_argument("--workspace", help="Downloaded Lean 4 problem directory containing numoj-problem.json.")
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
