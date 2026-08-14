from __future__ import annotations

import argparse
import json
import time
from pathlib import Path, PurePosixPath
from typing import Any, Dict

from . import common


LEAN_MANIFEST_FILENAME = "numoj-lean.json"


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


def _lean_manifest(problem_id: int, workspace: Dict[str, Any]) -> Dict[str, Any]:
    ordered = sorted(
        workspace.get("files") or [],
        key=lambda item: int(item.get("build_order") or 0),
    )
    return {
        "schema_version": int(workspace.get("schema_version") or 1),
        "problem_id": int(problem_id),
        "revision": str(workspace["revision"]),
        "default_file": str(workspace.get("default_file") or ""),
        "files": [
            {"path": str(item.get("path") or ""), "mode": str(item.get("mode") or "")}
            for item in ordered
        ],
        "build_order": [str(item.get("path") or "") for item in ordered],
        "verification": dict(workspace.get("verification") or {}),
    }


def _write_lean_workspace(
    *, problem_id: int, workspace: Dict[str, Any], directory: str, force: bool
) -> Dict[str, Any]:
    root = Path(directory).expanduser().resolve()
    manifest = _lean_manifest(problem_id, workspace)
    outputs = [root / LEAN_MANIFEST_FILENAME]
    for item in workspace.get("files") or []:
        outputs.append(root.joinpath(*_lean_relative_path(item.get("path")).parts))
    existing = [path for path in outputs if path.exists()]
    if existing and not force:
        raise common.CliError(
            f"Refusing to overwrite {existing[0]}; pass --force to replace the initialized workspace."
        )
    root.mkdir(parents=True, exist_ok=True)
    for item in workspace.get("files") or []:
        target = root.joinpath(*_lean_relative_path(item.get("path")).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(item.get("content") or ""), encoding="utf-8")
    (root / LEAN_MANIFEST_FILENAME).write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "success": True,
        "problem_id": int(problem_id),
        "revision": manifest["revision"],
        "path": str(root),
        "default_file": manifest["default_file"],
        "files": manifest["files"],
    }


def _read_lean_submission(directory: str, *, problem_id: int) -> Dict[str, Any]:
    root = Path(directory).expanduser().resolve()
    manifest_path = root / LEAN_MANIFEST_FILENAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise common.CliError(f"Lean workspace is missing {manifest_path}.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise common.CliError(f"Cannot read Lean workspace manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or not str(manifest.get("revision") or "").strip():
        raise common.CliError("Run problem lean-init first; the workspace manifest has no server revision.")
    manifest_problem_id = manifest.get("problem_id")
    if manifest_problem_id is not None and int(manifest_problem_id) != int(problem_id):
        raise common.CliError(
            f"This workspace belongs to problem {manifest_problem_id}, not problem {problem_id}."
        )
    descriptors = manifest.get("files")
    if not isinstance(descriptors, list):
        raise common.CliError("Lean workspace manifest.files must be an array.")
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
        raise common.CliError("Lean workspace manifest does not declare any writable files.")
    return {"revision": str(manifest["revision"]), "files": files}


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


def problem_lean_workspace(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    common.ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if common.response_is_json(resp) else {}
    workspace = _lean_workspace_from_payload(payload)
    common.output_json({
        "success": True,
        "problem_id": int(args.problem_id),
        "lean_workspace": workspace if args.full else _lean_workspace_summary(workspace),
    })


def problem_lean_init(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    common.ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if common.response_is_json(resp) else {}
    workspace = _lean_workspace_from_payload(payload)
    common.output_json(_write_lean_workspace(
        problem_id=args.problem_id,
        workspace=workspace,
        directory=args.directory,
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
    problem = common.add_cli_parser(subparsers, "problem", "Browse problems and submit code, Lean workspaces, Promptly prompts, or written-homework files.")
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
    pa = common.add_cli_parser(problem_sub, "lean-workspace", "Inspect the current Lean 4 workspace revision and file map.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID to inspect.")
    pa.add_argument("--full", action="store_true", help="Include all source-file contents and verification metadata.")
    pa.set_defaults(func=problem_lean_workspace)
    pa = common.add_cli_parser(problem_sub, "lean-init", "Initialize a local directory from the current Lean 4 workspace.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID to initialize.")
    pa.add_argument("directory", help="Directory to populate with the complete Lean 4 workspace.")
    pa.add_argument("--force", action="store_true", help="Replace files already present at the initialized paths.")
    pa.set_defaults(func=problem_lean_init)
    pa = common.add_cli_parser(problem_sub, "submit", "Submit source code, a Lean workspace, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    sg = pa.add_mutually_exclusive_group(required=True)
    sg.add_argument("--code", help="Source code text, or @file to read code from a file.")
    sg.add_argument("--code-file", help="Source code file path.")
    sg.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    sg.add_argument("--prompt-file", help="Promptly submission file path.")
    sg.add_argument("--file", help="Written-homework PDF or ZIP file path.")
    sg.add_argument("--workspace", help="Initialized Lean 4 workspace directory containing numoj-lean.json.")
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
