from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from . import common
from .common import *  # noqa: F401,F403 - command modules share the CLI helper surface.


PROBLEM_LLM_ENDPOINT_ARGUMENTS = (
    (
        "output_image_grading_endpoint_id",
        "--output-image-grading-endpoint-id",
        "Endpoint for grading a programming problem's output image.",
    ),
    (
        "ocr_endpoint_id",
        "--ocr-endpoint-id",
        "Endpoint for OCR in written-homework grading.",
    ),
    (
        "text_grading_endpoint_id",
        "--text-grading-endpoint-id",
        "Endpoint for text or TeX written-homework grading.",
    ),
    (
        "direct_image_grading_endpoint_id",
        "--direct-image-grading-endpoint-id",
        "Endpoint for direct image written-homework grading.",
    ),
    (
        "review_endpoint_id",
        "--review-endpoint-id",
        "Endpoint for reviewing a Promptly submission.",
    ),
    (
        "code_generation_endpoint_id",
        "--code-generation-endpoint-id",
        "Endpoint for generating code from an accepted Promptly submission.",
    ),
)

_ALL_PROBLEM_LLM_ENDPOINT_KEYS = frozenset(item[0] for item in PROBLEM_LLM_ENDPOINT_ARGUMENTS)
_WRITTEN_LLM_ENDPOINT_KEYS = frozenset({
    "ocr_endpoint_id",
    "text_grading_endpoint_id",
    "direct_image_grading_endpoint_id",
})
_PROMPTLY_LLM_ENDPOINT_KEYS = frozenset({"review_endpoint_id", "code_generation_endpoint_id"})
_OUTPUT_IMAGE_LLM_ENDPOINT_KEYS = frozenset({"output_image_grading_endpoint_id"})

LEAN_MANIFEST_FILENAME = "numoj-lean.json"


def parse_problem_llm_endpoint_id(raw: str) -> Optional[int]:
    """Parse a positive endpoint ID; the literal ``none`` explicitly clears it."""

    value = str(raw or "").strip()
    if value.lower() == "none":
        return None
    try:
        endpoint_id = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("endpoint ID must be a positive integer or 'none'") from exc
    if endpoint_id <= 0 or str(endpoint_id) != value:
        raise argparse.ArgumentTypeError("endpoint ID must be a positive integer or 'none'")
    return endpoint_id


def _add_problem_llm_endpoint_args(parser: argparse.ArgumentParser, *, editing: bool) -> None:
    suffix = (
        " Omit to keep the current binding; pass 'none' to clear it."
        if editing
        else " Omit it (or pass 'none') to leave this feature unconfigured."
    )
    for dest, option, help_text in PROBLEM_LLM_ENDPOINT_ARGUMENTS:
        parser.add_argument(
            option,
            dest=dest,
            type=parse_problem_llm_endpoint_id,
            default=argparse.SUPPRESS,
            metavar="ID|none",
            help=help_text + suffix,
        )


def _allowed_problem_llm_endpoint_keys(problem_type: Any, programming_grading_mode: Any) -> frozenset[str]:
    try:
        normalized_type = int(problem_type)
    except (TypeError, ValueError):
        return _ALL_PROBLEM_LLM_ENDPOINT_KEYS
    if normalized_type == 2:
        return _WRITTEN_LLM_ENDPOINT_KEYS
    if normalized_type != 1:
        return frozenset()
    try:
        normalized_mode = int(programming_grading_mode)
    except (TypeError, ValueError):
        normalized_mode = 1
    return _PROMPTLY_LLM_ENDPOINT_KEYS if normalized_mode == 3 else _OUTPUT_IMAGE_LLM_ENDPOINT_KEYS


def build_problem_llm_bindings_arg(
    args: argparse.Namespace,
    *,
    current: Optional[Dict[str, Any]] = None,
    problem_type: Any = None,
) -> Optional[str]:
    """Build the form's JSON binding value while preserving omitted edit options."""

    supplied = {
        key: getattr(args, key)
        for key in _ALL_PROBLEM_LLM_ENDPOINT_KEYS
        if hasattr(args, key)
    }
    current = current if isinstance(current, dict) else None
    current_mode = current.get("programming_grading_mode") if current is not None else None
    requested_mode = getattr(args, "programming_grading_mode", None)
    mode_changed = (
        current is not None
        and requested_mode is not None
        and str(requested_mode) != str(current_mode)
    )

    # Omitting all six options on a normal edit must leave the stored soft links
    # untouched. A mode switch is the exception: incompatible old-mode links need
    # to be removed so the server can validate the new mode's JSON shape.
    if current is None and not supplied:
        return None
    if current is not None and not supplied and not mode_changed:
        return None

    bindings: Dict[str, Any] = {}
    if current is not None:
        raw_bindings = current.get("llm_endpoint_bindings")
        if isinstance(raw_bindings, dict):
            bindings = dict(raw_bindings)
        elif isinstance(raw_bindings, str):
            try:
                parsed = json.loads(raw_bindings)
            except (TypeError, ValueError):
                parsed = {}
            if isinstance(parsed, dict):
                bindings = parsed

        effective_mode = requested_mode if requested_mode is not None else current_mode
        allowed = _allowed_problem_llm_endpoint_keys(problem_type, effective_mode)
        bindings = {key: value for key, value in bindings.items() if key in allowed}

    for key, endpoint_id in supplied.items():
        if endpoint_id is None:
            bindings.pop(key, None)
        else:
            # Keep explicitly supplied out-of-scope keys in the JSON so the
            # server, which owns the authoritative problem-type rules, rejects
            # them instead of the CLI silently ignoring an administrator typo.
            bindings[key] = endpoint_id

    return json.dumps(bindings, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


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
    if isinstance(payload.get("lean_workspace"), dict):
        necessary["lean_workspace"] = _lean_workspace_summary(payload["lean_workspace"])
    submit = payload.get("submit")
    if isinstance(submit, dict):
        necessary_submit = {
            key: submit[key]
            for key in ("input_kind", "accept", "help_text", "problem_type", "programming_grading_mode")
            if key in submit and submit.get(key) is not None
        }
        necessary["submit"] = necessary_submit
    return necessary


def _lean_workspace_from_payload(payload: Any) -> Dict[str, Any]:
    workspace = payload.get("lean_workspace") if isinstance(payload, dict) else None
    if not isinstance(workspace, dict) or not workspace.get("revision"):
        raise CliError("This problem does not have a Lean 4 workspace.")
    if not isinstance(workspace.get("files"), list):
        raise CliError("The server returned an invalid Lean 4 workspace.")
    return workspace


def _lean_relative_path(raw_path: Any) -> PurePosixPath:
    path = PurePosixPath(str(raw_path or ""))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise CliError(f"Invalid Lean workspace path: {raw_path!r}")
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
        raise CliError(
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
        raise CliError(f"Lean workspace is missing {manifest_path}.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"Cannot read Lean workspace manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict) or not str(manifest.get("revision") or "").strip():
        raise CliError("Run problem lean-init first; the workspace manifest has no server revision.")
    manifest_problem_id = manifest.get("problem_id")
    if manifest_problem_id is not None and int(manifest_problem_id) != int(problem_id):
        raise CliError(
            f"This workspace belongs to problem {manifest_problem_id}, not problem {problem_id}."
        )
    descriptors = manifest.get("files")
    if not isinstance(descriptors, list):
        raise CliError("Lean workspace manifest.files must be an array.")
    files: Dict[str, str] = {}
    for descriptor in descriptors:
        if not isinstance(descriptor, dict) or descriptor.get("mode") != "writable":
            continue
        relative = _lean_relative_path(descriptor.get("path"))
        source = root.joinpath(*relative.parts)
        try:
            files[relative.as_posix()] = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError(f"Cannot read writable Lean file {source}: {exc}") from exc
    if not files:
        raise CliError("Lean workspace manifest does not declare any writable files.")
    return {"revision": str(manifest["revision"]), "files": files}


def _lean_workspace_summary(workspace: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: workspace[key]
        for key in ("revision_id", "revision_number", "revision", "default_file", "created")
        if key in workspace
    } | {
        "files": [
            {"path": item.get("path"), "mode": item.get("mode")}
            for item in workspace.get("files") or []
        ]
    }


def _validate_readable_lean_zip(raw_path: str) -> str:
    path = Path(raw_path).expanduser()
    if not path.is_file():
        raise CliError(f"File not found: {path}")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            corrupt_member = archive.testzip()
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CliError(f"Cannot read Lean 4 problem-package ZIP {path}: {exc}") from exc
    if corrupt_member:
        raise CliError(
            f"Lean 4 problem-package ZIP contains a corrupt member: {corrupt_member}"
        )
    return str(path)


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

    workspace_directory = getattr(args, "workspace", None)
    if input_kind == "lean_workspace":
        if not workspace_directory:
            raise CliError("This Lean 4 problem requires --workspace.")
        if any(
            getattr(args, key, None)
            for key in ("file", "code", "code_file", "prompt", "prompt_file")
        ):
            raise CliError("This Lean 4 problem accepts a workspace directory, not code, prompt, or a file upload.")
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
            raise CliError("This problem requires --file.")
        if workspace_directory or args.code or args.code_file or args.prompt or args.prompt_file:
            raise CliError("This problem accepts a file submission, not code or prompt.")
        files = {"file": require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            close_files(files)
    elif input_kind == "prompt":
        if not (args.prompt or args.prompt_file):
            raise CliError("This Promptly problem requires --prompt or --prompt-file.")
        if workspace_directory or args.file or args.code or args.code_file:
            raise CliError("This Promptly problem accepts prompt text, not code or file.")
        prompt = Path(args.prompt_file).expanduser().read_text(encoding="utf-8") if args.prompt_file else read_text_value(args.prompt)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"prompt": prompt})
    else:
        if not (args.code or args.code_file):
            raise CliError("This programming problem requires --code or --code-file.")
        if workspace_directory or args.file or args.prompt or args.prompt_file:
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
    lean_package = getattr(args, "lean_package", None)
    if lean_package and (str(args.type) != "1" or args.lang != "lean4"):
        raise CliError("--lean-package requires --type 1 --lang lean4.")
    if lean_package:
        lean_package = _validate_readable_lean_zip(lean_package)
    programming_grading_prompt = build_promptly_grading_prompt_arg(args)
    llm_endpoint_bindings = build_problem_llm_bindings_arg(args)
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
            ("programming_output_filename", args.programming_output_filename),
            ("programming_grading_prompt", programming_grading_prompt),
            ("written_grading_mode", args.written_grading_mode),
            ("written_grading_prompt", read_text_value(args.written_grading_prompt)),
            ("llm_endpoint_bindings", llm_endpoint_bindings),
        ]
    )
    resp = client.request("POST", "/admin/add_problem", data=data, headers={"Accept": "application/json"})
    if not lean_package:
        print_or_save_response(resp)
        return

    ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if response_is_json(resp) else {}
    raise_for_failure_payload(payload, http_status=resp.status_code)
    problem_id = payload.get("problem_id") if isinstance(payload, dict) else None
    if not problem_id:
        raise CliError("The problem was created, but the server did not return its problem ID.")
    files = {"lean_package_zip": require_file(lean_package)}
    try:
        upload_resp = client.request(
            "POST",
            f"/admin/upload_lean_workspace/{problem_id}",
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        close_files(files)
    ensure_ok(upload_resp, allow_redirect=False)
    upload_payload = upload_resp.json() if response_is_json(upload_resp) else {}
    raise_for_failure_payload(upload_payload, http_status=upload_resp.status_code)
    workspace = _lean_workspace_from_payload(upload_payload)
    output_json({
        "success": True,
        "problem_id": int(problem_id),
        "message": upload_payload.get("message") or payload.get("message"),
        "lean_workspace": _lean_workspace_summary(workspace),
    })


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
    form_payload = form_resp.json() if response_is_json(form_resp) else {}
    form_payload = form_payload if isinstance(form_payload, dict) else {}
    current = form_payload.get("form") or {}
    problem = form_payload.get("problem") or {}
    programming_grading_prompt = build_promptly_grading_prompt_arg(args, current)
    llm_endpoint_bindings = build_problem_llm_bindings_arg(
        args,
        current=current,
        problem_type=problem.get("type") if isinstance(problem, dict) else None,
    )
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
            ("programming_output_filename", current_or_arg(current, "programming_output_filename", args.programming_output_filename)),
            ("programming_grading_prompt", programming_grading_prompt if programming_grading_prompt is not None else current.get("programming_grading_prompt", "")),
            ("written_grading_mode", current_or_arg(current, "written_grading_mode", args.written_grading_mode)),
            ("written_grading_prompt", current_or_arg(current, "written_grading_prompt", args.written_grading_prompt)),
            ("llm_endpoint_bindings", llm_endpoint_bindings),
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


def problem_lean_workspace(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/api/admin/problems/{args.problem_id}/lean-workspace",
    )
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if response_is_json(resp) else {}
    raise_for_failure_payload(payload, http_status=resp.status_code)
    output_json({
        "success": True,
        "problem_id": int(args.problem_id),
        "lean_workspace": _lean_workspace_summary(_lean_workspace_from_payload(payload)),
    })


def problem_lean_init(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/api/admin/problems/{args.problem_id}/lean-workspace",
    )
    ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if response_is_json(resp) else {}
    raise_for_failure_payload(payload, http_status=resp.status_code)
    workspace = _lean_workspace_from_payload(payload)
    output_json(_write_lean_workspace(
        problem_id=args.problem_id,
        workspace=workspace,
        directory=args.directory,
        force=args.force,
    ))


def problem_lean_upload(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"lean_package_zip": require_file(args.zip)}
    try:
        resp = client.request(
            "POST",
            f"/admin/upload_lean_workspace/{args.problem_id}",
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        close_files(files)
    ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if response_is_json(resp) else {}
    raise_for_failure_payload(payload, http_status=resp.status_code)
    output_json({
        "success": True,
        "problem_id": int(args.problem_id),
        "message": payload.get("message"),
        "lean_workspace": _lean_workspace_summary(_lean_workspace_from_payload(payload)),
    })


def problem_lean_download(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/admin/download_lean_workspace/{args.problem_id}",
    )
    output = args.output or f"lean-problem-{args.problem_id}.zip"
    print_or_save_response(resp, output=output, allow_redirect=False)


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
    resp = client.request("GET", f"/agent/runs/{args.task_id}/state")
    print_or_save_response(resp)


def problem_agent_run(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/agent/runs/{args.task_id}/state")
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
        "created_at",
        "updated_at",
        "completed_at",
    ):
        if key in event and event.get(key) not in (None, ""):
            necessary[key] = event[key]

    for key in ("logs", "submissions", "messages"):
        value = event.get(key)
        if isinstance(value, list):
            necessary[f"{key}_count"] = len(value)

    execution_trace = event.get("execution_trace")
    if isinstance(execution_trace, dict):
        trace_summary: Dict[str, Any] = {}
        for key in ("trace_id", "status", "error_message"):
            if execution_trace.get(key) not in (None, ""):
                trace_summary[key] = execution_trace[key]
        trace_messages = execution_trace.get("trace_messages")
        trace_files = execution_trace.get("trace_files")
        if isinstance(trace_messages, list):
            trace_summary["trace_messages_count"] = len(trace_messages)
        if isinstance(trace_files, list):
            trace_summary["trace_files_count"] = len(trace_files)
        necessary["execution_trace"] = trace_summary

    for key in ("result", "progress"):
        value = event.get(key)
        if isinstance(value, dict):
            necessary[key] = common.necessary_response_payload(value)
    return necessary or common.necessary_response_payload(event)


def problem_agent_run_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/agent/runs/{args.task_id}/stream", stream=True)
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
    payload = {
        "harness": args.harness,
        "endpoint_id": args.endpoint_id,
    }
    resp = client.request("POST", f"/agent/problems/{args.problem_id}/solve", json=payload)
    print_or_save_response(resp)


def problem_agent_generate_data(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data = {
        "harness": args.harness,
        "endpoint_id": args.endpoint_id,
        "test_point_count": args.count,
        "data_requirement": read_text_value(args.data_requirement),
    }
    files = {"standard_solution": require_file(args.standard_solution)}
    try:
        resp = client.request(
            "POST",
            f"/agent/problems/{args.problem_id}/generate-testdata",
            data=data,
            files=files,
        )
    finally:
        close_files(files)
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
    pa = add_cli_parser(ps, "submit", "Submit source code, a Lean workspace, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    submit_group = pa.add_mutually_exclusive_group(required=True)
    submit_group.add_argument("--code", help="Source code text, or @file to read code from a file.")
    submit_group.add_argument("--code-file", help="Source code file path.")
    submit_group.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    submit_group.add_argument("--prompt-file", help="Promptly submission file path.")
    submit_group.add_argument("--file", help="Written-homework PDF or ZIP file path.")
    submit_group.add_argument("--workspace", help="Initialized Lean 4 workspace directory containing numoj-lean.json.")
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
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python", "lean4"], default="matlab", help="Programming language for programming problems.")
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
    pa.add_argument(
        "--programming-output-filename",
        help=(
            "Expected output image filename in programming image-grading mode. "
            "Use png, jpg, jpeg, bmp, gif, or webp (for example, output.png)."
        ),
    )
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, default=1, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-prompt", default="", help="Rubric for AI grading of written homework, or @file.")
    pa.add_argument("--lean-package", help="Lean 4 problem-package ZIP to upload immediately after creating a --lang lean4 problem.")
    _add_problem_llm_endpoint_args(pa, editing=False)
    pa.set_defaults(func=problem_create)
    pa = add_cli_parser(ps, "edit-form", "Fetch administrator edit-form metadata for an existing problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose edit form should be fetched.")
    pa.add_argument("--full", action="store_true", help="Print the raw edit form payload, including long text fields.")
    pa.set_defaults(func=problem_edit_form)
    pa = add_cli_parser(ps, "edit", "Edit an existing programming or written-homework problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to edit.")
    pa.add_argument("--title", help="Problem title. Omit to keep the current value.")
    pa.add_argument("--content", help="Problem statement Markdown text, or @markdown-file. Omit to keep the current value.")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python", "lean4"], help="Programming language. Omit to keep the current value.")
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
    pa.add_argument(
        "--programming-output-filename",
        help=(
            "Expected output image filename in programming image-grading mode. "
            "Use png, jpg, jpeg, bmp, gif, or webp (for example, output.png)."
        ),
    )
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-prompt", help="Rubric for AI grading of written homework, or @file.")
    _add_problem_llm_endpoint_args(pa, editing=True)
    pa.set_defaults(func=problem_edit)
    pa = add_cli_parser(ps, "delete", "Delete a problem by ID.")
    pa.add_argument("problem_id", type=int, help="Problem ID to delete.")
    pa.set_defaults(func=problem_delete)
    pa = add_cli_parser(ps, "upload-testdata", "Upload a ZIP archive of test data for a programming problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose test data should be replaced or uploaded.")
    pa.add_argument("zip", help="Path to the ZIP archive containing test data files.")
    pa.set_defaults(func=problem_upload_testdata)
    pa = add_cli_parser(ps, "lean-workspace", "Inspect the current Lean 4 workspace revision and file map.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID to inspect.")
    pa.add_argument("--full", action="store_true", help="Include all source-file contents and verification metadata.")
    pa.set_defaults(func=problem_lean_workspace)
    pa = add_cli_parser(ps, "lean-init", "Initialize a local directory from the current Lean 4 workspace.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID to initialize.")
    pa.add_argument("directory", help="Directory to populate with the complete Lean 4 workspace.")
    pa.add_argument("--force", action="store_true", help="Replace files already present at the initialized paths.")
    pa.set_defaults(func=problem_lean_init)
    pa = add_cli_parser(ps, "lean-upload", "Publish a Lean 4 problem-package ZIP as a new immutable revision.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID whose workspace should be published.")
    pa.add_argument("zip", help="Path to the Lean 4 problem-package ZIP.")
    pa.set_defaults(func=problem_lean_upload)
    pa = add_cli_parser(ps, "lean-download", "Download the current Lean 4 problem-package ZIP.")
    pa.add_argument("problem_id", type=int, help="Lean 4 problem ID whose package should be downloaded.")
    pa.add_argument("-o", "--output", help="Path for the downloaded ZIP; defaults to lean-problem-<id>.zip.")
    pa.set_defaults(func=problem_lean_download)
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
    pa.set_defaults(func=problem_agent_run)
    pa = add_cli_parser(ps, "agent-run-stream", "Fetch recent stream lines for an agent task run.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.add_argument("--full", action="store_true", help="Print raw stream lines instead of the default agent-status summary.")
    pa.set_defaults(func=problem_agent_run_stream)
    pa = add_cli_parser(ps, "agent-tasks", "List recent problem-solving and test-data-generation agent tasks.")
    pa.set_defaults(func=problem_agent_tasks)
    pa = add_cli_parser(ps, "agent-solve", "Start an AI agent task to solve a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for the agent to solve.")
    pa.add_argument("--harness", required=True, choices=("claude_code", "codex", "opencode", "pi"), help="CLI harness to run.")
    pa.add_argument("--endpoint-id", type=int, required=True, help="Global LLM endpoint ID selected for this run.")
    pa.set_defaults(func=problem_agent_solve)
    pa = add_cli_parser(ps, "agent-generate-data", "Start an AI agent task to generate test data for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for which test data should be generated.")
    pa.add_argument("--harness", required=True, choices=("claude_code", "codex", "opencode", "pi"), help="CLI harness to run.")
    pa.add_argument("--endpoint-id", type=int, required=True, help="Global LLM endpoint ID selected for this run.")
    pa.add_argument("--count", type=int, required=True, help="Number of test cases or data files to request from the agent.")
    pa.add_argument("--standard-solution", required=True, help="Path to the UTF-8 reference solution file.")
    pa.add_argument("--data-requirement", default="", help="Additional natural-language requirements for generated test data.")
    pa.set_defaults(func=problem_agent_generate_data)
    pa = add_cli_parser(ps, "scores", "Fetch score records for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose scores should be returned.")
    pa.set_defaults(func=problem_scores)
