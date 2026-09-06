from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common


client_from_args = common.client_from_args


PROJECT_FIELDS = (
    "gpu_memory_mib", "gpu_approved_memory_mib", "runtime_blocked_reason",
    "id", "slug", "title", "summary", "description", "owner_username",
    "latest_version", "public_version", "submitted_version", "has_pending_review",
    "review_status", "review_note", "latest_review_note", "last_reviewed_version",
    "last_review_status", "last_review_note", "is_featured", "visibility", "cover_url", "tags",
    "play_url", "created_at", "updated_at", "review_requested_at",
)


def necessary_project(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {key: row[key] for key in PROJECT_FIELDS if key in row}


def necessary_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "projects": [necessary_project(row) for row in payload.get("projects") or []],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
    }


def necessary_project_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {"success": bool(payload.get("success", True)), "project": necessary_project(payload.get("project"))}


def necessary_delete_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("success", "deleted", "slug", "message")
        if key in payload
    }


def _output(resp, projector) -> None:
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(projector(resp.json()))
        return
    print(resp.text.strip())


def _metadata(args, *, creating=False) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for name in ("slug", "title", "summary", "tags", "cover_image", "gpu_memory_mib"):
        value = getattr(args, name, None)
        if value is not None:
            data[name] = str(value)
    description = getattr(args, "description", None)
    if description is not None:
        data["description"] = common.read_text_value(description)
    if creating and not data.get("title"):
        raise common.CliError("--title is required when creating a VibeHub project.")
    return data


def _get(args, path, *, projector=necessary_list_payload, params=None):
    resp = client_from_args(args).request("GET", path, params=params)
    _output(resp, projector)


def project_list(args):
    _get(args, "/api/vibehub/projects", params={"limit": args.limit} if args.limit is not None else None)


def project_mine(args):
    _get(args, "/api/vibehub/projects/mine")


def project_detail(args):
    _get(
        args,
        f"/api/vibehub/projects/{args.slug}",
        projector=necessary_project_payload,
        params={"view": args.view} if args.view else None,
    )


def project_create(args):
    files = {"package": common.require_file(args.package)}
    try:
        resp = client_from_args(args).request(
            "POST", "/api/vibehub/projects", data=_metadata(args, creating=True), files=files,
        )
    finally:
        common.close_files(files)
    _output(resp, necessary_project_payload)


def project_update(args):
    files = {"package": common.require_file(args.package)}
    try:
        resp = client_from_args(args).request(
            "POST", f"/api/vibehub/projects/{args.slug}/versions", data=_metadata(args), files=files,
        )
    finally:
        common.close_files(files)
    _output(resp, necessary_project_payload)


def project_edit(args):
    resp = client_from_args(args).request(
        "PATCH", f"/api/vibehub/projects/{args.slug}", json=_metadata(args),
    )
    _output(resp, necessary_project_payload)


def project_delete(args):
    if not args.yes:
        raise common.CliError("Deleting a VibeHub project requires --yes.")
    resp = client_from_args(args).request(
        "DELETE",
        f"/api/vibehub/projects/{args.slug}",
    )
    _output(resp, necessary_delete_payload)


def developer_guide(args):
    resp = client_from_args(args).request("GET", "/api/vibehub/developer-guide")
    common.print_or_save_response(
        resp,
        output=args.output,
        allow_redirect=False,
    )


def review_queue(args):
    _get(args, "/api/vibehub/admin/reviews")


def review_decide(args):
    resp = client_from_args(args).request(
        "POST",
        f"/api/vibehub/admin/reviews/{args.slug}",
        json={"decision": args.decision, "note": common.read_text_value(args.note or ""),
              "expected_version": args.expected_version,
              **({"gpu_memory_mib": args.gpu_memory_mib} if getattr(args, "gpu_memory_mib", None) is not None else {})},
    )
    _output(resp, necessary_project_payload)


def featured_set(args):
    resp = client_from_args(args).request(
        "POST",
        f"/api/vibehub/admin/featured/{args.slug}",
        json={"featured": args.state == "on"},
    )
    _output(resp, necessary_project_payload)


def _add_metadata_args(parser, *, include_slug=False, require_title=False):
    if include_slug:
        parser.add_argument("--slug", help="Optional stable URL slug.")
    parser.add_argument("--gpu-memory-mib", type=int, help="申请 GPU 显存（256–24576 MiB）；0 表示关闭。")
    parser.add_argument("--title", required=require_title, help="Project title.")
    parser.add_argument("--summary", help="Short card summary.")
    parser.add_argument("--description", help="Full description, or @file.")
    parser.add_argument("--tags", help="Comma-separated tags or JSON array.")
    parser.add_argument("--cover-image", help="Relative cover path inside the package.")


def register(subparsers: argparse._SubParsersAction) -> None:
    hub = common.add_cli_parser(subparsers, "vibehub", "Manage VibeHub projects, publication review, and featured status.")
    commands = hub.add_subparsers(dest="cmd", required=True)

    parser = common.add_cli_parser(commands, "guide", "Get the complete VibeHub developer guide from the server.")
    parser.add_argument("-o", "--output", help="Save the Markdown guide to this file instead of printing it.")
    parser.set_defaults(func=developer_guide)

    parser = common.add_cli_parser(commands, "list", "List public VibeHub projects.")
    parser.add_argument("--limit", type=int, help="Maximum number of projects.")
    parser.set_defaults(func=project_list)
    parser = common.add_cli_parser(commands, "mine", "List administrator-owned VibeHub projects.")
    parser.set_defaults(func=project_mine)
    parser = common.add_cli_parser(commands, "detail", "Fetch one VibeHub project.")
    parser.add_argument("slug")
    parser.add_argument("--view", choices=["public", "latest", "review"])
    parser.set_defaults(func=project_detail)
    parser = common.add_cli_parser(commands, "create", "Create a VibeHub project from ZIP.")
    parser.add_argument("package")
    _add_metadata_args(parser, include_slug=True, require_title=True)
    parser.set_defaults(func=project_create)
    parser = common.add_cli_parser(commands, "update", "Upload a new immutable package version.")
    parser.add_argument("slug")
    parser.add_argument("package")
    _add_metadata_args(parser)
    parser.set_defaults(func=project_update)
    parser = common.add_cli_parser(commands, "edit", "Edit metadata as a new immutable version.")
    parser.add_argument("slug")
    _add_metadata_args(parser)
    parser.set_defaults(func=project_edit)
    parser = common.add_cli_parser(commands, "delete", "Permanently delete a VibeHub project.")
    parser.add_argument("slug")
    parser.add_argument("--yes", action="store_true", help="Confirm permanent deletion.")
    parser.set_defaults(func=project_delete)
    parser = common.add_cli_parser(commands, "pending", "List versions awaiting publication review.")
    parser.set_defaults(func=review_queue)
    parser = common.add_cli_parser(commands, "review", "Approve or reject one submitted publication version.")
    parser.add_argument("slug")
    parser.add_argument("decision", choices=["approve", "reject"])
    parser.add_argument("--expected-version", type=int, required=True,
                        help="Version number shown in the pending-review queue.")
    parser.add_argument("--note", help="Review note, or @file.")
    parser.add_argument("--gpu-memory-mib", type=int, help="批准显存 MiB；0 表示不批准 GPU，省略则按申请值批准。")
    parser.set_defaults(func=review_decide)
    parser = common.add_cli_parser(commands, "featured", "Set or unset a project's featured status.")
    parser.add_argument("slug")
    parser.add_argument("state", choices=["on", "off"])
    parser.set_defaults(func=featured_set)


__all__ = ["necessary_list_payload", "necessary_project", "necessary_project_payload", "register"]
