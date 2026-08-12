from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common


client_from_args = common.client_from_args


PROJECT_FIELDS = (
    "id",
    "slug",
    "title",
    "summary",
    "description",
    "owner_username",
    "latest_version",
    "public_version",
    "submitted_version",
    "has_pending_review",
    "review_status",
    "review_note",
    "latest_review_note",
    "last_reviewed_version",
    "last_review_status",
    "last_review_note",
    "is_featured",
    "visibility",
    "cover_url",
    "tags",
    "play_url",
    "created_at",
    "updated_at",
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


def _output(resp, projector) -> None:
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(projector(resp.json()))
        return
    print(resp.text.strip())


def _metadata(args, *, creating=False) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for name in ("slug", "title", "summary", "tags", "cover_image"):
        value = getattr(args, name, None)
        if value is not None:
            data[name] = str(value)
    description = getattr(args, "description", None)
    if description is not None:
        data["description"] = common.read_text_value(description)
    if creating and not data.get("title"):
        raise common.CliError("--title is required when creating a VibeHub project.")
    return data


def project_list(args: argparse.Namespace) -> None:
    params = {"limit": args.limit} if args.limit is not None else None
    resp = client_from_args(args).request("GET", "/api/vibehub/projects", params=params)
    _output(resp, necessary_list_payload)


def project_mine(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/vibehub/projects/mine")
    _output(resp, necessary_list_payload)


def project_detail(args: argparse.Namespace) -> None:
    params = {"view": args.view} if args.view else None
    resp = client_from_args(args).request(
        "GET", f"/api/vibehub/projects/{args.slug}", params=params,
    )
    _output(resp, necessary_project_payload)


def project_create(args: argparse.Namespace) -> None:
    files = {"package": common.require_file(args.package)}
    try:
        resp = client_from_args(args).request(
            "POST",
            "/api/vibehub/projects",
            data=_metadata(args, creating=True),
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        common.close_files(files)
    _output(resp, necessary_project_payload)


def project_update(args: argparse.Namespace) -> None:
    files = {"package": common.require_file(args.package)}
    try:
        resp = client_from_args(args).request(
            "POST",
            f"/api/vibehub/projects/{args.slug}/versions",
            data=_metadata(args),
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        common.close_files(files)
    _output(resp, necessary_project_payload)


def project_edit(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request(
        "PATCH",
        f"/api/vibehub/projects/{args.slug}",
        json=_metadata(args),
    )
    _output(resp, necessary_project_payload)


def developer_guide(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/vibehub/developer-guide")
    common.print_or_save_response(
        resp,
        output=args.output,
        allow_redirect=False,
    )


def _add_metadata_args(parser, *, include_slug=False, require_title=False) -> None:
    if include_slug:
        parser.add_argument("--slug", help="Optional stable URL slug (lowercase letters, numbers, and hyphens).")
    parser.add_argument("--title", required=require_title, help="Project title.")
    parser.add_argument("--summary", help="Short card summary.")
    parser.add_argument("--description", help="Full description text, or @file to read it from a file.")
    parser.add_argument("--tags", help="Comma-separated tags or a JSON string array.")
    parser.add_argument("--cover-image", help="Safe relative cover-image path inside the package.")


def register(subparsers: argparse._SubParsersAction) -> None:
    hub = common.add_cli_parser(
        subparsers,
        "vibehub",
        "Browse, create, version, and publish VibeHub projects.",
    )
    commands = hub.add_subparsers(dest="cmd", required=True)

    parser = common.add_cli_parser(commands, "guide", "Get the complete VibeHub developer guide from the server.")
    parser.add_argument("-o", "--output", help="Save the Markdown guide to this file instead of printing it.")
    parser.set_defaults(func=developer_guide)

    parser = common.add_cli_parser(commands, "list", "List publicly playable VibeHub projects.")
    parser.add_argument("--limit", type=int, help="Maximum number of projects to return.")
    parser.set_defaults(func=project_list)

    parser = common.add_cli_parser(commands, "mine", "List the current user's VibeHub projects and latest draft versions.")
    parser.set_defaults(func=project_mine)

    parser = common.add_cli_parser(commands, "detail", "Fetch one public or owned VibeHub project.")
    parser.add_argument("slug", help="Project slug.")
    parser.add_argument("--view", choices=["public", "latest"], help="Select the public snapshot or the owned latest draft.")
    parser.set_defaults(func=project_detail)

    parser = common.add_cli_parser(commands, "create", "Create a VibeHub project from a complete ZIP package.")
    parser.add_argument("package", help="ZIP package containing root Dockerfile and vibehub.json.")
    _add_metadata_args(parser, include_slug=True, require_title=True)
    parser.set_defaults(func=project_create)

    parser = common.add_cli_parser(commands, "update", "Upload a new immutable package version for an owned project.")
    parser.add_argument("slug", help="Owned project slug.")
    parser.add_argument("package", help="New complete ZIP package.")
    _add_metadata_args(parser)
    parser.set_defaults(func=project_update)

    parser = common.add_cli_parser(commands, "edit", "Edit project metadata by creating a new immutable version.")
    parser.add_argument("slug", help="Owned project slug.")
    _add_metadata_args(parser)
    parser.set_defaults(func=project_edit)

__all__ = [
    "necessary_list_payload",
    "necessary_project",
    "necessary_project_payload",
    "register",
]
