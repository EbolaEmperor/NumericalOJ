from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict

from . import common


def _necessary_repository_job(job: Any) -> Any:
    if not isinstance(job, dict):
        return job
    necessary: Dict[str, Any] = {}
    for key in (
        "id",
        "status",
        "progress",
        "total_files",
        "processed_files",
        "total_chunks",
        "total_classes",
        "progress_message",
        "error_message",
        "cancel_requested",
        "created_at",
        "updated_at",
        "finished_at",
    ):
        if key in job:
            necessary[key] = job[key]
    return necessary


def necessary_repository_context_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("allowed_extensions", "max_file_size_bytes", "defaults"):
        if key in payload:
            necessary[key] = payload[key]
    return necessary


def necessary_repository_files_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    files = []
    for row in payload.get("files") or []:
        if not isinstance(row, dict):
            continue
        files.append({key: row[key] for key in ("id", "filename", "file_size", "created_at", "updated_at") if key in row})
    return {"files": files}


def necessary_repository_file_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {key: payload[key] for key in ("filename", "content") if key in payload}


def necessary_repository_index_start_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "message", "job_id", "replaced_job_id", "file_id", "filename", "need_confirm", "active_job_id"):
        if key in payload and payload.get(key) is not None:
            necessary[key] = payload[key]
    return necessary


def necessary_repository_index_status_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    if "job" in payload:
        return {"job": _necessary_repository_job(payload.get("job"))}
    return payload


def necessary_repository_active_status_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {"has_active": bool(payload.get("has_active"))}
    necessary["job"] = _necessary_repository_job(payload.get("job")) if payload.get("job") else None
    return necessary


def necessary_repository_search_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    hits = []
    for row in payload.get("hits") or []:
        if not isinstance(row, dict):
            continue
        hits.append({
            key: row[key]
            for key in (
                "chunk_id",
                "filename",
                "qualified_name",
                "signature",
                "summary",
                "class_name",
                "start_line",
                "end_line",
                "code",
                "score",
            )
            if key in row
        })
    return {"query": payload.get("query"), "hits": hits}


def necessary_repository_classes_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    classes = []
    for row in payload.get("classes") or []:
        if not isinstance(row, dict):
            continue
        classes.append({
            key: row[key]
            for key in (
                "class_id",
                "filename",
                "kind",
                "class_name",
                "qualified_name",
                "updated_at",
                "bases",
                "member_variables",
                "member_methods",
            )
            if key in row
        })
    return {"classes": classes}


def repository_page(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/repository/context")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_context_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_files(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/repository/files")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_files_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_get_file(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/repository/file/{args.file_id}")
    if args.output and common.response_is_json(resp) and resp.status_code < 400:
        data = resp.json()
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(data.get("content") or ""), encoding="utf-8")
        common.output_json({"success": True, "path": str(target), "filename": data.get("filename")})
        return
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_file_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_save_file(args: argparse.Namespace) -> None:
    content = Path(args.content_file).expanduser().read_text(encoding="utf-8") if args.content_file else common.read_text_value(args.content)
    payload: Dict[str, Any] = {"filename": args.filename, "content": content}
    if args.file_id is not None:
        payload["file_id"] = args.file_id
    resp = common.client_from_args(args).request("POST", "/api/repository/file", json=payload)
    common.print_or_save_response(resp)


def repository_delete_file(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("DELETE", f"/api/repository/file/{args.file_id}")
    common.print_or_save_response(resp)


def repository_upload(args: argparse.Namespace) -> None:
    files = {"file": common.require_file(args.file)}
    try:
        resp = common.client_from_args(args).request("POST", "/api/repository/upload", files=files)
    finally:
        common.close_files(files)
    common.print_or_save_response(resp)


def repository_build_index(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/api/repository/index/build", json={"force_restart": bool(args.force_restart)})
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_index_start_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_rebuild_file(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request(
        "POST",
        "/api/repository/index/rebuild_file",
        json={"file_id": args.file_id, "force_restart": bool(args.force_restart)},
    )
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_index_start_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_index_status(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/repository/index/status/{args.job_id}")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_index_status_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_active_status(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/repository/index/status/active")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_active_status_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_search(args: argparse.Namespace) -> None:
    payload: Dict[str, Any] = {"query": args.query}
    if args.top_k is not None:
        payload["top_k"] = args.top_k
    if args.score_threshold is not None:
        payload["score_threshold"] = args.score_threshold
    resp = common.client_from_args(args).request("POST", "/api/repository/index/search", json=payload)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_search_payload(resp.json()))
        return
    print(resp.text.strip())


def repository_classes(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", "/api/repository/index/classes", params={"limit": args.limit})
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_repository_classes_payload(resp.json()))
        return
    print(resp.text.strip())


def register(subparsers: argparse._SubParsersAction) -> None:
    repo = common.add_cli_parser(subparsers, "repository", "Manage the personal code repository and its vector-search index.")
    repo_sub = repo.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(repo_sub, "page", "Fetch the repository page context as JSON.")
    pa.set_defaults(func=repository_page)
    pa = common.add_cli_parser(repo_sub, "files", "List files in the current user's repository.")
    pa.set_defaults(func=repository_files)
    pa = common.add_cli_parser(repo_sub, "get", "Fetch one repository file by ID.")
    pa.add_argument("file_id", type=int, help="Repository file ID to fetch.")
    pa.add_argument("-o", "--output", help="Write file content when the API returns JSON content.")
    pa.set_defaults(func=repository_get_file)
    pa = common.add_cli_parser(repo_sub, "save", "Create or update a repository file.")
    pa.add_argument("--filename", required=True, help="Repository filename to create or update.")
    content_group = pa.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", help="File content text, or @file to read it from a file.")
    content_group.add_argument("--content-file", help="Path to a local file whose content should be saved.")
    pa.add_argument("--file-id", type=int, help="Existing repository file ID to update. Omit to create a new file.")
    pa.set_defaults(func=repository_save_file)
    pa = common.add_cli_parser(repo_sub, "delete", "Delete a repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to delete.")
    pa.set_defaults(func=repository_delete_file)
    pa = common.add_cli_parser(repo_sub, "upload", "Upload a local source file into the repository.")
    pa.add_argument("file", help="Path to the local file to upload.")
    pa.set_defaults(func=repository_upload)
    pa = common.add_cli_parser(repo_sub, "build-index", "Start or resume a repository-wide vector-index build.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the indexing job if one already exists.")
    pa.set_defaults(func=repository_build_index)
    pa = common.add_cli_parser(repo_sub, "rebuild-file", "Rebuild vector-index entries for one repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to re-index.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the file indexing job if one already exists.")
    pa.set_defaults(func=repository_rebuild_file)
    pa = common.add_cli_parser(repo_sub, "index-status", "Check status for a repository indexing job.")
    pa.add_argument("job_id", type=int, help="Indexing job ID returned by build-index or rebuild-file.")
    pa.set_defaults(func=repository_index_status)
    pa = common.add_cli_parser(repo_sub, "active-status", "Show currently active repository indexing jobs.")
    pa.set_defaults(func=repository_active_status)
    pa = common.add_cli_parser(repo_sub, "search", "Search indexed repository code using semantic/vector search.")
    pa.add_argument("--query", required=True, help="Natural-language or code query to search for.")
    pa.add_argument("--top-k", type=int, help="Maximum number of matching chunks to return.")
    pa.add_argument("--score-threshold", type=float, help="Minimum similarity score required for returned chunks.")
    pa.set_defaults(func=repository_search)
    pa = common.add_cli_parser(repo_sub, "classes", "List class metadata discovered in indexed repository code.")
    pa.add_argument("--limit", type=int, default=300, help="Maximum number of class records to return.")
    pa.set_defaults(func=repository_classes)
