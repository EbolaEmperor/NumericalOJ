from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

from . import common
from .common import *  # noqa: F401,F403 - command modules share the CLI helper surface.


DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS = 1_000_000
DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS = 384_000
DEFAULT_ENDPOINT_THINKING_COMPATIBILITY = True


def _necessary_competition(
    row: Any,
    *,
    include_description: bool = False,
    include_description_meta: bool = False,
    include_quality_gate: bool = False,
) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    keys = [
        "id",
        "title",
        "summary",
        "answer_format",
        "scoring_mode",
        "submission_method",
        "max_score",
        "submit_limit_per_window",
        "is_active",
        "participant_count",
        "submission_count",
        "agent_judge_timeout_seconds",
        "reverse_judge_finalize_timeout_seconds",
        "agent_judge_orchestration_mode",
        "elo_initial_rating",
        "elo_k_factor",
        "elo_max_matches",
        "elo_match_interval_seconds",
        "created_by",
        "created_at",
        "updated_at",
        "url",
    ]
    if include_description:
        keys.insert(3, "description")
    if include_quality_gate:
        keys.extend(("reverse_quality_gate_enabled", "reverse_quality_gate_prompt"))
    out = {key: row[key] for key in keys if key in row}
    if include_description_meta and not include_description and row.get("description"):
        out["description_chars"] = len(str(row.get("description") or ""))
    return out


def _necessary_ranking_file(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        key: row[key]
        for key in ("id", "filename", "file_size", "media_kind", "download_url", "created_at")
        if key in row
    }


def _necessary_ranking_submission(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        key: row[key]
        for key in (
            "id",
            "competition_id",
            "username",
            "answer_filename",
            "code_filename",
            "base_model",
            "agent_endpoint_id",
            "agent_endpoint_harness",
            "agent_endpoint_model",
            "agent_endpoint_label",
            "score",
            "rating",
            "status",
            "judge_status",
            "agent_judge_status",
            "appeal_status",
            "source",
            "created_at",
            "updated_at",
            "answer_download_url",
            "code_download_url",
            "ai_answer_available",
            "ai_answer_download_url",
        )
        if key in row
    }


def _necessary_match(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        key: row[key]
        for key in (
            "id",
            "submission_a_id",
            "submission_b_id",
            "username_a",
            "username_b",
            "winner",
            "score_a",
            "score_b",
            "rating_a_before",
            "rating_a_after",
            "rating_b_before",
            "rating_b_after",
            "status",
            "details",
            "error_message",
            "created_at",
        )
        if key in row
    }


def necessary_ranking_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "success": payload.get("success", True),
        "competitions": [_necessary_competition(row) for row in payload.get("competitions") or []],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
    }


def necessary_ranking_detail_payload(payload: Any, *, include_description: bool = False) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    if "success" in payload:
        necessary["success"] = payload["success"]
    if "competition" in payload:
        necessary["competition"] = _necessary_competition(
            payload.get("competition"),
            include_description=include_description,
            include_description_meta=True,
            include_quality_gate=True,
        )
    for key in (
        "tab",
        "submission_method",
        "judge_ready",
        "agent_judge_ready",
        "quality_gate_ready",
        "can_submit",
        "submit_block_reason",
        "submit_quota",
        "git_repo_url",
        "submission_stats",
        "appeal_stats",
    ):
        if key in payload:
            necessary[key] = payload[key]
    if "files" in payload:
        necessary["files"] = [_necessary_ranking_file(row) for row in payload.get("files") or []]
    for key in ("user_submissions", "all_submissions", "submissions"):
        if key in payload:
            necessary[key] = [_necessary_ranking_submission(row) for row in payload.get(key) or []]
    if "leaderboard" in payload:
        necessary["leaderboard"] = payload.get("leaderboard") or []
    if "matches" in payload:
        necessary["matches"] = [_necessary_match(row) for row in payload.get("matches") or []]
    if "all_appeals" in payload:
        necessary["appeals"] = payload.get("all_appeals") or []
    for key in ("current_page", "total_pages", "page_numbers", "matches_total", "matches_mine", "matches_per_page"):
        if key in payload:
            necessary[key] = payload[key]
    if "judge_rules" in payload:
        necessary["judge_rules"] = payload.get("judge_rules") or []
    if "aj_endpoints" in payload:
        necessary["aj_endpoints"] = payload.get("aj_endpoints") or []
    if "quality_gate_endpoints" in payload:
        necessary["quality_gate_endpoints"] = payload.get("quality_gate_endpoints") or []
    return necessary


def necessary_ranking_submissions_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "competition_id": payload.get("competition_id"),
        "submissions": [_necessary_ranking_submission(row) for row in payload.get("submissions") or []],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
        "page": payload.get("page"),
        "total_pages": payload.get("total_pages"),
    }


def necessary_ranking_leaderboard_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "competition_id": payload.get("competition_id"),
        "leaderboard": payload.get("leaderboard") or [],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
    }


def necessary_ranking_matches_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "competition_id": payload.get("competition_id"),
        "matches": [_necessary_match(row) for row in payload.get("matches") or []],
        "total": payload.get("total", 0),
        "page": payload.get("page"),
        "total_pages": payload.get("total_pages"),
        "mine": bool(payload.get("mine")),
    }


def necessary_ranking_match_detail_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return _necessary_match(payload)


def necessary_ranking_stream_event_payload(event: Any) -> Any:
    if not isinstance(event, dict):
        text = str(event or "")
        if len(text) <= 500:
            return text
        return {"text": text[:500], "chars": len(text), "truncated": True}

    necessary: Dict[str, Any] = {}
    for key in (
        "success",
        "competition_id",
        "submission_id",
        "id",
        "username",
        "status",
        "judge_status",
        "agent_judge_status",
        "score",
        "rating",
        "message",
        "error",
        "error_message",
        "created_at",
        "updated_at",
    ):
        if key in event and event.get(key) not in (None, ""):
            necessary[key] = event[key]

    for key in ("rules", "rule_results", "matches", "logs", "events"):
        value = event.get(key)
        if isinstance(value, list):
            necessary[f"{key}_count"] = len(value)

    details = event.get("details") or event.get("grade_details")
    if isinstance(details, dict):
        necessary["details_keys"] = sorted(str(key) for key in details.keys())
    return necessary or common.necessary_response_payload(event)


def necessary_reverse_judge_snapshot_payload(event: Any) -> Any:
    if not isinstance(event, dict):
        return necessary_ranking_stream_event_payload(event)
    out: Dict[str, Any] = {}
    for key in (
        "submission_id",
        "competition_id",
        "username",
        "status",
        "total_score",
        "max_score",
        "score",
        "error_message",
        "last_updated",
        "updated_at",
    ):
        if event.get(key) not in (None, ""):
            out[key] = event[key]
    steps = []
    for step in event.get("steps") or []:
        if not isinstance(step, dict):
            continue
        result = step.get("result") if isinstance(step.get("result"), dict) else {}
        step_key = step.get("step_key")
        item = {
            "step_key": step_key,
            "title": step.get("title"),
            "status": step.get("status"),
            "score": step.get("score") if step.get("score") is not None else result.get("score"),
            "max_score": step.get("max_score") if step.get("max_score") is not None else result.get("max_score"),
            "trace_messages_count": len(step.get("trace_messages") or []),
        }
        if step_key == "agent_answer":
            item["answer_available"] = bool(step.get("answer_available"))
        if step.get("error_message"):
            item["error_message"] = step["error_message"]
        if step_key == "quality_gate":
            for key in ("passed", "verdict", "summary", "violations"):
                if key in result:
                    item[key] = result[key]
        steps.append(item)
    if steps:
        out["steps"] = steps
    return out or common.necessary_response_payload(event)


def necessary_ranking_appeals_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("competition_id", "appeals", "count", "total", "page", "total_pages", "status_counts")
        if key in payload
    }


def necessary_ranking_appeal_review_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        key: payload[key]
        for key in ("success", "competition", "appeal", "submission", "rules", "rule_results", "history")
        if key in payload
    }


def ranking_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/ranking/competitions", params=params)
    common.output_projected_json_response(resp, necessary_ranking_list_payload)


def ranking_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    requested_tab = args.tab
    if requested_tab == "submissions":
        requested_tab = "all_submissions"
    params = {"tab": requested_tab} if requested_tab else None
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}", params=params)
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    ensure_ok(resp, allow_redirect=False)
    if not response_is_json(resp):
        raise CliError("Server did not return JSON for ranking detail.")
    payload = resp.json()
    returned_tab = payload.get("tab") if isinstance(payload, dict) else None
    if requested_tab and returned_tab and returned_tab != requested_tab:
        raise common.CliHttpError(409, {
            "success": False,
            "message": "The server returned a different ranking tab than requested.",
            "requested_tab": requested_tab,
            "returned_tab": returned_tab,
        })
    include_description = requested_tab == "description"
    output_json(common.necessary_response_payload(
        necessary_ranking_detail_payload(payload, include_description=include_description)
    ))


def ranking_create(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data = {
        "title": args.title,
        "summary": read_text_value(args.summary),
        "description": read_text_value(args.description),
        "max_score": args.max_score,
    }
    resp = client.request("POST", "/ranking/create", data=data)
    print_or_save_response(resp)


def ranking_copy(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/copy")
    print_or_save_response(resp)


def ranking_edit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    form_resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}", params={"tab": "edit"})
    ensure_ok(form_resp, allow_redirect=False)
    comp = (form_resp.json() if response_is_json(form_resp) else {}).get("competition") or {}
    current = {
        "title": comp.get("title"),
        "summary": comp.get("summary"),
        "description": comp.get("description"),
        "max_score": comp.get("max_score"),
        "is_active": bool(comp.get("is_active")),
        "answer_format": comp.get("answer_format"),
        "scoring_mode": comp.get("scoring_mode"),
        "scoring_script_timeout_seconds": comp.get("scoring_script_timeout_seconds"),
        "submit_limit_per_window": comp.get("submit_limit_per_window"),
        "submission_method": comp.get("submission_method"),
        "git_format": comp.get("git_format"),
        "agent_judge_orchestration_mode": comp.get("agent_judge_orchestration_mode"),
        "reverse_judge_finalize_timeout_seconds": comp.get("reverse_judge_finalize_timeout_seconds"),
        "elo_initial_rating": comp.get("elo_initial_rating"),
        "elo_k_factor": comp.get("elo_k_factor"),
        "elo_max_matches": comp.get("elo_max_matches"),
        "elo_match_interval_seconds": comp.get("elo_match_interval_seconds"),
        "elo_initial_burst": comp.get("elo_initial_burst"),
        "elo_max_pairs_per_round": comp.get("elo_max_pairs_per_round"),
        "agent_judge_timeout_seconds": comp.get("agent_judge_timeout_seconds"),
    }
    active = args.active
    if active is None:
        active = bool(current.get("is_active"))
    data = form_from_pairs(
        [
            ("title", current_or_arg(current, "title", args.title)),
            ("summary", current_or_arg(current, "summary", args.summary)),
            ("description", current_or_arg(current, "description", args.description)),
            ("max_score", current_or_arg(current, "max_score", args.max_score)),
            ("is_active", active),
            ("answer_format", current_or_arg(current, "answer_format", args.answer_format)),
            ("scoring_mode", current_or_arg(current, "scoring_mode", args.scoring_mode)),
            ("scoring_script_timeout_seconds", current_or_arg(current, "scoring_script_timeout_seconds", args.script_timeout)),
            ("submit_limit_per_window", current_or_arg(current, "submit_limit_per_window", args.submit_limit)),
            ("reset_limit_window", args.reset_limit_window),
            ("submission_method", current_or_arg(current, "submission_method", args.submission_method)),
            ("git_format", current_or_arg(current, "git_format", args.git_format)),
            ("agent_judge_orchestration_mode", current_or_arg(
                current, "agent_judge_orchestration_mode", args.agent_orchestration)),
            ("elo_initial_rating", current_or_arg(current, "elo_initial_rating", args.elo_initial_rating)),
            ("elo_k_factor", current_or_arg(current, "elo_k_factor", args.elo_k_factor)),
            ("elo_max_matches", current_or_arg(current, "elo_max_matches", args.elo_max_matches)),
            ("elo_match_interval_seconds", current_or_arg(current, "elo_match_interval_seconds", args.elo_match_interval)),
            ("elo_initial_burst", current_or_arg(current, "elo_initial_burst", args.elo_initial_burst)),
            ("elo_max_pairs_per_round", current_or_arg(current, "elo_max_pairs_per_round", args.elo_max_pairs_per_round)),
            ("agent_judge_timeout_seconds", current_or_arg(current, "agent_judge_timeout_seconds", args.agent_timeout)),
            ("reverse_judge_finalize_timeout_seconds", current_or_arg(
                current, "reverse_judge_finalize_timeout_seconds", args.reverse_finalize_timeout)),
        ]
    )
    resp = client.request("POST", f"/ranking/{args.competition_id}/edit", data=data)
    print_or_save_response(resp)


def ranking_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/delete")
    print_or_save_response(resp, allow_redirect=False)


def ranking_upload_attachment(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"attachment": require_file(args.file)}
    try:
        resp = client.request("POST", f"/ranking/{args.competition_id}/upload_attachment", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def ranking_delete_attachment(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/attachment/{args.file_id}/delete")
    print_or_save_response(resp, allow_redirect=False)


def ranking_download_attachment(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params = {"inline": "1"} if args.inline else None
    resp = client.request("GET", f"/ranking/{args.competition_id}/attachment/{args.file_id}/download", params=params)
    print_or_save_response(resp, output=args.output or ".")


def ranking_upload_reference(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"reference": require_file(args.file)}
    try:
        resp = client.request("POST", f"/ranking/{args.competition_id}/upload_reference", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def ranking_upload_script(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"scoring_script": require_file(args.file)}
    try:
        resp = client.request("POST", f"/ranking/{args.competition_id}/upload_scoring_script", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def ranking_clear_script(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/clear_scoring_script")
    print_or_save_response(resp)


def ranking_reset_limit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/reset_submit_limit")
    print_or_save_response(resp)


def ranking_rules(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    rules = parse_json_value(args.rules)
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/rules", json={"rules": rules})
    print_or_save_response(resp)


def ranking_endpoints(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    endpoints = parse_json_value(args.endpoints)
    if isinstance(endpoints, list):
        endpoints = [
            _resolve_endpoint_secret_fields(ep, getattr(args, "env_file", None))
            for ep in endpoints
        ]
    payload: Dict[str, Any] = {"endpoints": endpoints}
    if args.timeout_seconds is not None:
        payload["timeout_seconds"] = args.timeout_seconds
    if args.reverse_finalize_timeout is not None:
        payload["reverse_judge_finalize_timeout_seconds"] = args.reverse_finalize_timeout
    if args.orchestration_mode is not None:
        payload["orchestration_mode"] = args.orchestration_mode
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/endpoints", json=payload)
    print_or_save_response(resp)


def _read_dotenv_values(path: str) -> Dict[str, str]:
    return common.read_dotenv_values(path)


def _read_env_secret(name: str, env_file: Optional[str] = None) -> str:
    return common.read_env_secret(name, env_file)


def _resolve_endpoint_secret_fields(endpoint: Any, default_env_file: Optional[str] = None) -> Any:
    if not isinstance(endpoint, dict):
        return endpoint
    out = dict(endpoint)
    api_key_env = out.pop("api_key_env", None)
    env_file = out.pop("env_file", None) or default_env_file
    if api_key_env:
        out["api_key"] = _read_env_secret(str(api_key_env), env_file)
    return out


def _endpoint_api_key_from_args(args: argparse.Namespace) -> str:
    if getattr(args, "api_key", None) is not None:
        return read_text_value(args.api_key).strip()
    if getattr(args, "api_key_env", None) is not None:
        return _read_env_secret(args.api_key_env, getattr(args, "env_file", None))
    raise CliError("Endpoint API key is required. Use --api-key, --api-key @file, or --api-key-env NAME.")


def _endpoint_protocol_from_args(args: argparse.Namespace) -> str:
    """解析统一端点协议；只按 harness 能力校验，不读取模型名或 URL。"""

    harness = str(getattr(args, "harness", "claude_code") or "claude_code")
    protocol = str(getattr(args, "protocol", None) or "").strip().lower()
    allowed = {
        "claude_code": {"anthropic"},
        "codex": {"openai"},
        "opencode": {"openai"},
        "pi": {"openai", "anthropic"},
    }
    if not protocol:
        if harness == "pi":
            raise CliError("Pi endpoint requires --protocol openai or --protocol anthropic.")
        protocol = "anthropic" if harness == "claude_code" else "openai"
    if protocol not in allowed.get(harness, set()):
        raise CliError(f"Harness {harness} does not support the {protocol} protocol.")
    return protocol


def _endpoint_thinking_format(protocol: str, thinking_compatibility: bool) -> str:
    if not thinking_compatibility:
        return "none"
    return "thinking_type" if protocol == "anthropic" else "enable_thinking"


def ranking_save_endpoint(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    protocol = _endpoint_protocol_from_args(args)
    thinking_compatibility = getattr(
        args,
        "thinking_compatibility",
        DEFAULT_ENDPOINT_THINKING_COMPATIBILITY,
    )
    endpoint = {
        "harness": args.harness,
        "protocol": protocol,
        "base_url": args.base_url_value,
        "api_key": _endpoint_api_key_from_args(args),
        "model": args.model,
        "context_window_tokens": getattr(
            args,
            "context_window_tokens",
            DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
        ),
        "max_output_tokens": getattr(
            args,
            "max_output_tokens",
            DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
        ),
        "thinking_compatibility": thinking_compatibility,
        "thinking_format": _endpoint_thinking_format(
            protocol,
            thinking_compatibility,
        ),
        "concurrency_limit": args.concurrency_limit,
        "status": args.status,
    }
    payload: Dict[str, Any] = {"endpoints": [endpoint]}
    if args.timeout_seconds is not None:
        payload["timeout_seconds"] = args.timeout_seconds
    if args.reverse_finalize_timeout is not None:
        payload["reverse_judge_finalize_timeout_seconds"] = args.reverse_finalize_timeout
    if args.orchestration_mode is not None:
        payload["orchestration_mode"] = args.orchestration_mode
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/endpoints", json=payload)
    print_or_save_response(resp)


def ranking_save_quality_gate(args: argparse.Namespace) -> None:
    payload: Dict[str, Any] = {}
    if args.enabled is not None:
        payload["enabled"] = bool(args.enabled)
    if args.prompt is not None:
        payload["prompt"] = read_text_value(args.prompt)
    if not payload:
        raise CliError("Quality-gate configuration requires --enabled, --disabled, or --prompt.")
    resp = client_from_args(args).request(
        "POST",
        f"/ranking/{args.competition_id}/reverse_judge/quality_gate",
        json=payload,
    )
    print_or_save_response(resp)


def _require_quality_gate_endpoint_urls(endpoints: List[Any]) -> List[Dict[str, Any]]:
    """质量门禁端点必须显式提供可连接的模型 API 地址。"""
    validated: List[Dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints, start=1):
        if not isinstance(endpoint, dict):
            raise CliError(f"Quality-gate endpoint #{index} must be a JSON object.")
        base_url = str(endpoint.get("base_url") or "").strip()
        if not base_url:
            raise CliError(f"Quality-gate endpoint #{index} requires a non-empty base_url.")
        if not base_url.startswith(("http://", "https://")):
            raise CliError(f"Quality-gate endpoint #{index} base_url must start with http:// or https://.")
        normalized = dict(endpoint)
        normalized["base_url"] = base_url
        validated.append(normalized)
    return validated


def ranking_save_quality_gate_endpoints(args: argparse.Namespace) -> None:
    endpoints = parse_json_value(args.endpoints)
    if not isinstance(endpoints, list):
        raise CliError("Quality-gate endpoints must be a JSON array.")
    endpoints = [
        _resolve_endpoint_secret_fields(endpoint, getattr(args, "env_file", None))
        for endpoint in endpoints
    ]
    endpoints = _require_quality_gate_endpoint_urls(endpoints)
    resp = client_from_args(args).request(
        "POST",
        f"/ranking/{args.competition_id}/reverse_judge/quality_gate",
        json={"endpoints": endpoints},
    )
    print_or_save_response(resp)


def ranking_save_quality_gate_endpoint(args: argparse.Namespace) -> None:
    protocol = _endpoint_protocol_from_args(args)
    thinking_compatibility = getattr(
        args,
        "thinking_compatibility",
        DEFAULT_ENDPOINT_THINKING_COMPATIBILITY,
    )
    endpoint = _require_quality_gate_endpoint_urls([{
        "harness": args.harness,
        "protocol": protocol,
        "base_url": args.base_url_value,
        "api_key": _endpoint_api_key_from_args(args),
        "model": args.model,
        "context_window_tokens": getattr(
            args,
            "context_window_tokens",
            DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
        ),
        "max_output_tokens": getattr(
            args,
            "max_output_tokens",
            DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
        ),
        "thinking_compatibility": thinking_compatibility,
        "thinking_format": _endpoint_thinking_format(
            protocol,
            thinking_compatibility,
        ),
        "concurrency_limit": args.concurrency_limit,
        "status": args.status,
    }])[0]
    resp = client_from_args(args).request(
        "POST",
        f"/ranking/{args.competition_id}/reverse_judge/quality_gate",
        json={"endpoints": [endpoint]},
    )
    print_or_save_response(resp)


def ranking_batch_probe(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"classes": parse_csv(args.classes), "template": args.template}
    resp = client.request("POST", f"/ranking/{args.competition_id}/batch_eval/probe", json=payload)
    print_or_save_response(resp)


def ranking_batch_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/batch_eval/probe_status", params={"job": args.job_id})
    print_or_save_response(resp)


def ranking_batch_create(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"template": args.template, "usernames": parse_csv(args.usernames)}
    if getattr(args, "agent_endpoint_id", None) is not None:
        payload["agent_endpoint_id"] = args.agent_endpoint_id
    resp = client.request("POST", f"/ranking/{args.competition_id}/batch_eval/create", json=payload)
    print_or_save_response(resp)


def ranking_bulk_filter(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "start": args.start,
        "end": args.end,
        "username": args.username or "",
        "statuses": parse_csv(args.statuses),
    }
    resp = client.request("POST", f"/ranking/{args.competition_id}/bulk_rejudge/filter", json=payload)
    print_or_save_response(resp)


def ranking_bulk_start(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"submission_ids": parse_int_csv(args.submission_ids)}
    resp = client.request("POST", f"/ranking/{args.competition_id}/bulk_rejudge/start", json=payload)
    print_or_save_response(resp)


def ranking_bulk_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/bulk_rejudge/status/{args.job_id}")
    print_or_save_response(resp)


def ranking_matches(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.mine:
        params["mine"] = "1"
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/matches", params=params)
    common.output_projected_json_response(resp, necessary_ranking_matches_payload, allow_redirect=True)


def ranking_match_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/match/{args.match_id}/details.json")
    common.output_projected_json_response(resp, necessary_ranking_match_detail_payload, allow_redirect=True)


def ranking_rejudge_agent(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/ranking/{args.competition_id}/submission/{args.submission_id}/rejudge_agent",
    )
    print_or_save_response(resp, allow_redirect=False)


def ranking_submit_appeal(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/ranking/{args.competition_id}/submission/{args.submission_id}/appeal",
        data={"reason": read_text_value(args.reason)},
    )
    print_or_save_response(resp)


def ranking_appeal_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/submission/{args.submission_id}/appeal_status")
    print_or_save_response(resp)


def ranking_appeals(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params = {"page": args.page, "q": args.query or "", "status": args.status or ""}
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/appeals", params=params)
    common.output_projected_json_response(resp, necessary_ranking_appeals_payload, allow_redirect=True)


def ranking_appeal_review(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/appeals/{args.appeal_id}/review")
    if getattr(args, "full", False):
        print_or_save_response(resp, allow_redirect=False, project_json=False)
        return
    common.output_projected_json_response(resp, necessary_ranking_appeal_review_payload)


def ranking_appeal_handle(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "decision": args.decision,
        "admin_response": read_text_value(args.response),
        "overrides": parse_json_value(args.overrides) if args.overrides else {},
    }
    resp = client.request("POST", f"/ranking/{args.competition_id}/appeal/{args.appeal_id}/handle", json=payload)
    print_or_save_response(resp)


def ranking_elo_action(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/elo/{args.action}")
    print_or_save_response(resp)


def ranking_elo_delete_match(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/match/{args.match_id}/delete")
    print_or_save_response(resp)


def ranking_elo_rebuild(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/elo/rebuild")
    print_or_save_response(resp)


def ranking_delete_submission(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/submission/{args.submission_id}/delete")
    print_or_save_response(resp, allow_redirect=False)


def ranking_download_submission(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    if args.kind == "ai-answer":
        path = f"/api/ranking/submissions/{args.submission_id}/reverse-agent-answer"
    else:
        path = f"/ranking/submission/{args.submission_id}/{args.kind}"
    resp = client.request("GET", path)
    print_or_save_response(
        resp, output=args.output or ".", allow_redirect=False,
    )


def ranking_judge_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/judge_stream/{args.submission_id}", stream=True)
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
        "latest": necessary_ranking_stream_event_payload(latest) if latest is not None else None,
        "truncated": bool(stream_payload.get("truncated")),
    })


def ranking_reverse_judge_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/reverse_judge_stream/{args.submission_id}", stream=True)
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
        "latest": necessary_reverse_judge_snapshot_payload(latest) if latest is not None else None,
        "truncated": bool(stream_payload.get("truncated")),
    })


def ranking_my_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/my-submissions", params=params)
    common.output_projected_json_response(resp, necessary_ranking_submissions_payload, allow_redirect=True)


def ranking_all_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/api/ranking/competitions/{args.competition_id}/submissions",
        params={"page": args.page, "q": args.username or ""},
    )
    common.output_projected_json_response(resp, necessary_ranking_submissions_payload, allow_redirect=True)


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/leaderboard", params=params)
    common.output_projected_json_response(resp, necessary_ranking_leaderboard_payload, allow_redirect=True)


def _ranking_submission_ids(client: NumOJClient, competition_id: int) -> set[int]:
    resp = client.request("GET", f"/api/ranking/competitions/{competition_id}/my-submissions")
    if resp.status_code >= 400 or not response_is_json(resp):
        return set()
    try:
        payload = resp.json()
    except Exception:
        return set()
    return {
        int(row["id"])
        for row in (payload.get("submissions") or [])
        if row.get("id") is not None
    }


def ranking_submit_zip(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    before_ids = _ranking_submission_ids(client, args.competition_id)
    files = {"code_file": require_file(args.code_zip)}
    data: Dict[str, str] = {}
    if getattr(args, "base_model", None) is not None:
        data["base_model"] = args.base_model
    if getattr(args, "agent_endpoint_id", None) is not None:
        data["agent_endpoint_id"] = str(args.agent_endpoint_id)
    if args.answer_file:
        files["answer_file"] = require_file(args.answer_file)
    try:
        resp = client.request(
            "POST",
            f"/ranking/{args.competition_id}/submit",
            data=data,
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        close_files(files)
    ensure_ok(resp)
    after_ids = _ranking_submission_ids(client, args.competition_id)
    new_ids = sorted(after_ids - before_ids)
    payload: Dict[str, Any] = {
        "success": bool(new_ids),
    }
    if new_ids:
        payload["submission_id"] = new_ids[-1]
    else:
        payload["message"] = "The submission request completed, but no new submission record was created. Check the submission method, quota, or form errors."
    output_json(payload)


def ranking_git_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = "check_repo" if args.action == "check" else "git_submit"
    data: Dict[str, str] = {}
    if path == "git_submit" and getattr(args, "agent_endpoint_id", None) is not None:
        data["agent_endpoint_id"] = str(args.agent_endpoint_id)
    resp = client.request("POST", f"/ranking/{args.competition_id}/{path}", data=data or None)
    print_or_save_response(resp, allow_redirect=False)


def _add_endpoint_model_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--context-window-tokens",
        type=int,
        default=DEFAULT_ENDPOINT_CONTEXT_WINDOW_TOKENS,
        help="Model context-window size in tokens.",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=DEFAULT_ENDPOINT_MAX_OUTPUT_TOKENS,
        help="Maximum model output size in tokens.",
    )
    parser.add_argument(
        "--thinking-compatibility",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_ENDPOINT_THINKING_COMPATIBILITY,
        help=(
            "Enable model thinking/reasoning compatibility metadata; use "
            "--no-thinking-compatibility to disable it."
        ),
    )


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    rk = add_cli_parser(sub, "ranking", "Manage ranking competitions, submissions, judging, appeals, and AI-judge settings.")
    rs = rk.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(rs, "list", "List ranking competitions.")
    pa.add_argument("--limit", type=int, help="Maximum number of competitions to return.")
    pa.set_defaults(func=ranking_list)
    pa = add_cli_parser(rs, "detail", "Fetch ranking competition detail metadata as JSON.")
    pa.add_argument("competition_id", type=int, help="Competition ID to inspect.")
    pa.add_argument("--tab", help="Optional detail tab to request, such as submissions, all_submissions, leaderboard, matches, appeals, or edit.")
    pa.add_argument("--full", action="store_true", help="Print the raw detail payload, including page-only context.")
    pa.set_defaults(func=ranking_detail)
    pa = add_cli_parser(rs, "create", "Create a ranking competition.")
    pa.add_argument("--title", required=True, help="Competition title.")
    pa.add_argument("--summary", default="", help="Short competition summary.")
    pa.add_argument("--description", default="", help="Full competition description, or @file if supported by the server-side route.")
    pa.add_argument("--max-score", type=int, default=100, help="Maximum displayed score for the competition.")
    pa.set_defaults(func=ranking_create)
    pa = add_cli_parser(rs, "copy", "Copy an existing ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to copy.")
    pa.set_defaults(func=ranking_copy)
    pa = add_cli_parser(rs, "edit", "Edit ranking competition settings.")
    pa.add_argument("competition_id", type=int, help="Competition ID to edit.")
    pa.add_argument("--title", help="New competition title.")
    pa.add_argument("--summary", help="New short competition summary.")
    pa.add_argument("--description", help="New full competition description.")
    pa.add_argument("--max-score", type=int, help="New maximum displayed score.")
    active_group = pa.add_mutually_exclusive_group()
    active_group.add_argument("--active", dest="active", action="store_true", default=None, help="Mark the competition as active.")
    active_group.add_argument("--inactive", dest="active", action="store_false", default=None, help="Mark the competition as inactive.")
    pa.add_argument("--answer-format", choices=["json", "zip"], help="Expected answer format for submissions.")
    pa.add_argument("--scoring-mode", choices=["absolute", "elo", "agent_judge", "reverse_judge"], help="Scoring mode used by the competition.")
    pa.add_argument("--script-timeout", type=int, help="Timeout in seconds for scoring-script execution.")
    pa.add_argument("--submit-limit", type=int, help="Maximum number of submissions allowed in the active limit window.")
    pa.add_argument("--reset-limit-window", action="store_true", help="Reset the per-user submission-limit window.")
    pa.add_argument("--submission-method", choices=["zip", "git"], help="Submission method accepted by the competition.")
    pa.add_argument("--git-format", help="Git repository URL format or rule used to derive participant repositories.")
    pa.add_argument("--agent-orchestration", choices=["single", "topological"], help="AI-judge orchestration mode.")
    pa.add_argument("--elo-initial-rating", type=float, help="Initial ELO rating assigned to new submissions.")
    pa.add_argument("--elo-k-factor", type=float, help="ELO K-factor used when updating ratings.")
    pa.add_argument("--elo-max-matches", type=int, help="Maximum number of ELO matches per submission.")
    pa.add_argument("--elo-match-interval", type=int, help="Interval in seconds between automatic ELO match rounds.")
    pa.add_argument("--elo-initial-burst", type=int, help="Number of initial ELO matches to schedule quickly for a new submission.")
    pa.add_argument("--elo-max-pairs-per-round", type=int, help="Maximum number of ELO match pairs generated per scheduler round.")
    pa.add_argument("--agent-timeout", type=int, help="Timeout in seconds for Agent-as-Judge evaluation or reverse-judge AI answering.")
    pa.add_argument("--reverse-finalize-timeout", type=int, help="Timeout in seconds for reverse-judge forced finalization after AI answering is cut off.")
    pa.set_defaults(func=ranking_edit)
    pa = add_cli_parser(rs, "delete", "Delete a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to delete.")
    pa.set_defaults(func=ranking_delete)
    pa = add_cli_parser(rs, "upload-attachment", "Upload a participant-visible attachment for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID receiving the attachment.")
    pa.add_argument("file", help="Path to the attachment file.")
    pa.set_defaults(func=ranking_upload_attachment)
    pa = add_cli_parser(rs, "delete-attachment", "Delete a ranking competition attachment.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the attachment.")
    pa.add_argument("file_id", type=int, help="Attachment file ID to delete.")
    pa.set_defaults(func=ranking_delete_attachment)
    pa = add_cli_parser(rs, "download-attachment", "Download a ranking competition attachment.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the attachment.")
    pa.add_argument("file_id", type=int, help="Attachment file ID to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded attachment.")
    pa.add_argument("--inline", action="store_true", help="Request inline display semantics from the server when supported.")
    pa.set_defaults(func=ranking_download_attachment)
    pa = add_cli_parser(rs, "upload-reference", "Upload a reference answer file for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID receiving the reference answer.")
    pa.add_argument("file", help="Path to the reference answer file.")
    pa.set_defaults(func=ranking_upload_reference)
    pa = add_cli_parser(rs, "upload-script", "Upload a scoring script for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID receiving the scoring script.")
    pa.add_argument("file", help="Path to the scoring script file.")
    pa.set_defaults(func=ranking_upload_script)
    pa = add_cli_parser(rs, "clear-script", "Remove the scoring script from a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose scoring script should be cleared.")
    pa.set_defaults(func=ranking_clear_script)
    pa = add_cli_parser(rs, "reset-limit", "Reset submission limits for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submission limits should be reset.")
    pa.set_defaults(func=ranking_reset_limit)
    pa = add_cli_parser(rs, "save-rules", "Save Agent-as-Judge grading rules for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument("rules", help="JSON array of rule objects, or @file to read it from a file.")
    pa.set_defaults(func=ranking_rules)
    pa = add_cli_parser(rs, "save-endpoints", "Save AI-judge endpoint pool for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument(
        "endpoints",
        help=(
            "JSON array of endpoint objects; each may include api_key or api_key_env, "
            "protocol, context_window_tokens, max_output_tokens, "
            "thinking_compatibility, thinking_format, "
            "status=enabled|paused|disabled, or legacy enabled=true/false. Missing model "
            "metadata defaults to 1000000, 384000, and true on the server."
        ),
    )
    pa.add_argument("--env-file", help="Optional .env file used by endpoint api_key_env fields.")
    pa.add_argument("--timeout-seconds", type=int, help="AI-judge timeout in seconds.")
    pa.add_argument("--reverse-finalize-timeout", type=int, help="Reverse-judge forced-finalization timeout in seconds.")
    pa.add_argument("--orchestration-mode", choices=["single", "topological"], help="AI-judge orchestration mode.")
    pa.set_defaults(func=ranking_endpoints)
    pa = add_cli_parser(rs, "save-endpoint", "Replace the AI-judge endpoint pool with one endpoint.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument("--harness", choices=["claude_code", "codex", "opencode", "pi"], default="claude_code", help="Agent harness used by the endpoint.")
    pa.add_argument("--protocol", choices=["openai", "anthropic"], help="Upstream endpoint protocol; required for Pi.")
    pa.add_argument("--agent-base-url", dest="base_url_value", required=True, help="Base URL for the AI-judge model API.")
    key_group = pa.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--api-key", help="API key text, or @file to read it from a file.")
    key_group.add_argument("--api-key-env", help="Environment variable name holding the API key.")
    pa.add_argument("--env-file", help="Optional .env file used with --api-key-env.")
    pa.add_argument("--model", required=True, help="Model identifier used by the endpoint.")
    _add_endpoint_model_config_args(pa)
    pa.add_argument("--concurrency-limit", type=int, default=1, help="Maximum concurrent jobs for this endpoint.")
    pa.add_argument("--status", choices=["enabled", "paused", "disabled"], default="enabled", help="Endpoint status.")
    pa.add_argument("--timeout-seconds", type=int, help="AI-judge timeout in seconds.")
    pa.add_argument("--reverse-finalize-timeout", type=int, help="Reverse-judge forced-finalization timeout in seconds.")
    pa.add_argument("--orchestration-mode", choices=["single", "topological"], help="AI-judge orchestration mode.")
    pa.set_defaults(func=ranking_save_endpoint)
    pa = add_cli_parser(rs, "save-quality-gate", "Save reverse-judge quality-gate policy and enabled state.")
    pa.add_argument("competition_id", type=int, help="Reverse-judge competition ID to configure.")
    enabled_group = pa.add_mutually_exclusive_group()
    enabled_group.add_argument(
        "--enabled",
        dest="enabled",
        action="store_true",
        default=None,
        help="Enable quality-gate review (requires a non-empty prompt and an enabled quality endpoint).",
    )
    enabled_group.add_argument(
        "--disabled",
        dest="enabled",
        action="store_false",
        default=None,
        help="Disable quality-gate review.",
    )
    pa.add_argument("--prompt", help="Quality-gate review prompt, or @file to read it from a file.")
    pa.set_defaults(func=ranking_save_quality_gate)
    pa = add_cli_parser(
        rs,
        "save-quality-gate-endpoints",
        "Replace the independently scheduled reverse-judge quality-gate endpoint pool.",
    )
    pa.add_argument("competition_id", type=int, help="Reverse-judge competition ID to configure.")
    pa.add_argument(
        "endpoints",
        help=(
            "JSON array of quality endpoint objects, or @file; api_key_env, "
            "protocol, context_window_tokens, max_output_tokens, "
            "thinking_compatibility, thinking_format, and "
            "status=enabled|paused|disabled are supported. Missing model metadata defaults "
            "to 1000000, 384000, and true on the server."
        ),
    )
    pa.add_argument("--env-file", help="Optional .env file used by endpoint api_key_env fields.")
    pa.set_defaults(func=ranking_save_quality_gate_endpoints)
    pa = add_cli_parser(
        rs,
        "save-quality-gate-endpoint",
        "Replace the reverse-judge quality-gate pool with one endpoint.",
    )
    pa.add_argument("competition_id", type=int, help="Reverse-judge competition ID to configure.")
    pa.add_argument("--harness", choices=["claude_code", "codex", "opencode", "pi"], default="claude_code", help="Agent harness used by the quality endpoint.")
    pa.add_argument("--protocol", choices=["openai", "anthropic"], help="Upstream endpoint protocol; required for Pi.")
    pa.add_argument("--agent-base-url", dest="base_url_value", required=True, help="Base URL for the quality-review model API.")
    key_group = pa.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--api-key", help="API key text, or @file to read it from a file.")
    key_group.add_argument("--api-key-env", help="Environment variable name holding the API key.")
    pa.add_argument("--env-file", help="Optional .env file used with --api-key-env.")
    pa.add_argument("--model", required=True, help="Model identifier used by the quality endpoint.")
    _add_endpoint_model_config_args(pa)
    pa.add_argument("--concurrency-limit", type=int, default=1, help="Maximum concurrent quality reviews for this endpoint.")
    pa.add_argument("--status", choices=["enabled", "paused", "disabled"], default="enabled", help="Quality endpoint status.")
    pa.set_defaults(func=ranking_save_quality_gate_endpoint)
    pa = add_cli_parser(rs, "batch-probe", "Preview Git repositories that would be used for batch ranking submissions.")
    pa.add_argument("competition_id", type=int, help="Competition ID for the batch probe.")
    pa.add_argument("--classes", required=True, help="Comma-separated class_en list to include.")
    pa.add_argument("--template", required=True, help="Git URL template used to derive repository URLs.")
    pa.set_defaults(func=ranking_batch_probe)
    pa = add_cli_parser(rs, "batch-status", "Check status for a batch ranking-submission job.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the batch job.")
    pa.add_argument("job_id", help="Batch job ID returned by batch-create or bulk-start.")
    pa.set_defaults(func=ranking_batch_status)
    pa = add_cli_parser(rs, "batch-create", "Create ranking submissions in batch from a Git URL template.")
    pa.add_argument("competition_id", type=int, help="Competition ID for the batch submissions.")
    pa.add_argument("--template", required=True, help="Git URL template used to derive repository URLs.")
    pa.add_argument("--usernames", required=True, help="Comma-separated usernames to submit for.")
    pa.add_argument("--agent-endpoint-id", type=int, help="AI endpoint id selected for reverse_judge batch submissions.")
    pa.set_defaults(func=ranking_batch_create)
    pa = add_cli_parser(rs, "matches", "List ELO or Agent-as-Judge matches for a competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose matches should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--mine", action="store_true", help="Show only matches involving the current user when supported.")
    pa.set_defaults(func=ranking_matches)
    pa = add_cli_parser(rs, "match-detail", "Fetch details for one ranking match.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the match.")
    pa.add_argument("match_id", type=int, help="Match ID to inspect.")
    pa.set_defaults(func=ranking_match_detail)
    pa = add_cli_parser(rs, "bulk-filter", "Preview ranking submissions matching bulk-operation filters.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be filtered.")
    pa.add_argument("--start", help="Inclusive start time filter accepted by the server.")
    pa.add_argument("--end", help="Exclusive end time filter accepted by the server.")
    pa.add_argument("--username", help="Filter by username.")
    pa.add_argument("--statuses", help="Comma-separated statuses, such as judging, waiting, accepted, or abnormal.")
    pa.set_defaults(func=ranking_bulk_filter)
    pa = add_cli_parser(rs, "bulk-start", "Start a bulk ranking operation for selected submissions.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be processed.")
    pa.add_argument("--submission-ids", required=True, help="Comma-separated ranking submission IDs.")
    pa.set_defaults(func=ranking_bulk_start)
    pa = add_cli_parser(rs, "bulk-status", "Check status for a bulk ranking operation.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the bulk job.")
    pa.add_argument("job_id", help="Bulk job ID returned by bulk-start.")
    pa.set_defaults(func=ranking_bulk_status)
    pa = add_cli_parser(rs, "rejudge-agent", "Requeue Agent-as-Judge or reverse-judge evaluation for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to rejudge.")
    pa.set_defaults(func=ranking_rejudge_agent)
    pa = add_cli_parser(rs, "appeal", "Submit an appeal for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID being appealed.")
    pa.add_argument("--reason", required=True, help="Appeal reason text, or @file to read it from a file.")
    pa.set_defaults(func=ranking_submit_appeal)
    pa = add_cli_parser(rs, "appeal-status", "Fetch appeal status for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose appeal status should be fetched.")
    pa.set_defaults(func=ranking_appeal_status)
    pa = add_cli_parser(rs, "appeals", "List appeals for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose appeals should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--query", help="Search query for appeal list filtering.")
    pa.add_argument("--status", help="Appeal status filter accepted by the server.")
    pa.set_defaults(func=ranking_appeals)
    pa = add_cli_parser(rs, "appeal-review", "Fetch ranking appeal review metadata as JSON.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the appeal.")
    pa.add_argument("appeal_id", type=int, help="Appeal ID to review.")
    pa.add_argument("--full", action="store_true", help="Print the raw appeal review payload.")
    pa.set_defaults(func=ranking_appeal_review)
    pa = add_cli_parser(rs, "appeal-handle", "Resolve or reject a ranking appeal.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the appeal.")
    pa.add_argument("appeal_id", type=int, help="Appeal ID to handle.")
    pa.add_argument("--decision", choices=["resolved", "rejected"], required=True, help="Appeal decision to record.")
    pa.add_argument("--response", default="", help="Administrator response text sent with the decision.")
    pa.add_argument("--overrides", help="JSON object with score/status overrides, or @file to read it from a file.")
    pa.set_defaults(func=ranking_appeal_handle)
    for name in ("start", "stop", "reset"):
        descriptions = {
            "start": "Start automatic ELO matching for a ranking competition.",
            "stop": "Stop automatic ELO matching for a ranking competition.",
            "reset": "Reset ELO matching state for a ranking competition.",
        }
        pa = add_cli_parser(rs, f"elo-{name}", descriptions[name])
        pa.add_argument("competition_id", type=int, help="Competition ID whose ELO scheduler should be updated.")
        pa.set_defaults(func=ranking_elo_action, action=name)
    pa = add_cli_parser(rs, "elo-delete-match", "Delete one ELO match record.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the match.")
    pa.add_argument("match_id", type=int, help="ELO match ID to delete.")
    pa.set_defaults(func=ranking_elo_delete_match)
    pa = add_cli_parser(rs, "elo-rebuild", "Rebuild ELO ratings for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose ELO ratings should be rebuilt.")
    pa.set_defaults(func=ranking_elo_rebuild)
    pa = add_cli_parser(rs, "delete-submission", "Delete one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to delete.")
    pa.set_defaults(func=ranking_delete_submission)
    pa = add_cli_parser(rs, "download-submission", "Download an uploaded answer, code archive, or reverse-judge AI answer.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to download from.")
    pa.add_argument("kind", choices=["answer", "code", "ai-answer"], help="Submission artifact to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded artifact.")
    pa.set_defaults(func=ranking_download_submission)
    pa = add_cli_parser(rs, "judge-stream", "Fetch recent judge stream lines for a ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose judge stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.add_argument("--full", action="store_true", help="Print raw stream lines instead of the default judge-status summary.")
    pa.set_defaults(func=ranking_judge_stream)
    pa = add_cli_parser(rs, "reverse-stream", "Fetch recent reverse-judge step snapshots for a ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Reverse-judge submission ID whose step stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.add_argument("--full", action="store_true", help="Print raw stream lines instead of the default reverse-judge summary.")
    pa.set_defaults(func=ranking_reverse_judge_stream)
    pa = add_cli_parser(rs, "my-submissions", "List the current user's submissions for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be listed.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=ranking_my_submissions)
    pa = add_cli_parser(rs, "submissions", "List all visible submissions for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--username", help="Filter submissions by username.")
    pa.set_defaults(func=ranking_all_submissions)
    pa = add_cli_parser(rs, "leaderboard", "Fetch the leaderboard for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose leaderboard should be fetched.")
    pa.add_argument("--limit", type=int, help="Maximum number of leaderboard rows to return.")
    pa.set_defaults(func=ranking_leaderboard)
    pa = add_cli_parser(rs, "submit", "Submit a ZIP-based ranking entry; for reverse_judge, --code-zip is the problem package.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", help="Base model name associated with the submission. Required unless the competition is reverse_judge.")
    pa.add_argument("--code-zip", required=True, help="Path to the code ZIP archive, or reverse-judge problem ZIP package.")
    pa.add_argument("--answer-file", help="Optional answer file path to upload with the submission.")
    pa.add_argument("--agent-endpoint-id", type=int, help="AI endpoint id selected for reverse_judge submissions.")
    pa.set_defaults(func=ranking_submit_zip)
    pa = add_cli_parser(rs, "submit-zip", "Alias for ranking submit; submit a ZIP-based ranking entry.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", help="Base model name associated with the submission. Required unless the competition is reverse_judge.")
    pa.add_argument("--code-zip", required=True, help="Path to the code ZIP archive, or reverse-judge problem ZIP package.")
    pa.add_argument("--answer-file", help="Optional answer file path to upload with the submission.")
    pa.add_argument("--agent-endpoint-id", type=int, help="AI endpoint id selected for reverse_judge submissions.")
    pa.set_defaults(func=ranking_submit_zip)
    pa = add_cli_parser(
        rs,
        "git",
        "Use Git-based ranking submission: run check first, then submit.",
        epilog=(
            "Run `ranking git <competition_id> check` first to verify the server-derived "
            "repository URL and latest commit, then run `ranking git <competition_id> submit`. "
            "Do not pass a repository URL; NumOJ derives it from the competition Git rule and your username."
        ),
    )
    pa.add_argument("competition_id", type=int, help="Competition ID configured for Git submission.")
    pa.add_argument("action", choices=["check", "submit"], help="Use check to verify repository visibility; use submit to queue the checked repository for evaluation.")
    pa.add_argument("--agent-endpoint-id", type=int, help="AI endpoint id selected for reverse_judge git submissions.")
    pa.set_defaults(func=ranking_git_submit)
