from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common


def _necessary_competition(row: Any, *, include_description: bool = False) -> Dict[str, Any]:
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
    ]
    if include_description:
        keys.insert(3, "description")
    return {key: row[key] for key in keys if key in row}


def _necessary_ranking_file(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {key: row[key] for key in ("id", "filename", "media_kind", "download_url") if key in row}


def _necessary_answer_endpoint(row: Any) -> Dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        key: row[key]
        for key in ("id", "harness", "model", "label")
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
            "status",
            "created_at",
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
            "rating_a_before",
            "rating_a_after",
            "rating_b_before",
            "rating_b_after",
            "created_at",
            "details",
            "detail_output",
            "error_message",
        )
        if key in row
    }


def necessary_ranking_list_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "competitions": [_necessary_competition(row) for row in payload.get("competitions") or []],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
    }


def necessary_ranking_detail_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {
        "competition": _necessary_competition(payload.get("competition"), include_description=True),
    }
    for key in ("tab", "submission_method", "judge_ready", "can_submit", "submit_block_reason", "submit_quota", "git_repo_url"):
        if key in payload:
            necessary[key] = payload[key]
    if "files" in payload:
        necessary["files"] = [_necessary_ranking_file(row) for row in payload.get("files") or []]
    if "answer_endpoints" in payload:
        necessary["answer_endpoints"] = [
            _necessary_answer_endpoint(row)
            for row in payload.get("answer_endpoints") or []
            if isinstance(row, dict)
        ]
    if "user_submissions" in payload:
        necessary["user_submissions"] = [_necessary_ranking_submission(row) for row in payload.get("user_submissions") or []]
    if "leaderboard" in payload:
        necessary["leaderboard"] = payload.get("leaderboard") or []
    if "matches" in payload:
        necessary["matches"] = [_necessary_match(row) for row in payload.get("matches") or []]
        for key in ("matches_total", "matches_mine", "current_page", "total_pages", "matches_per_page"):
            if key in payload:
                necessary[key] = payload[key]
    return necessary


def necessary_ranking_submissions_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {
        "competition_id": payload.get("competition_id"),
        "submissions": [_necessary_ranking_submission(row) for row in payload.get("submissions") or []],
        "count": payload.get("count", 0),
        "total": payload.get("total", payload.get("count", 0)),
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


def necessary_reverse_judge_snapshot_payload(event: Any) -> Any:
    if not isinstance(event, dict):
        text = str(event or "")
        return text if len(text) <= 500 else {"text": text[:500], "chars": len(text), "truncated": True}
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
    return out


def ranking_list(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/ranking/competitions", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_list_payload(resp.json()))
        return
    print(resp.text.strip())


def ranking_detail(args: argparse.Namespace) -> None:
    params = {"tab": args.tab} if args.tab else None
    resp = common.client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_detail_payload(resp.json()))
        return
    print(resp.text.strip())


def ranking_matches(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.mine:
        params["mine"] = "1"
    resp = common.client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}/matches", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_matches_payload(resp.json()))
        return
    print(resp.text.strip())


def ranking_match_detail(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}/matches/{args.match_id}")
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_match_detail_payload(resp.json()))
        return
    print(resp.text.strip())


def _ranking_submission_ids(client: common.NumOJClient, competition_id: int) -> set[int]:
    resp = client.request("GET", f"/api/ranking/competitions/{competition_id}/my-submissions")
    if resp.status_code >= 400 or not common.response_is_json(resp):
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


def ranking_submit(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    before_ids = _ranking_submission_ids(client, args.competition_id)
    files = {"code_file": common.require_file(args.code_zip)}
    data: Dict[str, str] = {}
    if args.base_model is not None:
        data["base_model"] = args.base_model
    if getattr(args, "agent_endpoint_id", None) is not None:
        data["agent_endpoint_id"] = str(args.agent_endpoint_id)
    if args.answer_file:
        files["answer_file"] = common.require_file(args.answer_file)
    try:
        resp = client.request(
            "POST",
            f"/api/ranking/competitions/{args.competition_id}/submissions",
            data=data,
            files=files,
            headers={"Accept": "application/json"},
        )
    finally:
        common.close_files(files)

    # 反向代理可能在上游已落库后才因回写重定向失败返回 5xx。此时先用
    # 只读历史确认提交是否已创建；若已创建，绝不能把它误报为失败并诱发
    # 用户或 Agent 重复提交。
    if resp.status_code >= 500:
        after_ids = _ranking_submission_ids(client, args.competition_id)
        new_ids = sorted(after_ids - before_ids)
        if new_ids:
            common.output_json({
                "success": True,
                "submission_id": new_ids[-1],
                "recovered_from_transport_error": True,
                "message": (
                    f"提交接口返回 HTTP {resp.status_code}，但已确认提交 "
                    f"#{new_ids[-1]} 已创建；请不要重复提交。"
                ),
            })
            return

    if resp.status_code >= 400 and common.response_is_json(resp):
        payload = resp.json()
        if isinstance(payload, dict) and "success" not in payload:
            payload["success"] = False
        common.output_json(payload)
        return
    common.ensure_ok(resp)
    after_ids = _ranking_submission_ids(client, args.competition_id)
    new_ids = sorted(after_ids - before_ids)
    payload: Dict[str, Any] = {
        "success": bool(new_ids),
    }
    if new_ids:
        payload["submission_id"] = new_ids[-1]
    else:
        payload["message"] = "The submission request completed, but no new submission record was created. Check the submission method, quota, or form errors."
    common.output_json(payload)


def ranking_git(args: argparse.Namespace) -> None:
    path = "repository/check" if args.action == "check" else "repository/submissions"
    resp = common.client_from_args(args).request("POST", f"/api/ranking/competitions/{args.competition_id}/{path}")
    if resp.status_code >= 400 and common.response_is_json(resp):
        payload = resp.json()
        if isinstance(payload, dict) and "success" not in payload:
            payload["success"] = False
        common.output_json(payload)
        return
    common.print_or_save_response(resp)


def ranking_my_submissions(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/my-submissions", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_submissions_payload(resp.json()))
        return
    print(resp.text.strip())


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/leaderboard", params=params)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ranking_leaderboard_payload(resp.json()))
        return
    print(resp.text.strip())


def ranking_download_submission(args: argparse.Namespace) -> None:
    if args.kind == "ai-answer":
        path = f"/api/ranking/submissions/{args.submission_id}/reverse-agent-answer"
    else:
        path = f"/api/ranking/submissions/{args.submission_id}/{args.kind}"
    resp = common.client_from_args(args).request("GET", path)
    common.print_or_save_response(
        resp, output=args.output or ".", allow_redirect=False,
    )


def ranking_judge_stream(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}/submissions/{args.submission_id}/judge-events", stream=True)
    common.print_stream_lines(resp, max_lines=args.max_lines)


def ranking_reverse_judge_stream(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request(
        "GET",
        f"/api/ranking/competitions/{args.competition_id}/submissions/{args.submission_id}/reverse-judge-events",
        stream=True,
    )
    stream_payload = common.read_stream_events(resp, max_lines=args.max_lines)
    events = stream_payload.get("events") or []
    latest = events[-1] if events else None
    common.output_json({
        "success": True,
        "events_count": len(events),
        "latest": necessary_reverse_judge_snapshot_payload(latest) if latest is not None else None,
        "truncated": bool(stream_payload.get("truncated")),
    })


def ranking_submit_appeal(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request(
        "POST",
        f"/api/ranking/competitions/{args.competition_id}/submissions/{args.submission_id}/appeal",
        data={"reason": common.read_text_value(args.reason)},
    )
    common.print_or_save_response(resp)


def ranking_appeal_status(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}/submissions/{args.submission_id}/appeal")
    common.print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:
    ranking = common.add_cli_parser(subparsers, "ranking", "Use ranking competitions, submissions, matches, leaderboards, and appeals.")
    rank_sub = ranking.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(rank_sub, "list", "List ranking competitions.")
    pa.add_argument("--limit", type=int, help="Maximum number of competitions to return.")
    pa.set_defaults(func=ranking_list)
    pa = common.add_cli_parser(rank_sub, "detail", "Fetch ranking competition detail metadata as JSON.")
    pa.add_argument("competition_id", type=int, help="Competition ID to inspect.")
    pa.add_argument("--tab", help="Optional detail tab to request, such as submissions, leaderboard, or settings.")
    pa.set_defaults(func=ranking_detail)
    pa = common.add_cli_parser(rank_sub, "matches", "List ELO or Agent-as-Judge matches for a competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose matches should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--mine", action="store_true", help="Show only matches involving the current user when supported.")
    pa.set_defaults(func=ranking_matches)
    pa = common.add_cli_parser(rank_sub, "match-detail", "Fetch details for one ranking match.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the match.")
    pa.add_argument("match_id", type=int, help="Match ID to inspect.")
    pa.set_defaults(func=ranking_match_detail)
    pa = common.add_cli_parser(rank_sub, "submit", "Submit a ZIP-based ranking entry.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", help="Base model name associated with a normal submission; reverse-judge submissions do not require it.")
    pa.add_argument(
        "--code-zip",
        required=True,
        help="Submitted ZIP archive; this is the only uploaded artifact for ELO.",
    )
    pa.add_argument("--answer-file", help="Additional answer file required by absolute scoring only.")
    pa.add_argument("--agent-endpoint-id", type=int, help="AI endpoint ID for reverse-judge submissions.")
    pa.set_defaults(func=ranking_submit)
    pa = common.add_cli_parser(
        rank_sub,
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
    pa.set_defaults(func=ranking_git)
    pa = common.add_cli_parser(rank_sub, "my-submissions", "List the current user's submissions for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be listed.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=ranking_my_submissions)
    pa = common.add_cli_parser(rank_sub, "leaderboard", "Fetch the leaderboard for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose leaderboard should be fetched.")
    pa.add_argument("--limit", type=int, help="Maximum number of leaderboard rows to return.")
    pa.set_defaults(func=ranking_leaderboard)
    pa = common.add_cli_parser(rank_sub, "download-submission", "Download an uploaded answer, code archive, or reverse-judge AI answer.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to download from.")
    pa.add_argument("kind", choices=["answer", "code", "ai-answer"], help="Submission artifact to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded artifact.")
    pa.set_defaults(func=ranking_download_submission)
    pa = common.add_cli_parser(rank_sub, "judge-stream", "Fetch recent judge stream lines for a ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose judge stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=ranking_judge_stream)
    pa = common.add_cli_parser(rank_sub, "reverse-stream", "Fetch projected reverse-judge step snapshots for your submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Reverse-judge submission ID whose step stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to read.")
    pa.set_defaults(func=ranking_reverse_judge_stream)
    pa = common.add_cli_parser(rank_sub, "appeal", "Submit an appeal for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID being appealed.")
    pa.add_argument("--reason", required=True, help="Appeal reason text, or @file to read it from a file.")
    pa.set_defaults(func=ranking_submit_appeal)
    pa = common.add_cli_parser(rank_sub, "appeal-status", "Fetch appeal status for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose appeal status should be fetched.")
    pa.set_defaults(func=ranking_appeal_status)
