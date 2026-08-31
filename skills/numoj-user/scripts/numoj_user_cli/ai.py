from __future__ import annotations

import argparse
from typing import Any, Dict

from . import common


def necessary_ai_code_marks_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    necessary: Dict[str, Any] = {}
    for key in ("success", "source", "summary", "issues", "image_mismatch_analysis", "image_analysis_test_index"):
        value = payload.get(key)
        if value not in (None, "", []):
            necessary[key] = value
    if "success" in payload and "success" not in necessary:
        necessary["success"] = payload["success"]
    return necessary


def ai_code_marks(args: argparse.Namespace) -> None:
    payload = {
        "submission_id": args.submission_id,
        "force_refresh": bool(args.force_refresh),
    }
    resp = common.client_from_args(args).request("POST", "/api/ai/code-marks", json=payload)
    common.ensure_ok(resp, allow_redirect=False)
    if common.response_is_json(resp):
        common.output_json(necessary_ai_code_marks_payload(resp.json()))
        return
    print(resp.text.strip())


def register(subparsers: argparse._SubParsersAction) -> None:
    ai = common.add_cli_parser(subparsers, "ai", "Call AI tutor endpoints for submissions.")
    ai_sub = ai.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(ai_sub, "marks", "Fetch AI-generated code marks for one submission.")
    pa.add_argument("--submission-id", type=int, required=True, help="Submission ID whose AI marks should be fetched.")
    pa.add_argument("--force-refresh", action="store_true", help="Force the server to refresh cached AI marks.")
    pa.set_defaults(func=ai_code_marks)
