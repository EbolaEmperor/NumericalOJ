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


def grading_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/submit_grading/{args.submission_id}",
        data={"score": args.score, "comment": read_text_value(args.comment)},
    )
    print_or_save_response(resp)


def grading_next_pending(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/get_next_pending_submission/{args.submission_id}")
    print_or_save_response(resp, fail_on_business_error=False)


def grading_invalidate(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/invalidate_invalid_submissions/{args.problem_id}")
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    grading = add_cli_parser(sub, "grading", "Handle manual grading actions for written-homework submissions.")
    gs = grading.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(gs, "submit", "Submit a manual grading decision for a written-homework submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to grade.")
    pa.add_argument("--score", type=int, required=True, help="Score to assign.")
    pa.add_argument("--comment", default="", help="Optional grading comment.")
    pa.set_defaults(func=grading_submit)
    pa = add_cli_parser(gs, "next-pending", "Find the next pending manual-grading submission after the given submission.")
    pa.add_argument("submission_id", type=int, help="Current submission ID used as the search starting point.")
    pa.set_defaults(func=grading_next_pending)
    pa = add_cli_parser(gs, "invalidate-invalid", "Invalidate written-homework submissions marked invalid for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose invalid submissions should be invalidated.")
    pa.set_defaults(func=grading_invalidate)
