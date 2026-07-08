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


def ai_code_marks(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "submission_id": args.submission_id,
        "force_refresh": bool(args.force_refresh),
    }
    resp = client.request("POST", "/ask_ai_code_marks", json=payload)
    print_or_save_response(resp)


def register(subparsers: argparse._SubParsersAction) -> None:

    sub = subparsers

    tutor = add_cli_parser(sub, "ai", "Call AI tutor endpoints for submissions.")
    tutors = tutor.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(tutors, "marks", "Fetch AI-generated code marks for one submission.")
    pa.add_argument("--submission-id", type=int, required=True, help="Submission ID whose AI marks should be fetched.")
    pa.add_argument("--force-refresh", action="store_true", help="Force the server to refresh cached AI marks.")
    pa.set_defaults(func=ai_code_marks)

