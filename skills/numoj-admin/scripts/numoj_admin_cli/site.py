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

def site_home(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/v1/session")
    print_redirect_response(resp, allow_login_redirect=True)


def register(subparsers: argparse._SubParsersAction) -> None:
    site = add_cli_parser(subparsers, "site", "Inspect the public session bootstrap API.")
    sites = site.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(sites, "home", "Fetch the SPA session bootstrap payload.")
    pa.set_defaults(func=site_home)
