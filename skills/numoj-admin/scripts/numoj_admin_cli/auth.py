from __future__ import annotations

import argparse
import getpass
import html
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


def _admin_probe(session: requests.Session, base_url: str, timeout: float):
    return session.get(
        urljoin(base_url + "/", "/api/admin/users"),
        params={"page": 1},
        headers={"Accept": "application/json"},
        allow_redirects=False,
        timeout=timeout,
    )


def _login_failure_reason(resp: requests.Response) -> str:
    """Return a concise server-side login error without leaking an HTML page."""
    if response_is_json(resp):
        try:
            payload = resp.json() or {}
            if isinstance(payload, dict) and payload.get("message"):
                return str(payload["message"])
        except Exception:
            pass

    match = re.search(
        r'<div\b[^>]*\balert-danger\b[^>]*>(.*?)</div>',
        resp.text or "",
        flags=re.IGNORECASE | re.DOTALL,
    )
    if match:
        text = re.sub(r"<[^>]+>", " ", match.group(1))
        text = re.sub(r"\s+", " ", html.unescape(text)).strip()
        if text:
            return text

    return "服务器未返回可识别的登录成功响应"


def login(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    login_base_url = getattr(args, "login_base_url", None)
    raw_base_url = login_base_url or args.base_url or cfg.get("base_url") or ""
    if not raw_base_url and getattr(args, "prompt_base_url", False):
        raw_base_url = input("NumOJ URL (domain or ip:port): ").strip()
    base_url = normalize_base_url(raw_base_url)
    username = args.username or input("Username: ").strip()
    password = args.password or getpass.getpass("Password: ")
    sess = requests.Session()
    sess.trust_env = False
    resp = sess.post(
        urljoin(base_url + "/", "/login"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=args.timeout,
    )
    has_session_cookie = "session" in sess.cookies.get_dict()
    if resp.status_code >= 400 or not has_session_cookie:
        reason = _login_failure_reason(resp)
        raise CliError(f"Login failed. HTTP {resp.status_code}: {reason}")
    admin_resp = _admin_probe(sess, base_url, args.timeout)
    if admin_resp.status_code >= 400 or 300 <= admin_resp.status_code < 400:
        reason = ""
        if response_is_json(admin_resp):
            try:
                reason = str((admin_resp.json() or {}).get("message") or "")
            except Exception:
                reason = ""
        payload = {
            "success": False,
            "authenticated": admin_resp.status_code != 401 and not (300 <= admin_resp.status_code < 400),
            "admin": False,
            "base_url": base_url,
            "username": username,
            "http_status": admin_resp.status_code,
            "message": reason or "Login succeeded, but this account does not have administrator privileges.",
        }
        raise common.CliHttpError(admin_resp.status_code, payload)
    cfg["base_url"] = base_url
    cfg["username"] = username
    cfg["cookies"] = sess.cookies.get_dict()
    save_config(args.config, cfg)
    output_json(
        {
            "success": True,
            "base_url": base_url,
            "username": username,
            "token_type": "flask-session-cookie",
            "config": str(args.config),
        }
    )


def init_cli(args: argparse.Namespace) -> None:
    login(args)


def logout(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    if cfg.get("cookies"):
        try:
            client = NumOJClient(cfg, timeout=args.timeout)
            client.request("POST", "/logout")
        except Exception:
            pass
    cfg.pop("cookies", None)
    save_config(args.config, cfg)
    output_json({"success": True, "message": "local token cleared"})


def status(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    raw_base_url = args.base_url or cfg.get("base_url") or ""
    if not raw_base_url:
        output_json(
            {
                "authenticated": False,
                "admin": False,
                "base_url": None,
                "username": cfg.get("username"),
                "reason": "no_config",
            }
        )
        return
    base_url = normalize_base_url(raw_base_url)
    cookies = cfg.get("cookies") or {}
    if not cookies.get("session"):
        output_json(
            {
                "authenticated": False,
                "admin": False,
                "base_url": base_url,
                "username": cfg.get("username"),
                "reason": "no_session_cookie",
            }
        )
        return
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/users", params={"page": 1}, headers={"Accept": "application/json"})
    if resp.status_code in (301, 302, 303, 307, 308):
        output_json(
            {
                "authenticated": False,
                "admin": False,
                "base_url": client.base_url,
                "location": resp.headers.get("Location", ""),
                "reason": "redirected",
            }
        )
        return
    message = ""
    if response_is_json(resp):
        try:
            message = str((resp.json() or {}).get("message") or "")
        except Exception:
            message = ""
    authenticated = resp.status_code != 401 and not (300 <= resp.status_code < 400)
    output_json(
        {
            "authenticated": authenticated,
            "admin": resp.status_code < 400,
            "base_url": client.base_url,
            "username": cfg.get("username"),
            "http_status": resp.status_code,
            "reason": "ok" if resp.status_code < 400 else (message or "not_admin"),
        }
    )

def auth_send_password_code(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/send_password_code")
    print_or_save_response(resp)


def auth_change_password(args: argparse.Namespace) -> None:
    confirm = args.confirm_password or args.new_password
    resp = client_from_args(args).request(
        "POST",
        "/change_password",
        data={"code": args.code, "new_password": args.new_password, "confirm_password": confirm},
    )
    print_redirect_response(resp)


def register_init(subparsers: argparse._SubParsersAction) -> None:
    pa = add_cli_parser(subparsers, "init", "First-time setup: save the NumOJ URL and administrator session token.")
    pa.add_argument("--base-url", dest="login_base_url", required=False, help="NumOJ server URL, e.g. https://oj.example.com or 127.0.0.1:2025.")
    pa.add_argument("-u", "--username", help="Administrator username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Administrator password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=init_cli, prompt_base_url=True)


def register(subparsers: argparse._SubParsersAction) -> None:
    auth = add_cli_parser(subparsers, "auth", "Manage CLI authentication and account password actions.")
    auth_sub = auth.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(auth_sub, "login", "Log in and save a fresh administrator session cookie.")
    pa.add_argument("--base-url", dest="login_base_url", required=False, help="NumOJ server URL, e.g. https://oj.example.com.")
    pa.add_argument("-u", "--username", help="Administrator username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Administrator password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=login)
    pa = add_cli_parser(auth_sub, "logout", "Delete the saved local CLI session config.")
    pa.set_defaults(func=logout)
    pa = add_cli_parser(auth_sub, "status", "Check whether the saved session is authenticated and has administrator privileges.")
    pa.set_defaults(func=status)
    pa = add_cli_parser(auth_sub, "send-password-code", "Request a password-change verification code for the current session.")
    pa.set_defaults(func=auth_send_password_code)
    pa = add_cli_parser(auth_sub, "change-password", "Change the current account password using a verification code.")
    pa.add_argument("--code", required=True, help="Verification code received from the password-code request.")
    pa.add_argument("--new-password", required=True, help="New password to set for the current account.")
    pa.add_argument("--confirm-password", help="Confirmation password. Defaults to --new-password when omitted.")
    pa.set_defaults(func=auth_change_password)
