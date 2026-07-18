from __future__ import annotations

import argparse
import getpass
from urllib.parse import urljoin

from . import common


def login(args: argparse.Namespace) -> None:
    cfg = common.load_config(args.config)
    raw_base_url = getattr(args, "login_base_url", None) or args.base_url or cfg.get("base_url") or ""
    if not raw_base_url and getattr(args, "prompt_base_url", False):
        raw_base_url = input("NumOJ URL (domain or ip:port): ").strip()
    base_url = common.normalize_base_url(raw_base_url)
    username = args.username or input("Username: ").strip()
    password = args.password or getpass.getpass("Password: ")
    sess = common.requests.Session()
    sess.trust_env = False
    resp = sess.post(
        urljoin(base_url + "/", "/login"),
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=args.timeout,
    )
    if resp.status_code not in (301, 302, 303, 307, 308) or "session" not in sess.cookies.get_dict():
        raise common.CliError(f"Login failed. HTTP {resp.status_code}: {resp.text[:500].strip()}")
    cfg["base_url"] = base_url
    cfg["username"] = username
    cfg["cookies"] = sess.cookies.get_dict()
    common.save_config(args.config, cfg)
    common.output_json({"success": True, "base_url": base_url, "username": username, "config": str(args.config)})


def logout(args: argparse.Namespace) -> None:
    cfg = common.load_config(args.config)
    if cfg.get("cookies"):
        try:
            common.client_from_args(args, require_auth=False).request("POST", "/logout")
        except Exception:
            pass
    cfg.pop("cookies", None)
    common.save_config(args.config, cfg)
    common.output_json({"success": True, "message": "local token cleared"})


def status(args: argparse.Namespace) -> None:
    cfg = common.load_config(args.config)
    if not (cfg.get("base_url") or args.base_url):
        common.output_json(
            {
                "authenticated": False,
                "base_url": None,
                "username": cfg.get("username"),
            }
        )
        return
    client = common.client_from_args(args, require_auth=False)
    resp = client.request("GET", "/me/classes")
    common.output_json(
        {
            "authenticated": resp.status_code < 400,
            "base_url": client.base_url,
            "username": cfg.get("username"),
        }
    )


def auth_send_password_code(args: argparse.Namespace) -> None:
    resp = common.client_from_args(args).request("POST", "/send_password_code")
    common.print_or_save_response(resp)


def auth_change_password(args: argparse.Namespace) -> None:
    confirm = args.confirm_password or args.new_password
    resp = common.client_from_args(args).request(
        "POST",
        "/change_password",
        data={"code": args.code, "new_password": args.new_password, "confirm_password": confirm},
    )
    common.print_redirect_response(resp)


def register_init(subparsers: argparse._SubParsersAction) -> None:
    pa = common.add_cli_parser(subparsers, "init", "First-time setup: save the NumOJ URL and user session token.")
    pa.add_argument("--base-url", dest="login_base_url", help="NumOJ server URL, e.g. https://oj.example.com or 127.0.0.1:2025.")
    pa.add_argument("-u", "--username", help="Username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=login, prompt_base_url=True)


def register(subparsers: argparse._SubParsersAction) -> None:
    auth = common.add_cli_parser(subparsers, "auth", "Manage CLI authentication and account password actions.")
    auth_sub = auth.add_subparsers(dest="cmd", required=True)
    pa = common.add_cli_parser(auth_sub, "login", "Log in and save a fresh user session cookie.")
    pa.add_argument("--base-url", dest="login_base_url", help="NumOJ server URL, e.g. https://oj.example.com.")
    pa.add_argument("-u", "--username", help="Username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=login)
    pa = common.add_cli_parser(auth_sub, "logout", "Delete the saved local CLI session config.")
    pa.set_defaults(func=logout)
    pa = common.add_cli_parser(auth_sub, "status", "Check whether the saved session is authenticated.")
    pa.set_defaults(func=status)
    pa = common.add_cli_parser(auth_sub, "send-password-code", "Request a password-change verification code for the current session.")
    pa.set_defaults(func=auth_send_password_code)
    pa = common.add_cli_parser(auth_sub, "change-password", "Change the current account password using a verification code.")
    pa.add_argument("--code", required=True, help="Verification code received from the password-code request.")
    pa.add_argument("--new-password", required=True, help="New password to set for the current account.")
    pa.add_argument("--confirm-password", help="Confirmation password. Defaults to --new-password when omitted.")
    pa.set_defaults(func=auth_change_password)
