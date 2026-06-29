#!/usr/bin/env python3
"""NumericalOJ administrator CLI over existing web routes.

This tool intentionally does not import the Flask app or touch MySQL/Redis.
It authenticates by saving the Flask session cookie locally and then sends that
cookie back to existing routes, so current admin POST handlers can authorize it
without any new server-side POST endpoint.
"""

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

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "numoj-admin requires the Python package 'requests'. "
        "Install it in this skill runtime with: python3 -m pip install --user requests"
    ) from exc


DEFAULT_CONFIG_PATH = Path(
    os.environ.get("NUMOJ_CLI_CONFIG", "~/.numoj-cli/config.json")
).expanduser()


class CliError(RuntimeError):
    pass


def eprint(*parts: Any) -> None:
    print(*parts, file=sys.stderr)


def read_text_value(value: Optional[str]) -> str:
    if value is None:
        return ""
    if value.startswith("@"):
        return Path(value[1:]).expanduser().read_text(encoding="utf-8")
    return value


def parse_json_value(value: str) -> Any:
    text = read_text_value(value)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CliError(f"Invalid JSON: {exc}") from exc


def parse_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_int_csv(value: Optional[str]) -> List[int]:
    out: List[int] = []
    for item in parse_csv(value):
        try:
            out.append(int(item))
        except ValueError as exc:
            raise CliError(f"Expected integer in comma list, got {item!r}") from exc
    return out


def normalize_base_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise CliError("Missing base URL. Run init first, or pass --base-url.")
    if not re.match(r"^https?://", raw):
        raw = "http://" + raw
    return raw.rstrip("/")


def load_config(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CliError(f"Cannot read config {path}: {exc}") from exc


def save_config(path: Path, cfg: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def output_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False))


def content_disposition_filename(header: str) -> Optional[str]:
    if not header:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', header)
    if match:
        return os.path.basename(match.group(1))
    return None


class NumOJClient:
    def __init__(self, cfg: Dict[str, Any], *, timeout: float = 60.0):
        self.cfg = cfg
        self.base_url = normalize_base_url(cfg.get("base_url") or "")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "numoj-cli/0.1"})
        for name, value in (cfg.get("cookies") or {}).items():
            self.session.cookies.set(name, value)

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        resp = self.session.request(method.upper(), url, **kwargs)
        return resp


def response_is_json(resp: requests.Response) -> bool:
    return "application/json" in (resp.headers.get("Content-Type") or "").lower()


def ensure_ok(resp: requests.Response, *, allow_redirect: bool = True) -> None:
    if allow_redirect and 300 <= resp.status_code < 400:
        return
    if resp.status_code < 400:
        return
    body = resp.text[:1000].strip()
    raise CliError(f"HTTP {resp.status_code}: {body or resp.reason}")


def print_or_save_response(
    resp: requests.Response,
    *,
    output: Optional[str] = None,
    allow_redirect: bool = True,
) -> None:
    ensure_ok(resp, allow_redirect=allow_redirect)

    if 300 <= resp.status_code < 400:
        output_json(
            {
                "success": True,
                "status": resp.status_code,
                "location": resp.headers.get("Location", ""),
            }
        )
        return

    if output is not None:
        target = Path(output).expanduser()
        if target.is_dir():
            filename = content_disposition_filename(resp.headers.get("Content-Disposition", ""))
            target = target / (filename or "download.bin")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(resp.content)
        output_json({"success": True, "path": str(target), "bytes": len(resp.content)})
        return

    if response_is_json(resp):
        try:
            output_json(resp.json())
        except ValueError:
            print(resp.text)
        return

    text = resp.text.strip()
    if text:
        print(text)
    else:
        output_json({"success": True, "status": resp.status_code})


def redirect_response_payload(resp: requests.Response, *, id_pattern: Optional[str] = None, id_name: str = "id") -> Dict[str, Any]:
    ensure_ok(resp)
    location = resp.headers.get("Location", "")
    redirected = 300 <= resp.status_code < 400
    if not redirected:
        if response_is_json(resp):
            payload = resp.json()
            return payload if isinstance(payload, dict) else {"success": False, "status": resp.status_code, "response": payload}
        return {
            "success": False,
            "status": resp.status_code,
            "location": location,
            "message": "The server returned a form page instead of a success redirect; the operation was not completed.",
        }
    payload: Dict[str, Any] = {"success": True, "status": resp.status_code, "location": location}
    if id_pattern and location:
        match = re.search(id_pattern, location)
        if match:
            payload[id_name] = int(match.group(1))
        else:
            payload["success"] = False
            payload["message"] = f"The server redirect succeeded, but {id_name} could not be parsed from the Location header."
    return payload


def print_redirect_response(resp: requests.Response, *, id_pattern: Optional[str] = None, id_name: str = "id") -> None:
    payload = redirect_response_payload(resp, id_pattern=id_pattern, id_name=id_name)
    output_json(payload)


def print_stream_lines(resp: requests.Response, *, max_lines: int) -> None:
    ensure_ok(resp, allow_redirect=False)
    lines: List[str] = []
    for raw in resp.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        line = str(raw)
        if line:
            lines.append(line)
        if len(lines) >= max_lines:
            break
    output_json({"success": True, "status": resp.status_code, "lines": lines, "truncated": len(lines) >= max_lines})


def read_code_arg(args: argparse.Namespace) -> str:
    if getattr(args, "code_file", None):
        return Path(args.code_file).expanduser().read_text(encoding="utf-8")
    return read_text_value(getattr(args, "code", ""))


def require_file(path: str) -> Tuple[str, Any]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise CliError(f"File not found: {p}")
    return (p.name, p.open("rb"))


def close_files(files: Dict[str, Tuple[str, Any]]) -> None:
    for _, handle in files.values():
        try:
            handle.close()
        except Exception:
            pass


def form_from_pairs(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for key, value in pairs:
        if value is None:
            continue
        if isinstance(value, bool):
            data[key] = "1" if value else "0"
        else:
            data[key] = str(value)
    return data


def current_or_arg(current: Dict[str, Any], form_name: str, value: Any) -> Any:
    if value is not None:
        return read_text_value(value) if isinstance(value, str) else value
    return current.get(form_name, "")


def parse_promptly_review_config_value(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        obj = raw
    else:
        text = str(raw or "").strip()
        if not text:
            obj = {}
        else:
            try:
                parsed = json.loads(text)
                obj = parsed if isinstance(parsed, dict) else {}
            except Exception:
                obj = {"brief": text}
    examples = obj.get("example_replies")
    if not isinstance(examples, list):
        examples = obj.get("examples") if isinstance(obj.get("examples"), list) else []
    return {
        "brief": str(obj.get("brief") or obj.get("problem_brief") or obj.get("summary") or obj.get("context") or "").strip(),
        "prompt_requirements": str(obj.get("prompt_requirements") or obj.get("requirements") or obj.get("prompt_rules") or "").strip(),
        "example_replies": [str(item or "").strip() for item in examples if str(item or "").strip()],
    }


def _promptly_structured_args_present(args: argparse.Namespace) -> bool:
    return any([
        getattr(args, "promptly_brief", None) is not None,
        getattr(args, "promptly_requirements", None) is not None,
        getattr(args, "promptly_example_reply", None) is not None,
        getattr(args, "promptly_example_replies_json", None) is not None,
        bool(getattr(args, "clear_promptly_example_replies", False)),
    ])


def _read_promptly_examples_json(value: str) -> List[str]:
    parsed = parse_json_value(value)
    if isinstance(parsed, list):
        return [str(item or "").strip() for item in parsed if str(item or "").strip()]
    if isinstance(parsed, str):
        return [line.strip() for line in parsed.splitlines() if line.strip()]
    raise CliError("--promptly-example-replies-json must be a JSON array of strings.")


def build_promptly_grading_prompt_arg(args: argparse.Namespace, current: Optional[Dict[str, Any]] = None) -> Optional[str]:
    raw = getattr(args, "programming_grading_prompt", None)
    has_structured = _promptly_structured_args_present(args)
    if raw is not None and has_structured:
        raise CliError("Use either --programming-grading-prompt or structured Promptly options, not both.")
    if raw is not None:
        return read_text_value(raw)
    if not has_structured:
        return None

    current = current or {}
    base = current.get("promptly_review_config")
    if not isinstance(base, dict):
        base = parse_promptly_review_config_value(current.get("programming_grading_prompt"))
    config = parse_promptly_review_config_value(base)

    if getattr(args, "promptly_brief", None) is not None:
        config["brief"] = read_text_value(args.promptly_brief).strip()
    if getattr(args, "promptly_requirements", None) is not None:
        config["prompt_requirements"] = read_text_value(args.promptly_requirements).strip()

    if getattr(args, "promptly_example_replies_json", None) is not None:
        config["example_replies"] = _read_promptly_examples_json(args.promptly_example_replies_json)
    elif getattr(args, "promptly_example_reply", None) is not None:
        config["example_replies"] = [
            read_text_value(item).strip()
            for item in (args.promptly_example_reply or [])
            if read_text_value(item).strip()
        ]
    elif getattr(args, "clear_promptly_example_replies", False):
        config["example_replies"] = []

    return json.dumps(
        {
            "brief": config.get("brief") or "",
            "prompt_requirements": config.get("prompt_requirements") or "",
            "example_replies": config.get("example_replies") or [],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )


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
    if resp.status_code not in (301, 302, 303, 307, 308) or "session" not in sess.cookies.get_dict():
        body = resp.text[:500].strip()
        raise CliError(f"Login failed. HTTP {resp.status_code}: {body}")
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
            client.request("GET", "/logout")
        except Exception:
            pass
    cfg.pop("cookies", None)
    save_config(args.config, cfg)
    output_json({"success": True, "message": "local token cleared"})


def status(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    client = NumOJClient(cfg, timeout=args.timeout)
    resp = client.request("GET", "/api/admin/users", params={"page": 1})
    if resp.status_code in (301, 302, 303, 307, 308):
        output_json(
            {
                "authenticated": False,
                "admin": False,
                "base_url": client.base_url,
                "location": resp.headers.get("Location", ""),
            }
        )
        return
    output_json(
        {
            "authenticated": resp.status_code < 400,
            "admin": resp.status_code < 400,
            "base_url": client.base_url,
            "username": cfg.get("username"),
            "status": resp.status_code,
        }
    )


def site_home(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/")
    print_redirect_response(resp)


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


def client_from_args(args: argparse.Namespace) -> NumOJClient:
    cfg = load_config(args.config)
    if args.base_url:
        cfg["base_url"] = normalize_base_url(args.base_url)
    return NumOJClient(cfg, timeout=args.timeout)


def cmd_get(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", args.path, params=dict(args.param or []))
    print_or_save_response(resp, output=args.output)


def cmd_post(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data = dict(args.form or [])
    json_payload = parse_json_value(args.json) if args.json else None
    resp = client.request("POST", args.path, data=None if json_payload is not None else data, json=json_payload)
    print_or_save_response(resp)


def cmd_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("DELETE", args.path)
    print_or_save_response(resp)


# ----- Current user operations -----


def me_classes(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/me/classes")
    print_or_save_response(resp)


def me_join_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/join_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_leave_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/leave_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_set_primary_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/me/set_primary_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    cfg = load_config(args.config)
    username = args.username or cfg.get("username")
    if args.user_id is not None:
        resp = client.request("GET", "/admin/get_user_grades", params={"user_id": args.user_id})
        print_or_save_response(resp)
        return
    if not username:
        raise CliError("Missing username. Pass --user-id or run init first.")
    users_resp = client.request("GET", "/api/admin/users", params={"username": username})
    ensure_ok(users_resp, allow_redirect=False)
    payload = users_resp.json() if response_is_json(users_resp) else {}
    matches = [u for u in (payload.get("users") or []) if u.get("username") == username]
    if not matches:
        raise CliError("Cannot find current user id from /api/admin/users. Pass --user-id explicitly.")
    resp = client.request("GET", "/admin/get_user_grades", params={"user_id": matches[0]["id"]})
    print_or_save_response(resp)


# ----- Submission operations -----


def submission_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/submissions", params=params)
    print_or_save_response(resp)


def submission_problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/problems/{args.problem_id}/submissions", params=params)
    print_or_save_response(resp)


def submission_status_cmd(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_status/{args.submission_id}")
    print_or_save_response(resp)


def wait_promptly_review_result(
    client: NumOJClient,
    submission_id: int,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float,
) -> Dict[str, Any]:
    deadline = time.time() + max(0.0, float(timeout_seconds))
    interval = max(0.1, float(poll_interval_seconds))
    last_status: Dict[str, Any] = {}

    while True:
        resp = client.request("GET", f"/submission_status/{submission_id}")
        ensure_ok(resp, allow_redirect=False)
        payload = resp.json() if response_is_json(resp) else {}
        last_status = payload if isinstance(payload, dict) else {}

        status = str(last_status.get("status") or "").strip()
        reply = str(
            last_status.get("promptly_review_reply")
            or last_status.get("prompt_generation_error")
            or ""
        ).strip()
        if reply:
            return {
                "waited": True,
                "done": True,
                "accepted": False,
                "status": status,
                "reply": reply,
                "submission_status": last_status,
            }
        if status and status != "Generating":
            return {
                "waited": True,
                "done": True,
                "accepted": True,
                "status": status,
                "reply": "",
                "submission_status": last_status,
            }
        if time.time() >= deadline:
            return {
                "waited": True,
                "done": False,
                "accepted": None,
                "timed_out": True,
                "status": status or None,
                "reply": "",
                "submission_status": last_status,
            }
        time.sleep(interval)


def submission_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_status_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def submission_detail_cmd(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    if args.output:
        resp = client.request("GET", f"/submission_detail/{args.submission_id}")
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    resp = client.request("GET", f"/api/submissions/{args.submission_id}")
    print_or_save_response(resp)


def submission_last_code(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/get_last_submission_code/{args.problem_id}")
    print_or_save_response(resp)


def submission_output_image(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_output_image/{args.submission_id}/{args.test_index}")
    print_or_save_response(resp, output=args.output or ".")


def submission_download_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/download_submission_file/{args.submission_id}")
    print_or_save_response(resp, output=args.output or ".")


# ----- Problem management -----


def problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/problems" if args.output else "/api/problems", params=None if args.output else params)
    if args.output:
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    print_or_save_response(resp)


def problem_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/problem/{args.problem_id}" if args.output else f"/api/problems/{args.problem_id}"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_submit_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/submit/{args.problem_id}" if args.output else f"/api/problems/{args.problem_id}/submit-context"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    context_resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    ensure_ok(context_resp, allow_redirect=False)
    context = context_resp.json() if response_is_json(context_resp) else {}
    input_kind = ((context.get("submit") or {}).get("input_kind") or "").strip().lower()

    if input_kind == "file":
        if not args.file:
            raise CliError("This problem requires --file.")
        if args.code or args.code_file or args.prompt or args.prompt_file:
            raise CliError("This problem accepts a file submission, not code or prompt.")
        files = {"file": require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            close_files(files)
    elif input_kind == "prompt":
        if not (args.prompt or args.prompt_file):
            raise CliError("This Promptly problem requires --prompt or --prompt-file.")
        if args.file or args.code or args.code_file:
            raise CliError("This Promptly problem accepts prompt text, not code or file.")
        prompt = Path(args.prompt_file).expanduser().read_text(encoding="utf-8") if args.prompt_file else read_text_value(args.prompt)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"prompt": prompt})
    else:
        if not (args.code or args.code_file):
            raise CliError("This programming problem requires --code or --code-file.")
        if args.file or args.prompt or args.prompt_file:
            raise CliError("This programming problem accepts code, not prompt or file.")
        code = Path(args.code_file).expanduser().read_text(encoding="utf-8") if args.code_file else read_text_value(args.code)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"code": code})
    payload = redirect_response_payload(resp, id_pattern=r"/submission_detail/(\d+)", id_name="submission_id")
    if input_kind == "prompt" and payload.get("success") and payload.get("submission_id") and getattr(args, "wait_promptly", True):
        promptly_review = wait_promptly_review_result(
            client,
            int(payload["submission_id"]),
            timeout_seconds=args.wait_timeout,
            poll_interval_seconds=args.poll_interval,
        )
        payload["promptly_review"] = promptly_review
        if promptly_review.get("reply"):
            payload["reply"] = promptly_review["reply"]
    output_json(payload)


def problem_create_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/add_problem" if args.output else "/api/admin/problems/create-form")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_create(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    programming_grading_prompt = build_promptly_grading_prompt_arg(args)
    if programming_grading_prompt is None:
        programming_grading_prompt = ""
    data = form_from_pairs(
        [
            ("title", args.title),
            ("content", read_text_value(args.content)),
            ("initial_code", read_text_value(args.initial_code)),
            ("test_code", read_text_value(args.test_code)),
            ("forbidden_func", args.forbidden_func),
            ("type", args.type),
            ("lang", args.lang),
            ("time_limit", args.time_limit),
            ("submission_limit", args.submission_limit),
            ("programming_grading_mode", args.programming_grading_mode),
            ("programming_grading_model", args.programming_grading_model),
            ("programming_output_filename", args.programming_output_filename),
            ("programming_grading_prompt", programming_grading_prompt),
            ("written_grading_mode", args.written_grading_mode),
            ("written_grading_model", args.written_grading_model),
            ("written_grading_prompt", read_text_value(args.written_grading_prompt)),
        ]
    )
    resp = client.request("POST", "/admin/add_problem", data=data)
    print_or_save_response(resp)


def problem_edit_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/admin/edit_problem/{args.problem_id}" if args.output else f"/api/admin/problems/{args.problem_id}/edit-form"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_edit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    form_resp = client.request("GET", f"/api/admin/problems/{args.problem_id}/edit-form")
    ensure_ok(form_resp, allow_redirect=False)
    current = (form_resp.json() if response_is_json(form_resp) else {}).get("form") or {}
    programming_grading_prompt = build_promptly_grading_prompt_arg(args, current)
    data = form_from_pairs(
        [
            ("title", current_or_arg(current, "title", args.title)),
            ("content", current_or_arg(current, "content", args.content)),
            ("initial_code", current_or_arg(current, "initial_code", args.initial_code)),
            ("test_code", current_or_arg(current, "test_code", args.test_code)),
            ("forbidden_func", current_or_arg(current, "forbidden_func", args.forbidden_func)),
            ("lang", current_or_arg(current, "lang", args.lang)),
            ("time_limit", current_or_arg(current, "time_limit", args.time_limit)),
            ("submission_limit", current_or_arg(current, "submission_limit", args.submission_limit)),
            ("programming_grading_mode", current_or_arg(current, "programming_grading_mode", args.programming_grading_mode)),
            ("programming_grading_model", current_or_arg(current, "programming_grading_model", args.programming_grading_model)),
            ("programming_output_filename", current_or_arg(current, "programming_output_filename", args.programming_output_filename)),
            ("programming_grading_prompt", programming_grading_prompt if programming_grading_prompt is not None else current.get("programming_grading_prompt", "")),
            ("written_grading_mode", current_or_arg(current, "written_grading_mode", args.written_grading_mode)),
            ("written_grading_model", current_or_arg(current, "written_grading_model", args.written_grading_model)),
            ("written_grading_prompt", current_or_arg(current, "written_grading_prompt", args.written_grading_prompt)),
        ]
    )
    resp = client.request("POST", f"/admin/edit_problem/{args.problem_id}", data=data)
    print_or_save_response(resp)


def problem_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("DELETE", f"/admin/delete_problem/{args.problem_id}")
    print_or_save_response(resp)


def problem_upload_testdata(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"testdata_zip": require_file(args.zip)}
    try:
        resp = client.request("POST", f"/admin/upload_testdata/{args.problem_id}", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def problem_rejudge(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/admin/rejudge_problem/{args.problem_id}")
    print_or_save_response(resp)


def problem_rejudge_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/rejudge_status/{args.problem_id}")
    print_or_save_response(resp)


def problem_rejudge_time_range(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload: Dict[str, Any] = {"start": args.start, "end": args.end}
    if args.confirm_total is not None:
        payload["confirm_total"] = args.confirm_total
    resp = client.request("POST", "/admin/rejudge_time_range", json=payload)
    print_or_save_response(resp)


def problem_rejudge_time_range_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/rejudge_time_range_status")
    print_or_save_response(resp)


def problem_agent_run_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_status/{args.task_id}")
    print_or_save_response(resp)


def problem_agent_run_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/admin/agent_run/{args.task_id}" if args.output else f"/admin/agent_run_status/{args.task_id}"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_agent_run_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_stream/{args.task_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def problem_agent_tasks(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/agent_tasks" if args.output else "/api/admin/agent-tasks")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def problem_agent_solve(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"extra_prompt": read_text_value(args.extra_prompt)}
    resp = client.request("POST", f"/admin/agent_solve_problem/{args.problem_id}", json=payload)
    print_or_save_response(resp)


def problem_agent_generate_data(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "test_point_count": args.count,
        "standard_code": read_text_value(args.standard_code),
        "data_requirement": read_text_value(args.data_requirement),
    }
    resp = client.request("POST", f"/admin/agent_generate_testdata/{args.problem_id}", json=payload)
    print_or_save_response(resp)


def problem_scores(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/problem_scores/{args.problem_id}")
    print_or_save_response(resp)


# ----- Homework / class / score management -----


def homework_add(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data = {"class_en": args.class_en, "ddl": args.ddl}
    if args.problem_id is not None:
        data["problem_id"] = str(args.problem_id)
    if args.ranking_competition_id is not None:
        data["ranking_competition_id"] = str(args.ranking_competition_id)
    resp = client.request("POST", "/admin/add_homework", data=data)
    print_or_save_response(resp)


def homework_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/admin/homework", params={"sclass": args.class_en} if args.class_en else None)
    print_or_save_response(resp)


def homework_update_ddl(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"class_en": args.class_en, "homework_id": args.homework_id, "new_ddl": args.ddl}
    resp = client.request("POST", "/admin/update_ddl", json=payload)
    print_or_save_response(resp)


def homework_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"class_en": args.class_en, "homework_id": args.homework_id}
    resp = client.request("POST", "/admin/delete_homework", json=payload)
    print_or_save_response(resp)


def homework_export_scores(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    output = args.output or f"{args.class_en}_scores.csv"
    resp = client.request("GET", "/export_scores", params={"sclass": args.class_en})
    print_or_save_response(resp, output=output)


def homework_export_codes(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/export_student_codes", params={"sclass": args.class_en})
    print_or_save_response(resp)


def homework_export_progress(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/export_progress/{args.task_id}")
    print_or_save_response(resp)


def homework_download_export(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    output = args.output or "student_codes.zip"
    resp = client.request("GET", f"/download_export/{args.task_id}")
    print_or_save_response(resp, output=output)


def homework_upload_exam(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"file": require_file(args.file)}
    try:
        resp = client.request(
            "POST",
            "/admin/upload_exam_scores",
            data={"class_en": args.class_en},
            files=files,
        )
    finally:
        close_files(files)
    print_or_save_response(resp)


def class_adjust(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/admin/class_adjust", data={"enabled": "1" if args.enabled else "0"})
    print_or_save_response(resp)


def user_add_class_type(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/add_class_ajax",
        data={"class_en": args.class_en, "class_cn": args.class_cn},
    )
    print_or_save_response(resp)


def user_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {"page": args.page}
    if args.username:
        params["username"] = args.username
    if args.class_en:
        params["class"] = args.class_en
    resp = client.request("GET", "/api/admin/users", params=params)
    print_or_save_response(resp)


def user_set_primary_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/edit_user_ajax",
        data={"user_id": args.user_id, "class": args.class_en},
    )
    print_or_save_response(resp)


def user_rename(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/edit_username_ajax",
        data={"user_id": args.user_id, "new_username": args.username},
    )
    print_or_save_response(resp)


def user_add_to_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/add_user_to_class",
        data={"user_id": args.user_id, "class_en": args.class_en},
    )
    print_or_save_response(resp)


def user_remove_from_class(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/admin/remove_user_from_class",
        data={"user_id": args.user_id, "class_en": args.class_en},
    )
    print_or_save_response(resp)


def user_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/get_user_grades", params={"user_id": args.user_id})
    print_or_save_response(resp)


def user_update_grade(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    score = "" if args.clear else str(args.score)
    resp = client.request(
        "POST",
        "/admin/update_user_grade",
        data={"user_id": args.user_id, "problem_id": args.problem_id, "score": score},
    )
    print_or_save_response(resp)


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
    print_or_save_response(resp)


def grading_invalidate(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/invalidate_invalid_submissions/{args.problem_id}")
    print_or_save_response(resp)


# ----- Forum / repository / AI tutor -----


def forum_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/forum" if args.output else "/api/forum")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def forum_thread(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/forum/thread/{args.thread_id}" if args.output else f"/api/forum/threads/{args.thread_id}"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def forum_new_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/forum/new" if args.output else "/api/forum/new-context")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def forum_new(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/forum/new", data={"title": args.title, "content": read_text_value(args.content)})
    print_redirect_response(resp, id_pattern=r"/forum/thread/(\d+)", id_name="thread_id")


def forum_reply(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/forum/reply/{args.thread_id}", data={"content": read_text_value(args.content)})
    print_redirect_response(resp)


def forum_reply_thread(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/forum/thread/{args.thread_id}", data={"content": read_text_value(args.content)})
    print_redirect_response(resp)


def repository_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/code_repository" if args.output else "/api/repository/context")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def repository_files(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/repository/files")
    print_or_save_response(resp)


def repository_get_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/repository/file/{args.file_id}")
    if args.output and response_is_json(resp) and resp.status_code < 400:
        data = resp.json()
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(data.get("content") or ""), encoding="utf-8")
        output_json({"success": True, "path": str(target), "filename": data.get("filename")})
        return
    print_or_save_response(resp)


def repository_save_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    content = Path(args.content_file).expanduser().read_text(encoding="utf-8") if args.content_file else read_text_value(args.content)
    payload: Dict[str, Any] = {"filename": args.filename, "content": content}
    if args.file_id is not None:
        payload["file_id"] = args.file_id
    resp = client.request("POST", "/api/repository/file", json=payload)
    print_or_save_response(resp)


def repository_delete_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("DELETE", f"/api/repository/file/{args.file_id}")
    print_or_save_response(resp)


def repository_upload(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"file": require_file(args.file)}
    try:
        resp = client.request("POST", "/api/repository/upload", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def repository_build_index(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/api/repository/index/build", json={"force_restart": bool(args.force_restart)})
    print_or_save_response(resp)


def repository_rebuild_file(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        "/api/repository/index/rebuild_file",
        json={"file_id": args.file_id, "force_restart": bool(args.force_restart)},
    )
    print_or_save_response(resp)


def repository_index_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/repository/index/status/{args.job_id}")
    print_or_save_response(resp)


def repository_active_status(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/repository/index/status/active")
    print_or_save_response(resp)


def repository_search(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload: Dict[str, Any] = {"query": args.query}
    if args.top_k is not None:
        payload["top_k"] = args.top_k
    if args.score_threshold is not None:
        payload["score_threshold"] = args.score_threshold
    resp = client.request("POST", "/api/repository/index/search", json=payload)
    print_or_save_response(resp)


def repository_classes(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/api/repository/index/classes", params={"limit": args.limit})
    print_or_save_response(resp)


def ai_code_marks(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {
        "submission_id": args.submission_id,
        "force_refresh": bool(args.force_refresh),
    }
    resp = client.request("POST", "/ask_ai_code_marks", json=payload)
    print_or_save_response(resp)


# ----- AI detection -----


def ai_filter_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for key in ("class_en", "username", "problem_id", "submission_id", "score_min", "score_max"):
        value = getattr(args, key, None)
        if value is not None:
            payload[key] = value
    if getattr(args, "deduplicate", None) is not None:
        payload["deduplicate"] = bool(args.deduplicate)
    if getattr(args, "model", None):
        payload["model_id"] = args.model
    return payload


def ai_preview(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/admin/ai_detection/preview", json=ai_filter_payload(args))
    print_or_save_response(resp)


def ai_run_filtered(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", "/admin/ai_detection/run_filtered", json=ai_filter_payload(args))
    print_or_save_response(resp)


def ai_run_problem(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/admin/ai_detection/run/{args.problem_id}", json={"model_id": args.model} if args.model else {})
    print_or_save_response(resp)


def ai_run_single(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/admin/ai_detection/run_single/{args.submission_id}", json={"model_id": args.model} if args.model else {})
    print_or_save_response(resp)


def ai_run_user(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/admin/ai_detection/run_user/{args.username}", json={"model_id": args.model} if args.model else {})
    print_or_save_response(resp)


def ai_api_get(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", args.path)
    print_or_save_response(resp)


def ai_detection_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/ai_detection" if args.output else "/api/admin/ai-detection/dashboard")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def ai_detection_problem_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/admin/ai_detection/problem/{args.problem_id}" if args.output else f"/api/admin/ai-detection/problem/{args.problem_id}"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def ai_detection_student_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = f"/admin/ai_detection/student/{args.username}" if args.output else f"/api/admin/ai-detection/student/{args.username}"
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def ai_task_post(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    action = "delete_task" if args.action == "delete" else "stop"
    resp = client.request("POST", f"/admin/ai_detection/api/{action}/{args.task_id}")
    print_or_save_response(resp)


# ----- Ranking competition management -----


def ranking_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/ranking/" if args.output else "/api/ranking/competitions", params=None if args.output else params)
    if args.output:
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    print_or_save_response(resp)


def ranking_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params = {"tab": args.tab} if args.tab else None
    path = f"/ranking/{args.competition_id}/" if args.output else f"/api/ranking/competitions/{args.competition_id}"
    resp = client.request("GET", path, params=params)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


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
            ("elo_initial_rating", current_or_arg(current, "elo_initial_rating", args.elo_initial_rating)),
            ("elo_k_factor", current_or_arg(current, "elo_k_factor", args.elo_k_factor)),
            ("elo_max_matches", current_or_arg(current, "elo_max_matches", args.elo_max_matches)),
            ("elo_match_interval_seconds", current_or_arg(current, "elo_match_interval_seconds", args.elo_match_interval)),
            ("elo_initial_burst", current_or_arg(current, "elo_initial_burst", args.elo_initial_burst)),
            ("elo_max_pairs_per_round", current_or_arg(current, "elo_max_pairs_per_round", args.elo_max_pairs_per_round)),
            ("agent_judge_timeout_seconds", current_or_arg(current, "agent_judge_timeout_seconds", args.agent_timeout)),
        ]
    )
    resp = client.request("POST", f"/ranking/{args.competition_id}/edit", data=data)
    print_or_save_response(resp)


def ranking_delete(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("POST", f"/ranking/{args.competition_id}/delete")
    print_or_save_response(resp)


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
    print_or_save_response(resp)


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


def ranking_config(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    data: Dict[str, str] = {}
    if args.base_url_value is not None:
        data["agent_judge_base_url"] = args.base_url_value
    if args.model is not None:
        data["agent_judge_model"] = args.model
    if args.api_key is not None:
        data["agent_judge_api_key"] = read_text_value(args.api_key)
    if args.timeout_seconds is not None:
        data["agent_judge_timeout_seconds"] = str(args.timeout_seconds)
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/config", data=data)
    print_redirect_response(resp)


def ranking_rules(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    rules = parse_json_value(args.rules)
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/rules", json={"rules": rules})
    print_or_save_response(resp)


def ranking_endpoints(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload: Dict[str, Any] = {"endpoints": parse_json_value(args.endpoints)}
    if args.timeout_seconds is not None:
        payload["timeout_seconds"] = args.timeout_seconds
    resp = client.request("POST", f"/ranking/{args.competition_id}/agent_judge/endpoints", json=payload)
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
    print_or_save_response(resp)


def ranking_match_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/match/{args.match_id}/details.json")
    print_or_save_response(resp)


def ranking_rejudge_agent(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "POST",
        f"/ranking/{args.competition_id}/submission/{args.submission_id}/rejudge_agent",
    )
    print_or_save_response(resp)


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
    print_or_save_response(resp)


def ranking_appeal_review(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = (
        f"/ranking/{args.competition_id}/appeal/{args.appeal_id}/review"
        if args.output
        else f"/api/ranking/competitions/{args.competition_id}/appeals/{args.appeal_id}/review"
    )
    resp = client.request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


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
    print_or_save_response(resp)


def ranking_download_submission(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    kind = "answer" if args.kind == "answer" else "code"
    resp = client.request("GET", f"/ranking/submission/{args.submission_id}/{kind}")
    print_or_save_response(resp, output=args.output or ".")


def ranking_judge_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/judge_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def ranking_my_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/my-submissions", params=params)
    print_or_save_response(resp)


def ranking_all_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/api/ranking/competitions/{args.competition_id}/submissions",
        params={"page": args.page, "q": args.username or ""},
    )
    print_or_save_response(resp)


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/leaderboard", params=params)
    print_or_save_response(resp)


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
    data = {"base_model": args.base_model}
    if args.answer_file:
        files["answer_file"] = require_file(args.answer_file)
    try:
        resp = client.request("POST", f"/ranking/{args.competition_id}/submit", data=data, files=files)
    finally:
        close_files(files)
    ensure_ok(resp)
    after_ids = _ranking_submission_ids(client, args.competition_id)
    new_ids = sorted(after_ids - before_ids)
    location = resp.headers.get("Location", "")
    payload: Dict[str, Any] = {
        "success": bool(new_ids),
        "status": resp.status_code,
        "location": location,
    }
    if new_ids:
        payload["submission_id"] = new_ids[-1]
    else:
        payload["message"] = "The submission request completed, but no new submission record was created. Check the submission method, quota, or form errors."
    output_json(payload)


def ranking_git_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = "check_repo" if args.action == "check" else "git_submit"
    resp = client.request("POST", f"/ranking/{args.competition_id}/{path}")
    print_or_save_response(resp)


def add_common_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to the local CLI config file containing the saved server URL and session cookie.")
    parser.add_argument("--base-url", help="Override the server URL saved in the config file for this command.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP request timeout in seconds.")


def add_text_arg(parser: argparse.ArgumentParser, name: str, **kwargs: Any) -> None:
    parser.add_argument(name, **kwargs)


HELP_FORMATTER = argparse.ArgumentDefaultsHelpFormatter


def add_cli_parser(subparsers: argparse._SubParsersAction, name: str, description: str, **kwargs: Any) -> argparse.ArgumentParser:
    kwargs.setdefault("help", description)
    kwargs.setdefault("description", description)
    kwargs.setdefault("formatter_class", HELP_FORMATTER)
    return subparsers.add_parser(name, **kwargs)


def add_promptly_review_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--promptly-brief",
        help=(
            "Brief problem description for Promptly prompt review, or @file. "
            "Only the review model sees this; it is used to judge whether the student's idea matches the problem."
        ),
    )
    parser.add_argument(
        "--promptly-requirements",
        help=(
            "Detailed requirements for Promptly prompt review, or @file. "
            "Use this to require algorithm choices, data structures, state updates, boundary handling, and similar details."
        ),
    )
    parser.add_argument(
        "--promptly-example-reply",
        action="append",
        help=(
            "Example rejection reply for the Promptly review model to imitate. "
            "Repeat this option to provide multiple examples; each value may also be @file."
        ),
    )
    parser.add_argument(
        "--promptly-example-replies-json",
        help="JSON array of Promptly example rejection replies, or @file. Replaces the current example list.",
    )
    parser.add_argument(
        "--clear-promptly-example-replies",
        action="store_true",
        help="When editing, clear Promptly example replies. This only applies when no replacement example list is passed.",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="numoj-admin",
        description="NumericalOJ administrator CLI over existing HTTP routes.",
        formatter_class=HELP_FORMATTER,
    )
    add_common_http_args(p)
    sub = p.add_subparsers(dest="group", required=True)

    pa = add_cli_parser(sub, "init", "First-time setup: save the NumOJ URL and administrator session token.")
    pa.add_argument("--base-url", dest="login_base_url", required=False, help="NumOJ server URL, e.g. https://oj.example.com or 127.0.0.1:2025.")
    pa.add_argument("-u", "--username", help="Administrator username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Administrator password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=init_cli, prompt_base_url=True)

    site = add_cli_parser(sub, "site", "Inspect public site routes and login/problem-list redirects.")
    sites = site.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(sites, "home", "Fetch the site home route and show the response or redirect target.")
    pa.set_defaults(func=site_home)

    auth = add_cli_parser(sub, "auth", "Manage CLI authentication and account password actions.")
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

    me = add_cli_parser(sub, "me", "Inspect and update data for the currently configured account.")
    mes = me.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(mes, "classes", "List classes visible to the current account.")
    pa.set_defaults(func=me_classes)
    pa = add_cli_parser(mes, "join-class", "Join a class as the current account.")
    pa.add_argument("class_en", help="English class identifier, e.g. C2026A.")
    pa.set_defaults(func=me_join_class)
    pa = add_cli_parser(mes, "leave-class", "Leave a class as the current account.")
    pa.add_argument("class_en", help="English class identifier to leave, e.g. C2026A.")
    pa.set_defaults(func=me_leave_class)
    pa = add_cli_parser(mes, "set-primary-class", "Set the current account's primary class.")
    pa.add_argument("class_en", help="English class identifier to make primary, e.g. C2026A.")
    pa.set_defaults(func=me_set_primary_class)
    pa = add_cli_parser(mes, "grades", "Show grades for the current account or another user visible to the administrator.")
    pa.add_argument("--user-id", type=int, help="Admin-visible user ID. If omitted, the initialized username is used.")
    pa.add_argument("--username", help="Admin-visible username. Defaults to the initialized username.")
    pa.set_defaults(func=me_grades)
    pa = add_cli_parser(mes, "submissions", "List submissions for the current account.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)

    submission = add_cli_parser(sub, "submission", "Inspect submissions, status snapshots, generated output files, and saved source code.")
    ss = submission.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ss, "list", "List submissions visible to the current administrator session.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
    pa = add_cli_parser(ss, "problem", "List submissions for one programming or written problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submissions should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_problem_list)
    pa = add_cli_parser(ss, "status", "Fetch the current JSON status snapshot for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_status_cmd)
    pa = add_cli_parser(ss, "stream", "Fetch recent live evaluation stream lines for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=submission_stream)
    pa = add_cli_parser(ss, "detail", "Fetch submission details, either as JSON status or the raw HTML detail page.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.add_argument("-o", "--output", help="Write the original HTML detail page to this path instead of printing JSON status.")
    pa.set_defaults(func=submission_detail_cmd)
    pa = add_cli_parser(ss, "last-code", "Fetch the current user's last submitted code for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose latest code should be returned.")
    pa.set_defaults(func=submission_last_code)
    pa = add_cli_parser(ss, "output-image", "Download an output image produced by an image-grading submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID that produced the image.")
    pa.add_argument("test_index", type=int, help="Zero-based or server-defined test-point index of the image to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded image. If omitted, a default filename is used.")
    pa.set_defaults(func=submission_output_image)
    pa = add_cli_parser(ss, "download-file", "Download the original file attached to a written-homework submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose uploaded file should be downloaded.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded file. If omitted, a server-provided filename is used.")
    pa.set_defaults(func=submission_download_file)

    problem = add_cli_parser(sub, "problem", "Manage problems, submissions, test data, rejudging, and problem-solving agents.")
    ps = problem.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ps, "list", "List available problems from the problem-list page.")
    pa.add_argument("--limit", type=int, help="Maximum number of problems to return.")
    pa.add_argument("-o", "--output", help="Write the raw response or parsed output to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_list)
    pa = add_cli_parser(ps, "detail", "Fetch a problem detail page and summarize or save it.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.add_argument("-o", "--output", help="Write the full problem detail HTML to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_detail)
    pa = add_cli_parser(ps, "submit-page", "Fetch the submit page for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submit page should be fetched.")
    pa.add_argument("-o", "--output", help="Write the full submit page HTML to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_submit_page)
    pa = add_cli_parser(ps, "submit", "Submit source code, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    submit_group = pa.add_mutually_exclusive_group(required=True)
    submit_group.add_argument("--code", help="Source code text, or @file to read code from a file.")
    submit_group.add_argument("--code-file", help="Source code file path.")
    submit_group.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    submit_group.add_argument("--prompt-file", help="Promptly submission file path.")
    submit_group.add_argument("--file", help="Written-homework PDF or ZIP file path.")
    pa.add_argument(
        "--no-wait-promptly",
        dest="wait_promptly",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Return immediately after creating a Promptly submission instead of waiting for prompt review/generation status.",
    )
    pa.add_argument("--wait-timeout", type=float, default=60.0, help="Maximum seconds to wait for Promptly review/generation status after a prompt submission.")
    pa.add_argument("--poll-interval", type=float, default=1.0, help="Seconds between Promptly status polling requests.")
    pa.set_defaults(func=problem_submit)
    pa = add_cli_parser(ps, "create-form", "Fetch the administrator problem-creation form metadata.")
    pa.add_argument("-o", "--output", help="Write the raw create-form response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_create_form)
    pa = add_cli_parser(ps, "create", "Create a programming or written-homework problem.")
    pa.add_argument("--title", required=True, help="Problem title.")
    pa.add_argument("--content", required=True, help="Problem statement Markdown text, or @markdown-file.")
    pa.add_argument("--type", choices=["1", "2"], default="1", help="Problem type: 1=programming, 2=written homework.")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"], default="matlab", help="Programming language for programming problems.")
    pa.add_argument(
        "--time-limit-ms", "--time-limit",
        dest="time_limit",
        type=int,
        default=2000,
        help="Per-test-case time limit for programming problems, in milliseconds.",
    )
    pa.add_argument("--submission-limit", type=int, default=10, help="Maximum number of submissions allowed per regular student.")
    pa.add_argument("--initial-code", default="", help="Initial code prefilled on the submit page, or @file.")
    pa.add_argument("--test-code", default="", help="Helper code for interactive or special judging, or @file. Usually empty for standard problems.")
    pa.add_argument("--forbidden-func", default="", help="Comma-separated forbidden function names. Matching submissions are judged Forbidden.")
    pa.add_argument(
        "--programming-grading-mode",
        type=int,
        default=1,
        help="Programming grading mode: 1=standard code judging, 2=program-output image grading, 3=Promptly prompt judging.",
    )
    pa.add_argument("--programming-grading-model", help="Model identifier for programming image grading or Promptly review/code generation.")
    pa.add_argument("--programming-output-filename", help="Expected output image filename in programming image-grading mode.")
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, default=1, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-model", help="Model identifier for AI grading of written homework.")
    pa.add_argument("--written-grading-prompt", default="", help="Rubric for AI grading of written homework, or @file.")
    pa.set_defaults(func=problem_create)
    pa = add_cli_parser(ps, "edit-form", "Fetch administrator edit-form metadata for an existing problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose edit form should be fetched.")
    pa.add_argument("-o", "--output", help="Write the raw edit-form response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_edit_form)
    pa = add_cli_parser(ps, "edit", "Edit an existing programming or written-homework problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to edit.")
    pa.add_argument("--title", help="Problem title. Omit to keep the current value.")
    pa.add_argument("--content", help="Problem statement Markdown text, or @markdown-file. Omit to keep the current value.")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"], help="Programming language. Omit to keep the current value.")
    pa.add_argument(
        "--time-limit-ms", "--time-limit",
        dest="time_limit",
        type=int,
        help="Per-test-case time limit for programming problems, in milliseconds. Omit to keep the current value.",
    )
    pa.add_argument("--submission-limit", type=int, help="Maximum submissions allowed per regular student. Omit to keep the current value.")
    pa.add_argument("--initial-code", help="Initial code prefilled on the submit page, or @file. Omit to keep the current value.")
    pa.add_argument("--test-code", help="Helper code for interactive or special judging, or @file. Omit to keep the current value.")
    pa.add_argument("--forbidden-func", help="Comma-separated forbidden function names. Pass an empty string to clear.")
    pa.add_argument(
        "--programming-grading-mode",
        type=int,
        help="Programming grading mode: 1=standard code judging, 2=program-output image grading, 3=Promptly prompt judging.",
    )
    pa.add_argument("--programming-grading-model", help="Model identifier for programming image grading or Promptly review/code generation.")
    pa.add_argument("--programming-output-filename", help="Expected output image filename in programming image-grading mode.")
    pa.add_argument(
        "--programming-grading-prompt",
        help=(
            "Raw programming grading configuration text, or @file. In image-grading mode this is the rubric; "
            "in Promptly mode this is the full JSON configuration. Cannot be combined with structured --promptly-* options."
        ),
    )
    add_promptly_review_args(pa)
    pa.add_argument("--written-grading-mode", type=int, help="Written grading mode: 1=OCR+text grading, 2=direct image grading, 3=ZIP/LaTeX, 4=manual grading.")
    pa.add_argument("--written-grading-model", help="Model identifier for AI grading of written homework.")
    pa.add_argument("--written-grading-prompt", help="Rubric for AI grading of written homework, or @file.")
    pa.set_defaults(func=problem_edit)
    pa = add_cli_parser(ps, "delete", "Delete a problem by ID.")
    pa.add_argument("problem_id", type=int, help="Problem ID to delete.")
    pa.set_defaults(func=problem_delete)
    pa = add_cli_parser(ps, "upload-testdata", "Upload a ZIP archive of test data for a programming problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose test data should be replaced or uploaded.")
    pa.add_argument("zip", help="Path to the ZIP archive containing test data files.")
    pa.set_defaults(func=problem_upload_testdata)
    pa = add_cli_parser(ps, "rejudge", "Start a rejudge task for all submissions of one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to rejudge.")
    pa.set_defaults(func=problem_rejudge)
    pa = add_cli_parser(ps, "rejudge-status", "Check rejudge progress for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose rejudge status should be checked.")
    pa.set_defaults(func=problem_rejudge_status)
    pa = add_cli_parser(ps, "rejudge-time-range", "Start a rejudge task for submissions created within a time range.")
    pa.add_argument("--start", required=True, help="Inclusive start time, formatted as YYYY-MM-DDTHH:MM.")
    pa.add_argument("--end", required=True, help="Exclusive end time, formatted as YYYY-MM-DDTHH:MM.")
    pa.add_argument("--confirm-total", type=int, help="Expected number of affected submissions; the server may require this safety confirmation.")
    pa.set_defaults(func=problem_rejudge_time_range)
    pa = add_cli_parser(ps, "rejudge-time-range-status", "Check progress for the most recent time-range rejudge task.")
    pa.set_defaults(func=problem_rejudge_time_range_status)
    pa = add_cli_parser(ps, "agent-run-status", "Fetch JSON status for a problem-solving or test-data-generation agent task.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.set_defaults(func=problem_agent_run_status)
    pa = add_cli_parser(ps, "agent-run", "Fetch the HTML page for an agent task run.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.add_argument("-o", "--output", help="Write the full agent-run HTML to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_agent_run_page)
    pa = add_cli_parser(ps, "agent-run-stream", "Fetch recent stream lines for an agent task run.")
    pa.add_argument("task_id", help="Agent task ID returned by an agent command.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=problem_agent_run_stream)
    pa = add_cli_parser(ps, "agent-tasks", "List recent problem-solving and test-data-generation agent tasks.")
    pa.add_argument("-o", "--output", help="Write the full agent-task page response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=problem_agent_tasks)
    pa = add_cli_parser(ps, "agent-solve", "Start an AI agent task to solve a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for the agent to solve.")
    pa.add_argument("--extra-prompt", default="", help="Additional instruction text to pass to the problem-solving agent.")
    pa.set_defaults(func=problem_agent_solve)
    pa = add_cli_parser(ps, "agent-generate-data", "Start an AI agent task to generate test data for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID for which test data should be generated.")
    pa.add_argument("--count", type=int, required=True, help="Number of test cases or data files to request from the agent.")
    pa.add_argument("--standard-code", required=True, help="Reference solution code text, or @file to read it from a file.")
    pa.add_argument("--data-requirement", default="", help="Additional natural-language requirements for generated test data.")
    pa.set_defaults(func=problem_agent_generate_data)
    pa = add_cli_parser(ps, "scores", "Fetch score records for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose scores should be returned.")
    pa.set_defaults(func=problem_scores)

    hw = add_cli_parser(sub, "homework", "Manage class homework assignments, exports, exam scores, and class adjustment settings.")
    hs = hw.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(hs, "list", "List homework assigned to a class or visible classes.")
    pa.add_argument("--class-en", help="English class identifier to filter by, e.g. C2026A.")
    pa.set_defaults(func=homework_list)
    pa = add_cli_parser(hs, "add", "Assign a problem or ranking competition as homework for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier receiving the homework, e.g. C2026A.")
    pa.add_argument("--ddl", required=True, help="Homework deadline, formatted as YYYY-MM-DDTHH:MM or a MySQL datetime string.")
    group = pa.add_mutually_exclusive_group(required=True)
    group.add_argument("--problem-id", type=int, help="Problem ID to assign as homework.")
    group.add_argument("--ranking-competition-id", type=int, help="Ranking competition ID to assign as homework.")
    pa.set_defaults(func=homework_add)
    pa = add_cli_parser(hs, "update-ddl", "Update the deadline for one homework assignment.")
    pa.add_argument("--class-en", required=True, help="English class identifier that owns the homework.")
    pa.add_argument("--homework-id", required=True, help="Homework assignment ID to update.")
    pa.add_argument("--ddl", required=True, help="New deadline, formatted as YYYY-MM-DDTHH:MM or a MySQL datetime string.")
    pa.set_defaults(func=homework_update_ddl)
    pa = add_cli_parser(hs, "delete", "Delete one homework assignment from a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier that owns the homework.")
    pa.add_argument("--homework-id", required=True, help="Homework assignment ID to delete.")
    pa.set_defaults(func=homework_delete)
    pa = add_cli_parser(hs, "export-scores", "Export homework scores for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose scores should be exported.")
    pa.add_argument("-o", "--output", help="Path to write the exported score file.")
    pa.set_defaults(func=homework_export_scores)
    pa = add_cli_parser(hs, "export-codes", "Start an asynchronous export of submitted code for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose submitted code should be exported.")
    pa.set_defaults(func=homework_export_codes)
    pa = add_cli_parser(hs, "export-progress", "Check progress for a class code-export task.")
    pa.add_argument("task_id", help="Export task ID returned by export-codes.")
    pa.set_defaults(func=homework_export_progress)
    pa = add_cli_parser(hs, "download-export", "Download the archive generated by a class code-export task.")
    pa.add_argument("task_id", help="Export task ID returned by export-codes.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded archive.")
    pa.set_defaults(func=homework_download_export)
    pa = add_cli_parser(hs, "upload-exam", "Upload a final-exam score file for a class.")
    pa.add_argument("--class-en", required=True, help="English class identifier whose exam scores should be uploaded.")
    pa.add_argument("file", help="Path to the exam-score file to upload.")
    pa.set_defaults(func=homework_upload_exam)
    pa = add_cli_parser(hs, "class-adjust", "Enable or disable class adjustment mode.")
    pa.add_argument("enabled", type=lambda x: str(x).lower() in ("1", "true", "yes", "on"), help="Boolean switch: one of 1/0, true/false, yes/no, or on/off.")
    pa.set_defaults(func=class_adjust)

    user = add_cli_parser(sub, "user", "Manage users, classes, memberships, names, and grade overrides.")
    us = user.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(us, "list", "List users with optional username or class filters.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--username", help="Filter by username substring or exact username, depending on server behavior.")
    pa.add_argument("--class-en", help="Filter by English class identifier.")
    pa.set_defaults(func=user_list)
    pa = add_cli_parser(us, "add-class-type", "Create a class type entry available for user membership.")
    pa.add_argument("--class-en", required=True, help="English class code without the leading C, matching the web form behavior.")
    pa.add_argument("--class-cn", required=True, help="Chinese display name for the class.")
    pa.set_defaults(func=user_add_class_type)
    pa = add_cli_parser(us, "set-primary-class", "Set a user's primary class.")
    pa.add_argument("user_id", type=int, help="User ID to update.")
    pa.add_argument("class_en", help="English class identifier to set as primary.")
    pa.set_defaults(func=user_set_primary_class)
    pa = add_cli_parser(us, "rename", "Rename a user account.")
    pa.add_argument("user_id", type=int, help="User ID to rename.")
    pa.add_argument("username", help="New username.")
    pa.set_defaults(func=user_rename)
    pa = add_cli_parser(us, "add-to-class", "Add a user to a class.")
    pa.add_argument("user_id", type=int, help="User ID to add.")
    pa.add_argument("class_en", help="English class identifier to add the user to.")
    pa.set_defaults(func=user_add_to_class)
    pa = add_cli_parser(us, "remove-from-class", "Remove a user from a class.")
    pa.add_argument("user_id", type=int, help="User ID to remove.")
    pa.add_argument("class_en", help="English class identifier to remove from the user.")
    pa.set_defaults(func=user_remove_from_class)
    pa = add_cli_parser(us, "grades", "List all visible grades for a user.")
    pa.add_argument("user_id", type=int, help="User ID whose grades should be listed.")
    pa.set_defaults(func=user_grades)
    pa = add_cli_parser(us, "update-grade", "Set or clear a manual grade override for a user and problem.")
    pa.add_argument("user_id", type=int, help="User ID whose grade should be updated.")
    pa.add_argument("problem_id", type=int, help="Problem ID for the grade update.")
    g = pa.add_mutually_exclusive_group(required=True)
    g.add_argument("--score", type=int, help="Score value to set.")
    g.add_argument("--clear", action="store_true", help="Clear the existing manual grade override.")
    pa.set_defaults(func=user_update_grade)

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

    forum = add_cli_parser(sub, "forum", "Inspect and create forum threads and replies.")
    fs = forum.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(fs, "list", "List forum threads.")
    pa.add_argument("-o", "--output", help="Write the full forum list response to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=forum_list)
    pa = add_cli_parser(fs, "thread", "Fetch one forum thread and its replies.")
    pa.add_argument("thread_id", type=int, help="Forum thread ID to fetch.")
    pa.add_argument("-o", "--output", help="Write the full thread response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=forum_thread)
    pa = add_cli_parser(fs, "new-page", "Fetch the new-thread form page.")
    pa.add_argument("-o", "--output", help="Write the full new-thread page response to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=forum_new_page)
    pa = add_cli_parser(fs, "new", "Create a new forum thread.")
    pa.add_argument("--title", required=True, help="Thread title.")
    pa.add_argument("--content", required=True, help="Thread body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_new)
    pa = add_cli_parser(fs, "reply", "Post a reply to a forum thread.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply)
    pa = add_cli_parser(fs, "reply-thread", "Post a reply using the thread-reply route.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply_thread)

    repo = add_cli_parser(sub, "repository", "Manage the per-user code repository and its vector-search index.")
    repos = repo.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(repos, "page", "Fetch the repository page.")
    pa.add_argument("-o", "--output", help="Write the full repository page response to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=repository_page)
    pa = add_cli_parser(repos, "files", "List files in the current user's repository.")
    pa.set_defaults(func=repository_files)
    pa = add_cli_parser(repos, "get", "Fetch one repository file by ID.")
    pa.add_argument("file_id", type=int, help="Repository file ID to fetch.")
    pa.add_argument("-o", "--output", help="Write file content when the API returns JSON content.")
    pa.set_defaults(func=repository_get_file)
    pa = add_cli_parser(repos, "save", "Create or update a repository file.")
    pa.add_argument("--filename", required=True, help="Repository filename to create or update.")
    content_group = pa.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", help="File content text, or @file to read it from a file.")
    content_group.add_argument("--content-file", help="Path to a local file whose content should be saved.")
    pa.add_argument("--file-id", type=int, help="Existing repository file ID to update. Omit to create a new file.")
    pa.set_defaults(func=repository_save_file)
    pa = add_cli_parser(repos, "delete", "Delete a repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to delete.")
    pa.set_defaults(func=repository_delete_file)
    pa = add_cli_parser(repos, "upload", "Upload a local source file into the repository.")
    pa.add_argument("file", help="Path to the local file to upload.")
    pa.set_defaults(func=repository_upload)
    pa = add_cli_parser(repos, "build-index", "Start or resume a repository-wide vector-index build.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the indexing job if one already exists.")
    pa.set_defaults(func=repository_build_index)
    pa = add_cli_parser(repos, "rebuild-file", "Rebuild vector-index entries for one repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to re-index.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the file indexing job if one already exists.")
    pa.set_defaults(func=repository_rebuild_file)
    pa = add_cli_parser(repos, "index-status", "Check status for a repository indexing job.")
    pa.add_argument("job_id", type=int, help="Indexing job ID returned by build-index or rebuild-file.")
    pa.set_defaults(func=repository_index_status)
    pa = add_cli_parser(repos, "active-status", "Show currently active repository indexing jobs.")
    pa.set_defaults(func=repository_active_status)
    pa = add_cli_parser(repos, "search", "Search indexed repository code using semantic/vector search.")
    pa.add_argument("--query", required=True, help="Natural-language or code query to search for.")
    pa.add_argument("--top-k", type=int, help="Maximum number of matching chunks to return.")
    pa.add_argument("--score-threshold", type=float, help="Minimum similarity score required for returned chunks.")
    pa.set_defaults(func=repository_search)
    pa = add_cli_parser(repos, "classes", "List class metadata discovered in indexed repository code.")
    pa.add_argument("--limit", type=int, default=300, help="Maximum number of class records to return.")
    pa.set_defaults(func=repository_classes)

    tutor = add_cli_parser(sub, "ai", "Call AI tutor endpoints for submissions.")
    tutors = tutor.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(tutors, "marks", "Fetch AI-generated code marks for one submission.")
    pa.add_argument("--submission-id", type=int, required=True, help="Submission ID whose AI marks should be fetched.")
    pa.add_argument("--force-refresh", action="store_true", help="Force the server to refresh cached AI marks.")
    pa.set_defaults(func=ai_code_marks)

    ai = add_cli_parser(sub, "ai-detection", "Inspect and run AI-generated-code detection tasks.")
    ais = ai.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ais, "dashboard", "Fetch the administrator AI-detection dashboard page.")
    pa.add_argument("-o", "--output", help="Write the full dashboard response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=ai_detection_page)
    pa = add_cli_parser(ais, "problem-page", "Fetch the AI-detection page for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.add_argument("-o", "--output", help="Write the full problem AI-detection page to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=ai_detection_problem_page)
    pa = add_cli_parser(ais, "student-page", "Fetch the AI-detection page for one student.")
    pa.add_argument("username", help="Username to inspect.")
    pa.add_argument("-o", "--output", help="Write the full student AI-detection page to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=ai_detection_student_page)
    for name, func, description in (
        ("preview", ai_preview, "Preview submissions matching AI-detection filters without starting a detection task."),
        ("run-filtered", ai_run_filtered, "Start an AI-detection task for submissions matching filters."),
    ):
        pa = add_cli_parser(ais, name, description)
        pa.add_argument("--class-en", help="Filter by English class identifier.")
        pa.add_argument("--username", help="Filter by username.")
        pa.add_argument("--problem-id", type=int, help="Filter by problem ID.")
        pa.add_argument("--submission-id", type=int, help="Filter by a single submission ID.")
        pa.add_argument("--score-min", type=float, help="Minimum existing AI-detection score to include.")
        pa.add_argument("--score-max", type=float, help="Maximum existing AI-detection score to include.")
        pa.add_argument("--deduplicate", action="store_true", default=None, help="Ask the server to keep only one candidate per user/problem when supported.")
        pa.add_argument("--model", help="Detection model identifier to use.")
        pa.set_defaults(func=func)
    pa = add_cli_parser(ais, "run-problem", "Start AI-detection for all relevant submissions of one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to scan.")
    pa.add_argument("--model", help="Detection model identifier to use.")
    pa.set_defaults(func=ai_run_problem)
    pa = add_cli_parser(ais, "run-single", "Start AI-detection for one submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to scan.")
    pa.add_argument("--model", help="Detection model identifier to use.")
    pa.set_defaults(func=ai_run_single)
    pa = add_cli_parser(ais, "run-user", "Start AI-detection for submissions from one user.")
    pa.add_argument("username", help="Username whose submissions should be scanned.")
    pa.add_argument("--model", help="Detection model identifier to use.")
    pa.set_defaults(func=ai_run_user)
    for name, path, description in (
        ("summary", "/admin/ai_detection/api/summary", "Fetch AI-detection summary metrics."),
        ("tasks", "/admin/ai_detection/api/tasks", "List recent AI-detection tasks."),
        ("models", "/admin/ai_detection/api/available_models", "List AI-detection models available on the server."),
    ):
        pa = add_cli_parser(ais, name, description)
        pa.set_defaults(func=ai_api_get, path=path)
    pa = add_cli_parser(ais, "task", "Stop or delete an AI-detection task.")
    pa.add_argument("action", choices=["stop", "delete"], help="Task operation to perform.")
    pa.add_argument("task_id", help="AI-detection task ID.")
    pa.set_defaults(func=ai_task_post)

    rk = add_cli_parser(sub, "ranking", "Manage ranking competitions, submissions, judging, appeals, and Agent-as-Judge settings.")
    rs = rk.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(rs, "list", "List ranking competitions.")
    pa.add_argument("--limit", type=int, help="Maximum number of competitions to return.")
    pa.add_argument("-o", "--output", help="Write the full response to this file.")
    pa.add_argument("--max-chars", type=int, default=2000, help="Maximum number of response characters to print when not writing to a file.")
    pa.set_defaults(func=ranking_list)
    pa = add_cli_parser(rs, "detail", "Fetch a ranking competition detail page.")
    pa.add_argument("competition_id", type=int, help="Competition ID to inspect.")
    pa.add_argument("--tab", help="Optional detail-page tab to request, such as submissions, leaderboard, or settings.")
    pa.add_argument("-o", "--output", help="Write the full detail response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
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
    pa.add_argument("--scoring-mode", choices=["absolute", "elo", "agent_judge"], help="Scoring mode used by the competition.")
    pa.add_argument("--script-timeout", type=int, help="Timeout in seconds for scoring-script execution.")
    pa.add_argument("--submit-limit", type=int, help="Maximum number of submissions allowed in the active limit window.")
    pa.add_argument("--reset-limit-window", action="store_true", help="Reset the per-user submission-limit window.")
    pa.add_argument("--submission-method", choices=["zip", "git"], help="Submission method accepted by the competition.")
    pa.add_argument("--git-format", help="Git repository URL format or rule used to derive participant repositories.")
    pa.add_argument("--elo-initial-rating", type=float, help="Initial ELO rating assigned to new submissions.")
    pa.add_argument("--elo-k-factor", type=float, help="ELO K-factor used when updating ratings.")
    pa.add_argument("--elo-max-matches", type=int, help="Maximum number of ELO matches per submission.")
    pa.add_argument("--elo-match-interval", type=int, help="Interval in seconds between automatic ELO match rounds.")
    pa.add_argument("--elo-initial-burst", type=int, help="Number of initial ELO matches to schedule quickly for a new submission.")
    pa.add_argument("--elo-max-pairs-per-round", type=int, help="Maximum number of ELO match pairs generated per scheduler round.")
    pa.add_argument("--agent-timeout", type=int, help="Timeout in seconds for Agent-as-Judge evaluation.")
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
    pa = add_cli_parser(rs, "save-config", "Save Agent-as-Judge model configuration for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument("--agent-base-url", dest="base_url_value", help="Base URL for the Agent-as-Judge model API.")
    pa.add_argument("--api-key", help="API key text, or @file to read it from a file.")
    pa.add_argument("--model", help="Model identifier used by Agent-as-Judge.")
    pa.add_argument("--timeout-seconds", type=int, help="Agent-as-Judge timeout in seconds.")
    pa.set_defaults(func=ranking_config)
    pa = add_cli_parser(rs, "save-rules", "Save Agent-as-Judge grading rules for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument("rules", help="JSON array of rule objects, or @file to read it from a file.")
    pa.set_defaults(func=ranking_rules)
    pa = add_cli_parser(rs, "save-endpoints", "Save endpoint checks for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID to configure.")
    pa.add_argument("endpoints", help="JSON array of endpoint objects, or @file to read it from a file.")
    pa.add_argument("--timeout-seconds", type=int, help="Timeout in seconds for endpoint checks.")
    pa.set_defaults(func=ranking_endpoints)
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
    pa = add_cli_parser(rs, "rejudge-agent", "Requeue Agent-as-Judge evaluation for one ranking submission.")
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
    pa = add_cli_parser(rs, "appeal-review", "Fetch the review page for a ranking appeal.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the appeal.")
    pa.add_argument("appeal_id", type=int, help="Appeal ID to review.")
    pa.add_argument("-o", "--output", help="Write the full appeal-review response to this file.")
    pa.add_argument("--max-chars", type=int, default=3000, help="Maximum number of response characters to print when not writing to a file.")
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
    pa = add_cli_parser(rs, "download-submission", "Download the answer file or code archive from a ranking submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to download from.")
    pa.add_argument("kind", choices=["answer", "code"], help="Submission artifact to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded artifact.")
    pa.set_defaults(func=ranking_download_submission)
    pa = add_cli_parser(rs, "judge-stream", "Fetch recent judge stream lines for a ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose judge stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=ranking_judge_stream)
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
    pa = add_cli_parser(rs, "submit", "Submit a ZIP-based ranking entry.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", required=True, help="Base model name associated with the submission.")
    pa.add_argument("--code-zip", required=True, help="Path to the code ZIP archive to upload.")
    pa.add_argument("--answer-file", help="Optional answer file path to upload with the submission.")
    pa.set_defaults(func=ranking_submit_zip)
    pa = add_cli_parser(rs, "submit-zip", "Alias for ranking submit; submit a ZIP-based ranking entry.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", required=True, help="Base model name associated with the submission.")
    pa.add_argument("--code-zip", required=True, help="Path to the code ZIP archive to upload.")
    pa.add_argument("--answer-file", help="Optional answer file path to upload with the submission.")
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
    pa.set_defaults(func=ranking_git_submit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except KeyboardInterrupt:
        eprint("Interrupted")
        return 130
    except CliError as exc:
        eprint(f"error: {exc}")
        return 2
    except requests.RequestException as exc:
        eprint(f"request error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
