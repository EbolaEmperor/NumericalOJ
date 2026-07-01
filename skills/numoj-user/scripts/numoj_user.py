#!/usr/bin/env python3
"""NumericalOJ regular-user CLI over authenticated NumericalOJ HTTP APIs."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "numoj-user requires the Python package 'requests'. "
        "Install it with: python3 -m pip install --user requests"
    ) from exc


DEFAULT_CONFIG_PATH = Path(
    os.environ.get("NUMOJ_USER_CONFIG", "~/.numoj-user/config.json")
).expanduser()


class CliError(RuntimeError):
    pass


def eprint(*parts: Any) -> None:
    print(*parts, file=sys.stderr)


def output_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False))


def read_text_value(value: Optional[str]) -> str:
    if value is None:
        return ""
    if value.startswith("@"):
        return Path(value[1:]).expanduser().read_text(encoding="utf-8")
    return value


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


def content_disposition_filename(header: str) -> Optional[str]:
    if not header:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', header)
    if match:
        return os.path.basename(match.group(1))
    return None


class NumOJClient:
    def __init__(self, cfg: Dict[str, Any], *, timeout: float = 60.0):
        self.base_url = normalize_base_url(cfg.get("base_url") or "")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": "numoj-user-cli/0.1"})
        for name, value in (cfg.get("cookies") or {}).items():
            self.session.cookies.set(name, value)

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        return self.session.request(method.upper(), url, **kwargs)


def response_is_json(resp: requests.Response) -> bool:
    return "application/json" in (resp.headers.get("Content-Type") or "").lower()


def ensure_ok(resp: requests.Response, *, allow_redirect: bool = True) -> None:
    if allow_redirect and 300 <= resp.status_code < 400:
        return
    if resp.status_code < 400:
        return
    body = resp.text[:1000].strip()
    raise CliError(f"HTTP {resp.status_code}: {body or resp.reason}")


def print_or_save_response(resp: requests.Response, *, output: Optional[str] = None, allow_redirect: bool = True) -> None:
    ensure_ok(resp, allow_redirect=allow_redirect)
    if 300 <= resp.status_code < 400:
        output_json({"success": True, "status": resp.status_code, "location": resp.headers.get("Location", "")})
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
        output_json(resp.json())
        return
    text = resp.text.strip()
    print(text if text else json.dumps({"success": True, "status": resp.status_code}))


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


def client_from_args(args: argparse.Namespace, *, require_auth: bool = True) -> NumOJClient:
    cfg = load_config(args.config)
    if args.base_url:
        cfg["base_url"] = normalize_base_url(args.base_url)
    if require_auth and not (cfg.get("cookies") or {}).get("session"):
        raise CliError("CLI requires login. Run init or auth login first.")
    return NumOJClient(cfg, timeout=args.timeout)


def login(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    raw_base_url = getattr(args, "login_base_url", None) or args.base_url or cfg.get("base_url") or ""
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
        raise CliError(f"Login failed. HTTP {resp.status_code}: {resp.text[:500].strip()}")
    cfg["base_url"] = base_url
    cfg["username"] = username
    cfg["cookies"] = sess.cookies.get_dict()
    save_config(args.config, cfg)
    output_json({"success": True, "base_url": base_url, "username": username, "config": str(args.config)})


def logout(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    if cfg.get("cookies"):
        try:
            client_from_args(args, require_auth=False).request("GET", "/logout")
        except Exception:
            pass
    cfg.pop("cookies", None)
    save_config(args.config, cfg)
    output_json({"success": True, "message": "local token cleared"})


def status(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    if not (cfg.get("base_url") or args.base_url):
        output_json(
            {
                "authenticated": False,
                "base_url": None,
                "username": cfg.get("username"),
                "status": None,
            }
        )
        return
    client = client_from_args(args, require_auth=False)
    resp = client.request("GET", "/me/classes")
    output_json(
        {
            "authenticated": resp.status_code < 400,
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


def me_classes(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/me/classes")
    print_or_save_response(resp)


def me_join_class(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/me/join_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_leave_class(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/me/leave_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def me_set_primary_class(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/me/set_primary_class", data={"class_en": args.class_en})
    print_or_save_response(resp)


def submission_list(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client_from_args(args).request("GET", "/api/submissions", params=params)
    print_or_save_response(resp)


def submission_problem_list(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client_from_args(args).request("GET", f"/api/problems/{args.problem_id}/submissions", params=params)
    print_or_save_response(resp)


def submission_status_cmd(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/submission_status/{args.submission_id}")
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
    resp = client_from_args(args).request("GET", f"/submission_status_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def submission_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/submissions/{args.submission_id}")
    print_or_save_response(resp, allow_redirect=False)


def submission_last_code(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/api/get_last_submission_code/{args.problem_id}")
    print_or_save_response(resp)


def submission_output_image(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/submission_output_image/{args.submission_id}/{args.test_index}")
    print_or_save_response(resp, output=args.output or ".")


def me_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    best: Dict[str, Dict[str, Any]] = {}
    for page in range(1, args.pages + 1):
        resp = client.request("GET", "/api/submissions", params={"page": page})
        ensure_ok(resp, allow_redirect=False)
        payload = resp.json() if response_is_json(resp) else {}
        rows = payload.get("submissions") or []
        if not rows:
            break
        for row in rows:
            problem = row.get("display_problem_title") or row.get("problem_title") or f"submission:{row['id']}"
            try:
                score_value = float(str(row.get("score") or "0"))
            except ValueError:
                score_value = 0.0
            if problem not in best or score_value > float(best[problem].get("score_value") or 0):
                row["score_value"] = score_value
                best[problem] = row
    output_json({"success": True, "source": "visible submission history", "grades": list(best.values())})


def problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/problems", params=params)
    print_or_save_response(resp, allow_redirect=False)


def problem_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}")
    print_or_save_response(resp, allow_redirect=False)


def problem_submit_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/api/problems/{args.problem_id}/submit-context")
    print_or_save_response(resp, allow_redirect=False)


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


def forum_list(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/forum")
    print_or_save_response(resp, allow_redirect=False)


def forum_thread(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/api/forum/threads/{args.thread_id}")
    print_or_save_response(resp, allow_redirect=False)


def forum_new_page(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/forum/new-context")
    print_or_save_response(resp, allow_redirect=False)


def forum_new(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/forum/new", data={"title": args.title, "content": read_text_value(args.content)})
    print_redirect_response(resp, id_pattern=r"/forum/thread/(\d+)", id_name="thread_id")


def forum_reply(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", f"/forum/reply/{args.thread_id}", data={"content": read_text_value(args.content)})
    print_redirect_response(resp)


def forum_reply_thread(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", f"/forum/thread/{args.thread_id}", data={"content": read_text_value(args.content)})
    print_redirect_response(resp)


def repository_page(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/repository/context")
    print_or_save_response(resp, allow_redirect=False)


def repository_files(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/repository/files")
    print_or_save_response(resp)


def repository_get_file(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/api/repository/file/{args.file_id}")
    if args.output and response_is_json(resp) and resp.status_code < 400:
        data = resp.json()
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(data.get("content") or ""), encoding="utf-8")
        output_json({"success": True, "path": str(target), "filename": data.get("filename")})
        return
    print_or_save_response(resp)


def repository_save_file(args: argparse.Namespace) -> None:
    content = Path(args.content_file).expanduser().read_text(encoding="utf-8") if args.content_file else read_text_value(args.content)
    payload: Dict[str, Any] = {"filename": args.filename, "content": content}
    if args.file_id is not None:
        payload["file_id"] = args.file_id
    resp = client_from_args(args).request("POST", "/api/repository/file", json=payload)
    print_or_save_response(resp)


def repository_delete_file(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("DELETE", f"/api/repository/file/{args.file_id}")
    print_or_save_response(resp)


def repository_upload(args: argparse.Namespace) -> None:
    files = {"file": require_file(args.file)}
    try:
        resp = client_from_args(args).request("POST", "/api/repository/upload", files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def repository_build_index(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/api/repository/index/build", json={"force_restart": bool(args.force_restart)})
    print_or_save_response(resp)


def repository_rebuild_file(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request(
        "POST",
        "/api/repository/index/rebuild_file",
        json={"file_id": args.file_id, "force_restart": bool(args.force_restart)},
    )
    print_or_save_response(resp)


def repository_index_status(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/api/repository/index/status/{args.job_id}")
    print_or_save_response(resp)


def repository_active_status(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/repository/index/status/active")
    print_or_save_response(resp)


def repository_search(args: argparse.Namespace) -> None:
    payload: Dict[str, Any] = {"query": args.query}
    if args.top_k is not None:
        payload["top_k"] = args.top_k
    if args.score_threshold is not None:
        payload["score_threshold"] = args.score_threshold
    resp = client_from_args(args).request("POST", "/api/repository/index/search", json=payload)
    print_or_save_response(resp)


def repository_classes(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/api/repository/index/classes", params={"limit": args.limit})
    print_or_save_response(resp)


def ai_code_marks(args: argparse.Namespace) -> None:
    payload = {
        "submission_id": args.submission_id,
        "force_refresh": bool(args.force_refresh),
    }
    resp = client_from_args(args).request("POST", "/ask_ai_code_marks", json=payload)
    print_or_save_response(resp)


def ranking_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", "/api/ranking/competitions", params=params)
    print_or_save_response(resp, allow_redirect=False)


def ranking_detail(args: argparse.Namespace) -> None:
    params = {"tab": args.tab} if args.tab else None
    resp = client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}", params=params)
    print_or_save_response(resp, allow_redirect=False)


def ranking_matches(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"page": args.page}
    if args.mine:
        params["mine"] = "1"
    resp = client_from_args(args).request("GET", f"/api/ranking/competitions/{args.competition_id}/matches", params=params)
    print_or_save_response(resp)


def ranking_match_detail(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/ranking/{args.competition_id}/match/{args.match_id}/details.json")
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


def ranking_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    before_ids = _ranking_submission_ids(client, args.competition_id)
    files = {"code_file": require_file(args.code_zip)}
    data = {"base_model": args.base_model}
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
    if resp.status_code >= 400 and response_is_json(resp):
        payload = resp.json()
        if isinstance(payload, dict) and "success" not in payload:
            payload["success"] = False
        output_json(payload)
        return
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


def ranking_git(args: argparse.Namespace) -> None:
    path = "check_repo" if args.action == "check" else "git_submit"
    resp = client_from_args(args).request("POST", f"/ranking/{args.competition_id}/{path}")
    if resp.status_code >= 400 and response_is_json(resp):
        payload = resp.json()
        if isinstance(payload, dict) and "success" not in payload:
            payload["success"] = False
        output_json(payload)
        return
    print_or_save_response(resp)


def ranking_my_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/my-submissions", params=params)
    print_or_save_response(resp)


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params: Dict[str, Any] = {}
    if args.limit is not None:
        params["limit"] = args.limit
    resp = client.request("GET", f"/api/ranking/competitions/{args.competition_id}/leaderboard", params=params)
    print_or_save_response(resp)


def ranking_download_submission(args: argparse.Namespace) -> None:
    kind = "answer" if args.kind == "answer" else "code"
    resp = client_from_args(args).request("GET", f"/ranking/submission/{args.submission_id}/{kind}")
    print_or_save_response(resp, output=args.output or ".")


def ranking_judge_stream(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/ranking/{args.competition_id}/judge_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def ranking_submit_appeal(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request(
        "POST",
        f"/ranking/{args.competition_id}/submission/{args.submission_id}/appeal",
        data={"reason": read_text_value(args.reason)},
    )
    print_or_save_response(resp)


def ranking_appeal_status(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/ranking/{args.competition_id}/submission/{args.submission_id}/appeal_status")
    print_or_save_response(resp)


def add_common_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to the local CLI config file containing the saved server URL and session cookie.")
    parser.add_argument("--base-url", help="Override the server URL saved in the config file for this command.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP request timeout in seconds.")


HELP_FORMATTER = argparse.ArgumentDefaultsHelpFormatter


def add_cli_parser(subparsers: argparse._SubParsersAction, name: str, description: str, **kwargs: Any) -> argparse.ArgumentParser:
    kwargs.setdefault("help", description)
    kwargs.setdefault("description", description)
    kwargs.setdefault("formatter_class", HELP_FORMATTER)
    return subparsers.add_parser(name, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="numoj-user",
        description="NumericalOJ regular-user CLI over existing HTTP routes.",
        formatter_class=HELP_FORMATTER,
    )
    add_common_http_args(p)
    sub = p.add_subparsers(dest="group", required=True)

    pa = add_cli_parser(sub, "init", "First-time setup: save the NumOJ URL and user session token.")
    pa.add_argument("--base-url", dest="login_base_url", help="NumOJ server URL, e.g. https://oj.example.com or 127.0.0.1:2025.")
    pa.add_argument("-u", "--username", help="Username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=login, prompt_base_url=True)

    site = add_cli_parser(sub, "site", "Inspect public site routes and login/problem-list redirects.")
    site_sub = site.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(site_sub, "home", "Fetch the site home route and show the response or redirect target.")
    pa.set_defaults(func=site_home)

    auth = add_cli_parser(sub, "auth", "Manage CLI authentication and account password actions.")
    auth_sub = auth.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(auth_sub, "login", "Log in and save a fresh user session cookie.")
    pa.add_argument("--base-url", dest="login_base_url", help="NumOJ server URL, e.g. https://oj.example.com.")
    pa.add_argument("-u", "--username", help="Username. If omitted, the CLI prompts interactively.")
    pa.add_argument("-p", "--password", help="Password. If omitted, the CLI prompts without echoing input.")
    pa.set_defaults(func=login)
    pa = add_cli_parser(auth_sub, "logout", "Delete the saved local CLI session config.")
    pa.set_defaults(func=logout)
    pa = add_cli_parser(auth_sub, "status", "Check whether the saved session is authenticated.")
    pa.set_defaults(func=status)
    pa = add_cli_parser(auth_sub, "send-password-code", "Request a password-change verification code for the current session.")
    pa.set_defaults(func=auth_send_password_code)
    pa = add_cli_parser(auth_sub, "change-password", "Change the current account password using a verification code.")
    pa.add_argument("--code", required=True, help="Verification code received from the password-code request.")
    pa.add_argument("--new-password", required=True, help="New password to set for the current account.")
    pa.add_argument("--confirm-password", help="Confirmation password. Defaults to --new-password when omitted.")
    pa.set_defaults(func=auth_change_password)

    me = add_cli_parser(sub, "me", "Inspect and update data for the currently configured account.")
    me_sub = me.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(me_sub, "classes", "List classes visible to the current account.")
    pa.set_defaults(func=me_classes)
    pa = add_cli_parser(me_sub, "join-class", "Join a class as the current account.")
    pa.add_argument("class_en", help="English class identifier, e.g. C2026A.")
    pa.set_defaults(func=me_join_class)
    pa = add_cli_parser(me_sub, "leave-class", "Leave a class as the current account.")
    pa.add_argument("class_en", help="English class identifier to leave, e.g. C2026A.")
    pa.set_defaults(func=me_leave_class)
    pa = add_cli_parser(me_sub, "set-primary-class", "Set the current account's primary class.")
    pa.add_argument("class_en", help="English class identifier to make primary, e.g. C2026A.")
    pa.set_defaults(func=me_set_primary_class)
    pa = add_cli_parser(me_sub, "submissions", "List submissions for the current account.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
    pa = add_cli_parser(me_sub, "grades", "Summarize visible grades from recent submission history.")
    pa.add_argument("--pages", type=int, default=5, help="Number of submission-history pages to summarize.")
    pa.set_defaults(func=me_grades)

    problem = add_cli_parser(sub, "problem", "Browse problems and submit code, Promptly prompts, or written-homework files.")
    problem_sub = problem.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(problem_sub, "list", "List available problems from the problem-list API.")
    pa.add_argument("--limit", type=int, help="Maximum number of problems to return.")
    pa.set_defaults(func=problem_list)
    pa = add_cli_parser(problem_sub, "detail", "Fetch problem detail metadata as JSON.")
    pa.add_argument("problem_id", type=int, help="Problem ID to inspect.")
    pa.set_defaults(func=problem_detail)
    pa = add_cli_parser(problem_sub, "submit-page", "Fetch the submit-context metadata for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submit context should be fetched.")
    pa.set_defaults(func=problem_submit_page)
    pa = add_cli_parser(problem_sub, "submit", "Submit source code, a Promptly prompt, or a written-homework file to a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID to submit to.")
    sg = pa.add_mutually_exclusive_group(required=True)
    sg.add_argument("--code", help="Source code text, or @file to read code from a file.")
    sg.add_argument("--code-file", help="Source code file path.")
    sg.add_argument("--prompt", help="Promptly submission text, or @file to read the prompt from a file.")
    sg.add_argument("--prompt-file", help="Promptly submission file path.")
    sg.add_argument("--file", help="Written-homework PDF or ZIP file path.")
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

    submission = add_cli_parser(sub, "submission", "Inspect personal submissions, status snapshots, output files, and saved source code.")
    sub_sub = submission.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(sub_sub, "list", "List submissions visible to the current user.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_list)
    pa = add_cli_parser(sub_sub, "problem", "List submissions for one problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose submissions should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=submission_problem_list)
    pa = add_cli_parser(sub_sub, "status", "Fetch the current JSON status snapshot for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_status_cmd)
    pa = add_cli_parser(sub_sub, "stream", "Fetch recent live evaluation stream lines for a submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID whose stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=submission_stream)
    pa = add_cli_parser(sub_sub, "detail", "Fetch submission details as JSON.")
    pa.add_argument("submission_id", type=int, help="Submission ID to inspect.")
    pa.set_defaults(func=submission_detail)
    pa = add_cli_parser(sub_sub, "last-code", "Fetch the current user's last submitted code for a problem.")
    pa.add_argument("problem_id", type=int, help="Problem ID whose latest code should be returned.")
    pa.set_defaults(func=submission_last_code)
    pa = add_cli_parser(sub_sub, "output-image", "Download an output image produced by an image-grading submission.")
    pa.add_argument("submission_id", type=int, help="Submission ID that produced the image.")
    pa.add_argument("test_index", type=int, help="Zero-based or server-defined test-point index of the image to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded image. If omitted, a default filename is used.")
    pa.set_defaults(func=submission_output_image)

    forum = add_cli_parser(sub, "forum", "Inspect and create forum threads and replies.")
    forum_sub = forum.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(forum_sub, "list", "List forum threads.")
    pa.set_defaults(func=forum_list)
    pa = add_cli_parser(forum_sub, "thread", "Fetch one forum thread and its replies.")
    pa.add_argument("thread_id", type=int, help="Forum thread ID to fetch.")
    pa.set_defaults(func=forum_thread)
    pa = add_cli_parser(forum_sub, "new-page", "Fetch the new-thread form metadata as JSON.")
    pa.set_defaults(func=forum_new_page)
    pa = add_cli_parser(forum_sub, "new", "Create a new forum thread.")
    pa.add_argument("--title", required=True, help="Thread title.")
    pa.add_argument("--content", required=True, help="Thread body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_new)
    pa = add_cli_parser(forum_sub, "reply", "Post a reply to a forum thread.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply)
    pa = add_cli_parser(forum_sub, "reply-thread", "Post a reply using the thread-reply route.")
    pa.add_argument("thread_id", type=int, help="Thread ID to reply to.")
    pa.add_argument("--content", required=True, help="Reply body text, or @file to read it from a file.")
    pa.set_defaults(func=forum_reply_thread)

    repo = add_cli_parser(sub, "repository", "Manage the personal code repository and its vector-search index.")
    repo_sub = repo.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(repo_sub, "page", "Fetch the repository page context as JSON.")
    pa.set_defaults(func=repository_page)
    pa = add_cli_parser(repo_sub, "files", "List files in the current user's repository.")
    pa.set_defaults(func=repository_files)
    pa = add_cli_parser(repo_sub, "get", "Fetch one repository file by ID.")
    pa.add_argument("file_id", type=int, help="Repository file ID to fetch.")
    pa.add_argument("-o", "--output", help="Write file content when the API returns JSON content.")
    pa.set_defaults(func=repository_get_file)
    pa = add_cli_parser(repo_sub, "save", "Create or update a repository file.")
    pa.add_argument("--filename", required=True, help="Repository filename to create or update.")
    content_group = pa.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", help="File content text, or @file to read it from a file.")
    content_group.add_argument("--content-file", help="Path to a local file whose content should be saved.")
    pa.add_argument("--file-id", type=int, help="Existing repository file ID to update. Omit to create a new file.")
    pa.set_defaults(func=repository_save_file)
    pa = add_cli_parser(repo_sub, "delete", "Delete a repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to delete.")
    pa.set_defaults(func=repository_delete_file)
    pa = add_cli_parser(repo_sub, "upload", "Upload a local source file into the repository.")
    pa.add_argument("file", help="Path to the local file to upload.")
    pa.set_defaults(func=repository_upload)
    pa = add_cli_parser(repo_sub, "build-index", "Start or resume a repository-wide vector-index build.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the indexing job if one already exists.")
    pa.set_defaults(func=repository_build_index)
    pa = add_cli_parser(repo_sub, "rebuild-file", "Rebuild vector-index entries for one repository file.")
    pa.add_argument("file_id", type=int, help="Repository file ID to re-index.")
    pa.add_argument("--force-restart", action="store_true", help="Force the server to restart the file indexing job if one already exists.")
    pa.set_defaults(func=repository_rebuild_file)
    pa = add_cli_parser(repo_sub, "index-status", "Check status for a repository indexing job.")
    pa.add_argument("job_id", type=int, help="Indexing job ID returned by build-index or rebuild-file.")
    pa.set_defaults(func=repository_index_status)
    pa = add_cli_parser(repo_sub, "active-status", "Show currently active repository indexing jobs.")
    pa.set_defaults(func=repository_active_status)
    pa = add_cli_parser(repo_sub, "search", "Search indexed repository code using semantic/vector search.")
    pa.add_argument("--query", required=True, help="Natural-language or code query to search for.")
    pa.add_argument("--top-k", type=int, help="Maximum number of matching chunks to return.")
    pa.add_argument("--score-threshold", type=float, help="Minimum similarity score required for returned chunks.")
    pa.set_defaults(func=repository_search)
    pa = add_cli_parser(repo_sub, "classes", "List class metadata discovered in indexed repository code.")
    pa.add_argument("--limit", type=int, default=300, help="Maximum number of class records to return.")
    pa.set_defaults(func=repository_classes)

    ai = add_cli_parser(sub, "ai", "Call AI tutor endpoints for submissions.")
    ai_sub = ai.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(ai_sub, "marks", "Fetch AI-generated code marks for one submission.")
    pa.add_argument("--submission-id", type=int, required=True, help="Submission ID whose AI marks should be fetched.")
    pa.add_argument("--force-refresh", action="store_true", help="Force the server to refresh cached AI marks.")
    pa.set_defaults(func=ai_code_marks)

    ranking = add_cli_parser(sub, "ranking", "Use ranking competitions, submissions, matches, leaderboards, and appeals.")
    rank_sub = ranking.add_subparsers(dest="cmd", required=True)
    pa = add_cli_parser(rank_sub, "list", "List ranking competitions.")
    pa.add_argument("--limit", type=int, help="Maximum number of competitions to return.")
    pa.set_defaults(func=ranking_list)
    pa = add_cli_parser(rank_sub, "detail", "Fetch ranking competition detail metadata as JSON.")
    pa.add_argument("competition_id", type=int, help="Competition ID to inspect.")
    pa.add_argument("--tab", help="Optional detail tab to request, such as submissions, leaderboard, or settings.")
    pa.set_defaults(func=ranking_detail)
    pa = add_cli_parser(rank_sub, "matches", "List ELO or Agent-as-Judge matches for a competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose matches should be listed.")
    pa.add_argument("--page", type=int, default=1, help="Result page number to fetch.")
    pa.add_argument("--mine", action="store_true", help="Show only matches involving the current user when supported.")
    pa.set_defaults(func=ranking_matches)
    pa = add_cli_parser(rank_sub, "match-detail", "Fetch details for one ranking match.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the match.")
    pa.add_argument("match_id", type=int, help="Match ID to inspect.")
    pa.set_defaults(func=ranking_match_detail)
    pa = add_cli_parser(rank_sub, "submit", "Submit a ZIP-based ranking entry.")
    pa.add_argument("competition_id", type=int, help="Competition ID to submit to.")
    pa.add_argument("--base-model", required=True, help="Base model name associated with the submission.")
    pa.add_argument("--code-zip", required=True, help="Path to the code ZIP archive to upload.")
    pa.add_argument("--answer-file", help="Optional answer file path to upload with the submission.")
    pa.set_defaults(func=ranking_submit)
    pa = add_cli_parser(
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
    pa = add_cli_parser(rank_sub, "my-submissions", "List the current user's submissions for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose submissions should be listed.")
    pa.add_argument("--limit", type=int, help="Maximum number of submissions to return.")
    pa.set_defaults(func=ranking_my_submissions)
    pa = add_cli_parser(rank_sub, "leaderboard", "Fetch the leaderboard for a ranking competition.")
    pa.add_argument("competition_id", type=int, help="Competition ID whose leaderboard should be fetched.")
    pa.add_argument("--limit", type=int, help="Maximum number of leaderboard rows to return.")
    pa.set_defaults(func=ranking_leaderboard)
    pa = add_cli_parser(rank_sub, "download-submission", "Download the answer file or code archive from a ranking submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID to download from.")
    pa.add_argument("kind", choices=["answer", "code"], help="Submission artifact to download.")
    pa.add_argument("-o", "--output", help="Path to write the downloaded artifact.")
    pa.set_defaults(func=ranking_download_submission)
    pa = add_cli_parser(rank_sub, "judge-stream", "Fetch recent judge stream lines for a ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose judge stream should be fetched.")
    pa.add_argument("--max-lines", type=int, default=20, help="Maximum number of stream lines to print.")
    pa.set_defaults(func=ranking_judge_stream)
    pa = add_cli_parser(rank_sub, "appeal", "Submit an appeal for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID being appealed.")
    pa.add_argument("--reason", required=True, help="Appeal reason text, or @file to read it from a file.")
    pa.set_defaults(func=ranking_submit_appeal)
    pa = add_cli_parser(rank_sub, "appeal-status", "Fetch appeal status for one ranking submission.")
    pa.add_argument("competition_id", type=int, help="Competition ID that owns the submission.")
    pa.add_argument("submission_id", type=int, help="Ranking submission ID whose appeal status should be fetched.")
    pa.set_defaults(func=ranking_appeal_status)

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
