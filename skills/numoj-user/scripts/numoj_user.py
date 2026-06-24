#!/usr/bin/env python3
"""NumericalOJ regular-user CLI over existing web routes."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
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


def print_redirect_response(resp: requests.Response, *, id_pattern: Optional[str] = None, id_name: str = "id") -> None:
    ensure_ok(resp)
    location = resp.headers.get("Location", "")
    redirected = 300 <= resp.status_code < 400
    if not redirected:
        if response_is_json(resp):
            output_json(resp.json())
            return
        output_json(
            {
                "success": False,
                "status": resp.status_code,
                "location": location,
                "message": "服务器返回了表单页面而不是成功跳转；操作未完成。",
            }
        )
        return
    payload: Dict[str, Any] = {"success": True, "status": resp.status_code, "location": location}
    if id_pattern and location:
        match = re.search(id_pattern, location)
        if match:
            payload[id_name] = int(match.group(1))
        else:
            payload["success"] = False
            payload["message"] = f"服务器跳转成功，但未从 Location 中解析到 {id_name}"
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


def submission_stream(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/submission_status_stream/{args.submission_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def submission_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    if args.output:
        resp = client.request("GET", f"/submission_detail/{args.submission_id}")
        print_or_save_response(resp, output=args.output, allow_redirect=False)
    else:
        resp = client.request("GET", f"/api/submissions/{args.submission_id}")
        print_or_save_response(resp)


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
    if args.file:
        files = {"file": require_file(args.file)}
        try:
            resp = client.request("POST", f"/submit/{args.problem_id}", files=files)
        finally:
            close_files(files)
    else:
        code = Path(args.code_file).expanduser().read_text(encoding="utf-8") if args.code_file else read_text_value(args.code)
        resp = client.request("POST", f"/submit/{args.problem_id}", data={"code": code})
    print_redirect_response(resp, id_pattern=r"/submission_detail/(\d+)", id_name="submission_id")


def forum_list(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/forum" if args.output else "/api/forum")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def forum_thread(args: argparse.Namespace) -> None:
    path = f"/forum/thread/{args.thread_id}" if args.output else f"/api/forum/threads/{args.thread_id}"
    resp = client_from_args(args).request("GET", path)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


def forum_new_page(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/forum/new" if args.output else "/api/forum/new-context")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


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
    resp = client_from_args(args).request("GET", "/code_repository" if args.output else "/api/repository/context")
    print_or_save_response(resp, output=args.output, allow_redirect=False)


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
    resp = client.request("GET", "/ranking/" if args.output else "/api/ranking/competitions", params=None if args.output else params)
    if args.output:
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    print_or_save_response(resp)


def ranking_detail(args: argparse.Namespace) -> None:
    params = {"tab": args.tab} if args.tab else None
    path = f"/ranking/{args.competition_id}/" if args.output else f"/api/ranking/competitions/{args.competition_id}"
    resp = client_from_args(args).request("GET", path, params=params)
    print_or_save_response(resp, output=args.output, allow_redirect=False)


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
        payload["message"] = "提交请求完成，但没有产生新的提交记录。请检查比赛提交方式、配额或表单错误。"
    output_json(payload)


def ranking_git(args: argparse.Namespace) -> None:
    path = "check_repo" if args.action == "check" else "git_submit"
    resp = client_from_args(args).request("POST", f"/ranking/{args.competition_id}/{path}")
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
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="config file path")
    parser.add_argument("--base-url", help="override server base URL")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout seconds")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="numoj-user", description="NumericalOJ regular-user CLI over existing HTTP routes")
    add_common_http_args(p)
    sub = p.add_subparsers(dest="group", required=True)

    pa = sub.add_parser("init", help="first-time setup: save NumOJ URL and user session token")
    pa.add_argument("--base-url", dest="login_base_url", help="NumOJ URL, e.g. https://oj.example.com or 127.0.0.1:2025")
    pa.add_argument("-u", "--username")
    pa.add_argument("-p", "--password")
    pa.set_defaults(func=login, prompt_base_url=True)

    site = sub.add_parser("site")
    site_sub = site.add_subparsers(dest="cmd", required=True)
    pa = site_sub.add_parser("home")
    pa.set_defaults(func=site_home)

    auth = sub.add_parser("auth")
    auth_sub = auth.add_subparsers(dest="cmd", required=True)
    pa = auth_sub.add_parser("login")
    pa.add_argument("--base-url", dest="login_base_url")
    pa.add_argument("-u", "--username")
    pa.add_argument("-p", "--password")
    pa.set_defaults(func=login)
    pa = auth_sub.add_parser("logout")
    pa.set_defaults(func=logout)
    pa = auth_sub.add_parser("status")
    pa.set_defaults(func=status)
    pa = auth_sub.add_parser("send-password-code")
    pa.set_defaults(func=auth_send_password_code)
    pa = auth_sub.add_parser("change-password")
    pa.add_argument("--code", required=True)
    pa.add_argument("--new-password", required=True)
    pa.add_argument("--confirm-password")
    pa.set_defaults(func=auth_change_password)

    me = sub.add_parser("me")
    me_sub = me.add_subparsers(dest="cmd", required=True)
    pa = me_sub.add_parser("classes")
    pa.set_defaults(func=me_classes)
    pa = me_sub.add_parser("join-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_join_class)
    pa = me_sub.add_parser("leave-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_leave_class)
    pa = me_sub.add_parser("set-primary-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_set_primary_class)
    pa = me_sub.add_parser("submissions")
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_list)
    pa = me_sub.add_parser("grades")
    pa.add_argument("--pages", type=int, default=5, help="submission history pages to summarize")
    pa.set_defaults(func=me_grades)

    problem = sub.add_parser("problem")
    problem_sub = problem.add_subparsers(dest="cmd", required=True)
    pa = problem_sub.add_parser("list")
    pa.add_argument("--limit", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=problem_list)
    pa = problem_sub.add_parser("detail")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_detail)
    pa = problem_sub.add_parser("submit-page")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=problem_submit_page)
    pa = problem_sub.add_parser("submit")
    pa.add_argument("problem_id", type=int)
    sg = pa.add_mutually_exclusive_group(required=True)
    sg.add_argument("--code", help="source code text, or @file")
    sg.add_argument("--code-file", help="source code file path")
    sg.add_argument("--file", help="written-homework PDF/ZIP file path")
    pa.set_defaults(func=problem_submit)

    submission = sub.add_parser("submission")
    sub_sub = submission.add_subparsers(dest="cmd", required=True)
    pa = sub_sub.add_parser("list")
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_list)
    pa = sub_sub.add_parser("problem")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_problem_list)
    pa = sub_sub.add_parser("status")
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=submission_status_cmd)
    pa = sub_sub.add_parser("stream")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--max-lines", type=int, default=20)
    pa.set_defaults(func=submission_stream)
    pa = sub_sub.add_parser("detail")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("-o", "--output", help="save original HTML detail page instead of JSON status")
    pa.set_defaults(func=submission_detail)
    pa = sub_sub.add_parser("last-code")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=submission_last_code)
    pa = sub_sub.add_parser("output-image")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("test_index", type=int)
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=submission_output_image)

    forum = sub.add_parser("forum")
    forum_sub = forum.add_subparsers(dest="cmd", required=True)
    pa = forum_sub.add_parser("list")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=forum_list)
    pa = forum_sub.add_parser("thread")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=forum_thread)
    pa = forum_sub.add_parser("new-page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=forum_new_page)
    pa = forum_sub.add_parser("new")
    pa.add_argument("--title", required=True)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_new)
    pa = forum_sub.add_parser("reply")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_reply)
    pa = forum_sub.add_parser("reply-thread")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_reply_thread)

    repo = sub.add_parser("repository")
    repo_sub = repo.add_subparsers(dest="cmd", required=True)
    pa = repo_sub.add_parser("page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=repository_page)
    pa = repo_sub.add_parser("files")
    pa.set_defaults(func=repository_files)
    pa = repo_sub.add_parser("get")
    pa.add_argument("file_id", type=int)
    pa.add_argument("-o", "--output", help="write file content when the API returns JSON content")
    pa.set_defaults(func=repository_get_file)
    pa = repo_sub.add_parser("save")
    pa.add_argument("--filename", required=True)
    content_group = pa.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", help="text or @file")
    content_group.add_argument("--content-file")
    pa.add_argument("--file-id", type=int)
    pa.set_defaults(func=repository_save_file)
    pa = repo_sub.add_parser("delete")
    pa.add_argument("file_id", type=int)
    pa.set_defaults(func=repository_delete_file)
    pa = repo_sub.add_parser("upload")
    pa.add_argument("file")
    pa.set_defaults(func=repository_upload)
    pa = repo_sub.add_parser("build-index")
    pa.add_argument("--force-restart", action="store_true")
    pa.set_defaults(func=repository_build_index)
    pa = repo_sub.add_parser("rebuild-file")
    pa.add_argument("file_id", type=int)
    pa.add_argument("--force-restart", action="store_true")
    pa.set_defaults(func=repository_rebuild_file)
    pa = repo_sub.add_parser("index-status")
    pa.add_argument("job_id", type=int)
    pa.set_defaults(func=repository_index_status)
    pa = repo_sub.add_parser("active-status")
    pa.set_defaults(func=repository_active_status)
    pa = repo_sub.add_parser("search")
    pa.add_argument("--query", required=True)
    pa.add_argument("--top-k", type=int)
    pa.add_argument("--score-threshold", type=float)
    pa.set_defaults(func=repository_search)
    pa = repo_sub.add_parser("classes")
    pa.add_argument("--limit", type=int, default=300)
    pa.set_defaults(func=repository_classes)

    ai = sub.add_parser("ai")
    ai_sub = ai.add_subparsers(dest="cmd", required=True)
    pa = ai_sub.add_parser("marks")
    pa.add_argument("--submission-id", type=int, required=True)
    pa.add_argument("--force-refresh", action="store_true")
    pa.set_defaults(func=ai_code_marks)

    ranking = sub.add_parser("ranking")
    rank_sub = ranking.add_subparsers(dest="cmd", required=True)
    pa = rank_sub.add_parser("list")
    pa.add_argument("--limit", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=ranking_list)
    pa = rank_sub.add_parser("detail")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--tab")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ranking_detail)
    pa = rank_sub.add_parser("matches")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--mine", action="store_true")
    pa.set_defaults(func=ranking_matches)
    pa = rank_sub.add_parser("match-detail")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("match_id", type=int)
    pa.set_defaults(func=ranking_match_detail)
    pa = rank_sub.add_parser("submit")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--base-model", required=True)
    pa.add_argument("--code-zip", required=True)
    pa.add_argument("--answer-file")
    pa.set_defaults(func=ranking_submit)
    pa = rank_sub.add_parser(
        "git",
        help="Git-based ranking submission: run check first, then submit",
        description=(
            "Use when the ranking competition is configured for Git submission. "
            "Run check first, then submit. "
            "Run `ranking git <competition_id> check` first to verify the server-derived "
            "repository URL and latest commit, then run `ranking git <competition_id> submit`. "
            "Do not pass a repository URL; NumOJ derives it from the competition Git rule and your username."
        ),
    )
    pa.add_argument("competition_id", type=int)
    pa.add_argument("action", choices=["check", "submit"], help="check repository visibility first; submit queues the checked repository for evaluation")
    pa.set_defaults(func=ranking_git)
    pa = rank_sub.add_parser("my-submissions")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=ranking_my_submissions)
    pa = rank_sub.add_parser("leaderboard")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=ranking_leaderboard)
    pa = rank_sub.add_parser("download-submission")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("kind", choices=["answer", "code"])
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=ranking_download_submission)
    pa = rank_sub.add_parser("judge-stream")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--max-lines", type=int, default=20)
    pa.set_defaults(func=ranking_judge_stream)
    pa = rank_sub.add_parser("appeal")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--reason", required=True, help="text or @file")
    pa.set_defaults(func=ranking_submit_appeal)
    pa = rank_sub.add_parser("appeal-status")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
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
