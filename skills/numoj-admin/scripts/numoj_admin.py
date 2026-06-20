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
import html as html_lib
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


def print_redirect_response(resp: requests.Response, *, id_pattern: Optional[str] = None, id_name: str = "id") -> None:
    ensure_ok(resp)
    location = resp.headers.get("Location", "")
    payload: Dict[str, Any] = {"success": True, "status": resp.status_code, "location": location}
    if id_pattern and location:
        match = re.search(id_pattern, location)
        if match:
            payload[id_name] = int(match.group(1))
    output_json(payload)


def html_summary(
    resp: requests.Response,
    *,
    source: str,
    output: Optional[str] = None,
    max_chars: int = 2000,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    ensure_ok(resp, allow_redirect=False)
    if output:
        print_or_save_response(resp, output=output, allow_redirect=False)
        return
    text = strip_html(resp.text)
    payload: Dict[str, Any] = {
        "success": True,
        "source": source,
        "status": resp.status_code,
        "text": text[: max(0, max_chars)],
        "truncated": len(text) > max_chars,
    }
    if extra:
        payload.update(extra)
    output_json(payload)


def strip_html(markup: str) -> str:
    markup = re.sub(r"(?is)<script\b.*?</script>", " ", markup)
    markup = re.sub(r"(?is)<style\b.*?</style>", " ", markup)
    text = re.sub(r"(?s)<[^>]+>", " ", markup)
    text = html_lib.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_anchors(markup: str) -> List[Dict[str, str]]:
    anchors: List[Dict[str, str]] = []
    for match in re.finditer(r"<a\b([^>]*)>(.*?)</a>", markup, flags=re.I | re.S):
        href = html_attr(match.group(1), "href")
        if not href:
            continue
        anchors.append({"href": href, "text": strip_html(match.group(2))})
    return anchors


def parse_problem_links(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for anchor in extract_anchors(markup):
        match = re.search(r"/problem/(\d+)", anchor["href"])
        if not match:
            continue
        problem_id = int(match.group(1))
        if problem_id in seen:
            continue
        seen.add(problem_id)
        rows.append({"id": problem_id, "title": anchor["text"], "url": anchor["href"]})
    return rows


def parse_ranking_links(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for anchor in extract_anchors(markup):
        match = re.search(r"/ranking/(\d+)/?(?:[?#].*)?$", anchor["href"])
        if not match:
            continue
        competition_id = int(match.group(1))
        if competition_id in seen:
            continue
        seen.add(competition_id)
        rows.append({"id": competition_id, "title": anchor["text"], "url": anchor["href"]})
    return rows


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


def unique_ints(values: Iterable[str]) -> List[int]:
    seen = set()
    out: List[int] = []
    for raw in values:
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def extract_submission_ids(markup: str) -> List[int]:
    return unique_ints(re.findall(r"/submission_detail/(\d+)", markup))


def html_attr(block: str, attr: str) -> Optional[str]:
    match = re.search(rf'\b{re.escape(attr)}=(["\'])(.*?)\1', block, flags=re.S)
    return html_lib.unescape(match.group(2)) if match else None


def extract_div_blocks_by_class(markup: str, class_token: str) -> List[str]:
    open_re = re.compile(r'<div\b[^>]*\bclass=(["\'])(.*?)\1[^>]*>', flags=re.I | re.S)
    tag_re = re.compile(r"</?div\b[^>]*>", flags=re.I | re.S)
    blocks: List[str] = []
    for match in open_re.finditer(markup):
        class_value = html_lib.unescape(match.group(2))
        if class_token not in class_value.split():
            continue
        depth = 1
        pos = match.end()
        for tag in tag_re.finditer(markup, pos):
            token = tag.group(0)
            if token.startswith("</"):
                depth -= 1
            else:
                depth += 1
            if depth == 0:
                blocks.append(markup[match.start():tag.end()])
                break
    return blocks


def fetch_submission_status(client: NumOJClient, submission_id: int) -> Dict[str, Any]:
    resp = client.request("GET", f"/submission_status/{submission_id}")
    if resp.status_code >= 400 or not response_is_json(resp):
        return {"id": submission_id, "detail_url": f"/submission_detail/{submission_id}", "status_error": resp.status_code}
    data = resp.json()
    data["id"] = submission_id
    data["detail_url"] = f"/submission_detail/{submission_id}"
    return data


def parse_ranking_submission_cards(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for block in extract_div_blocks_by_class(markup, "aj-sub"):
        id_match = re.search(r'class=(["\'])aj-sub-id\1[^>]*>\s*#(\d+)', block, flags=re.I | re.S)
        if not id_match:
            id_match = re.search(r"#(\d+)", strip_html(block))
        if not id_match:
            continue
        status_match = re.search(r'class=(["\'])aj-st\b[^"\']*\1[^>]*>.*?</span>\s*(.*?)</span>', block, flags=re.I | re.S)
        score_match = re.search(r'class=(["\'])aj-sub-score\1[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        time_match = re.search(r'class=(["\'])aj-time\1[^>]*>(.*?)</span>', block, flags=re.I | re.S)
        user_match = re.search(r'class=(["\'])aj-sub-uname\1[^>]*>(.*?)</span>', block, flags=re.I | re.S)
        rows.append(
            {
                "id": int(id_match.group(2 if id_match.lastindex and id_match.lastindex >= 2 else 1)),
                "username": strip_html(user_match.group(2)) if user_match else None,
                "status": strip_html(status_match.group(2)) if status_match else None,
                "score": strip_html(score_match.group(2)) if score_match else None,
                "created_at": strip_html(time_match.group(2)) if time_match else None,
            }
        )
    return rows


def parse_leaderboard(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for block in extract_div_blocks_by_class(markup, "leaderboard-row"):
        rank_match = re.search(r'class=(["\'])lb-rank(?:-num)?\1[^>]*>(.*?)</', block, flags=re.I | re.S)
        if not rank_match:
            rank_match = re.search(r'class=(["\'])lb-rank\1[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        username_match = re.search(r'class=(["\'])lb-username\1[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        score_match = re.search(r'class=(["\'])lb-score-text\1[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        rows.append(
            {
                "rank": strip_html(rank_match.group(2)) if rank_match else None,
                "username": strip_html(username_match.group(2)) if username_match else None,
                "score": strip_html(score_match.group(2)) if score_match else None,
            }
        )
    return rows


def parse_admin_users(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for match in re.finditer(r'<tr\s+id=(["\'])userRow-(\d+)\1[^>]*>(.*?)</tr>', markup, flags=re.I | re.S):
        body = match.group(3)
        username_match = re.search(r'class=(["\'])user-username\1[^>]*>(.*?)</div>', body, flags=re.I | re.S)
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", body, flags=re.I | re.S)
        rows.append(
            {
                "id": int(match.group(2)),
                "username": strip_html(username_match.group(2)) if username_match else (strip_html(cells[1]) if len(cells) > 1 else ""),
                "email": strip_html(cells[2]) if len(cells) > 2 else "",
                "classes": strip_html(cells[3]) if len(cells) > 3 else "",
            }
        )
    return rows


def parse_homework_rows(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for body in re.findall(r"<tr\b[^>]*>(.*?)</tr>", markup, flags=re.I | re.S):
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", body, flags=re.I | re.S)
        if len(cells) < 4:
            continue
        first = strip_html(cells[0])
        title = strip_html(cells[1])
        if "暂无作业" in title:
            continue
        hw_id_match = re.search(r'data-hw-id=(["\'])(.*?)\1', body, flags=re.I | re.S)
        rows.append(
            {
                "homework_id": hw_id_match.group(2) if hw_id_match else None,
                "problem_or_competition_id": first,
                "title": title,
                "ddl": strip_html(cells[2]),
                "complete_count": strip_html(cells[3]),
            }
        )
    return rows


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


def extract_input_value(markup: str, name: str) -> Optional[str]:
    tag = _find_tag_by_name(markup, "input", name)
    if not tag:
        return None
    match = re.search(r'\bvalue=(["\'])(.*?)\1', tag, flags=re.S)
    return html_lib.unescape(match.group(2)) if match else ""


def extract_checkbox_value(markup: str, name: str) -> Optional[bool]:
    tag = _find_tag_by_name(markup, "input", name)
    if not tag:
        return None
    return bool(re.search(r"\bchecked\b", tag, flags=re.I))


def extract_textarea_value(markup: str, name: str) -> Optional[str]:
    match = re.search(
        rf'<textarea\b(?=[^>]*\bname=(["\']){re.escape(name)}\1)[^>]*>(.*?)</textarea>',
        markup,
        flags=re.I | re.S,
    )
    return html_lib.unescape(match.group(2)) if match else None


def extract_select_value(markup: str, name: str) -> Optional[str]:
    match = re.search(
        rf'<select\b(?=[^>]*\bname=(["\']){re.escape(name)}\1)[^>]*>(.*?)</select>',
        markup,
        flags=re.I | re.S,
    )
    if not match:
        return None
    body = match.group(2)
    selected = re.search(
        r'<option\b(?=[^>]*\bselected\b)[^>]*\bvalue=(["\'])(.*?)\1',
        body,
        flags=re.I | re.S,
    )
    if selected:
        return html_lib.unescape(selected.group(2))
    first = re.search(r'<option\b[^>]*\bvalue=(["\'])(.*?)\1', body, flags=re.I | re.S)
    return html_lib.unescape(first.group(2)) if first else None


def _find_tag_by_name(markup: str, tag_name: str, name: str) -> Optional[str]:
    match = re.search(
        rf'<{tag_name}\b(?=[^>]*\bname=(["\']){re.escape(name)}\1)[^>]*>',
        markup,
        flags=re.I | re.S,
    )
    return match.group(0) if match else None


def fetch_form_page(client: NumOJClient, path: str) -> str:
    resp = client.request("GET", path)
    ensure_ok(resp, allow_redirect=False)
    return resp.text


def current_or_arg(current: Dict[str, Any], form_name: str, value: Any) -> Any:
    if value is not None:
        return read_text_value(value) if isinstance(value, str) else value
    return current.get(form_name, "")


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
    resp = client.request("GET", "/admin/users")
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
            "admin": resp.status_code < 400 and "无权限" not in resp.text[:500],
            "base_url": client.base_url,
            "username": cfg.get("username"),
            "status": resp.status_code,
        }
    )


def auth_login_page(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/login")
    html_summary(resp, source="/login", output=args.output, max_chars=args.max_chars)


def site_home(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/")
    print_redirect_response(resp)


def auth_send_code(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/send_code", data={"email": args.email})
    print_or_save_response(resp)


def auth_register_page(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", "/register")
    html_summary(resp, source="/register", output=args.output, max_chars=args.max_chars)


def auth_register(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request(
        "POST",
        "/register",
        data={
            "username": args.username,
            "password": args.password,
            "email": args.email,
            "verification_code": args.code,
            "class": args.class_en,
        },
    )
    print_redirect_response(resp)


def auth_forgot_page(args: argparse.Namespace) -> None:
    params: Dict[str, Any] = {"step": args.step}
    if args.email:
        params["email"] = args.email
    resp = client_from_args(args).request("GET", "/forgot_password", params=params)
    html_summary(resp, source="/forgot_password", output=args.output, max_chars=args.max_chars)


def auth_forgot_request(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("POST", "/forgot_password", params={"step": "email"}, data={"email": args.email})
    print_redirect_response(resp)


def auth_forgot_reset(args: argparse.Namespace) -> None:
    confirm = args.confirm_password or args.new_password
    resp = client_from_args(args).request(
        "POST",
        "/forgot_password",
        params={"step": "verify", "email": args.email},
        data={"code": args.code, "new_password": args.new_password, "confirm_password": confirm},
    )
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
    users_resp = client.request("GET", "/admin/users", params={"username": username})
    ensure_ok(users_resp, allow_redirect=False)
    matches = [u for u in parse_admin_users(users_resp.text) if u.get("username") == username]
    if not matches:
        raise CliError("Cannot find current user id from /admin/users. Pass --user-id explicitly.")
    resp = client.request("GET", "/admin/get_user_grades", params={"user_id": matches[0]["id"]})
    print_or_save_response(resp)


# ----- Submission operations -----


def submissions_from_page(client: NumOJClient, path: str, *, params: Optional[Dict[str, Any]] = None, limit: Optional[int] = None) -> None:
    resp = client.request("GET", path, params=params)
    ensure_ok(resp, allow_redirect=False)
    ids = extract_submission_ids(resp.text)
    if limit is not None:
        ids = ids[: max(0, limit)]
    submissions = [fetch_submission_status(client, sid) for sid in ids]
    output_json(
        {
            "success": True,
            "source": path,
            "params": params or {},
            "count": len(submissions),
            "submission_ids": ids,
            "submissions": submissions,
        }
    )


def submission_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    submissions_from_page(client, "/my_submissions", params={"page": args.page}, limit=args.limit)


def submission_problem_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    submissions_from_page(client, f"/submissionslist/{args.problem_id}", params={"page": args.page}, limit=args.limit)


def submission_status_cmd(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submission_status/{args.submission_id}")
    print_or_save_response(resp)


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
    output_json(fetch_submission_status(client, args.submission_id))


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
    resp = client.request("GET", "/problems")
    if args.output:
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    ensure_ok(resp, allow_redirect=False)
    problems = parse_problem_links(resp.text)
    if args.limit is not None:
        problems = problems[: max(0, args.limit)]
    html_summary(resp, source="/problems", max_chars=args.max_chars, extra={"problems": problems, "count": len(problems)})


def problem_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/problem/{args.problem_id}")
    html_summary(resp, source=f"/problem/{args.problem_id}", output=args.output, max_chars=args.max_chars)


def problem_submit_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/submit/{args.problem_id}")
    html_summary(resp, source=f"/submit/{args.problem_id}", output=args.output, max_chars=args.max_chars)


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


def problem_create_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/add_problem")
    html_summary(resp, source="/admin/add_problem", output=args.output, max_chars=args.max_chars)


def problem_create(args: argparse.Namespace) -> None:
    client = client_from_args(args)
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
            ("programming_grading_prompt", read_text_value(args.programming_grading_prompt)),
            ("written_grading_mode", args.written_grading_mode),
            ("written_grading_model", args.written_grading_model),
            ("written_grading_prompt", read_text_value(args.written_grading_prompt)),
        ]
    )
    resp = client.request("POST", "/admin/add_problem", data=data)
    print_or_save_response(resp)


def problem_edit_form(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/edit_problem/{args.problem_id}")
    html_summary(resp, source=f"/admin/edit_problem/{args.problem_id}", output=args.output, max_chars=args.max_chars)


def problem_edit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    markup = fetch_form_page(client, f"/admin/edit_problem/{args.problem_id}")
    current = {
        "title": extract_input_value(markup, "title"),
        "content": extract_textarea_value(markup, "content"),
        "initial_code": extract_textarea_value(markup, "initial_code"),
        "test_code": extract_textarea_value(markup, "test_code"),
        "forbidden_func": extract_input_value(markup, "forbidden_func"),
        "lang": extract_select_value(markup, "lang"),
        "time_limit": extract_input_value(markup, "time_limit"),
        "submission_limit": extract_input_value(markup, "submission_limit"),
        "programming_grading_mode": extract_select_value(markup, "programming_grading_mode"),
        "programming_grading_model": extract_select_value(markup, "programming_grading_model"),
        "programming_output_filename": extract_input_value(markup, "programming_output_filename"),
        "programming_grading_prompt": extract_textarea_value(markup, "programming_grading_prompt"),
        "written_grading_mode": extract_select_value(markup, "written_grading_mode"),
        "written_grading_model": extract_select_value(markup, "written_grading_model"),
        "written_grading_prompt": extract_textarea_value(markup, "written_grading_prompt"),
    }
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
            ("programming_grading_prompt", current_or_arg(current, "programming_grading_prompt", args.programming_grading_prompt)),
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
    resp = client.request("GET", f"/admin/agent_run/{args.task_id}")
    html_summary(resp, source=f"/admin/agent_run/{args.task_id}", output=args.output, max_chars=args.max_chars)


def problem_agent_run_stream(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/agent_run_stream/{args.task_id}", stream=True)
    print_stream_lines(resp, max_lines=args.max_lines)


def problem_agent_tasks(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/admin/agent_tasks")
    html_summary(resp, source="/admin/agent_tasks", output=args.output, max_chars=args.max_chars)


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
    resp = client.request("GET", "/admin/homework", params={"sclass": args.class_en} if args.class_en else None)
    ensure_ok(resp, allow_redirect=False)
    output_json(
        {
            "success": True,
            "class_en": args.class_en,
            "homeworks": parse_homework_rows(resp.text),
        }
    )


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
    resp = client.request("GET", "/admin/users", params=params)
    ensure_ok(resp, allow_redirect=False)
    output_json(
        {
            "success": True,
            "params": params,
            "users": parse_admin_users(resp.text),
        }
    )


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
    resp = client.request("GET", "/forum")
    html_summary(resp, source="/forum", output=args.output, max_chars=args.max_chars)


def forum_thread(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/forum/thread/{args.thread_id}")
    html_summary(resp, source=f"/forum/thread/{args.thread_id}", output=args.output, max_chars=args.max_chars)


def forum_new_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/forum/new")
    html_summary(resp, source="/forum/new", output=args.output, max_chars=args.max_chars)


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
    resp = client.request("GET", "/code_repository")
    html_summary(resp, source="/code_repository", output=args.output, max_chars=args.max_chars)


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
        "problem_id": args.problem_id,
        "submission_id": args.submission_id,
        "user_code": read_code_arg(args),
        "force_refresh": bool(args.force_refresh),
    }
    resp = client.request("POST", "/ask_ai_code_marks", json=payload)
    print_or_save_response(resp)


def ai_ask(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"problem_id": args.problem_id, "submission_id": args.submission_id, "user_code": read_code_arg(args)}
    resp = client.request("POST", "/ask_ai", json=payload)
    print_or_save_response(resp, output=args.output)


def ai_for_ac(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    payload = {"problem_id": args.problem_id, "user_code": read_code_arg(args)}
    resp = client.request("POST", "/ask_ai_for_ac", json=payload)
    print_or_save_response(resp, output=args.output)


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
    resp = client.request("GET", "/admin/ai_detection")
    html_summary(resp, source="/admin/ai_detection", output=args.output, max_chars=args.max_chars)


def ai_detection_problem_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/ai_detection/problem/{args.problem_id}")
    html_summary(resp, source=f"/admin/ai_detection/problem/{args.problem_id}", output=args.output, max_chars=args.max_chars)


def ai_detection_student_page(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/admin/ai_detection/student/{args.username}")
    html_summary(resp, source=f"/admin/ai_detection/student/{args.username}", output=args.output, max_chars=args.max_chars)


def ai_task_post(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    action = "delete_task" if args.action == "delete" else "stop"
    resp = client.request("POST", f"/admin/ai_detection/api/{action}/{args.task_id}")
    print_or_save_response(resp)


# ----- Ranking competition management -----


def ranking_list(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", "/ranking/")
    if args.output:
        print_or_save_response(resp, output=args.output, allow_redirect=False)
        return
    ensure_ok(resp, allow_redirect=False)
    competitions = parse_ranking_links(resp.text)
    if args.limit is not None:
        competitions = competitions[: max(0, args.limit)]
    html_summary(resp, source="/ranking/", max_chars=args.max_chars, extra={"competitions": competitions, "count": len(competitions)})


def ranking_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    params = {"tab": args.tab} if args.tab else None
    resp = client.request("GET", f"/ranking/{args.competition_id}/", params=params)
    html_summary(resp, source=f"/ranking/{args.competition_id}/", output=args.output, max_chars=args.max_chars)


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
    markup = fetch_form_page(client, f"/ranking/{args.competition_id}/?tab=edit")
    current = {
        "title": extract_input_value(markup, "title"),
        "summary": extract_textarea_value(markup, "summary"),
        "description": extract_textarea_value(markup, "description"),
        "max_score": extract_input_value(markup, "max_score"),
        "is_active": extract_checkbox_value(markup, "is_active"),
        "answer_format": extract_select_value(markup, "answer_format"),
        "scoring_mode": extract_select_value(markup, "scoring_mode"),
        "scoring_script_timeout_seconds": extract_input_value(markup, "scoring_script_timeout_seconds"),
        "submit_limit_per_window": extract_input_value(markup, "submit_limit_per_window"),
        "submission_method": extract_select_value(markup, "submission_method"),
        "git_format": extract_input_value(markup, "git_format"),
        "elo_initial_rating": extract_input_value(markup, "elo_initial_rating"),
        "elo_k_factor": extract_input_value(markup, "elo_k_factor"),
        "elo_max_matches": extract_input_value(markup, "elo_max_matches"),
        "elo_match_interval_seconds": extract_input_value(markup, "elo_match_interval_seconds"),
        "elo_initial_burst": extract_input_value(markup, "elo_initial_burst"),
        "elo_max_pairs_per_round": extract_input_value(markup, "elo_max_pairs_per_round"),
        "agent_judge_timeout_seconds": extract_input_value(markup, "agent_judge_timeout_seconds"),
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
    resp = client.request("GET", f"/ranking/{args.competition_id}/matches_json", params=params)
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
    resp = client.request("GET", f"/ranking/{args.competition_id}/appeals_json", params=params)
    print_or_save_response(resp)


def ranking_appeal_review(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/appeal/{args.appeal_id}/review")
    html_summary(resp, source=f"/ranking/{args.competition_id}/appeal/{args.appeal_id}/review", output=args.output, max_chars=args.max_chars)


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
    resp = client.request("GET", f"/ranking/{args.competition_id}/", params={"tab": "submit"})
    ensure_ok(resp, allow_redirect=False)
    rows = parse_ranking_submission_cards(resp.text)
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    output_json({"success": True, "competition_id": args.competition_id, "submissions": rows, "count": len(rows)})


def ranking_all_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request(
        "GET",
        f"/ranking/{args.competition_id}/submissions_json",
        params={"page": args.page, "q": args.username or ""},
    )
    ensure_ok(resp, allow_redirect=False)
    payload = resp.json() if response_is_json(resp) else {}
    rows_html = str(payload.get("rows_html") or "")
    rows = parse_ranking_submission_cards(rows_html)
    output_json(
        {
            "success": True,
            "competition_id": args.competition_id,
            "page": args.page,
            "username": args.username or "",
            "count": len(rows),
            "submissions": rows,
            "total_pages": payload.get("total_pages"),
            "current_page": payload.get("current_page"),
        }
    )


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/", params={"tab": "leaderboard"})
    ensure_ok(resp, allow_redirect=False)
    rows = parse_leaderboard(resp.text)
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    output_json({"success": True, "competition_id": args.competition_id, "leaderboard": rows, "count": len(rows)})


def ranking_submit_zip(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    files = {"code_file": require_file(args.code_zip)}
    data = {"base_model": args.base_model}
    if args.answer_file:
        files["answer_file"] = require_file(args.answer_file)
    try:
        resp = client.request("POST", f"/ranking/{args.competition_id}/submit", data=data, files=files)
    finally:
        close_files(files)
    print_or_save_response(resp)


def ranking_git_submit(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    path = "check_repo" if args.action == "check" else "git_submit"
    resp = client.request("POST", f"/ranking/{args.competition_id}/{path}")
    print_or_save_response(resp)


def add_common_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="config file path")
    parser.add_argument("--base-url", help="override server base URL")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout seconds")


def add_text_arg(parser: argparse.ArgumentParser, name: str, **kwargs: Any) -> None:
    parser.add_argument(name, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="numoj-admin", description="NumericalOJ administrator CLI over existing HTTP routes")
    add_common_http_args(p)
    sub = p.add_subparsers(dest="group", required=True)

    pa = sub.add_parser("init", help="first-time setup: save NumOJ URL and administrator session token")
    pa.add_argument("--base-url", dest="login_base_url", required=False, help="NumOJ URL, e.g. https://oj.example.com or 127.0.0.1:2025")
    pa.add_argument("-u", "--username", help="administrator username")
    pa.add_argument("-p", "--password", help="administrator password")
    pa.set_defaults(func=init_cli, prompt_base_url=True)

    site = sub.add_parser("site")
    sites = site.add_subparsers(dest="cmd", required=True)
    pa = sites.add_parser("home")
    pa.set_defaults(func=site_home)

    auth = sub.add_parser("auth")
    auth_sub = auth.add_subparsers(dest="cmd", required=True)
    pa = auth_sub.add_parser("login")
    pa.add_argument("--base-url", dest="login_base_url", required=False, help="server URL, e.g. https://oj.example.com")
    pa.add_argument("-u", "--username")
    pa.add_argument("-p", "--password")
    pa.set_defaults(func=login)
    pa = auth_sub.add_parser("logout")
    pa.set_defaults(func=logout)
    pa = auth_sub.add_parser("status")
    pa.set_defaults(func=status)
    pa = auth_sub.add_parser("login-page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=auth_login_page)
    pa = auth_sub.add_parser("send-code")
    pa.add_argument("--email", required=True)
    pa.set_defaults(func=auth_send_code)
    pa = auth_sub.add_parser("register-page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=auth_register_page)
    pa = auth_sub.add_parser("register")
    pa.add_argument("--username", required=True)
    pa.add_argument("--password", required=True)
    pa.add_argument("--email", required=True)
    pa.add_argument("--code", required=True)
    pa.add_argument("--class-en", required=True)
    pa.set_defaults(func=auth_register)
    pa = auth_sub.add_parser("forgot-page")
    pa.add_argument("--step", choices=["email", "verify"], default="email")
    pa.add_argument("--email")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=auth_forgot_page)
    pa = auth_sub.add_parser("forgot-request")
    pa.add_argument("--email", required=True)
    pa.set_defaults(func=auth_forgot_request)
    pa = auth_sub.add_parser("forgot-reset")
    pa.add_argument("--email", required=True)
    pa.add_argument("--code", required=True)
    pa.add_argument("--new-password", required=True)
    pa.add_argument("--confirm-password")
    pa.set_defaults(func=auth_forgot_reset)
    pa = auth_sub.add_parser("send-password-code")
    pa.set_defaults(func=auth_send_password_code)
    pa = auth_sub.add_parser("change-password")
    pa.add_argument("--code", required=True)
    pa.add_argument("--new-password", required=True)
    pa.add_argument("--confirm-password")
    pa.set_defaults(func=auth_change_password)

    me = sub.add_parser("me")
    mes = me.add_subparsers(dest="cmd", required=True)
    pa = mes.add_parser("classes")
    pa.set_defaults(func=me_classes)
    pa = mes.add_parser("join-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_join_class)
    pa = mes.add_parser("leave-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_leave_class)
    pa = mes.add_parser("set-primary-class")
    pa.add_argument("class_en")
    pa.set_defaults(func=me_set_primary_class)
    pa = mes.add_parser("grades")
    pa.add_argument("--user-id", type=int, help="admin-visible user id; omitted means current initialized username")
    pa.add_argument("--username", help="admin-visible username; defaults to initialized username")
    pa.set_defaults(func=me_grades)
    pa = mes.add_parser("submissions")
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_list)

    submission = sub.add_parser("submission")
    ss = submission.add_subparsers(dest="cmd", required=True)
    pa = ss.add_parser("list")
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_list)
    pa = ss.add_parser("problem")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=submission_problem_list)
    pa = ss.add_parser("status")
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=submission_status_cmd)
    pa = ss.add_parser("stream")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--max-lines", type=int, default=20)
    pa.set_defaults(func=submission_stream)
    pa = ss.add_parser("detail")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("-o", "--output", help="save original HTML detail page instead of JSON status")
    pa.set_defaults(func=submission_detail_cmd)
    pa = ss.add_parser("last-code")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=submission_last_code)
    pa = ss.add_parser("output-image")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("test_index", type=int)
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=submission_output_image)
    pa = ss.add_parser("download-file")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=submission_download_file)

    problem = sub.add_parser("problem")
    ps = problem.add_subparsers(dest="cmd", required=True)
    pa = ps.add_parser("list")
    pa.add_argument("--limit", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=problem_list)
    pa = ps.add_parser("detail")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_detail)
    pa = ps.add_parser("submit-page")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=problem_submit_page)
    pa = ps.add_parser("submit")
    pa.add_argument("problem_id", type=int)
    submit_group = pa.add_mutually_exclusive_group(required=True)
    submit_group.add_argument("--code", help="source code text, or @file")
    submit_group.add_argument("--code-file", help="source code file path")
    submit_group.add_argument("--file", help="written-homework PDF/ZIP file path")
    pa.set_defaults(func=problem_submit)
    pa = ps.add_parser("create-form")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_create_form)
    pa = ps.add_parser("create")
    pa.add_argument("--title", required=True)
    pa.add_argument("--content", required=True, help="text or @markdown-file")
    pa.add_argument("--type", choices=["1", "2"], default="1")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"], default="matlab")
    pa.add_argument("--time-limit-ms", "--time-limit", dest="time_limit", type=int, default=2000, help="time limit in milliseconds")
    pa.add_argument("--submission-limit", type=int, default=10)
    pa.add_argument("--initial-code", default="")
    pa.add_argument("--test-code", default="")
    pa.add_argument("--forbidden-func", default="")
    pa.add_argument("--programming-grading-mode", type=int, default=1)
    pa.add_argument("--programming-grading-model")
    pa.add_argument("--programming-output-filename")
    pa.add_argument("--programming-grading-prompt", default="")
    pa.add_argument("--written-grading-mode", type=int, default=1)
    pa.add_argument("--written-grading-model")
    pa.add_argument("--written-grading-prompt", default="")
    pa.set_defaults(func=problem_create)
    pa = ps.add_parser("edit-form")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_edit_form)
    pa = ps.add_parser("edit")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--title")
    pa.add_argument("--content", help="text or @markdown-file")
    pa.add_argument("--lang", choices=["matlab", "c", "cpp", "python"])
    pa.add_argument("--time-limit-ms", "--time-limit", dest="time_limit", type=int, help="time limit in milliseconds")
    pa.add_argument("--submission-limit", type=int)
    pa.add_argument("--initial-code")
    pa.add_argument("--test-code")
    pa.add_argument("--forbidden-func")
    pa.add_argument("--programming-grading-mode", type=int)
    pa.add_argument("--programming-grading-model")
    pa.add_argument("--programming-output-filename")
    pa.add_argument("--programming-grading-prompt")
    pa.add_argument("--written-grading-mode", type=int)
    pa.add_argument("--written-grading-model")
    pa.add_argument("--written-grading-prompt")
    pa.set_defaults(func=problem_edit)
    pa = ps.add_parser("delete")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=problem_delete)
    pa = ps.add_parser("upload-testdata")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("zip")
    pa.set_defaults(func=problem_upload_testdata)
    pa = ps.add_parser("rejudge")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=problem_rejudge)
    pa = ps.add_parser("rejudge-status")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=problem_rejudge_status)
    pa = ps.add_parser("rejudge-time-range")
    pa.add_argument("--start", required=True, help="YYYY-MM-DDTHH:MM")
    pa.add_argument("--end", required=True, help="YYYY-MM-DDTHH:MM")
    pa.add_argument("--confirm-total", type=int)
    pa.set_defaults(func=problem_rejudge_time_range)
    pa = ps.add_parser("rejudge-time-range-status")
    pa.set_defaults(func=problem_rejudge_time_range_status)
    pa = ps.add_parser("agent-run-status")
    pa.add_argument("task_id")
    pa.set_defaults(func=problem_agent_run_status)
    pa = ps.add_parser("agent-run")
    pa.add_argument("task_id")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_agent_run_page)
    pa = ps.add_parser("agent-run-stream")
    pa.add_argument("task_id")
    pa.add_argument("--max-lines", type=int, default=20)
    pa.set_defaults(func=problem_agent_run_stream)
    pa = ps.add_parser("agent-tasks")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=problem_agent_tasks)
    pa = ps.add_parser("agent-solve")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--extra-prompt", default="")
    pa.set_defaults(func=problem_agent_solve)
    pa = ps.add_parser("agent-generate-data")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--count", type=int, required=True)
    pa.add_argument("--standard-code", required=True, help="text or @file")
    pa.add_argument("--data-requirement", default="")
    pa.set_defaults(func=problem_agent_generate_data)
    pa = ps.add_parser("scores")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=problem_scores)

    hw = sub.add_parser("homework")
    hs = hw.add_subparsers(dest="cmd", required=True)
    pa = hs.add_parser("list")
    pa.add_argument("--class-en")
    pa.set_defaults(func=homework_list)
    pa = hs.add_parser("add")
    pa.add_argument("--class-en", required=True)
    pa.add_argument("--ddl", required=True, help="YYYY-MM-DDTHH:MM or MySQL datetime")
    group = pa.add_mutually_exclusive_group(required=True)
    group.add_argument("--problem-id", type=int)
    group.add_argument("--ranking-competition-id", type=int)
    pa.set_defaults(func=homework_add)
    pa = hs.add_parser("update-ddl")
    pa.add_argument("--class-en", required=True)
    pa.add_argument("--homework-id", required=True)
    pa.add_argument("--ddl", required=True)
    pa.set_defaults(func=homework_update_ddl)
    pa = hs.add_parser("delete")
    pa.add_argument("--class-en", required=True)
    pa.add_argument("--homework-id", required=True)
    pa.set_defaults(func=homework_delete)
    pa = hs.add_parser("export-scores")
    pa.add_argument("--class-en", required=True)
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=homework_export_scores)
    pa = hs.add_parser("export-codes")
    pa.add_argument("--class-en", required=True)
    pa.set_defaults(func=homework_export_codes)
    pa = hs.add_parser("export-progress")
    pa.add_argument("task_id")
    pa.set_defaults(func=homework_export_progress)
    pa = hs.add_parser("download-export")
    pa.add_argument("task_id")
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=homework_download_export)
    pa = hs.add_parser("upload-exam")
    pa.add_argument("--class-en", required=True)
    pa.add_argument("file")
    pa.set_defaults(func=homework_upload_exam)
    pa = hs.add_parser("class-adjust")
    pa.add_argument("enabled", type=lambda x: str(x).lower() in ("1", "true", "yes", "on"))
    pa.set_defaults(func=class_adjust)

    user = sub.add_parser("user")
    us = user.add_subparsers(dest="cmd", required=True)
    pa = us.add_parser("list")
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--username")
    pa.add_argument("--class-en")
    pa.set_defaults(func=user_list)
    pa = us.add_parser("add-class-type")
    pa.add_argument("--class-en", required=True, help="without leading C, matching web form behavior")
    pa.add_argument("--class-cn", required=True)
    pa.set_defaults(func=user_add_class_type)
    pa = us.add_parser("set-primary-class")
    pa.add_argument("user_id", type=int)
    pa.add_argument("class_en")
    pa.set_defaults(func=user_set_primary_class)
    pa = us.add_parser("rename")
    pa.add_argument("user_id", type=int)
    pa.add_argument("username")
    pa.set_defaults(func=user_rename)
    pa = us.add_parser("add-to-class")
    pa.add_argument("user_id", type=int)
    pa.add_argument("class_en")
    pa.set_defaults(func=user_add_to_class)
    pa = us.add_parser("remove-from-class")
    pa.add_argument("user_id", type=int)
    pa.add_argument("class_en")
    pa.set_defaults(func=user_remove_from_class)
    pa = us.add_parser("grades")
    pa.add_argument("user_id", type=int)
    pa.set_defaults(func=user_grades)
    pa = us.add_parser("update-grade")
    pa.add_argument("user_id", type=int)
    pa.add_argument("problem_id", type=int)
    g = pa.add_mutually_exclusive_group(required=True)
    g.add_argument("--score", type=int)
    g.add_argument("--clear", action="store_true")
    pa.set_defaults(func=user_update_grade)

    grading = sub.add_parser("grading")
    gs = grading.add_subparsers(dest="cmd", required=True)
    pa = gs.add_parser("submit")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--score", type=int, required=True)
    pa.add_argument("--comment", default="")
    pa.set_defaults(func=grading_submit)
    pa = gs.add_parser("next-pending")
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=grading_next_pending)
    pa = gs.add_parser("invalidate-invalid")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=grading_invalidate)

    forum = sub.add_parser("forum")
    fs = forum.add_subparsers(dest="cmd", required=True)
    pa = fs.add_parser("list")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=forum_list)
    pa = fs.add_parser("thread")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=forum_thread)
    pa = fs.add_parser("new-page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=forum_new_page)
    pa = fs.add_parser("new")
    pa.add_argument("--title", required=True)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_new)
    pa = fs.add_parser("reply")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_reply)
    pa = fs.add_parser("reply-thread")
    pa.add_argument("thread_id", type=int)
    pa.add_argument("--content", required=True, help="text or @file")
    pa.set_defaults(func=forum_reply_thread)

    repo = sub.add_parser("repository")
    repos = repo.add_subparsers(dest="cmd", required=True)
    pa = repos.add_parser("page")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=repository_page)
    pa = repos.add_parser("files")
    pa.set_defaults(func=repository_files)
    pa = repos.add_parser("get")
    pa.add_argument("file_id", type=int)
    pa.add_argument("-o", "--output", help="write file content when the API returns JSON content")
    pa.set_defaults(func=repository_get_file)
    pa = repos.add_parser("save")
    pa.add_argument("--filename", required=True)
    content_group = pa.add_mutually_exclusive_group(required=True)
    content_group.add_argument("--content", help="text or @file")
    content_group.add_argument("--content-file")
    pa.add_argument("--file-id", type=int)
    pa.set_defaults(func=repository_save_file)
    pa = repos.add_parser("delete")
    pa.add_argument("file_id", type=int)
    pa.set_defaults(func=repository_delete_file)
    pa = repos.add_parser("upload")
    pa.add_argument("file")
    pa.set_defaults(func=repository_upload)
    pa = repos.add_parser("build-index")
    pa.add_argument("--force-restart", action="store_true")
    pa.set_defaults(func=repository_build_index)
    pa = repos.add_parser("rebuild-file")
    pa.add_argument("file_id", type=int)
    pa.add_argument("--force-restart", action="store_true")
    pa.set_defaults(func=repository_rebuild_file)
    pa = repos.add_parser("index-status")
    pa.add_argument("job_id", type=int)
    pa.set_defaults(func=repository_index_status)
    pa = repos.add_parser("active-status")
    pa.set_defaults(func=repository_active_status)
    pa = repos.add_parser("search")
    pa.add_argument("--query", required=True)
    pa.add_argument("--top-k", type=int)
    pa.add_argument("--score-threshold", type=float)
    pa.set_defaults(func=repository_search)
    pa = repos.add_parser("classes")
    pa.add_argument("--limit", type=int, default=300)
    pa.set_defaults(func=repository_classes)

    tutor = sub.add_parser("ai")
    tutors = tutor.add_subparsers(dest="cmd", required=True)
    pa = tutors.add_parser("marks")
    pa.add_argument("--problem-id", type=int, required=True)
    pa.add_argument("--submission-id", type=int, required=True)
    ag = pa.add_mutually_exclusive_group(required=True)
    ag.add_argument("--code", help="source code text, or @file")
    ag.add_argument("--code-file")
    pa.add_argument("--force-refresh", action="store_true")
    pa.set_defaults(func=ai_code_marks)
    pa = tutors.add_parser("ask")
    pa.add_argument("--problem-id", type=int, required=True)
    pa.add_argument("--submission-id", type=int, required=True)
    ag = pa.add_mutually_exclusive_group(required=True)
    ag.add_argument("--code", help="source code text, or @file")
    ag.add_argument("--code-file")
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=ai_ask)
    pa = tutors.add_parser("ac")
    pa.add_argument("--problem-id", type=int, required=True)
    ag = pa.add_mutually_exclusive_group(required=True)
    ag.add_argument("--code", help="source code text, or @file")
    ag.add_argument("--code-file")
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=ai_for_ac)

    ai = sub.add_parser("ai-detection")
    ais = ai.add_subparsers(dest="cmd", required=True)
    pa = ais.add_parser("dashboard")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ai_detection_page)
    pa = ais.add_parser("problem-page")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ai_detection_problem_page)
    pa = ais.add_parser("student-page")
    pa.add_argument("username")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ai_detection_student_page)
    for name, func in (("preview", ai_preview), ("run-filtered", ai_run_filtered)):
        pa = ais.add_parser(name)
        pa.add_argument("--class-en")
        pa.add_argument("--username")
        pa.add_argument("--problem-id", type=int)
        pa.add_argument("--submission-id", type=int)
        pa.add_argument("--score-min", type=float)
        pa.add_argument("--score-max", type=float)
        pa.add_argument("--deduplicate", action="store_true", default=None)
        pa.add_argument("--model")
        pa.set_defaults(func=func)
    pa = ais.add_parser("run-problem")
    pa.add_argument("problem_id", type=int)
    pa.add_argument("--model")
    pa.set_defaults(func=ai_run_problem)
    pa = ais.add_parser("run-single")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--model")
    pa.set_defaults(func=ai_run_single)
    pa = ais.add_parser("run-user")
    pa.add_argument("username")
    pa.add_argument("--model")
    pa.set_defaults(func=ai_run_user)
    for name, path in (
        ("summary", "/admin/ai_detection/api/summary"),
        ("tasks", "/admin/ai_detection/api/tasks"),
        ("models", "/admin/ai_detection/api/available_models"),
    ):
        pa = ais.add_parser(name)
        pa.set_defaults(func=ai_api_get, path=path)
    pa = ais.add_parser("task")
    pa.add_argument("action", choices=["stop", "delete"])
    pa.add_argument("task_id")
    pa.set_defaults(func=ai_task_post)

    rk = sub.add_parser("ranking")
    rs = rk.add_subparsers(dest="cmd", required=True)
    pa = rs.add_parser("list")
    pa.add_argument("--limit", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=2000)
    pa.set_defaults(func=ranking_list)
    pa = rs.add_parser("detail")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--tab")
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ranking_detail)
    pa = rs.add_parser("create")
    pa.add_argument("--title", required=True)
    pa.add_argument("--summary", default="")
    pa.add_argument("--description", default="")
    pa.add_argument("--max-score", type=int, default=100)
    pa.set_defaults(func=ranking_create)
    pa = rs.add_parser("copy")
    pa.add_argument("competition_id", type=int)
    pa.set_defaults(func=ranking_copy)
    pa = rs.add_parser("edit")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--title")
    pa.add_argument("--summary")
    pa.add_argument("--description")
    pa.add_argument("--max-score", type=int)
    active_group = pa.add_mutually_exclusive_group()
    active_group.add_argument("--active", dest="active", action="store_true", default=None)
    active_group.add_argument("--inactive", dest="active", action="store_false")
    pa.add_argument("--answer-format", choices=["json", "zip"])
    pa.add_argument("--scoring-mode", choices=["absolute", "elo", "agent_judge"])
    pa.add_argument("--script-timeout", type=int)
    pa.add_argument("--submit-limit", type=int)
    pa.add_argument("--reset-limit-window", action="store_true")
    pa.add_argument("--submission-method", choices=["zip", "git"])
    pa.add_argument("--git-format")
    pa.add_argument("--elo-initial-rating", type=float)
    pa.add_argument("--elo-k-factor", type=float)
    pa.add_argument("--elo-max-matches", type=int)
    pa.add_argument("--elo-match-interval", type=int)
    pa.add_argument("--elo-initial-burst", type=int)
    pa.add_argument("--elo-max-pairs-per-round", type=int)
    pa.add_argument("--agent-timeout", type=int)
    pa.set_defaults(func=ranking_edit)
    pa = rs.add_parser("delete")
    pa.add_argument("competition_id", type=int)
    pa.set_defaults(func=ranking_delete)
    pa = rs.add_parser("upload-attachment")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("file")
    pa.set_defaults(func=ranking_upload_attachment)
    pa = rs.add_parser("delete-attachment")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("file_id", type=int)
    pa.set_defaults(func=ranking_delete_attachment)
    pa = rs.add_parser("download-attachment")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("file_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--inline", action="store_true")
    pa.set_defaults(func=ranking_download_attachment)
    pa = rs.add_parser("upload-reference")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("file")
    pa.set_defaults(func=ranking_upload_reference)
    pa = rs.add_parser("upload-script")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("file")
    pa.set_defaults(func=ranking_upload_script)
    pa = rs.add_parser("clear-script")
    pa.add_argument("competition_id", type=int)
    pa.set_defaults(func=ranking_clear_script)
    pa = rs.add_parser("reset-limit")
    pa.add_argument("competition_id", type=int)
    pa.set_defaults(func=ranking_reset_limit)
    pa = rs.add_parser("save-config")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--agent-base-url", dest="base_url_value")
    pa.add_argument("--api-key", help="text or @file")
    pa.add_argument("--model")
    pa.add_argument("--timeout-seconds", type=int)
    pa.set_defaults(func=ranking_config)
    pa = rs.add_parser("save-rules")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("rules", help="JSON array or @file")
    pa.set_defaults(func=ranking_rules)
    pa = rs.add_parser("save-endpoints")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("endpoints", help="JSON array or @file")
    pa.add_argument("--timeout-seconds", type=int)
    pa.set_defaults(func=ranking_endpoints)
    pa = rs.add_parser("batch-probe")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--classes", required=True, help="comma separated class_en list")
    pa.add_argument("--template", required=True)
    pa.set_defaults(func=ranking_batch_probe)
    pa = rs.add_parser("batch-status")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("job_id")
    pa.set_defaults(func=ranking_batch_status)
    pa = rs.add_parser("batch-create")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--template", required=True)
    pa.add_argument("--usernames", required=True, help="comma separated usernames")
    pa.set_defaults(func=ranking_batch_create)
    pa = rs.add_parser("matches")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--mine", action="store_true")
    pa.set_defaults(func=ranking_matches)
    pa = rs.add_parser("match-detail")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("match_id", type=int)
    pa.set_defaults(func=ranking_match_detail)
    pa = rs.add_parser("bulk-filter")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--start")
    pa.add_argument("--end")
    pa.add_argument("--username")
    pa.add_argument("--statuses", help="comma separated: judging,waiting,accepted,abnormal")
    pa.set_defaults(func=ranking_bulk_filter)
    pa = rs.add_parser("bulk-start")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--submission-ids", required=True, help="comma separated submission ids")
    pa.set_defaults(func=ranking_bulk_start)
    pa = rs.add_parser("bulk-status")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("job_id")
    pa.set_defaults(func=ranking_bulk_status)
    pa = rs.add_parser("rejudge-agent")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=ranking_rejudge_agent)
    pa = rs.add_parser("appeal")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--reason", required=True, help="text or @file")
    pa.set_defaults(func=ranking_submit_appeal)
    pa = rs.add_parser("appeal-status")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=ranking_appeal_status)
    pa = rs.add_parser("appeals")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--query")
    pa.add_argument("--status")
    pa.set_defaults(func=ranking_appeals)
    pa = rs.add_parser("appeal-review")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("appeal_id", type=int)
    pa.add_argument("-o", "--output")
    pa.add_argument("--max-chars", type=int, default=3000)
    pa.set_defaults(func=ranking_appeal_review)
    pa = rs.add_parser("appeal-handle")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("appeal_id", type=int)
    pa.add_argument("--decision", choices=["resolved", "rejected"], required=True)
    pa.add_argument("--response", default="")
    pa.add_argument("--overrides", help="JSON object or @file")
    pa.set_defaults(func=ranking_appeal_handle)
    for name in ("start", "stop", "reset"):
        pa = rs.add_parser(f"elo-{name}")
        pa.add_argument("competition_id", type=int)
        pa.set_defaults(func=ranking_elo_action, action=name)
    pa = rs.add_parser("elo-delete-match")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("match_id", type=int)
    pa.set_defaults(func=ranking_elo_delete_match)
    pa = rs.add_parser("elo-rebuild")
    pa.add_argument("competition_id", type=int)
    pa.set_defaults(func=ranking_elo_rebuild)
    pa = rs.add_parser("delete-submission")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.set_defaults(func=ranking_delete_submission)
    pa = rs.add_parser("download-submission")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("kind", choices=["answer", "code"])
    pa.add_argument("-o", "--output")
    pa.set_defaults(func=ranking_download_submission)
    pa = rs.add_parser("judge-stream")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("submission_id", type=int)
    pa.add_argument("--max-lines", type=int, default=20)
    pa.set_defaults(func=ranking_judge_stream)
    pa = rs.add_parser("my-submissions")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=ranking_my_submissions)
    pa = rs.add_parser("submissions")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--page", type=int, default=1)
    pa.add_argument("--username")
    pa.set_defaults(func=ranking_all_submissions)
    pa = rs.add_parser("leaderboard")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--limit", type=int)
    pa.set_defaults(func=ranking_leaderboard)
    pa = rs.add_parser("submit")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--base-model", required=True)
    pa.add_argument("--code-zip", required=True)
    pa.add_argument("--answer-file")
    pa.set_defaults(func=ranking_submit_zip)
    pa = rs.add_parser("submit-zip")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--base-model", required=True)
    pa.add_argument("--code-zip", required=True)
    pa.add_argument("--answer-file")
    pa.set_defaults(func=ranking_submit_zip)
    pa = rs.add_parser("git")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("action", choices=["check", "submit"])
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
