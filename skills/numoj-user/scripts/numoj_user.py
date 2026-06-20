#!/usr/bin/env python3
"""NumericalOJ regular-user CLI over existing web routes."""

from __future__ import annotations

import argparse
import getpass
import html as html_lib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
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


def strip_html(markup: str) -> str:
    markup = re.sub(r"(?is)<script\b.*?</script>", " ", markup)
    markup = re.sub(r"(?is)<style\b.*?</style>", " ", markup)
    text = re.sub(r"(?s)<[^>]+>", " ", markup)
    text = html_lib.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


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
    payload: Dict[str, Any] = {"success": True, "status": resp.status_code, "location": location}
    if id_pattern and location:
        match = re.search(id_pattern, location)
        if match:
            payload[id_name] = int(match.group(1))
    output_json(payload)


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


def extract_div_blocks_by_class(markup: str, class_token: str) -> List[str]:
    open_re = re.compile(r'<div\b[^>]*\bclass=(["\'])(.*?)\1[^>]*>', flags=re.I | re.S)
    tag_re = re.compile(r"</?div\b[^>]*>", flags=re.I | re.S)
    blocks: List[str] = []
    for match in open_re.finditer(markup):
        if class_token not in html_lib.unescape(match.group(2)).split():
            continue
        depth = 1
        for tag in tag_re.finditer(markup, match.end()):
            if tag.group(0).startswith("</"):
                depth -= 1
            else:
                depth += 1
            if depth == 0:
                blocks.append(markup[match.start():tag.end()])
                break
    return blocks


def parse_ranking_submission_cards(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for block in extract_div_blocks_by_class(markup, "aj-sub"):
        id_match = re.search(r'class=(["\'])aj-sub-id\1[^>]*>\s*#(\d+)', block, flags=re.I | re.S)
        if not id_match:
            continue
        status_match = re.search(r'class=(["\'])aj-st\b[^"\']*\1[^>]*>.*?</span>\s*(.*?)</span>', block, flags=re.I | re.S)
        score_match = re.search(r'class=(["\'])aj-sub-score\1[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        time_match = re.search(r'class=(["\'])aj-time\1[^>]*>(.*?)</span>', block, flags=re.I | re.S)
        rows.append(
            {
                "id": int(id_match.group(2)),
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


def parse_submission_rows(markup: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for block in re.findall(r'<div class="list-group-item d-flex align-items-center">(.*?)</div>\s*</div>', markup, flags=re.I | re.S):
        sid_match = re.search(r"/submission_detail/(\d+)", block)
        if not sid_match:
            continue
        status_match = re.search(r'<span class="badge[^"]*">\s*(.*?)\s*</span>', block, flags=re.I | re.S)
        cells = re.findall(r'<div class="flex-fill[^"]*"[^>]*>(.*?)</div>', block, flags=re.I | re.S)
        rows.append(
            {
                "id": int(sid_match.group(1)),
                "status": strip_html(status_match.group(1)) if status_match else None,
                "score": strip_html(cells[2]) if len(cells) > 2 else None,
                "problem": strip_html(cells[3]) if len(cells) > 3 else None,
            }
        )
    return rows


def client_from_args(args: argparse.Namespace) -> NumOJClient:
    cfg = load_config(args.config)
    if args.base_url:
        cfg["base_url"] = normalize_base_url(args.base_url)
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
            client_from_args(args).request("GET", "/logout")
        except Exception:
            pass
    cfg.pop("cookies", None)
    save_config(args.config, cfg)
    output_json({"success": True, "message": "local token cleared"})


def status(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    client = client_from_args(args)
    resp = client.request("GET", "/me/classes")
    output_json(
        {
            "authenticated": resp.status_code < 400,
            "base_url": client.base_url,
            "username": cfg.get("username"),
            "status": resp.status_code,
        }
    )


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


def fetch_submission_status(client: NumOJClient, submission_id: int) -> Dict[str, Any]:
    resp = client.request("GET", f"/submission_status/{submission_id}")
    if resp.status_code >= 400 or not response_is_json(resp):
        return {"id": submission_id, "detail_url": f"/submission_detail/{submission_id}", "status_error": resp.status_code}
    data = resp.json()
    data["id"] = submission_id
    data["detail_url"] = f"/submission_detail/{submission_id}"
    return data


def submissions_from_page(client: NumOJClient, path: str, *, params: Optional[Dict[str, Any]] = None, limit: Optional[int] = None) -> None:
    resp = client.request("GET", path, params=params)
    ensure_ok(resp, allow_redirect=False)
    ids = extract_submission_ids(resp.text)
    if limit is not None:
        ids = ids[: max(0, limit)]
    output_json(
        {
            "success": True,
            "source": path,
            "count": len(ids),
            "submission_ids": ids,
            "submissions": [fetch_submission_status(client, sid) for sid in ids],
        }
    )


def submission_list(args: argparse.Namespace) -> None:
    submissions_from_page(client_from_args(args), "/my_submissions", params={"page": args.page}, limit=args.limit)


def submission_problem_list(args: argparse.Namespace) -> None:
    submissions_from_page(client_from_args(args), f"/submissionslist/{args.problem_id}", params={"page": args.page}, limit=args.limit)


def submission_status_cmd(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/submission_status/{args.submission_id}")
    print_or_save_response(resp)


def submission_detail(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    if args.output:
        resp = client.request("GET", f"/submission_detail/{args.submission_id}")
        print_or_save_response(resp, output=args.output, allow_redirect=False)
    else:
        output_json(fetch_submission_status(client, args.submission_id))


def submission_last_code(args: argparse.Namespace) -> None:
    resp = client_from_args(args).request("GET", f"/api/get_last_submission_code/{args.problem_id}")
    print_or_save_response(resp)


def me_grades(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    best: Dict[str, Dict[str, Any]] = {}
    for page in range(1, args.pages + 1):
        resp = client.request("GET", "/my_submissions", params={"page": page})
        ensure_ok(resp, allow_redirect=False)
        rows = parse_submission_rows(resp.text)
        if not rows:
            break
        for row in rows:
            problem = row.get("problem") or f"submission:{row['id']}"
            try:
                score_value = float(str(row.get("score") or "0"))
            except ValueError:
                score_value = 0.0
            if problem not in best or score_value > float(best[problem].get("score_value") or 0):
                row["score_value"] = score_value
                best[problem] = row
    output_json({"success": True, "source": "visible submission history", "grades": list(best.values())})


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


def ranking_submit(args: argparse.Namespace) -> None:
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


def ranking_git(args: argparse.Namespace) -> None:
    path = "check_repo" if args.action == "check" else "git_submit"
    resp = client_from_args(args).request("POST", f"/ranking/{args.competition_id}/{path}")
    print_or_save_response(resp)


def ranking_my_submissions(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/", params={"tab": "submit"})
    ensure_ok(resp, allow_redirect=False)
    rows = parse_ranking_submission_cards(resp.text)
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    output_json({"success": True, "competition_id": args.competition_id, "submissions": rows, "count": len(rows)})


def ranking_leaderboard(args: argparse.Namespace) -> None:
    client = client_from_args(args)
    resp = client.request("GET", f"/ranking/{args.competition_id}/", params={"tab": "leaderboard"})
    ensure_ok(resp, allow_redirect=False)
    rows = parse_leaderboard(resp.text)
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    output_json({"success": True, "competition_id": args.competition_id, "leaderboard": rows, "count": len(rows)})


def ranking_download_submission(args: argparse.Namespace) -> None:
    kind = "answer" if args.kind == "answer" else "code"
    resp = client_from_args(args).request("GET", f"/ranking/submission/{args.submission_id}/{kind}")
    print_or_save_response(resp, output=args.output or ".")


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
    pa = sub_sub.add_parser("detail")
    pa.add_argument("submission_id", type=int)
    pa.add_argument("-o", "--output", help="save original HTML detail page instead of JSON status")
    pa.set_defaults(func=submission_detail)
    pa = sub_sub.add_parser("last-code")
    pa.add_argument("problem_id", type=int)
    pa.set_defaults(func=submission_last_code)

    ranking = sub.add_parser("ranking")
    rank_sub = ranking.add_subparsers(dest="cmd", required=True)
    pa = rank_sub.add_parser("submit")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("--base-model", required=True)
    pa.add_argument("--code-zip", required=True)
    pa.add_argument("--answer-file")
    pa.set_defaults(func=ranking_submit)
    pa = rank_sub.add_parser("git")
    pa.add_argument("competition_id", type=int)
    pa.add_argument("action", choices=["check", "submit"])
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
