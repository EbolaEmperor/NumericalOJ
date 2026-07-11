from __future__ import annotations

import argparse
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

HELP_FORMATTER = argparse.ArgumentDefaultsHelpFormatter


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
        output_json({"success": True})
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
    print(text if text else json.dumps({"success": True}))


def redirect_response_payload(resp: requests.Response, *, id_pattern: Optional[str] = None, id_name: str = "id") -> Dict[str, Any]:
    ensure_ok(resp)
    location = resp.headers.get("Location", "")
    redirected = 300 <= resp.status_code < 400
    if not redirected:
        if response_is_json(resp):
            payload = resp.json()
            return payload if isinstance(payload, dict) else {"success": False, "response": payload}
        return {
            "success": False,
            "message": "The server returned a form page instead of a success redirect; the operation was not completed.",
        }
    payload: Dict[str, Any] = {"success": True}
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
    output_json({"success": True, "lines": lines, "truncated": len(lines) >= max_lines})


def read_stream_events(resp: requests.Response, *, max_lines: int) -> Dict[str, Any]:
    ensure_ok(resp, allow_redirect=False)
    lines: List[str] = []
    events: List[Any] = []
    for raw in resp.iter_lines(decode_unicode=True):
        if raw is None:
            continue
        line = str(raw)
        if not line:
            continue
        lines.append(line)
        if line.startswith("data:"):
            text = line[5:].strip()
            if text:
                try:
                    events.append(json.loads(text))
                except ValueError:
                    events.append(text)
        if len(lines) >= max_lines:
            break
    return {
        "success": True,
        "lines_read": len(lines),
        "events": events,
        "truncated": len(lines) >= max_lines,
    }


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


def add_common_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to the local CLI config file containing the saved server URL and session cookie.")
    parser.add_argument("--base-url", help="Override the server URL saved in the config file for this command.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP request timeout in seconds.")


def add_cli_parser(subparsers: argparse._SubParsersAction, name: str, description: str, **kwargs: Any) -> argparse.ArgumentParser:
    kwargs.setdefault("help", description)
    kwargs.setdefault("description", description)
    kwargs.setdefault("formatter_class", HELP_FORMATTER)
    return subparsers.add_parser(name, **kwargs)
