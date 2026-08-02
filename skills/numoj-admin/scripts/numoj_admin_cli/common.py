from __future__ import annotations

import argparse
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
        "numoj-admin requires the Python package 'requests'. "
        "Install it in this skill runtime with: python3 -m pip install --user requests"
    ) from exc


DEFAULT_CONFIG_PATH = Path(
    os.environ.get("NUMOJ_CLI_CONFIG", "~/.numoj-cli/config.json")
).expanduser()

HELP_FORMATTER = argparse.ArgumentDefaultsHelpFormatter


class CliError(RuntimeError):
    pass


class CliHttpError(CliError):
    def __init__(self, status_code: int, payload: Any):
        self.status_code = status_code
        self.payload = payload
        super().__init__(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def eprint(*parts: Any) -> None:
    print(*parts, file=sys.stderr)


def read_text_value(value: Optional[str]) -> str:
    if value is None:
        return ""
    if value.startswith("@"):
        path = Path(value[1:]).expanduser()
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError(f"Cannot read file: {path}: {exc.strerror or exc}") from exc
    return value


def read_dotenv_values(path: str) -> Dict[str, str]:
    """读取 CLI 密钥参数使用的 ``KEY=value`` 子集。

    双引号值遵循项目 ``.env`` 约定，按 JSON 字符串解析，因此引号、反斜杠和
    Unicode 转义不会被静默改写；单引号只做成对去壳，未加引号的值去除首尾空白。
    """
    env_path = Path(path).expanduser()
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CliError(
            f"Cannot read env file: {env_path}: {exc.strerror or exc}"
        ) from exc
    values: Dict[str, str] = {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        if not key:
            continue
        raw_value = value.strip()
        if raw_value.startswith('"'):
            try:
                parsed = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                raise CliError(
                    f"Invalid JSON string for {key} in {env_path}: {exc}"
                ) from exc
            if not isinstance(parsed, str):
                raise CliError(
                    f"Expected a JSON string for {key} in {env_path}."
                )
            values[key] = parsed
        elif (
            len(raw_value) >= 2
            and raw_value.startswith("'")
            and raw_value.endswith("'")
        ):
            values[key] = raw_value[1:-1]
        else:
            values[key] = raw_value
    return values


def read_env_secret(name: str, env_file: Optional[str] = None) -> str:
    """Resolve one non-empty secret from an optional dotenv file, then the process."""
    key_name = (name or "").strip()
    if not key_name:
        raise CliError("Missing environment variable name.")
    if env_file:
        value = read_dotenv_values(env_file).get(key_name, "").strip()
        if value:
            return value
    value = os.environ.get(key_name, "").strip()
    if value:
        return value
    source = f" in {env_file}" if env_file else ""
    raise CliError(f"Environment variable {key_name}{source} is empty or not set.")


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


REDUNDANT_JSON_KEYS = {
    "all_competitions",
    "all_problems",
    "api_url",
    "api_urls",
    "csrf",
    "csrf_token",
    "current_user",
    "daily_counts",
    "debug",
    "html",
    "location_href",
    "matched_usernames_text",
    "page_numbers",
    "params",
    "rendered_content",
    "rendered_description",
    "request",
    "session",
    "stack",
    "status_code",
    "template",
    "trace",
    "traceback",
    "user",
    "view",
}


def necessary_response_payload(payload: Any) -> Any:
    """Drop page-only and debug fields from generic JSON responses."""
    if isinstance(payload, dict):
        out: Dict[str, Any] = {}
        for key, value in payload.items():
            if key in REDUNDANT_JSON_KEYS:
                continue
            out[key] = necessary_response_payload(value)
        return out
    if isinstance(payload, list):
        return [necessary_response_payload(item) for item in payload]
    return payload


def _failure_payload(payload: Any, *, http_status: Optional[int] = None, message: Optional[str] = None) -> Dict[str, Any]:
    if isinstance(payload, dict):
        out = dict(payload)
    else:
        out = {"response": payload}
    out["success"] = False
    if http_status is not None:
        out.setdefault("http_status", http_status)
    if out.get("ok") is False:
        out.pop("ok", None)
    if "message" not in out:
        if "error" in out and out.get("error"):
            out["message"] = str(out["error"])
        elif message:
            out["message"] = message
        elif http_status is not None:
            out["message"] = f"HTTP {http_status}"
        else:
            out["message"] = "Operation failed."
    return out


def raise_for_failure_payload(payload: Any, *, http_status: Optional[int] = None) -> None:
    if not isinstance(payload, dict):
        return
    if payload.get("success") is False or payload.get("ok") is False:
        raise CliHttpError(http_status or 1, _failure_payload(payload, http_status=http_status))


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
        self.session.headers.update({"User-Agent": "numoj-cli/0.1", "Accept": "application/json"})
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
    if 300 <= resp.status_code < 400:
        if allow_redirect:
            return
        payload = redirect_response_payload(resp)
        payload["success"] = False
        payload.setdefault("http_status", resp.status_code)
        payload.setdefault("message", "The server redirected instead of returning the requested JSON response.")
        raise CliHttpError(resp.status_code, payload)
    if resp.status_code < 400:
        return
    if response_is_json(resp):
        try:
            payload = resp.json()
        except ValueError:
            payload = None
        if payload is not None:
            projected = necessary_response_payload(payload)
            if isinstance(projected, dict):
                projected = _failure_payload(projected, http_status=resp.status_code)
            else:
                projected = {"success": False, "http_status": resp.status_code, "response": projected}
            raise CliHttpError(resp.status_code, projected)
    body = resp.text[:1000].strip()
    lowered_body = body[:300].lower()
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in content_type or lowered_body.startswith("<!doctype") or "<html" in lowered_body:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        if title_match:
            body = re.sub(r"\s+", " ", title_match.group(1)).strip()
        else:
            body = ""
    payload = {
        "success": False,
        "http_status": resp.status_code,
        "message": body or getattr(resp, "reason", "") or f"HTTP {resp.status_code}",
    }
    raise CliHttpError(resp.status_code, payload)


def print_or_save_response(
    resp: requests.Response,
    *,
    output: Optional[str] = None,
    allow_redirect: bool = True,
    project_json: bool = True,
    fail_on_business_error: bool = True,
) -> None:
    ensure_ok(resp, allow_redirect=allow_redirect)

    if 300 <= resp.status_code < 400:
        payload = redirect_response_payload(resp)
        if output is not None:
            raise CliHttpError(
                resp.status_code,
                _failure_payload(
                    payload,
                    http_status=resp.status_code,
                    message="The server redirected instead of returning a downloadable file.",
                ),
            )
        if fail_on_business_error:
            raise_for_failure_payload(payload, http_status=resp.status_code)
        output_json(payload)
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
            payload = resp.json()
            projected = necessary_response_payload(payload) if project_json else payload
            if fail_on_business_error:
                raise_for_failure_payload(projected, http_status=resp.status_code)
            output_json(projected)
        except ValueError:
            print(resp.text)
        return

    text = resp.text.strip()
    if text:
        print(text)
    else:
        output_json({"success": True})


def _is_login_redirect(location: str) -> bool:
    return bool(re.search(r"(^|/)login(?:[/?#]|$)", location or ""))


def redirect_response_payload(
    resp: requests.Response,
    *,
    id_pattern: Optional[str] = None,
    id_name: str = "id",
    allow_login_redirect: bool = False,
) -> Dict[str, Any]:
    ensure_ok(resp)
    location = resp.headers.get("Location", "")
    redirected = 300 <= resp.status_code < 400
    if not redirected:
        if response_is_json(resp):
            payload = resp.json()
            if isinstance(payload, dict):
                projected = necessary_response_payload(payload)
                return projected if isinstance(projected, dict) else {"success": False, "response": projected}
            return {"success": False, "response": necessary_response_payload(payload)}
        return {
            "success": False,
            "message": "The server returned a form page instead of a success redirect; the operation was not completed.",
        }
    payload: Dict[str, Any] = {"success": True}
    if _is_login_redirect(location) and not allow_login_redirect:
        return {
            "success": False,
            "http_status": resp.status_code,
            "location": location,
            "message": "The server redirected to the login page; authenticate before running this command.",
        }
    if id_pattern and location:
        match = re.search(id_pattern, location)
        if match:
            payload[id_name] = int(match.group(1))
        else:
            payload["success"] = False
            payload["http_status"] = resp.status_code
            if location:
                payload["location"] = location
            payload["message"] = f"The server redirect succeeded, but {id_name} could not be parsed from the Location header."
    elif location:
        payload["location"] = location
    return payload


def print_redirect_response(
    resp: requests.Response,
    *,
    id_pattern: Optional[str] = None,
    id_name: str = "id",
    allow_login_redirect: bool = False,
) -> None:
    payload = redirect_response_payload(
        resp,
        id_pattern=id_pattern,
        id_name=id_name,
        allow_login_redirect=allow_login_redirect,
    )
    raise_for_failure_payload(payload, http_status=resp.status_code)
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
    event_payloads: List[Any] = []
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
                    event_payloads.append(json.loads(text))
                except ValueError:
                    event_payloads.append(text)
        if len(lines) >= max_lines:
            break
    return {
        "success": True,
        "lines_read": len(lines),
        "events": event_payloads,
        "truncated": len(lines) >= max_lines,
    }


def read_code_arg(args: argparse.Namespace) -> str:
    if getattr(args, "code_file", None):
        path = Path(args.code_file).expanduser()
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CliError(f"Cannot read file: {path}: {exc.strerror or exc}") from exc
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


def add_common_http_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH, help="Path to the local CLI config file containing the saved server URL and session cookie.")
    parser.add_argument("--base-url", help="Override the server URL saved in the config file for this command.")
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP request timeout in seconds.")


def add_text_arg(parser: argparse.ArgumentParser, name: str, **kwargs: Any) -> None:
    parser.add_argument(name, **kwargs)


def add_cli_parser(subparsers: argparse._SubParsersAction, name: str, description: str, **kwargs: Any) -> argparse.ArgumentParser:
    kwargs.setdefault("help", description)
    kwargs.setdefault("description", description)
    kwargs.setdefault("formatter_class", HELP_FORMATTER)
    return subparsers.add_parser(name, **kwargs)


def output_projected_json_response(resp: requests.Response, projector, *, allow_redirect: bool = False) -> None:
    ensure_ok(resp, allow_redirect=allow_redirect)
    if 300 <= resp.status_code < 400:
        payload = redirect_response_payload(resp)
        raise_for_failure_payload(payload, http_status=resp.status_code)
        output_json(payload)
        return
    if response_is_json(resp):
        payload = necessary_response_payload(projector(resp.json()))
        raise_for_failure_payload(payload, http_status=resp.status_code)
        output_json(payload)
        return
    print(resp.text.strip())
