# -*- coding: utf-8 -*-
"""Shared helpers for local CLI-driven end-to-end tests.

The e2e suite is intentionally local-only. It starts a Flask subprocess bound to
127.0.0.1 and drives the public CLI scripts through real HTTP routes. The
fixtures below refuse known production targets before any service is started.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import pytest


ROOT = Path(__file__).resolve().parents[2]
ADMIN_CLI = ROOT / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py"
USER_CLI = ROOT / "skills" / "numoj-user" / "scripts" / "numoj_user.py"
BASE_URL = "http://127.0.0.1:2025"
QUALITY_GATE_STUB_PORT = 19101


class _QualityGateStubHandler(BaseHTTPRequestHandler):
    """仅用于 e2e：强制每次正式审核前先完成一次 hello。"""

    protocol_version = "HTTP/1.1"
    hello_count: dict[str, int] = {}
    review_count: dict[str, int] = {}
    recovery_healthy = False

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _reply(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._reply(400, {"error": "invalid json"})
            return
        api_key = self.headers.get("x-api-key") or ""
        allowed_models = {
            "quality-pool-secret": "fake-quality-model",
            "recovering-quality-secret": "recovering-quality-model",
        }
        if (self.path != "/v1/messages"
                or allowed_models.get(api_key) != payload.get("model")):
            self._reply(401, {"error": "wrong endpoint configuration"})
            return
        messages = payload.get("messages") or []
        last_content = messages[-1].get("content") if messages and isinstance(messages[-1], dict) else ""
        if last_content == "hello" and not payload.get("system"):
            if api_key == "recovering-quality-secret" and not type(self).recovery_healthy:
                self._reply(503, {"error": "temporarily unhealthy"})
                return
            type(self).hello_count[api_key] = type(self).hello_count.get(api_key, 0) + 1
            self._reply(200, {"content": [{"type": "text", "text": "hello"}]})
            return
        if type(self).hello_count.get(api_key, 0) <= type(self).review_count.get(api_key, 0):
            self._reply(409, {"error": "hello required before review"})
            return
        type(self).review_count[api_key] = type(self).review_count.get(api_key, 0) + 1
        package_text = str(last_content or "")
        rejected = "quality_gate_reject.txt" in package_text
        result = {
            "passed": not rejected,
            "summary": (
                "命中私有审核标准：solution 和 judge 不得隐藏私有配对密码"
                if rejected else "题目包通过质量审核"
            ),
            "violations": ([{
                "rule": "solution 和 judge 不得隐藏私有配对密码",
                "reason": "发现测试用违规标记",
                "evidence": [{
                    "path": "quality_gate_reject.txt",
                    "line": 1,
                    "excerpt": "fake gate rejection marker",
                }],
            }] if rejected else []),
        }
        self._reply(200, {
            "content": [{
                "type": "text",
                "text": json.dumps(result, ensure_ascii=False),
            }],
        })


def _start_quality_gate_stub() -> tuple[ThreadingHTTPServer, threading.Thread]:
    _QualityGateStubHandler.hello_count = {}
    _QualityGateStubHandler.review_count = {}
    _QualityGateStubHandler.recovery_healthy = False
    try:
        server = ThreadingHTTPServer(
            ("127.0.0.1", QUALITY_GATE_STUB_PORT),
            _QualityGateStubHandler,
        )
    except OSError as exc:
        pytest.fail(f"Could not start quality-gate e2e stub: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def set_quality_gate_stub_recovery_healthy(healthy: bool) -> None:
    _QualityGateStubHandler.recovery_healthy = bool(healthy)


def judger_image_name() -> str:
    env_value = os.environ.get("JUDGER_DOCKER_IMAGE")
    if env_value:
        return env_value
    try:
        import config
        return getattr(config, "JUDGER_DOCKER_IMAGE", "numericaloj-judger:latest")
    except Exception:
        return "numericaloj-judger:latest"


def require_docker_judger_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI is not available for sandbox judging e2e.")
    image = judger_image_name()
    try:
        subprocess.run(
            ["docker", "image", "inspect", image],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"Docker judger image {image} is not available.")


def _assert_disposable_environment() -> None:
    import config

    hostname = socket.gethostname()
    if hostname == "computing":
        pytest.fail("Refusing to run CLI e2e tests on production host 'computing'.")

    mysql_host = str(getattr(config, "MYSQL_HOST", "127.0.0.1") or "127.0.0.1").strip().lower()
    redis_host = str(getattr(config, "REDIS_HOST", "127.0.0.1") or "127.0.0.1").strip().lower()
    allowed_hosts = {"127.0.0.1", "localhost", "mysql", "redis"}
    if mysql_host not in allowed_hosts:
        pytest.fail(f"Refusing to run CLI e2e tests against MYSQL_HOST={mysql_host!r}.")
    if redis_host not in allowed_hosts:
        pytest.fail(f"Refusing to run CLI e2e tests against REDIS_HOST={redis_host!r}.")


def _assert_port_free(host: str = "127.0.0.1", port: int = 2025) -> None:
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
    except OSError:
        return
    finally:
        sock.close()
    pytest.fail(f"Refusing to run CLI e2e tests: {host}:{port} is already in use.")


def _wait_for_http(proc: subprocess.Popen[str], url: str, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    last_error: Any = None
    while time.time() < deadline:
        if proc.poll() is not None:
            output = ""
            if proc.stdout is not None:
                output = proc.stdout.read()
            pytest.fail(f"Local Flask server exited early with {proc.returncode}:\n{output}")
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = exc
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.5)
    pytest.fail(f"Local Flask server did not become ready: {last_error}")


def _terminate_process(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


@pytest.fixture
def local_numoj_server() -> str:
    _assert_disposable_environment()
    _assert_port_free()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["OJ_LIVE_AI"] = "0"
    env["NUMOJ_FAKE_AGENT_JUDGE"] = "1"
    env["NUMOJ_FAKE_AGENT_JUDGE_DELAY_SECONDS"] = "0"
    env["NUMOJ_FAKE_REVERSE_JUDGE"] = "1"
    # 端点 hello 仍走本地 HTTP 桩，只将需要真实模型 CLI 的门禁
    # Agent 替换为确定性实现；容器安全边界由单元测独立覆盖。
    env["NUMOJ_FAKE_REVERSE_QUALITY_GATE"] = "1"
    env["NUMOJ_FAKE_PROGRAM_IMAGE_GRADING_RESULT"] = '{"score": 1, "comment": "本地 e2e 假图片批改通过。"}'
    env["NUMOJ_FAKE_WRITTEN_HOMEWORK_SCORE"] = "5"
    env["NUMOJ_FAKE_WRITTEN_HOMEWORK_COMMENT"] = "本地 e2e 假书面批改通过。"
    env["NUMOJ_FAKE_PROMPTLY_REVIEW_REQUIRED_TERMS"] = '["monotonic deque", "expired index"]'
    env["NUMOJ_FAKE_PROMPTLY_REVIEW_REPLY"] = "Please explain the monotonic deque and expired index handling."
    env["NUMOJ_FAKE_PROMPTLY_CODE"] = "print('hello')\n"
    quality_gate_server, quality_gate_thread = _start_quality_gate_stub()
    web_proc = subprocess.Popen(
        [sys.executable, "-B", "oj.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    celery_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "celery",
            "-A",
            "oj.celery",
            "worker",
            "--loglevel=warning",
            "-Q",
            "celery,agent,judge",
            "--pool=solo",
            "--concurrency=1",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_http(web_proc, f"{BASE_URL}/login")
        if celery_proc.poll() is not None:
            output = ""
            if celery_proc.stdout is not None:
                output = celery_proc.stdout.read()
            pytest.fail(f"Local Celery worker exited early with {celery_proc.returncode}:\n{output}")
        yield BASE_URL
    finally:
        _terminate_process(celery_proc)
        _terminate_process(web_proc)
        quality_gate_server.shutdown()
        quality_gate_server.server_close()
        quality_gate_thread.join(timeout=5)


class CliResult:
    def __init__(self, completed: subprocess.CompletedProcess[str]):
        self.returncode = completed.returncode
        self.stdout = completed.stdout
        self.stderr = completed.stderr

    @property
    def text(self) -> str:
        return self.stdout.strip()

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"CLI did not return JSON:\n{self.text}") from exc


class CliRunner:
    def __init__(self, base_url: str, tmp_path: Path):
        self.base_url = base_url
        self.tmp_path = tmp_path
        self.admin_config = tmp_path / "admin.json"
        self.user_config = tmp_path / "user.json"

    def run(
        self,
        script: Path,
        config_path: Optional[Path],
        *args: str,
        timeout: float = 60.0,
        check: bool = True,
    ) -> CliResult:
        cmd = [sys.executable, str(script)]
        if config_path is not None:
            cmd.extend(["--config", str(config_path)])
        cmd.extend(map(str, args))
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        result = CliResult(completed)
        if check and result.returncode != 0:
            pytest.fail(
                "CLI command failed\n"
                f"cmd: {' '.join(cmd)}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
        return result

    def admin(self, *args: str, **kwargs: Any) -> CliResult:
        return self.run(ADMIN_CLI, self.admin_config, *args, **kwargs)

    def user(self, *args: str, **kwargs: Any) -> CliResult:
        return self.run(USER_CLI, self.user_config, *args, **kwargs)

    def admin_json(self, *args: str, **kwargs: Any) -> Any:
        return self.admin(*args, **kwargs).json()

    def user_json(self, *args: str, **kwargs: Any) -> Any:
        return self.user(*args, **kwargs).json()

    def init_admin(self, username: str = "admin", password: str = "admin123") -> Any:
        return self.admin_json(
            "init",
            "--base-url",
            self.base_url,
            "-u",
            username,
            "-p",
            password,
        )

    def init_user(self, username: str, password: str = "pw123456") -> Any:
        return self.user_json(
            "init",
            "--base-url",
            self.base_url,
            "-u",
            username,
            "-p",
            password,
        )


@pytest.fixture
def cli(local_numoj_server: str, tmp_path: Path) -> CliRunner:
    return CliRunner(local_numoj_server, tmp_path)


@pytest.fixture
def unique_suffix() -> str:
    return str(int(time.time() * 1000))


def create_regular_user(username: str, password: str = "pw123456", email: Optional[str] = None) -> dict[str, Any]:
    from tests.helpers import make_user

    return make_user(username=username, password=password, email=email or f"{username}@example.com")


def get_user_id(username: str) -> int:
    from oj_modules import db_services

    user = db_services.get_user_by_username(username)
    if not user:
        pytest.fail(f"User {username!r} was not found in local test DB.")
    return int(user["id"])


def seed_verification_code(email: str, code: str = "123456") -> str:
    from oj_modules import db_services

    expires_at = datetime.now() + timedelta(minutes=10)
    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "REPLACE INTO verification_codes (email, code, expires_at) VALUES (%s, %s, %s)",
                (email, code, expires_at),
            )
        conn.commit()
    finally:
        conn.close()
    return code


def find_problem_id(problem_list_payload: dict[str, Any], title: str) -> int:
    for row in problem_list_payload.get("problems") or []:
        if title in str(row.get("title") or ""):
            return int(row["id"])
    pytest.fail(f"Created problem {title!r} was not visible through problem list: {problem_list_payload}")


def find_repository_file_id(files_payload: dict[str, Any], filename: str) -> int:
    for row in files_payload.get("files") or []:
        if row.get("filename") == filename:
            return int(row["id"])
    pytest.fail(f"Repository file {filename!r} was not visible through repository files: {files_payload}")


def ranking_id_from_create(payload: dict[str, Any]) -> int:
    match = re.search(r"/ranking/(\d+)/", str(payload.get("location") or ""))
    if not match:
        pytest.fail(f"Could not parse ranking id from create response: {payload}")
    return int(match.group(1))


def get_ranking_appeal_id(submission_id: int) -> int:
    from oj_modules import db_services

    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM ranking_appeals WHERE submission_id=%s ORDER BY id DESC LIMIT 1",
                (int(submission_id),),
            )
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        pytest.fail(f"Ranking appeal for submission {submission_id} was not found.")
    return int(row["id"])


def count_ranking_endpoints(competition_id: int) -> int:
    """仅供删除比赛 e2e 断言：确认含密钥的端点行没有成为孤儿。"""
    from oj_modules import db_services

    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM ranking_agent_judge_endpoints "
                "WHERE competition_id=%s",
                (int(competition_id),),
            )
            row = cur.fetchone() or {}
    finally:
        conn.close()
    return int(row.get("n") or 0)


def thread_id_from_create(payload: dict[str, Any]) -> int:
    match = re.search(r"/forum/thread/(\d+)", str(payload.get("location") or ""))
    if not match:
        pytest.fail(f"Could not parse forum thread id from response: {payload}")
    return int(match.group(1))


def find_forum_thread_id(cli: CliRunner, title: str, *, admin: bool = False) -> int:
    from oj_modules import db_services

    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM forum_threads WHERE title=%s ORDER BY id DESC LIMIT 1", (title,))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        pytest.fail(f"Forum thread {title!r} was not found.")
    return int(row["id"])


def find_homework_id(homework_payload: dict[str, Any], title: str) -> str:
    for row in homework_payload.get("homeworks") or []:
        if title in str(row.get("title") or ""):
            homework_id = row.get("homework_id")
            if homework_id:
                return str(homework_id)
    pytest.fail(f"Homework {title!r} was not visible through homework list: {homework_payload}")


def create_problem(
    cli: CliRunner,
    title: str,
    *,
    problem_type: str = "1",
    lang: str = "python",
    submission_limit: int = 10,
    content: str = "Created by CLI e2e.",
    extra: Optional[list[str]] = None,
) -> int:
    args = [
        "problem",
        "create",
        "--title",
        title,
        "--content",
        content,
        "--type",
        problem_type,
        "--lang",
        lang,
        "--time-limit-ms",
        "1000",
        "--submission-limit",
        str(submission_limit),
    ]
    if extra:
        args.extend(extra)
    assert cli.admin_json(*args)["success"] is True
    return find_problem_id(cli.admin_json("problem", "list", "--limit", "100"), title)


def add_problem_homework(cli: CliRunner, problem_id: int, title: str, class_en: str = "Cclass1") -> str:
    assert cli.admin_json(
        "homework",
        "add",
        "--class-en",
        class_en,
        "--problem-id",
        str(problem_id),
        "--ddl",
        "2099-01-01T00:00",
    )["success"] is True
    return find_homework_id(cli.admin_json("homework", "list", "--class-en", class_en), title)


def create_problem_with_homework(
    cli: CliRunner,
    title: str,
    *,
    submission_limit: int = 10,
    class_en: str = "Cclass1",
    extra: Optional[list[str]] = None,
) -> tuple[int, str]:
    problem_id = create_problem(cli, title, submission_limit=submission_limit, extra=extra)
    homework_id = add_problem_homework(cli, problem_id, title, class_en=class_en)
    return problem_id, homework_id


def write_zip(path: Path, files: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return path


def write_testdata_zip(path: Path) -> Path:
    return write_zip(path, {"1.in": "", "1.out": "hello"})


def assert_no_json_leaks(payload: Any, *, forbidden_keys: set[str], forbidden_terms: tuple[str, ...] = ()) -> None:
    key_hits: list[str] = []
    term_hits: list[str] = []

    def walk(value: Any, path: str = "$") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key in forbidden_keys:
                    key_hits.append(child_path)
                walk(child, child_path)
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, f"{path}[{idx}]")
        elif isinstance(value, str):
            for term in forbidden_terms:
                if term in value:
                    term_hits.append(f"{path}: {term}")

    walk(payload)
    assert not key_hits, f"Forbidden JSON keys leaked: {key_hits}"
    assert not term_hits, f"Forbidden JSON terms leaked: {term_hits}"


def create_local_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    subprocess.run(["git", "config", "user.email", "cli-e2e@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "CLI E2E"], cwd=path, check=True)
    (path / "README.md").write_text("cli e2e\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=path, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return path


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text)
