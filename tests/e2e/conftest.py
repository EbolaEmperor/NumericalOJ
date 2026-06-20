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
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import pytest


ROOT = Path(__file__).resolve().parents[2]
ADMIN_CLI = ROOT / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py"
USER_CLI = ROOT / "skills" / "numoj-user" / "scripts" / "numoj_user.py"
BASE_URL = "http://127.0.0.1:2025"


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


@pytest.fixture
def local_numoj_server() -> str:
    _assert_disposable_environment()
    _assert_port_free()
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["OJ_LIVE_AI"] = "0"
    env["NUMOJ_FAKE_AGENT_JUDGE"] = "1"
    env["NUMOJ_FAKE_AGENT_JUDGE_DELAY_SECONDS"] = "3600"
    proc = subprocess.Popen(
        [sys.executable, "-B", "oj.py"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_http(proc, f"{BASE_URL}/login")
        yield BASE_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


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
) -> tuple[int, str]:
    problem_id = create_problem(cli, title, submission_limit=submission_limit)
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
