# -*- coding: utf-8 -*-
"""Every public CLI command exposes help text."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import subprocess
import sys
import threading

import pytest

from tests.e2e.conftest import ADMIN_CLI, ROOT, USER_CLI, normalize_ws


USER_COMMAND_PATHS = [
    [],
    ["init"],
    ["auth"],
    ["auth", "login"],
    ["auth", "logout"],
    ["auth", "status"],
    ["auth", "send-password-code"],
    ["auth", "change-password"],
    ["me"],
    ["me", "classes"],
    ["me", "join-class"],
    ["me", "leave-class"],
    ["me", "submissions"],
    ["me", "grades"],
    ["problem"],
    ["problem", "list"],
    ["problem", "detail"],
    ["problem", "submit-page"],
    ["problem", "submit"],
    ["submission"],
    ["submission", "list"],
    ["submission", "problem"],
    ["submission", "status"],
    ["submission", "stream"],
    ["submission", "detail"],
    ["submission", "last-code"],
    ["submission", "output-image"],
    ["forum"],
    ["forum", "list"],
    ["forum", "thread"],
    ["forum", "new-page"],
    ["forum", "new"],
    ["forum", "reply"],
    ["forum", "reply-thread"],
    ["repository"],
    ["repository", "page"],
    ["repository", "files"],
    ["repository", "get"],
    ["repository", "save"],
    ["repository", "delete"],
    ["repository", "upload"],
    ["repository", "build-index"],
    ["repository", "rebuild-file"],
    ["repository", "index-status"],
    ["repository", "active-status"],
    ["repository", "search"],
    ["repository", "classes"],
    ["ai"],
    ["ai", "marks"],
    ["ranking"],
    ["ranking", "list"],
    ["ranking", "detail"],
    ["ranking", "matches"],
    ["ranking", "match-detail"],
    ["ranking", "submit"],
    ["ranking", "git"],
    ["ranking", "my-submissions"],
    ["ranking", "leaderboard"],
    ["ranking", "download-submission"],
    ["ranking", "judge-stream"],
    ["ranking", "reverse-stream"],
    ["ranking", "appeal"],
    ["ranking", "appeal-status"],
]


ADMIN_EXTRA_COMMAND_PATHS = [
    ["site-config"],
    ["site-config", "meta"],
    ["site-config", "llm"],
    ["site-config", "llm", "list"],
    ["site-config", "llm", "test"],
    ["site-config", "llm", "create"],
    ["site-config", "llm", "update"],
    ["site-config", "llm", "delete"],
    ["site-config", "llm", "lock"],
    ["site-config", "llm", "unlock"],
    ["site-config", "binding"],
    ["site-config", "binding", "list"],
    ["site-config", "binding", "set"],
    ["site-config", "binding", "lock-embedding"],
    ["site-config", "binding", "unlock-embedding"],
    ["site-config", "mail"],
    ["site-config", "mail", "get"],
    ["site-config", "mail", "test"],
    ["site-config", "mail", "set"],
    ["site-config", "mail", "clear"],
    ["site-config", "web-search"],
    ["site-config", "web-search", "get"],
    ["site-config", "web-search", "test"],
    ["site-config", "web-search", "set"],
    ["site-config", "web-search", "clear"],
    ["ai-detection"],
    ["ai-detection", "dashboard"],
    ["ai-detection", "problem-page"],
    ["ai-detection", "student-page"],
    ["ai-detection", "preview"],
    ["ai-detection", "run-filtered"],
    ["ai-detection", "run-problem"],
    ["ai-detection", "run-single"],
    ["ai-detection", "run-user"],
    ["ai-detection", "summary"],
    ["ai-detection", "tasks"],
    ["ai-detection", "models"],
    ["ai-detection", "task"],
    ["problem", "create-form"],
    ["problem", "create"],
    ["problem", "edit-form"],
    ["problem", "edit"],
    ["problem", "delete"],
    ["problem", "upload-testdata"],
    ["problem", "rejudge"],
    ["problem", "rejudge-status"],
    ["problem", "rejudge-time-range"],
    ["problem", "rejudge-time-range-status"],
    ["problem", "agent-run-status"],
    ["problem", "agent-run"],
    ["problem", "agent-run-stream"],
    ["problem", "agent-tasks"],
    ["problem", "agent-solve"],
    ["problem", "agent-generate-data"],
    ["problem", "scores"],
    ["homework"],
    ["homework", "list"],
    ["homework", "add"],
    ["homework", "update-ddl"],
    ["homework", "delete"],
    ["homework", "export-scores"],
    ["homework", "export-codes"],
    ["homework", "export-progress"],
    ["homework", "download-export"],
    ["homework", "plagiarism-start"],
    ["homework", "plagiarism-progress"],
    ["homework", "plagiarism-records"],
    ["homework", "plagiarism-download"],
    ["homework", "plagiarism-delete"],
    ["homework", "upload-exam"],
    ["homework", "class-adjust"],
    ["user"],
    ["user", "list"],
    ["user", "add-class-type"],
    ["user", "grant-admin"],
    ["user", "rename"],
    ["user", "add-to-class"],
    ["user", "remove-from-class"],
    ["user", "grades"],
    ["user", "update-grade"],
    ["grading"],
    ["grading", "submit"],
    ["grading", "next-pending"],
    ["grading", "invalidate-invalid"],
    ["submission", "download-file"],
    ["ranking", "create"],
    ["ranking", "copy"],
    ["ranking", "edit"],
    ["ranking", "delete"],
    ["ranking", "upload-attachment"],
    ["ranking", "delete-attachment"],
    ["ranking", "download-attachment"],
    ["ranking", "upload-reference"],
    ["ranking", "upload-script"],
    ["ranking", "clear-script"],
    ["ranking", "reset-limit"],
    ["ranking", "save-config"],
    ["ranking", "save-rules"],
    ["ranking", "save-endpoints"],
    ["ranking", "save-endpoint"],
    ["ranking", "save-quality-gate"],
    ["ranking", "save-quality-gate-endpoints"],
    ["ranking", "save-quality-gate-endpoint"],
    ["ranking", "batch-probe"],
    ["ranking", "batch-status"],
    ["ranking", "batch-create"],
    ["ranking", "bulk-filter"],
    ["ranking", "bulk-start"],
    ["ranking", "bulk-status"],
    ["ranking", "rejudge-agent"],
    ["ranking", "appeals"],
    ["ranking", "appeal-review"],
    ["ranking", "appeal-handle"],
    ["ranking", "elo-start"],
    ["ranking", "elo-stop"],
    ["ranking", "elo-reset"],
    ["ranking", "elo-delete-match"],
    ["ranking", "elo-rebuild"],
    ["ranking", "delete-submission"],
    ["ranking", "submissions"],
    ["ranking", "submit-zip"],
]


ADMIN_COMMAND_PATHS = USER_COMMAND_PATHS + ADMIN_EXTRA_COMMAND_PATHS


@pytest.mark.e2e
@pytest.mark.parametrize(
    ("script", "paths"),
    [(USER_CLI, USER_COMMAND_PATHS), (ADMIN_CLI, ADMIN_COMMAND_PATHS)],
)
def test_every_cli_command_has_help(script, paths):
    for path in paths:
        cmd = [sys.executable, str(script), *path, "--help"]
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0, f"{' '.join(cmd)}\n{completed.stderr}"
        assert "usage:" in completed.stdout


@pytest.mark.e2e
def test_admin_problem_agent_help_only_exposes_current_launch_contract():
    """Agent CLI 只暴露 Harness 启动参数，不再接受旧自建循环参数。"""

    help_by_command = {}
    for command in ("agent-solve", "agent-generate-data"):
        completed = subprocess.run(
            [sys.executable, str(ADMIN_CLI), "problem", command, "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0, completed.stderr
        help_by_command[command] = completed.stdout

    for help_text in help_by_command.values():
        assert "--harness {claude_code,codex,opencode,pi}" in help_text
        assert "--endpoint-id" in help_text
        assert "--extra-prompt" not in help_text
        assert "--standard-code" not in help_text
        assert "--max-rounds" not in help_text
        assert "--summary-endpoint-id" not in help_text

    solve_help = help_by_command["agent-solve"]
    assert "--count" not in solve_help
    assert "--data-requirement" not in solve_help
    assert "--standard-solution" not in solve_help

    generate_help = help_by_command["agent-generate-data"]
    assert "--count" in generate_help
    assert "--data-requirement" in generate_help
    assert "--standard-solution" in generate_help


@pytest.mark.e2e
def test_admin_problem_agent_commands_send_current_launch_contract(tmp_path):
    """真实 CLI 子进程必须按当前 Agent 路由契约发送两类启动请求。"""

    requests = []

    class CaptureHandler(BaseHTTPRequestHandler):
        def log_message(self, _format, *args):
            return

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            requests.append({
                "path": self.path,
                "content_type": self.headers.get("Content-Type") or "",
                "cookie": self.headers.get("Cookie") or "",
                "body": body,
            })
            payload = json.dumps({
                "success": True,
                "task_id": f"agent-task-{len(requests)}",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    except OSError as exc:
        pytest.skip(f"当前环境不能监听 loopback：{exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    config_path = tmp_path / "numoj-admin.json"
    config_path.write_text(
        json.dumps({
            "base_url": f"http://127.0.0.1:{server.server_port}",
            "cookies": {"session": "agent-cli-e2e-session"},
        }),
        encoding="utf-8",
    )
    standard_solution = tmp_path / "reference.py"
    standard_source = "print('reference answer')\n"
    standard_solution.write_text(standard_source, encoding="utf-8")

    def run_agent_command(*args):
        completed = subprocess.run(
            [
                sys.executable,
                str(ADMIN_CLI),
                "--config",
                str(config_path),
                *args,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0, completed.stderr
        return json.loads(completed.stdout)

    try:
        solve = run_agent_command(
            "problem",
            "agent-solve",
            "19",
            "--harness",
            "codex",
            "--endpoint-id",
            "41",
        )
        generate = run_agent_command(
            "problem",
            "agent-generate-data",
            "19",
            "--harness",
            "pi",
            "--endpoint-id",
            "42",
            "--count",
            "7",
            "--data-requirement",
            "覆盖边界与压力场景",
            "--standard-solution",
            str(standard_solution),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert solve == {"success": True, "task_id": "agent-task-1"}
    assert generate == {"success": True, "task_id": "agent-task-2"}
    assert len(requests) == 2

    solve_request = requests[0]
    assert solve_request["path"] == "/admin/agent_solve_problem/19"
    assert solve_request["content_type"].startswith("application/json")
    assert json.loads(solve_request["body"]) == {
        "harness": "codex",
        "endpoint_id": 41,
    }

    generate_request = requests[1]
    assert generate_request["path"] == "/admin/agent_generate_testdata/19"
    assert generate_request["content_type"].startswith("multipart/form-data;")
    message = BytesParser(policy=policy.default).parsebytes(
        (
            f"Content-Type: {generate_request['content_type']}\r\n"
            "MIME-Version: 1.0\r\n\r\n"
        ).encode("ascii")
        + generate_request["body"]
    )
    fields = {}
    files = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        value = part.get_payload(decode=True) or b""
        if filename is None:
            fields[name] = value.decode("utf-8")
        else:
            files[name] = {"filename": filename, "content": value}

    assert fields == {
        "harness": "pi",
        "endpoint_id": "42",
        "test_point_count": "7",
        "data_requirement": "覆盖边界与压力场景",
    }
    assert files == {
        "standard_solution": {
            "filename": "reference.py",
            "content": standard_source.encode("utf-8"),
        },
    }
    assert "session=agent-cli-e2e-session" in solve_request["cookie"]
    assert "session=agent-cli-e2e-session" in generate_request["cookie"]


@pytest.mark.e2e
def test_git_ranking_help_tells_users_to_check_first():
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ranking", "git", "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0
        assert "check first" in normalize_ws(completed.stdout)


@pytest.mark.e2e
@pytest.mark.parametrize("action", ["create", "edit"])
def test_admin_problem_help_explains_user_code_placeholder(action):
    completed = subprocess.run(
        [sys.executable, str(ADMIN_CLI), "problem", action, "--help"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    assert completed.returncode == 0
    help_text = normalize_ws(completed.stdout)
    assert "%%user_code_here" in help_text
    assert "student's submitted code is pasted at that marker" in help_text


@pytest.mark.e2e
def test_ai_marks_help_only_accepts_submission_id():
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ai", "marks", "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode == 0
        assert "--submission-id" in completed.stdout
        assert "--force-refresh" in completed.stdout
        assert "--problem-id" not in completed.stdout
        assert "--code" not in completed.stdout
        assert "--code-file" not in completed.stdout


@pytest.mark.e2e
@pytest.mark.parametrize("command", ["ask", "ac"])
def test_retired_ai_commands_are_unavailable(command):
    for script in (USER_CLI, ADMIN_CLI):
        completed = subprocess.run(
            [sys.executable, str(script), "ai", command, "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )
        assert completed.returncode != 0
