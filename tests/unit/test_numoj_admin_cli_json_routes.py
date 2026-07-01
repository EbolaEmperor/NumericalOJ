# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path


def _load_numoj_admin_cli_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py"
    spec = importlib.util.spec_from_file_location("numoj_admin_cli_json_routes", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    content = b'{"success":true}'
    text = '{"success":true}'

    def json(self):
        return {"success": True}


class _FakeClient:
    def __init__(self):
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        return _FakeResponse()


def test_numoj_admin_page_like_commands_use_json_api_without_output(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli, "client_from_args", lambda _args: fake_client)

    cases = [
        (cli.submission_detail_cmd, Namespace(submission_id=123), "/api/submissions/123"),
        (cli.problem_list, Namespace(limit=5), "/api/problems"),
        (cli.problem_detail, Namespace(problem_id=42), "/api/problems/42"),
        (cli.problem_submit_page, Namespace(problem_id=42), "/api/problems/42/submit-context"),
        (cli.problem_create_form, Namespace(), "/api/admin/problems/create-form"),
        (cli.problem_edit_form, Namespace(problem_id=42), "/api/admin/problems/42/edit-form"),
        (cli.problem_agent_run_page, Namespace(task_id="task-1"), "/admin/agent_run_status/task-1"),
        (cli.problem_agent_tasks, Namespace(), "/api/admin/agent-tasks"),
        (cli.forum_list, Namespace(), "/api/forum"),
        (cli.forum_thread, Namespace(thread_id=7), "/api/forum/threads/7"),
        (cli.forum_new_page, Namespace(), "/api/forum/new-context"),
        (cli.repository_page, Namespace(), "/api/repository/context"),
        (cli.ai_detection_page, Namespace(), "/api/admin/ai-detection/dashboard"),
        (cli.ai_detection_problem_page, Namespace(problem_id=42), "/api/admin/ai-detection/problem/42"),
        (cli.ai_detection_student_page, Namespace(username="alice"), "/api/admin/ai-detection/student/alice"),
        (cli.ranking_list, Namespace(limit=3), "/api/ranking/competitions"),
        (cli.ranking_detail, Namespace(competition_id=9, tab="leaderboard"), "/api/ranking/competitions/9"),
        (cli.ranking_appeal_review, Namespace(competition_id=9, appeal_id=11), "/api/ranking/competitions/9/appeals/11/review"),
    ]

    for func, args, expected_path in cases:
        func(args)
        assert fake_client.requests[-1][1] == expected_path


def test_numoj_admin_json_query_commands_do_not_accept_output_option():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    json_commands = [
        ("submission", "detail", "123"),
        ("problem", "list"),
        ("problem", "detail", "42"),
        ("problem", "submit-page", "42"),
        ("problem", "create-form"),
        ("problem", "edit-form", "42"),
        ("problem", "agent-run", "task-1"),
        ("problem", "agent-tasks"),
        ("forum", "list"),
        ("forum", "thread", "7"),
        ("forum", "new-page"),
        ("repository", "page"),
        ("ai-detection", "dashboard"),
        ("ai-detection", "problem-page", "42"),
        ("ai-detection", "student-page", "alice"),
        ("ranking", "list"),
        ("ranking", "detail", "9"),
        ("ranking", "appeal-review", "9", "11"),
    ]

    for command in json_commands:
        try:
            parser.parse_args([*command, "-o", "/tmp/out.json"])
        except SystemExit as exc:
            assert exc.code != 0
        else:
            raise AssertionError(f"{command} unexpectedly accepted -o")


def test_numoj_admin_download_commands_keep_output_option():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["submission", "output-image", "123", "0", "-o", "/tmp/out.bmp"])
    assert args.output == "/tmp/out.bmp"
