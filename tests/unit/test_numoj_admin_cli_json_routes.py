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


class _PayloadResponse:
    def __init__(self, payload, status_code=200):
        import json

        self._payload = payload
        self.status_code = status_code
        self.headers = {"Content-Type": "application/json"}
        self.text = json.dumps(payload, ensure_ascii=False)
        self.content = self.text.encode("utf-8")

    def json(self):
        return self._payload


class _SequenceClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        assert self.responses
        return self.responses.pop(0)


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


def test_homework_plagiarism_wait_tolerates_initial_missing_progress(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _SequenceClient([
        _PayloadResponse({"success": True, "task_id": "task-1"}),
        _PayloadResponse({"success": False, "message": "任务不存在或已过期"}, status_code=404),
        _PayloadResponse({
            "success": True,
            "progress": {
                "stage": "completed",
                "result": {"group_count": 1, "record_count": 2},
            },
        }),
    ])
    monkeypatch.setattr(cli, "client_from_args", lambda _args: fake_client)
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    cli.homework_plagiarism_start(Namespace(
        class_en="Cclass1",
        mode="byte",
        threshold=1,
        problem_ids="",
        targets="problem:1",
        wait=True,
        timeout=5,
        poll_interval=0.1,
    ))

    payload = cli.json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert payload["progress"]["stage"] == "completed"
    assert [request[1] for request in fake_client.requests] == [
        "/api/admin/homework/plagiarism/start",
        "/api/admin/homework/plagiarism/progress/task-1",
        "/api/admin/homework/plagiarism/progress/task-1",
    ]
