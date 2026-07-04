# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
from argparse import Namespace
from pathlib import Path


def _load_numoj_user_cli_module():
    root = Path(__file__).resolve().parents[2]
    path = root / "skills" / "numoj-user" / "scripts" / "numoj_user.py"
    spec = importlib.util.spec_from_file_location("numoj_user_cli_json_routes", path)
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


class _PayloadResponse(_FakeResponse):
    def __init__(self, payload):
        self._payload = payload
        self.text = "{}"
        self.content = b"{}"

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self):
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        return _FakeResponse()


def test_numoj_user_page_like_commands_use_json_api_without_output(monkeypatch):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cases = [
        (cli.submission_list, Namespace(page=1, limit=5), "/api/submissions"),
        (cli.submission_detail, Namespace(submission_id=123), "/api/submissions/123"),
        (cli.problem_list, Namespace(limit=5), "/api/problems"),
        (cli.problem_detail, Namespace(problem_id=42), "/api/problems/42"),
        (cli.problem_submit_page, Namespace(problem_id=42), "/api/problems/42/submit-context"),
        (cli.forum_list, Namespace(), "/api/forum"),
        (cli.forum_thread, Namespace(thread_id=7), "/api/forum/threads/7"),
        (cli.forum_new_page, Namespace(), "/api/forum/new-context"),
        (cli.repository_page, Namespace(), "/api/repository/context"),
        (cli.ranking_list, Namespace(limit=3), "/api/ranking/competitions"),
        (cli.ranking_detail, Namespace(competition_id=9, tab="leaderboard"), "/api/ranking/competitions/9"),
    ]

    for func, args, expected_path in cases:
        func(args)
        assert fake_client.requests[-1][1] == expected_path


def _problem_list_payload():
    return {
        "success": True,
        "problems": [{"id": 99, "title": "should be hidden"}],
        "homeworks": [
            {
                "complete_cnt": 0,
                "ddl": "2099-12-31 23:59:00",
                "has_submission": False,
                "id": 1,
                "is_completed": False,
                "kind": "problem",
                "max_score": None,
                "problem_id": 1,
                "problem_title": "滑动窗口极差",
                "total_score": 10,
            },
            {
                "complete_cnt": 0,
                "ddl": "2099-12-31 23:59:00",
                "has_submission": True,
                "id": 2,
                "is_completed": False,
                "kind": "problem",
                "max_score": 26,
                "problem_id": 2,
                "problem_title": "Slitherlink",
                "total_score": 137,
            },
        ],
    }


def test_problem_list_outputs_only_homeworks(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = _problem_list_payload()
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.problem_list(Namespace(limit=5))

    assert cli.json.loads(capsys.readouterr().out) == {"homeworks": payload["homeworks"]}


def _problem_detail_payload():
    return {
        "success": True,
        "problem": {
            "id": 42,
            "title": "Slitherlink",
            "content": "# Slitherlink\n\nSolve the puzzle.",
            "lang": "cpp",
            "max_score": 137,
            "rendered_content": "<p>hidden</p>",
            "submission_count": 1,
            "submission_limit": 5,
            "time_limit_ms": 1500,
            "type": 1,
            "user": {"username": "hidden"},
        },
        "initial_code": "int main() { return 0; }\n",
        "rendered_content": "<p>hidden</p>",
        "user": {"username": "alice"},
        "last_submissions": [
            {
                "id": 100,
                "score": 26,
                "status": "Wrong Answer",
                "submit_time": "2099-01-01 00:00:00",
            }
        ],
        "can_submit": True,
        "remaining_submissions": 4,
        "submit": {
            "accept": None,
            "action": "/submit/42",
            "help_text": "请提交 prompt。",
            "input_kind": "prompt",
            "input_name": "prompt",
            "method": "POST",
            "problem_type": 1,
            "programming_grading_mode": 3,
        },
    }


def test_problem_detail_outputs_necessary_user_facing_fields(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = _problem_detail_payload()
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.problem_detail(Namespace(problem_id=42))

    assert cli.json.loads(capsys.readouterr().out) == {
        "problem": {
            "id": 42,
            "title": "Slitherlink",
            "content": "# Slitherlink\n\nSolve the puzzle.",
            "lang": "cpp",
            "max_score": 137,
            "submission_count": 1,
            "submission_limit": 5,
            "time_limit_ms": 1500,
            "type": 1,
        },
        "initial_code": "int main() { return 0; }\n",
        "last_submissions": [
            {
                "id": 100,
                "score": 26,
                "status": "Wrong Answer",
                "submit_time": "2099-01-01 00:00:00",
            }
        ],
        "can_submit": True,
        "remaining_submissions": 4,
        "submit": {
            "help_text": "请提交 prompt。",
            "input_kind": "prompt",
        },
    }


def _submission_list_payload():
    return {
        "count": 1,
        "page": 1,
        "page_numbers": [1],
        "per_page": 20,
        "scope": "mine",
        "submission_ids": [2],
        "submissions": [
            {
                "created_at": "2026-06-29 17:23:29",
                "detail_url": "/submission_detail/2",
                "display_problem_title": "Slitherlink",
                "id": 2,
                "is_ac": False,
                "problem_title": "Slitherlink",
                "score": 26,
                "status": "Unaccepted",
                "username": "student1",
            }
        ],
        "success": True,
        "total_pages": 1,
        "user": {
            "class": "Cclass1",
            "class_cn": "测试班级",
            "email": "student1@example.com",
            "id": 2,
            "is_admin": 0,
            "username": "student1",
        },
    }


def test_submission_list_outputs_necessary_user_facing_fields(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = _submission_list_payload()
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.submission_list(Namespace(page=1, limit=None))

    assert cli.json.loads(capsys.readouterr().out) == {
        "count": 1,
        "page": 1,
        "per_page": 20,
        "total_pages": 1,
        "submissions": [
            {
                "id": 2,
                "created_at": "2026-06-29 17:23:29",
                "problem_title": "Slitherlink",
                "status": "Unaccepted",
                "score": 26,
                "is_ac": False,
            }
        ],
    }


def test_submission_problem_outputs_necessary_user_facing_fields(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "count": 1,
        "page": 1,
        "page_numbers": [1],
        "per_page": 30,
        "problem_id": 2,
        "submission_ids": [2],
        "submissions": [
            {
                "created_at": "2026-06-29 17:23:29",
                "detail_url": "/submission_detail/2",
                "display_problem_title": "Slitherlink",
                "id": 2,
                "is_ac": False,
                "problem_id": 2,
                "problem_title": "Slitherlink",
                "score": 26,
                "status": "Unaccepted",
                "username": "student1",
            }
        ],
        "success": True,
        "total_pages": 1,
        "user": {
            "class": "Cclass1",
            "class_cn": "测试班级",
            "email": "student1@example.com",
            "id": 2,
            "is_admin": 0,
            "username": "student1",
        },
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.submission_problem_list(Namespace(problem_id=2, page=1, limit=None))

    assert cli.json.loads(capsys.readouterr().out) == {
        "problem_id": 2,
        "count": 1,
        "page": 1,
        "per_page": 30,
        "total_pages": 1,
        "submissions": [
            {
                "id": 2,
                "created_at": "2026-06-29 17:23:29",
                "problem_title": "Slitherlink",
                "status": "Unaccepted",
                "score": 26,
                "is_ac": False,
            }
        ],
    }


def test_submission_detail_outputs_necessary_user_facing_fields(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "user": {"username": "student1"},
        "plang": "python",
        "problem": {"id": 2, "title": "Slitherlink", "content": "hidden duplicate"},
        "submission": {
            "id": 9,
            "username": "student1",
            "problem_id": 2,
            "problem_title": "Slitherlink",
            "problem_type": 1,
            "code": "print('hello')\n",
            "prompt_text": "",
            "generated_from_prompt": False,
            "prompt_generation_error": "",
            "promptly_review_reply": "",
            "status": "Accepted",
            "score": 100,
            "created_at": "2026-06-29 17:23:29",
            "test_points": [{"should": "move to top-level only"}],
        },
        "test_points": [{"status": "Accepted"}],
        "cached_ai_code_marks": {"code_used": "hidden duplicate"},
        "submission_latex_text": "",
        "submission_latex_error": "",
        "submission_latex_html": "<p>hidden</p>",
        "written_submission": {"show_latex_transcription": False},
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.submission_detail(Namespace(submission_id=9))

    assert cli.json.loads(capsys.readouterr().out) == {
        "submission": {
            "id": 9,
            "problem_id": 2,
            "problem_title": "Slitherlink",
            "problem_type": 1,
            "code": "print('hello')\n",
            "prompt_text": "",
            "generated_from_prompt": False,
            "prompt_generation_error": "",
            "promptly_review_reply": "",
            "status": "Accepted",
            "score": 100,
            "created_at": "2026-06-29 17:23:29",
        },
        "test_points": [{"status": "Accepted"}],
    }


def test_submission_last_code_output_writes_only_code_field(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "code": "print('hello')\n",
        "submission_id": 17,
        "score": 100,
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)
    output = tmp_path / "solution.py"

    cli.submission_last_code(Namespace(problem_id=42, output=str(output)))

    assert output.read_text(encoding="utf-8") == "print('hello')\n"
    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "path": str(output),
        "bytes": len("print('hello')\n".encode("utf-8")),
        "submission_id": 17,
    }


def test_numoj_user_json_query_commands_do_not_accept_output_option():
    cli = _load_numoj_user_cli_module()
    parser = cli.build_parser()
    json_commands = [
        ("submission", "list"),
        ("submission", "detail", "123"),
        ("problem", "list"),
        ("problem", "detail", "42"),
        ("problem", "submit-page", "42"),
        ("forum", "list"),
        ("forum", "thread", "7"),
        ("forum", "new-page"),
        ("repository", "page"),
        ("ranking", "list"),
        ("ranking", "detail", "9"),
    ]

    for command in json_commands:
        try:
            parser.parse_args([*command, "-o", "/tmp/out.json"])
        except SystemExit as exc:
            assert exc.code != 0
        else:
            raise AssertionError(f"{command} unexpectedly accepted -o")


def test_numoj_user_download_commands_keep_output_option():
    cli = _load_numoj_user_cli_module()
    parser = cli.build_parser()
    args = parser.parse_args(["submission", "output-image", "123", "0", "-o", "/tmp/out.bmp"])
    assert args.output == "/tmp/out.bmp"
    args = parser.parse_args(["submission", "last-code", "42", "-o", "/tmp/solution.py"])
    assert args.output == "/tmp/solution.py"
