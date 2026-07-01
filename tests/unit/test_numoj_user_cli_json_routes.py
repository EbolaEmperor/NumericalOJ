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


class _FakeClient:
    def __init__(self):
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        return _FakeResponse()


def test_numoj_user_page_like_commands_use_json_api_without_output(monkeypatch):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli, "client_from_args", lambda _args, **_kwargs: fake_client)

    cases = [
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


def test_numoj_user_json_query_commands_do_not_accept_output_option():
    cli = _load_numoj_user_cli_module()
    parser = cli.build_parser()
    json_commands = [
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

