# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
import uuid
from argparse import Namespace
from pathlib import Path

import pytest


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
        if path == "/api/forum/identity":
            return _PayloadResponse({
                "success": True,
                "identity": {"posting_token": "posting-token"},
            })
        return _FakeResponse()


class _PayloadResponse:
    def __init__(self, payload, status_code=200, headers=None):
        import json

        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = json.dumps(payload, ensure_ascii=False)
        self.content = self.text.encode("utf-8")

    def json(self):
        return self._payload


class _RedirectResponse:
    status_code = 302
    content = b""
    text = ""

    def __init__(self, location="/"):
        self.headers = {"Location": location}


class _StreamResponse:
    status_code = 200
    headers = {"Content-Type": "text/event-stream"}
    text = (
        'event: progress\n'
        'data: {"task_id":"task-1","submission_id":1,"status":"Running","score":50,'
        '"html":"<main>noise</main>","user":{"username":"admin"},'
        '"test_points":[{"test_index":1,"status":"Accepted"}]}\n'
    )
    content = text.encode("utf-8")

    def iter_lines(self, decode_unicode=False):
        lines = self.text.splitlines()
        for line in lines:
            yield line if decode_unicode else line.encode("utf-8")


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

    cases = [
        (cli.submission_detail_cmd, Namespace(submission_id=123), "/api/submissions/123"),
        (cli.problem_list, Namespace(limit=5), "/api/problems"),
        (cli.problem_detail, Namespace(problem_id=42), "/api/problems/42"),
        (cli.problem_submit_page, Namespace(problem_id=42), "/api/problems/42/submit-context"),
        (cli.problem_create_form, Namespace(), "/api/admin/problems/create-form"),
        (cli.problem_edit_form, Namespace(problem_id=42), "/api/admin/problems/42/edit-form"),
        (cli.problem_agent_run, Namespace(task_id="task-1"), "/agent/runs/task-1/state"),
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
        monkeypatch.setitem(func.__globals__, "client_from_args", lambda _args: fake_client)
        func(args)
        assert fake_client.requests[-1][1] == expected_path


def test_forum_write_commands_use_json_api_and_uuid(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setitem(
        cli.forum_new.__globals__,
        "client_from_args",
        lambda _args: fake_client,
    )

    cli.forum_new(Namespace(title="主题", content="正文"))
    method, path, kwargs = fake_client.requests[-1]
    assert (method, path) == ("POST", "/api/forum/threads")
    assert kwargs["json"]["title"] == "主题"
    assert kwargs["json"]["content"] == "正文"
    assert kwargs["json"]["expected_identity_token"] == "posting-token"
    assert uuid.UUID(kwargs["json"]["client_request_id"])

    cli.forum_reply(Namespace(thread_id=7, content="回复"))
    method, path, kwargs = fake_client.requests[-1]
    assert (method, path) == ("POST", "/api/forum/threads/7/replies")
    assert kwargs["json"]["content"] == "回复"
    assert kwargs["json"]["expected_identity_token"] == "posting-token"
    assert uuid.UUID(kwargs["json"]["client_request_id"])
    capsys.readouterr()


def test_repository_save_create_sends_current_structure_version(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "structure_version": 12, "files": []}),
        _PayloadResponse({"success": True, "file_id": 9}),
    ])
    monkeypatch.setattr(cli.repository, "client_from_args", lambda _args: client)

    cli.repository_save_file(Namespace(
        filename="src/main.cpp",
        content="int main() { return 0; }\n",
        content_file=None,
        file_id=None,
    ))

    assert client.requests == [
        ("GET", "/api/repository/files", {}),
        (
            "POST",
            "/api/repository/file",
            {
                "json": {
                    "filename": "src/main.cpp",
                    "content": "int main() { return 0; }\n",
                    "expected_structure_version": 12,
                }
            },
        ),
    ]
    capsys.readouterr()


def test_repository_save_update_sends_current_file_version(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "id": 9, "file_version": 7, "content": "old"}),
        _PayloadResponse({"success": True, "file_id": 9}),
    ])
    monkeypatch.setattr(cli.repository, "client_from_args", lambda _args: client)

    cli.repository_save_file(Namespace(
        filename="src/main.cpp",
        content="new\n",
        content_file=None,
        file_id=9,
    ))

    assert client.requests == [
        ("GET", "/api/repository/file/9", {}),
        (
            "POST",
            "/api/repository/file",
            {
                "json": {
                    "filename": "src/main.cpp",
                    "content": "new\n",
                    "file_id": 9,
                    "expected_file_version": 7,
                }
            },
        ),
    ]
    capsys.readouterr()


def test_repository_upload_sends_current_structure_version_as_form_data(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "structure_version": 21, "files": []}),
        _PayloadResponse({"success": True, "file_id": 3}),
    ])
    monkeypatch.setattr(cli.repository, "client_from_args", lambda _args: client)
    source = tmp_path / "solver.py"
    source.write_text("print('ok')\n", encoding="utf-8")

    cli.repository_upload(Namespace(file=str(source)))

    assert [(method, path) for method, path, _kwargs in client.requests] == [
        ("GET", "/api/repository/files"),
        ("POST", "/api/repository/upload"),
    ]
    upload_kwargs = client.requests[1][2]
    assert upload_kwargs["data"] == {"expected_structure_version": "21"}
    assert upload_kwargs["files"]["file"][0] == "solver.py"
    assert upload_kwargs["files"]["file"][1].closed
    capsys.readouterr()


def test_problem_agent_solve_sends_explicit_harness_and_endpoint_as_json(
    monkeypatch,
    capsys,
):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.problem, "client_from_args", lambda _args: fake_client)

    cli.problem_agent_solve(Namespace(
        problem_id=9,
        harness="claude_code",
        endpoint_id=12,
    ))

    method, path, kwargs = fake_client.requests[-1]
    assert (method, path) == ("POST", "/agent/problems/9/solve")
    assert kwargs == {
        "json": {
            "harness": "claude_code",
            "endpoint_id": 12,
        },
    }
    capsys.readouterr()


def test_problem_agent_generate_data_uploads_standard_solution_as_multipart(
    monkeypatch,
    capsys,
    tmp_path,
):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.problem, "client_from_args", lambda _args: fake_client)
    source = tmp_path / "answer.py"
    source.write_text("print(1)\n", encoding="utf-8")

    cli.problem_agent_generate_data(Namespace(
        problem_id=9,
        harness="codex",
        endpoint_id=12,
        count=4,
        standard_solution=str(source),
        data_requirement="覆盖边界",
    ))

    method, path, kwargs = fake_client.requests[-1]
    assert (method, path) == (
        "POST",
        "/agent/problems/9/generate-testdata",
    )
    assert kwargs["data"] == {
        "harness": "codex",
        "endpoint_id": 12,
        "test_point_count": 4,
        "data_requirement": "覆盖边界",
    }
    assert "json" not in kwargs
    assert kwargs["files"]["standard_solution"][0] == "answer.py"
    assert kwargs["files"]["standard_solution"][1].closed
    capsys.readouterr()


def test_problem_agent_commands_require_new_harness_contract_and_reject_old_flags(
    capsys,
):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()

    solve = parser.parse_args([
        "problem", "agent-solve", "9",
        "--harness", "opencode", "--endpoint-id", "12",
    ])
    assert solve.harness == "opencode"
    assert solve.endpoint_id == 12
    assert not hasattr(solve, "extra_prompt")

    generate = parser.parse_args([
        "problem", "agent-generate-data", "9",
        "--harness", "pi", "--endpoint-id", "13", "--count", "4",
        "--standard-solution", "answer.py",
        "--data-requirement", "覆盖边界",
    ])
    assert generate.harness == "pi"
    assert generate.endpoint_id == 13
    assert generate.standard_solution == "answer.py"
    assert not hasattr(generate, "standard_code")

    old_commands = (
        [
            "problem", "agent-solve", "9",
            "--harness", "codex", "--endpoint-id", "12",
            "--extra-prompt", "旧补充提示",
        ],
        [
            "problem", "agent-generate-data", "9",
            "--harness", "codex", "--endpoint-id", "12", "--count", "4",
            "--standard-solution", "answer.py",
            "--standard-code", "print(1)",
        ],
    )
    for argv in old_commands:
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(argv)
        assert exc_info.value.code != 0
    capsys.readouterr()


def test_problem_agent_stream_summary_uses_canonical_execution_trace():
    cli = _load_numoj_admin_cli_module()

    summary = cli.problem.necessary_agent_stream_event_payload({
        "task_id": "task-1",
        "status": "Running",
        "execution_trace": {
            "trace_id": "trace-1",
            "status": "running",
            "trace_messages": [{"text": "one"}, {"text": "two"}],
            "trace_files": [{"path": "codex_agent_judge.jsonl"}],
        },
        "events": [{"message": "旧自建轨迹"}],
    })

    assert summary["execution_trace"] == {
        "trace_id": "trace-1",
        "status": "running",
        "trace_messages_count": 2,
        "trace_files_count": 1,
    }
    assert "events_count" not in summary


def test_repository_delete_confirms_once_with_server_token(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    client = _SequenceClient([
        _PayloadResponse({
            "success": False,
            "code": "confirmation_required",
            "confirmation_token": "delete-token",
        }, status_code=409),
        _PayloadResponse({"success": True, "deleted": True}),
    ])
    monkeypatch.setattr(cli.repository, "client_from_args", lambda _args: client)

    cli.repository_delete_file(Namespace(file_id=9))

    assert client.requests == [
        ("DELETE", "/api/repository/file/9", {}),
        (
            "DELETE",
            "/api/repository/file/9",
            {"json": {"confirmation_token": "delete-token"}},
        ),
    ]
    capsys.readouterr()


def test_repository_delete_does_not_swallow_unrelated_conflict(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    client = _SequenceClient([
        _PayloadResponse({
            "success": False,
            "code": "structure_conflict",
            "message": "repository changed",
        }, status_code=409),
    ])
    monkeypatch.setattr(cli.repository, "client_from_args", lambda _args: client)

    with pytest.raises(cli.repository.CliError):
        cli.repository_delete_file(Namespace(file_id=9))

    assert client.requests == [("DELETE", "/api/repository/file/9", {})]


def test_ranking_detail_submissions_tab_maps_to_server_tab(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setitem(cli.ranking_detail.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_detail(Namespace(competition_id=9, tab="submissions", full=False))

    method, path, kwargs = fake_client.requests[-1]
    assert method == "GET"
    assert path == "/api/ranking/competitions/9"
    assert kwargs["params"] == {"tab": "all_submissions"}


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
    args = parser.parse_args(["submission", "output-image", "123", "1", "-o", "/tmp/out.bmp"])
    assert args.output == "/tmp/out.bmp"


def test_numoj_admin_submission_commands_do_not_accept_full_option():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    commands = [
        ("submission", "status", "123", "--full"),
        ("submission", "stream", "123", "--full"),
        ("submission", "detail", "123", "--full"),
        ("submission", "last-code", "123", "--full"),
    ]

    for command in commands:
        try:
            parser.parse_args(list(command))
        except SystemExit as exc:
            assert exc.code != 0
        else:
            raise AssertionError(f"{command} unexpectedly accepted --full")


def test_download_redirect_is_not_reported_as_saved(capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    target = tmp_path / "out.bin"

    try:
        cli.common.print_or_save_response(_RedirectResponse("/login"), output=str(target))
    except cli.common.CliHttpError as exc:
        payload = exc.payload
    else:
        raise AssertionError("download redirect should raise CliHttpError")

    assert payload["success"] is False
    assert payload["location"] == "/login"
    assert "redirected" in payload["message"]
    assert not target.exists()
    assert capsys.readouterr().out == ""


def test_non_download_redirect_is_not_reported_as_success(capsys):
    cli = _load_numoj_admin_cli_module()

    try:
        cli.common.print_or_save_response(_RedirectResponse("/login"))
    except cli.common.CliHttpError as exc:
        payload = exc.payload
    else:
        raise AssertionError("redirect should raise CliHttpError")

    assert payload["success"] is False
    assert payload["http_status"] == 302
    assert payload["location"] == "/login"
    assert "login" in payload["message"]
    assert capsys.readouterr().out == ""


def test_json_failure_payload_is_nonzero(capsys):
    cli = _load_numoj_admin_cli_module()

    try:
        cli.common.print_or_save_response(_PayloadResponse({"success": False, "message": "失败"}))
    except cli.common.CliHttpError as exc:
        payload = exc.payload
    else:
        raise AssertionError("success:false payload should raise CliHttpError")

    assert payload == {"success": False, "message": "失败", "http_status": 200}
    assert capsys.readouterr().out == ""


def test_runtime_cli_error_is_json(capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    missing = tmp_path / "missing.zip"

    rc = cli.main(["--base-url", "http://oj", "ranking", "upload-attachment", "1", str(missing)])

    assert rc == 2
    payload = cli.json.loads(capsys.readouterr().out)
    assert payload["success"] is False
    assert "File not found" in payload["message"]


def test_ai_detection_run_filtered_requires_filter(capsys):
    cli = _load_numoj_admin_cli_module()

    rc = cli.main(["ai-detection", "run-filtered", "--endpoint-id", "7"])

    assert rc == 2
    payload = cli.json.loads(capsys.readouterr().out)
    assert payload["success"] is False
    assert "requires at least one filter" in payload["message"]


def test_ai_detection_run_commands_require_positive_endpoint_id_and_preview_does_not():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()

    preview = parser.parse_args(["ai-detection", "preview", "--submission-id", "9"])
    assert not hasattr(preview, "endpoint_id")

    run_commands = (
        ["ai-detection", "run-filtered", "--submission-id", "9"],
        ["ai-detection", "run-problem", "3"],
        ["ai-detection", "run-single", "9"],
        ["ai-detection", "run-user", "alice"],
    )
    for argv in run_commands:
        with pytest.raises(SystemExit):
            parser.parse_args(argv)
        with pytest.raises(SystemExit):
            parser.parse_args([*argv, "--endpoint-id", "0"])

    with pytest.raises(SystemExit):
        parser.parse_args([
            "ai-detection",
            "run-single",
            "9",
            "--model",
            "legacy-model",
        ])


def test_ai_detection_cli_posts_endpoint_id_for_every_run_command(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.ai_detection, "client_from_args", lambda _args: fake_client)

    cases = (
        (
            ["ai-detection", "run-filtered", "--submission-id", "9", "--endpoint-id", "101"],
            "/admin/ai_detection/run_filtered",
            {"submission_id": 9, "endpoint_id": 101},
        ),
        (
            ["ai-detection", "run-problem", "3", "--endpoint-id", "102"],
            "/admin/ai_detection/run/3",
            {"endpoint_id": 102},
        ),
        (
            ["ai-detection", "run-single", "9", "--endpoint-id", "103"],
            "/admin/ai_detection/run_single/9",
            {"endpoint_id": 103},
        ),
        (
            ["ai-detection", "run-user", "alice", "--endpoint-id", "104"],
            "/admin/ai_detection/run_user/alice",
            {"endpoint_id": 104},
        ),
    )
    for argv, expected_path, expected_json in cases:
        args = parser.parse_args(argv)
        args.func(args)
        method, path, kwargs = fake_client.requests[-1]
        assert (method, path) == ("POST", expected_path)
        assert kwargs["json"] == expected_json
        assert "model_id" not in kwargs["json"]

    preview = parser.parse_args([
        "ai-detection",
        "preview",
        "--submission-id",
        "9",
    ])
    preview.func(preview)
    assert fake_client.requests[-1] == (
        "POST",
        "/admin/ai_detection/preview",
        {"json": {"submission_id": 9}},
    )
    capsys.readouterr()


def test_ranking_git_http_json_failure_is_nonzero(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    fake_client = _SequenceClient([
        _PayloadResponse({"message": "比赛不存在或已被删除"}, status_code=404),
    ])
    monkeypatch.setitem(cli.ranking_git_submit.__globals__, "client_from_args", lambda _args: fake_client)

    try:
        cli.ranking_git_submit(Namespace(competition_id=999999, action="check"))
    except cli.common.CliHttpError as exc:
        payload = exc.payload
    else:
        raise AssertionError("ranking git 4xx JSON should raise CliHttpError")

    assert payload == {
        "message": "比赛不存在或已被删除",
        "success": False,
        "http_status": 404,
    }


def test_non_json_http_error_is_structured_without_html():
    cli = _load_numoj_admin_cli_module()
    resp = _PayloadResponse(
        {"unused": True},
        status_code=404,
        headers={"Content-Type": "text/html"},
    )
    resp.text = "<!doctype html><html><head><title>404 Not Found</title></head><body>long html</body></html>"

    try:
        cli.common.ensure_ok(resp, allow_redirect=False)
    except cli.common.CliHttpError as exc:
        payload = exc.payload
    else:
        raise AssertionError("404 should raise CliHttpError")

    assert payload == {"success": False, "http_status": 404, "message": "404 Not Found"}


def test_auth_status_without_cookie_reports_unauthenticated(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    monkeypatch.setattr(cli.auth, "load_config", lambda _path: {"base_url": "http://oj", "username": "admin"})

    cli.auth.status(Namespace(config=tmp_path / "cfg.json", base_url=None, timeout=60.0))

    assert cli.json.loads(capsys.readouterr().out) == {
        "authenticated": False,
        "admin": False,
        "base_url": "http://oj",
        "username": "admin",
        "reason": "no_session_cookie",
    }


def test_auth_status_without_config_reports_uninitialized(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    monkeypatch.setattr(cli.auth, "load_config", lambda _path: {})

    cli.auth.status(Namespace(config=tmp_path / "cfg.json", base_url=None, timeout=60.0))

    assert cli.json.loads(capsys.readouterr().out) == {
        "authenticated": False,
        "admin": False,
        "base_url": None,
        "username": None,
        "reason": "no_config",
    }


def test_auth_login_surfaces_html_error_message(monkeypatch, tmp_path):
    cli = _load_numoj_admin_cli_module()

    class _FailedLoginResponse:
        status_code = 200
        headers = {"Content-Type": "text/html"}
        text = '<div class="alert alert-danger" role="alert">用户名或密码错误</div>'

    class _FailedLoginSession:
        trust_env = False

        class _Cookies:
            def get_dict(self):
                return {}

        def __init__(self):
            self.cookies = self._Cookies()

        def post(self, *args, **kwargs):
            return _FailedLoginResponse()

    monkeypatch.setattr(cli.auth.requests, "Session", _FailedLoginSession)
    args = Namespace(
        config=tmp_path / "cfg.json",
        login_base_url="http://oj",
        base_url=None,
        username="admin",
        password="bad-password",
        timeout=60.0,
        prompt_base_url=False,
    )

    try:
        cli.auth.login(args)
    except cli.common.CliError as exc:
        assert str(exc) == "Login failed. HTTP 200: 用户名或密码错误"
    else:
        raise AssertionError("failed HTML login should raise CliError")


def test_homework_list_does_not_duplicate_homework_keys(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "selected_class": "C1",
        "homeworks": [{"id": 1, "title": "A"}],
        "homework_list": [{"id": 2, "title": "B"}],
        "classes": [{"class_en": "C1"}],
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.homework_list.__globals__, "client_from_args", lambda _args: fake_client)

    cli.homework_list(Namespace(class_en="C1"))

    out = cli.json.loads(capsys.readouterr().out)
    assert out == {
        "selected_class": "C1",
        "classes": [{"class_en": "C1"}],
        "homeworks": [{"id": 1, "title": "A"}],
    }


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
    monkeypatch.setitem(cli.homework_plagiarism_start.__globals__, "client_from_args", lambda _args: fake_client)
    monkeypatch.setattr(cli.homework.time, "sleep", lambda _seconds: None)

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


def test_admin_ranking_list_omits_full_description(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "user": {"username": "admin"},
        "competitions": [
            {
                "id": 1,
                "title": "赛题",
                "summary": "短说明",
                "description": "长说明" * 100,
                "scoring_mode": "agent_judge",
                "submission_count": 3,
            }
        ],
        "count": 1,
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.ranking_list.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_list(Namespace(limit=3))

    out = cli.json.loads(capsys.readouterr().out)
    assert out == {
        "success": True,
        "competitions": [
            {
                "id": 1,
                "title": "赛题",
                "summary": "短说明",
                "scoring_mode": "agent_judge",
                "submission_count": 3,
            }
        ],
        "count": 1,
        "total": 1,
    }


def test_admin_submission_status_prints_full_payload_by_default(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "status": "Unaccepted",
        "score": 1,
        "test_points": [
            {"test_index": 1, "status": "Accepted", "stdout": "ok"},
            {"test_index": 2, "status": "Wrong Answer", "stdout": "bad", "stderr": ""},
        ],
        "debug": {"kept": True},
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.submission_status_cmd.__globals__, "client_from_args", lambda _args: fake_client)

    cli.submission_status_cmd(Namespace(submission_id=123))

    assert cli.json.loads(capsys.readouterr().out) == payload


def test_admin_submission_detail_prints_full_payload_by_default(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "submission": {"id": 123, "code": "disp(1)", "status": "Accepted"},
        "problem": {"id": 1, "title": "题目", "rendered_content": "<p>题面</p>"},
        "test_points": [{"test_index": 1, "status": "Accepted", "stdout": "ok"}],
        "html": "<main>kept</main>",
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.submission_detail_cmd.__globals__, "client_from_args", lambda _args: fake_client)

    cli.submission_detail_cmd(Namespace(submission_id=123))

    assert cli.json.loads(capsys.readouterr().out) == payload


def test_admin_submission_list_includes_limit_metadata(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "count": 2,
        "page": 1,
        "per_page": 20,
        "scope": "all",
        "submissions": [
            {"id": 1, "username": "alice", "problem_id": 10, "status": "Accepted"},
            {"id": 2, "username": "bob", "problem_id": 11, "status": "Wrong Answer"},
        ],
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.submission_list.__globals__, "client_from_args", lambda _args: fake_client)

    cli.submission_list(Namespace(page=1, limit=2))

    out = cli.json.loads(capsys.readouterr().out)
    assert out["limit"] == 2
    assert out["returned_count"] == 2
    assert out["per_page"] == 20
    assert out["submissions"][0]["problem_id"] == 10


def test_admin_ranking_detail_omits_description_by_default(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "competition": {"id": 1, "title": "赛", "description": "长说明" * 100},
        "tab": "description",
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.ranking_detail.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_detail(Namespace(competition_id=1, tab=None, full=False))

    out = cli.json.loads(capsys.readouterr().out)
    assert "description" not in out["competition"]
    assert out["competition"]["description_chars"] == len("长说明" * 100)


def test_admin_ranking_detail_description_tab_keeps_description(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "competition": {"id": 1, "title": "赛", "description": "完整说明"},
        "tab": "description",
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.ranking_detail.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_detail(Namespace(competition_id=1, tab="description", full=False))

    out = cli.json.loads(capsys.readouterr().out)
    assert out["competition"]["description"] == "完整说明"
    assert "description_chars" not in out["competition"]


def test_admin_ranking_detail_projects_quality_gate_configuration(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "competition": {
            "id": 1,
            "title": "反向赛",
            "reverse_quality_gate_enabled": 1,
            "reverse_quality_gate_prompt": "不得隐藏私有密码",
        },
        "quality_gate_endpoints": [
            {
                "id": 8,
                "harness": "codex",
                "base_url": "http://quality.local",
                "model": "quality-model",
                "status": "enabled",
                "has_key": True,
            }
        ],
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.ranking_detail.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_detail(Namespace(competition_id=1, tab="edit", full=False))

    out = cli.json.loads(capsys.readouterr().out)
    assert out["competition"]["reverse_quality_gate_enabled"] == 1
    assert out["competition"]["reverse_quality_gate_prompt"] == "不得隐藏私有密码"
    assert out["quality_gate_endpoints"][0]["has_key"] is True
    assert "api_key" not in out["quality_gate_endpoints"][0]


def test_admin_single_endpoint_cli_sends_model_metadata_and_accepts_pi(
        monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setitem(
        cli.ranking.ranking_save_endpoint.__globals__,
        "client_from_args",
        lambda _args: fake_client,
    )
    parser = cli.build_parser()

    default_args = parser.parse_args([
        "ranking", "save-endpoint", "3",
        "--harness", "pi",
        "--protocol", "openai",
        "--agent-base-url", "https://api.example.com/v1",
        "--api-key", "endpoint-secret",
        "--model", "custom-model",
    ])
    default_args.func(default_args)
    explicit_args = parser.parse_args([
        "ranking", "save-endpoint", "3",
        "--harness", "pi",
        "--protocol", "anthropic",
        "--agent-base-url", "https://api.example.com/v1",
        "--api-key", "endpoint-secret",
        "--model", "custom-model",
        "--context-window-tokens", "262144",
        "--max-output-tokens", "65536",
        "--no-thinking-compatibility",
    ])
    explicit_args.func(explicit_args)
    capsys.readouterr()

    default_endpoint = fake_client.requests[0][2]["json"]["endpoints"][0]
    assert default_endpoint["harness"] == "pi"
    assert default_endpoint["protocol"] == "openai"
    assert default_endpoint["context_window_tokens"] == 1_000_000
    assert default_endpoint["max_output_tokens"] == 384_000
    assert default_endpoint["thinking_compatibility"] is True
    assert default_endpoint["thinking_format"] == "enable_thinking"
    explicit_endpoint = fake_client.requests[1][2]["json"]["endpoints"][0]
    assert explicit_endpoint["protocol"] == "anthropic"
    assert explicit_endpoint["context_window_tokens"] == 262_144
    assert explicit_endpoint["max_output_tokens"] == 65_536
    assert explicit_endpoint["thinking_compatibility"] is False
    assert explicit_endpoint["thinking_format"] == "none"

    quality_args = parser.parse_args([
        "ranking", "save-quality-gate-endpoint", "3",
        "--harness", "pi",
        "--protocol", "openai",
        "--agent-base-url", "https://api.example.com/v1",
        "--api-key", "quality-secret",
        "--model", "quality-model",
        "--context-window-tokens", "524288",
        "--max-output-tokens", "131072",
        "--no-thinking-compatibility",
    ])
    assert quality_args.harness == "pi"
    assert quality_args.protocol == "openai"
    assert quality_args.context_window_tokens == 524_288
    assert quality_args.max_output_tokens == 131_072
    assert quality_args.thinking_compatibility is False


def test_admin_endpoint_pool_json_preserves_model_metadata(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setitem(
        cli.ranking_endpoints.__globals__,
        "client_from_args",
        lambda _args: fake_client,
    )
    endpoint = {
        "harness": "pi",
        "base_url": "https://api.example.com/v1",
        "api_key": "endpoint-secret",
        "model": "custom-model",
        "context_window_tokens": 131_072,
        "max_output_tokens": 32_768,
        "thinking_compatibility": False,
    }

    cli.ranking_endpoints(Namespace(
        competition_id=3,
        endpoints=cli.json.dumps([endpoint]),
        env_file=None,
        timeout_seconds=None,
        reverse_finalize_timeout=None,
        orchestration_mode=None,
    ))
    capsys.readouterr()

    assert fake_client.requests[0][2]["json"]["endpoints"] == [endpoint]


def test_admin_quality_gate_commands_reuse_file_and_env_secret_inputs(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    prompt_path = tmp_path / "quality-prompt.txt"
    prompt_path.write_text("不得隐藏私有协议。", encoding="utf-8")
    env_path = tmp_path / ".env"
    env_path.write_text("QUALITY_GATE_KEY=secret-from-env\n", encoding="utf-8")
    endpoints_path = tmp_path / "quality-endpoints.json"
    endpoints_path.write_text(
        '[{"harness":"codex","base_url":"http://quality.local",'
        '"api_key_env":"QUALITY_GATE_KEY","model":"quality-model",'
        '"concurrency_limit":2,"status":"enabled"}]',
        encoding="utf-8",
    )
    for func in (
        cli.ranking_save_quality_gate,
        cli.ranking_save_quality_gate_endpoints,
        cli.ranking_save_quality_gate_endpoint,
    ):
        monkeypatch.setitem(func.__globals__, "client_from_args", lambda _args: fake_client)

    cli.ranking_save_quality_gate(Namespace(
        competition_id=3,
        enabled=False,
        prompt=f"@{prompt_path}",
    ))
    cli.ranking_save_quality_gate_endpoints(Namespace(
        competition_id=3,
        endpoints=f"@{endpoints_path}",
        env_file=str(env_path),
    ))
    cli.ranking_save_quality_gate_endpoint(Namespace(
        competition_id=3,
        harness="claude_code",
        base_url_value="http://single-quality.local",
        api_key=None,
        api_key_env="QUALITY_GATE_KEY",
        env_file=str(env_path),
        model="single-quality-model",
        concurrency_limit=1,
        status="paused",
    ))
    capsys.readouterr()

    assert [request[1] for request in fake_client.requests] == [
        "/ranking/3/reverse_judge/quality_gate",
        "/ranking/3/reverse_judge/quality_gate",
        "/ranking/3/reverse_judge/quality_gate",
    ]
    assert fake_client.requests[0][2]["json"] == {
        "enabled": False,
        "prompt": "不得隐藏私有协议。",
    }
    assert fake_client.requests[1][2]["json"]["endpoints"][0]["api_key"] == "secret-from-env"
    assert "api_key_env" not in fake_client.requests[1][2]["json"]["endpoints"][0]
    assert fake_client.requests[2][2]["json"]["endpoints"] == [
        {
            "harness": "claude_code",
            "protocol": "anthropic",
            "base_url": "http://single-quality.local",
            "api_key": "secret-from-env",
            "model": "single-quality-model",
            "context_window_tokens": 1_000_000,
            "max_output_tokens": 384_000,
            "thinking_compatibility": True,
            "thinking_format": "thinking_type",
            "concurrency_limit": 1,
            "status": "paused",
        }
    ]


def test_admin_quality_gate_endpoint_commands_require_explicit_http_url(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    for func in (
        cli.ranking_save_quality_gate_endpoints,
        cli.ranking_save_quality_gate_endpoint,
    ):
        monkeypatch.setitem(func.__globals__, "client_from_args", lambda _args: fake_client)

    invalid_lists = (
        '[{"harness":"opencode","api_key":"secret","model":"gate-model"}]',
        '[{"harness":"opencode","base_url":"ftp://quality.local",'
        '"api_key":"secret","model":"gate-model"}]',
    )
    for endpoints in invalid_lists:
        try:
            cli.ranking_save_quality_gate_endpoints(Namespace(
                competition_id=3,
                endpoints=endpoints,
                env_file=None,
            ))
        except cli.CliError as exc:
            assert "base_url" in str(exc)
        else:
            raise AssertionError("quality-gate endpoint without an HTTP URL was accepted")

    try:
        cli.ranking_save_quality_gate_endpoint(Namespace(
            competition_id=3,
            harness="opencode",
            base_url_value="",
            api_key="secret",
            api_key_env=None,
            env_file=None,
            model="gate-model",
            concurrency_limit=1,
            status="enabled",
        ))
    except cli.CliError as exc:
        assert "base_url" in str(exc)
    else:
        raise AssertionError("single quality-gate endpoint without a URL was accepted")

    assert fake_client.requests == []


def test_admin_reverse_snapshot_uses_step_key_and_projects_quality_verdict():
    cli = _load_numoj_admin_cli_module()

    projected = cli.ranking.necessary_reverse_judge_snapshot_payload({
        "submission_id": 12,
        "status": "Error",
        "total_score": None,
        "last_updated": "2026-07-10 12:00:00",
        "steps": [
            {
                "step_key": "quality_gate",
                "title": "质量门禁",
                "status": "failed",
                "result": {
                    "passed": False,
                    "verdict": "reject",
                    "summary": "存在私有配对密码",
                    "violations": ["solution 与 judge 使用未公开密码"],
                    "private_debug": "must not leak",
                },
                "trace_messages": [{"text": "one"}],
            }
        ],
    })

    assert projected["last_updated"] == "2026-07-10 12:00:00"
    assert projected["steps"] == [
        {
            "step_key": "quality_gate",
            "title": "质量门禁",
            "status": "failed",
            "score": None,
            "max_score": None,
            "trace_messages_count": 1,
            "passed": False,
            "verdict": "reject",
            "summary": "存在私有配对密码",
            "violations": ["solution 与 judge 使用未公开密码"],
        }
    ]


def test_admin_ranking_submission_projection_keeps_ai_answer_metadata_only_for_mapping_input():
    cli = _load_numoj_admin_cli_module()

    projected = cli.ranking._necessary_ranking_submission({
        "id": 9,
        "status": "Accepted",
        "ai_answer_available": True,
        "ai_answer_download_url": "/api/ranking/submissions/9/reverse-agent-answer",
        "judge_attempt_id": "attempt-private",
        "secret": "must-not-leak",
    })

    assert projected == {
        "id": 9,
        "status": "Accepted",
        "ai_answer_available": True,
        "ai_answer_download_url": "/api/ranking/submissions/9/reverse-agent-answer",
    }
    assert cli.ranking._necessary_ranking_submission("not-a-mapping") == {}


def test_admin_reverse_snapshot_projects_agent_answer_availability_without_leaking_path():
    cli = _load_numoj_admin_cli_module()

    projected = cli.ranking.necessary_reverse_judge_snapshot_payload({
        "submission_id": 9,
        "status": "Accepted",
        "steps": [
            {
                "step_key": "agent_answer",
                "title": "AI 作答",
                "status": "completed",
                "answer_available": True,
                "answer_path": "/private/agent-answer.zip",
                "trace_messages": [{"text": "one"}, {"text": "two"}],
            },
            {
                "step_key": "quality_gate",
                "title": "质量门禁",
                "status": "completed",
                "answer_available": True,
                "result": {
                    "passed": True,
                    "verdict": "accept",
                    "violations": [],
                },
            },
        ],
    })

    agent_step, quality_step = projected["steps"]
    assert agent_step["answer_available"] is True
    assert agent_step["trace_messages_count"] == 2
    assert "answer_path" not in agent_step
    assert quality_step["passed"] is True
    assert quality_step["verdict"] == "accept"
    assert quality_step["violations"] == []
    assert "answer_available" not in quality_step
    assert "answer_path" not in repr(projected)


def test_admin_ranking_download_submission_routes_each_artifact_without_redirect(monkeypatch):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    saved = []
    monkeypatch.setitem(
        cli.ranking_download_submission.__globals__,
        "client_from_args",
        lambda _args: fake_client,
    )
    monkeypatch.setitem(
        cli.ranking_download_submission.__globals__,
        "print_or_save_response",
        lambda response, **kwargs: saved.append((response, kwargs)),
    )

    cases = [
        ("ai-answer", "/tmp/ai-answer.zip", "/api/ranking/submissions/9/reverse-agent-answer"),
        ("answer", None, "/ranking/submission/9/answer"),
        ("code", "/tmp/code.zip", "/ranking/submission/9/code"),
    ]
    for kind, output, expected_path in cases:
        cli.ranking_download_submission(Namespace(submission_id=9, kind=kind, output=output))
        method, path, kwargs = fake_client.requests[-1]
        response, save_kwargs = saved[-1]
        assert (method, path, kwargs) == ("GET", expected_path, {})
        assert isinstance(response, _FakeResponse)
        assert save_kwargs == {
            "output": output or ".",
            "allow_redirect": False,
        }


def test_admin_ranking_parser_accepts_only_supported_download_kinds():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()

    args = parser.parse_args([
        "ranking",
        "download-submission",
        "9",
        "ai-answer",
        "-o",
        "answer.zip",
    ])

    assert args.submission_id == 9
    assert args.kind == "ai-answer"
    assert args.output == "answer.zip"
    assert args.func is cli.ranking_download_submission
    try:
        parser.parse_args(["ranking", "download-submission", "9", "invalid"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("unsupported download kind was accepted")


def test_admin_problem_edit_form_omits_large_text_fields(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "action": "/admin/edit_problem/42",
        "form": {
            "title": "题目",
            "content": "abc",
            "test_code": "x" * 20,
            "time_limit": 1000,
        },
        "user": {"username": "admin"},
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setitem(cli.problem_edit_form.__globals__, "client_from_args", lambda _args: fake_client)

    cli.problem_edit_form(Namespace(problem_id=42, full=False))

    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "action": "/admin/edit_problem/42",
        "form": {
            "title": "题目",
            "time_limit": 1000,
            "omitted_text_fields": {
                "content": {"chars": 3},
                "test_code": {"chars": 20},
            },
        },
    }


def test_admin_problem_parser_exposes_six_endpoint_options_and_rejects_legacy_model_flags():
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()

    args = parser.parse_args([
        "problem",
        "create",
        "--title",
        "题目",
        "--content",
        "题面",
        "--output-image-grading-endpoint-id",
        "11",
        "--ocr-endpoint-id",
        "12",
        "--text-grading-endpoint-id",
        "13",
        "--direct-image-grading-endpoint-id",
        "14",
        "--review-endpoint-id",
        "15",
        "--code-generation-endpoint-id",
        "none",
    ])

    assert args.output_image_grading_endpoint_id == 11
    assert args.ocr_endpoint_id == 12
    assert args.text_grading_endpoint_id == 13
    assert args.direct_image_grading_endpoint_id == 14
    assert args.review_endpoint_id == 15
    assert args.code_generation_endpoint_id is None

    for legacy_option in ("--programming-grading-model", "--written-grading-model"):
        with pytest.raises(SystemExit):
            parser.parse_args([
                "problem",
                "create",
                "--title",
                "题目",
                "--content",
                "题面",
                legacy_option,
                "legacy-model",
            ])


def test_admin_problem_create_sends_endpoint_binding_json_and_allows_unconfigured(
        monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    fake_client = _FakeClient()
    monkeypatch.setitem(cli.problem_create.__globals__, "client_from_args", lambda _args: fake_client)

    configured = parser.parse_args([
        "problem",
        "create",
        "--title",
        "Promptly 题",
        "--content",
        "题面",
        "--programming-grading-mode",
        "3",
        "--review-endpoint-id",
        "31",
        "--code-generation-endpoint-id",
        "32",
    ])
    configured.func(configured)
    configured_data = fake_client.requests[-1][2]["data"]

    assert cli.json.loads(configured_data["llm_endpoint_bindings"]) == {
        "review_endpoint_id": 31,
        "code_generation_endpoint_id": 32,
    }
    assert "programming_grading_model" not in configured_data
    assert "written_grading_model" not in configured_data

    unconfigured = parser.parse_args([
        "problem",
        "create",
        "--title",
        "普通题",
        "--content",
        "题面",
    ])
    unconfigured.func(unconfigured)
    unconfigured_data = fake_client.requests[-1][2]["data"]

    assert "llm_endpoint_bindings" not in unconfigured_data
    capsys.readouterr()


def test_admin_problem_create_validates_lean_package_before_creating(
        monkeypatch, tmp_path):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    fake_client = _FakeClient()
    monkeypatch.setitem(cli.problem_create.__globals__, "client_from_args", lambda _args: fake_client)
    args = parser.parse_args([
        "problem",
        "create",
        "--title",
        "Lean 题",
        "--content",
        "题面",
        "--lang",
        "lean4",
        "--lean-package",
        str(tmp_path / "missing.zip"),
    ])

    with pytest.raises(cli.CliError, match="File not found"):
        args.func(args)

    assert fake_client.requests == []


def test_admin_problem_edit_omitted_endpoints_are_preserved_by_omitting_binding_payload(
        monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    client = _SequenceClient([
        _PayloadResponse({
            "success": True,
            "problem": {"id": 42, "type": 1},
            "form": {
                "title": "旧标题",
                "content": "旧题面",
                "programming_grading_mode": 2,
                "llm_endpoint_bindings": {"output_image_grading_endpoint_id": 41},
            },
        }),
        _FakeResponse(),
    ])
    monkeypatch.setitem(cli.problem_edit.__globals__, "client_from_args", lambda _args: client)
    args = parser.parse_args(["problem", "edit", "42", "--title", "新标题"])

    args.func(args)

    edit_data = client.requests[1][2]["data"]
    assert "llm_endpoint_bindings" not in edit_data
    assert "programming_grading_model" not in edit_data
    assert "written_grading_model" not in edit_data
    capsys.readouterr()


def test_admin_problem_edit_merges_updates_and_none_clears_one_binding(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    client = _SequenceClient([
        _PayloadResponse({
            "success": True,
            "problem": {"id": 42, "type": 2},
            "form": {
                "title": "书面题",
                "content": "题面",
                "written_grading_mode": 1,
                "llm_endpoint_bindings": {
                    "ocr_endpoint_id": 51,
                    "text_grading_endpoint_id": 52,
                    "direct_image_grading_endpoint_id": 53,
                },
            },
        }),
        _FakeResponse(),
    ])
    monkeypatch.setitem(cli.problem_edit.__globals__, "client_from_args", lambda _args: client)
    args = parser.parse_args([
        "problem",
        "edit",
        "42",
        "--ocr-endpoint-id",
        "none",
        "--text-grading-endpoint-id",
        "62",
    ])

    args.func(args)

    bindings = cli.json.loads(client.requests[1][2]["data"]["llm_endpoint_bindings"])
    assert bindings == {
        "text_grading_endpoint_id": 62,
        "direct_image_grading_endpoint_id": 53,
    }
    capsys.readouterr()


def test_admin_problem_edit_mode_switch_drops_incompatible_old_binding(monkeypatch, capsys):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    client = _SequenceClient([
        _PayloadResponse({
            "success": True,
            "problem": {"id": 42, "type": 1},
            "form": {
                "title": "图片题",
                "content": "题面",
                "programming_grading_mode": 2,
                "llm_endpoint_bindings": {"output_image_grading_endpoint_id": 71},
            },
        }),
        _FakeResponse(),
    ])
    monkeypatch.setitem(cli.problem_edit.__globals__, "client_from_args", lambda _args: client)
    args = parser.parse_args([
        "problem",
        "edit",
        "42",
        "--programming-grading-mode",
        "3",
        "--review-endpoint-id",
        "72",
        "--code-generation-endpoint-id",
        "73",
    ])

    args.func(args)

    bindings = cli.json.loads(client.requests[1][2]["data"]["llm_endpoint_bindings"])
    assert bindings == {
        "review_endpoint_id": 72,
        "code_generation_endpoint_id": 73,
    }
    capsys.readouterr()


class _LoginSession:
    trust_env = False

    class _Cookies:
        def get_dict(self):
            return {"session": "fake-session"}

    def __init__(self):
        self.cookies = self._Cookies()

    def post(self, *args, **kwargs):
        return _RedirectResponse("/problem_list")

    def get(self, *args, **kwargs):
        return _PayloadResponse({"success": True})


class _HygieneClient:
    def __init__(self):
        self.requests = []
        self.ranking_submitted = False
        self.base_url = "http://oj"

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        if kwargs.get("stream"):
            return _StreamResponse()
        if path == "/" or path.endswith("/logout"):
            return _RedirectResponse("/problem_list")
        if path.startswith("/download") or path.startswith("/export") or path.startswith("/ranking/submission/"):
            return self._file_response()
        if "download" in path and method.upper() == "GET":
            return self._file_response()
        if path.endswith("/submit") and "/ranking/" in path:
            self.ranking_submitted = True
            return self._generic_payload_response()
        if path == "/submit/1":
            return _RedirectResponse("/submission_detail/99")
        if path == "/api/problems/1/submit-context":
            return _PayloadResponse(self._problem_detail_payload(input_kind="code"))
        if path == "/api/problems/1":
            return _PayloadResponse(self._problem_detail_payload())
        if path == "/api/admin/problems/create-form":
            return _PayloadResponse(self._problem_form_payload())
        if path == "/api/admin/problems/1/edit-form":
            return _PayloadResponse(self._problem_form_payload())
        if path == "/api/admin/problems/1/lean-workspace":
            return _PayloadResponse(self._lean_workspace_payload())
        if path == "/admin/upload_lean_workspace/1":
            return _PayloadResponse(self._lean_workspace_payload())
        if path == "/api/problems":
            return _PayloadResponse(self._problem_list_payload())
        if path == "/api/submissions":
            return _PayloadResponse(self._submission_list_payload())
        if path == "/api/problems/1/submissions":
            return _PayloadResponse(self._submission_problem_payload())
        if path == "/submission_status/1":
            return _PayloadResponse(self._submission_status_payload())
        if path == "/api/submissions/1":
            return _PayloadResponse(self._submission_detail_payload())
        if path == "/api/get_last_submission_code/1":
            return _PayloadResponse({**self._noise(), "success": True, "code": "disp(1)"})
        if path == "/api/admin/homework":
            return _PayloadResponse(self._homework_list_payload())
        if path == "/api/admin/homework/plagiarism/records":
            return _PayloadResponse({
                **self._noise(),
                "success": True,
                "records": [{"id": 1, "matched_usernames_text": "a,b", "matched_usernames": ["a", "b"]}],
            })
        if path == "/api/admin/users":
            return _PayloadResponse(self._user_list_payload())
        if path == "/me/classes":
            return _PayloadResponse({**self._noise(), "classes": [{"class_en": "C1", "class_cn": "一班"}]})
        if path == "/admin/get_user_grades":
            return _PayloadResponse({**self._noise(), "grades": [{"problem_id": 1, "score": 95}]})
        if path == "/api/forum":
            return _PayloadResponse({
                **self._noise(),
                "count": 1,
                "threads": [{"id": 1, "title": "帖", "content": "列表不需要正文", **self._noise()}],
            })
        if path == "/api/forum/identity":
            return _PayloadResponse({
                "success": True,
                "identity": {"posting_token": "posting-token"},
            })
        if path == "/api/forum/threads/1":
            return _PayloadResponse({
                **self._noise(),
                "thread": {"id": 1, "title": "帖", "content": "正文", **self._noise()},
                "replies": [{"id": 2, "content": "回复", **self._noise()}],
                "reply_count": 1,
            })
        if path == "/api/forum/new-context":
            return _PayloadResponse({**self._noise(), "fields": ["title", "content"]})
        if path == "/api/repository/context":
            return _PayloadResponse({**self._noise(), "allowed_extensions": [".m"], "max_file_size_bytes": 1000, "defaults": {}})
        if path == "/api/repository/files":
            return _PayloadResponse({
                **self._noise(),
                "structure_version": 12,
                "files": [{"id": 1, "filename": "a.m", "file_size": 6, **self._noise()}],
            })
        if path == "/api/repository/file/1":
            return _PayloadResponse({**self._noise(), "file_version": 7, "filename": "a.m", "content": "disp(1)"})
        if path == "/api/repository/index/status/active":
            return _PayloadResponse({**self._noise(), "has_active": True, "job": self._job()})
        if path.startswith("/api/repository/index/status/"):
            return _PayloadResponse({**self._noise(), "job": self._job()})
        if path == "/api/repository/index/search":
            return _PayloadResponse({
                **self._noise(),
                "query": "vector",
                "hits": [{"chunk_id": 1, "filename": "a.m", "code": "disp(1)", **self._noise()}],
            })
        if path == "/api/repository/index/classes":
            return _PayloadResponse({
                **self._noise(),
                "classes": [{"class_id": 1, "filename": "a.m", "class_name": "A", **self._noise()}],
            })
        if path == "/api/admin/ai-detection/dashboard":
            return _PayloadResponse({**self._noise(), "success": True, "summary": {}, "classes": [], "problems": []})
        if path == "/api/admin/ai-detection/problem/1":
            return _PayloadResponse({**self._noise(), "success": True, "problem": {"id": 1}, "results": []})
        if path == "/api/admin/ai-detection/student/alice":
            return _PayloadResponse({**self._noise(), "success": True, "student": {"username": "alice"}, "results": []})
        if path == "/api/admin/dynamic-config/meta":
            return _PayloadResponse({**self._noise(), "success": True, "protocols": ["openai"], "features": []})
        if path == "/api/admin/dynamic-config/llm-endpoints/test":
            return _PayloadResponse({
                **self._noise(),
                "success": True,
                "test": {"passed": True, "latency_ms": 1},
                "test_token": "one-time-token",
            })
        if path == "/api/admin/dynamic-config/llm-endpoints" and method.upper() == "GET":
            return _PayloadResponse({
                **self._noise(),
                "success": True,
                "endpoints": [{
                    "id": 1,
                    "protocol": "openai",
                    "category": "text",
                    "base_url": "http://model",
                    "model": "model",
                    "api_key": "",
                    "api_key_configured": True,
                    "thinking_enabled": False,
                    "thinking_format": "none",
                }],
            })
        if path.startswith("/api/admin/dynamic-config/llm-endpoints"):
            return _PayloadResponse({
                **self._noise(),
                "success": True,
                "endpoint": {"id": 1, "model": "model", "api_key": "", "api_key_configured": True},
            })
        if path == "/api/admin/dynamic-config/feature-bindings":
            return _PayloadResponse({**self._noise(), "success": True, "bindings": []})
        if path.startswith("/api/admin/dynamic-config/feature-bindings/"):
            return _PayloadResponse({**self._noise(), "success": True, "binding": {"feature_key": "ai_code_annotation"}})
        if path == "/api/admin/dynamic-config/mail":
            return _PayloadResponse({**self._noise(), "success": True, "settings": None})
        if path == "/api/admin/dynamic-config/mail/test":
            return _PayloadResponse({**self._noise(), "success": True, "test": {"passed": True}})
        if path == "/api/admin/dynamic-config/web-search":
            return _PayloadResponse({**self._noise(), "success": True, "settings": None})
        if path == "/api/admin/dynamic-config/web-search/test":
            return _PayloadResponse({**self._noise(), "success": True, "test": {"passed": True}})
        if path == "/api/ranking/competitions":
            return _PayloadResponse(self._ranking_list_payload())
        if path == "/api/ranking/competitions/1":
            return _PayloadResponse(self._ranking_detail_payload())
        if path == "/api/ranking/competitions/1/matches":
            return _PayloadResponse({
                **self._noise(),
                "competition_id": 1,
                "matches": [{"id": 1, "details": {}, **self._noise()}],
                "total": 1,
                "page": 1,
                "total_pages": 1,
            })
        if path == "/ranking/1/match/1/details.json":
            return _PayloadResponse({"id": 1, "details": {}, **self._noise()})
        if path == "/api/ranking/competitions/1/appeals":
            return _PayloadResponse({**self._noise(), "competition_id": 1, "appeals": [{"id": 1}], "total": 1})
        if path == "/api/ranking/competitions/1/appeals/1/review":
            return _PayloadResponse({
                **self._noise(),
                "competition": {"id": 1, "title": "赛"},
                "appeal": {"id": 1},
                "submission": {"id": 1},
            })
        if path == "/api/ranking/competitions/1/my-submissions":
            submissions = [{"id": 2, "competition_id": 1}] if self.ranking_submitted else []
            return _PayloadResponse({**self._noise(), "competition_id": 1, "submissions": submissions, "count": len(submissions)})
        if path == "/api/ranking/competitions/1/submissions":
            return _PayloadResponse({**self._noise(), "competition_id": 1, "submissions": [{"id": 1, **self._noise()}], "count": 1})
        if path == "/api/ranking/competitions/1/leaderboard":
            return _PayloadResponse({**self._noise(), "competition_id": 1, "leaderboard": [{"username": "alice", "score": 1}], "count": 1})
        return self._generic_payload_response()

    def _noise(self):
        return {
            "user": {"username": "admin"},
            "params": {"page": 1},
            "page_numbers": [1, 2],
            "rendered_content": "<p>html</p>",
            "html": "<main>html</main>",
            "matched_usernames_text": "alice,bob",
            "nested": {"user": {"username": "nested"}, "message": "kept"},
        }

    def _generic_payload_response(self):
        return _PayloadResponse({**self._noise(), "success": True, "message": "ok", "id": 1, "task_id": "task-1"})

    def _file_response(self):
        return _PayloadResponse(
            {"file": True},
            headers={"Content-Type": "application/octet-stream", "Content-Disposition": 'attachment; filename="out.bin"'},
        )

    def _job(self):
        return {"id": 1, "status": "running", "progress": 50, **self._noise()}

    def _problem_list_payload(self):
        return {
            **self._noise(),
            "count": 1,
            "problems": [{"id": 1, "title": "题", "content": "列表不需要正文", "url": "/problem/1", **self._noise()}],
        }

    def _problem_detail_payload(self, input_kind="code"):
        return {
            **self._noise(),
            "problem": {"id": 1, "title": "题", "content": "题面", "lang": "matlab", "type": "1", **self._noise()},
            "initial_code": "disp(1)",
            "last_submissions": [{"id": 1, "status": "Accepted"}],
            "submit": {"input_kind": input_kind, "accept": ".m", **self._noise()},
        }

    def _problem_form_payload(self):
        return {
            **self._noise(),
            "success": True,
            "action": "/admin/edit_problem/1",
            "form": {"title": "题", "content": "题面", "test_code": "x" * 10, **self._noise()},
            "options": {"default_written_grading_prompt": "rubric"},
        }

    def _lean_workspace_payload(self):
        return {
            "success": True,
            "problem_id": 1,
            "message": "ok",
            "lean_workspace": {
                "revision_id": 1,
                "revision_number": 1,
                "revision": "revision-1",
                "schema_version": 1,
                "default_file": "Submission.lean",
                "verification": {
                    "target_module": "Problem",
                    "target_decl": "Problem.Target",
                    "entry_module": "Submission",
                    "entry_decl": "Submission.solution",
                    "permitted_axioms": [],
                },
                "files": [
                    {"path": "Problem.lean", "mode": "readonly", "build_order": 0, "content": "def Target : Prop := True\n"},
                    {"path": "Submission.lean", "mode": "writable", "build_order": 1, "content": "import Problem\n"},
                ],
            },
        }

    def _submission_list_payload(self):
        return {
            **self._noise(),
            "count": 1,
            "page": 1,
            "submissions": [{"id": 1, "username": "alice", "problem_id": 1, "status": "Accepted", **self._noise()}],
        }

    def _submission_problem_payload(self):
        payload = self._submission_list_payload()
        payload["problem_id"] = 1
        return payload

    def _submission_status_payload(self):
        return {
            **self._noise(),
            "status": "Unaccepted",
            "score": 50,
            "test_points": [
                {"test_index": 1, "status": "Accepted", **self._noise()},
                {"test_index": 2, "status": "Wrong Answer", "stdout": "bad", **self._noise()},
            ],
        }

    def _submission_detail_payload(self):
        return {
            **self._noise(),
            "submission": {"id": 1, "username": "alice", "problem_id": 1, "code": "x" * 100, "status": "Accepted"},
            "problem": {"id": 1, "title": "题", "lang": "matlab"},
            "test_points": [{"test_index": 1, "status": "Accepted", **self._noise()}],
        }

    def _homework_list_payload(self):
        return {
            **self._noise(),
            "selected_class": "C1",
            "homeworks": [{"id": 1, "title": "作业"}],
            "classes": [{"class_en": "C1"}],
            "all_problems": [{"id": 1}],
            "all_competitions": [{"id": 1}],
        }

    def _user_list_payload(self):
        return {
            **self._noise(),
            "page": 1,
            "per_page": 20,
            "total": 1,
            "users": [{"id": 1, "username": "admin", **self._noise()}],
            "classes": [{"class_en": "C1"}],
        }

    def _ranking_list_payload(self):
        return {
            **self._noise(),
            "count": 1,
            "competitions": [{"id": 1, "title": "赛", "description": "列表不需要长描述", **self._noise()}],
        }

    def _ranking_detail_payload(self):
        return {
            **self._noise(),
            "competition": {"id": 1, "title": "赛", "description": "详情需要描述", **self._noise()},
            "tab": "leaderboard",
            "files": [{"id": 1, "filename": "a.zip", **self._noise()}],
            "submissions": [{"id": 1, "competition_id": 1, **self._noise()}],
            "leaderboard": [{"username": "alice", "score": 1}],
            "matches": [{"id": 1, "details": {}, **self._noise()}],
            "page_numbers": [1, 2],
        }


def _leaf_command_paths(parser):
    import argparse

    paths = []

    def walk(node, path=()):
        sub_actions = [action for action in node._actions if isinstance(action, argparse._SubParsersAction)]
        if not sub_actions:
            paths.append(path)
            return
        for action in sub_actions:
            for name, subparser in action.choices.items():
                walk(subparser, path + (name,))

    walk(parser)
    return paths


def _assert_no_redundant_keys(payload, banned, path="$"):
    if isinstance(payload, dict):
        forbidden = sorted(key for key in payload if key in banned)
        assert not forbidden, f"{path} contains redundant keys: {forbidden}"
        for key, value in payload.items():
            _assert_no_redundant_keys(value, banned, f"{path}.{key}")
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            _assert_no_redundant_keys(value, banned, f"{path}[{index}]")


def test_numoj_admin_all_default_commands_prune_redundant_output_except_full_submission(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_admin_cli_module()
    parser = cli.build_parser()
    fake_client = _HygieneClient()

    for module in (
        cli.ai,
        cli.ai_detection,
        cli.auth,
        cli.forum,
        cli.grading,
        cli.homework,
        cli.me,
        cli.problem,
        cli.ranking,
        cli.repository,
        cli.site,
        cli.submission,
        cli.user,
        cli.vibehub,
    ):
        monkeypatch.setattr(module, "client_from_args", lambda _args, client=fake_client: client)
    monkeypatch.setattr(cli.site_config.common, "client_from_args", lambda _args: fake_client)

    monkeypatch.setattr(cli.auth.requests, "Session", _LoginSession)
    monkeypatch.setattr(cli.auth, "load_config", lambda _path: {"base_url": "http://oj", "username": "admin", "cookies": {"session": "x"}})
    monkeypatch.setattr(cli.auth, "save_config", lambda _path, _cfg: None)
    monkeypatch.setattr(cli.auth, "NumOJClient", lambda _cfg, timeout=60.0: fake_client)
    monkeypatch.setattr(cli.me, "load_config", lambda _path: {"username": "admin"})

    fixture_file = tmp_path / "fixture.txt"
    fixture_file.write_text("payload", encoding="utf-8")
    fixture_zip = tmp_path / "fixture.zip"
    fixture_zip.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    output_file = tmp_path / "out.bin"

    command_argvs = [
        ["init", "--base-url", "http://oj", "-u", "admin", "-p", "pw"],
        ["site", "home"],
        ["site-config", "meta"],
        ["site-config", "llm", "list"],
        ["site-config", "llm", "test", "1"],
        [
            "site-config", "llm", "create", "--protocol", "openai",
            "--category", "text", "--endpoint-base-url", "http://model",
            "--api-key", "key", "--model", "model",
            "--input-price-per-million", "1",
            "--cached-input-price-per-million", "0.5",
            "--output-price-per-million", "2",
        ],
        ["site-config", "llm", "update", "1", "--model", "model-v2"],
        ["site-config", "llm", "delete", "1"],
        ["site-config", "llm", "lock", "1", "--reason", "verified"],
        ["site-config", "llm", "unlock", "1", "--password", "pw", "--confirmation", "confirm"],
        ["site-config", "binding", "list"],
        ["site-config", "binding", "set", "ai_code_annotation", "--endpoint-id", "1"],
        ["site-config", "binding", "lock-embedding", "--reason", "verified"],
        ["site-config", "binding", "unlock-embedding", "--password", "pw", "--confirmation", "confirm"],
        ["site-config", "mail", "get"],
        ["site-config", "mail", "test"],
        ["site-config", "mail", "set", "--smtp-server", "smtp.example.com", "--smtp-port", "465", "--smtp-username", "admin@example.com", "--smtp-password", "secret"],
        ["site-config", "mail", "clear"],
        ["site-config", "web-search", "get"],
        ["site-config", "web-search", "test"],
        ["site-config", "web-search", "set", "--search-base-url", "http://search", "--authorization", "secret"],
        ["site-config", "web-search", "clear"],
        ["auth", "login", "--base-url", "http://oj", "-u", "admin", "-p", "pw"],
        ["auth", "logout"],
        ["auth", "status"],
        ["auth", "send-password-code"],
        ["auth", "change-password", "--code", "123456", "--new-password", "pw"],
        ["me", "classes"],
        ["me", "join-class", "C1"],
        ["me", "leave-class", "C1"],
        ["me", "grades", "--user-id", "1"],
        ["me", "submissions"],
        ["submission", "list"],
        ["submission", "problem", "1"],
        ["submission", "status", "1"],
        ["submission", "stream", "1"],
        ["submission", "detail", "1"],
        ["submission", "last-code", "1"],
        ["submission", "output-image", "1", "1", "-o", str(output_file)],
        ["submission", "download-file", "1", "-o", str(output_file)],
        ["problem", "list"],
        ["problem", "detail", "1"],
        ["problem", "submit-page", "1"],
        ["problem", "submit", "1", "--code", "disp(1)"],
        ["problem", "create-form"],
        ["problem", "create", "--title", "题", "--content", "题面"],
        ["problem", "edit-form", "1"],
        ["problem", "edit", "1"],
        ["problem", "delete", "1"],
        ["problem", "upload-testdata", "1", str(fixture_zip)],
        ["problem", "lean-workspace", "1"],
        ["problem", "lean-init", "1", str(tmp_path / "lean-workspace")],
        ["problem", "lean-upload", "1", str(fixture_zip)],
        ["problem", "lean-download", "1", "-o", str(output_file)],
        ["problem", "rejudge", "1"],
        ["problem", "rejudge-status", "1"],
        ["problem", "rejudge-time-range", "--start", "2026-01-01T00:00", "--end", "2026-01-02T00:00"],
        ["problem", "rejudge-time-range-status"],
        ["problem", "agent-run-status", "task-1"],
        ["problem", "agent-run", "task-1"],
        ["problem", "agent-run-stream", "task-1"],
        ["problem", "agent-tasks"],
        [
            "problem", "agent-solve", "1", "--harness", "codex",
            "--endpoint-id", "1",
        ],
        [
            "problem", "agent-generate-data", "1", "--harness", "codex",
            "--endpoint-id", "1", "--count", "1", "--standard-solution",
            str(fixture_file),
        ],
        ["problem", "scores", "1"],
        ["homework", "list"],
        ["homework", "add", "--class-en", "C1", "--ddl", "2026-01-01T00:00", "--problem-id", "1"],
        ["homework", "update-ddl", "--class-en", "C1", "--homework-id", "1", "--ddl", "2026-01-02T00:00"],
        ["homework", "delete", "--class-en", "C1", "--homework-id", "1"],
        ["homework", "export-scores", "--class-en", "C1", "-o", str(output_file)],
        ["homework", "export-codes", "--class-en", "C1"],
        ["homework", "export-progress", "task-1"],
        ["homework", "download-export", "task-1", "-o", str(output_file)],
        ["homework", "plagiarism-start", "--class-en", "C1", "--targets", "problem:1"],
        ["homework", "plagiarism-progress", "task-1"],
        ["homework", "plagiarism-records", "--class-en", "C1"],
        ["homework", "plagiarism-download", "--class-en", "C1", "-o", str(output_file)],
        ["homework", "plagiarism-delete", "--class-en", "C1", "--record-ids", "1"],
        ["homework", "upload-exam", "--class-en", "C1", str(fixture_file)],
        ["homework", "class-adjust", "1"],
        ["user", "list"],
        ["user", "add-class-type", "--class-en", "1", "--class-cn", "一班"],
        ["user", "grant-admin", "1"],
        ["user", "rename", "1", "admin2"],
        ["user", "add-to-class", "1", "C1"],
        ["user", "remove-from-class", "1", "C1"],
        ["user", "grades", "1"],
        ["user", "update-grade", "1", "1", "--score", "90"],
        ["grading", "submit", "1", "--score", "90"],
        ["grading", "next-pending", "1"],
        ["grading", "invalidate-invalid", "1"],
        ["forum", "list"],
        ["forum", "thread", "1"],
        ["forum", "new-page"],
        ["forum", "new", "--title", "帖", "--content", "正文"],
        ["forum", "reply", "1", "--content", "回复"],
        ["forum", "reply-thread", "1", "--content", "回复"],
        ["repository", "page"],
        ["repository", "files"],
        ["repository", "get", "1"],
        ["repository", "save", "--filename", "a.m", "--content", "disp(1)"],
        ["repository", "delete", "1"],
        ["repository", "upload", str(fixture_file)],
        ["repository", "build-index"],
        ["repository", "rebuild-file", "1"],
        ["repository", "index-status", "1"],
        ["repository", "active-status"],
        ["repository", "search", "--query", "vector"],
        ["repository", "classes"],
        ["ai", "marks", "--submission-id", "1"],
        ["ai-detection", "dashboard"],
        ["ai-detection", "problem-page", "1"],
        ["ai-detection", "student-page", "alice"],
        ["ai-detection", "preview"],
        ["ai-detection", "run-filtered", "--submission-id", "1", "--endpoint-id", "1"],
        ["ai-detection", "run-problem", "1", "--endpoint-id", "1"],
        ["ai-detection", "run-single", "1", "--endpoint-id", "1"],
        ["ai-detection", "run-user", "alice", "--endpoint-id", "1"],
        ["ai-detection", "summary"],
        ["ai-detection", "tasks"],
        ["ai-detection", "models"],
        ["ai-detection", "task", "stop", "task-1"],
        ["ranking", "list"],
        ["ranking", "detail", "1"],
        ["ranking", "create", "--title", "赛"],
        ["ranking", "copy", "1"],
        ["ranking", "edit", "1"],
        ["ranking", "delete", "1"],
        ["ranking", "upload-attachment", "1", str(fixture_file)],
        ["ranking", "delete-attachment", "1", "1"],
        ["ranking", "download-attachment", "1", "1", "-o", str(output_file)],
        ["ranking", "upload-reference", "1", str(fixture_file)],
        ["ranking", "upload-script", "1", str(fixture_file)],
        ["ranking", "clear-script", "1"],
        ["ranking", "reset-limit", "1"],
        ["ranking", "save-rules", "1", '[{"name":"rule"}]'],
        ["ranking", "save-endpoints", "1", '[{"url":"http://model"}]'],
        ["ranking", "save-endpoint", "1", "--agent-base-url", "http://model", "--api-key", "key", "--model", "generic-model"],
        ["ranking", "save-quality-gate", "1", "--disabled", "--prompt", "审核提示"],
        ["ranking", "save-quality-gate-endpoints", "1", "[]"],
        ["ranking", "save-quality-gate-endpoint", "1", "--agent-base-url", "http://quality", "--api-key", "key", "--model", "generic-model"],
        ["ranking", "batch-probe", "1", "--classes", "C1", "--template", "https://git/{username}"],
        ["ranking", "batch-status", "1", "job-1"],
        ["ranking", "batch-create", "1", "--template", "https://git/{username}", "--usernames", "alice"],
        ["ranking", "matches", "1"],
        ["ranking", "match-detail", "1", "1"],
        ["ranking", "bulk-filter", "1"],
        ["ranking", "bulk-start", "1", "--submission-ids", "1"],
        ["ranking", "bulk-status", "1", "job-1"],
        ["ranking", "rejudge-agent", "1", "1"],
        ["ranking", "appeal", "1", "1", "--reason", "理由"],
        ["ranking", "appeal-status", "1", "1"],
        ["ranking", "appeals", "1"],
        ["ranking", "appeal-review", "1", "1"],
        ["ranking", "appeal-handle", "1", "1", "--decision", "resolved"],
        ["ranking", "elo-start", "1"],
        ["ranking", "elo-stop", "1"],
        ["ranking", "elo-reset", "1"],
        ["ranking", "elo-delete-match", "1", "1"],
        ["ranking", "elo-rebuild", "1"],
        ["ranking", "delete-submission", "1", "1"],
        ["ranking", "download-submission", "1", "answer", "-o", str(output_file)],
        ["ranking", "judge-stream", "1", "1"],
        ["ranking", "reverse-stream", "1", "1"],
        ["ranking", "my-submissions", "1"],
        ["ranking", "submissions", "1"],
        ["ranking", "leaderboard", "1"],
        ["ranking", "submit", "1", "--base-model", "baseline", "--code-zip", str(fixture_zip)],
        ["ranking", "submit-zip", "1", "--base-model", "baseline", "--code-zip", str(fixture_zip)],
        ["ranking", "submit", "1", "--code-zip", str(fixture_zip)],
        ["ranking", "git", "1", "check"],
        ["ranking", "git", "1", "submit"],
        ["vibehub", "guide"],
        ["vibehub", "list"],
        ["vibehub", "mine"],
        ["vibehub", "detail", "demo-vibe"],
        ["vibehub", "create", str(fixture_zip), "--title", "Demo"],
        ["vibehub", "update", "demo-vibe", str(fixture_zip)],
        ["vibehub", "edit", "demo-vibe", "--summary", "updated"],
        ["vibehub", "pending"],
        ["vibehub", "review", "demo-vibe", "approve", "--expected-version", "1"],
        ["vibehub", "featured", "demo-vibe", "on"],
    ]

    expected_paths = {" ".join(path) for path in _leaf_command_paths(parser)}
    actual_paths = {" ".join(argv[: len(path)]) for argv in command_argvs for path in _leaf_command_paths(parser) if tuple(argv[: len(path)]) == path}
    assert actual_paths == expected_paths

    full_submission_commands = {
        ("submission", "status"),
        ("submission", "detail"),
        ("submission", "last-code"),
    }

    for argv in command_argvs:
        assert cli.main(argv) == 0, argv
        stdout = capsys.readouterr().out
        assert stdout.strip(), argv
        payload = cli.json.loads(stdout)
        if tuple(argv[:2]) in full_submission_commands:
            continue
        try:
            _assert_no_redundant_keys(payload, cli.common.REDUNDANT_JSON_KEYS)
        except AssertionError as exc:
            raise AssertionError(f"{argv}: {exc}") from exc
