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
        monkeypatch.setitem(func.__globals__, "client_from_args", lambda _args: fake_client)
        func(args)
        assert fake_client.requests[-1][1] == expected_path


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

    rc = cli.main(["ai-detection", "run-filtered"])

    assert rc == 2
    payload = cli.json.loads(capsys.readouterr().out)
    assert payload["success"] is False
    assert "requires at least one filter" in payload["message"]


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
            "base_url": "http://single-quality.local",
            "api_key": "secret-from-env",
            "model": "single-quality-model",
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
                "files": [{"id": 1, "filename": "a.m", "file_size": 6, **self._noise()}],
            })
        if path == "/api/repository/file/1":
            return _PayloadResponse({**self._noise(), "filename": "a.m", "content": "disp(1)"})
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
    ):
        monkeypatch.setattr(module, "client_from_args", lambda _args, client=fake_client: client)

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
        ["auth", "login", "--base-url", "http://oj", "-u", "admin", "-p", "pw"],
        ["auth", "logout"],
        ["auth", "status"],
        ["auth", "send-password-code"],
        ["auth", "change-password", "--code", "123456", "--new-password", "pw"],
        ["me", "classes"],
        ["me", "join-class", "C1"],
        ["me", "leave-class", "C1"],
        ["me", "set-primary-class", "C1"],
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
        ["problem", "rejudge", "1"],
        ["problem", "rejudge-status", "1"],
        ["problem", "rejudge-time-range", "--start", "2026-01-01T00:00", "--end", "2026-01-02T00:00"],
        ["problem", "rejudge-time-range-status"],
        ["problem", "agent-run-status", "task-1"],
        ["problem", "agent-run", "task-1"],
        ["problem", "agent-run-stream", "task-1"],
        ["problem", "agent-tasks"],
        ["problem", "agent-solve", "1"],
        ["problem", "agent-generate-data", "1", "--count", "1", "--standard-code", "disp(1)"],
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
        ["user", "set-primary-class", "1", "C1"],
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
        ["ai-detection", "run-filtered", "--submission-id", "1"],
        ["ai-detection", "run-problem", "1"],
        ["ai-detection", "run-single", "1"],
        ["ai-detection", "run-user", "alice"],
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
        ["ranking", "save-config", "1", "--model", "qwen"],
        ["ranking", "save-rules", "1", '[{"name":"rule"}]'],
        ["ranking", "save-endpoints", "1", '[{"url":"http://model"}]'],
        ["ranking", "save-endpoint", "1", "--agent-base-url", "http://model", "--api-key", "key", "--model", "qwen"],
        ["ranking", "save-quality-gate", "1", "--disabled", "--prompt", "审核提示"],
        ["ranking", "save-quality-gate-endpoints", "1", "[]"],
        ["ranking", "save-quality-gate-endpoint", "1", "--agent-base-url", "http://quality", "--api-key", "key", "--model", "qwen"],
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
