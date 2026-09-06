# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
import uuid
from argparse import Namespace
from pathlib import Path

import pytest


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


class _StatusPayloadResponse(_PayloadResponse):
    def __init__(self, status_code, payload):
        super().__init__(payload)
        self.status_code = status_code


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


class _SequenceClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        assert self.responses
        return self.responses.pop(0)


class _StreamResponse(_FakeResponse):
    headers = {"Content-Type": "text/event-stream"}

    def __init__(self, payload):
        import json

        self.text = f"event: done\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
        self.content = self.text.encode("utf-8")

    def iter_lines(self, decode_unicode=False):
        for line in self.text.splitlines():
            yield line if decode_unicode else line.encode("utf-8")


def test_me_classes_projects_equal_membership_contract(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "memberships": [
            {"class_en": "C1", "class_cn": "一班"},
            {"class_en": "C2", "class_cn": "二班"},
        ],
        "all_classes": [
            {"class_en": "C1", "class_cn": "一班"},
            {"class_en": "C2", "class_cn": "二班"},
            {"class_en": "C3", "class_cn": "三班"},
        ],
        "internal": "hidden",
    }
    monkeypatch.setattr(
        fake_client,
        "request",
        lambda *args, **kwargs: _PayloadResponse(payload),
    )
    monkeypatch.setattr(
        cli.common,
        "client_from_args",
        lambda _args, **_kwargs: fake_client,
    )

    cli.me_classes(Namespace())

    assert cli.json.loads(capsys.readouterr().out) == {
        "memberships": payload["memberships"],
        "all_classes": payload["all_classes"],
    }


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


def test_problem_list_falls_back_to_flat_visible_problems(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": True,
        "homeworks_by_class": [
            {
                "class_en": "Cclass1",
                "hw_list": [{"problem_id": 1, "problem_title": "unlimited source"}],
            }
        ],
        "problems": [
            {
                "kind": "problem",
                "id": 2,
                "problem_id": 2,
                "title": "limited flat row",
                "class_en": "Cclass2",
            }
        ],
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _PayloadResponse(payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.problem_list(Namespace(limit=1))

    assert cli.json.loads(capsys.readouterr().out) == {"homeworks": payload["problems"]}


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
        "submit_block_code": "",
        "submit_block_reason": "",
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
        "submit_block_code": "",
        "submit_block_reason": "",
        "remaining_submissions": 4,
        "submit": {
            "help_text": "请提交 prompt。",
            "input_kind": "prompt",
        },
    }


def test_problem_download_writes_statement_and_ordinary_initial_code(
    monkeypatch, capsys, tmp_path
):
    cli = _load_numoj_user_cli_module()
    payload = _problem_detail_payload()
    client = _SequenceClient([_PayloadResponse(payload)])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)
    workspace = tmp_path / "workspace"

    cli.problem_download(Namespace(
        problem_id=42,
        output=str(workspace),
        force=False,
    ))

    assert client.requests == [("GET", "/api/problems/42", {})]
    assert (workspace / "PROBLEM.md").read_text(encoding="utf-8") == (
        payload["problem"]["content"]
    )
    assert (workspace / "solution.cpp").read_text(encoding="utf-8") == (
        payload["initial_code"]
    )
    snapshot = cli.json.loads(
        (workspace / "numoj-problem.json").read_text(encoding="utf-8")
    )
    assert snapshot == {
        "schema_version": 1,
        "problem_id": 42,
        "submit_kind": "prompt",
        "problem": {"title": "Slitherlink", "lang": "cpp", "type": 1},
        "resources": ["PROBLEM.md", "solution.cpp"],
    }
    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "problem_id": 42,
        "path": str(workspace.resolve()),
        "files": ["PROBLEM.md", "solution.cpp", "numoj-problem.json"],
    }


def test_problem_download_writes_all_lean_files_and_generic_snapshot(
    monkeypatch, capsys, tmp_path
):
    cli = _load_numoj_user_cli_module()
    payload = {
        "success": True,
        "problem": {
            "id": 42,
            "title": "Lean theorem",
            "content": "Prove it.",
            "lang": "lean4",
            "type": 1,
        },
        "initial_code": "do not create solution.lean",
        "submit": {"input_kind": "lean_workspace"},
        "user": {"username": "must-not-enter-snapshot"},
        "lean_workspace": {
            "schema_version": 1,
            "revision": "revision-2",
            "revision_number": 2,
            "default_file": "Submission.lean",
            "verification": {
                "entry_decl": "Submission.answer",
                "allowed_axioms": ["propext"],
            },
            "files": [
                {
                    "path": "Submission.lean",
                    "mode": "writable",
                    "build_order": 2,
                    "content": "theorem answer : True := by trivial\n",
                },
                {
                    "path": "Problem/Statement.lean",
                    "mode": "readonly",
                    "build_order": 1,
                    "content": "def statement : Prop := True\n",
                },
            ],
        },
    }
    client = _SequenceClient([_PayloadResponse(payload)])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)
    workspace = tmp_path / "workspace"

    cli.problem_download(Namespace(
        problem_id=42,
        output=str(workspace),
        force=False,
    ))

    assert (workspace / "PROBLEM.md").read_text(encoding="utf-8") == "Prove it."
    assert (workspace / "Problem/Statement.lean").read_text(encoding="utf-8") == (
        "def statement : Prop := True\n"
    )
    assert (workspace / "Submission.lean").read_text(encoding="utf-8") == (
        "theorem answer : True := by trivial\n"
    )
    assert not (workspace / "solution.lean").exists()
    snapshot = cli.json.loads(
        (workspace / "numoj-problem.json").read_text(encoding="utf-8")
    )
    assert snapshot["problem_id"] == 42
    assert snapshot["submit_kind"] == "lean_workspace"
    assert snapshot["lean_workspace"] == {
        "schema_version": 1,
        "revision": "revision-2",
        "default_file": "Submission.lean",
        "files": [
            {
                "path": "Problem/Statement.lean",
                "mode": "readonly",
                "build_order": 1,
            },
            {
                "path": "Submission.lean",
                "mode": "writable",
                "build_order": 2,
            },
        ],
        "build_order": ["Problem/Statement.lean", "Submission.lean"],
        "verification": {
            "entry_decl": "Submission.answer",
            "allowed_axioms": ["propext"],
        },
    }
    assert "user" not in snapshot
    capsys.readouterr()


def test_problem_download_refuses_overwrite_without_force(monkeypatch, tmp_path):
    cli = _load_numoj_user_cli_module()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "PROBLEM.md").write_text("local work", encoding="utf-8")
    payload = _problem_detail_payload()
    client = _SequenceClient([
        _PayloadResponse(payload),
        _PayloadResponse(payload),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

    with pytest.raises(cli.CliError, match="Refusing to overwrite"):
        cli.problem_download(Namespace(
            problem_id=42,
            output=str(workspace),
            force=False,
        ))

    assert (workspace / "PROBLEM.md").read_text(encoding="utf-8") == "local work"
    assert not (workspace / "solution.cpp").exists()

    cli.problem_download(Namespace(
        problem_id=42,
        output=str(workspace),
        force=True,
    ))

    assert (workspace / "PROBLEM.md").read_text(encoding="utf-8") == (
        payload["problem"]["content"]
    )
    assert (workspace / "solution.cpp").is_file()


def test_lean_workspace_submit_uses_generic_snapshot_and_json_api_contract(
    monkeypatch, capsys, tmp_path
):
    cli = _load_numoj_user_cli_module()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "numoj-problem.json").write_text(
        cli.json.dumps(
            {
                "schema_version": 1,
                "problem_id": 42,
                "submit_kind": "lean_workspace",
                "lean_workspace": {
                    "revision": "revision-1",
                    "files": [
                        {"path": "Problem.lean", "mode": "readonly"},
                        {"path": "Submission.lean", "mode": "writable"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    (workspace / "Submission.lean").write_text(
        "theorem answer : True := by trivial\n",
        encoding="utf-8",
    )

    client = _SequenceClient([
        _PayloadResponse({"submit": {"input_kind": "lean_workspace"}}),
        _StatusPayloadResponse(201, {"success": True, "submission_id": 321}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

    cli.problem_submit(Namespace(
        problem_id=42,
        workspace=str(workspace),
        file=None,
        code=None,
        code_file=None,
        prompt=None,
        prompt_file=None,
    ))

    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "submission_id": 321,
    }
    method, path, kwargs = client.requests[1]
    assert (method, path) == ("POST", "/api/problems/42/submissions")
    assert "json" not in kwargs
    assert kwargs["headers"] == {"Accept": "application/json"}
    assert cli.json.loads(kwargs["data"]["lean_workspace"]) == {
        "revision": "revision-1",
        "files": {
            "Submission.lean": "theorem answer : True := by trivial\n"
        },
    }


def test_problem_submit_preserves_server_deadline_warning_after_success(
    monkeypatch, capsys
):
    cli = _load_numoj_user_cli_module()
    warning = {
        "code": "homework_deadline_passed",
        "message": "本次提交不计入一班的作业成绩",
        "homeworks": [{
            "homework_id": 3,
            "class_en": "C1",
            "class_cn": "一班",
            "ddl": "01-01 00:00",
        }],
    }
    client = _SequenceClient([
        _PayloadResponse({
            "can_submit": True,
            "submit_block_code": "",
            "submit_block_reason": "",
            "submit_warning": warning,
            "submit": {"input_kind": "code"},
        }),
        _StatusPayloadResponse(201, {
            "success": True,
            "submission_id": 91,
            "warning": warning,
        }),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

    cli.problem_submit(Namespace(
        problem_id=42,
        workspace=None,
        file=None,
        code="print('hello')",
        code_file=None,
        prompt=None,
        prompt_file=None,
    ))

    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "submission_id": 91,
        "warning": warning,
    }
    assert len(client.requests) == 2
    assert client.requests[1] == (
        "POST",
        "/api/problems/42/submissions",
        {
            "data": {"code": "print('hello')"},
            "headers": {"Accept": "application/json"},
        },
    )


def test_lean_workspace_submit_accepts_legacy_manifest_fallback(
    monkeypatch, capsys, tmp_path
):
    cli = _load_numoj_user_cli_module()
    workspace = tmp_path / "legacy-workspace"
    workspace.mkdir()
    (workspace / "numoj-lean.json").write_text(
        cli.json.dumps({
            "problem_id": 42,
            "revision": "legacy-revision",
            "files": [{"path": "Submission.lean", "mode": "writable"}],
        }),
        encoding="utf-8",
    )
    (workspace / "Submission.lean").write_text("example : True := by trivial\n")

    client = _SequenceClient([
        _PayloadResponse({"submit": {"input_kind": "lean_workspace"}}),
        _StatusPayloadResponse(201, {"success": True, "submission_id": 322}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

    cli.problem_submit(Namespace(
        problem_id=42,
        workspace=str(workspace),
        file=None,
        code=None,
        code_file=None,
        prompt=None,
        prompt_file=None,
    ))

    payload = cli.json.loads(client.requests[1][2]["data"]["lean_workspace"])
    assert payload == {
        "revision": "legacy-revision",
        "files": {"Submission.lean": "example : True := by trivial\n"},
    }
    assert cli.json.loads(capsys.readouterr().out)["submission_id"] == 322


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


def test_repository_build_index_outputs_need_confirm_payload(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    payload = {
        "success": False,
        "need_confirm": True,
        "active_job_id": 123,
        "message": "上一个整理任务正在运行，是否终止？",
    }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _StatusPayloadResponse(409, payload))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.repository_build_index(Namespace(force_restart=False))

    assert cli.json.loads(capsys.readouterr().out) == payload


def test_repository_save_create_sends_current_structure_version(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "structure_version": 12, "files": []}),
        _PayloadResponse({"success": True, "file_id": 9}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

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
    cli = _load_numoj_user_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "id": 9, "file_version": 7, "content": "old"}),
        _PayloadResponse({"success": True, "file_id": 9}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

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
    cli = _load_numoj_user_cli_module()
    client = _SequenceClient([
        _PayloadResponse({"success": True, "structure_version": 21, "files": []}),
        _PayloadResponse({"success": True, "file_id": 3}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)
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


def test_repository_delete_confirms_once_with_server_token(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    client = _SequenceClient([
        _StatusPayloadResponse(409, {
            "success": False,
            "code": "confirmation_required",
            "confirmation_token": "delete-token",
        }),
        _PayloadResponse({"success": True, "deleted": True}),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

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
    cli = _load_numoj_user_cli_module()
    client = _SequenceClient([
        _StatusPayloadResponse(409, {
            "success": False,
            "code": "structure_conflict",
            "message": "repository changed",
        }),
    ])
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: client)

    with pytest.raises(cli.common.CliError, match="HTTP 409"):
        cli.repository_delete_file(Namespace(file_id=9))

    assert client.requests == [("DELETE", "/api/repository/file/9", {})]


def test_forum_reply_rejects_blank_content(monkeypatch):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    with pytest.raises(cli.common.CliError, match="Reply content cannot be empty"):
        cli.forum_reply(Namespace(thread_id=7, content="   "))

    assert fake_client.requests == []


def test_forum_write_commands_use_json_api_and_uuid(monkeypatch, capsys):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

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
    args = parser.parse_args(["problem", "download", "42", "-o", "/tmp/problem"])
    assert args.output == "/tmp/problem"
    assert args.force is False
    args = parser.parse_args(["submission", "output-image", "123", "0", "-o", "/tmp/out.bmp"])
    assert args.output == "/tmp/out.bmp"
    args = parser.parse_args(["submission", "last-code", "42", "-o", "/tmp/solution.py"])
    assert args.output == "/tmp/solution.py"


@pytest.mark.parametrize("command", ["lean-workspace", "lean-init"])
def test_numoj_user_problem_removes_lean_specific_download_commands(command):
    cli = _load_numoj_user_cli_module()

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["problem", command, "42"])


def test_user_ranking_submit_allows_missing_base_model_and_omits_it_from_request(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_user_cli_module()
    parser = cli.build_parser()
    parsed = parser.parse_args(["ranking", "submit", "9", "--code-zip", str(tmp_path / "problem.zip")])
    assert parsed.base_model is None

    problem_zip = tmp_path / "problem.zip"
    problem_zip.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    class _SubmitClient(_FakeClient):
        def __init__(self):
            super().__init__()
            self.submitted = False

        def request(self, method, path, **kwargs):
            self.requests.append((method, path, kwargs))
            if path.endswith("/my-submissions"):
                rows = [{"id": 41}] if self.submitted else []
                return _PayloadResponse({"submissions": rows})
            if path == "/api/ranking/competitions/9/submissions":
                self.submitted = True
                return _PayloadResponse({"success": True})
            raise AssertionError(path)

    fake_client = _SubmitClient()
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)
    cli.ranking_submit(Namespace(
        competition_id=9,
        base_model=None,
        code_zip=str(problem_zip),
        answer_file=None,
        agent_endpoint_id=7,
    ))

    assert cli.json.loads(capsys.readouterr().out) == {"success": True, "submission_id": 41}
    submit_request = next(
        request
        for request in fake_client.requests
        if request[:2] == ("POST", "/api/ranking/competitions/9/submissions")
    )
    assert submit_request[2]["data"] == {"agent_endpoint_id": "7"}


def test_user_ranking_submit_confirms_creation_after_a_proxy_5xx(monkeypatch, capsys, tmp_path):
    cli = _load_numoj_user_cli_module()
    problem_zip = tmp_path / "submission.zip"
    problem_zip.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

    class _SubmitClient(_FakeClient):
        def __init__(self):
            super().__init__()
            self.submitted = False

        def request(self, method, path, **kwargs):
            self.requests.append((method, path, kwargs))
            if path.endswith("/my-submissions"):
                rows = [{"id": 42}] if self.submitted else []
                return _PayloadResponse({"submissions": rows})
            if path == "/api/ranking/competitions/9/submissions":
                self.submitted = True
                return _StatusPayloadResponse(502, {"message": "upstream redirect failed"})
            raise AssertionError(path)

    fake_client = _SubmitClient()
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.ranking_submit(Namespace(
        competition_id=9,
        base_model="search-bot",
        code_zip=str(problem_zip),
        answer_file=None,
        agent_endpoint_id=None,
    ))

    assert cli.json.loads(capsys.readouterr().out) == {
        "success": True,
        "submission_id": 42,
        "recovered_from_transport_error": True,
        "message": "提交接口返回 HTTP 502，但已确认提交 #42 已创建；请不要重复提交。",
    }


@pytest.mark.parametrize("new_result", [False, True])
def test_user_reverse_stream_projects_four_steps_without_internal_fields(monkeypatch, capsys, new_result):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    snapshot = {
        "submission_id": 12,
        "status": "Error",
        "steps": [
            {"step_key": "solution_check", "title": "标准答案自检", "status": "passed", "stdout": "hidden"},
            {
                "step_key": "quality_gate",
                "title": "质量门禁",
                "status": "failed",
                "result": {
                    "passed": False,
                    "verdict": "reject",
                    "summary": "不合规",
                    "violations": ["存在私有密码"],
                    "raw_model_response": "hidden",
                },
            },
            {"step_key": "agent_answer", "title": "AI 作答", "status": "pending"},
            {"step_key": "ai_judge", "title": "评测 AI 答案", "status": "pending"},
        ],
        "quality_gate_endpoints": [{"id": 99, "api_key": "must-not-leak"}],
    }
    if new_result:
        snapshot["steps"][1]["result"] = {
            "passed": False,
            "reason": "题目未通过质量门禁，请检查题目包后重试",
        }
    monkeypatch.setattr(fake_client, "request", lambda *args, **kwargs: _StreamResponse(snapshot))
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)

    cli.ranking_reverse_judge_stream(Namespace(competition_id=3, submission_id=12, max_lines=20))

    out = cli.json.loads(capsys.readouterr().out)
    assert [step["step_key"] for step in out["latest"]["steps"]] == [
        "solution_check",
        "quality_gate",
        "agent_answer",
        "ai_judge",
    ]
    gate = out["latest"]["steps"][1]
    assert gate["passed"] is False
    if new_result:
        assert gate["reason"] == "题目未通过质量门禁，请检查题目包后重试"
        assert not {"verdict", "summary", "violations"}.intersection(gate)
    else:
        assert gate["verdict"] == "reject"
        assert gate["summary"] == "不合规"
        assert gate["violations"] == ["存在私有密码"]
    assert "quality_gate_endpoints" not in out["latest"]
    assert "stdout" not in out["latest"]["steps"][0]
    assert "raw_model_response" not in gate


def test_user_ranking_submission_projection_keeps_ai_answer_metadata_and_filters_internal_fields():
    cli = _load_numoj_user_cli_module()

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


def test_user_reverse_snapshot_projects_agent_availability_only():
    cli = _load_numoj_user_cli_module()

    projected = cli.necessary_reverse_judge_snapshot_payload({
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


def test_user_ranking_download_submission_routes_and_saves_all_supported_artifacts(monkeypatch):
    cli = _load_numoj_user_cli_module()
    fake_client = _FakeClient()
    saved = []
    monkeypatch.setattr(cli.common, "client_from_args", lambda _args, **_kwargs: fake_client)
    monkeypatch.setattr(
        cli.common,
        "print_or_save_response",
        lambda response, **kwargs: saved.append((response, kwargs)),
    )

    cases = [
        ("ai-answer", "/tmp/ai-answer.zip", "/api/ranking/submissions/9/reverse-agent-answer"),
        ("answer", None, "/api/ranking/submissions/9/answer"),
        ("code", "/tmp/code.zip", "/api/ranking/submissions/9/code"),
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


def test_user_ranking_parser_supports_ai_answer_choice():
    cli = _load_numoj_user_cli_module()
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
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["ranking", "download-submission", "9", "invalid"])
    assert exc_info.value.code == 2


def test_user_ranking_detail_projects_only_safe_answer_endpoints():
    cli = _load_numoj_user_cli_module()

    projected = cli.necessary_ranking_detail_payload({
        "competition": {
            "id": 3,
            "title": "反向赛",
            "description": "公开题面",
            "reverse_quality_gate_enabled": 1,
            "reverse_quality_gate_prompt": "管理员私有审核标准",
        },
        "quality_gate_endpoints": [
            {"id": 99, "base_url": "http://quality.local", "api_key": "secret"}
        ],
        "answer_endpoints": [{
            "id": 7,
            "harness": "pi",
            "model": "gpt-answer",
            "label": "Pi (gpt-answer)",
            "base_url": "http://answer.local",
            "api_key": "answer-secret",
            "status": "enabled",
            "pool_kind": "primary",
        }],
    })

    assert "reverse_quality_gate_enabled" not in projected["competition"]
    assert "reverse_quality_gate_prompt" not in projected["competition"]
    assert "quality_gate_endpoints" not in projected
    assert projected["answer_endpoints"] == [{
        "id": 7,
        "harness": "pi",
        "model": "gpt-answer",
        "label": "Pi (gpt-answer)",
    }]


def test_user_cli_has_no_quality_gate_endpoint_selector():
    cli = _load_numoj_user_cli_module()
    parser = cli.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([
            "ranking",
            "submit",
            "3",
            "--code-zip",
            "problem.zip",
            "--quality-gate-endpoint-id",
            "99",
        ])
