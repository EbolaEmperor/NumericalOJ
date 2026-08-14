from __future__ import annotations

from types import SimpleNamespace

from flask import Flask
import pytest

from oj_modules.editor.language_server import LanguageServiceProtocolError
from oj_modules.editor.lean import (
    LeanLanguageServerSession,
    LeanSourceStateError,
    _incremental_content_change,
)
from oj_modules.routes import lean_routes
from oj_modules.security import auth


class _FakeLeanSession(LeanLanguageServerSession):
    def __init__(self) -> None:
        super().__init__("test")
        self.notifications = []
        self.requests = []
        self.semantic_data = [0, 0, 7, 0, 0]
        self._semantic_legend = {
            "tokenTypes": ["keyword", "function"],
            "tokenModifiers": ["declaration"],
        }

    def _start_locked(self) -> None:
        return None

    def _notify_locked(self, method, params) -> None:
        self.notifications.append((method, params))

    def _request_locked(self, method, params):
        self.requests.append((method, params))
        if method == "textDocument/semanticTokens/full":
            return {"data": list(self.semantic_data)}
        if method == "$/lean/plainGoal":
            return {"goals": ["⊢ True"], "rendered": "⊢ True"}
        return None


def test_lean_semantic_tokens_follow_source_version_and_reuse_cache():
    session = _FakeLeanSession()

    first = session.check(
        "theorem answer : True := by trivial",
        {"line": 0, "character": 8},
    )
    first["semantic_tokens"]["data"][0] = 99
    cursor_only = session.check(
        "theorem answer : True := by trivial",
        {"line": 0, "character": 24},
    )
    changed = session.check(
        "theorem answer : True := by exact True.intro",
        {"line": 0, "character": 30},
    )

    semantic_requests = [
        method
        for method, _ in session.requests
        if method == "textDocument/semanticTokens/full"
    ]
    assert semantic_requests == [
        "textDocument/semanticTokens/full",
        "textDocument/semanticTokens/full",
    ]
    assert cursor_only["semantic_tokens"]["data"] == [0, 0, 7, 0, 0]
    assert cursor_only["semantic_tokens"]["result_id"].startswith("1:")
    assert changed["semantic_tokens"]["result_id"].startswith("2:")
    assert [method for method, _ in session.notifications] == [
        "textDocument/didOpen",
        "textDocument/didChange",
    ]


def test_lean_semantic_tokens_reject_unknown_token_type():
    session = _FakeLeanSession()
    session.semantic_data = [0, 0, 7, 2, 0]

    with pytest.raises(LanguageServiceProtocolError, match="类型无效"):
        session.check(
            "theorem answer : True := by trivial",
            {"line": 0, "character": 0},
        )


def test_lean_check_endpoint_returns_semantic_tokens(monkeypatch):
    class _Service:
        def check_source(
            self,
            session_key,
            sources,
            active_file,
            position,
            known_semantic_result_id,
        ):
            assert session_key == "7:42:rev-1"
            assert sources == {
                "Problem.lean": "def Problem.Target : Prop := True",
                "Submission.lean": "theorem Submission.answer : True := by trivial",
            }
            assert active_file == "Submission.lean"
            assert position == {"line": 0, "character": 8}
            assert known_semantic_result_id is None
            return {
                "source_state_id": "state-1",
                "goals": [],
                "goal_rendered": "",
                "diagnostics": [],
                "processing": [],
                "document_version": 1,
                "semantic_tokens": {
                    "legend": {
                        "tokenTypes": ["keyword"],
                        "tokenModifiers": [],
                    },
                    "data": [0, 0, 7, 0, 0],
                    "result_id": "1:abc",
                },
            }

    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(lean_routes.lean_bp)
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 0},
    )
    monkeypatch.setattr(lean_routes, "get_lean_interactive_service", _Service)
    monkeypatch.setattr(
        lean_routes,
        "normalize_lean_submission_payload",
        lambda **_kwargs: (
            {
                "revision": "rev-1",
                "files": [
                    {
                        "path": "Problem.lean",
                        "mode": "readonly",
                        "content": "def Problem.Target : Prop := True",
                    },
                    {
                        "path": "Submission.lean",
                        "mode": "writable",
                        "content": "",
                    },
                ],
            },
            {
                "Submission.lean": (
                    "theorem Submission.answer : True := by trivial"
                )
            },
        ),
    )
    monkeypatch.setattr(lean_routes, "_rds", None)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/lean/check",
        json={
            "problem_id": 42,
            "revision": "rev-1",
            "files": {
                "Submission.lean": (
                    "theorem Submission.answer : True := by trivial"
                )
            },
            "active_file": "Submission.lean",
            "version": 9,
            "position": {"line": 0, "character": 8},
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["version"] == 9
    assert payload["source_state_id"] == "state-1"
    assert payload["semantic_tokens"] == {
        "legend": {"tokenTypes": ["keyword"], "tokenModifiers": []},
        "data": [0, 0, 7, 0, 0],
        "result_id": "1:abc",
    }


def test_lean_cursor_check_reuses_session_without_loading_workspace(
    monkeypatch,
):
    class _Service:
        def check_cursor(
            self,
            session_key,
            source_state_id,
            document_version,
            active_file,
            position,
            known_semantic_result_id,
        ):
            assert session_key == "7:42:rev-1:tab-1"
            assert source_state_id == "state-1"
            assert document_version == 4
            assert active_file == "Submission.lean"
            assert position == {"line": 2, "character": 6}
            assert known_semantic_result_id == "4:abc"
            return {
                "source_state_id": "state-1",
                "goals": ["⊢ True"],
                "goal_rendered": "⊢ True",
                "diagnostics": None,
                "processing": None,
                "document_version": 4,
                "semantic_tokens": None,
            }

    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(lean_routes.lean_bp)
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 0},
    )
    monkeypatch.setattr(lean_routes, "get_lean_interactive_service", _Service)
    monkeypatch.setattr(
        lean_routes,
        "normalize_lean_submission_payload",
        lambda **_kwargs: pytest.fail("cursor 请求不应读取工作区"),
    )
    monkeypatch.setattr(lean_routes, "_rds", None)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/lean/check",
        json={
            "request_kind": "cursor",
            "problem_id": 42,
            "revision": "rev-1",
            "client_session_id": "tab-1",
            "source_state_id": "state-1",
            "document_version": 4,
            "known_semantic_result_id": "4:abc",
            "active_file": "Submission.lean",
            "version": 9,
            "position": {"line": 2, "character": 6},
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["version"] == 9
    assert payload["source_state_id"] == "state-1"
    assert payload["semantic_tokens"] is None
    assert payload["diagnostics"] is None
    assert payload["processing"] is None
    assert payload["goals"] == ["⊢ True"]


def test_lean_cursor_check_requests_source_resync(monkeypatch):
    class _Service:
        def check_cursor(self, *_args):
            raise LeanSourceStateError("Lean 4 源码状态已失效")

    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(lean_routes.lean_bp)
    monkeypatch.setattr(
        auth,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 0},
    )
    monkeypatch.setattr(lean_routes, "get_lean_interactive_service", _Service)
    monkeypatch.setattr(
        lean_routes,
        "normalize_lean_submission_payload",
        lambda **_kwargs: pytest.fail("cursor 请求不应读取工作区"),
    )
    monkeypatch.setattr(lean_routes, "_rds", None)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/lean/check",
        json={
            "request_kind": "cursor",
            "problem_id": 42,
            "revision": "rev-1",
            "client_session_id": "tab-1",
            "source_state_id": "missing-state",
            "document_version": 4,
            "known_semantic_result_id": "4:abc",
            "active_file": "Submission.lean",
            "version": 9,
            "position": {"line": 2, "character": 6},
        },
    )

    assert response.status_code == 409
    assert response.get_json()["code"] == "resync_required"


def test_lean_incremental_change_uses_utf16_positions():
    change = _incremental_content_change(
        "-- 😀 alpha\ntheorem answer : True := by trivial",
        "-- 😀 beta\ntheorem answer : True := by trivial",
    )

    assert change == {
        "range": {
            "start": {"line": 0, "character": 6},
            "end": {"line": 0, "character": 10},
        },
        "text": "bet",
    }


def test_lean_opens_only_active_documents_and_sends_range_changes():
    session = _FakeLeanSession()
    sources = {
        "Problem.lean": "def Problem.Target : Prop := True",
        "Submission.lean": "theorem answer : True := by trivial",
    }

    session.check_source(
        sources,
        "Submission.lean",
        {"line": 0, "character": 8},
    )

    opened = [
        params["textDocument"]["uri"]
        for method, params in session.notifications
        if method == "textDocument/didOpen"
    ]
    assert opened == ["file:///workspace/Submission.lean"]

    changed_sources = dict(sources)
    changed_sources["Submission.lean"] = (
        "theorem answer : True := by exact True.intro"
    )
    session.check_source(
        changed_sources,
        "Submission.lean",
        {"line": 0, "character": 30},
    )
    did_change = next(
        params
        for method, params in session.notifications
        if method == "textDocument/didChange"
    )
    assert "range" in did_change["contentChanges"][0]
    assert did_change["contentChanges"][0]["text"] == "exact True.intro"

    session.check_source(
        changed_sources,
        "Problem.lean",
        {"line": 0, "character": 4},
    )
    assert session._open_documents == {"Problem.lean"}
    assert [
        (method, params["textDocument"]["uri"])
        for method, params in session.notifications
        if method in {"textDocument/didClose", "textDocument/didOpen"}
    ][-2:] == [
        ("textDocument/didClose", "file:///workspace/Submission.lean"),
        ("textDocument/didOpen", "file:///workspace/Problem.lean"),
    ]


def test_lean_workspace_sync_uses_only_the_archive_upload_command():
    session = LeanLanguageServerSession("test")
    session._process = object()
    calls = []

    def run(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0)

    session._run_docker_exec = run
    session._sync_workspace_locked(
        {"Problem.lean": "def Problem.Target : Prop := True"}
    )

    assert len(calls) == 1
    assert calls[0][0] == ["tar", "-xf", "-", "-C", "/workspace"]
    assert calls[0][1]["input_bytes"]
    session._process = None


def test_lean_failed_dependency_build_is_not_repeated_without_source_change():
    session = LeanLanguageServerSession("test")
    session._process = object()
    session._workspace_digests = {
        "Problem.lean": "problem-v1",
        "Submission.lean": "submission-v1",
    }
    calls = []

    def run(arguments, **_kwargs):
        calls.append(arguments)
        return SimpleNamespace(returncode=1)

    session._run_docker_exec = run
    sources = {
        "Problem.lean": "bad source",
        "Submission.lean": "import Problem",
    }

    assert session._compile_dependencies_locked(sources, "Submission.lean")
    assert not session._compile_dependencies_locked(sources, "Submission.lean")
    assert len(calls) == 1

    session._workspace_digests["Problem.lean"] = "problem-v2"
    assert session._compile_dependencies_locked(sources, "Submission.lean")
    assert len(calls) == 2
    session._process = None


def test_lean_cursor_only_reuses_diagnostics_semantics_and_exact_goal():
    session = _FakeLeanSession()
    first = session.check_source(
        "theorem answer : True := by trivial",
        {"line": 0, "character": 8},
    )

    cursor = session.check_cursor(
        first["source_state_id"],
        first["document_version"],
        "Submission.lean",
        {"line": 0, "character": 8},
        first["semantic_tokens"]["result_id"],
    )

    assert cursor["semantic_tokens"] is None
    assert cursor["diagnostics"] is None
    assert cursor["processing"] is None
    assert [method for method, _ in session.requests].count(
        "textDocument/waitForDiagnostics"
    ) == 1
    assert [method for method, _ in session.requests].count(
        "textDocument/semanticTokens/full"
    ) == 1
    assert [method for method, _ in session.requests].count(
        "$/lean/plainGoal"
    ) == 1

    with pytest.raises(LeanSourceStateError):
        session.check_cursor(
            "stale-state",
            first["document_version"],
            "Submission.lean",
            {"line": 0, "character": 8},
        )


def test_lean_semantic_response_uses_single_splice_for_known_result():
    session = _FakeLeanSession()
    first = session.check_source(
        "theorem answer : True := by trivial",
        {"line": 0, "character": 8},
    )
    first_tokens = first["semantic_tokens"]
    session.semantic_data = [
        0, 0, 7, 0, 0,
        0, 8, 6, 1, 0,
    ]

    changed = session.check_source(
        "theorem answer : True := by exact True.intro",
        {"line": 0, "character": 30},
        known_semantic_result_id=first_tokens["result_id"],
    )
    delta = changed["semantic_tokens"]

    assert delta["previous_result_id"] == first_tokens["result_id"]
    assert "data" not in delta
    assert len(delta["edits"]) == 1
    edit = delta["edits"][0]
    reconstructed = (
        first_tokens["data"][:edit["start"]]
        + edit["data"]
        + first_tokens["data"][
            edit["start"] + edit["deleteCount"]:
        ]
    )
    assert reconstructed == session.semantic_data
