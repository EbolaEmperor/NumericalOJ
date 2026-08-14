from __future__ import annotations

from flask import Flask
import pytest

from oj_modules.editor.language_server import LanguageServiceProtocolError
from oj_modules.editor.lean import LeanLanguageServerSession
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
        def check(self, session_key, source, position):
            assert session_key == "7:42"
            return {
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
    monkeypatch.setattr(lean_routes, "_rds", None)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/lean/check",
        json={
            "problem_id": 42,
            "source": "theorem answer : True := by trivial",
            "version": 9,
            "position": {"line": 0, "character": 8},
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["version"] == 9
    assert payload["semantic_tokens"] == {
        "legend": {"tokenTypes": ["keyword"], "tokenModifiers": []},
        "data": [0, 0, 7, 0, 0],
        "result_id": "1:abc",
    }
