from __future__ import annotations

from flask import Flask

from oj_modules import auth_helpers
from oj_modules.language_server_services import LanguageServiceBusyError
from oj_modules.routes import editor_language_routes


class _FakeService:
    def __init__(self):
        self.calls = []

    def legend(self):
        return {
            "tokenTypes": ["variable", "class"],
            "tokenModifiers": ["declaration"],
        }

    def semantic_tokens(self, document_key, source):
        self.calls.append((document_key, source))
        return {"data": [0, 0, 6, 1, 1], "result_id": "1:abc"}


def _app(monkeypatch, service):
    app = Flask(__name__)
    app.secret_key = "test-only"
    app.register_blueprint(editor_language_routes.editor_language_bp)
    monkeypatch.setattr(
        auth_helpers,
        "get_user_by_username",
        lambda username: {"id": 7, "username": username, "is_admin": 0},
    )
    monkeypatch.setattr(
        editor_language_routes,
        "get_editor_language_service",
        lambda language: service,
    )
    monkeypatch.setattr(editor_language_routes, "_rds", None)
    return app


def test_editor_semantic_token_endpoints_require_login(monkeypatch):
    response = _app(monkeypatch, _FakeService()).test_client().get(
        "/api/editor/semantic-token-legend",
        headers={"Accept": "application/json"},
    )

    assert response.status_code == 401
    assert response.get_json()["success"] is False


def test_editor_semantic_token_endpoints_forward_authenticated_source(monkeypatch):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    legend = client.get("/api/editor/semantic-token-legend?language=python")
    tokens = client.post(
        "/api/editor/semantic-tokens",
        json={
            "problem_id": 31,
            "language": "python",
            "source": "names: list[str] = []",
        },
    )

    assert legend.status_code == 200
    assert legend.get_json()["legend"]["tokenTypes"] == ["variable", "class"]
    assert tokens.status_code == 200
    assert tokens.get_json()["data"] == [0, 0, 6, 1, 1]
    assert service.calls == [("7:31:python", "names: list[str] = []")]


def test_editor_semantic_tokens_validate_payload_before_calling_clangd(monkeypatch):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/editor/semantic-tokens",
        json={"problem_id": True, "language": "cpp", "source": "int main() {}"},
    )

    assert response.status_code == 400
    assert service.calls == []


def test_editor_semantic_tokens_reject_oversized_body_before_json_parse(monkeypatch):
    client = _app(monkeypatch, _FakeService()).test_client()
    monkeypatch.setattr(editor_language_routes, "_REQUEST_MAX_BYTES", 32)
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/editor/semantic-tokens",
        data=b'{' + b'"source":"' + b'x' * 100 + b'"}',
        content_type="application/json",
    )

    assert response.status_code == 413
    assert response.get_json()["message"] == "请求体过大"


def test_editor_semantic_tokens_return_retryable_busy_response(monkeypatch):
    class BusyService(_FakeService):
        def semantic_tokens(self, document_key, source):
            raise LanguageServiceBusyError("clangd", "clangd 正忙")

    client = _app(monkeypatch, BusyService()).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/editor/semantic-tokens",
        json={"problem_id": 31, "language": "cpp", "source": "int x;"},
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "1"
