from __future__ import annotations

from flask import Flask

from oj_modules import auth_helpers
from oj_modules.language_server_services import LanguageServiceBusyError
from oj_modules.repository import tree as repository_tree
from oj_modules.repository.language import RepositorySemanticTarget
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
        lambda username: {
            "id": {"alice": 7, "bob": 8}.get(username, 9),
            "username": username,
            "is_admin": 0,
        },
    )
    monkeypatch.setattr(
        editor_language_routes,
        "get_editor_language_service",
        lambda language: service,
    )
    monkeypatch.setattr(
        editor_language_routes,
        "get_repository_semantic_target",
        lambda owner_id, entry_id, language: RepositorySemanticTarget(
            owner_id=owner_id,
            storage_key="a" * 32,
            generation=5,
            entry_id=entry_id,
            relative_path=f"entry-{entry_id}.{'c' if language == 'c' else 'cpp'}",
            language=language,
        ),
    )
    monkeypatch.setattr(
        editor_language_routes,
        "ensure_repository_semantic_target_current",
        lambda target: None,
    )

    class FakeRepositoryService:
        def semantic_tokens(self, target, source, snapshot_loader):
            service.calls.append(
                (
                    (
                        f"{target.owner_id}:editor:repository:"
                        f"{target.entry_id}:{target.language}"
                    ),
                    source,
                )
            )
            return {
                "data": [0, 0, 6, 1, 1],
                "result_id": f"repository:{target.generation}:1:abc",
            }

    monkeypatch.setattr(
        editor_language_routes,
        "get_repository_clangd_service",
        lambda language: FakeRepositoryService(),
    )
    monkeypatch.setattr(editor_language_routes, "_rds", None)
    monkeypatch.setattr(
        editor_language_routes,
        "_markdown_semantic_cache",
        editor_language_routes.SemanticTokenResultCache(),
    )
    monkeypatch.setattr(editor_language_routes, "_semantic_legend_cache", {})
    monkeypatch.setattr(editor_language_routes, "_semantic_legend_inflight", set())
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


def test_editor_contexts_use_owned_repository_ids_and_isolated_document_keys(
    monkeypatch,
):
    service = _FakeService()
    app = _app(monkeypatch, service)
    alice = app.test_client()
    bob = app.test_client()
    with alice.session_transaction() as user_session:
        user_session["username"] = "alice"
    with bob.session_transaction() as user_session:
        user_session["username"] = "bob"

    requests = (
        (
            alice,
            {
                "context": "repository",
                "repository_entry_id": 42,
                "language": "cpp",
                "source": "int repository_value;",
            },
        ),
        (
            alice,
            {
                "context": "problem-form",
                "document_id": "initial-code",
                "language": "python",
                "source": "form_value = 1",
            },
        ),
        (
            bob,
            {
                "context": "repository",
                "repository_entry_id": 42,
                "language": "cpp",
                "source": "int another_value;",
            },
        ),
    )

    for client, payload in requests:
        response = client.post("/api/editor/semantic-tokens", json=payload)
        assert response.status_code == 200

    assert service.calls == [
        (
            "7:editor:repository:42:cpp",
            "int repository_value;",
        ),
        (
            "7:editor:problem-form:initial-code:python",
            "form_value = 1",
        ),
        (
            "8:editor:repository:42:cpp",
            "int another_value;",
        ),
    ]


def test_generic_editor_contexts_reject_unsafe_document_identity(monkeypatch):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    invalid_payloads = (
        {
            "context": "repository",
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "repository",
            "repository_entry_id": "",
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "repository",
            "repository_entry_id": 0,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "repository",
            "repository_entry_id": True,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "repository",
            "document_id": "entry-42",
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "problem-form",
            "document_id": "x" * 65,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "problem-form",
            "document_id": 17,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "repository",
            "repository_entry_id": 42,
            "problem_id": 31,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "repository_entry_id": 42,
            "problem_id": 31,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "markdown",
            "repository_entry_id": 42,
            "language": "cpp",
            "source": "int value;",
        },
    )

    for payload in invalid_payloads:
        response = client.post("/api/editor/semantic-tokens", json=payload)
        assert response.status_code == 400

    assert service.calls == []


def test_repository_semantic_tokens_reject_missing_owned_entry(
    monkeypatch,
):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"
    monkeypatch.setattr(
        editor_language_routes,
        "get_repository_semantic_target",
        lambda *_args: (_ for _ in ()).throw(
            repository_tree.RepositoryDomainError(
                "仓库文件不存在",
                code="not_found",
                status=404,
            )
        ),
    )

    response = client.post(
        "/api/editor/semantic-tokens",
        json={
            "context": "repository",
            "repository_entry_id": 42,
            "language": "cpp",
            "source": "int value;",
        },
    )

    assert response.status_code == 404
    assert response.get_json()["code"] == "not_found"
    assert service.calls == []


def test_markdown_cpp_tokens_use_isolated_context_and_hidden_bits_preamble(
    monkeypatch,
):
    class MarkdownService(_FakeService):
        def semantic_tokens(self, document_key, source):
            self.calls.append((document_key, source))
            return {
                "data": [
                    0, 1, 7, 0, 0,
                    1, 0, 3, 1, 0,
                    1, 4, 4, 0, 1,
                ],
                "inactive_regions": [
                    {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 1, "character": 0},
                    },
                    {
                        "start": {"line": 1, "character": 0},
                        "end": {"line": 2, "character": 0},
                    },
                    {
                        "start": {"line": 2, "character": 4},
                        "end": {"line": 2, "character": 8},
                    },
                ],
                "result_id": "1:markdown",
            }

    service = MarkdownService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    response = client.post(
        "/api/editor/semantic-tokens",
        json={
            "context": "markdown",
            "language": "cpp",
            "source": "int value;\nint main() {}",
        },
    )

    assert response.status_code == 200
    assert response.get_json()["data"] == [
        0, 0, 3, 1, 0,
        1, 4, 4, 0, 1,
    ]
    assert response.get_json()["inactive_regions"] == [
        {
            "start": {"line": 0, "character": 0},
            "end": {"line": 1, "character": 0},
        },
        {
            "start": {"line": 1, "character": 4},
            "end": {"line": 1, "character": 8},
        },
    ]
    assert service.calls == [
        (
            "7:markdown:cpp",
            "#include <bits/stdc++.h>\nint value;\nint main() {}",
        )
    ]


def test_markdown_semantic_context_rejects_unsupported_or_bound_requests(
    monkeypatch,
):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    for payload in (
        {
            "context": "markdown",
            "language": "javascript",
            "source": "value = 1",
        },
        {
            "context": "markdown",
            "problem_id": 1,
            "language": "cpp",
            "source": "int value;",
        },
        {
            "context": "unknown",
            "language": "cpp",
            "source": "int value;",
        },
    ):
        response = client.post("/api/editor/semantic-tokens", json=payload)
        assert response.status_code == 400
    assert service.calls == []


def test_markdown_semantic_context_uses_each_editor_language_service(
    monkeypatch,
):
    service = _FakeService()
    client = _app(monkeypatch, service).test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    cases = (
        ("c", "int c_value;", "c"),
        ("py", "py_value: int = 1", "python"),
        ("python", "python_value: int = 1", "python"),
        ("matlab", "matlab_value = 1;", "matlab"),
        ("octave", "octave_value = 1;", "matlab"),
    )
    for language, source, _canonical in cases:
        response = client.post(
            "/api/editor/semantic-tokens",
            json={
                "context": "markdown",
                "language": language,
                "source": source,
            },
        )
        assert response.status_code == 200
        assert response.get_json()["data"] == [0, 0, 6, 1, 1]

    assert service.calls == [
        (f"7:markdown:{canonical}", source)
        for _language, source, canonical in cases
    ]


def test_markdown_cache_keys_are_isolated_by_canonical_language():
    source = "value = 1;"

    keys = {
        editor_language_routes._markdown_cache_key(language, source)
        for language in ("c", "cpp", "python", "matlab")
    }

    assert len(keys) == 4


def test_markdown_cpp_result_cache_is_shared_across_authenticated_users(
    monkeypatch,
):
    class CacheableService(_FakeService):
        def semantic_tokens(self, document_key, source):
            self.calls.append((document_key, source))
            return {"data": [1, 0, 3, 1, 0], "result_id": "1:cache"}

    service = CacheableService()
    app = _app(monkeypatch, service)
    alice = app.test_client()
    bob = app.test_client()
    with alice.session_transaction() as user_session:
        user_session["username"] = "alice"
    with bob.session_transaction() as user_session:
        user_session["username"] = "bob"
    payload = {
        "context": "markdown",
        "language": "cpp",
        "source": "std::vector<int> values;",
    }

    first = alice.post("/api/editor/semantic-tokens", json=payload)
    second = bob.post("/api/editor/semantic-tokens", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.get_json()["data"] == second.get_json()["data"] == [
        0, 0, 3, 1, 0,
    ]
    expected_result_id = (
        "markdown:"
        + editor_language_routes._markdown_cache_key(
            payload["language"],
            payload["source"],
        )[:12]
    )
    assert first.get_json()["result_id"] == expected_result_id
    assert second.get_json()["result_id"] == expected_result_id
    assert service.calls == [
        (
            "7:markdown:cpp",
            "#include <bits/stdc++.h>\nstd::vector<int> values;",
        )
    ]


def test_markdown_cpp_duplicate_inflight_returns_retryable_code(monkeypatch):
    service = _FakeService()
    app = _app(monkeypatch, service)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"
    source = "std::vector<int> values;"
    cache_key = editor_language_routes._markdown_cache_key("cpp", source)
    assert (
        editor_language_routes._markdown_semantic_cache.claim(cache_key).state
        == "owner"
    )

    response = client.post(
        "/api/editor/semantic-tokens",
        json={
            "context": "markdown",
            "language": "cpp",
            "source": source,
        },
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "1"
    assert response.get_json()["code"] == "result_pending"
    assert service.calls == []


def test_markdown_cpp_busy_failure_releases_cache_owner_for_retry(monkeypatch):
    class FlakyService(_FakeService):
        def semantic_tokens(self, document_key, source):
            self.calls.append((document_key, source))
            if len(self.calls) == 1:
                raise LanguageServiceBusyError("clangd", "clangd 正忙")
            return {"data": [1, 0, 3, 1, 0], "result_id": "1:retry"}

    service = FlakyService()
    app = _app(monkeypatch, service)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"
    payload = {
        "context": "markdown",
        "language": "cpp",
        "source": "std::vector<int> values;",
    }

    first = client.post("/api/editor/semantic-tokens", json=payload)
    second = client.post("/api/editor/semantic-tokens", json=payload)

    assert first.status_code == 429
    assert first.get_json()["code"] == "service_busy"
    assert second.status_code == 200
    assert second.get_json()["data"] == [0, 0, 3, 1, 0]
    assert len(service.calls) == 2


def test_markdown_cpp_has_stricter_source_and_token_response_limits(monkeypatch):
    class LargeTokenService(_FakeService):
        def semantic_tokens(self, document_key, source):
            self.calls.append((document_key, source))
            data = [0, 0, 1, 0, 0, 1, 0, 1, 1, 0]
            data.extend(
                [value for _ in range(12_000) for value in (0, 1, 1, 1, 0)]
            )
            return {"data": data, "result_id": "1:large"}

    service = LargeTokenService()
    app = _app(monkeypatch, service)
    client = app.test_client()
    with client.session_transaction() as user_session:
        user_session["username"] = "alice"

    too_large = client.post(
        "/api/editor/semantic-tokens",
        json={
            "context": "markdown",
            "language": "cpp",
            "source": "界" * 200_000,
        },
    )
    accepted = client.post(
        "/api/editor/semantic-tokens",
        json={
            "context": "markdown",
            "language": "cpp",
            "source": "x" * 12_001,
        },
    )

    assert too_large.status_code == 413
    assert too_large.get_json()["code"] == "source_too_large"
    assert accepted.status_code == 200
    assert len(accepted.get_json()["data"]) == 12_000 * 5
    assert len(service.calls) == 1


def test_semantic_legend_is_cached_and_cold_duplicates_retry(monkeypatch):
    class LegendService(_FakeService):
        def __init__(self):
            super().__init__()
            self.legend_calls = 0

        def legend(self):
            self.legend_calls += 1
            return super().legend()

    service = LegendService()
    app = _app(monkeypatch, service)
    alice = app.test_client()
    bob = app.test_client()
    with alice.session_transaction() as user_session:
        user_session["username"] = "alice"
    with bob.session_transaction() as user_session:
        user_session["username"] = "bob"

    first = alice.get("/api/editor/semantic-token-legend?language=cpp")
    second = bob.get("/api/editor/semantic-token-legend?language=cpp")
    assert first.status_code == second.status_code == 200
    assert service.legend_calls == 1

    editor_language_routes._semantic_legend_cache.clear()
    state, _ = editor_language_routes._legend_cache_claim("cpp")
    assert state == "owner"
    pending = alice.get("/api/editor/semantic-token-legend?language=cpp")
    assert pending.status_code == 429
    assert pending.headers["Retry-After"] == "1"
    assert pending.get_json()["code"] == "legend_pending"
    editor_language_routes._legend_cache_publish("cpp", None)


def test_semantic_prefix_filter_reencodes_same_and_later_display_lines():
    assert editor_language_routes._without_semantic_prefix_lines(
        [
            0, 2, 7, 0, 0,
            1, 4, 3, 1, 0,
            0, 6, 5, 0, 1,
            1, 2, 4, 1, 1,
        ],
        1,
    ) == [
        0, 4, 3, 1, 0,
        0, 6, 5, 0, 1,
        1, 2, 4, 1, 1,
    ]


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
    assert response.get_json()["code"] == "service_busy"


def test_editor_semantic_request_budget_tracks_four_mebibyte_source_limit():
    assert editor_language_routes._REQUEST_MAX_BYTES == (
        4 * 1024 * 1024 * 6 + 16 * 1024
    )
