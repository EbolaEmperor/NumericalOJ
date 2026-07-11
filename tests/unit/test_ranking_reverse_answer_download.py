import http.server
import os
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from flask import Flask
from werkzeug.exceptions import NotFound

import oj_modules.ranking_reverse_judge_db as reverse_db
from oj_modules.routes import ranking_routes as routes
import oj_modules.tasks.ranking_reverse_judge_tasks as reverse_tasks


def _app():
    app = Flask(__name__)
    app.secret_key = "test"
    return app


def _patch_submission_root(monkeypatch, tmp_path):
    root = tmp_path / "submission"
    monkeypatch.setattr(reverse_db, "submission_dir", lambda _sid: str(root))
    monkeypatch.setattr(reverse_tasks, "submission_dir", lambda _sid: str(root))
    return root


def test_reverse_endpoint_proxy_rewrites_credentials_and_pins_upstream():
    temporary_token = "attempt-only-token"
    real_key = "sk-real-worker-only-key"
    incoming = {
        "Content-Type": "application/json",
        "x-api-key": temporary_token,
        "Host": "attacker.example",
        "Connection": "keep-alive",
    }

    assert reverse_tasks._reverse_proxy_token_valid(incoming, temporary_token) is True
    assert reverse_tasks._reverse_proxy_token_valid(incoming, real_key) is False
    forwarded = reverse_tasks._reverse_proxy_upstream_headers(
        incoming, real_key, reverse_tasks.HARNESS_CLAUDE_CODE,
    )
    assert forwarded == {
        "Content-Type": "application/json",
        "x-api-key": real_key,
    }
    assert temporary_token not in repr(forwarded)

    upstream = urlsplit("https://real-endpoint.example/compatible?tenant=oj")
    assert reverse_tasks._reverse_proxy_target_url(
        upstream, "POST", "http://attacker.example/v1/messages?stream=1",
    ) == (
        "https://real-endpoint.example/compatible/v1/messages"
        "?tenant=oj&stream=1"
    )
    assert reverse_tasks._reverse_proxy_target_url(
        upstream, "POST", "/v1/account",
    ) == ""

    codex_incoming = {
        "Authorization": f"Bearer {temporary_token}",
        "Accept": "text/event-stream",
    }
    assert reverse_tasks._reverse_proxy_token_valid(
        codex_incoming, temporary_token,
    ) is True
    assert reverse_tasks._reverse_proxy_upstream_headers(
        codex_incoming, real_key, reverse_tasks.HARNESS_CODEX,
    ) == {
        "Accept": "text/event-stream",
        "Authorization": f"Bearer {real_key}",
    }
    assert reverse_tasks._reverse_proxy_target_url(
        upstream, "POST", "/v1/responses",
    ) == "https://real-endpoint.example/compatible/v1/responses?tenant=oj"
    assert reverse_tasks._ReverseProxyNoRedirect().redirect_request(
        None, None, 302, "Found", {}, "https://attacker.example/steal",
    ) is None


def test_reverse_proxy_server_bounds_connections_and_sets_read_timeout(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.timeout = None
            self.sent = b""
            self.shutdown_calls = []
            self.closed = False

        def settimeout(self, value):
            self.timeout = value

        def sendall(self, value):
            self.sent += value

        def shutdown(self, how):
            self.shutdown_calls.append(how)

        def close(self):
            self.closed = True

    class FakeResponse:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    server = object.__new__(reverse_tasks._BoundedReverseProxyServer)
    server._connection_slots = threading.BoundedSemaphore(1)
    server._active_lock = threading.Lock()
    server._active_clients = set()
    server._active_upstreams = set()
    server._closing = False
    closed = []
    started = []
    server.shutdown_request = lambda request: closed.append(request)
    monkeypatch.setattr(
        http.server.ThreadingHTTPServer,
        "process_request",
        lambda _server, request, _address: started.append(request),
    )
    first = FakeSocket()
    second = FakeSocket()

    server.process_request(first, ("127.0.0.1", 1))
    server.process_request(second, ("127.0.0.1", 2))

    assert started == [first]
    assert first.timeout == reverse_tasks.REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS
    assert second.timeout == reverse_tasks.REVERSE_ENDPOINT_PROXY_CLIENT_TIMEOUT_SECONDS
    assert b"503 Service Unavailable" in second.sent
    assert closed == [second]
    upstream = FakeResponse()
    assert server.register_upstream(upstream) is True
    server.close_active_requests()
    assert first.shutdown_calls == [reverse_tasks.socket.SHUT_RDWR]
    assert first.closed is True
    assert upstream.closed is True
    assert server._closing is True
    server._connection_slots.release()


def test_reverse_proxy_stream_reader_prefers_non_buffering_read1():
    class ChunkedResponse:
        def __init__(self):
            self.calls = []

        def read1(self, size):
            self.calls.append(("read1", size))
            return b"data: first\n\n"

        def read(self, _size):
            raise AssertionError("chunked/SSE 不得优先调用聚合式 read")

    response = ChunkedResponse()
    assert reverse_tasks._reverse_proxy_read_chunk(response, 1024) == b"data: first\n\n"
    assert response.calls == [("read1", 1024)]


def test_reverse_endpoint_proxy_uses_real_key_only_upstream_and_expires():
    seen = []
    redirect_seen = []
    redirect_target = None
    stream_first_sent = threading.Event()
    stream_release = threading.Event()
    stream_client_received = threading.Event()
    stream_lines = []

    class RedirectTargetHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            redirect_seen.append(dict(self.headers))
            self.send_response(204)
            self.end_headers()

    class UpstreamHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            seen.append({
                "path": self.path,
                "api_key": self.headers.get("x-api-key"),
                "authorization": self.headers.get("Authorization"),
                "body": body,
            })
            if body == b'stream':
                payload = b'data: first\n\n'
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
                self.wfile.flush()
                stream_first_sent.set()
                stream_release.wait(timeout=3)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                return
            if body == b'redirect':
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{redirect_target.server_address[1]}/steal",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    try:
        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    except PermissionError:
        pytest.skip("当前测试沙箱禁止绑定 loopback 端口")
    try:
        redirect_target = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), RedirectTargetHandler,
        )
    except PermissionError:
        upstream.server_close()
        pytest.skip("当前测试沙箱禁止绑定 loopback 端口")
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    redirect_thread = threading.Thread(
        target=redirect_target.serve_forever, daemon=True,
    )
    upstream_thread.start()
    redirect_thread.start()
    real_key = "sk-real-worker-only-key"
    proxy = reverse_tasks._start_reverse_endpoint_proxy(
        f"http://127.0.0.1:{upstream.server_address[1]}/compatible",
        real_key,
        reverse_tasks.HARNESS_CLAUDE_CODE,
    )
    proxy_url = proxy.local_base_url + "/v1/messages"
    try:
        request = urllib.request.Request(
            proxy_url,
            data=b'{"messages":[]}',
            headers={"Content-Type": "application/json", "x-api-key": proxy.token},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            assert response.read() == b'{"ok":true}'

        assert seen == [{
            "path": "/compatible/v1/messages",
            "api_key": real_key,
            "authorization": None,
            "body": b'{"messages":[]}',
        }]
        assert proxy.token != real_key

        wrong = urllib.request.Request(
            proxy_url,
            data=b'{}',
            headers={"x-api-key": real_key},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as wrong_error:
            urllib.request.urlopen(wrong, timeout=3)
        assert wrong_error.value.code == 403

        disallowed = urllib.request.Request(
            proxy.local_base_url + "/v1/account",
            data=b'{}',
            headers={"x-api-key": proxy.token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as path_error:
            urllib.request.urlopen(disallowed, timeout=3)
        assert path_error.value.code == 404
        assert len(seen) == 1

        def read_stream():
            stream_request = urllib.request.Request(
                proxy_url,
                data=b'stream',
                headers={"x-api-key": proxy.token},
                method="POST",
            )
            with urllib.request.urlopen(stream_request, timeout=3) as response:
                stream_lines.append(response.readline())
                stream_client_received.set()

        stream_thread = threading.Thread(target=read_stream, daemon=True)
        stream_thread.start()
        assert stream_first_sent.wait(timeout=1)
        try:
            assert stream_client_received.wait(timeout=1)
            assert stream_lines == [b'data: first\n']
        finally:
            stream_release.set()
            stream_thread.join(timeout=3)

        redirect_request = urllib.request.Request(
            proxy_url,
            data=b'redirect',
            headers={"x-api-key": proxy.token},
            method="POST",
        )
        no_redirect_client = urllib.request.build_opener(
            reverse_tasks._ReverseProxyNoRedirect(),
        )
        with pytest.raises(urllib.error.HTTPError) as redirect_error:
            no_redirect_client.open(redirect_request, timeout=3)
        assert redirect_error.value.code == 302
        assert seen[-1]["api_key"] == real_key
        assert redirect_seen == []
    finally:
        stream_release.set()
        proxy.close()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=3)
        redirect_target.shutdown()
        redirect_target.server_close()
        redirect_thread.join(timeout=3)

    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(
            urllib.request.Request(
                proxy_url, data=b'{}',
                headers={"x-api-key": proxy.token}, method="POST",
            ),
            timeout=1,
        )


def test_reverse_agent_answer_archive_path_is_attempt_scoped_and_cannot_escape(
        monkeypatch, tmp_path):
    root = _patch_submission_root(monkeypatch, tmp_path)

    archive = reverse_db.reverse_agent_answer_archive_path(
        7, "../../outside\\attempt!?",
    )

    answer_root = os.path.realpath(root / "reverse_agent_answers")
    assert archive.startswith(answer_root + os.sep)
    assert os.path.dirname(archive) == answer_root
    assert archive.endswith(".zip")
    assert ".." not in os.path.basename(archive)


def test_persist_agent_answer_archive_keeps_delivery_and_excludes_harness_state(
        monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    (source / "src").mkdir(parents=True)
    (source / "src" / "solve.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "README.md").write_text("answer\n", encoding="utf-8")
    for internal in (".claude", ".codex", ".opencode"):
        (source / internal).mkdir()
        (source / internal / "credential.txt").write_text("secret", encoding="utf-8")
    (source / ".aj_harness.log").write_text("internal", encoding="utf-8")

    archive_path = reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)

    assert archive_path == reverse_db.reverse_agent_answer_archive_path(9, "attempt-1")
    assert os.path.isfile(archive_path)
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        assert "ai_answer/" in names
        assert "ai_answer/src/solve.py" in names
        assert "ai_answer/README.md" in names
        assert archive.read("ai_answer/src/solve.py") == b"print('ok')\n"
        assert not any(
            name.startswith(("ai_answer/.claude", "ai_answer/.codex", "ai_answer/.opencode"))
            or "/.aj_" in name or name.startswith("ai_answer/.aj_")
            for name in names
        )


def test_persist_agent_answer_archive_rejects_symlink_and_keeps_previous_zip(
        monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    source.mkdir()
    (source / "solve.py").write_text("ok", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    try:
        (source / "leak.txt").symlink_to(outside)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")

    target = reverse_db.reverse_agent_answer_archive_path(9, "attempt-1")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("ai_answer/old.txt", "old")
    old_bytes = Path(target).read_bytes()

    with pytest.raises(RuntimeError, match="符号链接或特殊文件"):
        reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)

    assert Path(target).read_bytes() == old_bytes
    assert not list((tmp_path / "submission" / "reverse_agent_answers").glob("*.tmp-*"))


def test_same_attempt_retry_invalidates_old_archive_before_new_failure(
        monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    target = Path(reverse_db.reverse_agent_answer_archive_path(9, "attempt-1"))
    target.parent.mkdir(parents=True)
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("ai_answer/old.txt", "old")

    assert reverse_tasks._invalidate_reverse_answer_archive(9, "attempt-1") is True
    assert not target.exists()

    source = tmp_path / "answer"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    try:
        (source / "leak.txt").symlink_to(outside)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")
    with pytest.raises(RuntimeError):
        reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)
    assert not target.exists()


def test_archive_publish_guard_rechecks_attempt_before_atomic_replace(
        monkeypatch, tmp_path):
    submission_root = _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    source.mkdir()
    (source / "solve.py").write_text("ok", encoding="utf-8")
    checks = iter((True, False))

    with pytest.raises(RuntimeError, match="attempt 已失效"):
        reverse_tasks._persist_agent_answer_archive(
            9, "attempt-1", source,
            publish_guard=lambda: next(checks),
        )

    assert not Path(
        reverse_db.reverse_agent_answer_archive_path(9, "attempt-1")
    ).exists()
    assert not submission_root.exists()


def test_persist_agent_answer_archive_rejects_fifo(monkeypatch, tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("当前平台不支持 FIFO")
    _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    source.mkdir()
    os.mkfifo(source / "pipe")

    with pytest.raises(RuntimeError, match="符号链接或特殊文件"):
        reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)


def test_persist_agent_answer_archive_enforces_file_count_limit(
        monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    monkeypatch.setattr(reverse_tasks, "REVERSE_ANSWER_MAX_FILES", 1)
    source = tmp_path / "answer"
    source.mkdir()
    (source / "one.txt").write_text("1", encoding="utf-8")
    (source / "two.txt").write_text("2", encoding="utf-8")

    with pytest.raises(RuntimeError, match="文件或目录数量超过限制"):
        reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)

    assert not os.path.exists(
        reverse_db.reverse_agent_answer_archive_path(9, "attempt-1")
    )


def test_persist_agent_answer_archive_counts_empty_directories(monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    monkeypatch.setattr(reverse_tasks, "REVERSE_ANSWER_MAX_FILES", 1)
    source = tmp_path / "answer"
    (source / "one").mkdir(parents=True)
    (source / "two").mkdir()

    with pytest.raises(RuntimeError, match="文件或目录数量超过限制"):
        reverse_tasks._persist_agent_answer_archive(9, "attempt-1", source)


@pytest.mark.parametrize("encoding", ["plain", "base64", "hex"])
def test_persist_agent_answer_archive_rejects_endpoint_secret_encodings(
        monkeypatch, tmp_path, encoding):
    import base64

    _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    source.mkdir()
    secret = "sk-private-endpoint-secret"
    payload = {
        "plain": secret,
        "base64": base64.b64encode(secret.encode()).decode(),
        "hex": secret.encode().hex(),
    }[encoding]
    (source / "result.txt").write_text(payload, encoding="utf-8")

    with pytest.raises(RuntimeError, match="包含端点凭证"):
        reverse_tasks._persist_agent_answer_archive(
            9, "attempt-1", source, sensitive_values=(secret,),
        )

    assert not os.path.exists(
        reverse_db.reverse_agent_answer_archive_path(9, "attempt-1")
    )


def test_persist_agent_answer_archive_rejects_secret_encoded_in_filename(
        monkeypatch, tmp_path):
    import base64

    _patch_submission_root(monkeypatch, tmp_path)
    source = tmp_path / "answer"
    source.mkdir()
    secret = "sk-private-endpoint-secret"
    encoded = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
    (source / encoded).write_bytes(b"")

    with pytest.raises(RuntimeError, match="文件名包含端点凭证"):
        reverse_tasks._persist_agent_answer_archive(
            9, "attempt-1", source, sensitive_values=(secret,),
        )


def test_reverse_snapshot_exposes_only_current_attempt_archive_availability(
        monkeypatch, tmp_path):
    _patch_submission_root(monkeypatch, tmp_path)
    submission = {
        "id": 9,
        "judge_attempt_id": "current-attempt",
        "status": "Accepted",
        "score": 75,
        "error_message": "",
    }
    monkeypatch.setattr(reverse_db, "get_ranking_submission", lambda _sid: submission)
    monkeypatch.setattr(reverse_db, "list_reverse_judge_steps", lambda _sid: [{
        "step_key": reverse_db.STEP_AGENT,
        "step_order": 3,
        "title": "AI 作答",
        "status": "passed",
    }])
    old_archive = reverse_db.reverse_agent_answer_archive_path(9, "old-attempt")
    os.makedirs(os.path.dirname(old_archive), exist_ok=True)
    Path(old_archive).write_bytes(b"old")

    unavailable = reverse_db.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in unavailable["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is False
    assert "answer_path" not in agent_step

    current_archive = reverse_db.reverse_agent_answer_archive_path(9, "current-attempt")
    Path(current_archive).write_bytes(b"current")
    available = reverse_db.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in available["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is True
    assert "answer_path" not in agent_step

    submission["status"] = "Judging"
    running = reverse_db.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in running["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is False

    submission["status"] = "Accepted"
    current_archive_path = Path(current_archive)
    current_archive_path.unlink()
    outside_archive = tmp_path / "outside.zip"
    outside_archive.write_bytes(b"outside")
    try:
        current_archive_path.symlink_to(outside_archive)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")
    linked = reverse_db.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in linked["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is False


@pytest.mark.parametrize("viewer", [
    {"username": "alice", "is_admin": 0},
    {"username": "admin", "is_admin": 1},
])
def test_download_reverse_agent_answer_allows_owner_and_admin(
        monkeypatch, tmp_path, viewer):
    archive_path = tmp_path / "answer.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("ai_answer/solve.py", "print('ok')")
    monkeypatch.setattr(
        routes, "_require_user",
        lambda: (viewer, None),
    )
    monkeypatch.setattr(routes, "get_ranking_submission", lambda _sid: {
        "id": 9,
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Accepted",
    })
    monkeypatch.setattr(
        routes, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    seen = []
    monkeypatch.setattr(
        routes, "reverse_agent_answer_archive_path",
        lambda sid, attempt: seen.append((sid, attempt)) or str(archive_path),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        response = routes.download_reverse_agent_answer(3, 9)
        response.direct_passthrough = False
        body = response.get_data()
        response.close()

    assert seen == [(9, "current")]
    assert body == archive_path.read_bytes()
    assert response.mimetype == "application/zip"
    assert "reverse_ai_answer_9.zip" in response.headers["Content-Disposition"]
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    ("user", "submission", "competition"),
    [
        (
            {"username": "mallory", "is_admin": 0},
            {"competition_id": 3, "username": "alice", "judge_attempt_id": "a1"},
            {"id": 3, "scoring_mode": "reverse_judge"},
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": 4, "username": "alice", "judge_attempt_id": "a1"},
            {"id": 3, "scoring_mode": "reverse_judge"},
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": 3, "username": "alice", "judge_attempt_id": "a1"},
            {"id": 3, "scoring_mode": "agent_judge"},
        ),
    ],
)
def test_download_reverse_agent_answer_hides_unauthorized_or_wrong_mode(
        monkeypatch, tmp_path, user, submission, competition):
    archive_path = tmp_path / "answer.zip"
    archive_path.write_bytes(b"zip")
    monkeypatch.setattr(routes, "_require_user", lambda: (user, None))
    monkeypatch.setattr(routes, "get_ranking_submission", lambda _sid: submission)
    monkeypatch.setattr(routes, "get_competition", lambda _cid: competition)
    monkeypatch.setattr(
        routes, "reverse_agent_answer_archive_path", lambda *_args: str(archive_path),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)


def test_download_reverse_agent_answer_rejects_missing_or_symlink_archive(
        monkeypatch, tmp_path):
    monkeypatch.setattr(
        routes, "_require_user",
        lambda: ({"username": "alice", "is_admin": 0}, None),
    )
    monkeypatch.setattr(routes, "get_ranking_submission", lambda _sid: {
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Accepted",
    })
    monkeypatch.setattr(
        routes, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    missing = tmp_path / "missing.zip"
    monkeypatch.setattr(
        routes, "reverse_agent_answer_archive_path", lambda *_args: str(missing),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)

    target = tmp_path / "target.zip"
    target.write_bytes(b"zip")
    try:
        missing.symlink_to(target)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")
    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)


def test_download_reverse_agent_answer_is_hidden_until_submission_finishes(
        monkeypatch, tmp_path):
    archive_path = tmp_path / "answer.zip"
    archive_path.write_bytes(b"zip")
    monkeypatch.setattr(
        routes, "_require_user",
        lambda: ({"username": "alice", "is_admin": 0}, None),
    )
    monkeypatch.setattr(routes, "get_ranking_submission", lambda _sid: {
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Judging",
    })
    monkeypatch.setattr(
        routes, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    monkeypatch.setattr(
        routes, "reverse_agent_answer_archive_path",
        lambda *_args: str(archive_path),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)


def test_reverse_detail_template_shows_download_only_after_archive_is_available():
    root = Path(__file__).resolve().parents[2]
    modal = (root / "templates" / "_reverse_judge_detail_modal.html").read_text(
        encoding="utf-8",
    )
    card = (root / "templates" / "_ranking_sub_card.html").read_text(
        encoding="utf-8",
    )

    assert "下载 AI 解答" in modal
    assert 'id="rjAnswerDownload"' in modal
    assert "answerStep.answer_available" in modal
    assert "data-answer-download-url" in card
    assert "ranking.download_reverse_agent_answer" in card
