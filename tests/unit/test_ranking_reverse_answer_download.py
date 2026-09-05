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

from backend.oj_modules.api import ranking_api
from backend.oj_modules.ranking import artifacts as ranking_artifacts
import backend.oj_modules.ranking.reverse_judge.db as reverse_db
import backend.oj_modules.ranking.reverse_judge.service as reverse_service
from backend.oj_modules.routes import ranking_routes as routes
import backend.oj_modules.tasks.ranking.reverse_judge as reverse_tasks


def _app():
    app = Flask(__name__)
    app.secret_key = "test"
    return app


def _patch_submission_root(monkeypatch, tmp_path):
    root = tmp_path / "submission"
    monkeypatch.setattr(reverse_db, "submission_dir", lambda _sid: str(root))
    monkeypatch.setattr(reverse_tasks, "submission_dir", lambda _sid: str(root))
    return root


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
    for internal in (".claude",):
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
            name.startswith("ai_answer/.claude")
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
    monkeypatch.setattr(reverse_service, "get_ranking_submission", lambda _sid: submission)
    monkeypatch.setattr(reverse_service, "list_reverse_judge_steps", lambda _sid: [{
        "step_key": reverse_db.STEP_AGENT,
        "step_order": 3,
        "title": "AI 作答",
        "status": "passed",
    }])
    old_archive = reverse_db.reverse_agent_answer_archive_path(9, "old-attempt")
    os.makedirs(os.path.dirname(old_archive), exist_ok=True)
    Path(old_archive).write_bytes(b"old")

    unavailable = reverse_service.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in unavailable["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is False
    assert "answer_path" not in agent_step

    current_archive = reverse_db.reverse_agent_answer_archive_path(9, "current-attempt")
    Path(current_archive).write_bytes(b"current")
    available = reverse_service.build_reverse_judge_snapshot(9)
    agent_step = next(
        step for step in available["steps"] if step["step_key"] == "agent_answer"
    )
    assert agent_step["answer_available"] is True
    assert "answer_path" not in agent_step

    submission["status"] = "Judging"
    running = reverse_service.build_reverse_judge_snapshot(9)
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
    linked = reverse_service.build_reverse_judge_snapshot(9)
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
    monkeypatch.setattr(ranking_artifacts, "get_ranking_submission", lambda _sid: {
        "id": 9,
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Accepted",
    })
    monkeypatch.setattr(
        ranking_artifacts, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    seen = []
    monkeypatch.setattr(
        ranking_artifacts, "available_reverse_agent_answer_archive_path",
        lambda sid, attempt, status: (
            seen.append((sid, attempt, status)) or str(archive_path)
        ),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        response = routes.download_reverse_agent_answer(3, 9)
        response.direct_passthrough = False
        body = response.get_data()
        response.close()

    assert seen == [(9, "current", "Accepted")]
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
    monkeypatch.setattr(ranking_artifacts, "get_ranking_submission", lambda _sid: submission)
    monkeypatch.setattr(ranking_artifacts, "get_competition", lambda _cid: competition)
    monkeypatch.setattr(
        ranking_artifacts,
        "available_reverse_agent_answer_archive_path",
        lambda *_args: str(archive_path),
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
    monkeypatch.setattr(ranking_artifacts, "get_ranking_submission", lambda _sid: {
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Accepted",
    })
    monkeypatch.setattr(
        ranking_artifacts, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    missing = tmp_path / "missing.zip"
    monkeypatch.setattr(
        ranking_artifacts,
        "available_reverse_agent_answer_archive_path",
        lambda *_args: None,
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
    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda *_args: str(missing),
    )
    monkeypatch.setattr(
        ranking_artifacts,
        "available_reverse_agent_answer_archive_path",
        reverse_db.available_reverse_agent_answer_archive_path,
    )
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
    monkeypatch.setattr(ranking_artifacts, "get_ranking_submission", lambda _sid: {
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "current",
        "status": "Judging",
    })
    monkeypatch.setattr(
        ranking_artifacts, "get_competition",
        lambda _cid: {"id": 3, "scoring_mode": "reverse_judge"},
    )
    monkeypatch.setattr(
        ranking_artifacts,
        "available_reverse_agent_answer_archive_path",
        lambda *_args: None,
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)


@pytest.mark.parametrize("status", ["Accepted", "Error"])
def test_available_reverse_agent_answer_archive_path_accepts_terminal_regular_file(
        monkeypatch, tmp_path, status):
    archive_path = tmp_path / "current.zip"
    archive_path.write_bytes(b"zip")
    calls = []
    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda submission_id, attempt_id: (
            calls.append((submission_id, attempt_id)) or str(archive_path)
        ),
    )

    result = reverse_db.available_reverse_agent_answer_archive_path(
        9, "attempt-1", status,
    )

    assert result == str(archive_path)
    assert calls == [(9, "attempt-1")]


def test_available_reverse_agent_answer_archive_path_rejects_unavailable_inputs(
        monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda submission_id, attempt_id: calls.append(
            (submission_id, attempt_id),
        ) or str(tmp_path / "missing.zip"),
    )

    assert reverse_db.available_reverse_agent_answer_archive_path(
        9, "attempt-1", "Judging",
    ) is None
    assert calls == []
    assert reverse_db.available_reverse_agent_answer_archive_path(
        9, "attempt-1", "Accepted",
    ) is None

    directory = tmp_path / "archive-dir"
    directory.mkdir()
    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda *_args: str(directory),
    )
    assert reverse_db.available_reverse_agent_answer_archive_path(
        9, "attempt-1", "Error",
    ) is None

    target = tmp_path / "target.zip"
    target.write_bytes(b"zip")
    symlink = tmp_path / "answer-link.zip"
    try:
        symlink.symlink_to(target)
    except OSError:
        pytest.skip("当前文件系统不支持符号链接")
    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda *_args: str(symlink),
    )
    assert reverse_db.available_reverse_agent_answer_archive_path(
        9, "attempt-1", "Accepted",
    ) is None

    monkeypatch.setattr(
        reverse_db,
        "reverse_agent_answer_archive_path",
        lambda *_args: (_ for _ in ()).throw(ValueError("invalid attempt")),
    )
    assert reverse_db.available_reverse_agent_answer_archive_path(
        9, None, "Accepted",
    ) is None


def test_build_reverse_judge_snapshot_missing_submission_short_circuits(
        monkeypatch):
    monkeypatch.setattr(reverse_service, "get_ranking_submission", lambda _sid: None)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("提交不存在时不应继续查询步骤或归档")

    monkeypatch.setattr(reverse_service, "list_reverse_judge_steps", unexpected)
    monkeypatch.setattr(
        reverse_service, "available_reverse_agent_answer_archive_path", unexpected,
    )

    assert reverse_service.build_reverse_judge_snapshot(9) is None


@pytest.mark.parametrize(
    ("archive_path", "expected_available"),
    [("/tmp/current.zip", True), (None, False)],
)
def test_build_reverse_judge_snapshot_exposes_current_archive_only_on_agent_step(
        monkeypatch, archive_path, expected_available):
    submission = {
        "id": 9,
        "judge_attempt_id": "current",
        "status": "Accepted",
        "score": 88,
        "error_message": "",
    }
    monkeypatch.setattr(
        reverse_service, "get_ranking_submission", lambda _sid: submission,
    )
    monkeypatch.setattr(reverse_service, "list_reverse_judge_steps", lambda _sid: [
        {
            "step_key": reverse_db.STEP_AGENT,
            "step_order": 3,
            "title": "AI 作答",
            "status": "passed",
        },
        {
            "step_key": reverse_db.STEP_AI_JUDGE,
            "step_order": 4,
            "title": "评测 AI 答案",
            "status": "passed",
        },
    ])
    archive_calls = []
    monkeypatch.setattr(
        reverse_service,
        "available_reverse_agent_answer_archive_path",
        lambda submission_id, attempt_id, status: (
            archive_calls.append((submission_id, attempt_id, status))
            or archive_path
        ),
    )

    snapshot = reverse_service.build_reverse_judge_snapshot(9)

    assert archive_calls == [(9, "current", "Accepted")]
    assert snapshot is not None
    agent_step, judge_step = snapshot["steps"]
    assert agent_step["answer_available"] is expected_available
    assert "answer_available" not in judge_step
    if archive_path is not None:
        assert archive_path not in repr(snapshot)


@pytest.mark.parametrize(
    ("viewer", "requested_competition_id"),
    [
        ({"username": "alice", "is_admin": 0}, 3),
        ({"username": "admin", "is_admin": 1}, None),
    ],
)
def test_resolve_reverse_agent_answer_archive_authorized_user_uses_current_attempt(
        monkeypatch, viewer, requested_competition_id):
    monkeypatch.setattr(ranking_artifacts, "get_ranking_submission", lambda _sid: {
        "id": 9,
        "competition_id": 3,
        "username": "alice",
        "judge_attempt_id": "a2",
        "status": "Accepted",
    })
    monkeypatch.setattr(ranking_artifacts, "get_competition", lambda _cid: {
        "id": 3,
        "scoring_mode": "reverse_judge",
    })
    calls = []
    monkeypatch.setattr(
        ranking_artifacts,
        "available_reverse_agent_answer_archive_path",
        lambda submission_id, attempt_id, status: (
            calls.append((submission_id, attempt_id, status))
            or "/tmp/current.zip"
        ),
    )

    result = ranking_artifacts.resolve_reverse_agent_answer_archive(
        viewer, 9, competition_id=requested_competition_id,
    )

    assert result == "/tmp/current.zip"
    assert calls == [(9, "a2", "Accepted")]


@pytest.mark.parametrize(
    ("viewer", "submission", "requested_competition_id", "competition"),
    [
        ({"username": "alice", "is_admin": 0}, None, 3, None),
        (
            {"username": "mallory", "is_admin": 0},
            {"competition_id": 3, "username": "alice"},
            3,
            {"scoring_mode": "reverse_judge"},
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": "invalid", "username": "alice"},
            None,
            None,
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": 4, "username": "alice"},
            3,
            {"scoring_mode": "reverse_judge"},
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": 3, "username": "alice"},
            3,
            None,
        ),
        (
            {"username": "alice", "is_admin": 0},
            {"competition_id": 3, "username": "alice"},
            3,
            {"scoring_mode": "agent_judge"},
        ),
    ],
)
def test_resolve_reverse_agent_answer_archive_hides_invalid_or_unauthorized(
        monkeypatch, viewer, submission, requested_competition_id, competition):
    monkeypatch.setattr(
        ranking_artifacts, "get_ranking_submission", lambda _sid: submission,
    )
    monkeypatch.setattr(ranking_artifacts, "get_competition", lambda _cid: competition)

    def unexpected(*_args, **_kwargs):
        raise AssertionError("guard 失败后不应检查归档")

    monkeypatch.setattr(
        ranking_artifacts, "available_reverse_agent_answer_archive_path", unexpected,
    )

    assert ranking_artifacts.resolve_reverse_agent_answer_archive(
        viewer, 9, competition_id=requested_competition_id,
    ) is None


def test_send_reverse_agent_answer_archive_returns_hardened_zip(
        tmp_path):
    archive_path = tmp_path / "answer.zip"
    archive_bytes = b"PK\x03\x04test-archive"
    archive_path.write_bytes(archive_bytes)

    with _app().test_request_context("/api/download"):
        response = ranking_artifacts.send_reverse_agent_answer_archive(str(archive_path), 9)
        response.direct_passthrough = False
        body = response.get_data()
        response.close()

    assert body == archive_bytes
    assert response.mimetype == "application/zip"
    assert "reverse_ai_answer_9.zip" in response.headers["Content-Disposition"]
    assert response.headers["Cache-Control"] == "private, no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_download_reverse_agent_answer_delegates_auth_resolution_and_send(
        monkeypatch):
    auth_error = object()
    resolver_calls = []
    sender_calls = []
    monkeypatch.setattr(routes, "_require_user", lambda: (None, auth_error))

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        assert routes.download_reverse_agent_answer(3, 9) is auth_error

    user = {"username": "alice", "is_admin": 0}
    monkeypatch.setattr(routes, "_require_user", lambda: (user, None))
    monkeypatch.setattr(
        routes,
        "resolve_reverse_agent_answer_archive",
        lambda actual_user, submission_id, competition_id=None: (
            resolver_calls.append(
                (actual_user, submission_id, competition_id),
            ) or "/tmp/current.zip"
        ),
    )
    sent_response = object()
    monkeypatch.setattr(
        routes,
        "send_reverse_agent_answer_archive",
        lambda archive_path, submission_id: (
            sender_calls.append((archive_path, submission_id)) or sent_response
        ),
    )

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        assert routes.download_reverse_agent_answer(3, 9) is sent_response

    assert resolver_calls == [(user, 9, 3)]
    assert sender_calls == [("/tmp/current.zip", 9)]


def test_download_reverse_agent_answer_missing_archive_aborts_404(monkeypatch):
    user = {"username": "alice", "is_admin": 0}
    monkeypatch.setattr(routes, "_require_user", lambda: (user, None))
    monkeypatch.setattr(
        routes, "resolve_reverse_agent_answer_archive", lambda *_args, **_kwargs: None,
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("归档缺失时不应发送响应")

    monkeypatch.setattr(routes, "send_reverse_agent_answer_archive", unexpected)

    with _app().test_request_context("/ranking/3/submission/9/reverse_agent_answer"):
        with pytest.raises(NotFound):
            routes.download_reverse_agent_answer(3, 9)


def test_submission_download_urls_exposes_available_reverse_answer(monkeypatch):
    calls = []
    monkeypatch.setattr(
        ranking_api,
        "available_reverse_agent_answer_archive_path",
        lambda submission_id, attempt_id, status: (
            calls.append((submission_id, attempt_id, status))
            or "/tmp/current.zip"
        ),
    )

    result = ranking_api._submission_download_urls({
        "id": 9,
        "judge_attempt_id": "attempt-2",
        "status": "Accepted",
    }, include_reverse_answer=True)

    assert calls == [(9, "attempt-2", "Accepted")]
    assert result["answer_download_url"] == "/api/ranking/submissions/9/answer"
    assert result["code_download_url"] == "/api/ranking/submissions/9/code"
    assert result["ai_answer_available"] is True
    assert result["ai_answer_download_url"] == (
        "/api/ranking/submissions/9/reverse-agent-answer"
    )
    assert "judge_attempt_id" not in result


def test_submission_download_urls_does_not_advertise_disabled_or_missing_archive(
        monkeypatch):
    calls = []
    monkeypatch.setattr(
        ranking_api,
        "available_reverse_agent_answer_archive_path",
        lambda *args: calls.append(args) or None,
    )

    disabled = ranking_api._submission_download_urls({
        "id": 9,
        "judge_attempt_id": "attempt-2",
        "status": "Accepted",
    }, include_reverse_answer=False)
    assert calls == []
    assert disabled["ai_answer_available"] is False
    assert disabled["ai_answer_download_url"] is None

    unavailable = ranking_api._submission_download_urls({
        "id": 9,
        "judge_attempt_id": "attempt-2",
        "status": "Error",
    }, include_reverse_answer=True)
    assert calls == [(9, "attempt-2", "Error")]
    assert unavailable["ai_answer_available"] is False
    assert unavailable["ai_answer_download_url"] is None

    missing_id = ranking_api._submission_download_urls({
        "judge_attempt_id": "attempt-2",
        "status": "Accepted",
    }, include_reverse_answer=True)
    assert calls == [(9, "attempt-2", "Error")]
    assert missing_id["ai_answer_available"] is False
    assert missing_id["ai_answer_download_url"] is None
    assert "judge_attempt_id" not in missing_id


@pytest.mark.parametrize("include_admin", [False, True])
def test_safe_submission_filters_sensitive_fields_only_for_non_admin(
        monkeypatch, include_admin):
    calls = []
    projected = {
        "id": 9,
        "elo_rating": 1200,
        "elo_match_count": 4,
        "elo_in_pool": 1,
        "judge_log": "private log",
        "traceback": "private traceback",
        "ai_answer_available": True,
        "ai_answer_download_url": "/api/ranking/submissions/9/reverse-agent-answer",
    }
    monkeypatch.setattr(
        ranking_api,
        "_submission_download_urls",
        lambda row, include_reverse_answer=False: (
            calls.append((row, include_reverse_answer)) or dict(projected)
        ),
    )
    source = {"id": 9}

    result = ranking_api._safe_submission(
        source,
        include_admin=include_admin,
        include_reverse_answer=True,
    )

    assert calls == [(source, True)]
    assert result["ai_answer_available"] is True
    assert result["ai_answer_download_url"].endswith("/reverse-agent-answer")
    sensitive = {"elo_rating", "elo_match_count", "elo_in_pool", "judge_log", "traceback"}
    if include_admin:
        assert sensitive <= result.keys()
    else:
        assert sensitive.isdisjoint(result)


def test_reverse_agent_answer_api_returns_auth_error_and_hidden_404(monkeypatch):
    auth_error = object()
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (None, auth_error))

    with _app().test_request_context("/api/ranking/submissions/9/reverse-agent-answer"):
        assert ranking_api.reverse_agent_answer(9) is auth_error

    user = {"username": "alice", "is_admin": 0}
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (user, None))
    resolver_calls = []
    monkeypatch.setattr(
        ranking_api,
        "resolve_reverse_agent_answer_archive",
        lambda actual_user, submission_id: (
            resolver_calls.append((actual_user, submission_id)) or None
        ),
    )

    with _app().test_request_context("/api/ranking/submissions/9/reverse-agent-answer"):
        response, status = ranking_api.reverse_agent_answer(9)

    assert resolver_calls == [(user, 9)]
    assert status == 404
    assert response.get_json() == {
        "success": False,
        "message": "AI 解答不存在或无权限",
    }


def test_reverse_agent_answer_api_success_delegates_binary_response(monkeypatch):
    user = {"username": "alice", "is_admin": 0}
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (user, None))
    resolver_calls = []
    sender_calls = []
    monkeypatch.setattr(
        ranking_api,
        "resolve_reverse_agent_answer_archive",
        lambda actual_user, submission_id: (
            resolver_calls.append((actual_user, submission_id))
            or "/tmp/current.zip"
        ),
    )
    sent_response = object()
    monkeypatch.setattr(
        ranking_api,
        "send_reverse_agent_answer_archive",
        lambda archive_path, submission_id: (
            sender_calls.append((archive_path, submission_id)) or sent_response
        ),
    )

    with _app().test_request_context("/api/ranking/submissions/9/reverse-agent-answer"):
        assert ranking_api.reverse_agent_answer(9) is sent_response

    assert resolver_calls == [(user, 9)]
    assert sender_calls == [("/tmp/current.zip", 9)]


def _patch_competition_detail_common(monkeypatch, comp, user):
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (user, None))
    monkeypatch.setattr(
        ranking_api, "_competition_for_user", lambda *_args: (comp, None),
    )
    monkeypatch.setattr(ranking_api, "list_competition_files", lambda _cid: [])
    monkeypatch.setattr(
        ranking_api,
        "get_ranking_navigation_state",
        lambda competition_id, username: {
            "competition_id": competition_id,
            "username": username,
        },
    )
    monkeypatch.setattr(ranking_api, "_agent_judge_endpoint_ready", lambda *_args: True)
    monkeypatch.setattr(ranking_api, "_reverse_quality_gate_ready", lambda *_args: True)
    monkeypatch.setattr(ranking_api, "list_agent_judge_endpoints", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ranking_api, "list_quality_gate_endpoints", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ranking_api, "_masked_agent_endpoints", lambda rows: rows)
    monkeypatch.setattr(
        ranking_api,
        "_safe_competition",
        lambda row, include_admin=False: {
            "id": row["id"],
            "scoring_mode": row["scoring_mode"],
        },
    )


def test_competition_detail_reverse_submit_enables_answer_projection(monkeypatch):
    comp = {
        "id": 3,
        "scoring_mode": "reverse_judge",
        "submission_method": "zip",
    }
    user = {"username": "alice", "is_admin": 0}
    _patch_competition_detail_common(monkeypatch, comp, user)
    source_row = {"id": 9}
    monkeypatch.setattr(
        ranking_api, "list_user_submissions", lambda *_args: [source_row],
    )
    projection_calls = []
    monkeypatch.setattr(
        ranking_api,
        "_safe_submission",
        lambda row, include_admin=False, include_reverse_answer=False: (
            projection_calls.append(
                (row, include_admin, include_reverse_answer),
            ) or {"id": row["id"], "projected": True}
        ),
    )
    monkeypatch.setattr(ranking_api, "_ranking_submit_block_reason", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(ranking_api, "get_submission_quota", lambda *_args, **_kwargs: None)

    with _app().test_request_context("/api/ranking/competitions/3?tab=submit"):
        response = ranking_api.competition_detail(3)

    data = response.get_json()
    assert projection_calls == [(source_row, False, True)]
    assert data["success"] is True
    assert data["user_submissions"] == [{"id": 9, "projected": True}]


@pytest.mark.parametrize(
    ("scoring_mode", "expected_reverse"),
    [("reverse_judge", True), ("absolute", False)],
)
def test_competition_detail_all_submissions_flag_tracks_scoring_mode(
        monkeypatch, scoring_mode, expected_reverse):
    comp = {
        "id": 3,
        "scoring_mode": scoring_mode,
        "submission_method": "zip",
    }
    user = {"username": "admin", "is_admin": 1}
    _patch_competition_detail_common(monkeypatch, comp, user)
    source_row = {"id": 9}
    monkeypatch.setattr(
        ranking_api,
        "list_all_submissions",
        lambda *_args, **_kwargs: ([source_row], 1, 1),
    )
    monkeypatch.setattr(ranking_api, "get_submission_stats", lambda _cid: {})
    projection_calls = []
    monkeypatch.setattr(
        ranking_api,
        "_submission_download_urls",
        lambda row, include_reverse_answer=False: (
            projection_calls.append((row, include_reverse_answer))
            or {"id": row["id"]}
        ),
    )

    with _app().test_request_context(
            "/api/ranking/competitions/3?tab=all_submissions"):
        response = ranking_api.competition_detail(3)

    data = response.get_json()
    assert projection_calls == [(source_row, expected_reverse)]
    assert data["success"] is True
    assert data["total"] == 1
    assert data["all_submissions"] == [{"id": 9}]


@pytest.mark.parametrize(
    ("scoring_mode", "expected_reverse"),
    [("reverse_judge", True), ("absolute", False)],
)
def test_my_submissions_projection_flag_tracks_mode_and_limit(
        monkeypatch, scoring_mode, expected_reverse):
    user = {"username": "alice", "is_admin": 0}
    comp = {"id": 3, "scoring_mode": scoring_mode}
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (user, None))
    monkeypatch.setattr(
        ranking_api, "_competition_for_user", lambda *_args: (comp, None),
    )
    source_rows = [{"id": 9}, {"id": 10}]
    monkeypatch.setattr(
        ranking_api, "list_user_submissions", lambda *_args: source_rows,
    )
    monkeypatch.setattr(
        ranking_api,
        "_safe_competition",
        lambda *_args, **_kwargs: {"id": 3, "scoring_mode": scoring_mode},
    )
    projection_calls = []
    monkeypatch.setattr(
        ranking_api,
        "_safe_submission",
        lambda row, include_admin=False, include_reverse_answer=False: (
            projection_calls.append(
                (row["id"], include_admin, include_reverse_answer),
            ) or {"id": row["id"]}
        ),
    )

    with _app().test_request_context(
            "/api/ranking/competitions/3/my-submissions?limit=1"):
        response = ranking_api.my_submissions(3)

    data = response.get_json()
    assert projection_calls == [(9, False, expected_reverse)]
    assert data["count"] == 1
    assert data["total"] == 2
    assert data["submissions"] == [{"id": 9}]


def test_all_submissions_api_rejects_non_admin_before_queries(monkeypatch):
    monkeypatch.setattr(
        ranking_api,
        "_require_user",
        lambda: ({"username": "alice", "is_admin": 0}, None),
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("非管理员不应查询比赛或提交")

    monkeypatch.setattr(ranking_api, "_competition_for_user", unexpected)
    monkeypatch.setattr(ranking_api, "list_all_submissions", unexpected)

    with _app().test_request_context("/api/ranking/competitions/3/submissions"):
        response, status = ranking_api.all_submissions(3)

    assert status == 403
    assert response.get_json() == {"success": False, "message": "无权限"}


@pytest.mark.parametrize(
    ("scoring_mode", "expected_reverse"),
    [("reverse_judge", True), ("absolute", False)],
)
def test_all_submissions_api_admin_projection_flag_tracks_mode(
        monkeypatch, scoring_mode, expected_reverse):
    user = {"username": "admin", "is_admin": 1}
    comp = {"id": 3, "scoring_mode": scoring_mode}
    monkeypatch.setattr(ranking_api, "_require_user", lambda: (user, None))
    monkeypatch.setattr(
        ranking_api, "_competition_for_user", lambda *_args: (comp, None),
    )
    source_row = {"id": 9}
    list_calls = []
    monkeypatch.setattr(
        ranking_api,
        "list_all_submissions",
        lambda competition_id, **kwargs: (
            list_calls.append((competition_id, kwargs))
            or ([source_row], 2, 3)
        ),
    )
    monkeypatch.setattr(
        ranking_api,
        "_safe_competition",
        lambda *_args, **_kwargs: {"id": 3, "scoring_mode": scoring_mode},
    )
    monkeypatch.setattr(ranking_api, "get_submission_stats", lambda _cid: {"total": 3})
    projection_calls = []
    monkeypatch.setattr(
        ranking_api,
        "_submission_download_urls",
        lambda row, include_reverse_answer=False: (
            projection_calls.append((row, include_reverse_answer))
            or {"id": row["id"]}
        ),
    )

    with _app().test_request_context(
            "/api/ranking/competitions/3/submissions?page=2&q=alice"):
        response = ranking_api.all_submissions(3)

    data = response.get_json()
    assert list_calls == [(3, {
        "page": 2,
        "per_page": ranking_api.SUBMISSIONS_PER_PAGE,
        "username_q": "alice",
    })]
    assert projection_calls == [(source_row, expected_reverse)]
    assert data["count"] == 1
    assert data["total"] == 3
    assert data["page"] == 2
    assert data["submissions"] == [{"id": 9}]


@pytest.fixture(autouse=True)
def _no_judge_sessions_by_default(monkeypatch):
    monkeypatch.setattr(reverse_service, 'get_judge_session_for_attempt', lambda *args: None)


def test_reverse_snapshot_links_generic_session_without_internal_dispatch_state(monkeypatch):
    monkeypatch.setattr(reverse_service, 'get_ranking_submission', lambda sid: {
        'id': sid, 'judge_attempt_id': 'attempt', 'status': 'Judging'})
    monkeypatch.setattr(reverse_service, 'list_reverse_judge_steps', lambda sid: [{
        'step_key': reverse_db.STEP_QUALITY_GATE, 'status': 'passed',
        'result_json': {'passed': True, 'summary': '通过', '_agent': {
            'session_id': 'private-unrelated-quality', 'task_id': 'private-task',
            'slot_key': 'private-pool-slot', 'endpoint_id': 11}},
        'trace_dir': '/private/legacy/trace',
    }, {
        'step_key': reverse_db.STEP_AGENT, 'status': 'running',
        'result_json': {'_agent': {'session_id': 'private-unrelated-answer'}},
    }])
    lookups = []
    def get_session(submission_id, attempt_id, kind):
        lookups.append((submission_id, attempt_id, kind))
        return {'session_id': {
            'reverse_quality': 'generic-quality',
            'reverse_answer': 'generic-answer',
        }[kind]}
    monkeypatch.setattr(reverse_service, 'get_judge_session_for_attempt', get_session)
    snapshot = reverse_service.build_reverse_judge_snapshot(7)
    quality, answer = snapshot['steps']
    assert quality['agent_session_id'] == 'generic-quality'
    assert answer['agent_session_id'] == 'generic-answer'
    assert quality['result'] == {'passed': True, 'summary': '通过'}
    assert lookups == [(7, 'attempt', 'reverse_quality'), (7, 'attempt', 'reverse_answer')]
    assert 'private' not in repr(snapshot)
    assert all('trace_messages' not in step and 'trace_files' not in step for step in snapshot['steps'])


@pytest.mark.parametrize('step_key', [reverse_db.STEP_QUALITY_GATE, reverse_db.STEP_AGENT])
def test_reverse_snapshot_has_no_link_when_dispatch_failed_before_session_creation(monkeypatch, step_key):
    monkeypatch.setattr(reverse_service, 'get_ranking_submission', lambda sid: {
        'id': sid, 'judge_attempt_id': 'attempt', 'status': 'Error'})
    monkeypatch.setattr(reverse_service, 'list_reverse_judge_steps', lambda sid: [{
        'step_key': step_key, 'status': 'error',
        'error_message': '通用 Agent 派发失败：材料导入失败',
        'result_json': {'_agent': {'session_id': 'not-created', 'task_id': 'not-created-run'}},
    }])

    snapshot = reverse_service.build_reverse_judge_snapshot(7)

    assert snapshot['steps'][0]['agent_session_id'] is None
    assert snapshot['steps'][0]['status'] == 'error'
    assert snapshot['steps'][0]['error_message'] == '通用 Agent 派发失败：材料导入失败'
    assert 'not-created' not in repr(snapshot)
