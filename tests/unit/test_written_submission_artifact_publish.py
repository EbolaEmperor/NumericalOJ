#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""人工书面作业 generation 发布与崩溃恢复测试（无 MySQL/Redis）。"""

import io
import json
from pathlib import Path

import pytest
from flask import Flask

from oj_modules import db_services
from oj_modules.judging import core as judger_core
from oj_modules.project_paths import PROJECT_ROOT
from oj_modules.submissions import archive as submission_archive
from oj_modules.submissions import written_artifacts as artifacts
from oj_modules.routes import problem_core_routes


class _UploadedFile:
    def __init__(self, payload):
        self.payload = payload

    def save(self, destination):
        Path(destination).write_bytes(self.payload)


def _submission(filename="old.pdf", **overrides):
    row = {
        "id": 41,
        "problem_id": 7,
        "problem_title": "人工作业",
        "problem_type": 2,
        "username": "student",
        "code": " ",
        "score": 4,
        "status": "Completed",
        "test_points": json.dumps(filename, ensure_ascii=False),
        "created_at": "2026-07-01 10:00:00",
    }
    row.update(overrides)
    return row


@pytest.fixture
def publish_environment(monkeypatch, tmp_path):
    upload_root = tmp_path / "uploads"
    run_root = tmp_path / "judger"
    monkeypatch.setattr(judger_core, "JUDGER_RUN_ROOT", str(run_root))

    upload_target = upload_root / "41"
    upload_target.mkdir(parents=True)
    (upload_target / "old.pdf").write_bytes(b"old-pdf")
    archive_target = Path(submission_archive.archive_dir_for_submission(41))
    archive_target.mkdir(parents=True)
    (archive_target / "legacy.txt").write_text("old archive", encoding="utf-8")
    return {
        "upload_root": upload_root,
        "upload_target": upload_target,
        "archive_target": archive_target,
        "problem": {"id": 7, "title": "人工作业", "type": 2},
        "user": {"id": 3, "username": "student", "email": "student@example.com"},
        "classes": [{"class_en": "C1", "class_cn": "一班"}],
    }


def _call_publish(env, *, payload=b"new-pdf", max_bytes=1024, overwrite=None):
    state = {"submission": _submission()}
    events = []

    def default_overwrite(submission_id, stored_filename, expected):
        events.append(("overwrite", submission_id, stored_filename, expected["score"]))
        state["submission"] = {
            **state["submission"],
            "score": 0,
            "status": "Pending",
            "test_points": json.dumps(stored_filename, ensure_ascii=False),
        }

    result = artifacts.publish_manual_written_submission(
        uploaded_file=_UploadedFile(payload),
        filename="file_new.pdf",
        previous_submission=_submission(),
        problem=env["problem"],
        user=env["user"],
        classes=env["classes"],
        overwrite_record=overwrite or default_overwrite,
        load_current_record=lambda _sid: state["submission"],
        max_bytes=max_bytes,
        upload_root=env["upload_root"],
    )
    return result, state, events


def _journals(env):
    root = env["upload_root"] / artifacts.JOURNAL_DIRNAME
    return list(root.glob("*.json")) if root.exists() else []


def _assert_old_artifacts(env):
    assert {path.name for path in env["upload_target"].iterdir()} == {"old.pdf"}
    assert (env["upload_target"] / "old.pdf").read_bytes() == b"old-pdf"
    assert (env["archive_target"] / "legacy.txt").read_text(encoding="utf-8") == "old archive"
    assert _journals(env) == []
    assert list(env["archive_target"].parent.glob(".*.backup-*")) == []


def test_success_switches_database_only_after_immutable_files_are_ready(publish_environment):
    env = publish_environment

    result, state, events = _call_publish(env)

    stored = Path(result).name
    assert stored.startswith("file_new.") and stored.endswith(".pdf")
    assert Path(result).read_bytes() == b"new-pdf"
    assert {path.name for path in env["upload_target"].iterdir()} == {stored}
    assert json.loads(state["submission"]["test_points"]) == stored
    assert events == [("overwrite", 41, stored, 4)]
    assert (env["archive_target"] / "submitted.pdf").read_bytes() == b"new-pdf"
    assert artifacts.READY_MARKER not in {
        path.name for path in env["archive_target"].iterdir()
    }
    assert _journals(env) == []


def test_oversized_upload_never_calls_database_or_touches_old_files(publish_environment):
    calls = []
    with pytest.raises(artifacts.WrittenSubmissionArtifactError, match="已保留"):
        _call_publish(
            publish_environment,
            payload=b"too-large",
            max_bytes=3,
            overwrite=lambda *_args: calls.append(_args),
        )
    assert calls == []
    _assert_old_artifacts(publish_environment)


def test_database_rejection_rolls_back_generation_and_archive(publish_environment):
    with pytest.raises(artifacts.WrittenSubmissionArtifactError, match="已保留"):
        _call_publish(
            publish_environment,
            overwrite=lambda *_args: (_ for _ in ()).throw(RuntimeError("CAS rejected")),
        )
    _assert_old_artifacts(publish_environment)


def test_archive_switch_failure_occurs_before_database_update(
    monkeypatch,
    publish_environment,
):
    calls = []
    monkeypatch.setattr(
        artifacts._DirectorySwap,
        "publish",
        lambda _swap: (_ for _ in ()).throw(OSError("rename failed")),
    )
    with pytest.raises(artifacts.WrittenSubmissionArtifactError, match="已保留"):
        _call_publish(
            publish_environment,
            overwrite=lambda *_args: calls.append(_args),
        )
    assert calls == []
    _assert_old_artifacts(publish_environment)


def test_recovery_rolls_back_worker_death_before_database_commit(publish_environment):
    env = publish_environment
    state = {"submission": _submission()}

    with pytest.raises(KeyboardInterrupt):
        artifacts.publish_manual_written_submission(
            uploaded_file=_UploadedFile(b"new-pdf"),
            filename="file_new.pdf",
            previous_submission=state["submission"],
            problem=env["problem"],
            user=env["user"],
            classes=env["classes"],
            overwrite_record=lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
            load_current_record=lambda _sid: state["submission"],
            max_bytes=1024,
            upload_root=env["upload_root"],
        )

    assert len(_journals(env)) == 1
    result = artifacts.recover_written_submission_publications(
        lambda _sid: state["submission"],
        upload_root=env["upload_root"],
        min_age_seconds=0,
    )
    assert result == {"completed": 0, "rolled_back": 1, "conflicts": 0, "failed": 0}
    _assert_old_artifacts(env)


def test_recovery_finishes_ambiguous_commit_without_deleting_new_file(publish_environment):
    env = publish_environment
    state = {"submission": _submission()}

    def commit_then_die(_sid, stored_filename, _expected):
        state["submission"] = {
            **state["submission"],
            "score": 0,
            "status": "Pending",
            "test_points": json.dumps(stored_filename),
        }
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        artifacts.publish_manual_written_submission(
            uploaded_file=_UploadedFile(b"new-pdf"),
            filename="file_new.pdf",
            previous_submission=state["submission"],
            problem=env["problem"],
            user=env["user"],
            classes=env["classes"],
            overwrite_record=commit_then_die,
            load_current_record=lambda _sid: state["submission"],
            max_bytes=1024,
            upload_root=env["upload_root"],
        )

    result = artifacts.recover_written_submission_publications(
        lambda _sid: state["submission"],
        upload_root=env["upload_root"],
        min_age_seconds=0,
    )
    stored = json.loads(state["submission"]["test_points"])
    assert result == {"completed": 1, "rolled_back": 0, "conflicts": 0, "failed": 0}
    assert (env["upload_target"] / stored).read_bytes() == b"new-pdf"
    assert {path.name for path in env["upload_target"].iterdir()} == {stored}
    assert _journals(env) == []


def test_recovery_refuses_to_overwrite_an_unrelated_concurrent_generation(
    publish_environment,
):
    env = publish_environment
    state = {"submission": _submission()}
    with pytest.raises(KeyboardInterrupt):
        artifacts.publish_manual_written_submission(
            uploaded_file=_UploadedFile(b"new-pdf"),
            filename="file_new.pdf",
            previous_submission=state["submission"],
            problem=env["problem"],
            user=env["user"],
            classes=env["classes"],
            overwrite_record=lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
            load_current_record=lambda _sid: state["submission"],
            max_bytes=1024,
            upload_root=env["upload_root"],
        )
    state["submission"] = _submission("another-generation.pdf", score=9)

    result = artifacts.recover_written_submission_publications(
        lambda _sid: state["submission"],
        upload_root=env["upload_root"],
        min_age_seconds=0,
    )
    assert result["conflicts"] == 1
    assert len(_journals(env)) == 1


class _DbCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 0
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.connection.calls.append((normalized, params))
        self.rowcount = 0
        self.result = None
        if normalized.startswith("SELECT id, username, is_admin FROM users"):
            self.result = {"id": 3, "username": "student", "is_admin": 0}
        elif normalized.startswith("SELECT id, username, problem_id, test_points"):
            self.result = dict(self.connection.submission)
        elif normalized.startswith("INSERT INTO submission_limits"):
            self.rowcount = 1
        elif normalized.startswith("SELECT submission_count FROM submission_limits"):
            self.result = {"submission_count": self.connection.submission_count}
        elif normalized.startswith("UPDATE submission_limits"):
            self.rowcount = 1
        elif normalized.startswith("UPDATE submissions"):
            if self.connection.fail_submission_update:
                raise RuntimeError("injected update failure")
            self.rowcount = 1
        else:  # pragma: no cover - 新 SQL 必须显式加入契约
            raise AssertionError(f"unexpected SQL: {normalized}")

    def fetchone(self):
        return self.result


class _DbConnection:
    def __init__(self, *, submission=None, submission_count=2, fail_submission_update=False):
        self.submission = submission or _submission()
        self.submission_count = submission_count
        self.fail_submission_update = fail_submission_update
        self.calls = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = 0

    def cursor(self):
        return _DbCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed += 1


def test_database_cas_reserves_quota_and_updates_pointer_in_one_transaction(monkeypatch):
    connection = _DbConnection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda _sid: None)

    db_services.overwrite_written_submission(
        41,
        "file_new.generation.pdf",
        submission_limit=5,
        username="student",
        problem_id=7,
        user_id=3,
        expected_submission=_submission(),
    )

    statements = [sql for sql, _params in connection.calls]
    lock_index = next(i for i, sql in enumerate(statements) if "FROM submissions" in sql)
    quota_index = next(i for i, sql in enumerate(statements) if sql.startswith("UPDATE submission_limits"))
    update_index = next(i for i, sql in enumerate(statements) if sql.startswith("UPDATE submissions"))
    assert lock_index < quota_index < update_index
    assert connection.commits == 1 and connection.rollbacks == 0


def test_database_cas_rejects_concurrent_grading_before_reserving_quota(monkeypatch):
    connection = _DbConnection(submission=_submission(score=9, status="Reviewed"))
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)

    with pytest.raises(RuntimeError, match="其他流程更新"):
        db_services.overwrite_written_submission(
            41,
            "file_new.generation.pdf",
            submission_limit=5,
            username="student",
            problem_id=7,
            user_id=3,
            expected_submission=_submission(),
        )

    statements = [sql for sql, _params in connection.calls]
    assert not any(sql.startswith("INSERT INTO submission_limits") for sql in statements)
    assert not any(sql.startswith("UPDATE submissions") for sql in statements)
    assert connection.commits == 0 and connection.rollbacks == 1


def test_database_quota_rejection_never_updates_submission(monkeypatch):
    connection = _DbConnection(submission_count=2)
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)

    with pytest.raises(db_services.SubmissionLimitExceeded):
        db_services.overwrite_written_submission(
            41,
            "file_new.generation.pdf",
            submission_limit=2,
            username="student",
            problem_id=7,
            user_id=3,
            expected_submission=_submission(),
        )

    assert not any(
        sql.startswith("UPDATE submissions") for sql, _params in connection.calls
    )
    assert connection.commits == 0 and connection.rollbacks == 1


def test_manual_overwrite_route_passes_expected_snapshot_to_cas(monkeypatch):
    app = Flask(__name__)
    app.secret_key = "test-secret"
    user = {"id": 3, "username": "student", "is_admin": 0}
    problem = {
        "id": 7,
        "title": "人工作业",
        "type": 2,
        "submission_limit": 5,
        "written_grading_mode": 4,
    }
    overwritten = []
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    monkeypatch.setattr(problem_core_routes, "get_problem", lambda _pid: problem)
    monkeypatch.setattr(
        problem_core_routes, "get_problem_homework_assignments", lambda *_args: [],
    )
    monkeypatch.setattr(problem_core_routes, "get_latest_written_submission", lambda *_a: _submission())
    monkeypatch.setattr(problem_core_routes, "get_user_classes_cached", lambda _uid: [])
    monkeypatch.setattr(
        problem_core_routes,
        "overwrite_written_submission",
        lambda *args, **kwargs: overwritten.append((args, kwargs)),
    )

    def fail_after_cas(**kwargs):
        expected = _submission()
        kwargs["overwrite_record"](41, "file_answer.generation.pdf", expected)
        raise artifacts.WrittenSubmissionArtifactError("新作业发布失败，已保留上一份有效作业")

    monkeypatch.setattr(problem_core_routes, "publish_manual_written_submission", fail_after_cas)
    monkeypatch.setattr(problem_core_routes, "url_for", lambda endpoint, **_values: f"/{endpoint}")

    with app.test_request_context(
        "/submit/7",
        method="POST",
        data={"file": (io.BytesIO(b"new-pdf"), "answer.pdf")},
        content_type="multipart/form-data",
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302
    assert overwritten[0][0] == (41, "file_answer.generation.pdf")
    assert overwritten[0][1]["expected_submission"] == _submission()


def test_watchdog_and_stopped_worker_recovery_both_include_publication_recovery():
    source = PROJECT_ROOT / "oj_modules" / "runtime" / "pending_recovery.py"
    text = source.read_text(encoding="utf-8")
    assert "recover_written_submission_publications" in text
    assert "min_age_seconds=0" in text
    assert "DEFAULT_RECOVERY_GRACE_SECONDS" in text
