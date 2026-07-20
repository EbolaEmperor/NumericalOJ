#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""提交审计边界测试：不连接 MySQL/Redis，不记录用户提交原文。"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import pytest

from oj_modules import db_services, submission_archive
from oj_modules import written_submission_artifacts as artifacts


class _DatabaseCursor:
    def __init__(self, connection):
        self.connection = connection
        self.lastrowid = 0
        self.rowcount = 0
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        return False

    def execute(self, sql, params=None):
        statement = " ".join(str(sql).split())
        self.connection.statements.append((statement, params))
        self._result = None
        self.rowcount = 0
        if statement.startswith("SELECT id, username, is_admin, class FROM users"):
            self._result = dict(self.connection.user)
        elif statement.startswith("SELECT id FROM problems"):
            self._result = {"id": params[0]}
        elif statement.startswith("SELECT COUNT(*) FROM submissions"):
            self._result = {"COUNT(*)": 1}
        elif statement.startswith("SELECT id, username, problem_id, test_points"):
            self._result = dict(self.connection.submission)
        elif statement.startswith("INSERT INTO users"):
            self.lastrowid = self.connection.user_insert_id
            self.rowcount = 1
        elif statement.startswith("INSERT INTO submissions"):
            self.lastrowid = self.connection.submission_insert_id
            self.rowcount = 1
        elif statement.startswith("UPDATE submissions"):
            self.rowcount = 1
        else:
            # 其余语句是 create_user 的班级关系写入或书面首提计数更新；
            # 本测试关心事务和审计边界，不模拟这些表的持久状态。
            self.rowcount = 1
        return self.rowcount

    def fetchone(self):
        return self._result

    def fetchall(self):
        return []


class _DatabaseConnection:
    def __init__(self, *, order=None, fail_commit=False, submission=None):
        self.order = order if order is not None else []
        self.fail_commit = fail_commit
        self.user_insert_id = 73
        self.submission_insert_id = 501
        self.user = {
            "id": 3,
            "username": "student-current",
            "is_admin": 1,
            "class": None,
        }
        self.submission = submission or _written_submission()
        self.statements = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return _DatabaseCursor(self)

    def commit(self):
        self.order.append("commit")
        self.commits += 1
        if self.fail_commit:
            raise RuntimeError("injected commit failure")

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class _UploadedFile:
    def __init__(self, payload: bytes):
        self.payload = payload

    def save(self, destination):
        Path(destination).write_bytes(self.payload)


def _written_submission(filename="old.pdf", **overrides):
    row = {
        "id": 41,
        "problem_id": 7,
        "username": "student-current",
        "test_points": json.dumps(filename, ensure_ascii=False),
        "score": 8,
        "status": "Completed",
        "created_at": "2026-07-01 10:00:00",
    }
    row.update(overrides)
    return row


def _install_submission_database(
    monkeypatch,
    *,
    problem_type=1,
    order=None,
    fail_commit=False,
):
    connection = _DatabaseConnection(order=order, fail_commit=fail_commit)
    monkeypatch.setattr(db_services, "get_problem", lambda _problem_id: {"type": problem_type})
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda _sid: None)
    monkeypatch.setattr(db_services, "bump_daily_submission_count", lambda: None)
    return connection


def _create_submission(**overrides):
    arguments = {
        "problem_id": 7,
        "problem_title": "审计题",
        "username": "stale-name",
        "code": "source-code-secret-中文",
        "score": 0,
        "test_points": [{"status": "Passed"}],
        "prompt_text": "prompt-secret-中文",
        "user_id": 3,
    }
    arguments.update(overrides)
    return db_services.create_submission(**arguments)


@pytest.mark.parametrize(
    ("problem_type", "generated", "task_name", "expected_origin"),
    [
        (1, False, "", "web"),
        (1, True, "", "promptly"),
        (1, False, "oj.agent.solve_problem", "agent"),
        (2, False, "", "written"),
        ("essay-v2", False, "", "web"),
    ],
)
def test_create_submission_emits_only_fingerprints_after_commit(
    monkeypatch,
    problem_type,
    generated,
    task_name,
    expected_origin,
):
    order = []
    connection = _install_submission_database(
        monkeypatch,
        problem_type=problem_type,
        order=order,
    )
    monkeypatch.setattr(
        db_services,
        "current_context",
        lambda: {"task_name": task_name} if task_name else {},
    )
    events = []

    def capture(domain, **payload):
        order.append("audit")
        events.append((domain, payload))

    monkeypatch.setattr(db_services, "emit_audit", capture)

    submission_id = _create_submission(generated_from_prompt=generated)

    assert submission_id == 501
    assert order == ["commit", "audit"]
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed is True
    assert len(events) == 1
    domain, event = events[0]
    assert domain == "submissions"
    assert event["action"] == "submission.created"
    assert event["submission"]["origin"] == expected_origin
    assert event["problem"] == {"id": 7, "type": problem_type}
    assert event["user"] == {"id": 3, "name": "student-current"}

    code = "source-code-secret-中文"
    prompt = "prompt-secret-中文"
    assert event["content"]["code"] == {
        "present": True,
        "bytes": len(code.encode("utf-8")),
        "sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
    }
    assert event["content"]["prompt"] == {
        "present": True,
        "bytes": len(prompt.encode("utf-8")),
        "sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
    }
    encoded_event = json.dumps(event, ensure_ascii=False, sort_keys=True)
    assert code not in encoded_event
    assert prompt not in encoded_event


def test_create_submission_does_not_audit_a_failed_commit(monkeypatch):
    order = []
    connection = _install_submission_database(
        monkeypatch,
        order=order,
        fail_commit=True,
    )
    events = []
    monkeypatch.setattr(db_services, "current_context", lambda: {})
    monkeypatch.setattr(db_services, "emit_audit", lambda *args, **kwargs: events.append((args, kwargs)))

    with pytest.raises(RuntimeError, match="commit failure"):
        _create_submission()

    assert order == ["commit"]
    assert events == []
    assert connection.commits == 1
    assert connection.rollbacks == 1
    assert connection.closed is True


def test_create_submission_is_not_reversed_by_logging_failure(monkeypatch):
    connection = _install_submission_database(monkeypatch)
    monkeypatch.setattr(db_services, "current_context", lambda: {})
    audit_logger = logging.getLogger("numoj.audit.submissions")
    monkeypatch.setattr(
        audit_logger,
        "log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("log socket unavailable")),
    )

    assert _create_submission() == 501
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_create_user_returns_transaction_insert_id(monkeypatch):
    connection = _DatabaseConnection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)

    user_id = db_services.create_user(
        "new-user",
        "password-hash",
        "new-user@example.com",
        {"class_en": "C1", "class_cn": "一班"},
    )

    assert user_id == 73
    assert isinstance(user_id, int)
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed is True
    assert len(connection.statements) == 3
    assert connection.statements[-1][1] == (73, "C1", 1)


def test_overwrite_written_submission_audits_after_commit(monkeypatch):
    order = []
    previous = _written_submission()
    connection = _DatabaseConnection(order=order, submission=previous)
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda _sid: None)
    events = []

    def capture(domain, **payload):
        order.append("audit")
        events.append((domain, payload))

    monkeypatch.setattr(db_services, "emit_audit", capture)

    result = db_services.overwrite_written_submission(
        41,
        "answer.generation.pdf",
        user_id=3,
        expected_submission=previous,
    )

    assert result == previous
    assert order == ["commit", "audit"]
    assert connection.commits == 1
    domain, event = events[0]
    assert domain == "submissions"
    assert event["action"] == "submission.revision.committed"
    assert event["submission"] == {
        "id": 41,
        "kind": "written",
        "origin": "manual_overwrite",
        "initial_status": "Pending",
        "previous_status": "Completed",
    }
    assert event["problem"] == {"id": 7}
    assert event["user"] == {"id": 3, "name": "student-current"}


def test_overwrite_written_submission_does_not_audit_a_failed_commit(monkeypatch):
    previous = _written_submission()
    connection = _DatabaseConnection(fail_commit=True, submission=previous)
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    events = []
    monkeypatch.setattr(db_services, "emit_audit", lambda *args, **kwargs: events.append((args, kwargs)))

    with pytest.raises(RuntimeError, match="commit failure"):
        db_services.overwrite_written_submission(
            41,
            "answer.generation.pdf",
            expected_submission=previous,
        )

    assert events == []
    assert connection.rollbacks == 1
    assert connection.closed is True


def test_overwrite_written_submission_is_not_reversed_by_logging_failure(monkeypatch):
    previous = _written_submission()
    connection = _DatabaseConnection(submission=previous)
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda _sid: None)
    audit_logger = logging.getLogger("numoj.audit.submissions")
    monkeypatch.setattr(
        audit_logger,
        "log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    result = db_services.overwrite_written_submission(
        41,
        "answer.generation.pdf",
        expected_submission=previous,
    )

    assert result == previous
    assert connection.commits == 1


def test_archive_submission_file_records_only_artifact_metadata(monkeypatch, tmp_path):
    source = tmp_path / "private-source.pdf"
    payload = b"private-written-answer-content"
    source.write_bytes(payload)
    archived = tmp_path / "archive" / "stored.pdf"
    monkeypatch.setattr(db_services, "archive_submission_by_id", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        submission_archive,
        "archive_uploaded_submission_file",
        lambda *_args, **_kwargs: archived,
    )
    events = []
    monkeypatch.setattr(
        db_services,
        "emit_audit",
        lambda domain, **event: events.append((domain, event)),
    )

    result = db_services.archive_submission_file_by_id(
        41,
        source,
        preferred_filename="answer.pdf",
        raise_errors=True,
    )

    assert result == archived
    assert len(events) == 1
    domain, event = events[0]
    assert domain == "submissions"
    assert event["action"] == "submission.artifact.archived"
    assert event["submission"] == {"id": 41, "kind": "written"}
    assert event["artifact"] == {
        "type": "written",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    encoded_event = json.dumps(event, ensure_ascii=False, sort_keys=True)
    assert payload.decode("ascii") not in encoded_event
    assert str(source) not in encoded_event


def test_archive_submission_file_is_not_reversed_by_logging_failure(monkeypatch, tmp_path):
    source = tmp_path / "answer.pdf"
    source.write_bytes(b"answer")
    archived = tmp_path / "archive" / "answer.pdf"
    monkeypatch.setattr(db_services, "archive_submission_by_id", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        submission_archive,
        "archive_uploaded_submission_file",
        lambda *_args, **_kwargs: archived,
    )
    audit_logger = logging.getLogger("numoj.audit.submissions")
    monkeypatch.setattr(
        audit_logger,
        "log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("collector down")),
    )

    assert db_services.archive_submission_file_by_id(
        41,
        source,
        preferred_filename="answer.pdf",
        raise_errors=True,
    ) == archived


def test_audit_published_submission_records_metadata_without_content_or_path(
    monkeypatch,
    tmp_path,
):
    destination = tmp_path / "private" / "answer.generation.pdf"
    destination.parent.mkdir()
    payload = b"manual-written-secret"
    destination.write_bytes(payload)
    events = []
    monkeypatch.setattr(
        artifacts,
        "emit_audit",
        lambda domain, **event: events.append((domain, event)),
    )
    data = {
        "stored_filename": destination.name,
        "old_filename": "old.pdf",
        "sha256": hashlib.sha256(payload).hexdigest(),
    }

    artifacts._audit_published_submission(
        submission_id=41,
        token="a" * 32,
        data=data,
        destination=destination,
        problem={"id": 7},
        user={"id": 3, "username": "student-current"},
    )
    destination.unlink()
    artifacts._audit_published_submission(
        submission_id=41,
        token="b" * 32,
        data=data,
        destination=destination,
        problem=None,
        user=None,
    )

    assert len(events) == 2
    domain, event = events[0]
    assert domain == "submissions"
    assert event["action"] == "submission.artifact.published"
    assert event["artifact"] == {
        "type": "written",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert event["submission"]["publication_id"] == "a" * 32
    assert "old_filename" not in event["submission"]
    assert event["problem"] == {"id": 7}
    assert event["user"] == {"id": 3, "name": "student-current"}
    encoded_event = json.dumps(event, ensure_ascii=False, sort_keys=True)
    assert payload.decode("ascii") not in encoded_event
    assert str(tmp_path) not in encoded_event
    assert events[1][1]["artifact"]["bytes"] is None
    assert events[1][1]["problem"] == {"id": None}
    assert events[1][1]["user"] == {"id": None, "name": None}


def _prepare_manual_publish(monkeypatch, tmp_path, *, payload=b"manual-upload-secret"):
    upload_root = tmp_path / "uploads"
    run_root = tmp_path / "judger"
    monkeypatch.setattr(submission_archive.judger_core, "JUDGER_RUN_ROOT", str(run_root))

    def build_archive(archive_staging, **_kwargs):
        Path(archive_staging, "metadata.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(artifacts, "_build_archive_staging", build_archive)
    state = {"submission": _written_submission()}
    return upload_root, state, _UploadedFile(payload), payload


def _publish_manual(upload_root, state, uploaded_file, overwrite_record):
    return artifacts.publish_manual_written_submission(
        uploaded_file=uploaded_file,
        filename="answer.pdf",
        previous_submission=_written_submission(),
        problem={"id": 7, "type": 2},
        user={"id": 3, "username": "student-current"},
        classes=[],
        overwrite_record=overwrite_record,
        load_current_record=lambda _submission_id: state["submission"],
        max_bytes=1024,
        upload_root=upload_root,
    )


def test_publish_manual_written_submission_audits_after_database_switch(
    monkeypatch,
    tmp_path,
):
    upload_root, state, uploaded_file, payload = _prepare_manual_publish(
        monkeypatch,
        tmp_path,
    )
    order = []
    events = []

    def overwrite(_submission_id, stored_filename, _expected):
        order.append("overwrite")
        state["submission"] = _written_submission(
            stored_filename,
            status="Pending",
            score=0,
        )

    def capture(domain, **event):
        order.append("audit")
        events.append((domain, event))

    monkeypatch.setattr(artifacts, "emit_audit", capture)

    result = _publish_manual(upload_root, state, uploaded_file, overwrite)

    assert Path(result).read_bytes() == payload
    assert order == ["overwrite", "audit"]
    assert len(events) == 1
    domain, event = events[0]
    assert domain == "submissions"
    assert event["submission"]["id"] == 41
    assert event["submission"]["origin"] == "manual_overwrite"
    assert event["artifact"]["bytes"] == len(payload)
    assert event["artifact"]["sha256"] == hashlib.sha256(payload).hexdigest()
    encoded_event = json.dumps(event, ensure_ascii=False, sort_keys=True)
    assert payload.decode("ascii") not in encoded_event
    assert str(tmp_path) not in encoded_event


def test_publish_manual_written_submission_audits_confirmed_ambiguous_commit(
    monkeypatch,
    tmp_path,
):
    upload_root, state, uploaded_file, _payload = _prepare_manual_publish(
        monkeypatch,
        tmp_path,
    )
    events = []
    monkeypatch.setattr(
        artifacts,
        "emit_audit",
        lambda domain, **event: events.append((domain, event)),
    )

    def commit_then_lose_response(_submission_id, stored_filename, _expected):
        state["submission"] = _written_submission(
            stored_filename,
            status="Pending",
            score=0,
        )
        raise RuntimeError("database response lost after commit")

    result = _publish_manual(
        upload_root,
        state,
        uploaded_file,
        commit_then_lose_response,
    )

    assert Path(result).is_file()
    assert len(events) == 1
    assert events[0][1]["action"] == "submission.artifact.published"
    assert list((upload_root / artifacts.JOURNAL_DIRNAME).glob("*.json")) == []


def test_publish_manual_written_submission_is_not_reversed_by_logging_failure(
    monkeypatch,
    tmp_path,
):
    upload_root, state, uploaded_file, payload = _prepare_manual_publish(
        monkeypatch,
        tmp_path,
    )

    def overwrite(_submission_id, stored_filename, _expected):
        state["submission"] = _written_submission(stored_filename, status="Pending", score=0)

    audit_logger = logging.getLogger("numoj.audit.submissions")
    monkeypatch.setattr(
        audit_logger,
        "log",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("collector unavailable")),
    )

    result = _publish_manual(upload_root, state, uploaded_file, overwrite)

    assert Path(result).read_bytes() == payload
    assert json.loads(state["submission"]["test_points"]).startswith("answer.")
