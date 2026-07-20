# -*- coding: utf-8 -*-
"""打榜赛提交审计的事务顺序、覆盖面与隐私边界测试。"""

import hashlib
import json
import logging
from pathlib import Path

import pytest

from oj_modules import ranking_db


class _Cursor:
    def __init__(self, *, rowcount=1, lastrowid=71, fetch_values=()):
        self.rowcount = rowcount
        self.lastrowid = lastrowid
        self.calls = []
        self._fetch_values = list(fetch_values)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        if self._fetch_values:
            return self._fetch_values.pop(0)
        return None


class _Connection:
    def __init__(self, cursor, *, commit_error=None, events=None, label="commit"):
        self.fake_cursor = cursor
        self.commit_error = commit_error
        self.events = events
        self.label = label
        self.commit_count = 0
        self.rollback_count = 0
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.commit_count += 1
        if self.events is not None:
            self.events.append(self.label)
        if self.commit_error is not None:
            raise self.commit_error

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        self.closed = True


def _audit_spy(monkeypatch, *, events=None, committed=None):
    calls = []

    def record(domain, **fields):
        if committed is not None:
            assert committed()
        if events is not None:
            events.append("audit")
        calls.append((domain, fields))

    monkeypatch.setattr(ranking_db, "emit_audit", record)
    return calls


def _create_regular_db(monkeypatch, *, commit_error=None):
    cursor = _Cursor()
    connection = _Connection(cursor, commit_error=commit_error)
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)
    monkeypatch.setattr(ranking_db, "_lock_submission_quota", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        ranking_db,
        "_insert_ranking_submission",
        lambda *_a, **_kw: 71,
    )
    monkeypatch.setattr(ranking_db, "_record_submission_metric", lambda _sid: None)
    return connection


def _create_staged_file(tmp_path, name, content):
    staging = tmp_path / "staging"
    staging.mkdir(exist_ok=True)
    path = staging / name
    path.write_bytes(content)
    return path


def _prepare_artifact_submission(monkeypatch, tmp_path, *, commit_error=None):
    cursor = _Cursor(rowcount=1)
    connection = _Connection(cursor, commit_error=commit_error)
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)
    monkeypatch.setattr(ranking_db, "_lock_submission_quota", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        ranking_db,
        "_insert_ranking_submission",
        lambda *_a, **_kw: 71,
    )
    monkeypatch.setattr(
        ranking_db,
        "submission_dir",
        lambda submission_id: str(tmp_path / "submissions" / str(submission_id)),
    )
    monkeypatch.setattr(ranking_db, "_record_submission_metric", lambda _sid: None)
    return connection


def _assert_artifact_is_private(artifact, *, artifact_type, content, root):
    assert artifact == {
        "type": artifact_type,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    serialized = json.dumps(artifact, ensure_ascii=False)
    assert str(root) not in serialized
    assert content.decode("utf-8") not in serialized


def test_artifact_audit_metadata_returns_only_safe_file_fingerprint(tmp_path):
    content = b"private-ranking-code"
    artifact_path = tmp_path / "internal" / "opaque-storage-name"
    artifact_path.parent.mkdir()
    artifact_path.write_bytes(content)

    metadata = ranking_db._artifact_audit_metadata(
        str(artifact_path),
        "code",
    )

    _assert_artifact_is_private(
        metadata,
        artifact_type="code",
        content=content,
        root=tmp_path,
    )


def test_artifact_audit_metadata_handles_missing_and_unreadable_files(monkeypatch):
    assert ranking_db._artifact_audit_metadata(None, "answer") is None

    def unavailable(_path, *, artifact_type):
        return {"type": artifact_type, "available": False}

    monkeypatch.setattr(ranking_db, "safe_file_fingerprint", unavailable)
    assert ranking_db._artifact_audit_metadata(
        "/secret/internal/path",
        "answer",
    ) == {"type": "answer", "available": False}


def test_audit_ranking_submission_created_builds_structured_event(monkeypatch):
    calls = _audit_spy(monkeypatch)
    artifact = {"type": "code", "bytes": 4, "sha256": "a" * 64}

    ranking_db._audit_ranking_submission_created(
        "81",
        "9",
        "student",
        source="batch",
        status="Queued",
        origin="admin_rejudge_clone",
        agent_endpoint_id=3,
        base_model="model-a",
        artifacts=(None, artifact),
        parent_submission_id=70,
    )

    assert calls == [(
        "submissions",
        {
            "action": "submission.created",
            "outcome": "success",
            "message": "打榜赛提交已创建",
            "submission": {
                "id": 81,
                "kind": "ranking",
                "origin": "admin_rejudge_clone",
                "source": "batch",
                "initial_status": "Queued",
                "parent_id": 70,
                "agent_endpoint_id": 3,
                "base_model": "model-a",
            },
            "competition": {"id": 9},
            "user": {"name": "student"},
            "artifacts": [artifact],
        },
    )]


@pytest.mark.parametrize(
    ("requested_source", "expected_source"),
    [("self", "self"), ("BATCH", "batch")],
)
def test_create_ranking_submission_audits_self_and_batch_after_commit(
        monkeypatch, requested_source, expected_source):
    connection = _create_regular_db(monkeypatch)
    inserted_sources = []
    monkeypatch.setattr(
        ranking_db,
        "_insert_ranking_submission",
        lambda _cursor, _competition, _username, *, source, agent_endpoint_id: (
            inserted_sources.append(source) or 71
        ),
    )
    audit_calls = []

    def audit(*args, **kwargs):
        assert connection.commit_count == 1
        audit_calls.append((args, kwargs))

    monkeypatch.setattr(ranking_db, "_audit_ranking_submission_created", audit)

    result = ranking_db.create_ranking_submission(
        9,
        "student",
        source=requested_source,
        enforce_quota=True,
        agent_endpoint_id=4,
    )

    assert result == 71
    assert inserted_sources == [expected_source]
    assert connection.rollback_count == 0
    assert connection.closed is True
    assert audit_calls == [(
        (71, 9, "student"),
        {
            "source": expected_source,
            "status": "Pending",
            "origin": "git_or_batch",
            "agent_endpoint_id": 4,
        },
    )]


def test_create_ranking_submission_commit_failure_never_audits(monkeypatch):
    connection = _create_regular_db(
        monkeypatch,
        commit_error=OSError("commit failed"),
    )
    audits = []
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_submission_created",
        lambda *_a, **_kw: audits.append(1),
    )

    with pytest.raises(OSError, match="commit failed"):
        ranking_db.create_ranking_submission(9, "student")

    assert audits == []
    assert connection.rollback_count == 1
    assert connection.closed is True


def test_create_ranking_submission_logging_failure_is_fail_open(monkeypatch):
    connection = _create_regular_db(monkeypatch)

    def fail_log(*_args, **_kwargs):
        raise OSError("collector unavailable")

    monkeypatch.setattr(logging.Logger, "log", fail_log)

    assert ranking_db.create_ranking_submission(9, "student") == 71
    assert connection.commit_count == 1
    assert connection.closed is True


def test_create_ranking_artifact_submission_audits_safe_metadata_after_commit(
        monkeypatch, tmp_path):
    code_content = b"secret-code-body"
    answer_content = b"secret-answer-body"
    code = _create_staged_file(tmp_path, "code.zip", code_content)
    answer = _create_staged_file(tmp_path, "answer.json", answer_content)
    connection = _prepare_artifact_submission(monkeypatch, tmp_path)
    calls = []

    def audit(*args, **kwargs):
        assert connection.commit_count == 1
        calls.append((args, kwargs))

    monkeypatch.setattr(ranking_db, "_audit_ranking_submission_created", audit)

    result = ranking_db.create_ranking_artifact_submission(
        9,
        "student",
        code_staged_path=str(code),
        code_filename="code.zip",
        answer_staged_path=str(answer),
        answer_filename="answer.json",
        base_model="model-a",
        source="batch",
        agent_endpoint_id=8,
    )

    assert result == 71
    assert len(calls) == 1
    args, fields = calls[0]
    assert args == (71, 9, "student")
    assert fields["source"] == "batch"
    assert fields["status"] == "Judging"
    assert fields["origin"] == "artifact_upload"
    assert fields["agent_endpoint_id"] == 8
    assert fields["base_model"] == "model-a"
    code_artifact, answer_artifact = fields["artifacts"]
    _assert_artifact_is_private(
        code_artifact,
        artifact_type="code",
        content=code_content,
        root=tmp_path,
    )
    _assert_artifact_is_private(
        answer_artifact,
        artifact_type="answer",
        content=answer_content,
        root=tmp_path,
    )


def test_create_ranking_artifact_submission_confirmed_commit_is_audited_once(
        monkeypatch, tmp_path):
    code = _create_staged_file(tmp_path, "code.zip", b"code")
    connection = _prepare_artifact_submission(
        monkeypatch,
        tmp_path,
        commit_error=OSError("commit response lost"),
    )
    monkeypatch.setattr(ranking_db, "_artifact_commit_matches", lambda *_a: True)
    calls = []
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_submission_created",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    result = ranking_db.create_ranking_artifact_submission(
        9,
        "student",
        code_staged_path=str(code),
        code_filename="code.zip",
    )

    assert result == 71
    assert connection.commit_count == 1
    assert connection.rollback_count == 1
    assert len(calls) == 1
    assert calls[0][1]["origin"] == "artifact_upload"


def test_create_ranking_artifact_submission_unconfirmed_commit_never_audits(
        monkeypatch, tmp_path):
    code = _create_staged_file(tmp_path, "code.zip", b"code")
    _prepare_artifact_submission(
        monkeypatch,
        tmp_path,
        commit_error=OSError("commit response lost"),
    )
    monkeypatch.setattr(ranking_db, "_artifact_commit_matches", lambda *_a: False)
    calls = []
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_submission_created",
        lambda *_a, **_kw: calls.append(1),
    )

    with pytest.raises(ranking_db.RankingSubmissionCommitUnknown):
        ranking_db.create_ranking_artifact_submission(
            9,
            "student",
            code_staged_path=str(code),
            code_filename="code.zip",
        )

    assert calls == []


def test_create_ranking_artifact_submission_logging_failure_is_fail_open(
        monkeypatch, tmp_path):
    code = _create_staged_file(tmp_path, "code.zip", b"private")
    connection = _prepare_artifact_submission(monkeypatch, tmp_path)

    def fail_log(*_args, **_kwargs):
        raise OSError("collector unavailable")

    monkeypatch.setattr(logging.Logger, "log", fail_log)

    assert ranking_db.create_ranking_artifact_submission(
        9,
        "student",
        code_staged_path=str(code),
        code_filename="code.zip",
    ) == 71
    assert connection.commit_count == 1


def test_update_submission_files_audits_only_changed_row_after_commit(
        monkeypatch, tmp_path):
    code_content = b"private-code"
    answer_content = b"private-answer"
    code = tmp_path / "storage" / "code.bin"
    answer = tmp_path / "storage" / "answer.bin"
    code.parent.mkdir()
    code.write_bytes(code_content)
    answer.write_bytes(answer_content)
    cursor = _Cursor(rowcount=1)
    connection = _Connection(cursor)
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)
    calls = _audit_spy(
        monkeypatch,
        committed=lambda: connection.commit_count == 1,
    )

    result = ranking_db.update_submission_files(
        71,
        "answer.json",
        str(answer),
        "code.zip",
        str(code),
        base_model="model-a",
    )

    assert result is None
    assert connection.closed is True
    assert len(calls) == 1
    domain, fields = calls[0]
    assert domain == "submissions"
    assert fields["action"] == "submission.artifacts.attached"
    assert fields["submission"] == {
        "id": 71,
        "kind": "ranking",
        "base_model": "model-a",
        "status": "Judging",
    }
    code_artifact, answer_artifact = fields["artifacts"]
    _assert_artifact_is_private(
        code_artifact,
        artifact_type="code",
        content=code_content,
        root=tmp_path,
    )
    _assert_artifact_is_private(
        answer_artifact,
        artifact_type="answer",
        content=answer_content,
        root=tmp_path,
    )


def test_update_submission_files_no_change_or_commit_failure_never_audits(monkeypatch):
    calls = _audit_spy(monkeypatch)
    no_change = _Connection(_Cursor(rowcount=0))
    failing = _Connection(_Cursor(rowcount=1), commit_error=OSError("commit failed"))
    connections = iter((no_change, failing))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: next(connections))

    ranking_db.update_submission_files(71, None, None, None, None)
    with pytest.raises(OSError, match="commit failed"):
        ranking_db.update_submission_files(72, None, None, None, None)

    assert calls == []
    assert no_change.closed is True
    assert failing.closed is True


def test_update_submission_files_logging_failure_is_fail_open(monkeypatch):
    connection = _Connection(_Cursor(rowcount=1))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)

    def fail_log(*_args, **_kwargs):
        raise OSError("collector unavailable")

    monkeypatch.setattr(logging.Logger, "log", fail_log)

    assert ranking_db.update_submission_files(
        71, None, None, None, None,
    ) is None
    assert connection.commit_count == 1


def test_clone_ranking_submission_audits_creation_then_attached_artifacts(
        monkeypatch, tmp_path):
    source_code_content = b"source-private-code"
    source_answer_content = b"source-private-answer"
    source_code = tmp_path / "source" / "code.zip"
    source_answer = tmp_path / "source" / "answer.json"
    source_code.parent.mkdir()
    source_code.write_bytes(source_code_content)
    source_answer.write_bytes(source_answer_content)
    source = {
        "id": 70,
        "competition_id": 9,
        "username": "student",
        "answer_filename": "answer.json",
        "answer_path": str(source_answer),
        "code_filename": "code.zip",
        "code_path": str(source_code),
        "base_model": "model-a",
        "agent_endpoint_id": 8,
        "agent_endpoint_harness": "codex",
        "agent_endpoint_model": "model-a",
    }
    events = []
    first = _Connection(
        _Cursor(lastrowid=81, fetch_values=(source,)),
        events=events,
        label="first-commit",
    )
    second = _Connection(
        _Cursor(rowcount=1),
        events=events,
        label="final-commit",
    )
    connections = iter((first, second))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: next(connections))
    monkeypatch.setattr(
        ranking_db,
        "submission_dir",
        lambda submission_id: str(tmp_path / "clones" / str(submission_id)),
    )
    monkeypatch.setattr(ranking_db, "_record_submission_metric", lambda _sid: None)
    creation_calls = []
    attachment_calls = []

    def audit_created(*args, **fields):
        assert events == ["first-commit"]
        events.append("created-audit")
        creation_calls.append((args, fields))

    def audit_attached(*args, **fields):
        assert events == ["first-commit", "created-audit", "final-commit"]
        events.append("attached-audit")
        attachment_calls.append((args, fields))

    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_submission_created",
        audit_created,
    )
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_artifacts_attached",
        audit_attached,
    )

    result, returned_source = ranking_db.clone_ranking_submission_for_rejudge(
        70,
        competition_id=9,
        status="Queued",
    )

    assert result == 81
    assert returned_source is source
    assert events == [
        "first-commit",
        "created-audit",
        "final-commit",
        "attached-audit",
    ]
    assert first.closed is True and second.closed is True
    args, fields = creation_calls[0]
    assert args == (81, 9, "student")
    assert fields["source"] == "batch"
    assert fields["status"] == "Queued"
    assert fields["origin"] == "admin_rejudge_clone"
    assert fields["parent_submission_id"] == 70
    assert "artifacts" not in fields

    args, fields = attachment_calls[0]
    assert args == (81,)
    assert fields["status"] == "Queued"
    assert fields["origin"] == "admin_rejudge_clone"
    assert fields["base_model"] == "model-a"
    code_artifact, answer_artifact = fields["artifacts"]
    _assert_artifact_is_private(
        code_artifact,
        artifact_type="code",
        content=source_code_content,
        root=tmp_path,
    )
    _assert_artifact_is_private(
        answer_artifact,
        artifact_type="answer",
        content=source_answer_content,
        root=tmp_path,
    )


def test_clone_ranking_submission_final_commit_failure_keeps_creation_audit(
        monkeypatch, tmp_path):
    source_file = tmp_path / "source" / "code.zip"
    source_file.parent.mkdir()
    source_file.write_bytes(b"code")
    source = {
        "competition_id": 9,
        "username": "student",
        "answer_filename": None,
        "answer_path": None,
        "code_filename": "code.zip",
        "code_path": str(source_file),
        "base_model": None,
        "agent_endpoint_id": None,
        "agent_endpoint_harness": None,
        "agent_endpoint_model": None,
    }
    first = _Connection(_Cursor(lastrowid=81, fetch_values=(source,)))
    second = _Connection(
        _Cursor(rowcount=1),
        commit_error=OSError("final commit failed"),
    )
    connections = iter((first, second))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: next(connections))
    monkeypatch.setattr(
        ranking_db,
        "submission_dir",
        lambda submission_id: str(tmp_path / "clones" / str(submission_id)),
    )
    monkeypatch.setattr(ranking_db, "_record_submission_metric", lambda _sid: None)
    creation_calls = []
    attachment_calls = []
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_submission_created",
        lambda *args, **fields: creation_calls.append((args, fields)),
    )
    monkeypatch.setattr(
        ranking_db,
        "_audit_ranking_artifacts_attached",
        lambda *args, **fields: attachment_calls.append((args, fields)),
    )

    with pytest.raises(OSError, match="final commit failed"):
        ranking_db.clone_ranking_submission_for_rejudge(70)

    assert len(creation_calls) == 1
    assert creation_calls[0][0] == (81, 9, "student")
    assert creation_calls[0][1]["parent_submission_id"] == 70
    assert attachment_calls == []
    assert second.closed is True


def test_delete_ranking_submission_audits_only_committed_deletion(monkeypatch):
    events = []
    deleted = _Connection(_Cursor(rowcount=1), events=events)
    missing = _Connection(_Cursor(rowcount=0), events=events)
    connections = iter((deleted, missing))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: next(connections))
    calls = _audit_spy(monkeypatch, events=events)

    assert ranking_db.delete_ranking_submission(71) == 1
    assert ranking_db.delete_ranking_submission(72) == 0

    assert events == ["commit", "audit", "commit"]
    assert calls == [(
        "submissions",
        {
            "action": "submission.deleted",
            "outcome": "success",
            "message": "打榜赛提交已删除",
            "submission": {"id": 71, "kind": "ranking"},
        },
    )]
    assert deleted.closed is True and missing.closed is True


def test_delete_ranking_submission_commit_failure_never_audits(monkeypatch):
    connection = _Connection(
        _Cursor(rowcount=1),
        commit_error=OSError("commit failed"),
    )
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)
    calls = _audit_spy(monkeypatch)

    with pytest.raises(OSError, match="commit failed"):
        ranking_db.delete_ranking_submission(71)

    assert calls == []
    assert connection.closed is True


def test_delete_ranking_submission_logging_failure_is_fail_open(monkeypatch):
    connection = _Connection(_Cursor(rowcount=1))
    monkeypatch.setattr(ranking_db, "get_db_connection", lambda: connection)

    def fail_log(*_args, **_kwargs):
        raise OSError("collector unavailable")

    monkeypatch.setattr(logging.Logger, "log", fail_log)

    assert ranking_db.delete_ranking_submission(71) == 1
    assert connection.commit_count == 1
