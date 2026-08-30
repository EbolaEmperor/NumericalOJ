# -*- coding: utf-8 -*-

from backend.oj_modules import db_services
from backend.oj_modules.routes import rejudge_routes


class _FakeCursor:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


class _FakeConnection:
    def __init__(self):
        self.calls = []
        self.committed = False
        self.closed = False

    def cursor(self):
        return _FakeCursor(self.calls)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def test_reset_submission_for_rejudge_clears_programming_test_points(monkeypatch):
    conn = _FakeConnection()
    refreshed = []
    monkeypatch.setattr(db_services, "get_db_connection", lambda: conn)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda sid: refreshed.append(sid))

    db_services.reset_submission_for_rejudge(17, problem_type=1)

    assert conn.committed is True
    assert conn.closed is True
    assert refreshed == [17]
    sql, params = conn.calls[0]
    assert params == (17,)
    assert "status='Pending'" in sql
    assert "score=0" in sql
    assert "test_points=''" in sql


def test_reset_submission_for_rejudge_keeps_written_test_points(monkeypatch):
    conn = _FakeConnection()
    monkeypatch.setattr(db_services, "get_db_connection", lambda: conn)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda sid: None)

    db_services.reset_submission_for_rejudge(23, problem_type=2)

    sql, params = conn.calls[0]
    assert params == (23,)
    assert "status='Pending'" in sql
    assert "score=0" in sql
    assert "test_points" not in sql


def test_enqueue_rejudge_resets_before_scheduling(monkeypatch):
    hset_calls = []
    reset_calls = []
    apply_calls = []

    class FakeRedis:
        def hset(self, key, mapping=None):
            hset_calls.append((key, mapping))

    class FakeTask:
        def apply_async(self, *, args, countdown):
            apply_calls.append((args, countdown))

    monkeypatch.setattr(rejudge_routes, "_rds", FakeRedis())
    monkeypatch.setattr(rejudge_routes, "_rejudge_task", FakeTask())
    monkeypatch.setattr(
        rejudge_routes,
        "reset_submission_for_rejudge",
        lambda sid, problem_type=None: reset_calls.append((sid, problem_type)),
    )

    submissions = [
        {"id": 101, "problem_type": 1, "status": "Accepted"},
        {"id": 102, "problem_type": 2, "status": "Unaccepted"},
    ]
    rejudge_routes._enqueue_rejudge(submissions, "rejudge:test")

    assert hset_calls == [("rejudge:test", {"total": 2, "done": 0})]
    assert reset_calls == [(101, 1), (102, 2)]
    assert apply_calls == [
        ([101, "rejudge:test"], 0),
        ([102, "rejudge:test"], rejudge_routes._REJUDGE_STAGGER_SECONDS),
    ]
