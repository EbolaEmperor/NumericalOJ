from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest
from flask import Flask

from backend.oj_modules import db_services
from backend.oj_modules.submissions import repository_snapshots as submission_repository_snapshots
from backend.oj_modules.routes import problem_core_routes


class _QuotaStore:
    def __init__(self, *, fail_submission_insert=False):
        self.lock = threading.Lock()
        self.user_id = 1
        self.username = "student"
        self.user_exists = True
        self.submission_count = 0
        self.submissions = 0
        self.problem_count = 0
        self.next_submission_id = 1
        self.fail_submission_insert = fail_submission_insert
        self.sql = []
        self.inserted_usernames = []
        self.quota_usernames = []


class _FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.lastrowid = None
        self.rowcount = 0
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def _begin_locked_transaction(self):
        if self.connection.locked:
            return
        self.connection.store.lock.acquire()
        self.connection.locked = True
        self.connection.local_submission_count = self.connection.store.submission_count
        self.connection.local_submissions = self.connection.store.submissions
        self.connection.local_problem_count = self.connection.store.problem_count

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.connection.store.sql.append(normalized)
        self.rowcount = 0
        self._result = None

        if normalized.startswith("SELECT id, username, is_admin FROM users WHERE id="):
            self._begin_locked_transaction()
            if self.connection.store.user_exists and int(params[0]) == self.connection.store.user_id:
                self._result = {
                    "id": self.connection.store.user_id,
                    "username": self.connection.store.username,
                    "is_admin": 1,
                }
        elif normalized.startswith("SELECT id, username, is_admin FROM users WHERE username="):
            self._begin_locked_transaction()
            if self.connection.store.user_exists and params[0] == self.connection.store.username:
                self._result = {
                    "id": self.connection.store.user_id,
                    "username": self.connection.store.username,
                    "is_admin": 1,
                }
        elif normalized.startswith("INSERT INTO submission_limits"):
            self._begin_locked_transaction()
            self.connection.store.quota_usernames.append(params[0])
            self.rowcount = 1
        elif normalized.startswith("SELECT submission_count FROM submission_limits"):
            self._result = {"submission_count": self.connection.local_submission_count}
        elif "SET submission_count=submission_count+1" in normalized:
            self.connection.local_submission_count += 1
            self.rowcount = 1
        elif "SET submission_count=GREATEST(submission_count-1, 0)" in normalized:
            self._begin_locked_transaction()
            if self.connection.local_submission_count > 0:
                self.connection.local_submission_count -= 1
                self.rowcount = 1
        elif normalized.startswith("SELECT id FROM problems") and normalized.endswith("FOR UPDATE"):
            self._begin_locked_transaction()
            self._result = {"id": params[0]}
        elif normalized.startswith("SELECT COUNT(*) FROM submissions"):
            self._result = {"COUNT(*)": self.connection.local_submissions}
        elif normalized.startswith("UPDATE problems SET cnt=cnt+1"):
            self.connection.local_problem_count += 1
            self.rowcount = 1
        elif normalized.startswith("INSERT INTO submissions"):
            if self.connection.store.fail_submission_insert:
                raise RuntimeError("injected submission insert failure")
            if not self.connection.locked:
                self._begin_locked_transaction()
            self.lastrowid = self.connection.store.next_submission_id
            self.connection.store.next_submission_id += 1
            self.connection.local_submissions += 1
            self.connection.store.inserted_usernames.append(params[1])
            self.rowcount = 1
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")
        return self.rowcount

    def fetchone(self):
        return self._result

    def fetchall(self):
        return []


class _FakeConnection:
    def __init__(self, store):
        self.store = store
        self.locked = False
        self.local_submission_count = store.submission_count
        self.local_submissions = store.submissions
        self.local_problem_count = store.problem_count
        self.commit_count = 0
        self.rollback_count = 0

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.commit_count += 1
        if self.locked:
            self.store.submission_count = self.local_submission_count
            self.store.submissions = self.local_submissions
            self.store.problem_count = self.local_problem_count
            self.locked = False
            self.store.lock.release()

    def rollback(self):
        self.rollback_count += 1
        if self.locked:
            self.locked = False
            self.store.lock.release()

    def close(self):
        if self.locked:
            self.rollback()


def _install_fake_submission_db(monkeypatch, store, *, problem_type=1):
    connections = []

    def connection_factory():
        connection = _FakeConnection(store)
        connections.append(connection)
        return connection

    monkeypatch.setattr(db_services, "get_problem", lambda _problem_id: {"type": problem_type})
    monkeypatch.setattr(db_services, "get_db_connection", connection_factory)
    monkeypatch.setattr(db_services, "refresh_submission_status_snapshot", lambda _sid: None)
    monkeypatch.setattr(db_services, "bump_daily_submission_count", lambda: None)
    monkeypatch.setattr(
        submission_repository_snapshots,
        "capture_submission_repository_snapshot",
        lambda _cursor, **_kwargs: {"snapshot_key": "0" * 32},
    )
    return connections


def _create_counted_submission():
    return db_services.create_submission(
        problem_id=7,
        problem_title="并发题",
        username="student",
        code="print(1)",
        score=0,
        test_points=[],
        submission_limit=1,
        user_id=1,
    )


def test_concurrent_counted_submissions_cannot_cross_limit(monkeypatch):
    store = _QuotaStore()
    _install_fake_submission_db(monkeypatch, store)
    start_barrier = threading.Barrier(2)

    def load_problem(_problem_id):
        start_barrier.wait(timeout=2)
        return {"type": 1}

    monkeypatch.setattr(db_services, "get_problem", load_problem)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(_create_counted_submission) for _ in range(2)]

    results = []
    errors = []
    for future in futures:
        try:
            results.append(future.result())
        except Exception as exc:  # 测试需要保留线程中的明确异常类型
            errors.append(exc)

    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], db_services.SubmissionLimitExceeded)
    assert errors[0].limit == 1
    assert store.submission_count == 1
    assert store.submissions == 1
    assert any(sql.endswith("FOR UPDATE") for sql in store.sql)


def test_uncounted_submission_does_not_touch_quota(monkeypatch):
    store = _QuotaStore()
    _install_fake_submission_db(monkeypatch, store)

    submission_id = db_services.create_submission(
        7, "Agent 提交", "student", "print(1)", 0, [],
    )

    assert submission_id == 1
    assert store.submission_count == 0
    assert not any("submission_limits" in sql for sql in store.sql)


def test_submission_insert_failure_rolls_back_reserved_quota(monkeypatch):
    store = _QuotaStore(fail_submission_insert=True)
    connections = _install_fake_submission_db(monkeypatch, store)

    with pytest.raises(RuntimeError, match="injected submission insert failure"):
        _create_counted_submission()

    assert store.submission_count == 0
    assert store.submissions == 0
    assert connections[0].commit_count == 0
    assert connections[0].rollback_count >= 1


def test_release_submission_quota_is_atomic_and_never_negative(monkeypatch):
    store = _QuotaStore()
    store.submission_count = 1
    _install_fake_submission_db(monkeypatch, store)

    assert db_services.release_submission_quota("student", 7) is True
    assert db_services.release_submission_quota("student", 7) is False
    assert store.submission_count == 0


def test_written_first_submission_counters_and_insert_commit_together(monkeypatch):
    store = _QuotaStore()
    connections = _install_fake_submission_db(monkeypatch, store, problem_type=2)

    submission_id = db_services.create_submission(
        9, "书面题", "student", " ", 0, ["answer.pdf"],
    )

    assert submission_id == 1
    assert store.submissions == 1
    assert store.problem_count == 1
    assert connections[0].commit_count == 1


def test_submission_with_stable_user_id_uses_current_username(monkeypatch):
    store = _QuotaStore()
    store.username = "student-new"
    _install_fake_submission_db(monkeypatch, store)

    submission_id = db_services.create_submission(
        7,
        "改名并发题",
        "student-old",
        "print(1)",
        0,
        [],
        submission_limit=2,
        user_id=store.user_id,
    )

    assert submission_id == 1
    assert store.inserted_usernames == ["student-new"]
    assert store.quota_usernames == ["student-new"]


def test_submission_identity_uses_shared_user_lock_to_avoid_repository_lock_cycle(
    monkeypatch,
):
    store = _QuotaStore()
    _install_fake_submission_db(monkeypatch, store)

    _create_counted_submission()

    user_reads = [
        sql
        for sql in store.sql
        if sql.startswith(
            "SELECT id, username, is_admin FROM users WHERE "
        )
    ]
    assert user_reads
    assert all(sql.endswith("FOR SHARE") for sql in user_reads)
    assert not any(sql.endswith("FOR UPDATE") for sql in user_reads)


def test_submission_without_user_id_rejects_stale_username(monkeypatch):
    store = _QuotaStore()
    store.username = "student-new"
    connections = _install_fake_submission_db(monkeypatch, store)

    with pytest.raises(LookupError, match="用户名已变更"):
        db_services.create_submission(
            7,
            "改名并发题",
            "student-old",
            "print(1)",
            0,
            [],
            submission_limit=2,
        )

    assert store.submissions == 0
    assert store.submission_count == 0
    assert connections[0].rollback_count == 1


def test_reserve_quota_with_stable_user_id_uses_current_username(monkeypatch):
    store = _QuotaStore()
    store.username = "student-new"
    _install_fake_submission_db(monkeypatch, store)

    count = db_services.reserve_submission_quota(
        "student-old",
        7,
        2,
        user_id=store.user_id,
    )

    assert count == 1
    assert store.submission_count == 1
    assert store.quota_usernames == ["student-new"]


class _ArchiveFailureStore:
    def __init__(self, *, fail_status_update=False):
        self.username = "student-new"
        self.problem_id = 7
        self.status = "Pending"
        self.submission_count = 1
        self.fail_status_update = fail_status_update


class _ArchiveFailureCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rowcount = 0
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.rowcount = 0
        self._result = None
        if normalized.startswith("SELECT id, username, problem_id FROM submissions"):
            self._result = {
                "id": params[0],
                "username": self.connection.store.username,
                "problem_id": self.connection.store.problem_id,
            }
        elif "SET submission_count=GREATEST(submission_count-1, 0)" in normalized:
            if self.connection.local_submission_count > 0:
                self.connection.local_submission_count -= 1
                self.rowcount = 1
        elif normalized.startswith("UPDATE submissions SET status='Error'"):
            if self.connection.store.fail_status_update:
                raise RuntimeError("injected status update failure")
            self.connection.local_status = "Error"
            self.rowcount = 1
        else:
            raise AssertionError(f"unexpected SQL: {normalized}")
        return self.rowcount

    def fetchone(self):
        return self._result


class _ArchiveFailureConnection:
    def __init__(self, store):
        self.store = store
        self.local_status = store.status
        self.local_submission_count = store.submission_count
        self.commit_count = 0
        self.rollback_count = 0

    def cursor(self):
        return _ArchiveFailureCursor(self)

    def commit(self):
        self.commit_count += 1
        self.store.status = self.local_status
        self.store.submission_count = self.local_submission_count

    def rollback(self):
        self.rollback_count += 1

    def close(self):
        pass


def _install_fake_archive_failure_db(monkeypatch, store):
    connection = _ArchiveFailureConnection(store)
    monkeypatch.setattr(db_services, "get_db_connection", lambda: connection)
    return connection


def test_mark_archive_failed_updates_status_and_quota_in_one_transaction(monkeypatch):
    store = _ArchiveFailureStore()
    connection = _install_fake_archive_failure_db(monkeypatch, store)
    refreshed = []
    monkeypatch.setattr(
        db_services,
        "refresh_submission_status_snapshot",
        lambda submission_id: refreshed.append(submission_id),
    )

    released = db_services.mark_submission_archive_failed(31, release_quota=True)

    assert released is True
    assert store.status == "Error"
    assert store.submission_count == 0
    assert connection.commit_count == 1
    assert connection.rollback_count == 0
    assert refreshed == [31]


def test_mark_archive_failed_rolls_back_quota_when_status_update_fails(monkeypatch):
    store = _ArchiveFailureStore(fail_status_update=True)
    connection = _install_fake_archive_failure_db(monkeypatch, store)
    monkeypatch.setattr(
        db_services,
        "refresh_submission_status_snapshot",
        lambda _submission_id: pytest.fail("事务失败后不应刷新快照"),
    )

    with pytest.raises(RuntimeError, match="injected status update failure"):
        db_services.mark_submission_archive_failed(31, release_quota=True)

    assert store.status == "Pending"
    assert store.submission_count == 1
    assert connection.commit_count == 0
    assert connection.rollback_count == 1


def test_mark_archive_failed_ignores_snapshot_refresh_failure(monkeypatch):
    store = _ArchiveFailureStore()
    _install_fake_archive_failure_db(monkeypatch, store)
    monkeypatch.setattr(
        db_services,
        "refresh_submission_status_snapshot",
        lambda _submission_id: (_ for _ in ()).throw(RuntimeError("redis failed")),
    )

    assert db_services.mark_submission_archive_failed(31) is False
    assert store.status == "Error"


def _route_app():
    app = Flask(__name__)
    app.secret_key = "test-secret"
    return app


def _install_submit_route_fakes(monkeypatch):
    user = {"id": 1, "username": "student", "is_admin": 0}
    problem = {
        "id": 7,
        "title": "并发题",
        "type": 1,
        "submission_limit": 1,
        "programming_grading_mode": 1,
    }
    monkeypatch.setattr(problem_core_routes, "current_user", lambda: user)
    monkeypatch.setattr(problem_core_routes, "get_problem", lambda _pid: problem)
    monkeypatch.setattr(
        problem_core_routes, "get_problem_homework_assignments", lambda *_args: [],
    )
    monkeypatch.setattr(problem_core_routes, "can_submit", lambda *_args: True)
    monkeypatch.setattr(problem_core_routes, "url_for", lambda endpoint, **values: f"/{endpoint}")
    return user, problem


def test_submit_route_handles_limit_exception_without_queueing(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    queued = []
    monkeypatch.setattr(
        problem_core_routes,
        "_evaluate_submission_task",
        type("Task", (), {"delay": lambda self, submission_id: queued.append(submission_id)})(),
    )
    monkeypatch.setattr(
        problem_core_routes,
        "create_submission",
        lambda **_kwargs: (_ for _ in ()).throw(
            db_services.SubmissionLimitExceeded("student", 7, 1, 1)
        ),
    )

    with _route_app().test_request_context(
        "/submit/7", method="POST", data={"code": "print(1)"},
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302
    assert queued == []


def test_submit_route_returns_expired_homework_warning_to_json_client(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(
        problem_core_routes,
        "get_problem_homework_assignments",
        lambda *_args: [{
            "id": 3,
            "class_en": "C1",
            "class_cn": "一班",
            "ddl": datetime(2026, 1, 1),
            "is_expired": True,
        }],
    )
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 41)
    monkeypatch.setattr(
        problem_core_routes, "archive_submission_by_id", lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(problem_core_routes, "_evaluate_submission_task", None)

    with _route_app().test_request_context(
        "/submit/7",
        method="POST",
        data={"code": "print(1)"},
        headers={"Accept": "application/json"},
    ):
        response = problem_core_routes.submit_solution(7)

    response, status = response
    assert status == 201
    assert response.get_json() == {
        "success": True,
        "submission_id": 41,
        "warning": {
            "code": "homework_deadline_passed",
            "message": (
                "本次提交不会计入以下已截止的班级作业："
                "一班（截止 2026-01-01 00:00）。提交仍会正常评测，并计入题库练习成绩。"
            ),
            "homeworks": [{
                "homework_id": 3,
                "class_en": "C1",
                "class_cn": "一班",
                "ddl": "2026-01-01 00:00",
            }],
        },
        "warnings": [{
            "code": "homework_deadline_passed",
            "message": (
                "本次提交不会计入以下已截止的班级作业："
                "一班（截止 2026-01-01 00:00）。提交仍会正常评测，并计入题库练习成绩。"
            ),
            "homeworks": [{
                "homework_id": 3,
                "class_en": "C1",
                "class_cn": "一班",
                "ddl": "2026-01-01 00:00",
            }],
        }, {
            "message": "提交成功，但评测任务未初始化。",
        }],
    }


def test_browser_submit_requires_deadline_warning_acknowledgement(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(
        problem_core_routes,
        "get_problem_homework_assignments",
        lambda *_args: [{
            "id": 3,
            "class_en": "C1",
            "class_cn": "一班",
            "ddl": datetime(2026, 1, 1),
            "is_expired": True,
        }],
    )
    create_submission = MagicMock(return_value=41)
    monkeypatch.setattr(
        problem_core_routes, "create_submission", create_submission,
    )

    with _route_app().test_request_context(
        "/submit/7", method="POST", data={"code": "print(1)"},
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302
    assert response.location.endswith("/problem_core.problem_detail")
    create_submission.assert_not_called()


def test_submit_route_returns_submission_id_to_json_client(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 41)
    monkeypatch.setattr(
        problem_core_routes,
        "archive_submission_by_id",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(problem_core_routes, "_evaluate_submission_task", None)

    with _route_app().test_request_context(
        "/submit/7",
        method="POST",
        data={"code": "print(1)"},
        headers={"Accept": "application/json"},
    ):
        response = problem_core_routes.submit_solution(7)

    response, status = response
    assert status == 201
    assert response.get_json() == {
        "success": True,
        "submission_id": 41,
        "warning": {"message": "提交成功，但评测任务未初始化。"},
        "warnings": [{"message": "提交成功，但评测任务未初始化。"}],
    }


def test_archive_failure_releases_counted_submission_quota(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    failures = []
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 31)
    monkeypatch.setattr(
        problem_core_routes,
        "archive_submission_by_id",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("archive failed")),
    )
    monkeypatch.setattr(
        problem_core_routes,
        "mark_submission_archive_failed",
        lambda submission_id, *, release_quota: failures.append(
            (submission_id, release_quota)
        ),
    )

    with _route_app().test_request_context(
        "/submit/7", method="POST", data={"code": "print(1)"},
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302
    assert failures == [(31, True)]


def test_quota_compensation_failure_does_not_hide_original_submission_error(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 32)
    monkeypatch.setattr(
        problem_core_routes,
        "archive_submission_by_id",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("archive failed")),
    )
    monkeypatch.setattr(
        problem_core_routes,
        "mark_submission_archive_failed",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("quota database failed")
        ),
    )

    with _route_app().test_request_context(
        "/submit/7", method="POST", data={"code": "print(1)"},
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302


def test_post_submit_skips_advisory_precheck_and_passes_stable_user_id(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    created = []
    monkeypatch.setattr(
        problem_core_routes,
        "can_submit",
        lambda *_args: pytest.fail("POST 不应执行非事务性的提交次数预检查"),
    )
    monkeypatch.setattr(
        problem_core_routes,
        "create_submission",
        lambda **kwargs: created.append(kwargs) or 41,
    )
    monkeypatch.setattr(
        problem_core_routes,
        "archive_submission_by_id",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(problem_core_routes, "_evaluate_submission_task", None)

    with _route_app().test_request_context(
        "/submit/7", method="POST", data={"code": "print(1)"},
    ):
        response = problem_core_routes.submit_solution(7)

    assert response.status_code == 302
    assert created[0]["user_id"] == 1
    assert created[0]["submission_limit"] == 1


def test_api_submission_returns_task_warning_as_json(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 42)
    monkeypatch.setattr(problem_core_routes, "archive_submission_by_id", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(problem_core_routes, "_evaluate_submission_task", None)

    with _route_app().test_request_context(
        "/api/problems/7/submissions",
        method="POST",
        data={"code": "print(1)"},
        headers={"Accept": "application/json"},
    ):
        response, status = problem_core_routes.submit_solution(7)

    payload = response.get_json()
    assert status == 201
    assert payload["success"] is True
    assert payload["submission_id"] == 42
    assert "评测任务未初始化" in payload["warning"]["message"]


def test_api_archive_failure_keeps_submission_id_and_real_message(monkeypatch):
    _install_submit_route_fakes(monkeypatch)
    monkeypatch.setattr(problem_core_routes, "create_submission", lambda **_kwargs: 43)
    monkeypatch.setattr(
        problem_core_routes,
        "archive_submission_by_id",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("archive failed")),
    )
    monkeypatch.setattr(problem_core_routes, "mark_submission_archive_failed", lambda *_args, **_kwargs: None)

    with _route_app().test_request_context(
        "/api/problems/7/submissions",
        method="POST",
        data={"code": "print(1)"},
        headers={"Accept": "application/json"},
    ):
        response, status = problem_core_routes.submit_solution(7)

    payload = response.get_json()
    assert status == 500
    assert payload == {
        "success": False,
        "message": "提交归档失败，已停止入队：archive failed",
        "submission_id": 43,
    }
