"""显式恢复事务、调度竞争及管理员入口；全部基础设施均为内存模拟。"""

from copy import deepcopy
from datetime import datetime
import json
from types import SimpleNamespace

from flask import Flask
import pytest

from backend.oj_modules.api import faithsieve_api as api
from backend.oj_modules.faithsieve import services
from backend.oj_modules.faithsieve.recovery import (
    FaithSieveRecoveryConflict, FaithSieveRecoveryDispatchError, FaithSieveRecoveryError,
)
from backend.oj_modules.security.origin_guard import install_same_origin_protection


ATTEMPT = "b" * 32


def failed_run(**changes):
    return {"attempt_id": ATTEMPT, "submission_id": 12, "problem_id": 3, "endpoint_id": 4,
            "harness": "pi", "execution_mode": "workflow", "requested_by": "admin",
            "session_id": f"faithsieve-{ATTEMPT}", "status": "failed", "result_json": None,
            "started_at": datetime(2026, 10, 9, 8, 32, 49), "elapsed_seconds": 1800,
            "task_id": "old", "finished_at": datetime(2026, 10, 9, 9, 0), **changes}


class Lock:
    def __init__(self):
        self.available, self.released = True, False
    def acquire(self, **_options):
        return self.available
    def release(self):
        self.released = True


class Connection:
    def __init__(self):
        self.run = failed_run()
        self.named_lock = 1
        self.other_active = self.active_judge = 0
        self.calls = []
        self.rowcount = 1
        self.result = None
        self.commits = self.rollbacks = 0
        self.closed = False
        self.fail_commit = False
    def cursor(self):
        return self
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        pass
    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.rowcount = 1
        if "GET_LOCK" in sql:
            self.result = {"acquired": self.named_lock}
        elif "SELECT *" in sql:
            self.result = deepcopy(self.run)
        elif "SELECT COUNT" in sql:
            self.result = {"total": self.active_judge if "agent_sessions" in sql else self.other_active}
        elif "SET status='queued'" in sql:
            self.run.update(status="queued", task_id=params[0], finished_at=None)
        elif "SET status='failed'" in sql:
            self.rowcount = int(self.run["status"] == "queued" and self.run["task_id"] == params[1])
            if self.rowcount:
                self.run["status"] = "failed"
        else:
            self.result = None
    def fetchone(self):
        return self.result
    def commit(self):
        self.commits += 1
        if self.fail_commit and self.commits == 1:
            raise OSError("private connection details")
    def rollback(self):
        self.rollbacks += 1
    def close(self):
        self.closed = True


@pytest.fixture
def state(monkeypatch, tmp_path):
    connection, lock, dispatched, prepared = Connection(), Lock(), [], []
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(services, "create_redis_client", lambda: SimpleNamespace(lock=lambda *_a, **_k: lock))
    monkeypatch.setattr(services, "get_run", lambda _id: deepcopy(connection.run))
    monkeypatch.setattr(services, "_validate_inputs", lambda _run: tmp_path)
    def prepare(_workspace, run, actor):
        prepared.append((deepcopy(run), actor))
        return {"target_key": "role-000009-attempt-1"}
    monkeypatch.setattr(services, "prepare_recovery", prepare)
    dispatcher = SimpleNamespace(apply_async=lambda **options: dispatched.append(options))
    return SimpleNamespace(connection=connection, lock=lock, dispatched=dispatched, prepared=prepared, dispatcher=dispatcher)


def retry(state):
    return services.retry_failed_run(ATTEMPT, actor="admin", dispatcher=state.dispatcher)


def test_retry_keeps_attempt_identity_and_original_budget_and_uses_control_entry(state):
    original = deepcopy(state.connection.run)
    assert retry(state) == {"attempt_id": ATTEMPT, "status": "queued"}
    assert len(state.prepared) == len(state.dispatched) == 1
    assert state.prepared[0] == (original, "admin")
    assert state.connection.run["started_at"] == original["started_at"]
    for key in ("endpoint_id", "harness", "submission_id", "problem_id", "session_id", "execution_mode", "requested_by"):
        assert state.connection.run[key] == original[key]
    assert state.dispatched[0]["args"] == (ATTEMPT,) and state.dispatched[0]["queue"] == "celery"
    update = next(sql for sql, _params in state.connection.calls if "SET status='queued'" in sql)
    assert "started_at=" not in update and "TIMESTAMPDIFF" in update
    assert state.connection.commits == 1 and state.connection.closed and state.lock.released


@pytest.mark.parametrize("changes", [
    {"status": "completed"}, {"status": "inconclusive"}, {"execution_mode": "skill"},
    {"elapsed_seconds": 7200}, {"elapsed_seconds": -1}, {"elapsed_seconds": 1800.0},
    {"elapsed_seconds": True}, {"result_json": "{}"},
])
def test_ineligible_run_never_authorizes_or_dispatches(state, changes):
    state.connection.run.update(changes)
    with pytest.raises(FaithSieveRecoveryError):
        retry(state)
    assert state.prepared == state.dispatched == []
    assert state.connection.rollbacks == 1 and state.lock.released


@pytest.mark.parametrize("which", ["workflow", "queue", "judge", "other_run"])
def test_concurrent_or_active_work_cannot_be_recovered(state, which):
    if which == "workflow":
        state.lock.available = False
    elif which == "queue":
        state.connection.named_lock = 0
    elif which == "judge":
        state.connection.active_judge = 1
    else:
        state.connection.other_active = 1
    with pytest.raises(FaithSieveRecoveryConflict):
        retry(state)
    assert state.prepared == state.dispatched == []


def test_repeated_post_after_queue_does_not_dispatch_twice(state):
    retry(state)
    with pytest.raises(FaithSieveRecoveryConflict):
        retry(state)
    assert len(state.dispatched) == len(state.prepared) == 1


def test_dispatch_failure_only_rolls_back_still_queued_same_delivery(state):
    def fail(**_options):
        raise OSError("private broker details")
    state.dispatcher.apply_async = fail
    with pytest.raises(FaithSieveRecoveryDispatchError, match="调度未确认"):
        retry(state)
    assert state.connection.run["status"] == "failed" and len(state.prepared) == 1
    query = next(sql for sql, _params in state.connection.calls if "SET status='failed'" in sql)
    assert "status='queued' AND task_id=%s" in query
    assert state.connection.commits == 2


def test_broker_accepted_and_claimed_before_publish_error_is_not_marked_failed(state):
    def fail(**_options):
        state.connection.run["status"] = "running"
        raise OSError("private broker details")
    state.dispatcher.apply_async = fail
    assert retry(state) == {"attempt_id": ATTEMPT, "status": "running"}
    assert state.connection.run["status"] == "running"


def test_uncertain_commit_checks_persistent_state_before_dispatch(state):
    state.connection.fail_commit = True
    assert retry(state)["status"] == "queued"
    assert len(state.dispatched) == 1 and state.connection.rollbacks == 0


def test_failed_commit_with_unconfirmed_queue_never_dispatches(state, monkeypatch):
    state.connection.fail_commit = True
    monkeypatch.setattr(services, "get_run", lambda _id: failed_run())
    with pytest.raises(FaithSieveRecoveryDispatchError):
        retry(state)
    assert not state.dispatched and state.connection.rollbacks == 1


def test_get_eligibility_runs_same_preflight_without_lock_authorization_or_commit(state, monkeypatch):
    monkeypatch.setattr(services, "create_redis_client", lambda: pytest.fail("GET不能创建执行锁"))
    assert services.can_retry_failed_run(ATTEMPT)
    assert state.connection.commits == 0 and not state.prepared and not state.dispatched


def test_get_eligibility_rejects_changed_protocol_before_showing_button(state, monkeypatch):
    monkeypatch.setattr(services, "_validate_inputs", lambda _run: (_ for _ in ()).throw(FaithSieveRecoveryError("wire已变化")))
    assert services.can_retry_failed_run(ATTEMPT) is False
    assert state.connection.commits == 0 and not state.prepared


@pytest.fixture
def client(monkeypatch):
    app = Flask(__name__)
    install_same_origin_protection(app)
    app.register_blueprint(api.faithsieve_api_bp)
    monkeypatch.setattr(api, "current_user", lambda: {"username": "admin", "is_admin": True})
    monkeypatch.setattr(api, "is_admin", lambda user: bool(user and user.get("is_admin")))
    return app.test_client()


@pytest.mark.parametrize("user,expected", [(None, 401), ({"is_admin": False}, 403)])
def test_retry_authentication_precedes_any_service_access(client, monkeypatch, user, expected):
    monkeypatch.setattr(api, "current_user", lambda: user)
    monkeypatch.setattr(api, "retry_failed_run", lambda *_a, **_k: pytest.fail("未授权不得访问恢复服务"))
    assert client.post(f"/api/admin/faithsieve/{ATTEMPT}/retry").status_code == expected


def test_cross_origin_retry_is_rejected_before_service(client, monkeypatch):
    monkeypatch.setattr(api, "retry_failed_run", lambda *_a, **_k: pytest.fail("跨站不得访问恢复服务"))
    assert client.post(f"/api/admin/faithsieve/{ATTEMPT}/retry", headers={"Origin": "https://elsewhere.example"}).status_code == 403


@pytest.mark.parametrize("body", [{"endpoint_id": 8}, {"harness": "pi"}, {"prompt": "rewrite"}, None, [], True])
def test_retry_rejects_options_and_nonempty_body(client, monkeypatch, body):
    monkeypatch.setattr(api, "retry_failed_run", lambda *_a, **_k: pytest.fail("不能替换恢复输入"))
    response = client.post(f"/api/admin/faithsieve/{ATTEMPT}/retry", data=json.dumps(body), content_type="application/json")
    assert response.status_code == 400


@pytest.mark.parametrize("empty_json", [False, True])
def test_retry_route_dispatches_same_attempt_without_options(client, monkeypatch, empty_json):
    calls = []
    def service(attempt, **options):
        calls.append((attempt, options))
        return {"attempt_id": attempt, "status": "queued"}
    monkeypatch.setattr(api, "retry_failed_run", service)
    response = client.post(f"/api/admin/faithsieve/{ATTEMPT}/retry", **({"json": {}} if empty_json else {}))
    assert response.status_code == 200 and response.get_json()["status"] == "queued"
    assert calls == [(ATTEMPT, {"actor": "admin"})]
    assert response.headers["Cache-Control"] == "private, no-store"


@pytest.mark.parametrize("error,status", [(FaithSieveRecoveryConflict("重复"), 409), (FaithSieveRecoveryError("输入变化"), 400),
                                        (FaithSieveRecoveryDispatchError("调度未确认"), 503), (OSError("private details"), 400)])
def test_retry_error_status_and_safe_text(client, monkeypatch, error, status):
    monkeypatch.setattr(api, "retry_failed_run", lambda *_a, **_k: (_ for _ in ()).throw(error))
    response = client.post(f"/api/admin/faithsieve/{ATTEMPT}/retry")
    assert response.status_code == status and "private details" not in response.get_data(as_text=True)


@pytest.mark.parametrize("status,mode,eligible,expected", [
    ("failed", "workflow", True, True), ("failed", "workflow", False, False),
    ("running", "workflow", True, False), ("failed", "skill", True, False),
])
def test_detail_retry_flag_is_backend_qualification_only(client, monkeypatch, status, mode, eligible, expected):
    monkeypatch.setattr(api, "get_faithsieve_detail", lambda _id: {"run": {"status": status, "execution_mode": mode}})
    monkeypatch.setattr(api, "workflow_snapshot", lambda _run: {"stages": []})
    monkeypatch.setattr(api, "can_retry_failed_run", lambda _id: eligible)
    response = client.get(f"/api/admin/faithsieve/{ATTEMPT}")
    assert response.status_code == 200
    assert response.get_json()["run"]["retry_eligible"] is expected
