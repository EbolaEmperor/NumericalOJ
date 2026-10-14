"""多维重测只在管理员二次确认同一批记录后投递。"""

import json
from datetime import datetime

import pytest
from flask import Flask

from backend.oj_modules.routes import rejudge_routes
from backend.oj_modules.submissions import rejudge_filters


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.expirations = {}
        self.hashes = {}

    def setex(self, key, ttl, value):
        self.values[key] = value
        self.expirations[key] = ttl

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value
        return True

    def eval(self, script, key_count, key, expected):
        assert key_count == 1
        assert "redis.call('del'" in script
        if self.values.get(key) == expected:
            del self.values[key]
            return 1
        return 0

    def exists(self, key):
        return key in self.values or key in self.hashes

    def hgetall(self, key):
        return self.hashes.get(key, {})

    def hset(self, key, mapping=None):
        self.hashes.setdefault(key, {}).update(mapping or {})


class FakeCursor:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return next(self.responses)


class FakeConnection:
    def __init__(self, responses):
        self.fake_cursor = FakeCursor(responses)
        self.closed = False

    def cursor(self):
        return self.fake_cursor

    def close(self):
        self.closed = True


@pytest.fixture
def api(monkeypatch):
    app = Flask(__name__)
    app.register_blueprint(rejudge_routes.rejudge_bp)
    redis = FakeRedis()
    user = {"username": "admin", "is_admin": 1, "id": 8}
    state = {
        "user": user,
        "rows": [{"id": 1, "problem_type": 1, "status": "Accepted", "created_at": datetime(2026, 10, 14)}],
        "queries": [],
        "queued": [],
        "bulk_queued": [],
    }

    def query(filters):
        state["queries"].append(filters)
        return state["rows"]

    monkeypatch.setattr(rejudge_routes, "current_user", lambda: state["user"])
    monkeypatch.setattr(rejudge_routes, "_rds", redis)
    monkeypatch.setattr(rejudge_routes, "_rejudge_task", object())
    class FakeBulkTask:
        def apply_async(self, **kwargs):
            state["bulk_queued"].append(kwargs)

    monkeypatch.setattr(rejudge_routes, "_bulk_rejudge_task", FakeBulkTask())
    monkeypatch.setattr(rejudge_routes, "get_filtered_rejudge_submissions", query)
    monkeypatch.setattr(
        rejudge_routes,
        "_enqueue_rejudge",
        lambda rows, key, clear_running_lock=False: state["queued"].append((rows, key, clear_running_lock)),
    )
    monkeypatch.setattr(rejudge_routes, "emit_audit", lambda *_args, **_kwargs: None)
    return app.test_client(), state, redis


def test_filtered_query_intersects_dimensions_and_parameterizes_choices(monkeypatch):
    filters = rejudge_filters.normalize_rejudge_filters({
        "usernames": ["alice", "bob' OR 1=1 --", "alice"],
        "problem_ids": [12, 11],
        "statuses": ["Wrong Answer", "Accepted"],
        "start": "2026-10-01T00:00",
        "end": "2026-10-14 23:59:59",
    })
    rows = [{"id": 15, "problem_type": 2, "status": "Accepted"}]
    conn = FakeConnection([rows])
    monkeypatch.setattr(rejudge_filters, "get_db_connection", lambda: conn)

    assert rejudge_filters.get_filtered_rejudge_submissions(filters) == rows

    sql, params = conn.fake_cursor.calls[0]
    assert "username IN (%s,%s) AND problem_id IN (%s,%s) AND status IN (%s,%s) AND created_at BETWEEN %s AND %s" in sql
    assert "bob'" not in sql
    assert "LIMIT" not in sql
    assert params == ("alice", "bob' OR 1=1 --", 11, 12, "Accepted", "Wrong Answer", "2026-10-01 00:00:00", "2026-10-14 23:59:59")
    assert conn.closed


def test_all_dimensions_do_not_add_restrictive_predicates(monkeypatch):
    conn = FakeConnection([[]])
    monkeypatch.setattr(rejudge_filters, "get_db_connection", lambda: conn)
    filters = rejudge_filters.normalize_rejudge_filters({"usernames": [], "problem_ids": [], "statuses": []})

    assert rejudge_filters.get_filtered_rejudge_submissions(filters) == []

    assert conn.fake_cursor.calls == [("SELECT id, problem_type, status, created_at FROM submissions ORDER BY id ASC", ())]


def test_large_multiselect_keeps_every_parameter_and_no_row_limit(monkeypatch):
    usernames = [f"student_{number}" for number in range(2000)]
    problem_ids = list(range(1, 2001))
    filters = rejudge_filters.normalize_rejudge_filters({"usernames": usernames, "problem_ids": problem_ids})
    conn = FakeConnection([[{"id": 123}]])
    monkeypatch.setattr(rejudge_filters, "get_db_connection", lambda: conn)

    assert rejudge_filters.get_filtered_rejudge_submissions(filters) == [{"id": 123}]

    sql, params = conn.fake_cursor.calls[0]
    assert " AND " in sql
    assert "LIMIT" not in sql
    assert len(params) == 4000
    assert set(params[:2000]) == set(usernames)
    assert params[2000:] == tuple(problem_ids)


def test_long_judge_status_names_remain_selectable():
    statuses = ["Time Limit Exceeded", "Memory Limit Exceeded", "Output Limit Exceeded"]

    assert rejudge_filters.normalize_rejudge_filters({"statuses": statuses})["statuses"] == sorted(statuses)


def test_end_minute_includes_entire_minute_while_explicit_seconds_are_preserved():
    minute_range = rejudge_filters.normalize_rejudge_filters({"start": "2026-10-14T23:59", "end": "2026-10-14T23:59"})
    exact_range = rejudge_filters.normalize_rejudge_filters({"start": "2026-10-14T23:59:12", "end": "2026-10-14T23:59:42"})

    assert minute_range["start"] == "2026-10-14 23:59:00"
    assert minute_range["end"] == "2026-10-14 23:59:59"
    assert exact_range["start"] == "2026-10-14 23:59:12"
    assert exact_range["end"] == "2026-10-14 23:59:42"


@pytest.mark.parametrize("payload", [
    {"usernames": "alice"},
    {"usernames": [""]},
    {"usernames": [False]},
    {"problem_ids": [True]},
    {"problem_ids": [0]},
    {"problem_ids": [11.5]},
    {"problem_ids": [2_147_483_648]},
    {"statuses": "Accepted"},
    {"statuses": [""]},
    {"start": "2026-10-14T00:00"},
    {"start": "bad", "end": "2026-10-14T00:00"},
    {"start": "2026-10-15T00:00", "end": "2026-10-14T00:00"},
    [],
    None,
])
def test_invalid_filters_never_query_or_queue(api, payload):
    client, state, _redis = api

    response = client.post("/api/admin/rejudge-ranges", data=json.dumps(payload), content_type="application/json")

    assert response.status_code == 400
    assert response.get_json()["success"] is False
    assert state["queries"] == []
    assert state["queued"] == []


def test_preview_and_second_confirmation_rejudge_entire_batch_above_old_limit(api):
    client, state, redis = api
    state["rows"] = [{"id": n, "problem_type": 1, "status": "Accepted"} for n in range(1, 602)]
    payload = {"usernames": ["alice"], "problem_ids": [11], "statuses": ["Accepted"]}

    preview = client.post("/api/admin/rejudge-ranges", json=payload).get_json()

    assert preview["success"] and preview["preview"]
    assert preview["total"] == 601
    assert state["queued"] == []
    assert list(redis.expirations.values()) == [rejudge_filters.CONFIRMATION_TTL_SECONDS]

    confirmed = client.post("/api/admin/rejudge-ranges", json={
        **payload,
        "confirm_total": preview["total"],
        "confirmation_token": preview["confirmation_token"],
    }).get_json()

    batch_id = preview["confirmation_token"]
    assert confirmed == {"success": True, "preview": False, "message": "已开始重测", "total": 601, "batch_id": batch_id, "progress_url": f"/api/admin/rejudge-ranges/status?batch_id={batch_id}"}
    assert state["queued"] == []
    assert state["bulk_queued"] == [{
        "args": [[{"id": row["id"], "problem_type": 1, "status": "Accepted"} for row in state["rows"]], "rejudge:batch:" + batch_id],
        "queue": "celery",
        "task_id": batch_id,
    }]
    assert redis.hashes["rejudge:batch:" + batch_id] == {"total": 601, "done": 0, "scheduled": 0, "dispatch_status": "queued"}
    assert redis.values == {rejudge_filters.LATEST_REJUDGE_BATCH_KEY: batch_id}


def test_legacy_time_range_remains_supported_and_all_other_dimensions_default_all(api):
    client, state, _redis = api
    payload = {"start": "2026-10-01T00:00", "end": "2026-10-14T23:59"}
    preview = client.post("/admin/rejudge_time_range", data=payload).get_json()

    assert state["queries"] == [{"usernames": [], "problem_ids": [], "statuses": [], "start": "2026-10-01 00:00:00", "end": "2026-10-14 23:59:59"}]

    confirmed = client.post("/admin/rejudge_time_range", data={
        **payload,
        "confirm_total": str(preview["total"]),
        "confirmation_token": preview["confirmation_token"],
    }).get_json()
    assert confirmed["preview"] is False
    assert len(state["bulk_queued"]) == 1


@pytest.mark.parametrize("change", ["count", "ids", "filters", "admin", "expired", "missing_token", "invalid_token", "wrong_total"])
def test_changed_or_unbound_confirmation_requires_new_preview(api, change):
    client, state, redis = api
    payload = {"usernames": ["alice"]}
    preview = client.post("/api/admin/rejudge-ranges", json=payload).get_json()
    confirmation = {**payload, "confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]}
    if change == "count":
        state["rows"] = state["rows"] + [{"id": 2}]
    elif change == "ids":
        state["rows"] = [{"id": 2}]
    elif change == "filters":
        confirmation["usernames"] = []
    elif change == "admin":
        state["user"] = {"username": "other-admin", "is_admin": 1}
    elif change == "expired":
        redis.values.clear()
    elif change == "missing_token":
        confirmation.pop("confirmation_token")
    elif change == "invalid_token":
        confirmation["confirmation_token"] = "../any-key"
    elif change == "wrong_total":
        confirmation["confirm_total"] = True

    updated = client.post("/api/admin/rejudge-ranges", json=confirmation).get_json()

    assert updated["preview"] is True
    assert updated["total"] == len(state["rows"])
    assert updated["confirmation_token"] != preview["confirmation_token"]
    assert state["queued"] == []


def test_confirmation_is_consumed_once(api):
    client, state, _redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()
    payload = {"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]}

    first = client.post("/api/admin/rejudge-ranges", json=payload).get_json()
    duplicate = client.post("/api/admin/rejudge-ranges", json=payload).get_json()

    assert first["preview"] is False
    assert duplicate["preview"] is True
    assert len(state["bulk_queued"]) == 1


def test_zero_matches_preview_cannot_enqueue_even_with_confirm_total_zero(api):
    client, state, _redis = api
    state["rows"] = []

    response = client.post("/api/admin/rejudge-ranges", json={"confirm_total": 0}).get_json()

    assert response["success"] and response["preview"]
    assert response["total"] == 0
    assert "confirmation_token" not in response
    assert state["queued"] == []


def test_options_only_return_filter_fields_and_reuse_problem_labels(monkeypatch):
    conn = FakeConnection([[{"username": "alice"}, {"username": "bob"}], [{"status": "Accepted"}, {"status": "Wrong Answer"}]])
    monkeypatch.setattr(rejudge_filters, "get_db_connection", lambda: conn)
    monkeypatch.setattr(rejudge_filters, "get_submission_problem_options", lambda: [{"problem_id": 11, "problem_title": "「NA-1」 牛顿迭代", "latest_submission_id": 17}])

    assert rejudge_filters.get_rejudge_filter_options() == {
        "usernames": ["alice", "bob"],
        "problem_options": [{"problem_id": 11, "filter_label": "P0011 · 牛顿迭代"}],
        "statuses": ["Accepted", "Wrong Answer"],
    }
    assert conn.closed


@pytest.mark.parametrize("path,method", [
    ("/api/admin/rejudge-ranges", "post"),
    ("/admin/rejudge_time_range", "post"),
    ("/api/admin/rejudge-ranges/options", "get"),
    ("/api/admin/rejudge-ranges/status", "get"),
    ("/admin/rejudge_time_range_status", "get"),
    ("/api/admin/problems/11/rejudge-status", "get"),
    ("/admin/rejudge_status/11", "get"),
])
def test_rejudge_filters_and_progress_require_admin(api, path, method):
    client, state, _redis = api
    state["user"] = {"username": "student", "is_admin": 0}

    response = getattr(client, method)(path)

    assert response.status_code == 403
    assert response.get_json()["success"] is False
    assert state["queries"] == []
    assert state["queued"] == []


def test_admin_options_are_private_and_progress_keeps_existing_key(api, monkeypatch):
    client, _state, redis = api
    options = {"usernames": ["alice"], "problem_options": [], "statuses": ["Accepted"]}
    monkeypatch.setattr(rejudge_routes, "get_rejudge_filter_options", lambda: options)
    redis.hashes["rejudge:timerange"] = {"total": "5", "done": "2"}

    response = client.get("/api/admin/rejudge-ranges/options")

    assert response.get_json() == {"success": True, **options}
    assert response.headers["Cache-Control"] == "private, no-store"
    progress_response = client.get("/api/admin/rejudge-ranges/status")
    assert progress_response.get_json() == {"success": True, "progress": 40, "total": 5, "done": 2}
    assert progress_response.headers["Cache-Control"] == "private, no-store"


def test_parallel_batches_have_independent_progress_and_default_uses_latest(api):
    client, _state, redis = api
    batches = []
    for username in ("alice", "bob"):
        payload = {"usernames": [username]}
        preview = client.post("/api/admin/rejudge-ranges", json=payload).get_json()
        confirmation = client.post("/api/admin/rejudge-ranges", json={
            **payload,
            "confirm_total": preview["total"],
            "confirmation_token": preview["confirmation_token"],
        }).get_json()
        batches.append(confirmation)

    assert batches[0]["batch_id"] != batches[1]["batch_id"]
    redis.hashes[rejudge_filters.batch_progress_key(batches[0]["batch_id"])] = {"total": 10, "done": 3}
    redis.hashes[rejudge_filters.batch_progress_key(batches[1]["batch_id"])] = {"total": 20, "done": 15}

    assert client.get(batches[0]["progress_url"]).get_json() == {"success": True, "total": 10, "done": 3, "progress": 30}
    assert client.get(batches[1]["progress_url"]).get_json() == {"success": True, "total": 20, "done": 15, "progress": 75}
    assert client.get("/api/admin/rejudge-ranges/status").get_json() == {"success": True, "total": 20, "done": 15, "progress": 75}


def test_invalid_batch_id_cannot_read_arbitrary_redis_key(api):
    client, _state, _redis = api

    response = client.get("/api/admin/rejudge-ranges/status?batch_id=rejudge:submission:1")

    assert response.status_code == 400
    assert response.get_json()["success"] is False


@pytest.mark.parametrize("command", ["get", "eval", "setex"])
def test_confirmation_storage_failure_never_dispatches(api, monkeypatch, command):
    client, state, redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()

    def unavailable(*_args):
        raise ConnectionError("Redis unavailable")

    monkeypatch.setattr(redis, command, unavailable)
    payload = {} if command == "setex" else {"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]}
    response = client.post("/api/admin/rejudge-ranges", json=payload)

    assert response.status_code == 503
    assert response.get_json()["success"] is False
    assert state["queued"] == []
    assert state["bulk_queued"] == []


@pytest.mark.parametrize("failure", ["cas_lost", "corrupt_snapshot", "count_only", "huge_count"])
def test_confirmation_cannot_fall_back_to_only_matching_count(api, monkeypatch, failure):
    client, state, redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()
    payload = {"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]}
    if failure == "cas_lost":
        monkeypatch.setattr(redis, "eval", lambda *_args: 0)
    elif failure == "corrupt_snapshot":
        redis.values["rejudge:confirmation:" + preview["confirmation_token"]] = "invalid JSON"
    elif failure == "count_only":
        payload.pop("confirmation_token")
    else:
        payload["confirm_total"] = "9" * 5000

    response = client.post("/api/admin/rejudge-ranges", json=payload)

    assert response.status_code == 200
    assert response.get_json()["preview"] is True
    assert state["queued"] == []
    assert state["bulk_queued"] == []


def test_latest_pointer_failure_cannot_reverse_successful_dispatch(api, monkeypatch):
    client, state, redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()

    def unavailable(*_args):
        raise ConnectionError("Redis pointer unavailable")

    monkeypatch.setattr(redis, "set", unavailable)
    response = client.post("/api/admin/rejudge-ranges", json={"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]})

    assert response.status_code == 200
    assert response.get_json()["preview"] is False
    assert len(state["bulk_queued"]) == 1
    assert client.get(response.get_json()["progress_url"]).get_json()["success"] is True


def test_bulk_dispatch_failure_returns_failure_and_marks_progress(api, monkeypatch):
    client, state, _redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()

    def unavailable(**_kwargs):
        raise ConnectionError("broker unavailable")

    monkeypatch.setattr(rejudge_routes._bulk_rejudge_task, "apply_async", unavailable)
    response = client.post("/api/admin/rejudge-ranges", json={"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]})

    assert response.status_code == 503
    assert response.get_json()["success"] is False
    assert state["queued"] == []
    assert state["bulk_queued"] == []
    assert client.get("/api/admin/rejudge-ranges/status?batch_id=" + preview["confirmation_token"]).get_json() == {"success": False, "message": "重测任务投递失败"}


def test_missing_bulk_handle_cannot_consume_confirmation(api, monkeypatch):
    client, state, redis = api
    preview = client.post("/api/admin/rejudge-ranges", json={}).get_json()
    monkeypatch.setattr(rejudge_routes, "_bulk_rejudge_task", None)

    response = client.post("/api/admin/rejudge-ranges", json={"confirm_total": preview["total"], "confirmation_token": preview["confirmation_token"]})

    assert response.status_code == 500
    assert "rejudge:confirmation:" + preview["confirmation_token"] in redis.values
    assert state["bulk_queued"] == []
