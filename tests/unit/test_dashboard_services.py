from datetime import date, datetime
from threading import Event, Thread
from unittest.mock import MagicMock

import pytest

from backend.oj_modules.classroom import dashboard as dashboard_services


@pytest.fixture(autouse=True)
def _reset_dashboard_cache():
    dashboard_services.clear_dashboard_cache()
    dashboard_services.init_class_activity_cache(None)
    yield
    dashboard_services.clear_dashboard_cache()
    dashboard_services.init_class_activity_cache(None)


class _Cursor:
    def __init__(self, *, rows=None, one_by_sql=None):
        self.rows = rows or []
        self.one_by_sql = one_by_sql or {}
        self.executions = []
        self.current_sql = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params=None):
        self.current_sql = " ".join(sql.split())
        self.executions.append((self.current_sql, params))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        for fragment, value in self.one_by_sql.items():
            if fragment in self.current_sql:
                return value
        return None


class _Connection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


class _HashRedis:
    def __init__(self):
        self.hashes = {}
        self.expirations = {}

    def hset(self, key, *, mapping):
        self.hashes[key] = dict(mapping)

    def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    def expire(self, key, seconds):
        self.expirations[key] = seconds

    def pipeline(self, *, transaction=True):
        assert transaction is True
        return _HashRedisPipeline(self)

    def rename(self, source, destination):
        self.hashes[destination] = self.hashes.pop(source)
        self.expirations.pop(source, None)

    def delete(self, key):
        self.hashes.pop(key, None)
        self.expirations.pop(key, None)


class _HashRedisPipeline:
    def __init__(self, redis_client):
        self.redis_client = redis_client
        self.operations = []

    def rename(self, source, destination):
        self.operations.append(("rename", source, destination))
        return self

    def persist(self, key):
        self.operations.append(("persist", key))
        return self

    def execute(self):
        for operation in self.operations:
            if operation[0] == "rename":
                self.redis_client.rename(operation[1], operation[2])
            elif operation[0] == "persist":
                self.redis_client.expirations.pop(operation[1], None)


def test_select_visible_class_honors_request_then_stable_class_code_fallback():
    classes = [
        {"class_en": "C2"},
        {"class_en": "C1"},
    ]

    assert dashboard_services.select_visible_class(classes, "C2") == classes[0]
    assert dashboard_services.select_visible_class(classes, "not-visible") == classes[1]
    assert dashboard_services.select_visible_class([], "C1") is None


def test_visible_classes_for_user_uses_role_specific_source(monkeypatch):
    monkeypatch.setattr(
        dashboard_services,
        "get_all_classes",
        lambda: [{"class_en": "C2"}],
    )
    get_user_classes = MagicMock(return_value=[{"class_en": "C1"}])
    monkeypatch.setattr(dashboard_services, "get_user_classes", get_user_classes)

    assert dashboard_services.visible_classes_for_user(None) == []
    assert dashboard_services.visible_classes_for_user({"id": 9, "is_admin": 0}) == [
        {"class_en": "C1"}
    ]
    assert dashboard_services.visible_classes_for_user({"id": 1, "is_admin": 1}) == [
        {"class_en": "C2"}
    ]
    get_user_classes.assert_called_once_with(9)


def test_build_activity_calendar_aligns_to_monday_and_marks_future_days():
    today = date(2026, 7, 22)  # Wednesday
    counts = {
        date(2026, 5, 4): 1,
        date(2026, 7, 20): 2,
        date(2026, 7, 21): 4,
        date(2026, 7, 22): 8,
    }

    calendar = dashboard_services.build_activity_calendar(counts, today=today, days=84)

    assert len(calendar) == 84
    assert calendar[0]["day"] == date(2026, 5, 4)
    assert calendar[0]["weekday"] == 0
    assert calendar[-1]["day"] == date(2026, 7, 26)
    assert [item["intensity"] for item in calendar if item["count"]] == [1, 1, 2, 4]
    assert all(item["count"] == 0 and item["future"] for item in calendar[-4:])


def test_cached_reuses_value_until_expiry_and_clear_forces_reload():
    loader = MagicMock(side_effect=[{"value": 1}, {"value": 2}, {"value": 3}])

    first = dashboard_services._cached(("k",), loader, now_monotonic=100)
    assert dashboard_services._cached(("k",), loader, now_monotonic=129) is first
    assert dashboard_services._cached(("k",), loader, now_monotonic=130) == {"value": 2}
    dashboard_services.clear_dashboard_cache()
    assert dashboard_services._cached(("k",), loader, now_monotonic=131) == {"value": 3}
    assert loader.call_count == 3


def test_clear_prevents_in_flight_loader_from_repopulating_stale_cache():
    started = Event()
    release = Event()
    first_result = []

    def slow_loader():
        started.set()
        assert release.wait(timeout=2)
        return {"value": "stale"}

    worker = Thread(
        target=lambda: first_result.append(
            dashboard_services._cached(("race",), slow_loader)
        )
    )
    worker.start()
    assert started.wait(timeout=2)
    dashboard_services.clear_dashboard_cache()
    release.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert first_result == [{"value": "stale"}]
    assert ("race",) not in dashboard_services._cache
    assert dashboard_services._cached(
        ("race",), lambda: {"value": "fresh"}
    ) == {"value": "fresh"}


def test_problem_metrics_apply_terminal_and_current_class_filters(monkeypatch):
    captured = {}

    def metric_rows(query, params):
        captured["query"] = " ".join(query.split())
        captured["params"] = params
        return [{"entity_id": 7, "submission_count": 4, "accepted_count": 3}]

    monkeypatch.setattr(dashboard_services, "_metric_rows", metric_rows)

    result = dashboard_services.get_problem_submission_metrics(
        [9, 7, 9], class_en="C2026"
    )

    assert result == {
        7: {"submission_count": 4, "accepted_count": 3, "pass_rate": 0.75}
    }
    assert "s.problem_id IN (%s,%s)" in captured["query"]
    assert "s.status NOT IN" in captured["query"]
    assert "u.is_admin = 0" in captured["query"]
    assert "user_class_map" in captured["query"]
    assert captured["params"][:2] == (7, 9)
    assert captured["params"][-1:] == ("C2026",)
    assert "u.class" not in captured["query"]
    for status in dashboard_services._NON_TERMINAL_STATUSES:
        assert status in captured["params"]


def test_ranking_metrics_only_count_self_submissions(monkeypatch):
    captured = {}

    def metric_rows(query, params):
        captured["query"] = " ".join(query.split())
        captured["params"] = params
        return [{"entity_id": 3, "submission_count": 2, "accepted_count": 0}]

    monkeypatch.setattr(dashboard_services, "_metric_rows", metric_rows)

    result = dashboard_services.get_ranking_submission_metrics([3])

    assert result[3]["pass_rate"] == 0
    assert "rs.source = 'self'" in captured["query"]
    assert captured["params"][0] == 3


def test_attach_submission_metrics_handles_problem_and_ranking_homeworks(monkeypatch):
    problem_metrics = MagicMock(
        return_value={7: {"submission_count": 2, "accepted_count": 1, "pass_rate": 0.5}}
    )
    ranking_metrics = MagicMock(
        return_value={4: {"submission_count": 5, "accepted_count": 5, "pass_rate": 1}}
    )
    monkeypatch.setattr(dashboard_services, "get_problem_submission_metrics", problem_metrics)
    monkeypatch.setattr(dashboard_services, "get_ranking_submission_metrics", ranking_metrics)
    homeworks = [
        {"id": 1, "problem_id": 7},
        {"id": 2, "problem_id": None, "ranking_competition_id": 4},
        {
            "id": 3,
            "problem_id": None,
            "ranking_competition_id": 5,
            "scoring_mode": "elo",
        },
    ]

    result = dashboard_services.attach_submission_metrics(homeworks, class_en="C1")

    assert result is not homeworks
    assert all("submission_metrics" not in item for item in homeworks)
    assert result[0]["submission_metrics"]["pass_rate"] == 0.5
    assert result[1]["submission_metrics"]["pass_rate"] == 1
    assert result[2]["submission_metrics"] is None
    problem_metrics.assert_called_once_with([7], class_en="C1")
    ranking_metrics.assert_called_once_with([4], class_en="C1")


def test_load_all_class_activity_batches_normal_and_ranking_submissions(monkeypatch):
    class _ActivityCursor(_Cursor):
        def fetchall(self):
            if "FROM class_table" in self.current_sql:
                return [{"class_en": "C1"}, {"class_en": "C2"}]
            return [
                {
                    "class_en": "C1",
                    "activity_day": datetime(2026, 7, 21, 0, 0),
                    "submission_count": 3,
                },
                {
                    "class_en": "C1",
                    "activity_day": date(2026, 7, 22),
                    "submission_count": 2,
                },
            ]

    cursor = _ActivityCursor()
    connection = _Connection(cursor)
    factory = MagicMock(return_value=connection)
    monkeypatch.setattr(dashboard_services, "get_db_connection", factory)

    result = dashboard_services.load_all_class_activity(
        today=date(2026, 7, 22), days=14
    )

    assert factory.call_count == 1
    assert connection.closed is True
    aggregate_sql, params = cursor.executions[2]
    assert cursor.executions[0] == ("SET time_zone = '+08:00'", None)
    assert "FROM class_table" in cursor.executions[1][0]
    assert "FROM submissions s" in aggregate_sql
    assert "UNION ALL" in aggregate_sql
    assert "FROM ranking_submissions rs" in aggregate_sql
    assert "rs.source = 'self'" in aggregate_sql
    assert len(params) == 4
    by_day = {item["day"]: item for item in result["C1"]}
    assert by_day[date(2026, 7, 21)]["count"] == 3
    assert by_day[date(2026, 7, 22)]["count"] == 2
    assert all(item["count"] == 0 for item in result["C2"])


def test_get_class_activity_only_reads_atomically_published_redis_snapshot(monkeypatch):
    redis_client = _HashRedis()
    snapshot = {
        "C1": dashboard_services.build_activity_calendar(
            {date(2026, 7, 22): 5},
            today=date(2026, 7, 22),
            days=14,
        ),
    }
    dashboard_services.publish_class_activity_snapshot(redis_client, snapshot)
    dashboard_services.init_class_activity_cache(redis_client)
    monkeypatch.setattr(
        dashboard_services,
        "get_db_connection",
        MagicMock(side_effect=AssertionError("请求路径不应查询 MySQL")),
    )

    result = dashboard_services.get_class_activity("C1")

    assert result[-5]["day"] == date(2026, 7, 22)
    assert result[-5]["count"] == 5
    assert dashboard_services.get_class_activity("new-class") == []
    assert dashboard_services.CLASS_ACTIVITY_CACHE_KEY in redis_client.hashes
    assert not any("staging" in key for key in redis_client.hashes)


def test_failed_snapshot_publish_preserves_previous_redis_snapshot(monkeypatch):
    redis_client = _HashRedis()
    old_snapshot = {
        "C1": dashboard_services.build_activity_calendar(
            {date(2026, 7, 21): 2},
            today=date(2026, 7, 22),
            days=14,
        ),
    }
    dashboard_services.publish_class_activity_snapshot(redis_client, old_snapshot)
    previous = dict(
        redis_client.hashes[dashboard_services.CLASS_ACTIVITY_CACHE_KEY]
    )

    class _FailedPipeline:
        def rename(self, _source, _destination):
            return self

        def persist(self, _key):
            return self

        def execute(self):
            raise OSError("redis transaction failed")

    monkeypatch.setattr(
        redis_client,
        "pipeline",
        lambda *, transaction=True: _FailedPipeline(),
    )

    with pytest.raises(OSError, match="transaction failed"):
        dashboard_services.publish_class_activity_snapshot(
            redis_client,
            {"C1": []},
        )

    assert redis_client.hashes[dashboard_services.CLASS_ACTIVITY_CACHE_KEY] == previous
    assert not any("staging" in key for key in redis_client.hashes)


def test_get_layout_navigation_context_returns_real_admin_counts(monkeypatch):
    cursor = _Cursor(
        one_by_sql={
            "FROM C1": {"total": 6},
            "FROM submissions": {"total": 312},
            "FROM problems": {"total": 42},
            "FROM users": {"total": 19},
            "FROM agent_task_runs": {"active": 1},
        }
    )
    connection = _Connection(cursor)
    monkeypatch.setattr(dashboard_services, "get_db_connection", lambda: connection)
    monkeypatch.setattr(
        dashboard_services,
        "visible_classes_for_user",
        lambda _user: [{"class_en": "C1"}],
    )

    result = dashboard_services.get_layout_navigation_context(
        {"id": 1, "username": "admin", "is_admin": 1}
    )
    same_result = dashboard_services.get_layout_navigation_context(
        {"id": 1, "username": "admin", "is_admin": 1},
        selected_class_en="UNRECOGNIZED",
    )

    assert result == {
        "counts": {"homeworks": 6, "submissions": 312, "problems": 42, "users": 19},
        "agent_active": True,
        "selected_class_en": "C1",
    }
    assert same_result == result
    assert connection.closed is True
    assert sum("FROM submissions" in sql for sql, _ in cursor.executions) == 1
    assert any("status IN ('Pending', 'Running')" in sql for sql, _ in cursor.executions)


def test_dashboard_cache_is_capacity_bounded():
    for index in range(dashboard_services._CACHE_MAX_ENTRIES + 40):
        dashboard_services._cached(
            ("capacity", index),
            lambda index=index: index,
            now_monotonic=100,
        )

    assert len(dashboard_services._cache) == dashboard_services._CACHE_MAX_ENTRIES


def test_dashboard_cache_coalesces_concurrent_misses():
    started = Event()
    release = Event()
    loader = MagicMock()

    def load():
        loader()
        started.set()
        release.wait(timeout=2)
        return {"value": 1}

    results = []
    first = Thread(target=lambda: results.append(dashboard_services._cached(("shared",), load)))
    second = Thread(target=lambda: results.append(dashboard_services._cached(("shared",), load)))
    first.start()
    assert started.wait(timeout=2)
    second.start()
    release.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert results == [{"value": 1}, {"value": 1}]
    loader.assert_called_once_with()


def test_metric_rows_closes_connection_when_query_fails(monkeypatch):
    cursor = _Cursor()

    def fail_execute(_sql, _params=None):
        raise RuntimeError("database unavailable")

    cursor.execute = fail_execute
    connection = _Connection(cursor)
    monkeypatch.setattr(dashboard_services, "get_db_connection", lambda: connection)

    with pytest.raises(RuntimeError, match="database unavailable"):
        dashboard_services._metric_rows("SELECT 1", ())

    assert connection.closed is True
