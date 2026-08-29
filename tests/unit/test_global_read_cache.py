from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from oj_modules import db_services
from oj_modules.infrastructure.mysql import MySQLPoolExhausted
from oj_modules.shared.singleflight_cache import BoundedSingleFlightTTLCache
from oj_modules.site_config import services


class _MailCursor:
    def __init__(self, row):
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    def execute(self, sql):
        assert "site_mail_settings" in sql

    def fetchone(self):
        return dict(self.row) if self.row else None


class _MailConnection:
    def __init__(self, row):
        self.row = row
        self.closed = False

    def cursor(self):
        return _MailCursor(self.row)

    def close(self):
        self.closed = True


def _new_cache(*, clock=None):
    kwargs = {
        "ttl_seconds": 5.0,
        "wait_timeout_seconds": 0.05,
        "failure_cooldown_seconds": 0.25,
    }
    if clock is not None:
        kwargs["clock"] = clock
    return BoundedSingleFlightTTLCache(**kwargs)


def _run_concurrently(count, callback, started, release):
    barrier = threading.Barrier(count)

    def invoke():
        barrier.wait(timeout=5)
        try:
            callback()
        except Exception as error:
            return type(error), error.args
        return None

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(invoke) for _ in range(count)]
        try:
            assert started.wait(2)
        finally:
            release.set()
        return [future.result(timeout=2) for future in futures]


def test_class_adjust_flag_cache_reuses_loader_and_can_be_invalidated(monkeypatch):
    calls = []
    monkeypatch.setattr(db_services, "_class_adjust_cache", _new_cache())
    monkeypatch.setattr(
        db_services,
        "get_setting",
        lambda key, default=None: calls.append((key, default)) or "1",
    )

    assert db_services.is_class_adjust_enabled() is True
    assert db_services.is_class_adjust_enabled() is True
    assert len(calls) == 1

    db_services._invalidate_class_adjust_cache()
    assert db_services.is_class_adjust_enabled() is True
    assert len(calls) == 2


def test_mail_settings_cache_reuses_raw_row_without_leaking_secret(monkeypatch):
    row = {
        "id": 1,
        "smtp_server": "smtp.example.test",
        "smtp_port": 465,
        "smtp_username": "mailer@example.test",
        "smtp_password": "mail-secret",
    }
    connections = []

    def connect():
        connection = _MailConnection(row)
        connections.append(connection)
        return connection

    monkeypatch.setattr(services, "_mail_settings_cache", _new_cache())
    monkeypatch.setattr(services, "get_db_connection", connect)

    public = services.get_mail_settings()
    internal = services.get_mail_settings(include_secret=True)

    assert len(connections) == 1
    assert connections[0].closed is True
    assert public["smtp_password"] == ""
    assert public["smtp_password_configured"] is True
    assert internal["smtp_password"] == "mail-secret"

    services._invalidate_mail_settings_cache()
    services.get_mail_settings()
    assert len(connections) == 2


def test_mail_settings_cache_remembers_missing_row(monkeypatch):
    connections = []

    def connect():
        connection = _MailConnection(None)
        connections.append(connection)
        return connection

    monkeypatch.setattr(services, "_mail_settings_cache", _new_cache())
    monkeypatch.setattr(services, "get_db_connection", connect)

    assert services.get_mail_settings() is None
    assert services.get_mail_settings(include_secret=True) is None
    assert len(connections) == 1


def test_mail_settings_failure_fans_out_once_to_64_callers_and_cools_down(
    monkeypatch,
):
    now = [10.0]
    started = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    calls = 0
    failing = True
    row = {
        "id": 1,
        "smtp_server": "smtp.example.test",
        "smtp_port": 465,
        "smtp_username": "mailer@example.test",
        "smtp_password": "secret",
    }

    def connect():
        nonlocal calls
        with call_lock:
            calls += 1
        if failing:
            started.set()
            assert release.wait(2)
            raise RuntimeError("mail database unavailable")
        return _MailConnection(row)

    monkeypatch.setattr(
        services,
        "_mail_settings_cache",
        _new_cache(clock=lambda: now[0]),
    )
    monkeypatch.setattr(services, "get_db_connection", connect)

    results = _run_concurrently(
        64,
        lambda: services.get_mail_settings(wait_timeout_seconds=1.0),
        started,
        release,
    )

    assert calls == 1
    assert results == [(RuntimeError, ("mail database unavailable",))] * 64
    with pytest.raises(RuntimeError, match="mail database unavailable"):
        services.get_mail_settings(wait_timeout_seconds=0.0)
    assert calls == 1

    failing = False
    now[0] += 1.0
    assert services.get_mail_settings()["smtp_server"] == "smtp.example.test"
    assert calls == 2


def test_class_adjust_failure_fans_out_once_to_32_callers_and_cools_down(
    monkeypatch,
):
    now = [20.0]
    started = threading.Event()
    release = threading.Event()
    call_lock = threading.Lock()
    calls = 0
    failing = True

    def load_setting(key, default=None):
        nonlocal calls
        assert key == db_services.CLASS_ADJUST_FLAG_KEY
        assert default == "1"
        with call_lock:
            calls += 1
        if failing:
            started.set()
            assert release.wait(2)
            raise RuntimeError("settings database unavailable")
        return "1"

    monkeypatch.setattr(
        db_services,
        "_class_adjust_cache",
        _new_cache(clock=lambda: now[0]),
    )
    monkeypatch.setattr(db_services, "get_setting", load_setting)

    results = _run_concurrently(
        32,
        lambda: db_services.is_class_adjust_enabled(wait_timeout_seconds=1.0),
        started,
        release,
    )

    assert calls == 1
    assert results == [
        (RuntimeError, ("settings database unavailable",))
    ] * 32
    with pytest.raises(RuntimeError, match="settings database unavailable"):
        db_services.is_class_adjust_enabled(wait_timeout_seconds=0.0)
    assert calls == 1

    failing = False
    now[0] += 1.0
    assert db_services.is_class_adjust_enabled() is True
    assert calls == 2


def test_template_style_zero_wait_fails_fast_while_cold_load_is_in_flight(
    monkeypatch,
):
    started = threading.Event()
    release = threading.Event()

    def load_setting(key, default=None):
        started.set()
        assert release.wait(2)
        return "1"

    monkeypatch.setattr(db_services, "_class_adjust_cache", _new_cache())
    monkeypatch.setattr(db_services, "get_setting", load_setting)
    with ThreadPoolExecutor(max_workers=1) as executor:
        owner = executor.submit(db_services.is_class_adjust_enabled)
        assert started.wait(1)
        try:
            with pytest.raises(MySQLPoolExhausted):
                db_services.is_class_adjust_enabled(wait_timeout_seconds=0.0)
        finally:
            release.set()
        assert owner.result(timeout=1) is True


def test_mail_settings_invalidation_during_load_prevents_stale_publish(
    monkeypatch,
):
    old_started = threading.Event()
    allow_old = threading.Event()
    call_lock = threading.Lock()
    calls = 0
    old_row = {
        "id": 1,
        "smtp_server": "old.example.test",
        "smtp_port": 465,
        "smtp_username": "old@example.test",
        "smtp_password": "old-secret",
    }
    new_row = {
        "id": 1,
        "smtp_server": "new.example.test",
        "smtp_port": 465,
        "smtp_username": "new@example.test",
        "smtp_password": "new-secret",
    }

    def connect():
        nonlocal calls
        with call_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            old_started.set()
            assert allow_old.wait(2)
            return _MailConnection(old_row)
        return _MailConnection(new_row)

    monkeypatch.setattr(services, "_mail_settings_cache", _new_cache())
    monkeypatch.setattr(services, "get_db_connection", connect)

    with ThreadPoolExecutor(max_workers=1) as executor:
        old_load = executor.submit(services.get_mail_settings)
        assert old_started.wait(1)
        services._invalidate_mail_settings_cache()
        current = services.get_mail_settings(wait_timeout_seconds=1.0)
        allow_old.set()
        stale_owner_result = old_load.result(timeout=1)

    assert stale_owner_result["smtp_server"] == "old.example.test"
    assert current["smtp_server"] == "new.example.test"
    assert services.get_mail_settings()["smtp_server"] == "new.example.test"
    assert calls == 2
