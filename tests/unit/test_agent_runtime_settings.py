"""通用 Agent 站点级运行参数的聚焦测试。"""

from __future__ import annotations

import pytest

from backend.oj_modules.agents import runtime_settings


class _Cursor:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        self.connection.statements.append((normalized, params))
        if self.connection.fail_on_execute:
            raise RuntimeError("database unavailable")

    def fetchone(self):
        return self.connection.row


class _Connection:
    def __init__(self, row=None, *, fail_on_execute=False):
        self.row = row
        self.fail_on_execute = fail_on_execute
        self.statements = []
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        (None, runtime_settings.AGENT_CONCURRENCY_DEFAULT),
        ({"v": "1"}, 1),
        ({"v": "100"}, 100),
    ],
)
def test_agent_concurrency_limit_reads_site_setting_or_default(
    monkeypatch,
    row,
    expected,
):
    connection = _Connection(row)
    monkeypatch.setattr(runtime_settings, "get_db_connection", lambda: connection)

    assert runtime_settings.get_agent_concurrency_limit() == expected
    assert connection.statements == [
        (
            "SELECT v FROM site_settings WHERE k=%s",
            (runtime_settings.AGENT_CONCURRENCY_SETTING_KEY,),
        )
    ]
    assert connection.closed is True


@pytest.mark.parametrize(
    "value",
    [None, True, False, 0, 101, -1, 1.0, "1.0", "01", "", "eight"],
)
def test_agent_concurrency_limit_rejects_values_outside_strict_integer_range(value):
    with pytest.raises(
        runtime_settings.AgentRuntimeSettingsValidationError,
        match="1 \u5230 100",
    ):
        runtime_settings.normalize_agent_concurrency_limit(value)


def test_agent_concurrency_limit_is_upserted_as_text(monkeypatch):
    connection = _Connection()
    monkeypatch.setattr(runtime_settings, "get_db_connection", lambda: connection)

    assert runtime_settings.set_agent_concurrency_limit("24") == 24
    assert connection.statements == [
        (
            "INSERT INTO site_settings (k, v) VALUES (%s, %s) "
            "ON DUPLICATE KEY UPDATE v=VALUES(v)",
            (runtime_settings.AGENT_CONCURRENCY_SETTING_KEY, "24"),
        )
    ]
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert connection.closed is True


def test_agent_concurrency_limit_write_rolls_back_and_closes(monkeypatch):
    connection = _Connection(fail_on_execute=True)
    monkeypatch.setattr(runtime_settings, "get_db_connection", lambda: connection)

    with pytest.raises(RuntimeError, match="database unavailable"):
        runtime_settings.set_agent_concurrency_limit(8)

    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert connection.closed is True
