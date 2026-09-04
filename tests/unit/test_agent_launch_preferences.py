"""解题/造数据 Agent 启动偏好的聚焦回归测试。"""

from __future__ import annotations

from datetime import datetime

import pytest

from backend.oj_modules.problems import agent_preferences
from backend.oj_modules.problems.agent_launch import AgentLaunchValidationError


class _FakeCursor:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def execute(self, sql, params):
        normalized_sql = " ".join(str(sql).split())
        self.connection.calls.append((normalized_sql, params))
        if normalized_sql.startswith("INSERT INTO agent_launch_preferences"):
            user_id, harness, endpoint_source, endpoint_id = params
            now = datetime(2026, 8, 3, 12, 0, 0)
            created_at = (
                self.connection.row or {}
            ).get("created_at", now)
            self.connection.row = {
                "user_id": user_id,
                "harness": harness,
                "endpoint_source": endpoint_source,
                "endpoint_id": endpoint_id,
                "created_at": created_at,
                "updated_at": now,
            }

    def fetchone(self):
        if self.connection.force_missing_select:
            return None
        return dict(self.connection.row) if self.connection.row else None


class _FakeConnection:
    def __init__(self, row=None, *, force_missing_select=False):
        self.row = row
        self.force_missing_select = force_missing_select
        self.calls = []
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_get_agent_launch_preference_is_scoped_by_user(monkeypatch):
    created_at = datetime(2026, 8, 1, 8, 30, 0)
    updated_at = datetime(2026, 8, 2, 9, 45, 0)
    connection = _FakeConnection(
        {
            "user_id": 7,
            "harness": "pi",
            "endpoint_id": 23,
            "created_at": created_at,
            "updated_at": updated_at,
        }
    )
    monkeypatch.setattr(
        agent_preferences,
        "get_db_connection",
        lambda: connection,
    )

    preference = agent_preferences.get_agent_launch_preference(7)

    assert preference == {
        "user_id": 7,
        "harness": "pi",
        "endpoint_source": "global",
        "endpoint_ref": "global:23",
        "endpoint_id": 23,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    assert len(connection.calls) == 1
    assert "WHERE user_id=%s" in connection.calls[0][0]
    assert "task_kind" not in connection.calls[0][0]
    assert connection.calls[0][1] == (7,)
    assert connection.closed is True


def test_get_agent_launch_preference_returns_none_when_unsaved(monkeypatch):
    connection = _FakeConnection()
    monkeypatch.setattr(
        agent_preferences,
        "get_db_connection",
        lambda: connection,
    )

    assert agent_preferences.get_agent_launch_preference(11) is None
    assert connection.closed is True


def test_save_agent_launch_preference_upserts_and_returns_latest_row(monkeypatch):
    connection = _FakeConnection(
        {
            "user_id": 7,
            "harness": "claude_code",
            "endpoint_id": 3,
            "created_at": datetime(2026, 8, 1, 8, 30, 0),
            "updated_at": datetime(2026, 8, 1, 8, 30, 0),
        }
    )
    monkeypatch.setattr(
        agent_preferences,
        "get_db_connection",
        lambda: connection,
    )

    preference = agent_preferences.save_agent_launch_preference(
        7,
        "pi",
        41,
    )

    assert preference["user_id"] == 7
    assert preference["harness"] == "pi"
    assert preference["endpoint_source"] == "global"
    assert preference["endpoint_ref"] == "global:41"
    assert preference["endpoint_id"] == 41
    assert len(connection.calls) == 2
    assert connection.calls[0][1] == (7, "pi", "global", 41)
    assert "ON DUPLICATE KEY UPDATE" in connection.calls[0][0]
    assert connection.calls[1][1] == (7,)
    assert connection.committed is True
    assert connection.rolled_back is False
    assert connection.closed is True


@pytest.mark.parametrize(
    ("args", "message"),
    (
        ((0, "pi", 1), "用户 ID 无效"),
        ((1, "unknown", 1), "Agent harness 无效"),
        ((1, "pi", 0), "LLM 节点 ID 无效"),
        ((1, "pi", True), "LLM 节点 ID 无效"),
        ((1, "pi", 1.5), "LLM 节点 ID 无效"),
    ),
)
def test_save_agent_launch_preference_rejects_invalid_values_before_db(
    monkeypatch,
    args,
    message,
):
    monkeypatch.setattr(
        agent_preferences,
        "get_db_connection",
        lambda: pytest.fail("非法偏好不能访问数据库"),
    )

    with pytest.raises(AgentLaunchValidationError, match=message):
        agent_preferences.save_agent_launch_preference(*args)


def test_save_agent_launch_preference_rolls_back_when_row_cannot_be_read(
    monkeypatch,
):
    connection = _FakeConnection(force_missing_select=True)
    monkeypatch.setattr(
        agent_preferences,
        "get_db_connection",
        lambda: connection,
    )

    with pytest.raises(RuntimeError, match="保存后无法读取"):
        agent_preferences.save_agent_launch_preference(
            7,
            "pi",
            23,
        )

    assert connection.committed is False
    assert connection.rolled_back is True
    assert connection.closed is True


def test_agent_launch_preferences_schema_is_declared():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    preference = specs["agent_launch_preferences"]

    assert preference.columns["user_id"].lower() == "int not null"
    assert "task_kind" not in preference.columns
    assert preference.columns["harness"].lower() == "varchar(32) not null"
    assert (
        preference.columns["endpoint_source"].lower()
        == "varchar(16) not null default 'global'"
    )
    assert preference.columns["endpoint_id"].lower() == "bigint not null"
    assert preference.indexes["PRIMARY"].lower() == "primary key (`user_id`)"
    assert "idx_agent_launch_preferences_endpoint" in preference.indexes

    bootstrap = init_db_schema.DATABASE_BOOTSTRAP_SQL.read_text(
        encoding="utf-8"
    )
    compact = " ".join(bootstrap.lower().split())
    assert (
        "constraint `fk_agent_launch_preferences_user` foreign key "
        "(`user_id`) references `users` (`id`) on delete cascade"
    ) in compact
    assert "agent_launch_preferences_task_kind" not in compact
    assert (
        "check (`harness` in ('claude_code','pi'))"
        in compact
    )


def test_removed_harness_preference_is_ignored(monkeypatch):
    connection = _FakeConnection({
        "user_id": 7,
        "harness": "codex",
        "endpoint_source": "global",
        "endpoint_id": 23,
    })
    monkeypatch.setattr(agent_preferences, "get_db_connection", lambda: connection)

    assert agent_preferences.get_agent_launch_preference(7) is None
