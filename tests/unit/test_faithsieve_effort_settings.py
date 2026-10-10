"""纯 LLM 思考强度只持久化到已有站点设置，未触及真实数据库。"""

import pytest

from backend.oj_modules.site_config import services
from tests.unit.test_agent_sessions import _ScriptedConnection


@pytest.mark.parametrize("stored,expected", [(None, None), ({"v": None}, None),
                                                 ({"v": "low"}, "low"), ({"v": "medium"}, "medium")])
def test_get_endpoint_effort_reads_only_its_setting(monkeypatch, stored, expected):
    connection = _ScriptedConnection(one_values=[stored])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    assert services.get_faithsieve_pure_reasoning_effort(4) == expected
    assert connection.cursor_instance.calls == [
        ("SELECT v FROM site_settings WHERE k=%s", ("FAITHSIEVE_PURE_REASONING_EFFORT:4",))
    ]
    assert connection.closed and connection.commits == connection.rollbacks == 0


@pytest.mark.parametrize("effort", [None, "low", "medium"])
def test_set_effort_validates_endpoint_and_commits_only_its_key(monkeypatch, effort):
    connection = _ScriptedConnection(one_values=[{"id": 4}])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    assert services.set_faithsieve_pure_reasoning_effort("4", effort) == effort
    calls = connection.cursor_instance.calls
    assert calls[0] == ("SELECT id FROM llm_endpoints WHERE id=%s FOR UPDATE", (4,))
    if effort is None:
        assert calls[1] == ("DELETE FROM site_settings WHERE k=%s", ("FAITHSIEVE_PURE_REASONING_EFFORT:4",))
    else:
        assert calls[1] == (
            "INSERT INTO site_settings (k, v) VALUES (%s, %s) ON DUPLICATE KEY UPDATE v=VALUES(v)",
            ("FAITHSIEVE_PURE_REASONING_EFFORT:4", effort),
        )
    assert len(calls) == 2 and connection.closed
    assert connection.commits == 1 and connection.rollbacks == 0


def test_missing_endpoint_setting_cannot_be_written(monkeypatch):
    connection = _ScriptedConnection(one_values=[None])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    with pytest.raises(services.DynamicConfigNotFoundError, match="端点不存在"):
        services.set_faithsieve_pure_reasoning_effort(4, "low")
    assert len(connection.cursor_instance.calls) == 1
    assert connection.closed and connection.commits == 0 and connection.rollbacks == 1


@pytest.mark.parametrize("effort", ["", "default", "high", " LOW ", True, False, 0, [], {}, ["low"]])
def test_invalid_effort_is_rejected_before_writes(monkeypatch, effort):
    monkeypatch.setattr(services, "get_db_connection", lambda: pytest.fail("非法配置不能连接数据库"))
    with pytest.raises(services.DynamicConfigValidationError, match="思考强度"):
        services.set_faithsieve_pure_reasoning_effort(4, effort)


@pytest.mark.parametrize("endpoint_id", [None, "", " 4 ", "04", "4.0", True, False, 0, -4, 4.0, [], {}])
def test_invalid_endpoint_id_cannot_access_configuration(monkeypatch, endpoint_id):
    monkeypatch.setattr(services, "get_db_connection", lambda: pytest.fail("非法端点不能连接数据库"))
    with pytest.raises(services.DynamicConfigValidationError, match="端点 ID"):
        services.get_faithsieve_pure_reasoning_effort(endpoint_id)
    with pytest.raises(services.DynamicConfigValidationError, match="端点 ID"):
        services.set_faithsieve_pure_reasoning_effort(endpoint_id, "low")


@pytest.mark.parametrize("value", ["default", "HIGH", " low ", True, 1, {"effort": "low"}])
def test_corrupt_stored_setting_is_not_silently_defaulted(monkeypatch, value):
    connection = _ScriptedConnection(one_values=[{"v": value}])
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    with pytest.raises(services.DynamicConfigValidationError, match="思考强度"):
        services.get_faithsieve_pure_reasoning_effort(4)
    assert connection.closed and connection.commits == 0


def test_failed_setting_write_rolls_back_and_closes(monkeypatch):
    connection = _ScriptedConnection(one_values=[{"id": 4}])
    execute = connection.cursor_instance.execute
    def fail_write(query, params):
        if query.startswith("INSERT"):
            raise RuntimeError("模拟保存失败")
        execute(query, params)
    connection.cursor_instance.execute = fail_write
    monkeypatch.setattr(services, "get_db_connection", lambda: connection)
    with pytest.raises(RuntimeError, match="模拟保存失败"):
        services.set_faithsieve_pure_reasoning_effort(4, "low")
    assert connection.closed and connection.rollbacks == 1 and connection.commits == 0
