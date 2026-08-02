import pytest

from oj_modules.integrations import modelscope_web_search as web_search


def test_web_search_runtime_requires_database_settings(monkeypatch):
    monkeypatch.setattr(web_search, "get_web_search_settings", lambda **_: None)

    with pytest.raises(RuntimeError, match="站点尚未配置联网搜索"):
        web_search._resolve_runtime_settings(None)


def test_web_search_runtime_uses_database_url_and_authorization(monkeypatch):
    monkeypatch.setattr(
        web_search,
        "get_web_search_settings",
        lambda **_: {
            "base_url": "https://search.example.invalid/mcp",
            "authorization": "Bearer database-secret",
        },
    )

    base_url, authorization, tool_name, timeout = web_search._resolve_runtime_settings(37)

    assert base_url == "https://search.example.invalid/mcp"
    assert authorization == "Bearer database-secret"
    assert tool_name == "bailian_web_search"
    assert timeout == 37


def test_web_search_runtime_uses_explicit_task_snapshot_without_rereading_database(monkeypatch):
    def should_not_read_database(**_kwargs):
        raise AssertionError("运行中不应重新读取全站配置")

    monkeypatch.setattr(web_search, "get_web_search_settings", should_not_read_database)
    snapshot = {
        "base_url": "https://snapshot.example.invalid/mcp",
        "authorization": "Bearer snapshot-secret",
    }

    base_url, authorization, tool_name, timeout = web_search._resolve_runtime_settings(
        41,
        snapshot,
    )

    assert base_url == "https://snapshot.example.invalid/mcp"
    assert authorization == "Bearer snapshot-secret"
    assert tool_name == "bailian_web_search"
    assert timeout == 41
