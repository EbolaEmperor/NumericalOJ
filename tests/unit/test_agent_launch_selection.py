import pytest

from oj_modules.problems import agent_launch


def _endpoint(endpoint_id, *, protocol, category="text"):
    return {
        "id": endpoint_id,
        "protocol": protocol,
        "category": category,
        "base_url": "https://model.example/v1",
        "api_key": "secret",
        "api_key_configured": True,
        "model": f"model-{endpoint_id}",
        "thinking_enabled": False,
        "thinking_format": "none",
        "test_status": "passed",
    }


def test_launch_endpoint_matrix_includes_opencode_global_nodes_without_secrets(
    monkeypatch,
):
    endpoints = [
        _endpoint(1, protocol="openai"),
        _endpoint(2, protocol="anthropic", category="omni"),
        _endpoint(3, protocol="openai", category="vision"),
        _endpoint(4, protocol="openai", category="embedding"),
    ]
    monkeypatch.setattr(
        agent_launch,
        "list_llm_endpoints",
        lambda **kwargs: endpoints,
    )

    result = agent_launch.list_launch_endpoints_by_harness()

    assert [item["id"] for item in result["claude_code"]] == [2]
    assert [item["id"] for item in result["codex"]] == [1]
    assert [item["id"] for item in result["opencode"]] == [1]
    assert [item["id"] for item in result["pi"]] == [1, 2]
    assert all(
        "api_key" not in item and "base_url" not in item
        for items in result.values()
        for item in items
    )


def test_launch_endpoint_matrix_excludes_nodes_without_configured_api_key(
    monkeypatch,
):
    configured = _endpoint(1, protocol="openai")
    missing = _endpoint(2, protocol="openai")
    missing["api_key_configured"] = False
    monkeypatch.setattr(
        agent_launch,
        "list_llm_endpoints",
        lambda **_kwargs: [configured, missing],
    )

    result = agent_launch.list_launch_endpoints_by_harness()

    assert [item["id"] for item in result["codex"]] == [1]
    assert [item["id"] for item in result["opencode"]] == [1]


def test_resolve_launch_endpoint_fails_closed_for_unknown_harness(monkeypatch):
    monkeypatch.setattr(
        agent_launch,
        "get_llm_endpoint",
        lambda *_args, **_kwargs: _endpoint(1, protocol="openai"),
    )

    with pytest.raises(agent_launch.AgentLaunchValidationError, match="harness"):
        agent_launch.resolve_launch_endpoint("typo", 1, include_secret=True)


def test_resolve_launch_endpoint_checks_selected_protocol(monkeypatch):
    monkeypatch.setattr(
        agent_launch,
        "get_llm_endpoint",
        lambda *_args, **_kwargs: _endpoint(2, protocol="anthropic"),
    )

    with pytest.raises(agent_launch.AgentLaunchValidationError, match="不兼容"):
        agent_launch.resolve_launch_endpoint("codex", 2, include_secret=True)

    resolved = agent_launch.resolve_launch_endpoint(
        "claude_code", 2, include_secret=True,
    )
    assert resolved["api_key"] == "secret"


@pytest.mark.parametrize(
    "endpoint_id",
    [True, False, 1.0, "1.0", " 1", "01", 0, -1, 9_223_372_036_854_775_808],
)
def test_resolve_launch_endpoint_rejects_non_strict_positive_ids(
    monkeypatch,
    endpoint_id,
):
    monkeypatch.setattr(
        agent_launch,
        "get_llm_endpoint",
        lambda *_args, **_kwargs: pytest.fail("非法 ID 不应读取节点"),
    )

    with pytest.raises(agent_launch.AgentLaunchValidationError, match="有效"):
        agent_launch.resolve_launch_endpoint(
            "codex", endpoint_id, include_secret=False,
        )


def test_resolve_public_launch_endpoint_requires_configured_api_key(monkeypatch):
    endpoint = _endpoint(3, protocol="openai")
    endpoint["api_key"] = ""
    endpoint["api_key_configured"] = False
    monkeypatch.setattr(
        agent_launch,
        "get_llm_endpoint",
        lambda *_args, **_kwargs: endpoint,
    )

    with pytest.raises(agent_launch.AgentLaunchValidationError, match="API Key"):
        agent_launch.resolve_launch_endpoint(
            "codex", 3, include_secret=False,
        )
