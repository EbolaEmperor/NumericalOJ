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
        "input_price_per_million": "1",
        "cached_input_price_per_million": "0.1",
        "output_price_per_million": "4",
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
    assert result["codex"][0]["ref"] == "global:1"
    assert result["codex"][0]["metered"] is True
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


def test_launch_endpoint_matrix_includes_only_current_users_personal_nodes(
    monkeypatch,
):
    monkeypatch.setattr(agent_launch, "list_llm_endpoints", lambda **_kwargs: [])
    monkeypatch.setattr(
        agent_launch,
        "list_user_agent_endpoints",
        lambda user_id, **_kwargs: [
            {
                **_endpoint(9, protocol="openai"),
                "ref": "user:9",
                "source": "user",
                "is_personal": True,
                "metered": False,
            }
        ] if user_id == 7 else [],
    )

    result = agent_launch.list_launch_endpoints_by_harness(user_id=7)

    assert result["codex"][0]["ref"] == "user:9"
    assert result["codex"][0]["metered"] is False


def test_resolve_personal_endpoint_is_scoped_to_current_user(monkeypatch):
    seen = []

    def get_personal(endpoint_id, user_id, *, include_secret):
        seen.append((endpoint_id, user_id, include_secret))
        return _endpoint(endpoint_id, protocol="openai")

    monkeypatch.setattr(agent_launch, "get_user_agent_endpoint", get_personal)

    resolved = agent_launch.resolve_launch_endpoint(
        "codex",
        "user:9",
        include_secret=True,
        user_id=7,
    )

    assert seen == [(9, 7, True)]
    assert resolved["ref"] == "user:9"
    assert resolved["metered"] is False

    with pytest.raises(
        agent_launch.AgentLaunchValidationError,
        match="不属于当前用户",
    ):
        agent_launch.resolve_launch_endpoint(
            "codex",
            "user:9",
            include_secret=True,
        )


def test_endpoint_token_pricing_requires_all_three_prices():
    endpoint = _endpoint(4, protocol="openai")
    endpoint.pop("input_price_per_million")
    endpoint.pop("cached_input_price_per_million")
    endpoint.pop("output_price_per_million")
    assert agent_launch.token_pricing_from_endpoint(endpoint) is None

    endpoint.update({
        "input_price_per_million": "2.00",
        "cached_input_price_per_million": "0.20",
        "output_price_per_million": "8.00",
    })
    assert agent_launch.token_pricing_from_endpoint(endpoint) == {
        "input_price_per_million": "2.00",
        "cached_input_price_per_million": "0.20",
        "output_price_per_million": "8.00",
    }


def test_agent_session_freezes_llm_endpoint_revision():
    endpoint = {"id": 8, "revision": 12}

    assert agent_launch.validate_launch_endpoint_revision(endpoint, 12) is endpoint
    with pytest.raises(
        agent_launch.AgentLaunchValidationError,
        match="配置已变化",
    ):
        agent_launch.validate_launch_endpoint_revision(endpoint, 11)
    with pytest.raises(
        agent_launch.AgentLaunchValidationError,
        match="版本无效",
    ):
        agent_launch.validate_launch_endpoint_revision(endpoint, None)


def test_button_tasks_pin_their_skill_while_custom_sessions_follow_role():
    assert agent_launch.normalize_agent_task_kind("custom") == "custom"
    assert agent_launch.skill_for_agent_task("custom", "user") == "numoj-user"
    assert agent_launch.skill_for_agent_task("custom", "admin") == "numoj-admin"
    assert agent_launch.skill_for_agent_task("solve", "user") == "numoj-user"
    # user 仅用于恢复升级前已落库的造数据会话；新版按钮固定持久化 admin。
    assert agent_launch.skill_for_agent_task("testdata", "user") == "numoj-user"
    assert agent_launch.skill_for_agent_task("testdata", "admin") == "numoj-admin"

    with pytest.raises(
        agent_launch.AgentLaunchValidationError,
        match="只能使用 user",
    ):
        agent_launch.normalize_agent_access_role("admin", task_kind="solve")
