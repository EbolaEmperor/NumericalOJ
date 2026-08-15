from __future__ import annotations

from oj_modules.agents import user_endpoints


def test_agent_user_endpoint_schema_and_source_columns_are_declared():
    from scripts import init_db_schema

    specs = init_db_schema._load_schema_specs()
    endpoint = specs["agent_user_endpoints"]

    assert endpoint.columns["user_id"].lower() == "int not null"
    assert endpoint.columns["name"].lower() == "varchar(100) not null"
    assert endpoint.columns["api_key"].lower() == "text not null"
    assert "idx_agent_user_endpoints_user_model" in endpoint.indexes
    assert (
        specs["agent_sessions"].columns["endpoint_source"].lower()
        == "varchar(16) not null default 'global'"
    )
    assert (
        specs["agent_launch_preferences"].columns["endpoint_source"].lower()
        == "varchar(16) not null default 'global'"
    )
    assert (
        specs["llm_endpoints"].columns["input_price_per_million"].lower()
        == "decimal(20,8) not null"
    )


def test_personal_endpoint_normalization_forces_text_and_unmetered_prices():
    normalized = user_endpoints.normalize_user_agent_endpoint_payload({
        "protocol": "openai",
        "name": "私人节点",
        "base_url": "https://example.test/v1",
        "api_key": "secret",
        "model": "private-model",
        "thinking_enabled": False,
        "thinking_format": "none",
        "category": "embedding",
        "input_price_per_million": "999",
        "cached_input_price_per_million": "999",
        "output_price_per_million": "999",
    })

    assert normalized["category"] == "text"
    assert normalized["name"] == "私人节点"
    assert "input_price_per_million" not in normalized


def test_personal_endpoint_public_view_hides_secret_and_has_stable_ref():
    row = {
        "id": 8,
        "user_id": 4,
        "name": "我的 Claude",
        "protocol": "anthropic",
        "base_url": "https://example.test",
        "api_key": "secret",
        "model": "private-model",
        "thinking_enabled": 1,
        "thinking_format": "thinking_type",
        "revision": 3,
        "test_status": "passed",
    }

    public = user_endpoints._public_endpoint(row)
    private = user_endpoints._public_endpoint(row, include_secret=True)

    assert public["ref"] == "user:8"
    assert public["name"] == "我的 Claude"
    assert public["category"] == "text"
    assert public["metered"] is False
    assert public["api_key"] == ""
    assert public["api_key_configured"] is True
    assert private["api_key"] == "secret"
