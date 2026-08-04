# -*- coding: utf-8 -*-

import pytest
from decimal import Decimal

from oj_modules.site_config import services


def llm_payload(**overrides):
    payload = {
        "protocol": "openai",
        "category": "text",
        "base_url": "https://api.example.test/v1",
        "api_key": "secret-canary",
        "model": "model-a",
        "thinking_enabled": False,
        "thinking_format": "enable_thinking",
    }
    payload.update(overrides)
    return payload


def test_llm_normalization_preserves_disabled_wire_format():
    normalized = services.normalize_llm_endpoint_payload(llm_payload())

    assert "name" not in normalized
    assert normalized["model"] == "model-a"
    assert normalized["thinking_enabled"] is False
    assert normalized["thinking_format"] == "enable_thinking"


def test_llm_normalization_requires_provider_model_identifier():
    with pytest.raises(services.DynamicConfigValidationError, match="模型"):
        services.normalize_llm_endpoint_payload(llm_payload(model=""))


def test_llm_normalization_uses_internal_anthropic_machine_value():
    normalized = services.normalize_llm_endpoint_payload(
        llm_payload(
            protocol="anthropic",
            thinking_enabled=False,
            thinking_format="enable_thinking",
        )
    )

    assert normalized["thinking_enabled"] is False
    assert normalized["thinking_format"] == "thinking_type"

    explicitly_disabled = services.normalize_llm_endpoint_payload(
        llm_payload(
            protocol="anthropic",
            thinking_enabled=True,
            thinking_format="none",
        )
    )
    assert explicitly_disabled["thinking_format"] == "none"
    assert explicitly_disabled["thinking_enabled"] is False

    default_enabled = llm_payload(protocol="anthropic", thinking_enabled=True)
    default_enabled.pop("thinking_format")
    normalized_default = services.normalize_llm_endpoint_payload(default_enabled)
    assert normalized_default["thinking_format"] == "thinking_type"
    assert normalized_default["thinking_enabled"] is True


def test_embedding_normalization_clears_thinking():
    normalized = services.normalize_llm_endpoint_payload(
        llm_payload(
            category="embedding",
            thinking_enabled=True,
            thinking_format="thinking_type",
        )
    )

    assert normalized["thinking_enabled"] is False
    assert normalized["thinking_format"] == "none"


def test_llm_prices_are_optional_but_atomic_and_decimal_safe():
    blank = services.normalize_llm_endpoint_payload(llm_payload())
    assert blank["input_price_per_million"] is None
    assert blank["cached_input_price_per_million"] is None
    assert blank["output_price_per_million"] is None

    priced = services.normalize_llm_endpoint_payload(llm_payload(
        input_price_per_million="2.50",
        cached_input_price_per_million="0.25",
        output_price_per_million="8.125",
    ))
    assert priced["input_price_per_million"] == "2.50"
    assert priced["cached_input_price_per_million"] == "0.25"
    assert priced["output_price_per_million"] == "8.125"

    free = services.normalize_llm_endpoint_payload(llm_payload(
        input_price_per_million=0,
        cached_input_price_per_million=0,
        output_price_per_million=0,
    ))
    assert free["input_price_per_million"] == "0"

    with pytest.raises(services.DynamicConfigValidationError, match="全部填写"):
        services.normalize_llm_endpoint_payload(llm_payload(
            input_price_per_million="2.5",
        ))
    with pytest.raises(services.DynamicConfigValidationError, match="非负数字"):
        services.normalize_llm_endpoint_payload(llm_payload(
            input_price_per_million="-1",
            cached_input_price_per_million="0.2",
            output_price_per_million="8",
        ))

    public = services._public_endpoint({
        **llm_payload(),
        "input_price_per_million": Decimal("2.50000000"),
        "cached_input_price_per_million": Decimal("0.25000000"),
        "output_price_per_million": Decimal("8.12500000"),
    })
    assert public["input_price_per_million"] == "2.50000000"


@pytest.mark.parametrize(
    "base_url",
    [
        "api.example.test/v1",
        "ftp://api.example.test/v1",
        "https://user:password@api.example.test/v1",
        "https://api.example.test/v1?tenant=1",
        "https://api.example.test/v1#fragment",
        "https://api.example.test/v1/chat/completions",
        "https://api.example.test/v1/messages",
        "https://api.example.test/v1/embeddings",
        "https://api.example.test/v1/responses",
    ],
)
def test_llm_normalization_rejects_non_sdk_base_url(base_url):
    with pytest.raises(services.DynamicConfigValidationError):
        services.normalize_llm_endpoint_payload(llm_payload(base_url=base_url))


def test_tester_normalization_masks_candidate_secrets():
    result = services.run_dynamic_config_tester(
        lambda candidate: {
            "passed": False,
            "message": f"remote echoed {candidate['api_key']}",
            "latency_ms": "12",
        },
        llm_payload(),
    )

    assert result == {
        "passed": False,
        "status": "failed",
        "message": "remote echoed [已脱敏]",
        "latency_ms": 12,
    }


def test_public_endpoint_unlock_permission_belongs_only_to_locker():
    row = {
        **llm_payload(),
        "id": 8,
        "is_locked": 1,
        "locked_by_user_id": 7,
    }

    locker_view = services._public_endpoint(row, actor_user_id=7)
    other_admin_view = services._public_endpoint(row, actor_user_id=9)

    assert locker_view["can_unlock"] is True
    assert other_admin_view["can_unlock"] is False
    assert "name" not in locker_view
    assert locker_view["api_key"] == ""
    assert locker_view["api_key_configured"] is True


def test_mail_and_search_edit_can_preserve_existing_secret():
    mail = services.normalize_mail_settings_payload(
        {
            "smtp_server": "smtp.new.test",
            "smtp_port": 465,
            "smtp_username": "mailer",
            "smtp_password": "",
        },
        existing={"smtp_password": "old-mail-secret"},
    )
    search = services.normalize_web_search_settings_payload(
        {"base_url": "https://search.new.test/mcp", "authorization": ""},
        existing={"authorization": "Bearer old-search-secret"},
    )

    assert mail["smtp_password"] == "old-mail-secret"
    assert search["authorization"] == "Bearer old-search-secret"


def test_meta_has_exact_confirmation_and_feature_machine_values():
    meta = services.get_dynamic_config_meta()

    assert meta["protocols"] == ["openai", "anthropic"]
    assert meta["categories"] == ["omni", "text", "vision", "embedding"]
    assert meta["thinking_formats"] == [
        "enable_thinking",
        "thinking_type",
        "none",
    ]
    assert set(meta["unlock_confirmations"].values()) == {
        "我已阅读上述内容，我清楚后果，我坚持要解锁"
    }
    embedding = next(
        feature
        for feature in meta["features"]
        if feature["key"] == "repository_embedding"
    )
    assert embedding["allowed_categories"] == ["embedding"]
    assert embedding["lockable"] is True
    labels = {feature["key"]: feature["label"] for feature in meta["features"]}
    assert set(labels) == {
        "ai_code_annotation",
        "code_image_analysis",
        "repository_structuring",
        "repository_embedding",
    }
    assert labels["ai_code_annotation"] == "AI 代码标注"
    assert labels["repository_structuring"] == "仓库结构化"
    assert labels["repository_embedding"] == "Embedding"


def test_list_endpoints_has_no_filter_query(monkeypatch):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql):
            calls.append(sql)

        def fetchall(self):
            return []

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            return None

    monkeypatch.setattr(services, "get_db_connection", lambda: Connection())

    assert services.list_llm_endpoints() == []
    assert calls == ["SELECT * FROM llm_endpoints ORDER BY model ASC, id ASC"]
