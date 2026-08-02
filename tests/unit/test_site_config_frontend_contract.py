from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_site_config_has_exactly_three_internal_pages():
    template = (ROOT / "templates/admin/site_config.html").read_text(encoding="utf-8")

    assert template.count("data-config-tab=") == 3
    assert 'data-config-tab="endpoints"' in template
    assert 'data-config-tab="features"' in template
    assert 'data-config-tab="other"' in template
    assert "LLM 端点" in template
    assert "功能配置" in template
    assert "其他配置" in template
    assert ".env" not in template


def test_locked_cards_use_a_single_unlock_overlay_action():
    script = (ROOT / "static/app/site-config.js").read_text(encoding="utf-8")

    assert "site-config-lock-overlay" in script
    assert 'data-endpoint-action="unlock"' in script
    assert "data-feature-unlock" in script
    assert "data-unlock-reason" in script
    assert "你无法解锁" in (ROOT / "templates/admin/site_config.html").read_text(encoding="utf-8")


def test_endpoint_secrets_are_never_rendered_from_list_payload():
    script = (ROOT / "static/app/site-config.js").read_text(encoding="utf-8")

    # 卡片只读取“是否已配置”，不会拼入 endpoint.api_key。
    assert "endpoint.api_key_configured" in script
    assert "endpoint.api_key}" not in script
    assert "endpoint.api_key)" not in script
    assert "API Key 已配置" in script


def test_endpoint_save_is_gated_by_matching_test_token():
    script = (ROOT / "static/app/site-config.js").read_text(encoding="utf-8")

    assert "endpointFormFingerprint" in script
    assert "test_token" in script
    assert "字段已经变化，请重新测试连接" in script
    assert "[data-endpoint-save]').disabled = true" in script
