# -*- coding: utf-8 -*-

import pytest

from backend.oj_modules.site_config import services
from backend.oj_modules.db_services import get_db_connection, get_user_by_username
from backend.oj_modules.security.credentials import hash_password


def endpoint_payload(**overrides):
    payload = {
        "protocol": "openai",
        "category": "text",
        "base_url": "https://api.example.test/v1",
        "api_key": "db-secret-canary",
        "model": "model-a",
        "thinking_enabled": False,
        "thinking_format": "enable_thinking",
        "input_price_per_million": "0",
        "cached_input_price_per_million": "0",
        "output_price_per_million": "0",
    }
    payload.update(overrides)
    return payload


def create_endpoint(user_id, **overrides):
    payload = endpoint_payload(**overrides)
    tested = services.test_llm_endpoint(
        payload,
        user_id=user_id,
        tester=lambda _candidate: {
            "passed": True,
            "message": "连接成功",
            "latency_ms": 9,
        },
    )
    return services.save_llm_endpoint(
        payload,
        user_id=user_id,
        test_token=tested["test_token"],
    )


def test_llm_endpoint_two_phase_save_masks_secret_and_consumes_grant():
    admin = get_user_by_username("admin")
    payload = endpoint_payload()
    probe = services.test_llm_endpoint(
        payload,
        user_id=admin["id"],
        tester=lambda candidate: {
            "passed": candidate["api_key"] == "db-secret-canary",
            "message": "真实测试通过",
            "latency_ms": 14,
        },
    )

    endpoint = services.save_llm_endpoint(
        payload,
        user_id=admin["id"],
        test_token=probe["test_token"],
    )

    assert endpoint["api_key"] == ""
    assert endpoint["api_key_configured"] is True
    assert endpoint["test_status"] == "passed"
    assert services.get_llm_endpoint(endpoint["id"], include_secret=True)["api_key"] == (
        "db-secret-canary"
    )

    with pytest.raises(services.DynamicConfigTestFailedError):
        services.test_llm_endpoint(
            {**payload, "model": "unsaved-broken-model", "api_key": ""},
            endpoint_id=endpoint["id"],
            user_id=admin["id"],
            tester=lambda _candidate: False,
        )
    assert services.get_llm_endpoint(endpoint["id"])["test_status"] == "passed"

    with pytest.raises(services.DynamicConfigConflictError, match="已使用"):
        services.save_llm_endpoint(
            payload,
            user_id=admin["id"],
            test_token=probe["test_token"],
        )

    edit = {**payload, "model": "model-b", "api_key": ""}
    edit_probe = services.test_llm_endpoint(
        edit,
        endpoint_id=endpoint["id"],
        user_id=admin["id"],
        tester=lambda _candidate: True,
    )
    edited = services.save_llm_endpoint(
        edit,
        endpoint_id=endpoint["id"],
        user_id=admin["id"],
        test_token=edit_probe["test_token"],
    )
    assert edited["model"] == "model-b"
    assert services.get_llm_endpoint(endpoint["id"], include_secret=True)["api_key"] == (
        "db-secret-canary"
    )


def test_llm_endpoints_allow_the_same_model_on_distinct_connections():
    admin = get_user_by_username("admin")
    first = create_endpoint(
        admin["id"],
        model="shared-provider-model",
        base_url="https://region-a.example.test/v1",
    )
    second = create_endpoint(
        admin["id"],
        model="shared-provider-model",
        base_url="https://region-b.example.test/v1",
    )

    assert first["id"] != second["id"]
    assert first["model"] == second["model"] == "shared-provider-model"
    assert services.get_llm_endpoint(first["id"])["base_url"].endswith(
        "region-a.example.test/v1"
    )
    assert services.get_llm_endpoint(second["id"])["base_url"].endswith(
        "region-b.example.test/v1"
    )

    services.set_feature_binding(
        "ai_code_annotation", first["id"], user_id=admin["id"]
    )
    rebound = services.set_feature_binding(
        "ai_code_annotation", second["id"], user_id=admin["id"]
    )
    assert rebound["endpoint_id"] == second["id"]


def test_llm_endpoint_token_prices_round_trip_as_normalized_decimals():
    admin = get_user_by_username("admin")
    endpoint = create_endpoint(
        admin["id"],
        model="priced-model",
        input_price_per_million="2.5",
        cached_input_price_per_million="0.25",
        output_price_per_million="8.125",
    )

    assert endpoint["input_price_per_million"] == "2.5"
    assert endpoint["cached_input_price_per_million"] == "0.25"
    assert endpoint["output_price_per_million"] == "8.125"


def test_endpoint_lock_blocks_testing_and_only_locker_can_unlock():
    admin = get_user_by_username("admin")
    endpoint = create_endpoint(admin["id"])
    locked = services.lock_llm_endpoint(
        endpoint["id"], user_id=admin["id"], reason="生产稳定配置"
    )
    assert locked["can_unlock"] is True

    tester_called = False

    def tester(_candidate):
        nonlocal tester_called
        tester_called = True
        return True

    with pytest.raises(services.DynamicConfigLockedError):
        services.test_llm_endpoint(
            endpoint_payload(),
            endpoint_id=endpoint["id"],
            user_id=admin["id"],
            tester=tester,
        )
    assert tester_called is False

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, is_admin, email)
                VALUES ('other_admin', %s, 1, 'other@example.test')
                """,
                (hash_password("other-password"),),
            )
        conn.commit()
    finally:
        conn.close()
    other = get_user_by_username("other_admin")
    assert services.get_llm_endpoint(
        endpoint["id"], actor_user_id=other["id"]
    )["can_unlock"] is False
    other_view = services.get_llm_endpoint(
        endpoint["id"], actor_user_id=other["id"]
    )
    assert other_view["lock_reason"] == "生产稳定配置"
    with pytest.raises(services.DynamicConfigLockedError, match="执行锁定"):
        services.unlock_llm_endpoint(
            endpoint["id"],
            user=other,
            password="other-password",
            confirmation=services.UNLOCK_CONFIRMATION,
        )

    unlocked = services.unlock_llm_endpoint(
        endpoint["id"],
        user=admin,
        password="admin123",
        confirmation=services.UNLOCK_CONFIRMATION,
    )
    assert unlocked["is_locked"] is False


def test_failed_endpoint_can_be_bound_and_delete_preserves_dangling_id():
    admin = get_user_by_username("admin")
    endpoint = create_endpoint(admin["id"])
    with pytest.raises(services.DynamicConfigTestFailedError):
        services.test_llm_endpoint(
            endpoint_payload(),
            endpoint_id=endpoint["id"],
            user_id=admin["id"],
            tester=lambda _candidate: {"passed": False, "message": "暂时失败"},
        )

    binding = services.set_feature_binding(
        "ai_code_annotation", endpoint["id"], user_id=admin["id"]
    )
    assert binding["endpoint"]["test_status"] == "failed"
    assert services.resolve_feature_endpoint("ai_code_annotation")["id"] == endpoint["id"]

    services.delete_llm_endpoint(endpoint["id"])
    dangling = services.get_feature_binding("ai_code_annotation")
    assert dangling["endpoint_id"] == endpoint["id"]
    assert dangling["endpoint_missing"] is True
    with pytest.raises(
        services.DynamicConfigNotFoundError,
        match=rf"端点不存在（ID: {endpoint['id']}）",
    ):
        services.resolve_feature_endpoint("ai_code_annotation")


def test_embedding_empty_binding_has_explicit_lock_lifecycle():
    admin = get_user_by_username("admin")

    locked = services.lock_embedding_binding(
        user_id=admin["id"], reason="索引向量维度不可随意改变"
    )
    assert locked["endpoint_id"] is None
    assert locked["is_locked"] is True
    assert locked["can_unlock"] is True

    with pytest.raises(services.DynamicConfigLockedError):
        services.set_feature_binding(
            "repository_embedding", None, user_id=admin["id"]
        )

    unlocked = services.unlock_embedding_binding(
        user=admin,
        password="admin123",
        confirmation=services.UNLOCK_CONFIRMATION,
    )
    assert unlocked["is_locked"] is False
    saved = services.set_feature_binding(
        "repository_embedding", None, user_id=admin["id"]
    )
    assert saved["is_locked"] is False


def test_deleting_embedding_endpoint_keeps_locked_dangling_binding():
    admin = get_user_by_username("admin")
    endpoint = create_endpoint(
        admin["id"],
        model="embedding-model",
        category="embedding",
        thinking_enabled=False,
        thinking_format="none",
    )
    services.set_feature_binding(
        "repository_embedding", endpoint["id"], user_id=admin["id"]
    )
    services.lock_embedding_binding(
        user_id=admin["id"], reason="保持索引向量维度"
    )

    services.delete_llm_endpoint(endpoint["id"])

    binding = services.get_feature_binding(
        "repository_embedding", actor_user_id=admin["id"]
    )
    assert binding["endpoint_id"] == endpoint["id"]
    assert binding["endpoint_missing"] is True
    assert binding["is_locked"] is True
    assert binding["lock_reason"] == "保持索引向量维度"
    assert binding["can_unlock"] is True


def test_mail_and_web_search_can_save_without_prior_test_and_clear():
    admin = get_user_by_username("admin")
    mail = services.save_mail_settings(
        {
            "smtp_server": "smtp.example.test",
            "smtp_port": 465,
            "smtp_username": "mailer@example.test",
            "smtp_password": "mail-secret",
        },
        user_id=admin["id"],
    )
    assert mail["test_status"] == "untested"
    tested_candidate = {}
    result = services.test_mail_settings(
        {**mail, "smtp_password": ""},
        user_id=admin["id"],
        recipient_email=admin["email"],
        tester=lambda candidate: tested_candidate.update(candidate) or True,
    )
    assert result["passed"] is True
    assert tested_candidate["smtp_password"] == "mail-secret"
    assert tested_candidate["recipient_email"] == admin["email"]

    search = services.save_web_search_settings(
        {
            "base_url": "https://search.example.test/mcp",
            "authorization": "Bearer search-secret",
        },
        user_id=admin["id"],
    )
    assert search["authorization"] == ""
    assert search["test_status"] == "untested"

    services.clear_mail_settings()
    services.clear_web_search_settings()
    assert services.get_mail_settings() is None
    assert services.get_web_search_settings() is None
