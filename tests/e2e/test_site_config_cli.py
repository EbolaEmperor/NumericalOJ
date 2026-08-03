# -*- coding: utf-8 -*-
"""通过 numoj-admin、真实 HTTP 路由和 MySQL 验证全站配置完整生命周期。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.e2e.conftest import (
    ADMIN_CLI,
    QUALITY_GATE_STUB_PORT,
    create_regular_user,
    dynamic_config_probe_requests,
    get_user_id,
)


LOCAL_LLM_BASE_URL = f"http://127.0.0.1:{QUALITY_GATE_STUB_PORT}/v1"
LOCAL_MCP_URL = f"http://127.0.0.1:{QUALITY_GATE_STUB_PORT}/mcp"
UPDATED_LOCAL_MCP_URL = f"http://localhost:{QUALITY_GATE_STUB_PORT}/mcp"


def _db_rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    from oj_modules.db_services import get_db_connection

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            return list(cursor.fetchall())
    finally:
        conn.close()


def _write_secret_env(tmp_path: Path, unique_suffix: str) -> tuple[Path, dict[str, str]]:
    secrets = {
        # 引号与反斜杠用于真实覆盖 CLI 的 JSON dotenv 反转义。
        "E2E_LLM_API_KEY": f'e2e-pass-llm-"quoted"-\\path-{unique_suffix}',
        "E2E_BAD_LLM_API_KEY": f"e2e-reject-llm-{unique_suffix}",
        "E2E_EMBEDDING_API_KEY": f"e2e-pass-embedding-{unique_suffix}",
        "E2E_SMTP_PASSWORD": f"e2e-pass-smtp-{unique_suffix}",
        "E2E_BAD_SMTP_PASSWORD": f"e2e-reject-smtp-{unique_suffix}",
        "E2E_WEB_AUTHORIZATION": f"Bearer e2e-pass-web-search-{unique_suffix}",
        "E2E_BAD_WEB_AUTHORIZATION": f"Bearer e2e-reject-web-search-{unique_suffix}",
        "E2E_ADMIN_PASSWORD": "admin123",
        "E2E_OTHER_ADMIN_PASSWORD": "pw123456",
    }
    env_file = tmp_path / "site-config-secrets.env"
    env_file.write_text(
        "".join(
            f"{name}={json.dumps(value, ensure_ascii=False)}\n"
            for name, value in secrets.items()
        ),
        encoding="utf-8",
    )
    env_file.chmod(0o600)
    return env_file, secrets


def _assert_no_secret_text(text: str, secrets: dict[str, str]) -> None:
    for secret in secrets.values():
        assert secret not in text


def _endpoint_by_id(endpoints: list[dict[str, Any]], endpoint_id: int) -> dict[str, Any]:
    return next(item for item in endpoints if int(item["id"]) == endpoint_id)


@pytest.mark.e2e
def test_site_config_cli_complete_lifecycle(cli, unique_suffix, tmp_path):
    """覆盖每个 site-config 叶命令及其核心成功、失败和所有权语义。"""

    assert cli.init_admin()["success"] is True
    env_file, secrets = _write_secret_env(tmp_path, unique_suffix)

    def cli_result(config: Path, *args: str, check: bool = True):
        result = cli.run(ADMIN_CLI, config, *args, check=check)
        assert result.returncode == (0 if check else 2)
        _assert_no_secret_text(result.stdout, secrets)
        _assert_no_secret_text(result.stderr, secrets)
        return result

    def cli_json(config: Path, *args: str, check: bool = True) -> dict[str, Any]:
        payload = cli_result(config, *args, check=check).json()
        _assert_no_secret_text(json.dumps(payload, ensure_ascii=False), secrets)
        if check:
            assert payload["success"] is True
        else:
            assert payload["success"] is False
            assert payload["message"]
        return payload

    def admin_json(*args: str, check: bool = True) -> dict[str, Any]:
        return cli_json(cli.admin_config, *args, check=check)

    meta = admin_json("site-config", "meta")
    assert meta["protocols"] == ["openai", "anthropic"]
    assert meta["categories"] == ["omni", "text", "vision", "embedding"]
    feature_specs = {item["key"]: item for item in meta["features"]}
    assert set(feature_specs) == {
        "ai_code_annotation",
        "code_image_analysis",
        "repository_structuring",
        "repository_embedding",
    }
    endpoint_confirmation = meta["unlock_confirmations"]["endpoint"]
    embedding_confirmation = meta["unlock_confirmations"]["embedding_binding"]
    assert endpoint_confirmation
    assert embedding_confirmation
    assert admin_json("site-config", "llm", "list")["endpoints"] == []

    # 新候选 test 不保存端点，但会签发由服务端持久化的单次测试凭证。
    probe_model = f"e2e-probe-{unique_suffix}"
    direct_probe = admin_json(
        "site-config",
        "llm",
        "test",
        "--protocol",
        "openai",
        "--category",
        "omni",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        probe_model,
        "--no-thinking",
    )
    assert direct_probe["test"]["passed"] is True
    assert "test_token" not in json.dumps(direct_probe, ensure_ascii=False)
    assert _db_rows("SELECT id FROM llm_endpoints WHERE model=%s", (probe_model,)) == []
    assert _db_rows(
        "SELECT id FROM dynamic_config_test_grants "
        "WHERE target_id IS NULL AND consumed_at IS NULL"
    )

    failed_model = f"e2e-failed-{unique_suffix}"
    failed_create = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "openai",
        "--category",
        "text",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_BAD_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        failed_model,
        check=False,
    )
    assert failed_create["http_status"] == 422
    assert _db_rows("SELECT id FROM llm_endpoints WHERE model=%s", (failed_model,)) == []

    text_model = f"e2e-text-{unique_suffix}"
    created_text = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "openai",
        "--category",
        "text",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        text_model,
        "--thinking",
    )
    text_endpoint = created_text["endpoint"]
    text_endpoint_id = int(text_endpoint["id"])
    assert created_text["test"]["passed"] is True
    assert text_endpoint["model"] == text_model
    assert text_endpoint["base_url"] == LOCAL_LLM_BASE_URL
    assert text_endpoint["thinking_enabled"] is True
    assert text_endpoint["thinking_format"] == "enable_thinking"
    assert text_endpoint["api_key_configured"] is True
    assert text_endpoint["api_key"] in ("", "********")
    assert _db_rows(
        "SELECT id FROM dynamic_config_test_grants "
        "WHERE target_id IS NULL AND consumed_at IS NOT NULL"
    )

    tested_existing = admin_json(
        "site-config", "llm", "test", str(text_endpoint_id)
    )
    assert tested_existing["test"]["passed"] is True
    assert "test_token" not in json.dumps(tested_existing, ensure_ascii=False)
    assert _db_rows(
        "SELECT id FROM dynamic_config_test_grants "
        "WHERE target_id=%s AND consumed_at IS NULL",
        (text_endpoint_id,),
    )

    # 编辑失败不得修改任何持久字段，也不能绕过连通性测试。
    before_failed_update = _db_rows(
        "SELECT protocol, category, base_url, model, revision "
        "FROM llm_endpoints WHERE id=%s",
        (text_endpoint_id,),
    )[0]
    failed_update_model = f"e2e-failed-update-{unique_suffix}"
    failed_update = admin_json(
        "site-config",
        "llm",
        "update",
        str(text_endpoint_id),
        "--api-key-env",
        "E2E_BAD_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        failed_update_model,
        check=False,
    )
    assert failed_update["http_status"] == 422
    assert _db_rows(
        "SELECT protocol, category, base_url, model, revision "
        "FROM llm_endpoints WHERE id=%s",
        (text_endpoint_id,),
    )[0] == before_failed_update

    anthropic_model = f"e2e-anthropic-{unique_suffix}"
    updated_text = admin_json(
        "site-config",
        "llm",
        "update",
        str(text_endpoint_id),
        "--protocol",
        "anthropic",
        "--model",
        anthropic_model,
        "--thinking",
    )["endpoint"]
    assert updated_text["protocol"] == "anthropic"
    assert updated_text["model"] == anthropic_model
    assert updated_text["thinking_enabled"] is True
    assert updated_text["thinking_format"] == "thinking_type"

    duplicate = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "openai",
        "--category",
        "text",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        anthropic_model,
        "--no-thinking",
        check=False,
    )
    assert duplicate["http_status"] == 409
    assert len(_db_rows("SELECT id FROM llm_endpoints WHERE model=%s", (anthropic_model,))) == 1

    omni_model = f"e2e-omni-{unique_suffix}"
    omni_endpoint = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "openai",
        "--category",
        "omni",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        omni_model,
        "--no-thinking",
    )["endpoint"]
    omni_endpoint_id = int(omni_endpoint["id"])

    vision_model = f"e2e-vision-{unique_suffix}"
    vision_endpoint = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "anthropic",
        "--category",
        "vision",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key-env",
        "E2E_LLM_API_KEY",
        "--env-file",
        str(env_file),
        "--model",
        vision_model,
        "--no-thinking",
    )["endpoint"]
    vision_endpoint_id = int(vision_endpoint["id"])

    embedding_key_file = tmp_path / "embedding-api-key.txt"
    embedding_key_file.write_text(secrets["E2E_EMBEDDING_API_KEY"], encoding="utf-8")
    embedding_model = f"e2e-embedding-{unique_suffix}"
    embedding_endpoint = admin_json(
        "site-config",
        "llm",
        "create",
        "--protocol",
        "openai",
        "--category",
        "embedding",
        "--endpoint-base-url",
        LOCAL_LLM_BASE_URL,
        "--api-key",
        f"@{embedding_key_file}",
        "--model",
        embedding_model,
        "--no-thinking",
    )["endpoint"]
    embedding_endpoint_id = int(embedding_endpoint["id"])
    assert embedding_endpoint["thinking_enabled"] is False
    assert embedding_endpoint["thinking_format"] == "none"

    endpoint_list = admin_json("site-config", "llm", "list")["endpoints"]
    assert {item["category"] for item in endpoint_list} == {
        "text",
        "omni",
        "vision",
        "embedding",
    }
    assert {int(item["id"]) for item in endpoint_list} == {
        text_endpoint_id,
        omni_endpoint_id,
        vision_endpoint_id,
        embedding_endpoint_id,
    }
    assert all(item["api_key"] in ("", "********") for item in endpoint_list)

    # 每个功能都经过 CLI 绑定；类别不兼容必须 fail-closed。
    incompatible = admin_json(
        "site-config",
        "binding",
        "set",
        "code_image_analysis",
        "--endpoint-id",
        str(text_endpoint_id),
        check=False,
    )
    assert incompatible["http_status"] == 400
    binding_targets = {
        key: (
            embedding_endpoint_id
            if key == "repository_embedding"
            else vision_endpoint_id
            if key == "code_image_analysis"
            else text_endpoint_id
        )
        for key in feature_specs
    }
    for feature_key, endpoint_id in binding_targets.items():
        binding = admin_json(
            "site-config",
            "binding",
            "set",
            feature_key,
            "--endpoint-id",
            str(endpoint_id),
        )["binding"]
        assert binding["endpoint_id"] == endpoint_id
    bindings = {
        item["feature_key"]: item
        for item in admin_json("site-config", "binding", "list")["bindings"]
    }
    assert set(bindings) == set(feature_specs)
    assert {key: item["endpoint_id"] for key, item in bindings.items()} == binding_targets

    # 创建第二位管理员，用真实 CLI Session 覆盖锁原因可见但不可解锁。
    other_admin_username = f"cli_site_config_admin_{unique_suffix}"
    other_admin_password = secrets["E2E_OTHER_ADMIN_PASSWORD"]
    create_regular_user(
        username=other_admin_username,
        password=other_admin_password,
    )
    other_admin_id = get_user_id(other_admin_username)
    assert admin_json("user", "grant-admin", str(other_admin_id))["is_admin"] is True
    other_admin_config = tmp_path / "other-admin.json"
    other_init = cli_json(
        other_admin_config,
        "init",
        "--base-url",
        cli.base_url,
        "-u",
        other_admin_username,
        "-p",
        other_admin_password,
    )
    assert other_init["username"] == other_admin_username

    embedding_reason_text = "e2e embedding dimension freeze"
    embedding_reason = tmp_path / "embedding-lock-reason.txt"
    embedding_reason.write_text(embedding_reason_text, encoding="utf-8")
    locked_binding = admin_json(
        "site-config",
        "binding",
        "lock-embedding",
        "--reason",
        f"@{embedding_reason}",
    )["binding"]
    assert locked_binding["is_locked"] is True
    assert locked_binding["can_unlock"] is True
    other_binding = next(
        item
        for item in cli_json(
            other_admin_config, "site-config", "binding", "list"
        )["bindings"]
        if item["feature_key"] == "repository_embedding"
    )
    assert other_binding["lock_reason"] == embedding_reason_text
    assert other_binding["can_unlock"] is False
    other_embedding_unlock = cli_json(
        other_admin_config,
        "site-config",
        "binding",
        "unlock-embedding",
        "--confirmation",
        embedding_confirmation,
        "--password-env",
        "E2E_OTHER_ADMIN_PASSWORD",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert other_embedding_unlock["http_status"] == 423
    blocked_embedding_change = admin_json(
        "site-config",
        "binding",
        "set",
        "repository_embedding",
        "--clear",
        check=False,
    )
    assert blocked_embedding_change["http_status"] == 423
    assert admin_json(
        "site-config",
        "binding",
        "unlock-embedding",
        "--confirmation",
        embedding_confirmation,
        "--password-env",
        "E2E_ADMIN_PASSWORD",
        "--env-file",
        str(env_file),
    )["binding"]["is_locked"] is False

    endpoint_reason_text = "e2e stable endpoint"
    endpoint_reason = tmp_path / "endpoint-lock-reason.txt"
    endpoint_reason.write_text(endpoint_reason_text, encoding="utf-8")
    locked_endpoint = admin_json(
        "site-config",
        "llm",
        "lock",
        str(text_endpoint_id),
        "--reason",
        f"@{endpoint_reason}",
    )["endpoint"]
    assert locked_endpoint["is_locked"] is True
    assert locked_endpoint["can_unlock"] is True
    other_endpoint = _endpoint_by_id(
        cli_json(other_admin_config, "site-config", "llm", "list")["endpoints"],
        text_endpoint_id,
    )
    assert other_endpoint["lock_reason"] == endpoint_reason_text
    assert other_endpoint["can_unlock"] is False

    for blocked_args in (
        ("site-config", "llm", "test", str(text_endpoint_id)),
        (
            "site-config",
            "llm",
            "update",
            str(text_endpoint_id),
            "--model",
            f"e2e-locked-update-{unique_suffix}",
        ),
        ("site-config", "llm", "delete", str(text_endpoint_id)),
    ):
        assert admin_json(*blocked_args, check=False)["http_status"] == 423

    wrong_confirmation = admin_json(
        "site-config",
        "llm",
        "unlock",
        str(text_endpoint_id),
        "--confirmation",
        "wrong confirmation",
        "--password-env",
        "E2E_ADMIN_PASSWORD",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert wrong_confirmation["http_status"] == 400
    wrong_password = admin_json(
        "site-config",
        "llm",
        "unlock",
        str(text_endpoint_id),
        "--confirmation",
        endpoint_confirmation,
        "--password",
        "wrong-password",
        check=False,
    )
    assert wrong_password["http_status"] == 400
    other_unlock = cli_json(
        other_admin_config,
        "site-config",
        "llm",
        "unlock",
        str(text_endpoint_id),
        "--confirmation",
        endpoint_confirmation,
        "--password-env",
        "E2E_OTHER_ADMIN_PASSWORD",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert other_unlock["http_status"] == 423
    assert admin_json(
        "site-config",
        "llm",
        "unlock",
        str(text_endpoint_id),
        "--confirmation",
        endpoint_confirmation,
        "--password-env",
        "E2E_ADMIN_PASSWORD",
        "--env-file",
        str(env_file),
    )["endpoint"]["is_locked"] is False

    # SMTP 只替代不可接受的外部邮件写入，其候选字段由 E2E tester 全量校验。
    assert admin_json("site-config", "mail", "get")["settings"] is None
    failed_mail = admin_json(
        "site-config",
        "mail",
        "test",
        "--smtp-server",
        "smtp.example.test",
        "--smtp-port",
        "465",
        "--smtp-username",
        "mailer@example.test",
        "--smtp-password-env",
        "E2E_BAD_SMTP_PASSWORD",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert failed_mail["http_status"] == 422
    assert admin_json("site-config", "mail", "get")["settings"] is None
    saved_mail = admin_json(
        "site-config",
        "mail",
        "set",
        "--smtp-server",
        "smtp.example.test",
        "--smtp-port",
        "465",
        "--smtp-username",
        "mailer@example.test",
        "--smtp-password-env",
        "E2E_SMTP_PASSWORD",
        "--env-file",
        str(env_file),
    )["settings"]
    assert saved_mail["smtp_server"] == "smtp.example.test"
    assert saved_mail["smtp_port"] == 465
    assert saved_mail["smtp_username"] == "mailer@example.test"
    assert saved_mail["smtp_password_configured"] is True
    assert saved_mail["smtp_password"] in ("", "********")
    assert saved_mail["test_status"] == "untested"
    assert admin_json("site-config", "mail", "test")["test"]["passed"] is True
    assert admin_json("site-config", "mail", "get")["settings"]["test_status"] == "passed"
    updated_mail = admin_json(
        "site-config", "mail", "set", "--smtp-server", "smtp-updated.example.test"
    )["settings"]
    assert updated_mail["smtp_server"] == "smtp-updated.example.test"
    assert updated_mail["smtp_port"] == 465
    assert updated_mail["smtp_username"] == "mailer@example.test"
    assert updated_mail["smtp_password_configured"] is True
    assert updated_mail["test_status"] == "untested"
    failed_mail_override = admin_json(
        "site-config",
        "mail",
        "test",
        "--smtp-password-env",
        "E2E_BAD_SMTP_PASSWORD",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert failed_mail_override["http_status"] == 422
    assert admin_json("site-config", "mail", "test")["test"]["passed"] is True
    assert admin_json("site-config", "mail", "clear")["success"] is True
    assert admin_json("site-config", "mail", "get")["settings"] is None

    # WebSearch 使用真实 MCP initialize 适配器访问本地 HTTP 桩。
    assert admin_json("site-config", "web-search", "get")["settings"] is None
    failed_search = admin_json(
        "site-config",
        "web-search",
        "test",
        "--search-base-url",
        LOCAL_MCP_URL,
        "--authorization-env",
        "E2E_BAD_WEB_AUTHORIZATION",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert failed_search["http_status"] == 422
    assert admin_json("site-config", "web-search", "get")["settings"] is None
    saved_search = admin_json(
        "site-config",
        "web-search",
        "set",
        "--search-base-url",
        LOCAL_MCP_URL,
        "--authorization-env",
        "E2E_WEB_AUTHORIZATION",
        "--env-file",
        str(env_file),
    )["settings"]
    assert saved_search["base_url"] == LOCAL_MCP_URL
    assert saved_search["authorization_configured"] is True
    assert saved_search["authorization"] in ("", "********")
    assert saved_search["test_status"] == "untested"
    assert admin_json("site-config", "web-search", "test")["test"]["passed"] is True
    assert admin_json(
        "site-config", "web-search", "get"
    )["settings"]["test_status"] == "passed"
    updated_search = admin_json(
        "site-config",
        "web-search",
        "set",
        "--search-base-url",
        UPDATED_LOCAL_MCP_URL,
    )["settings"]
    assert updated_search["base_url"] == UPDATED_LOCAL_MCP_URL
    assert updated_search["authorization_configured"] is True
    assert updated_search["test_status"] == "untested"
    failed_search_override = admin_json(
        "site-config",
        "web-search",
        "test",
        "--authorization-env",
        "E2E_BAD_WEB_AUTHORIZATION",
        "--env-file",
        str(env_file),
        check=False,
    )
    assert failed_search_override["http_status"] == 422
    assert admin_json("site-config", "web-search", "test")["test"]["passed"] is True
    assert admin_json("site-config", "web-search", "clear")["success"] is True
    assert admin_json("site-config", "web-search", "get")["settings"] is None

    # 请求记录证明 CLI 配置实际穿过通用协议适配层，而不是在 E2E 中被短路。
    probe_requests = dynamic_config_probe_requests()
    assert secrets["E2E_LLM_API_KEY"] not in json.dumps(probe_requests, ensure_ascii=False)
    assert secrets["E2E_WEB_AUTHORIZATION"] not in json.dumps(probe_requests, ensure_ascii=False)

    def request_for(kind: str, model: str | None = None) -> dict[str, Any]:
        return next(
            item
            for item in probe_requests
            if item["kind"] == kind
            and (model is None or item["payload"].get("model") == model)
        )

    openai_thinking_payload = request_for("openai_chat", text_model)["payload"]
    assert openai_thinking_payload["enable_thinking"] is True
    assert "thinking" not in openai_thinking_payload
    anthropic_thinking_payload = request_for(
        "anthropic_messages", anthropic_model
    )["payload"]
    assert anthropic_thinking_payload["thinking"] == {"type": "adaptive"}
    assert "enable_thinking" not in anthropic_thinking_payload
    omni_payload = request_for("openai_chat", omni_model)["payload"]
    assert "enable_thinking" not in omni_payload
    assert "thinking" not in omni_payload
    vision_payload = request_for("anthropic_messages", vision_model)["payload"]
    assert "thinking" not in vision_payload
    assert "enable_thinking" not in vision_payload
    embedding_payload = request_for("openai_embeddings", embedding_model)["payload"]
    assert embedding_payload["input"] == ["NumericalOJ endpoint connectivity probe"]
    mcp_payload = request_for("web_search_mcp")["payload"]
    assert mcp_payload["jsonrpc"] == "2.0"
    assert mcp_payload["method"] == "initialize"

    # 允许直接删除被引用端点：绑定保留悬空 ID，由管理员自行清理。
    for endpoint_id in (
        text_endpoint_id,
        omni_endpoint_id,
        vision_endpoint_id,
        embedding_endpoint_id,
    ):
        assert admin_json(
            "site-config", "llm", "delete", str(endpoint_id)
        )["success"] is True
    dangling = {
        item["feature_key"]: item
        for item in admin_json("site-config", "binding", "list")["bindings"]
    }
    assert dangling["ai_code_annotation"]["endpoint_id"] == text_endpoint_id
    assert dangling["ai_code_annotation"]["endpoint_missing"] is True
    assert dangling["repository_embedding"]["endpoint_id"] == embedding_endpoint_id
    assert dangling["repository_embedding"]["endpoint_missing"] is True
    for feature_key in feature_specs:
        cleared = admin_json(
            "site-config", "binding", "set", feature_key, "--clear"
        )["binding"]
        assert cleared["endpoint_id"] is None
    assert admin_json("site-config", "llm", "list")["endpoints"] == []

    non_admin_username = f"cli_site_config_non_admin_{unique_suffix}"
    create_regular_user(username=non_admin_username, password="pw123456")
    assert cli.init_user(non_admin_username)["success"] is True
    forbidden = cli.run(
        ADMIN_CLI,
        cli.user_config,
        "site-config",
        "meta",
        check=False,
    )
    assert forbidden.returncode == 2
    forbidden_payload = forbidden.json()
    assert forbidden_payload["success"] is False
    assert forbidden_payload["http_status"] == 403
    assert forbidden_payload["message"]
    _assert_no_secret_text(forbidden.stdout + forbidden.stderr, secrets)
