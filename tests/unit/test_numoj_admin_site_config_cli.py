from __future__ import annotations

import importlib.util
import json
from argparse import Namespace
from pathlib import Path

import pytest


def _load_cli():
    root = Path(__file__).resolve().parents[2]
    path = root / "skills" / "numoj-admin" / "scripts" / "numoj_admin.py"
    spec = importlib.util.spec_from_file_location("numoj_admin_site_config_cli", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _Response:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.headers = {"Content-Type": "application/json"}
        self.text = json.dumps(payload, ensure_ascii=False)
        self.content = self.text.encode()

    def json(self):
        return self.payload


class _Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        return self.responses.pop(0)


def _llm_args(**overrides):
    values = {
        "protocol": "openai",
        "category": "text",
        "endpoint_base_url": "https://llm.example.com/v1",
        "api_key": "very-secret-key",
        "api_key_env": None,
        "env_file": None,
        "model": "example-model",
        "context_window_tokens": None,
        "max_output_tokens": None,
        "thinking_enabled": True,
        "input_price_per_million": "1",
        "cached_input_price_per_million": "0.1",
        "output_price_per_million": "4",
        "peak_pricing_enabled": None,
        "peak_time_ranges": None,
        "peak_input_price_per_million": None,
        "peak_cached_input_price_per_million": None,
        "peak_output_price_per_million": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_llm_create_tests_then_saves_without_printing_secrets(monkeypatch, capsys):
    cli = _load_cli()
    client = _Client(
        _Response({
            "success": True,
            "test": {
                "passed": True,
                "context_window_tokens": 128_000,
                "max_output_tokens": 16_000,
            },
            "test_token": "one-time-token",
            "api_key": "very-secret-key",
        }),
        _Response({
            "success": True,
            "endpoint": {"id": 7, "model": "example-model", "api_key": "very-secret-key"},
        }, 201),
    )
    monkeypatch.setattr(cli.site_config.common, "client_from_args", lambda _args: client)

    cli.site_config.llm_create(_llm_args(
        context_window_tokens=256_000,
        max_output_tokens=12_000,
    ))

    assert [request[:2] for request in client.requests] == [
        ("POST", "/api/admin/dynamic-config/llm-endpoints/test"),
        ("POST", "/api/admin/dynamic-config/llm-endpoints"),
    ]
    assert client.requests[0][2]["json"]["api_key"] == "very-secret-key"
    assert client.requests[0][2]["json"]["context_window_tokens"] == 256_000
    assert client.requests[0][2]["json"]["max_output_tokens"] == 12_000
    assert client.requests[1][2]["json"]["test_token"] == "one-time-token"
    assert client.requests[1][2]["json"]["context_window_tokens"] == 128_000
    assert client.requests[1][2]["json"]["max_output_tokens"] == 16_000
    stdout = capsys.readouterr().out
    assert "very-secret-key" not in stdout
    assert "one-time-token" not in stdout
    assert json.loads(stdout)["endpoint"]["api_key"] == "********"


def test_llm_protocol_update_preserves_thinking_with_new_wire_format(monkeypatch, capsys):
    cli = _load_cli()
    client = _Client(
        _Response({
            "success": True,
            "endpoints": [{"id": 7, "protocol": "openai", "thinking_enabled": True}],
        }),
        _Response({"success": True, "test": {"passed": True}, "test_token": "token"}),
        _Response({"success": True, "endpoint": {"id": 7, "protocol": "anthropic"}}),
    )
    monkeypatch.setattr(cli.site_config.common, "client_from_args", lambda _args: client)
    args = _llm_args(
        endpoint_id=7,
        protocol="anthropic",
        category=None,
        endpoint_base_url=None,
        api_key=None,
        model=None,
        thinking_enabled=None,
    )

    cli.site_config.llm_update(args)

    tested = client.requests[1][2]["json"]
    saved = client.requests[2][2]["json"]
    assert tested["thinking_enabled"] is True
    assert tested["thinking_format"] == "thinking_type"
    assert saved["thinking_enabled"] is True
    assert saved["thinking_format"] == "thinking_type"
    capsys.readouterr()


def test_llm_update_sends_optional_token_prices_through_test_and_save(monkeypatch, capsys):
    cli = _load_cli()
    client = _Client(
        _Response({"success": True, "test": {"passed": True}, "test_token": "token"}),
        _Response({"success": True, "endpoint": {"id": 7}}),
    )
    monkeypatch.setattr(cli.site_config.common, "client_from_args", lambda _args: client)
    args = _llm_args(
        endpoint_id=7,
        protocol=None,
        category=None,
        endpoint_base_url=None,
        api_key=None,
        model=None,
        thinking_enabled=None,
        input_price_per_million="1",
        cached_input_price_per_million="0.02",
        output_price_per_million="2",
    )

    cli.site_config.llm_update(args)

    expected = {
        "input_price_per_million": "1",
        "cached_input_price_per_million": "0.02",
        "output_price_per_million": "2",
    }
    assert client.requests[0][2]["json"] == {"endpoint_id": 7, **expected}
    assert client.requests[1][2]["json"] == {"test_token": "token", **expected}
    capsys.readouterr()


def test_llm_create_can_enable_peak_pricing_and_sends_all_peak_fields(monkeypatch, capsys):
    cli = _load_cli()
    client = _Client(
        _Response({"success": True, "test": {"passed": True}, "test_token": "token"}),
        _Response({"success": True, "endpoint": {"id": 7}}),
    )
    monkeypatch.setattr(cli.site_config.common, "client_from_args", lambda _args: client)

    cli.site_config.llm_create(_llm_args(
        peak_pricing_enabled=True,
        peak_time_ranges="9:00-12:00, 14:00-18:00",
        peak_input_price_per_million="2",
        peak_cached_input_price_per_million="0.2",
        peak_output_price_per_million="8",
    ))

    expected = {
        "peak_pricing_enabled": True,
        "peak_time_ranges": "9:00-12:00, 14:00-18:00",
        "peak_input_price_per_million": "2",
        "peak_cached_input_price_per_million": "0.2",
        "peak_output_price_per_million": "8",
    }
    assert all(expected.items() <= request[2]["json"].items() for request in client.requests)
    capsys.readouterr()


def test_failed_site_config_response_is_redacted_before_cli_error():
    cli = _load_cli()
    client = _Client(_Response({"success": False, "message": "denied", "api_key": "secret"}, 422))

    with pytest.raises(cli.common.CliHttpError) as raised:
        cli.site_config._api_json(client, "GET", "/llm-endpoints")

    assert raised.value.payload["api_key"] == "********"
    assert "secret" not in str(raised.value)


def test_site_config_secret_can_be_read_from_dotenv(monkeypatch, tmp_path):
    cli = _load_cli()
    env_file = tmp_path / "site-config.env"
    env_file.write_text("NUMOJ_KEY=dotenv-secret\n", encoding="utf-8")
    args = _llm_args(api_key=None, api_key_env="NUMOJ_KEY", env_file=str(env_file))

    payload = cli.site_config._llm_payload(args, required=True)

    assert payload["api_key"] == "dotenv-secret"


def test_site_config_dotenv_json_string_preserves_quotes_and_backslashes(tmp_path):
    cli = _load_cli()
    env_file = tmp_path / "site-config.env"
    expected = 'secret-with-"quote"-and-\\path'
    env_file.write_text(
        f"NUMOJ_KEY={json.dumps(expected)}\n",
        encoding="utf-8",
    )

    assert cli.common.read_env_secret("NUMOJ_KEY", str(env_file)) == expected


def test_site_config_dotenv_rejects_invalid_json_string(tmp_path):
    cli = _load_cli()
    env_file = tmp_path / "site-config.env"
    env_file.write_text('NUMOJ_KEY="unterminated\n', encoding="utf-8")

    with pytest.raises(cli.common.CliError, match="Invalid JSON string"):
        cli.common.read_env_secret("NUMOJ_KEY", str(env_file))


def test_llm_new_candidate_requires_all_non_secret_fields():
    cli = _load_cli()
    args = _llm_args(model=None)

    with pytest.raises(cli.common.CliError, match="model"):
        cli.site_config._llm_payload(args, required=True)
