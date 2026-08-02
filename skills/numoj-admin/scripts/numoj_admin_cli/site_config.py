from __future__ import annotations

import argparse
import getpass
from typing import Any, Dict, Optional

from . import common


API_ROOT = "/api/admin/dynamic-config"
LLM_PROTOCOLS = ("openai", "anthropic")
LLM_CATEGORIES = ("omni", "text", "vision", "embedding")
SENSITIVE_FIELDS = {"api_key", "smtp_password", "authorization", "password"}


def positive_id(raw: str) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("ID must be a positive integer") from exc
    if value <= 0 or str(value) != str(raw).strip():
        raise argparse.ArgumentTypeError("ID must be a positive integer")
    return value


def _safe_payload(value: Any) -> Any:
    """Defensively redact secrets even if a future server response echoes one."""
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, item in value.items():
            if key == "test_token":
                continue
            if key in SENSITIVE_FIELDS:
                result[key] = "********" if item else item
            else:
                result[key] = _safe_payload(item)
        return result
    if isinstance(value, list):
        return [_safe_payload(item) for item in value]
    return value


def _api_json(client: common.NumOJClient, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
    resp = client.request(method, f"{API_ROOT}{path}", **kwargs)
    try:
        common.ensure_ok(resp, allow_redirect=False)
    except common.CliHttpError as exc:
        raise common.CliHttpError(exc.status_code, _safe_payload(exc.payload)) from None
    if not common.response_is_json(resp):
        raise common.CliError("The server did not return the expected JSON response.")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise common.CliError("The server returned malformed JSON.") from exc
    common.raise_for_failure_payload(
        _safe_payload(payload),
        http_status=resp.status_code,
    )
    if not isinstance(payload, dict):
        raise common.CliError("The server returned an unexpected JSON value.")
    return payload


def _output(payload: Dict[str, Any]) -> None:
    common.output_json(_safe_payload(common.necessary_response_payload(payload)))


def _secret_from_args(
    args: argparse.Namespace,
    *,
    direct_attr: str,
    env_attr: str,
    label: str,
    required: bool = False,
) -> Optional[str]:
    direct = getattr(args, direct_attr, None)
    env_name = getattr(args, env_attr, None)
    if direct is not None:
        value = common.read_text_value(direct).strip()
        if not value:
            raise common.CliError(f"{label} cannot be empty.")
        return value
    if env_name is not None:
        return common.read_env_secret(env_name, getattr(args, "env_file", None))
    if required:
        raise common.CliError(
            f"{label} is required. Pass its direct option, @file, or environment-variable option."
        )
    return None


def _add_secret_args(
    parser: argparse.ArgumentParser,
    *,
    direct_option: str,
    direct_dest: str,
    env_option: str,
    env_dest: str,
    label: str,
    required: bool = False,
) -> None:
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument(
        direct_option,
        dest=direct_dest,
        help=f"{label} text, or @file to read it from a file.",
    )
    group.add_argument(
        env_option,
        dest=env_dest,
        help=f"Environment variable name holding {label}.",
    )
    parser.add_argument(
        "--env-file",
        help=f"Optional .env file used with {env_option}.",
    )


def _add_thinking_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--thinking",
        dest="thinking_enabled",
        action="store_true",
        default=None,
        help="Enable the protocol-compatible thinking request field.",
    )
    group.add_argument(
        "--no-thinking",
        dest="thinking_enabled",
        action="store_false",
        default=None,
        help="Do not send a thinking request field.",
    )


def _add_llm_candidate_args(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument(
        "--protocol",
        choices=LLM_PROTOCOLS,
        required=required,
        help="Endpoint compatibility protocol.",
    )
    parser.add_argument(
        "--category",
        choices=LLM_CATEGORIES,
        required=required,
        help="Endpoint capability category.",
    )
    parser.add_argument(
        "--endpoint-base-url",
        required=required,
        help="Model API SDK base URL.",
    )
    _add_secret_args(
        parser,
        direct_option="--api-key",
        direct_dest="api_key",
        env_option="--api-key-env",
        env_dest="api_key_env",
        label="API key",
        required=required,
    )
    parser.add_argument("--model", required=required, help="Model identifier and endpoint name.")
    _add_thinking_args(parser)


def _find_endpoint(client: common.NumOJClient, endpoint_id: int) -> Dict[str, Any]:
    payload = _api_json(client, "GET", "/llm-endpoints")
    for endpoint in payload.get("endpoints") or []:
        if isinstance(endpoint, dict) and int(endpoint.get("id") or 0) == endpoint_id:
            return endpoint
    raise common.CliError(f"LLM endpoint {endpoint_id} was not found.")


def _llm_payload(
    args: argparse.Namespace,
    *,
    client: Optional[common.NumOJClient] = None,
    endpoint_id: Optional[int] = None,
    required: bool = False,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for arg_name, field_name in (
        ("protocol", "protocol"),
        ("category", "category"),
        ("endpoint_base_url", "base_url"),
        ("model", "model"),
    ):
        value = getattr(args, arg_name, None)
        if value is not None:
            payload[field_name] = value
    if required:
        missing = [
            field_name
            for field_name in ("protocol", "category", "base_url", "model")
            if not str(payload.get(field_name) or "").strip()
        ]
        if missing:
            raise common.CliError(
                "A new LLM candidate requires: " + ", ".join(missing) + "."
            )
    api_key = _secret_from_args(
        args,
        direct_attr="api_key",
        env_attr="api_key_env",
        label="API key",
        required=required,
    )
    if api_key is not None:
        payload["api_key"] = api_key

    thinking_enabled = getattr(args, "thinking_enabled", None)
    existing_endpoint: Optional[Dict[str, Any]] = None
    if thinking_enabled is not None:
        payload["thinking_enabled"] = bool(thinking_enabled)
        if thinking_enabled:
            protocol = payload.get("protocol")
            if protocol is None and client is not None and endpoint_id is not None:
                existing_endpoint = _find_endpoint(client, endpoint_id)
                protocol = existing_endpoint.get("protocol")
            if protocol is None:
                raise common.CliError("--thinking requires --protocol for a new candidate.")
            payload["thinking_format"] = (
                "thinking_type" if protocol == "anthropic" else "enable_thinking"
            )
        else:
            payload["thinking_format"] = "none"
    elif "protocol" in payload and client is not None and endpoint_id is not None:
        # A protocol change must preserve the logical thinking switch while
        # translating its wire format to the newly selected protocol.
        existing_endpoint = existing_endpoint or _find_endpoint(client, endpoint_id)
        enabled = bool(existing_endpoint.get("thinking_enabled"))
        payload["thinking_enabled"] = enabled
        payload["thinking_format"] = (
            "thinking_type"
            if enabled and payload["protocol"] == "anthropic"
            else "enable_thinking"
            if enabled
            else "none"
        )
    return payload


def meta(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "GET", "/meta"))


def llm_list(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "GET", "/llm-endpoints"))


def llm_test(args: argparse.Namespace) -> None:
    client = common.client_from_args(args)
    endpoint_id = getattr(args, "endpoint_id", None)
    payload = _llm_payload(
        args,
        client=client,
        endpoint_id=endpoint_id,
        required=endpoint_id is None,
    )
    if endpoint_id is not None:
        payload["endpoint_id"] = endpoint_id
    result = _api_json(client, "POST", "/llm-endpoints/test", json=payload)
    _output(result)


def _llm_test_then_save(
    args: argparse.Namespace,
    *,
    endpoint_id: Optional[int],
) -> None:
    client = common.client_from_args(args)
    candidate = _llm_payload(
        args,
        client=client,
        endpoint_id=endpoint_id,
        required=endpoint_id is None,
    )
    test_payload = dict(candidate)
    if endpoint_id is not None:
        test_payload["endpoint_id"] = endpoint_id
    tested = _api_json(client, "POST", "/llm-endpoints/test", json=test_payload)
    test_token = str(tested.get("test_token") or "").strip()
    if not test_token:
        raise common.CliError("The connection test passed without returning a save token.")
    save_payload = {**candidate, "test_token": test_token}
    if endpoint_id is None:
        saved = _api_json(client, "POST", "/llm-endpoints", json=save_payload)
    else:
        saved = _api_json(
            client,
            "PUT",
            f"/llm-endpoints/{endpoint_id}",
            json=save_payload,
        )
    saved["test"] = tested.get("test")
    _output(saved)


def llm_create(args: argparse.Namespace) -> None:
    _llm_test_then_save(args, endpoint_id=None)


def llm_update(args: argparse.Namespace) -> None:
    _llm_test_then_save(args, endpoint_id=args.endpoint_id)


def llm_delete(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "DELETE",
            f"/llm-endpoints/{args.endpoint_id}",
        )
    )


def llm_lock(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            f"/llm-endpoints/{args.endpoint_id}/lock",
            json={"reason": common.read_text_value(args.reason).strip()},
        )
    )


def _unlock_password(args: argparse.Namespace) -> str:
    password = _secret_from_args(
        args,
        direct_attr="password",
        env_attr="password_env",
        label="Administrator password",
    )
    if password is None:
        password = getpass.getpass("Administrator password: ")
    if not password:
        raise common.CliError("Administrator password cannot be empty.")
    return password


def llm_unlock(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            f"/llm-endpoints/{args.endpoint_id}/unlock",
            json={
                "password": _unlock_password(args),
                "confirmation": common.read_text_value(args.confirmation).strip(),
            },
        )
    )


def binding_list(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "GET", "/feature-bindings"))


def binding_set(args: argparse.Namespace) -> None:
    endpoint_id = None if args.clear else args.endpoint_id
    _output(
        _api_json(
            common.client_from_args(args),
            "PUT",
            f"/feature-bindings/{args.feature_key}",
            json={"endpoint_id": endpoint_id},
        )
    )


def binding_lock_embedding(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            "/feature-bindings/repository_embedding/lock",
            json={"reason": common.read_text_value(args.reason).strip()},
        )
    )


def binding_unlock_embedding(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            "/feature-bindings/repository_embedding/unlock",
            json={
                "password": _unlock_password(args),
                "confirmation": common.read_text_value(args.confirmation).strip(),
            },
        )
    )


def _mail_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for key in ("smtp_server", "smtp_port", "smtp_username"):
        value = getattr(args, key, None)
        if value is not None:
            payload[key] = value
    password = _secret_from_args(
        args,
        direct_attr="smtp_password",
        env_attr="smtp_password_env",
        label="SMTP password",
    )
    if password is not None:
        payload["smtp_password"] = password
    return payload


def mail_get(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "GET", "/mail"))


def mail_test(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            "/mail/test",
            json=_mail_payload(args),
        )
    )


def mail_set(args: argparse.Namespace) -> None:
    payload = _mail_payload(args)
    if not payload:
        raise common.CliError("mail set requires at least one configuration option.")
    _output(_api_json(common.client_from_args(args), "PUT", "/mail", json=payload))


def mail_clear(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "DELETE", "/mail"))


def _web_search_payload(args: argparse.Namespace) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    if getattr(args, "search_base_url", None) is not None:
        payload["base_url"] = args.search_base_url
    authorization = _secret_from_args(
        args,
        direct_attr="authorization",
        env_attr="authorization_env",
        label="Authorization value",
    )
    if authorization is not None:
        payload["authorization"] = authorization
    return payload


def web_search_get(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "GET", "/web-search"))


def web_search_test(args: argparse.Namespace) -> None:
    _output(
        _api_json(
            common.client_from_args(args),
            "POST",
            "/web-search/test",
            json=_web_search_payload(args),
        )
    )


def web_search_set(args: argparse.Namespace) -> None:
    payload = _web_search_payload(args)
    if not payload:
        raise common.CliError("web-search set requires at least one configuration option.")
    _output(
        _api_json(
            common.client_from_args(args),
            "PUT",
            "/web-search",
            json=payload,
        )
    )


def web_search_clear(args: argparse.Namespace) -> None:
    _output(_api_json(common.client_from_args(args), "DELETE", "/web-search"))


def _add_unlock_args(parser: argparse.ArgumentParser) -> None:
    password = parser.add_mutually_exclusive_group()
    password.add_argument(
        "--password",
        help="Current administrator password, or @file; prompts when omitted.",
    )
    password.add_argument(
        "--password-env",
        help="Environment variable name holding the current administrator password.",
    )
    parser.add_argument("--env-file", help="Optional .env file used with --password-env.")
    parser.add_argument(
        "--confirmation",
        required=True,
        help="Exact unlock confirmation text returned by site-config meta, or @file.",
    )


def _register_llm(subparsers: argparse._SubParsersAction) -> None:
    parser = common.add_cli_parser(subparsers, "llm", "Manage the global LLM endpoint pool.")
    commands = parser.add_subparsers(dest="llm_cmd", required=True)

    command = common.add_cli_parser(commands, "list", "List global LLM endpoints.")
    command.set_defaults(func=llm_list)

    command = common.add_cli_parser(commands, "test", "Test a new candidate or an existing LLM endpoint.")
    command.add_argument("endpoint_id", nargs="?", type=positive_id, help="Existing endpoint ID; omit for a new candidate.")
    _add_llm_candidate_args(command, required=False)
    command.set_defaults(func=llm_test)

    command = common.add_cli_parser(commands, "create", "Test and create a global LLM endpoint.")
    _add_llm_candidate_args(command, required=True)
    command.set_defaults(func=llm_create)

    command = common.add_cli_parser(commands, "update", "Test and update a global LLM endpoint.")
    command.add_argument("endpoint_id", type=positive_id, help="Endpoint ID to update.")
    _add_llm_candidate_args(command, required=False)
    command.set_defaults(func=llm_update)

    command = common.add_cli_parser(commands, "delete", "Delete a global LLM endpoint.")
    command.add_argument("endpoint_id", type=positive_id, help="Endpoint ID to delete.")
    command.set_defaults(func=llm_delete)

    command = common.add_cli_parser(commands, "lock", "Lock a global LLM endpoint.")
    command.add_argument("endpoint_id", type=positive_id, help="Endpoint ID to lock.")
    command.add_argument("--reason", required=True, help="Lock reason text, or @file.")
    command.set_defaults(func=llm_lock)

    command = common.add_cli_parser(commands, "unlock", "Unlock a global LLM endpoint.")
    command.add_argument("endpoint_id", type=positive_id, help="Endpoint ID to unlock.")
    _add_unlock_args(command)
    command.set_defaults(func=llm_unlock)


def _register_binding(subparsers: argparse._SubParsersAction) -> None:
    parser = common.add_cli_parser(subparsers, "binding", "Manage global feature-to-endpoint bindings.")
    commands = parser.add_subparsers(dest="binding_cmd", required=True)

    command = common.add_cli_parser(commands, "list", "List global feature bindings.")
    command.set_defaults(func=binding_list)

    command = common.add_cli_parser(commands, "set", "Set or clear one global feature binding.")
    command.add_argument("feature_key", help="Feature key returned by site-config meta.")
    target = command.add_mutually_exclusive_group(required=True)
    target.add_argument("--endpoint-id", type=positive_id, help="Compatible global endpoint ID.")
    target.add_argument("--clear", action="store_true", help="Clear the selected binding.")
    command.set_defaults(func=binding_set)

    command = common.add_cli_parser(commands, "lock-embedding", "Lock the repository Embedding binding.")
    command.add_argument("--reason", required=True, help="Lock reason text, or @file.")
    command.set_defaults(func=binding_lock_embedding)

    command = common.add_cli_parser(commands, "unlock-embedding", "Unlock the repository Embedding binding.")
    _add_unlock_args(command)
    command.set_defaults(func=binding_unlock_embedding)


def _add_mail_values(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--smtp-server", help="SMTP server hostname.")
    parser.add_argument("--smtp-port", type=int, help="SMTP server port.")
    parser.add_argument("--smtp-username", help="SMTP username.")
    _add_secret_args(
        parser,
        direct_option="--smtp-password",
        direct_dest="smtp_password",
        env_option="--smtp-password-env",
        env_dest="smtp_password_env",
        label="SMTP password",
    )


def _register_mail(subparsers: argparse._SubParsersAction) -> None:
    parser = common.add_cli_parser(subparsers, "mail", "Manage global SMTP settings.")
    commands = parser.add_subparsers(dest="mail_cmd", required=True)
    command = common.add_cli_parser(commands, "get", "Get global SMTP settings.")
    command.set_defaults(func=mail_get)
    command = common.add_cli_parser(commands, "test", "Send a test message with candidate SMTP settings.")
    _add_mail_values(command)
    command.set_defaults(func=mail_test)
    command = common.add_cli_parser(commands, "set", "Save global SMTP settings.")
    _add_mail_values(command)
    command.set_defaults(func=mail_set)
    command = common.add_cli_parser(commands, "clear", "Clear global SMTP settings.")
    command.set_defaults(func=mail_clear)


def _add_web_search_values(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--search-base-url", help="WebSearch MCP SDK base URL.")
    _add_secret_args(
        parser,
        direct_option="--authorization",
        direct_dest="authorization",
        env_option="--authorization-env",
        env_dest="authorization_env",
        label="Authorization value",
    )


def _register_web_search(subparsers: argparse._SubParsersAction) -> None:
    parser = common.add_cli_parser(subparsers, "web-search", "Manage global WebSearch MCP settings.")
    commands = parser.add_subparsers(dest="web_search_cmd", required=True)
    command = common.add_cli_parser(commands, "get", "Get global WebSearch MCP settings.")
    command.set_defaults(func=web_search_get)
    command = common.add_cli_parser(commands, "test", "Test candidate WebSearch MCP settings.")
    _add_web_search_values(command)
    command.set_defaults(func=web_search_test)
    command = common.add_cli_parser(commands, "set", "Save global WebSearch MCP settings.")
    _add_web_search_values(command)
    command.set_defaults(func=web_search_set)
    command = common.add_cli_parser(commands, "clear", "Clear global WebSearch MCP settings.")
    command.set_defaults(func=web_search_clear)


def register(subparsers: argparse._SubParsersAction) -> None:
    parser = common.add_cli_parser(
        subparsers,
        "site-config",
        "Manage global LLM endpoints, feature bindings, mail, and WebSearch settings.",
    )
    commands = parser.add_subparsers(dest="site_config_cmd", required=True)
    command = common.add_cli_parser(commands, "meta", "Inspect site-config enums, features, and unlock phrases.")
    command.set_defaults(func=meta)
    _register_llm(commands)
    _register_binding(commands)
    _register_mail(commands)
    _register_web_search(commands)
