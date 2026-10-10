import io
import json
import traceback

import pytest

from backend.oj_modules.ai import endpoints as adapter


class FakeResponse:
    def __init__(self, payload=None, *, status_code=200, content_type="application/json", lines=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self._lines = list(lines or [])
        self.closed = False

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def iter_lines(self, decode_unicode=False):
        del decode_unicode
        yield from self._lines

    def close(self):
        self.closed = True


def endpoint(
    *,
    protocol="openai",
    category="text",
    thinking_enabled=False,
    thinking_format="none",
    api_key="sk-super-secret",
    base_url=None,
    context_window_tokens=384_000,
    max_output_tokens=32_000,
):
    if base_url is None:
        base_url = (
            "https://llm.example.test/v1"
            if protocol == "openai"
            else "https://llm.example.test/anthropic"
        )
    return adapter.LLMEndpointSnapshot(
        id=7,
        category=category,
        protocol=protocol,
        base_url=base_url,
        api_key=api_key,
        model="model-id",
        thinking_enabled=thinking_enabled,
        thinking_format=thinking_format,
        context_window_tokens=context_window_tokens,
        max_output_tokens=max_output_tokens,
    )


def install_post(monkeypatch, response):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(adapter.requests, "post", fake_post)
    return calls


def install_get(monkeypatch, response):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return response

    monkeypatch.setattr(adapter.requests, "get", fake_get)
    return calls


def test_endpoint_snapshot_is_immutable_normalized_and_secret_safe():
    snapshot = adapter.LLMEndpointSnapshot.from_mapping({
        "endpoint_id": "9",
        "category": "TEXT",
        "protocol": "OPENAI",
        "base_url": "https://api.example.test/root/v1/",
        "api_key": "  secret-canary  ",
        "model": "  model-a  ",
        "thinking_enabled": "true",
        "thinking_wire_format": "enable_thinking",
    })

    assert snapshot.id == 9
    assert snapshot.category is adapter.LLMEndpointCategory.TEXT
    assert snapshot.protocol is adapter.LLMProtocol.OPENAI
    assert snapshot.base_url == "https://api.example.test/root/v1"
    assert snapshot.model == "model-a"
    assert snapshot.thinking_enabled is True
    assert snapshot.openai_thinking_format is adapter.OpenAIThinkingWireFormat.ENABLE_THINKING
    assert snapshot.context_window_tokens == 384_000
    assert snapshot.max_output_tokens == 32_000
    assert "secret-canary" not in repr(snapshot)
    assert "api_key" not in snapshot.to_public_dict()
    assert "name" not in snapshot.to_public_dict()
    assert snapshot.to_public_dict()["has_api_key"] is True
    assert snapshot.to_public_dict()["thinking_format"] == "enable_thinking"
    with pytest.raises(AttributeError):
        snapshot.model = "changed"


@pytest.mark.parametrize(
    "base_url",
    [
        "api.example.test/v1",
        "ftp://api.example.test/v1",
        "https://user:password@api.example.test/v1",
    ],
)
def test_endpoint_rejects_invalid_base_urls(base_url):
    with pytest.raises(adapter.LLMEndpointValidationError):
        endpoint(base_url=base_url)


def test_embedding_endpoint_normalizes_thinking_and_rejects_anthropic():
    snapshot = endpoint(
        category="embedding",
        thinking_enabled=True,
        thinking_format="enable_thinking",
    )
    assert snapshot.thinking_enabled is False
    assert snapshot.openai_thinking_format is adapter.OpenAIThinkingWireFormat.NONE

    with pytest.raises(adapter.LLMEndpointValidationError, match="Embedding"):
        endpoint(protocol="anthropic", category="embedding")


def test_standard_url_joining():
    openai = endpoint(base_url="https://api.example.test/tenant/v1/")
    anthropic = endpoint(
        protocol="anthropic",
        base_url="https://api.example.test/apps/anthropic/",
    )
    anthropic_with_v1 = endpoint(
        protocol="anthropic",
        base_url="https://api.example.test/apps/anthropic/v1",
    )
    embedding = endpoint(category="embedding")

    assert adapter.endpoint_request_url(openai) == (
        "https://api.example.test/tenant/v1/chat/completions"
    )
    assert adapter.endpoint_request_url(anthropic) == (
        "https://api.example.test/apps/anthropic/v1/messages"
    )
    assert adapter.endpoint_request_url(anthropic_with_v1) == (
        "https://api.example.test/apps/anthropic/v1/messages"
    )
    assert adapter.endpoint_request_url(embedding, "embedding") == (
        "https://llm.example.test/v1/embeddings"
    )


def test_base_url_query_is_preserved_after_request_path_joining():
    snapshot = endpoint(
        base_url="https://api.example.test/tenant/v1/?api-version=2026-08-01"
    )

    assert snapshot.base_url == (
        "https://api.example.test/tenant/v1?api-version=2026-08-01"
    )
    assert adapter.endpoint_request_url(snapshot) == (
        "https://api.example.test/tenant/v1/chat/completions"
        "?api-version=2026-08-01"
    )


def test_base_url_drops_fragment_without_guessing_provider_path_semantics():
    snapshot = endpoint(
        base_url="https://api.example.test/tenant/messages#dashboard"
    )

    assert snapshot.base_url == "https://api.example.test/tenant/messages"


@pytest.mark.parametrize(
    ("wire_format", "thinking_enabled", "expected"),
    [
        ("enable_thinking", True, {"enable_thinking": True}),
        ("enable_thinking", False, {"enable_thinking": False}),
        ("thinking.type", True, {"enable_thinking": True}),
        ("thinking.type", False, {}),
        ("none", True, {}),
    ],
)
def test_openai_thinking_wire_formats(monkeypatch, wire_format, thinking_enabled, expected):
    response = FakeResponse({
        "model": "model-id",
        "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    })
    calls = install_post(monkeypatch, response)
    snapshot = endpoint(
        thinking_enabled=thinking_enabled,
        thinking_format=wire_format,
    )

    result = adapter.call_text(snapshot, "hello")

    assert result.text == "OK"
    url, kwargs = calls[0]
    assert url.endswith("/v1/chat/completions")
    assert kwargs["headers"] == {
        "Authorization": "Bearer sk-super-secret",
        "Content-Type": "application/json",
    }
    payload = kwargs["json"]
    for key in ("enable_thinking", "thinking"):
        if key in expected:
            assert payload[key] == expected[key]
        else:
            assert key not in payload
    serialized = json.dumps(payload)
    assert "effort" not in serialized
    assert "budget" not in serialized


def test_thinking_type_accepts_db_and_wire_spelling():
    from_db = endpoint(thinking_format="thinking_type", thinking_enabled=True)
    from_wire_name = endpoint(thinking_format="thinking.type", thinking_enabled=True)

    assert from_db.thinking_format is adapter.OpenAIThinkingWireFormat.THINKING_TYPE
    assert from_wire_name.thinking_format is adapter.OpenAIThinkingWireFormat.THINKING_TYPE
    assert from_wire_name.to_public_dict()["thinking_format"] == "thinking_type"


def test_openai_response_normalizes_content_reasoning_tools_and_usage(monkeypatch):
    response = FakeResponse({
        "model": "returned-model",
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "content": [
                    {"type": "text", "text": "先查询"},
                    {"type": "text", "text": "工具"},
                ],
                "reasoning_content": "内部思考",
                "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"x\":1}"},
                }],
            },
        }],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
    })
    install_post(monkeypatch, response)

    result = adapter.call_chat(endpoint(), [{"role": "user", "content": "go"}])

    assert result.text == "先查询工具"
    assert result.reasoning == "内部思考"
    assert result.finish_reason == "tool_calls"
    assert result.model == "returned-model"
    assert result.usage == adapter.LLMUsage(10, 4, 14)
    assert result.tool_calls == (adapter.LLMToolCall("call-1", "lookup", '{"x":1}'),)
    assert result.to_openai_message()["tool_calls"][0]["function"]["name"] == "lookup"


def test_anthropic_auth_thinking_message_and_tool_translation(monkeypatch):
    response = FakeResponse({
        "model": "returned-model",
        "stop_reason": "tool_use",
        "content": [
            {"type": "thinking", "thinking": "内部思考", "signature": ""},
            {"type": "text", "text": "调用工具"},
            {"type": "tool_use", "id": "next-call", "name": "lookup", "input": {"x": 2}},
        ],
        "usage": {"input_tokens": 12, "output_tokens": 7},
    })
    calls = install_post(monkeypatch, response)
    snapshot = endpoint(
        protocol="anthropic",
        thinking_enabled=False,
        thinking_format="thinking_type",
    )
    tools = [{
        "type": "function",
        "function": {
            "name": "lookup",
            "description": "Lookup a number",
            "parameters": {
                "type": "object",
                "properties": {"x": {"type": "integer"}},
                "required": ["x"],
            },
        },
    }]
    messages = [
        {"role": "system", "content": "系统约束"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "old-call",
                "type": "function",
                "function": {"name": "lookup", "arguments": '{"x":1}'},
            }],
        },
        {"role": "tool", "tool_call_id": "old-call", "name": "lookup", "content": '{"value":1}'},
        {"role": "user", "content": "继续"},
    ]

    result = adapter.call_chat(
        snapshot,
        messages,
        tools=tools,
        tool_choice={"type": "function", "function": {"name": "lookup"}},
        max_tokens=123,
    )

    url, kwargs = calls[0]
    assert url == "https://llm.example.test/anthropic/v1/messages"
    assert kwargs["headers"] == {
        "x-api-key": "sk-super-secret",
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = kwargs["json"]
    assert payload["system"] == "系统约束"
    assert payload["max_tokens"] == 123
    assert payload["thinking"] == {"type": "disabled"}
    assert payload["tools"][0]["input_schema"]["required"] == ["x"]
    assert payload["tool_choice"] == {"type": "tool", "name": "lookup"}
    assert payload["messages"][0] == {
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": "old-call",
            "name": "lookup",
            "input": {"x": 1},
        }],
    }
    assert payload["messages"][1]["role"] == "user"
    assert payload["messages"][1]["content"][0] == {
        "type": "tool_result",
        "tool_use_id": "old-call",
        "content": '{"value":1}',
    }
    assert payload["messages"][1]["content"][1] == {"type": "text", "text": "继续"}
    assert result.text == "调用工具"
    assert result.reasoning == "内部思考"
    assert result.tool_calls == (
        adapter.LLMToolCall("next-call", "lookup", '{"x":2}'),
    )
    assert result.usage == adapter.LLMUsage(12, 7, 19)


def test_anthropic_thinking_enabled_is_explicit_and_has_no_budget_or_effort(monkeypatch):
    response = FakeResponse({
        "content": [{"type": "text", "text": "OK"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    calls = install_post(monkeypatch, response)

    adapter.call_text(
        endpoint(
            protocol="anthropic",
            thinking_enabled=True,
            thinking_format="thinking_type",
        ),
        "hello",
    )

    payload = calls[0][1]["json"]
    assert payload["thinking"] == {"type": "adaptive"}
    assert payload["max_tokens"] == 32000
    serialized = json.dumps(payload)
    assert "effort" not in serialized
    assert "budget" not in serialized


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("method", ["chat", "text", "vision"])
def test_optional_request_reasoning_effort_maps_by_protocol_without_changing_thinking_or_limit(monkeypatch, protocol, method):
    response = (FakeResponse({"content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn"})
                if protocol == "anthropic" else
                FakeResponse({"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}))
    calls = install_post(monkeypatch, response)
    snapshot = endpoint(protocol=protocol, category="omni", thinking_enabled=True,
                        thinking_format="thinking_type" if protocol == "anthropic" else "enable_thinking",
                        max_output_tokens=2048)
    options = {"reasoning_effort": "low", "max_tokens": 64000}
    if method == "chat":
        adapter.call_chat(snapshot, [{"role": "user", "content": "hello"}], **options)
    elif method == "text":
        adapter.call_text(snapshot, "hello", **options)
    else:
        adapter.call_vision(snapshot, "hello", ["https://images.example.test/a.png"], **options)
    payload = calls[0][1]["json"]
    assert payload["max_tokens"] == 2048
    assert "budget" not in json.dumps(payload)
    if protocol == "anthropic":
        assert payload["thinking"] == {"type": "adaptive"}
        assert payload["output_config"] == {"effort": "low"}
        assert "reasoning_effort" not in payload
    else:
        assert payload["enable_thinking"] is True
        assert payload["reasoning_effort"] == "low"
        assert "output_config" not in payload


@pytest.mark.parametrize("effort", ["", "none", "unknown", True, 1000, {"effort": "low"}])
def test_invalid_request_reasoning_effort_is_rejected_before_http(monkeypatch, effort):
    calls = install_post(monkeypatch, FakeResponse({}))
    with pytest.raises(adapter.LLMEndpointValidationError, match="reasoning_effort"):
        adapter.call_chat(endpoint(), [{"role": "user", "content": "hello"}], reasoning_effort=effort)
    assert not calls


def _invoke_chat_entry(method, snapshot, **options):
    if method == "chat":
        return adapter.call_chat(snapshot, [{"role": "user", "content": "返回 JSON"}], **options)
    if method == "text":
        return adapter.call_text(snapshot, "返回 JSON", **options)
    return adapter.call_vision(snapshot, "返回 JSON", ["https://images.example.test/a.png"], **options)


@pytest.mark.parametrize("method", ["chat", "text", "vision"])
@pytest.mark.parametrize("thinking_enabled", [False, True])
def test_json_object_response_format_uses_standard_openai_wire_without_changing_limits(monkeypatch, method, thinking_enabled):
    calls = install_post(monkeypatch, FakeResponse({"choices": [{"message": {"content": '{"ok":true}'}}]}))
    snapshot = endpoint(category="omni", thinking_enabled=thinking_enabled,
                        thinking_format="enable_thinking", max_output_tokens=2048)
    response_format = {"type": "json_object"}
    result = _invoke_chat_entry(method, snapshot, response_format=response_format,
                                max_tokens=64000, reasoning_effort="low")
    assert result.text == '{"ok":true}' and len(calls) == 1
    payload = calls[0][1]["json"]
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["response_format"] is not response_format
    assert payload["enable_thinking"] is thinking_enabled
    assert payload["reasoning_effort"] == "low" and payload["max_tokens"] == 2048
    assert "tools" not in payload and "tool_choice" not in payload and "thinking" not in payload


@pytest.mark.parametrize("method", ["chat", "text", "vision"])
@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("explicit_none", [False, True])
def test_default_response_format_does_not_add_wire_fields(monkeypatch, method, protocol, explicit_none):
    response = ({"choices": [{"message": {"content": "OK"}}]} if protocol == "openai"
                else {"content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn"})
    calls = install_post(monkeypatch, FakeResponse(response))
    result = _invoke_chat_entry(method, endpoint(protocol=protocol, category="omni"),
                                **({"response_format": None} if explicit_none else {}))
    assert result.text == "OK" and len(calls) == 1
    payload = calls[0][1]["json"]
    assert "response_format" not in payload and "tools" not in payload and "tool_choice" not in payload
    assert "enable_thinking" not in payload


@pytest.mark.parametrize("method", ["chat", "text", "vision"])
@pytest.mark.parametrize("response_format", [
    {}, "json_object", True, [], {"type": True}, {"type": "text"},
    {"type": "json_schema", "json_schema": {}}, {"type": "json_object", "extra": True},
])
def test_invalid_response_format_is_rejected_before_http(monkeypatch, method, response_format):
    calls = install_post(monkeypatch, FakeResponse({}))
    with pytest.raises(adapter.LLMEndpointValidationError, match="response_format"):
        _invoke_chat_entry(method, endpoint(category="omni"), response_format=response_format)
    assert not calls


@pytest.mark.parametrize("method", ["chat", "text", "vision"])
def test_anthropic_response_format_is_explicitly_rejected_without_protocol_conversion(monkeypatch, method):
    calls = install_post(monkeypatch, FakeResponse({}))
    with pytest.raises(adapter.LLMEndpointValidationError, match="response_format.*OpenAI"):
        _invoke_chat_entry(method, endpoint(protocol="anthropic", category="omni"), response_format={"type": "json_object"})
    assert not calls


@pytest.mark.parametrize("method", ["chat", "text", "vision"])
def test_openai_enable_thinking_off_is_explicit_for_all_chat_entries(monkeypatch, method):
    calls = install_post(monkeypatch, FakeResponse({"choices": [{"message": {"content": "OK"}}]}))
    _invoke_chat_entry(method, endpoint(category="omni", thinking_format="enable_thinking", thinking_enabled=False))
    payload = calls[0][1]["json"]
    assert payload["enable_thinking"] is False
    assert "thinking" not in payload and "response_format" not in payload
    assert "reasoning_effort" not in payload and "output_config" not in payload
    assert payload["max_tokens"] == 32000


@pytest.mark.parametrize(
    ("thinking_format", "thinking_enabled"),
    [("none", False), ("none", True), ("thinking_type", False)],
)
def test_anthropic_off_is_explicit_and_rejects_enable_thinking(
        monkeypatch, thinking_format, thinking_enabled):
    response = FakeResponse({
        "content": [{"type": "text", "text": "OK"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    calls = install_post(monkeypatch, response)

    adapter.call_text(
        endpoint(
            protocol="anthropic",
            thinking_format=thinking_format,
            thinking_enabled=thinking_enabled,
        ),
        "hello",
    )

    payload = calls[0][1]["json"]
    assert payload["thinking"] == {"type": "disabled"}
    assert "enable_thinking" not in payload
    serialized = json.dumps(payload)
    assert "effort" not in serialized
    assert "budget" not in serialized
    with pytest.raises(adapter.LLMEndpointValidationError, match="enable_thinking"):
        endpoint(protocol="anthropic", thinking_format="enable_thinking")


def test_anthropic_off_rejection_does_not_retry_with_provider_defaults(monkeypatch):
    calls = install_post(monkeypatch, FakeResponse(
        {"error": {"type": "invalid_request_error", "message": "thinking cannot be disabled"}},
        status_code=400,
    ))

    with pytest.raises(adapter.LLMEndpointRequestError):
        adapter.call_text(endpoint(protocol="anthropic"), "hello")

    assert len(calls) == 1
    assert calls[0][1]["json"]["thinking"] == {"type": "disabled"}


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_chat_requests_use_node_output_capacity_for_both_protocols(monkeypatch, protocol):
    payload = (
        {"choices": [{"message": {"content": "OK"}}]}
        if protocol == "openai"
        else {"content": [{"type": "text", "text": "OK"}]}
    )
    calls = install_post(monkeypatch, FakeResponse(payload))

    adapter.call_text(
        endpoint(
            protocol=protocol,
            context_window_tokens=12000,
            max_output_tokens=7000,
        ),
        "hello",
    )

    assert calls[0][1]["json"]["max_tokens"] == 7000


def test_explicit_output_request_cannot_exceed_node_capacity(monkeypatch):
    calls = install_post(monkeypatch, FakeResponse({
        "choices": [{"message": {"content": "OK"}}],
    }))

    adapter.call_text(
        endpoint(max_output_tokens=2048),
        "hello",
        max_tokens=99999,
    )

    assert calls[0][1]["json"]["max_tokens"] == 2048


def test_endpoint_rejects_output_capacity_above_context_capacity():
    with pytest.raises(adapter.LLMEndpointValidationError, match="上下文窗口"):
        endpoint(context_window_tokens=1024, max_output_tokens=2048)


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
def test_vision_payload_translation(monkeypatch, protocol):
    payload = (
        {"choices": [{"message": {"content": "白色"}, "finish_reason": "stop"}]}
        if protocol == "openai"
        else {
            "content": [{"type": "text", "text": "白色"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 1},
        }
    )
    calls = install_post(monkeypatch, FakeResponse(payload))
    snapshot = endpoint(protocol=protocol, category="vision")
    image = adapter.LLMImage.from_bytes(b"fake-image-bytes", "image/png")

    result = adapter.call_vision(snapshot, "主要颜色？", [image])

    assert result.text == "白色"
    body = calls[0][1]["json"]
    content = body["messages"][0]["content"]
    if protocol == "openai":
        assert content[0]["type"] == "image_url"
        assert content[0]["image_url"]["url"].startswith("data:image/png;base64,")
    else:
        assert content[0]["type"] == "image"
        assert content[0]["source"]["type"] == "base64"
        assert content[0]["source"]["media_type"] == "image/png"
        assert content[0]["source"]["data"] == "ZmFrZS1pbWFnZS1ieXRlcw=="


def test_openai_embedding_request_and_response_order(monkeypatch):
    response = FakeResponse({
        "model": "embedding-model",
        "data": [
            {"index": 1, "embedding": [0.3, 0.4]},
            {"index": 0, "embedding": [0.1, 0.2]},
        ],
        "usage": {"prompt_tokens": 4, "total_tokens": 4},
    })
    calls = install_post(monkeypatch, response)

    result = adapter.create_embeddings(
        endpoint(category="embedding"),
        ["first", "second"],
        dimensions=2,
    )

    assert calls[0][0] == "https://llm.example.test/v1/embeddings"
    assert calls[0][1]["json"] == {
        "model": "model-id",
        "input": ["first", "second"],
        "dimensions": 2,
    }
    assert result.vectors == ((0.1, 0.2), (0.3, 0.4))
    assert result.model == "embedding-model"
    assert result.usage == adapter.LLMUsage(4, 0, 4)


def sse(data):
    return [f"data: {json.dumps(data, ensure_ascii=False)}", ""]


def test_openai_stream_parsing_and_delta_callback(monkeypatch):
    lines = []
    lines += sse({
        "model": "stream-model",
        "choices": [{
            "delta": {
                "content": "你",
                "reasoning_content": "想",
                "tool_calls": [{
                    "index": 0,
                    "id": "call-1",
                    "function": {"name": "look", "arguments": "{\"x\":"},
                }],
            },
            "finish_reason": None,
        }],
    })
    lines += sse({
        "choices": [{
            "delta": {
                "content": "好",
                "reasoning_content": "完",
                "tool_calls": [{
                    "index": 0,
                    "function": {"name": "up", "arguments": "1}"},
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    })
    lines += ["data: [DONE]", ""]
    response = FakeResponse(
        content_type="text/event-stream; charset=utf-8",
        lines=lines,
    )
    calls = install_post(monkeypatch, response)
    deltas = []
    reasoning_deltas = []

    result = adapter.call_text(
        endpoint(),
        "go",
        stream=True,
        on_text_delta=deltas.append,
        on_reasoning_delta=reasoning_deltas.append,
    )

    assert calls[0][1]["stream"] is True
    assert calls[0][1]["json"]["stream"] is True
    assert deltas == ["你", "好"]
    assert reasoning_deltas == ["想", "完"]
    assert result.text == "你好"
    assert result.reasoning == "想完"
    assert result.tool_calls == (
        adapter.LLMToolCall("call-1", "lookup", '{"x":1}'),
    )
    assert result.finish_reason == "tool_calls"
    assert result.usage == adapter.LLMUsage(5, 3, 8)
    assert response.closed is True


def test_anthropic_stream_parsing_and_delta_callback(monkeypatch):
    events = [
        {"type": "message_start", "message": {"model": "a-model", "usage": {"input_tokens": 6}}},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "thinking", "thinking": "先"},
        },
        {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "想"}},
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "text", "text": "你"},
        },
        {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "好"}},
        {
            "type": "content_block_start",
            "index": 2,
            "content_block": {"type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": '{"x":1}'},
        },
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 4},
        },
        {"type": "message_stop"},
    ]
    lines = []
    for event in events:
        lines += [f"event: {event['type']}"] + sse(event)
    response = FakeResponse(content_type="text/event-stream", lines=lines)
    install_post(monkeypatch, response)
    deltas = []
    reasoning_deltas = []

    result = adapter.call_text(
        endpoint(protocol="anthropic"),
        "go",
        stream=True,
        on_text_delta=deltas.append,
        on_reasoning_delta=reasoning_deltas.append,
    )

    assert deltas == ["你", "好"]
    assert reasoning_deltas == ["先", "想"]
    assert result.text == "你好"
    assert result.reasoning == "先想"
    assert result.tool_calls == (
        adapter.LLMToolCall("tool-1", "lookup", '{"x":1}'),
    )
    assert result.finish_reason == "tool_use"
    assert result.model == "a-model"
    assert result.usage == adapter.LLMUsage(6, 4, 10)


@pytest.mark.parametrize("vision", [False, True])
def test_continuation_messages_are_appended_after_unchanged_first_request(
    monkeypatch,
    vision,
):
    response = FakeResponse({
        "choices": [{"message": {"content": "最终结果"}}],
    })
    calls = install_post(monkeypatch, response)
    continuation = [
        {"role": "assistant", "content": "首轮原始回复"},
        {"role": "user", "content": "参考其他评委后重评"},
    ]

    if vision:
        adapter.call_vision(
            endpoint(category="vision"),
            "首轮图片请求",
            [adapter.LLMImage.from_bytes(b"image", "image/png")],
            continuation_messages=continuation,
        )
    else:
        adapter.call_text(
            endpoint(),
            "首轮文本请求",
            continuation_messages=continuation,
        )

    messages = calls[0][1]["json"]["messages"]
    assert messages[-2:] == continuation
    assert messages[0]["role"] == "user"
    if vision:
        assert messages[0]["content"][-1] == {
            "type": "text",
            "text": "首轮图片请求",
        }
    else:
        assert messages[0]["content"] == "首轮文本请求"


def test_streaming_timeout_disables_read_deadline(monkeypatch):
    response = FakeResponse(
        content_type="text/event-stream",
        lines=sse({"choices": [{"delta": {"content": "{}"}}]}),
    )
    calls = install_post(monkeypatch, response)

    adapter.call_text(
        endpoint(),
        "go",
        timeout=None,
        on_text_delta=lambda _delta: None,
    )

    assert calls[0][1]["timeout"] == (30.0, None)


def test_http_failure_and_probe_never_expose_api_key(monkeypatch):
    secret = "key-must-never-leak"
    response = FakeResponse(
        {"error": {"message": f"bad key {secret}"}},
        status_code=401,
    )
    install_post(monkeypatch, response)
    snapshot = endpoint(api_key=secret)

    with pytest.raises(adapter.LLMEndpointRequestError) as caught:
        adapter.call_text(snapshot, "hello")
    assert secret not in str(caught.value)
    assert secret not in repr(snapshot)

    probe = adapter.probe_endpoint(snapshot)
    assert probe.ok is False
    assert probe.message == "模型端点鉴权失败（HTTP 401）。"
    assert secret not in repr(probe)


@pytest.mark.parametrize(("exception_type", "failure", "message"), [
    (adapter.requests.exceptions.Timeout, "timeout", "模型端点响应超时。"),
    (adapter.requests.exceptions.ConnectTimeout, "timeout", "模型端点响应超时。"),
    (adapter.requests.exceptions.ReadTimeout, "timeout", "模型端点响应超时。"),
    (adapter.requests.exceptions.ConnectionError, "connection", "模型端点连接失败。"),
    (adapter.requests.exceptions.SSLError, "connection", "模型端点连接失败。"),
    (adapter.requests.exceptions.RequestException, "other", "模型端点请求失败。"),
    (adapter.requests.exceptions.InvalidURL, "other", "模型端点请求失败。"),
    (RuntimeError, "other", "模型端点请求失败。"),
])
def test_request_failure_classification_discards_sensitive_exception_chain(
    monkeypatch, exception_type, failure, message,
):
    secret = "request-exception-secret-canary"
    private_url = "https://private-upstream.example.test/private?token=" + secret
    upstream_error = exception_type(f"{private_url}: rejected Authorization {secret}")
    upstream_error.request = object()
    upstream_error.response = object()

    def fake_post(*args, **kwargs):
        raise upstream_error

    monkeypatch.setattr(adapter.requests, "post", fake_post)
    with pytest.raises(adapter.LLMEndpointRequestError) as caught:
        adapter.call_text(endpoint(api_key=secret), "hello", timeout=600)

    error = caught.value
    assert str(error) == message
    assert vars(error) == {"status_code": None, "request_failure": failure, "provider_reason": None}
    assert error.__context__ is None and error.__cause__ is None
    public_error = "".join(traceback.format_exception(error))
    assert secret not in public_error and private_url not in public_error


def test_request_failure_classifier_does_not_stringify_vendor_exception(monkeypatch):
    class UnprintableVendorError(Exception):
        def __str__(self):
            raise AssertionError("供应商异常原文不应被读取")

    def fake_post(*args, **kwargs):
        raise UnprintableVendorError()

    monkeypatch.setattr(adapter.requests, "post", fake_post)
    result = adapter.probe_endpoint(endpoint())
    assert result.ok is False
    assert result.message == "模型端点请求失败。"


def test_request_failure_defaults_keep_existing_error_construction():
    error = adapter.LLMEndpointRequestError("固定旧说明", status_code=402)
    assert error.status_code == 402 and error.request_failure is None
    assert error.provider_reason is None
    assert str(error) == "固定旧说明"


@pytest.mark.parametrize("failure", ["SECRET-VALUE", "Timeout", "", True, 1, [], {}])
def test_request_failure_constructor_rejects_noncanonical_values(failure):
    with pytest.raises(ValueError, match="分类无效") as caught:
        adapter.LLMEndpointRequestError("固定说明", request_failure=failure)
    assert "SECRET" not in str(caught.value)


def test_http_error_does_not_gain_a_transport_failure_classification():
    error = adapter._status_error(402)
    assert error.status_code == 402 and error.request_failure is None
    with pytest.raises(ValueError, match="分类无效"):
        adapter.LLMEndpointRequestError("固定说明", status_code=402, request_failure="timeout")


@pytest.mark.parametrize("timeout_type", [TimeoutError, adapter.requests.packages.urllib3.exceptions.ReadTimeoutError])
@pytest.mark.parametrize("outer_type", [adapter.requests.exceptions.ProxyError, adapter.requests.exceptions.ConnectionError])
def test_typed_nested_proxy_timeout_is_reported_without_exception_text(monkeypatch, timeout_type, outer_type):
    errors = adapter.requests.packages.urllib3.exceptions
    secret = "nested-proxy-secret"
    timeout = (timeout_type(secret) if timeout_type is TimeoutError
               else timeout_type(None, "https://private.example/" + secret, secret))
    proxy = errors.ProxyError(secret, timeout)
    retry = errors.MaxRetryError(None, "https://private.example/" + secret, proxy)
    upstream = outer_type(retry)

    def fake_post(*args, **kwargs):
        raise upstream

    monkeypatch.setattr(adapter.requests, "post", fake_post)
    with pytest.raises(adapter.LLMEndpointRequestError) as caught:
        adapter.call_chat(endpoint(), [{"role": "user", "content": "go"}])
    assert caught.value.request_failure == "timeout"
    assert caught.value.__context__ is None
    assert secret not in "".join(traceback.format_exception(caught.value))


def test_proxy_classification_does_not_infer_timeout_from_text_and_handles_cycles():
    errors = adapter.requests.packages.urllib3.exceptions
    assert adapter._request_failure_kind(adapter.requests.exceptions.ProxyError("Read timed out timeout")) == "connection"
    retry = errors.MaxRetryError(None, "https://example.test/", None)
    retry.reason = retry
    assert adapter._request_failure_kind(adapter.requests.exceptions.ProxyError(retry)) == "connection"


class StrictSSEResponse(FakeResponse):
    def __init__(self, chunks, *, trap_after=False, error=None, content_type="text/event-stream"):
        super().__init__(content_type=content_type)
        self.chunks = chunks
        self.trap_after = trap_after
        self.error = error
        self.consumed = 0

    def iter_content(self, *, chunk_size, decode_unicode):
        assert chunk_size == 8192 and decode_unicode is False
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk
        if self.error is not None:
            raise self.error
        if self.trap_after:
            raise AssertionError("不得等待终止标记之后的 EOF")


STRICT_MESSAGES = [{"role": "user", "content": "go"}]


def sse_chunk(event):
    return ("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode()


def strict_text_chunks(protocol, *, finish=None, terminal=True):
    if protocol == "openai":
        chunks = [sse_chunk({"choices": [{"delta": {"content": "完成", "reasoning_content": "核对"},
                                          "finish_reason": finish}]})]
        if terminal:
            chunks.append(b"data: [DONE]\n\n")
        return chunks
    chunks = [sse_chunk({"type": "message_start", "message": {"model": "model-id", "usage": {"input_tokens": 9}}}),
              sse_chunk({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": "完成"}}),
              sse_chunk({"type": "message_delta", "delta": {"stop_reason": finish}, "usage": {"output_tokens": 4}})]
    if terminal:
        chunks.append(sse_chunk({"type": "message_stop"}))
    return chunks


@pytest.mark.parametrize(("protocol", "finish"), [("openai", "stop"), ("anthropic", "end_turn")])
def test_strict_stream_closes_at_terminal_without_reading_eof(monkeypatch, protocol, finish):
    response = StrictSSEResponse(strict_text_chunks(protocol, finish=finish), trap_after=True)
    calls = install_post(monkeypatch, response)
    options = {"stream_options": {"include_usage": True}} if protocol == "openai" else {}
    result = adapter.call_chat(endpoint(protocol=protocol), [{"role": "user", "content": "go"}],
                               stream=True, require_complete_stream=True, **options)
    assert result.text == "完成" and result.finish_reason == finish
    assert response.closed and response.consumed == len(response.chunks)
    assert calls[0][1]["json"]["stream"] is True
    if protocol == "openai":
        assert calls[0][1]["json"]["stream_options"] == {"include_usage": True}
        assert result.reasoning == "核对"
    else:
        assert "stream_options" not in calls[0][1]["json"]
        assert result.usage == adapter.LLMUsage(9, 4, 13)


def test_strict_openai_aggregates_tool_arguments_and_usage_before_done(monkeypatch):
    chunks = [
        sse_chunk({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call-1", "function": {
            "name": "faithsieve_result", "arguments": '{"数学":"\\\\forall '}}]}}]}),
        sse_chunk({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": 'x"}'}}]},
                                 "finish_reason": "tool_calls"}]}),
        sse_chunk({"choices": [], "usage": {"prompt_tokens": 7, "completion_tokens": 8, "total_tokens": 15}}),
        b"data: [DONE]\n\n",
    ]
    response = StrictSSEResponse(chunks, trap_after=True)
    install_post(monkeypatch, response)
    result = adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True,
                               stream_options={"include_usage": True})
    assert result.tool_calls == (adapter.LLMToolCall("call-1", "faithsieve_result", '{"数学":"\\\\forall x"}'),)
    assert result.usage == adapter.LLMUsage(7, 8, 15)


@pytest.mark.parametrize(("protocol", "finish"), [("openai", "length"), ("anthropic", "max_tokens")])
def test_strict_terminal_preserves_token_limit_finish_for_callers_existing_gate(monkeypatch, protocol, finish):
    response = StrictSSEResponse(strict_text_chunks(protocol, finish=finish), trap_after=True)
    install_post(monkeypatch, response)
    result = adapter.call_chat(endpoint(protocol=protocol), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert result.finish_reason == finish and response.closed


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize(("finish", "terminal"), [(None, True), ("SECRET-FINISH", True), ("stop", False)])
def test_strict_stream_requires_terminal_and_a_legal_finish(monkeypatch, protocol, finish, terminal):
    response = StrictSSEResponse(strict_text_chunks(protocol, finish=finish, terminal=terminal))
    install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointResponseError, match="完整结束") as caught:
        adapter.call_chat(endpoint(protocol=protocol), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert "SECRET" not in str(caught.value) and response.closed


@pytest.mark.parametrize("wire", [b'data: {"x":NaN}\n\n', b'data: {"x":1,"x":2}\n\n',
                                 b'data: {"error":"SECRET"}\n\n', b'data: not-json-SECRET\n\n',
                                 b'data: {"x":"\xff"}\n\n'])
def test_strict_invalid_sse_frames_are_safe_response_errors(monkeypatch, wire):
    response = StrictSSEResponse([wire])
    install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointResponseError) as caught:
        adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert "SECRET" not in str(caught.value) and response.closed


def test_strict_stream_counts_keepalives_and_a_single_unterminated_long_line(monkeypatch):
    response = StrictSSEResponse([b":ping\n\n" * 5, b"data: " + b"x" * 40])
    install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointResponseError, match="字节限制"):
        adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True, max_stream_bytes=50)
    assert response.closed


def test_strict_stream_accepts_two_mib_artifact_arguments_packaging(monkeypatch):
    arguments = json.dumps({"artifact": "x" * (2 * 1024 * 1024 - 512)})
    payload = sse_chunk({"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {
        "name": "faithsieve_result", "arguments": arguments}}]}, "finish_reason": "tool_calls"}]})
    chunks = [payload[i:i + 8192] for i in range(0, len(payload), 8192)] + [b"data: [DONE]\n\n"]
    response = StrictSSEResponse(chunks, trap_after=True)
    install_post(monkeypatch, response)
    result = adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert result.tool_calls[0].arguments == arguments and response.closed


def test_strict_stream_network_error_is_classified_without_sensitive_chain(monkeypatch):
    response = StrictSSEResponse(strict_text_chunks("openai", finish="stop", terminal=False),
                                 error=adapter.requests.exceptions.ReadTimeout("SECRET-URL-TIMEOUT"))
    install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointRequestError) as caught:
        adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert caught.value.request_failure == "timeout" and response.closed
    assert caught.value.__context__ is None and "SECRET" not in str(caught.value)


def test_strict_stream_rejects_non_sse_without_parsing_json_fallback(monkeypatch):
    response = StrictSSEResponse([], content_type="application/json")
    install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointResponseError, match="SSE"):
        adapter.call_chat(endpoint(), STRICT_MESSAGES, stream=True, require_complete_stream=True)
    assert response.closed


@pytest.mark.parametrize("options", [
    {"require_complete_stream": True},
    {"stream": True, "require_complete_stream": "yes"},
    {"stream": True, "max_stream_bytes": 100},
    {"stream": True, "require_complete_stream": True, "max_stream_bytes": True},
    {"stream": True, "require_complete_stream": True, "max_stream_bytes": 0},
    {"stream": True, "require_complete_stream": True, "max_stream_bytes": 8 * 1024 * 1024 + 1},
    {"stream_options": {"include_usage": True}},
    {"stream": True, "stream_options": {"include_usage": False}},
    {"stream": True, "stream_options": {"include_usage": True, "SECRET": 1}},
])
def test_strict_stream_option_validation_precedes_any_http(monkeypatch, options):
    calls = install_post(monkeypatch, FakeResponse())
    with pytest.raises(adapter.LLMEndpointValidationError):
        adapter.call_chat(endpoint(), STRICT_MESSAGES, **options)
    assert calls == []


def test_anthropic_rejects_openai_stream_options_before_http(monkeypatch):
    calls = install_post(monkeypatch, FakeResponse())
    with pytest.raises(adapter.LLMEndpointValidationError):
        adapter.call_chat(endpoint(protocol="anthropic"), STRICT_MESSAGES, stream=True,
                           stream_options={"include_usage": True})
    assert calls == []


@pytest.mark.parametrize(
    ("snapshot", "response", "expected_suffix"),
    [
        (
            endpoint(category="text"),
            {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]},
            "/chat/completions",
        ),
        (
            endpoint(category="vision"),
            {"choices": [{"message": {"content": "白色"}, "finish_reason": "stop"}]},
            "/chat/completions",
        ),
        (
            endpoint(protocol="anthropic", category="omni"),
            {
                "content": [{"type": "text", "text": "白色"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 2, "output_tokens": 1},
            },
            "/v1/messages",
        ),
        (
            endpoint(category="embedding"),
            {"data": [{"index": 0, "embedding": [0.1, 0.2]}]},
            "/embeddings",
        ),
    ],
)
def test_real_probe_shape_for_all_four_categories(
    monkeypatch,
    snapshot,
    response,
    expected_suffix,
):
    calls = install_post(monkeypatch, FakeResponse(response))

    result = adapter.probe_endpoint(snapshot, timeout=3)

    assert result.ok is True
    assert result.category is snapshot.category
    assert result.protocol is snapshot.protocol
    assert result.message == "端点测试成功。"
    assert calls[0][0].endswith(expected_suffix)
    body = calls[0][1]["json"]
    if snapshot.category is not adapter.LLMEndpointCategory.EMBEDDING:
        assert body["max_tokens"] == 64
    if snapshot.category in {adapter.LLMEndpointCategory.VISION, adapter.LLMEndpointCategory.OMNI}:
        content = body["messages"][0]["content"]
        assert any(block["type"] in {"image", "image_url"} for block in content)
    elif snapshot.category is adapter.LLMEndpointCategory.TEXT:
        assert isinstance(body["messages"][0]["content"], str)
        assert body["messages"][0]["content"]
    else:
        assert len(body["input"]) == 1
        assert isinstance(body["input"][0], str)
        assert body["input"][0]


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("category", ["text", "vision", "omni"])
@pytest.mark.parametrize("thinking_enabled", [False, True])
@pytest.mark.parametrize("administrator_limit", [32, 512, 64000])
def test_probe_output_budget_preserves_thinking_mode_and_administrator_limit(
    monkeypatch, protocol, category, thinking_enabled, administrator_limit,
):
    response = (
        {"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]}
        if protocol == "openai"
        else {"content": [{"type": "text", "text": "OK"}], "stop_reason": "end_turn"}
    )
    calls = install_post(monkeypatch, FakeResponse(response))
    snapshot = endpoint(
        protocol=protocol, category=category, thinking_enabled=thinking_enabled,
        thinking_format="thinking_type" if protocol == "anthropic" else "enable_thinking",
        max_output_tokens=administrator_limit,
    )

    assert adapter.probe_endpoint(snapshot).ok is True
    assert len(calls) == 1
    body = calls[0][1]["json"]
    assert body["max_tokens"] == min(2048 if thinking_enabled else 64, administrator_limit)
    if protocol == "anthropic":
        assert body["thinking"] == {"type": "adaptive" if thinking_enabled else "disabled"}
    elif thinking_enabled:
        assert body["enable_thinking"] is True
    else:
        assert body["enable_thinking"] is False and "thinking" not in body
    assert "budget_tokens" not in json.dumps(body)
    assert "reasoning_effort" not in body and "effort" not in body


def test_dynamic_config_tester_adapter_returns_supported_shape(monkeypatch):
    calls = install_post(monkeypatch, FakeResponse({
        "choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}],
    }))
    get_calls = install_get(monkeypatch, FakeResponse({"data": []}))
    candidate = {
        "protocol": "openai",
        "category": "text",
        "base_url": "https://llm.example.test/v1",
        "api_key": "not-returned",
        "model": "model-id",
        "thinking_enabled": False,
        "thinking_format": "none",
    }

    result = adapter.test_endpoint_candidate(candidate, timeout=3)

    assert result["passed"] is True
    assert result["message"] == "端点测试成功。"
    assert isinstance(result["latency_ms"], int)
    assert result["upstream_context_window_tokens"] is None
    assert result["upstream_max_output_tokens"] is None
    assert "not-returned" not in repr(result)
    assert len(calls) == 1
    assert len(get_calls) == 1


def test_openai_model_metadata_uses_list_exact_match_and_preserves_query():
    post_calls = []
    get_calls = []

    def post(url, **kwargs):
        post_calls.append((url, kwargs))
        return FakeResponse({
            "choices": [{"message": {"content": "OK"}}],
        })

    def get(url, **kwargs):
        get_calls.append((url, kwargs))
        return FakeResponse({
            "data": [
                {
                    "id": "provider/other-model",
                    "context_length": 1,
                    "max_output_tokens": 1,
                },
                {
                    "id": "provider/model-id",
                    "context_length": "131072",
                    "max_output_tokens": 32768,
                    "max_tokens": 1,
                    "top_provider": {
                        "context_length": 100000,
                        "max_completion_tokens": "16000",
                    },
                },
            ],
        })

    result = adapter.test_endpoint_candidate(
        {
            "protocol": "openai",
            "category": "text",
            "base_url": "https://llm.example.test/v1?api-version=2026-08-01",
            "api_key": "secret",
            "model": "provider/model-id",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        timeout=3,
        request_post=post,
        request_get=get,
    )

    assert result["passed"] is True
    assert result["upstream_context_window_tokens"] == 100000
    assert result["upstream_max_output_tokens"] == 16000
    assert post_calls[0][1]["json"]["max_tokens"] == 64
    assert get_calls == [(
        "https://llm.example.test/v1/models?api-version=2026-08-01",
        {
            "headers": {
                "Authorization": "Bearer secret",
                "Content-Type": "application/json",
            },
            "timeout": 3.0,
            "allow_redirects": False,
        },
    )]


def test_anthropic_model_metadata_uses_encoded_direct_model_url():
    get_calls = []

    def post(_url, **_kwargs):
        return FakeResponse({
            "content": [{"type": "text", "text": "OK"}],
            "stop_reason": "end_turn",
        })

    def get(url, **kwargs):
        get_calls.append((url, kwargs))
        return FakeResponse({
            "id": "claude/model small",
            "max_input_tokens": "200000",
            "max_tokens": 8192,
            "limits": {"max_output_tokens": 10000},
        })

    result = adapter.test_endpoint_candidate(
        {
            "protocol": "anthropic",
            "category": "text",
            "base_url": "https://llm.example.test/v1?beta=true",
            "api_key": "secret",
            "model": "claude/model small",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        timeout=4,
        request_post=post,
        request_get=get,
    )

    assert result["passed"] is True
    assert result["upstream_context_window_tokens"] == 200000
    assert result["upstream_max_output_tokens"] == 8192
    assert get_calls == [(
        "https://llm.example.test/v1/models/claude%2Fmodel%20small?beta=true",
        {
            "headers": {
                "x-api-key": "secret",
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            "timeout": 4.0,
            "allow_redirects": False,
        },
    )]


@pytest.mark.parametrize(
    "metadata_response",
    [
        FakeResponse({}, status_code=404),
        FakeResponse(ValueError("not json")),
        FakeResponse({"data": [{"id": "another-model", "context_length": 1}]}),
        FakeResponse({
            "data": [{
                "id": "model-id",
                "max_tokens": 1,
                "context_length": 0,
                "max_output_tokens": -1,
            }],
        }),
    ],
)
def test_model_metadata_failures_and_missing_limits_are_best_effort(
    metadata_response,
):
    def post(_url, **_kwargs):
        return FakeResponse({
            "choices": [{"message": {"content": "OK"}}],
        })

    result = adapter.test_endpoint_candidate(
        {
            "protocol": "openai",
            "category": "text",
            "base_url": "https://llm.example.test/v1",
            "api_key": "secret",
            "model": "model-id",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        request_post=post,
        request_get=lambda _url, **_kwargs: metadata_response,
    )

    assert result["passed"] is True
    assert result["upstream_context_window_tokens"] is None
    assert result["upstream_max_output_tokens"] is None


def test_failed_inference_probe_does_not_request_model_metadata():
    result = adapter.test_endpoint_candidate(
        {
            "protocol": "openai",
            "category": "text",
            "base_url": "https://llm.example.test/v1",
            "api_key": "secret",
            "model": "model-id",
            "thinking_enabled": False,
            "thinking_format": "none",
        },
        request_post=lambda _url, **_kwargs: FakeResponse({}, status_code=401),
        request_get=lambda _url, **_kwargs: pytest.fail("不应请求模型元数据"),
    )

    assert result["passed"] is False
    assert result["message"] == "模型端点鉴权失败（HTTP 401）。"


def test_dynamic_config_tester_adapter_converts_validation_error_without_secret():
    secret = "must-not-appear"
    result = adapter.test_endpoint_candidate({
        "protocol": "openai",
        "category": "text",
        "base_url": f"https://user:{secret}@llm.example.test/v1",
        "api_key": secret,
        "model": "model-id",
        "thinking_enabled": False,
        "thinking_format": "none",
    })

    assert result["passed"] is False
    assert "用户凭证" in result["message"]
    assert secret not in repr(result)


@pytest.mark.parametrize("timeout", [0, -1, "bad", float("inf"), float("nan")])
def test_invalid_timeout_is_rejected_before_http(monkeypatch, timeout):
    monkeypatch.setattr(adapter.requests, "post", lambda *_args, **_kwargs: pytest.fail("不应发请求"))

    with pytest.raises(adapter.LLMEndpointValidationError, match="timeout"):
        adapter.call_text(endpoint(), "hello", timeout=timeout)


def test_category_guards_are_fail_closed(monkeypatch):
    monkeypatch.setattr(adapter.requests, "post", lambda *_args, **_kwargs: pytest.fail("不应发请求"))

    with pytest.raises(adapter.LLMEndpointValidationError, match="文本"):
        adapter.call_text(endpoint(category="vision"), "hello")
    with pytest.raises(adapter.LLMEndpointValidationError, match="视觉"):
        adapter.call_vision(endpoint(category="text"), "hello", ["https://images.example.test/a.png"])
    with pytest.raises(adapter.LLMEndpointValidationError, match="Embedding"):
        adapter.create_embeddings(endpoint(category="text"), ["hello"])


class ProviderErrorResponse:
    def __init__(self, chunks, *, status_code=403):
        self.status_code = status_code
        self.headers = {"Content-Type": "application/json"}
        self.chunks = chunks
        self.reads = 0
        self.closed = 0

    def iter_content(self, *, chunk_size, decode_unicode):
        assert chunk_size == 1024 and decode_unicode is False
        for chunk in self.chunks:
            self.reads += 1
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk

    def close(self):
        self.closed += 1

    def json(self):
        pytest.fail("错误分类不能用无界 json() 读取")


def provider_http_error(monkeypatch, response, *, protocol="openai", stream=False):
    calls = install_post(monkeypatch, response)
    with pytest.raises(adapter.LLMEndpointRequestError) as caught:
        adapter.call_chat(endpoint(protocol=protocol), [{"role": "user", "content": "ok"}], stream=stream)
    assert len(calls) == 1 and response.closed == 1
    # HTTP 客户端延迟读取与供应商是否输出 SSE 是两个独立开关。
    assert calls[0][1]["stream"] is True
    assert calls[0][1]["json"]["stream"] is stream
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    return caught.value


@pytest.mark.parametrize(("code", "reason", "message"), [
    ("AccessDenied.Unpurchased", "service_not_enabled", "模型端点服务未开通或不具备调用资格（HTTP 403）。"),
    ("AllocationQuota.FreeTierOnly", "free_tier_exhausted", "模型端点免费额度已耗尽，当前仅允许使用免费额度（HTTP 403）。"),
])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("stream", [False, True])
def test_403_known_code_uses_fixed_reason_without_sensitive_body(
    monkeypatch, code, reason, message, wrapped, protocol, stream,
):
    secret = "vendor-secret-canary"
    body = {"code": code, "message": secret, "request_id": secret,
            "url": f"https://private.example.test/{secret}"}
    raw = json.dumps({"error": body} if wrapped else body).encode()
    response = ProviderErrorResponse([raw[index:index + 7] for index in range(0, len(raw), 7)])
    error = provider_http_error(monkeypatch, response, protocol=protocol, stream=stream)
    assert error.status_code == 403 and error.request_failure is None
    assert error.provider_reason == reason and str(error) == message
    rendered = "".join(traceback.format_exception(error))
    assert secret not in str(error) + repr(error) + repr(vars(error)) + rendered
    assert "private.example.test" not in rendered


@pytest.mark.parametrize("payload", [
    {"code": "SECRET-CODE", "message": "AccessDenied.Unpurchased"},
    {"code": "accessdenied.unpurchased"}, {"code": "AccessDenied.Unpurchased SECRET"},
    {"code": "Arrearage"}, {"code": True}, {"code": 403}, {"code": None},
    {"code": ["AccessDenied.Unpurchased"]}, {"code": {"value": "AccessDenied.Unpurchased"}},
    {"error": "AccessDenied.Unpurchased"}, {"error": None}, {"error": []},
    {"error": {"message": "AccessDenied.Unpurchased"}},
    {"data": {"code": "AccessDenied.Unpurchased"}},
    {"code": "AccessDenied.Unpurchased", "error": {"code": "AccessDenied.Unpurchased"}},
    {"code": "AccessDenied.Unpurchased", "error": {"code": "AllocationQuota.FreeTierOnly"}},
    None, [{"code": "AccessDenied.Unpurchased"}],
])
def test_403_unknown_or_ambiguous_code_keeps_legacy_classification(monkeypatch, payload):
    response = ProviderErrorResponse([json.dumps(payload).encode()])
    error = provider_http_error(monkeypatch, response)
    assert error.status_code == 403 and error.provider_reason is None
    assert str(error) == "模型端点鉴权失败（HTTP 403）。"
    assert "SECRET" not in str(error) + repr(vars(error))


@pytest.mark.parametrize("raw", [
    b'{"code":"AccessDenied.Unpurchased","code":"AccessDenied.Unpurchased"}',
    b'{"code":"AccessDenied.Unpurchased","unused":NaN}',
    b'{"code":"AccessDenied.Unpurchased","unused":Infinity}',
    b'{"code":"AccessDenied.Unpurchased","unused":-Infinity}',
    b'{"code":"AccessDenied.Unpurchased"}{}',
    b'```json\n{"code":"AccessDenied.Unpurchased"}\n```',
    b'{"code":"AccessDenied.Unpurchased","message":"\\q"}',
    b'{"code":"AccessDenied.Unpurchased","message":"\xff"}',
    b'not JSON SECRET', b'',
])
def test_403_invalid_json_does_not_guess_or_expose_body(monkeypatch, raw):
    error = provider_http_error(monkeypatch, ProviderErrorResponse([raw]))
    assert error.status_code == 403 and error.provider_reason is None
    assert "SECRET" not in str(error) + repr(vars(error))


def test_403_reader_accepts_exact_limit_and_refuses_larger_body(monkeypatch):
    base = b'{"code":"AccessDenied.Unpurchased","padding":""}'
    raw = base[:-2] + b"x" * (8192 - len(base)) + base[-2:]
    assert len(raw) == 8192
    response = ProviderErrorResponse([raw])
    assert provider_http_error(monkeypatch, response).provider_reason == "service_not_enabled"
    response = ProviderErrorResponse([raw + b" ", AssertionError("不应读越界后的内容")])
    assert provider_http_error(monkeypatch, response).provider_reason is None
    assert response.reads == 1


@pytest.mark.parametrize("declared", ["8193", "9" * 100, "invalid SECRET", "-1", "", "４０", 8193, True])
@pytest.mark.parametrize("header_name", ["Content-Length", "content-length"])
def test_403_reader_rejects_excessive_or_invalid_declared_length_without_body_reads(
    monkeypatch, declared, header_name,
):
    response = ProviderErrorResponse([AssertionError("超限声明不能读取 body")])
    response.headers[header_name] = declared
    error = provider_http_error(monkeypatch, response)
    assert error.status_code == 403 and error.provider_reason is None
    assert response.reads == 0
    assert "SECRET" not in str(error) + repr(vars(error))


def test_403_valid_declared_length_still_uses_incremental_reader(monkeypatch):
    raw = b'{"code":"AccessDenied.Unpurchased"}'
    response = ProviderErrorResponse([raw[:10], raw[10:]])
    response.headers["Content-Length"] = str(len(raw))
    assert provider_http_error(monkeypatch, response).provider_reason == "service_not_enabled"
    assert response.reads == 2


@pytest.mark.parametrize("protocol", ["openai", "anthropic"])
@pytest.mark.parametrize("category", ["text", "vision"])
@pytest.mark.parametrize("failure", [None, "invalid_json", "read_error"])
def test_deferred_http_receive_preserves_nonstream_json_and_closes_response_once(
    protocol, category, failure,
):
    class LazyBody(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.reads = 0
            self.released = 0

        def read(self, size=-1):
            self.reads += 1
            if failure == "read_error" and self.reads > 1:
                raise adapter.requests.exceptions.ConnectionError("SECRET response URL api-key")
            return super().read(size)

        def release_conn(self):
            self.released += 1

    class LazyResponse(adapter.requests.Response):
        def __init__(self, raw):
            super().__init__()
            self.status_code = 200
            self.headers["Content-Type"] = "application/json"
            self.encoding = "utf-8"
            self.raw = raw
            self.close_count = 0

        def close(self):
            self.close_count += 1
            super().close()

    payload = ({"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
                "model": "model-id", "usage": {"prompt_tokens": 2, "completion_tokens": 3}}
               if protocol == "openai" else
               {"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
                "model": "model-id", "usage": {"input_tokens": 2, "output_tokens": 3}})
    body = LazyBody(b"SECRET invalid JSON" if failure == "invalid_json" else json.dumps(payload).encode())
    response = LazyResponse(body)
    calls = []

    def post(_url, **kwargs):
        assert response._content is False and body.reads == 0
        calls.append(kwargs)
        return response

    def invoke():
        snapshot = endpoint(protocol=protocol, category=category)
        if category == "vision":
            return adapter.call_vision(snapshot, "ok", ["https://images.example.test/a.png"], request_post=post)
        return adapter.call_chat(snapshot, [{"role": "user", "content": "ok"}], request_post=post)

    if failure is None:
        result = invoke()
        assert result.text == "ok" and result.model == "model-id"
        assert result.finish_reason == ("stop" if protocol == "openai" else "end_turn")
        assert result.usage == adapter.LLMUsage(2, 3, 5)
    else:
        with pytest.raises(adapter.LLMEndpointResponseError) as caught:
            invoke()
        assert "SECRET" not in "".join(traceback.format_exception(caught.value))
    assert len(calls) == 1 and calls[0]["stream"] is True
    assert calls[0]["json"]["stream"] is False
    assert response.close_count == 1 and body.released == 1 and body.reads > 0


@pytest.mark.parametrize("chunk", [b": heartbeat\n", b"", "not bytes"])
def test_403_reader_is_bounded_even_without_eof(monkeypatch, chunk):
    monkeypatch.setattr(adapter, "_HTTP_ERROR_MAX_BYTES", 32)
    def chunks():
        while True:
            yield chunk
    response = ProviderErrorResponse(chunks())
    assert provider_http_error(monkeypatch, response).provider_reason is None
    assert response.reads <= 34


@pytest.mark.parametrize("reader_error", [
    adapter.requests.exceptions.ReadTimeout("SECRET URL api-key reader-timeout"),
    adapter.requests.exceptions.ConnectionError("SECRET URL api-key connection"),
    RuntimeError("SECRET URL api-key reader"),
])
def test_403_reader_failure_preserves_http_error_without_retry_or_exception_chain(monkeypatch, reader_error):
    response = ProviderErrorResponse([b'{"code":"AccessDenied.Unpurchased"}', reader_error])
    error = provider_http_error(monkeypatch, response)
    assert error.status_code == 403 and error.provider_reason is None and error.request_failure is None
    assert "SECRET" not in "".join(traceback.format_exception(error)) + repr(vars(error))


@pytest.mark.parametrize("status", [400, 401, 402, 404, 429, 500, "403"])
def test_provider_reason_requires_real_integer_403_and_other_http_paths_are_unchanged(monkeypatch, status):
    response = ProviderErrorResponse([AssertionError("其他状态不应读供应商 body")], status_code=status)
    error = provider_http_error(monkeypatch, response)
    assert error.status_code == int(status) and error.provider_reason is None
    assert response.reads == 0
    assert str(error) == str(adapter._status_error(status))


@pytest.mark.parametrize("reason", [True, 403, [], {}, "SECRET", "", "Service_Not_Enabled"])
def test_provider_reason_constructor_rejects_noncanonical_values(reason):
    with pytest.raises(ValueError, match="供应商失败分类无效"):
        adapter.LLMEndpointRequestError("固定说明", status_code=403, provider_reason=reason)


@pytest.mark.parametrize("status", [None, 400, 401, 402, 404, "403", 403.0, True])
def test_provider_reason_constructor_requires_403(status):
    with pytest.raises(ValueError, match="供应商失败分类无效"):
        adapter.LLMEndpointRequestError("固定说明", status_code=status, provider_reason="service_not_enabled")
