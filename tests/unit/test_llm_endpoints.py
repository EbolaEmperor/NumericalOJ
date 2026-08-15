import json

import pytest

from oj_modules.ai import endpoints as adapter


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
        ("enable_thinking", False, {}),
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
    assert "thinking" not in payload
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
    assert payload["max_tokens"] == 4096
    serialized = json.dumps(payload)
    assert "effort" not in serialized
    assert "budget" not in serialized


def test_anthropic_none_omits_thinking_and_rejects_enable_thinking(monkeypatch):
    response = FakeResponse({
        "content": [{"type": "text", "text": "OK"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1},
    })
    calls = install_post(monkeypatch, response)

    adapter.call_text(endpoint(protocol="anthropic", thinking_format="none"), "hello")

    assert "thinking" not in calls[0][1]["json"]
    with pytest.raises(adapter.LLMEndpointValidationError, match="enable_thinking"):
        endpoint(protocol="anthropic", thinking_format="enable_thinking")


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

    result = adapter.call_text(endpoint(), "go", stream=True, on_text_delta=deltas.append)

    assert calls[0][1]["stream"] is True
    assert calls[0][1]["json"]["stream"] is True
    assert deltas == ["你", "好"]
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

    result = adapter.call_text(
        endpoint(protocol="anthropic"),
        "go",
        stream=True,
        on_text_delta=deltas.append,
    )

    assert deltas == ["你", "好"]
    assert result.text == "你好"
    assert result.reasoning == "先想"
    assert result.tool_calls == (
        adapter.LLMToolCall("tool-1", "lookup", '{"x":1}'),
    )
    assert result.finish_reason == "tool_use"
    assert result.model == "a-model"
    assert result.usage == adapter.LLMUsage(6, 4, 10)


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
