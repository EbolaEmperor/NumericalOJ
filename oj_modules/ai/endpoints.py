#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""厂商无关的全局 LLM 端点协议适配层。

本模块只理解两种线上协议：OpenAI-compatible Chat Completions 与
Anthropic-compatible Messages。调用方使用统一的 OpenAI 风格消息结构；协议差异、
鉴权、URL 拼接、Thinking 参数和响应解析均在这里完成。

API Key 只用于构造请求头。所有可打印值、公开快照和异常消息都不会包含密钥。
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import struct
import time
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import requests


class LLMProtocol(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class LLMEndpointCategory(str, Enum):
    OMNI = "omni"
    TEXT = "text"
    VISION = "vision"
    EMBEDDING = "embedding"


class OpenAIThinkingWireFormat(str, Enum):
    ENABLE_THINKING = "enable_thinking"
    # 数据库存储和管理界面使用下划线机器值；真正的 JSON wire format
    # 仍由 ``_apply_thinking`` 生成 ``thinking.type``。
    THINKING_TYPE = "thinking_type"
    NONE = "none"


_CHAT_CATEGORIES = {
    LLMEndpointCategory.OMNI,
    LLMEndpointCategory.TEXT,
}
_VISION_CATEGORIES = {
    LLMEndpointCategory.OMNI,
    LLMEndpointCategory.VISION,
}
_FULL_REQUEST_PATH_SUFFIXES = (
    "/chat/completions",
    "/v1/messages",
    "/embeddings",
    "/responses",
)
_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_ANTHROPIC_MAX_TOKENS = 4096
_PROBE_MAX_TOKENS = 64_000


class LLMEndpointError(RuntimeError):
    """适配层的安全、可直接展示异常。"""


class LLMEndpointValidationError(LLMEndpointError, ValueError):
    pass


class LLMEndpointRequestError(LLMEndpointError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(str(message))
        self.status_code = status_code


class LLMEndpointResponseError(LLMEndpointError):
    pass


def _enum_value(enum_type, value, field_name):
    normalized = str(value or "").strip().lower()
    if enum_type is OpenAIThinkingWireFormat and normalized == "thinking.type":
        normalized = OpenAIThinkingWireFormat.THINKING_TYPE.value
    try:
        return enum_type(normalized)
    except (TypeError, ValueError):
        raise LLMEndpointValidationError(f"{field_name} 取值无效。") from None


def _strict_bool(value, field_name):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value or "").strip().lower()
    if text in {"1", "true"}:
        return True
    if text in {"0", "false", ""}:
        return False
    raise LLMEndpointValidationError(f"{field_name} 必须是布尔值。")


def _normalize_base_url(value):
    raw = str(value or "").strip()
    if not raw:
        raise LLMEndpointValidationError("Base URL 不能为空。")
    try:
        parts = urlsplit(raw)
    except Exception:
        raise LLMEndpointValidationError("Base URL 格式无效。") from None
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise LLMEndpointValidationError("Base URL 必须是完整的 HTTP(S) 地址。")
    if parts.username is not None or parts.password is not None:
        raise LLMEndpointValidationError("Base URL 不允许包含用户凭证。")
    if parts.query or parts.fragment:
        raise LLMEndpointValidationError("Base URL 不允许包含 Query 或 Fragment。")
    path = (parts.path or "").rstrip("/")
    lowered_path = path.lower()
    if any(lowered_path.endswith(suffix) for suffix in _FULL_REQUEST_PATH_SUFFIXES):
        raise LLMEndpointValidationError("请填写 SDK Base URL，不要填写完整请求 URL。")
    return urlunsplit((parts.scheme.lower(), parts.netloc, path, "", ""))


@dataclass(frozen=True, slots=True)
class LLMEndpointSnapshot:
    """一次模型调用固定使用的端点快照。"""

    id: int | None
    category: LLMEndpointCategory | str
    protocol: LLMProtocol | str
    base_url: str
    api_key: str = field(repr=False)
    model: str
    thinking_enabled: bool = False
    thinking_format: OpenAIThinkingWireFormat | str = OpenAIThinkingWireFormat.NONE

    def __post_init__(self):
        if self.id is not None:
            try:
                endpoint_id = int(self.id)
            except (TypeError, ValueError):
                raise LLMEndpointValidationError("端点 ID 无效。") from None
            if endpoint_id <= 0:
                raise LLMEndpointValidationError("端点 ID 无效。")
            object.__setattr__(self, "id", endpoint_id)

        model = str(self.model or "").strip()
        api_key = str(self.api_key or "").strip()
        if not model:
            raise LLMEndpointValidationError("模型名称不能为空。")
        if not api_key:
            raise LLMEndpointValidationError("API Key 不能为空。")

        category = _enum_value(LLMEndpointCategory, self.category, "端点类别")
        protocol = _enum_value(LLMProtocol, self.protocol, "端点协议")
        thinking_enabled = _strict_bool(self.thinking_enabled, "思考开关")
        thinking_format = _enum_value(
            OpenAIThinkingWireFormat,
            self.thinking_format,
            "思考参数格式",
        )

        if category is LLMEndpointCategory.EMBEDDING:
            if protocol is not LLMProtocol.OPENAI:
                raise LLMEndpointValidationError("Embedding 端点仅支持 OpenAI-compatible 协议。")
            thinking_enabled = False
            thinking_format = OpenAIThinkingWireFormat.NONE
        elif (
            protocol is LLMProtocol.ANTHROPIC
            and thinking_format is OpenAIThinkingWireFormat.ENABLE_THINKING
        ):
            raise LLMEndpointValidationError(
                "Anthropic-compatible 协议不支持 enable_thinking 参数格式。"
            )
        elif thinking_format is OpenAIThinkingWireFormat.NONE:
            thinking_enabled = False

        object.__setattr__(self, "model", model)
        object.__setattr__(self, "api_key", api_key)
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "base_url", _normalize_base_url(self.base_url))
        object.__setattr__(self, "thinking_enabled", thinking_enabled)
        object.__setattr__(self, "thinking_format", thinking_format)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]):
        if not isinstance(value, Mapping):
            raise LLMEndpointValidationError("端点快照格式无效。")
        thinking_format = value.get("openai_thinking_format")
        if thinking_format is None:
            thinking_format = value.get("thinking_wire_format")
        if thinking_format is None:
            thinking_format = value.get("thinking_format", OpenAIThinkingWireFormat.NONE.value)
        return cls(
            id=value.get("id", value.get("endpoint_id")),
            category=value.get("category", ""),
            protocol=value.get("protocol", ""),
            base_url=value.get("base_url", ""),
            api_key=value.get("api_key", ""),
            model=value.get("model", ""),
            thinking_enabled=value.get("thinking_enabled", False),
            thinking_format=thinking_format,
        )

    @property
    def has_api_key(self):
        return bool(self.api_key)

    @property
    def openai_thinking_format(self):
        """兼容早期调用方；新代码统一使用 :attr:`thinking_format`。"""

        return self.thinking_format

    def to_public_dict(self):
        return {
            "id": self.id,
            "category": self.category.value,
            "protocol": self.protocol.value,
            "base_url": self.base_url,
            "model": self.model,
            "thinking_enabled": self.thinking_enabled,
            "thinking_format": self.thinking_format.value,
            "has_api_key": self.has_api_key,
        }


@dataclass(frozen=True, slots=True)
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True, slots=True)
class LLMToolCall:
    id: str
    name: str
    arguments: str

    def to_openai_dict(self):
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.arguments},
        }


@dataclass(frozen=True, slots=True)
class LLMChatResult:
    text: str
    reasoning: str = ""
    tool_calls: tuple[LLMToolCall, ...] = ()
    finish_reason: str | None = None
    model: str | None = None
    usage: LLMUsage = LLMUsage()

    def to_openai_message(self):
        message = {"role": "assistant", "content": self.text}
        if self.tool_calls:
            message["tool_calls"] = [call.to_openai_dict() for call in self.tool_calls]
        return message


@dataclass(frozen=True, slots=True)
class LLMEmbeddingResult:
    vectors: tuple[tuple[float, ...], ...]
    model: str | None = None
    usage: LLMUsage = LLMUsage()


@dataclass(frozen=True, slots=True)
class LLMEndpointProbeResult:
    ok: bool
    category: LLMEndpointCategory
    protocol: LLMProtocol
    latency_ms: int
    message: str

    @property
    def passed(self):
        return self.ok

    def to_tester_result(self):
        """转换为 ``site_config.services`` tester 接受的稳定字典。"""

        return {
            "passed": self.ok,
            "message": self.message,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True, slots=True)
class LLMImage:
    """远程图片 URL 或 ``data:image/...;base64,...``。"""

    source: str

    def __post_init__(self):
        source = str(self.source or "").strip()
        if not source:
            raise LLMEndpointValidationError("图片来源不能为空。")
        if source.startswith("data:"):
            _parse_image_data_url(source)
        else:
            parts = urlsplit(source)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                raise LLMEndpointValidationError("图片来源必须是 HTTP(S) URL 或 Base64 Data URL。")
            if parts.username is not None or parts.password is not None:
                raise LLMEndpointValidationError("图片 URL 不允许包含用户凭证。")
        object.__setattr__(self, "source", source)

    @classmethod
    def from_bytes(cls, data: bytes, media_type: str):
        use_type = str(media_type or "").strip().lower()
        if not use_type.startswith("image/"):
            raise LLMEndpointValidationError("图片 MIME 类型无效。")
        encoded = base64.b64encode(bytes(data)).decode("ascii")
        return cls(f"data:{use_type};base64,{encoded}")


def _coerce_endpoint(endpoint):
    if isinstance(endpoint, LLMEndpointSnapshot):
        return endpoint
    return LLMEndpointSnapshot.from_mapping(endpoint)


def _coerce_image(value):
    if isinstance(value, LLMImage):
        return value
    if isinstance(value, Mapping):
        source = value.get("source", value.get("url", ""))
        return LLMImage(source)
    return LLMImage(value)


def _parse_image_data_url(value):
    header, separator, encoded = str(value or "").partition(",")
    if not separator or not header.lower().startswith("data:image/") or not header.lower().endswith(";base64"):
        raise LLMEndpointValidationError("图片 Data URL 格式无效。")
    media_type = header[5:-7].strip().lower()
    if not media_type.startswith("image/"):
        raise LLMEndpointValidationError("图片 MIME 类型无效。")
    try:
        base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise LLMEndpointValidationError("图片 Base64 数据无效。") from None
    return media_type, encoded


def _append_path(base_url, suffix):
    parts = urlsplit(base_url)
    base_path = (parts.path or "").rstrip("/")
    use_suffix = "/" + str(suffix or "").strip("/")
    if use_suffix.startswith("/v1/") and base_path.lower().endswith("/v1"):
        use_suffix = use_suffix[len("/v1"):]
    return urlunsplit((parts.scheme, parts.netloc, base_path + use_suffix, "", ""))


def endpoint_request_url(endpoint, operation="chat"):
    use_endpoint = _coerce_endpoint(endpoint)
    operation = str(operation or "").strip().lower()
    if operation == "chat":
        suffix = "/chat/completions" if use_endpoint.protocol is LLMProtocol.OPENAI else "/v1/messages"
    elif operation == "embedding":
        if use_endpoint.protocol is not LLMProtocol.OPENAI:
            raise LLMEndpointValidationError("Embedding 仅支持 OpenAI-compatible 协议。")
        suffix = "/embeddings"
    else:
        raise LLMEndpointValidationError("端点操作类型无效。")
    return _append_path(use_endpoint.base_url, suffix)


def _request_headers(endpoint):
    if endpoint.protocol is LLMProtocol.OPENAI:
        return {
            "Authorization": f"Bearer {endpoint.api_key}",
            "Content-Type": "application/json",
        }
    return {
        "x-api-key": endpoint.api_key,
        "anthropic-version": _ANTHROPIC_VERSION,
        "Content-Type": "application/json",
    }


def _positive_int(value, field_name, *, allow_none=True):
    if value is None and allow_none:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise LLMEndpointValidationError(f"{field_name} 必须是正整数。") from None
    if result <= 0:
        raise LLMEndpointValidationError(f"{field_name} 必须是正整数。")
    return result


def _positive_float(value, field_name):
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise LLMEndpointValidationError(f"{field_name} 必须大于 0。") from None
    if not math.isfinite(result) or result <= 0:
        raise LLMEndpointValidationError(f"{field_name} 必须大于 0。")
    return result


def _json_copy(value, field_name):
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError):
        raise LLMEndpointValidationError(f"{field_name} 必须是可序列化的 JSON 数据。") from None


def _apply_thinking(endpoint, payload):
    # 管理员只配置“是否开启思考”。关闭时不向兼容端点发送任何思考字段；
    # 开启时只按协议选择通用 wire shape，不对具体模型厂商做分支。
    if (
        not endpoint.thinking_enabled
        or endpoint.thinking_format is OpenAIThinkingWireFormat.NONE
    ):
        return
    if endpoint.protocol is LLMProtocol.ANTHROPIC:
        if endpoint.thinking_format is OpenAIThinkingWireFormat.THINKING_TYPE:
            payload["thinking"] = {"type": "adaptive"}
        return
    # OpenAI-compatible 统一使用 enable_thinking；thinking_type 只作为旧数据
    # 的内部兼容值读取，不能改变协议层的通用请求形状。
    payload["enable_thinking"] = True


def _text_from_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, Mapping):
        value = content.get("text")
        if isinstance(value, str):
            return value
        if isinstance(value, Mapping) and isinstance(value.get("value"), str):
            return value["value"]
        return ""
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes, bytearray)):
        return "".join(_text_from_content(item) for item in content)
    return ""


def _canonical_content_blocks(content):
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if not isinstance(content, Sequence) or isinstance(content, (bytes, bytearray)):
        return [{"type": "text", "text": str(content)}]
    blocks = []
    for raw_item in content:
        if isinstance(raw_item, str):
            blocks.append({"type": "text", "text": raw_item})
            continue
        if not isinstance(raw_item, Mapping):
            raise LLMEndpointValidationError("消息内容块格式无效。")
        item = _json_copy(raw_item, "消息内容块")
        item_type = str(item.get("type") or "").strip().lower()
        if item_type in {"text", "input_text", "output_text"}:
            blocks.append({"type": "text", "text": _text_from_content(item)})
        elif item_type == "image_url":
            image_url = item.get("image_url")
            source = image_url.get("url") if isinstance(image_url, Mapping) else image_url
            blocks.append({"type": "image_url", "image_url": {"url": _coerce_image(source).source}})
        elif item_type == "image":
            source = item.get("source")
            if isinstance(source, Mapping):
                if source.get("type") == "url":
                    image = _coerce_image(source.get("url"))
                elif source.get("type") == "base64":
                    media_type = str(source.get("media_type") or "image/png")
                    try:
                        decoded = base64.b64decode(
                            str(source.get("data") or ""),
                            validate=True,
                        )
                    except (ValueError, binascii.Error):
                        raise LLMEndpointValidationError("图片 Base64 数据无效。") from None
                    image = LLMImage.from_bytes(decoded, media_type)
                else:
                    raise LLMEndpointValidationError("图片内容块来源无效。")
            else:
                image = _coerce_image(source)
            blocks.append({"type": "image_url", "image_url": {"url": image.source}})
        else:
            raise LLMEndpointValidationError("消息包含不支持的内容块。")
    return blocks


def _openai_messages(messages):
    if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes, bytearray)) or not messages:
        raise LLMEndpointValidationError("消息列表不能为空。")
    result = []
    for raw_message in messages:
        if not isinstance(raw_message, Mapping):
            raise LLMEndpointValidationError("消息格式无效。")
        role = str(raw_message.get("role") or "").strip().lower()
        if role not in {"system", "user", "assistant", "tool"}:
            raise LLMEndpointValidationError("消息角色无效。")
        item = {"role": role, "content": raw_message.get("content", "")}
        if isinstance(item["content"], Sequence) and not isinstance(item["content"], str):
            item["content"] = _canonical_content_blocks(item["content"])
        if role == "assistant" and raw_message.get("tool_calls"):
            item["tool_calls"] = _json_copy(raw_message.get("tool_calls"), "工具调用")
        if role == "tool":
            call_id = str(raw_message.get("tool_call_id") or "").strip()
            if not call_id:
                raise LLMEndpointValidationError("工具结果缺少 tool_call_id。")
            item["tool_call_id"] = call_id
            if raw_message.get("name") is not None:
                item["name"] = str(raw_message.get("name") or "")
        result.append(item)
    return result


def _anthropic_image_block(source):
    image = _coerce_image(source)
    if image.source.startswith("data:"):
        media_type, encoded = _parse_image_data_url(image.source)
        return {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": encoded,
            },
        }
    return {
        "type": "image",
        "source": {"type": "url", "url": image.source},
    }


def _anthropic_content_blocks(content):
    blocks = []
    for item in _canonical_content_blocks(content):
        if item["type"] == "text":
            blocks.append({"type": "text", "text": item.get("text", "")})
        else:
            blocks.append(_anthropic_image_block(item["image_url"]["url"]))
    return blocks


def _tool_call_parts(raw_call):
    if not isinstance(raw_call, Mapping):
        raise LLMEndpointValidationError("工具调用格式无效。")
    function = raw_call.get("function")
    if isinstance(function, Mapping):
        name = str(function.get("name") or "").strip()
        arguments = function.get("arguments", "{}")
    else:
        name = str(raw_call.get("name") or "").strip()
        arguments = raw_call.get("input", {})
    if not name:
        raise LLMEndpointValidationError("工具调用缺少名称。")
    if isinstance(arguments, str):
        try:
            parsed = json.loads(arguments or "{}")
        except json.JSONDecodeError:
            raise LLMEndpointValidationError("工具调用参数不是有效 JSON。") from None
    else:
        parsed = _json_copy(arguments, "工具调用参数")
    if not isinstance(parsed, Mapping):
        raise LLMEndpointValidationError("工具调用参数必须是 JSON 对象。")
    call_id = str(raw_call.get("id") or "").strip()
    if not call_id:
        raise LLMEndpointValidationError("工具调用缺少 ID。")
    return call_id, name, dict(parsed)


def _merge_anthropic_message(messages, role, blocks):
    if not blocks:
        blocks = [{"type": "text", "text": ""}]
    if messages and messages[-1]["role"] == role:
        previous = messages[-1]["content"]
        if isinstance(previous, str):
            previous = [{"type": "text", "text": previous}]
            messages[-1]["content"] = previous
        previous.extend(blocks)
    else:
        messages.append({"role": role, "content": blocks})


def _anthropic_messages(messages):
    if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes, bytearray)) or not messages:
        raise LLMEndpointValidationError("消息列表不能为空。")
    system_parts = []
    result = []
    for raw_message in messages:
        if not isinstance(raw_message, Mapping):
            raise LLMEndpointValidationError("消息格式无效。")
        role = str(raw_message.get("role") or "").strip().lower()
        if role == "system":
            text = _text_from_content(raw_message.get("content"))
            if text:
                system_parts.append(text)
            continue
        if role == "tool":
            call_id = str(raw_message.get("tool_call_id") or "").strip()
            if not call_id:
                raise LLMEndpointValidationError("工具结果缺少 tool_call_id。")
            block = {
                "type": "tool_result",
                "tool_use_id": call_id,
                "content": _text_from_content(raw_message.get("content")),
            }
            _merge_anthropic_message(result, "user", [block])
            continue
        if role not in {"user", "assistant"}:
            raise LLMEndpointValidationError("消息角色无效。")
        blocks = [
            block
            for block in _anthropic_content_blocks(raw_message.get("content", ""))
            if block.get("type") != "text" or str(block.get("text") or "")
        ]
        if role == "assistant":
            for raw_call in raw_message.get("tool_calls") or []:
                call_id, name, arguments = _tool_call_parts(raw_call)
                blocks.append({
                    "type": "tool_use",
                    "id": call_id,
                    "name": name,
                    "input": arguments,
                })
        _merge_anthropic_message(result, role, blocks)
    if not result:
        raise LLMEndpointValidationError("消息列表缺少 user 或 assistant 消息。")
    return "\n\n".join(system_parts), result


def _anthropic_tools(tools):
    if not tools:
        return []
    result = []
    for raw_tool in tools:
        if not isinstance(raw_tool, Mapping):
            raise LLMEndpointValidationError("工具定义格式无效。")
        function = raw_tool.get("function")
        if isinstance(function, Mapping):
            name = function.get("name")
            description = function.get("description")
            parameters = function.get("parameters", {"type": "object", "properties": {}})
        else:
            name = raw_tool.get("name")
            description = raw_tool.get("description")
            parameters = raw_tool.get("input_schema", {"type": "object", "properties": {}})
        name = str(name or "").strip()
        if not name:
            raise LLMEndpointValidationError("工具定义缺少名称。")
        item = {
            "name": name,
            "input_schema": _json_copy(parameters, "工具参数定义"),
        }
        if description is not None:
            item["description"] = str(description)
        result.append(item)
    return result


def _anthropic_tool_choice(tool_choice):
    if tool_choice is None:
        return None
    if isinstance(tool_choice, str):
        mapping = {
            "auto": {"type": "auto"},
            "none": {"type": "none"},
            "required": {"type": "any"},
            "any": {"type": "any"},
        }
        result = mapping.get(tool_choice.strip().lower())
        if result is None:
            raise LLMEndpointValidationError("tool_choice 取值无效。")
        return result
    if not isinstance(tool_choice, Mapping):
        raise LLMEndpointValidationError("tool_choice 格式无效。")
    if tool_choice.get("type") == "function" and isinstance(tool_choice.get("function"), Mapping):
        name = str(tool_choice["function"].get("name") or "").strip()
        if not name:
            raise LLMEndpointValidationError("tool_choice 缺少工具名称。")
        return {"type": "tool", "name": name}
    use_type = str(tool_choice.get("type") or "").strip().lower()
    if use_type in {"auto", "none", "any"}:
        return {"type": use_type}
    if use_type == "tool" and str(tool_choice.get("name") or "").strip():
        return {"type": "tool", "name": str(tool_choice["name"]).strip()}
    raise LLMEndpointValidationError("tool_choice 格式无效。")


def _build_chat_payload(
    endpoint,
    messages,
    *,
    tools=None,
    tool_choice=None,
    temperature=None,
    max_tokens=None,
    stream=False,
):
    max_tokens = _positive_int(max_tokens, "max_tokens")
    if endpoint.protocol is LLMProtocol.OPENAI:
        payload = {
            "model": endpoint.model,
            "messages": _openai_messages(messages),
            "stream": bool(stream),
        }
        if tools:
            payload["tools"] = _json_copy(tools, "工具定义")
            if tool_choice is not None:
                payload["tool_choice"] = _json_copy(tool_choice, "tool_choice") if not isinstance(tool_choice, str) else tool_choice
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
    else:
        system, anthropic_messages = _anthropic_messages(messages)
        payload = {
            "model": endpoint.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens or _DEFAULT_ANTHROPIC_MAX_TOKENS,
            "stream": bool(stream),
        }
        if system:
            payload["system"] = system
        if tools:
            payload["tools"] = _anthropic_tools(tools)
            use_choice = _anthropic_tool_choice(tool_choice)
            if use_choice is not None:
                payload["tool_choice"] = use_choice
    if temperature is not None:
        try:
            use_temperature = float(temperature)
        except (TypeError, ValueError):
            raise LLMEndpointValidationError("temperature 必须是数字。") from None
        if not math.isfinite(use_temperature):
            raise LLMEndpointValidationError("temperature 必须是有限数字。")
        payload["temperature"] = use_temperature
    _apply_thinking(endpoint, payload)
    return payload


def _status_error(status_code):
    try:
        status = int(status_code)
    except (TypeError, ValueError):
        status = 0
    if status in {401, 403}:
        message = f"模型端点鉴权失败（HTTP {status}）。"
    elif status == 404:
        message = "模型端点请求地址或模型不存在（HTTP 404）。"
    elif status == 429:
        message = "模型端点触发限流（HTTP 429）。"
    elif status >= 500:
        message = f"模型端点服务异常（HTTP {status}）。"
    else:
        message = f"模型端点请求失败（HTTP {status}）。" if status else "模型端点请求失败。"
    return LLMEndpointRequestError(message, status_code=status or None)


def _post(endpoint, payload, *, timeout, stream):
    try:
        response = requests.post(
            endpoint_request_url(endpoint, "chat"),
            headers=_request_headers(endpoint),
            json=payload,
            timeout=float(timeout),
            stream=bool(stream),
        )
    except Exception:
        raise LLMEndpointRequestError("无法连接模型端点。") from None
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        try:
            response.close()
        except Exception:
            pass
        raise _status_error(response.status_code)
    return response


def _parse_usage(data, protocol):
    usage = data if isinstance(data, Mapping) else {}
    if protocol is LLMProtocol.OPENAI:
        input_tokens = usage.get("prompt_tokens", usage.get("input_tokens", 0))
        output_tokens = usage.get("completion_tokens", usage.get("output_tokens", 0))
    else:
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
    try:
        input_tokens = int(input_tokens or 0)
    except (TypeError, ValueError):
        input_tokens = 0
    try:
        output_tokens = int(output_tokens or 0)
    except (TypeError, ValueError):
        output_tokens = 0
    try:
        total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens))
    except (TypeError, ValueError):
        total_tokens = input_tokens + output_tokens
    return LLMUsage(input_tokens, output_tokens, total_tokens)


def _tool_call_from_openai(raw_call, index):
    if not isinstance(raw_call, Mapping):
        return None
    function = raw_call.get("function") if isinstance(raw_call.get("function"), Mapping) else {}
    name = str(function.get("name") or "").strip()
    if not name:
        return None
    arguments = function.get("arguments", "{}")
    if not isinstance(arguments, str):
        arguments = json.dumps(arguments or {}, ensure_ascii=False, separators=(",", ":"))
    call_id = str(raw_call.get("id") or f"call_{index}").strip()
    return LLMToolCall(call_id, name, arguments)


def _parse_openai_response(data):
    if not isinstance(data, Mapping):
        raise LLMEndpointResponseError("模型端点返回的 JSON 格式无效。")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        raise LLMEndpointResponseError("模型端点未返回有效 choices。")
    choice = choices[0]
    message = choice.get("message") if isinstance(choice.get("message"), Mapping) else {}
    text = _text_from_content(message.get("content"))
    reasoning = _text_from_content(message.get("reasoning_content"))
    tool_calls = []
    for index, raw_call in enumerate(message.get("tool_calls") or []):
        call = _tool_call_from_openai(raw_call, index)
        if call is not None:
            tool_calls.append(call)
    if not text and not tool_calls and not reasoning:
        raise LLMEndpointResponseError("模型端点未返回文本、思考内容或工具调用。")
    return LLMChatResult(
        text=text,
        reasoning=reasoning,
        tool_calls=tuple(tool_calls),
        finish_reason=str(choice.get("finish_reason")) if choice.get("finish_reason") is not None else None,
        model=str(data.get("model")) if data.get("model") is not None else None,
        usage=_parse_usage(data.get("usage"), LLMProtocol.OPENAI),
    )


def _parse_anthropic_response(data):
    if not isinstance(data, Mapping):
        raise LLMEndpointResponseError("模型端点返回的 JSON 格式无效。")
    content = data.get("content")
    if not isinstance(content, list):
        raise LLMEndpointResponseError("模型端点未返回有效 content。")
    text_parts = []
    reasoning_parts = []
    tool_calls = []
    for index, block in enumerate(content):
        if not isinstance(block, Mapping):
            continue
        block_type = str(block.get("type") or "").strip().lower()
        if block_type == "text":
            text_parts.append(_text_from_content(block))
        elif block_type in {"thinking", "redacted_thinking"}:
            reasoning_parts.append(str(block.get("thinking") or ""))
        elif block_type == "tool_use":
            name = str(block.get("name") or "").strip()
            if not name:
                continue
            arguments = json.dumps(block.get("input") or {}, ensure_ascii=False, separators=(",", ":"))
            tool_calls.append(LLMToolCall(str(block.get("id") or f"call_{index}"), name, arguments))
    text = "".join(text_parts)
    reasoning = "".join(reasoning_parts)
    if not text and not tool_calls and not reasoning:
        raise LLMEndpointResponseError("模型端点未返回文本、思考内容或工具调用。")
    return LLMChatResult(
        text=text,
        reasoning=reasoning,
        tool_calls=tuple(tool_calls),
        finish_reason=str(data.get("stop_reason")) if data.get("stop_reason") is not None else None,
        model=str(data.get("model")) if data.get("model") is not None else None,
        usage=_parse_usage(data.get("usage"), LLMProtocol.ANTHROPIC),
    )


def _response_json(response):
    try:
        return response.json()
    except Exception:
        raise LLMEndpointResponseError("模型端点返回的内容不是有效 JSON。") from None
    finally:
        try:
            response.close()
        except Exception:
            pass


def _iter_sse_json(response):
    data_lines = []
    try:
        for raw_line in response.iter_lines(decode_unicode=True):
            if isinstance(raw_line, bytes):
                line = raw_line.decode("utf-8", errors="replace")
            else:
                line = str(raw_line or "")
            if not line:
                if data_lines:
                    joined = "\n".join(data_lines)
                    data_lines = []
                    if joined.strip() != "[DONE]":
                        try:
                            yield json.loads(joined)
                        except json.JSONDecodeError:
                            raise LLMEndpointResponseError("模型端点返回了无效的流式事件。") from None
                continue
            if line.startswith(":") or line.startswith("event:") or line.startswith("id:"):
                continue
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        if data_lines:
            joined = "\n".join(data_lines)
            if joined.strip() != "[DONE]":
                try:
                    yield json.loads(joined)
                except json.JSONDecodeError:
                    raise LLMEndpointResponseError("模型端点返回了无效的流式事件。") from None
    finally:
        try:
            response.close()
        except Exception:
            pass


def _emit_delta(callback, text):
    if text and callable(callback):
        callback(text)


def _parse_openai_stream(response, on_text_delta):
    text_parts = []
    reasoning_parts = []
    finish_reason = None
    model = None
    usage = LLMUsage()
    tool_states = {}
    saw_event = False
    for event in _iter_sse_json(response):
        if not isinstance(event, Mapping):
            continue
        saw_event = True
        if event.get("model") is not None:
            model = str(event["model"])
        if event.get("usage") is not None:
            usage = _parse_usage(event.get("usage"), LLMProtocol.OPENAI)
        choices = event.get("choices") or []
        if not choices or not isinstance(choices[0], Mapping):
            continue
        choice = choices[0]
        if choice.get("finish_reason") is not None:
            finish_reason = str(choice["finish_reason"])
        delta = choice.get("delta") if isinstance(choice.get("delta"), Mapping) else {}
        delta_text = _text_from_content(delta.get("content"))
        if delta_text:
            text_parts.append(delta_text)
            _emit_delta(on_text_delta, delta_text)
        delta_reasoning = _text_from_content(delta.get("reasoning_content"))
        if delta_reasoning:
            reasoning_parts.append(delta_reasoning)
        for fallback_index, raw_call in enumerate(delta.get("tool_calls") or []):
            if not isinstance(raw_call, Mapping):
                continue
            try:
                index = int(raw_call.get("index", fallback_index))
            except (TypeError, ValueError):
                index = fallback_index
            state = tool_states.setdefault(index, {"id": "", "name": "", "arguments": []})
            if raw_call.get("id"):
                state["id"] = str(raw_call["id"])
            function = raw_call.get("function") if isinstance(raw_call.get("function"), Mapping) else {}
            if function.get("name"):
                state["name"] += str(function["name"])
            if function.get("arguments"):
                state["arguments"].append(str(function["arguments"]))
    if not saw_event:
        raise LLMEndpointResponseError("模型端点未返回流式事件。")
    tool_calls = []
    for index in sorted(tool_states):
        state = tool_states[index]
        if state["name"]:
            tool_calls.append(LLMToolCall(
                state["id"] or f"call_{index}",
                state["name"],
                "".join(state["arguments"]) or "{}",
            ))
    text = "".join(text_parts)
    reasoning = "".join(reasoning_parts)
    if not text and not reasoning and not tool_calls:
        raise LLMEndpointResponseError("模型端点未返回文本、思考内容或工具调用。")
    return LLMChatResult(text, reasoning, tuple(tool_calls), finish_reason, model, usage)


def _parse_anthropic_stream(response, on_text_delta):
    text_parts = []
    reasoning_parts = []
    finish_reason = None
    model = None
    input_tokens = 0
    output_tokens = 0
    blocks = {}
    saw_event = False
    for event in _iter_sse_json(response):
        if not isinstance(event, Mapping):
            continue
        saw_event = True
        event_type = str(event.get("type") or "")
        if event_type == "message_start":
            message = event.get("message") if isinstance(event.get("message"), Mapping) else {}
            if message.get("model") is not None:
                model = str(message["model"])
            usage = _parse_usage(message.get("usage"), LLMProtocol.ANTHROPIC)
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
        elif event_type == "content_block_start":
            try:
                index = int(event.get("index", len(blocks)))
            except (TypeError, ValueError):
                index = len(blocks)
            block = event.get("content_block") if isinstance(event.get("content_block"), Mapping) else {}
            block_type = str(block.get("type") or "")
            state = {
                "type": block_type,
                "id": str(block.get("id") or f"call_{index}"),
                "name": str(block.get("name") or ""),
                "json": [],
                "initial_input": block.get("input"),
            }
            blocks[index] = state
            if block_type == "text" and block.get("text"):
                delta_text = str(block["text"])
                text_parts.append(delta_text)
                _emit_delta(on_text_delta, delta_text)
            elif block_type == "thinking" and block.get("thinking"):
                reasoning_parts.append(str(block["thinking"]))
        elif event_type == "content_block_delta":
            try:
                index = int(event.get("index", 0))
            except (TypeError, ValueError):
                index = 0
            state = blocks.setdefault(index, {
                "type": "", "id": f"call_{index}", "name": "", "json": [], "initial_input": None,
            })
            delta = event.get("delta") if isinstance(event.get("delta"), Mapping) else {}
            delta_type = str(delta.get("type") or "")
            if delta_type == "text_delta" or delta.get("text") is not None:
                delta_text = str(delta.get("text") or "")
                text_parts.append(delta_text)
                _emit_delta(on_text_delta, delta_text)
            elif delta_type == "thinking_delta" or delta.get("thinking") is not None:
                reasoning_parts.append(str(delta.get("thinking") or ""))
            elif delta_type == "input_json_delta" or delta.get("partial_json") is not None:
                state["json"].append(str(delta.get("partial_json") or ""))
        elif event_type == "message_delta":
            delta = event.get("delta") if isinstance(event.get("delta"), Mapping) else {}
            if delta.get("stop_reason") is not None:
                finish_reason = str(delta["stop_reason"])
            usage = _parse_usage(event.get("usage"), LLMProtocol.ANTHROPIC)
            output_tokens = max(output_tokens, usage.output_tokens)
    if not saw_event:
        raise LLMEndpointResponseError("模型端点未返回流式事件。")
    tool_calls = []
    for index in sorted(blocks):
        state = blocks[index]
        if state["type"] != "tool_use" or not state["name"]:
            continue
        arguments = "".join(state["json"])
        if not arguments:
            arguments = json.dumps(state["initial_input"] or {}, ensure_ascii=False, separators=(",", ":"))
        tool_calls.append(LLMToolCall(state["id"], state["name"], arguments))
    text = "".join(text_parts)
    reasoning = "".join(reasoning_parts)
    if not text and not reasoning and not tool_calls:
        raise LLMEndpointResponseError("模型端点未返回文本、思考内容或工具调用。")
    usage = LLMUsage(input_tokens, output_tokens, input_tokens + output_tokens)
    return LLMChatResult(text, reasoning, tuple(tool_calls), finish_reason, model, usage)


def call_chat(
    endpoint,
    messages,
    *,
    tools=None,
    tool_choice=None,
    temperature=None,
    max_tokens=None,
    timeout=300,
    stream=False,
    on_text_delta: Callable[[str], None] | None = None,
):
    """调用文本/全模态端点，返回统一的消息、工具调用与 usage。"""

    use_endpoint = _coerce_endpoint(endpoint)
    if use_endpoint.category not in _CHAT_CATEGORIES:
        raise LLMEndpointValidationError("该类别端点不能用于文本或 Agent 调用。")
    timeout_value = _positive_float(timeout, "timeout")
    use_stream = bool(stream or on_text_delta is not None)
    payload = _build_chat_payload(
        use_endpoint,
        messages,
        tools=tools,
        tool_choice=tool_choice,
        temperature=temperature,
        max_tokens=max_tokens,
        stream=use_stream,
    )
    response = _post(use_endpoint, payload, timeout=timeout_value, stream=use_stream)
    content_type = str(getattr(response, "headers", {}).get("Content-Type", "")).lower()
    if use_stream and "text/event-stream" in content_type:
        if use_endpoint.protocol is LLMProtocol.OPENAI:
            return _parse_openai_stream(response, on_text_delta)
        return _parse_anthropic_stream(response, on_text_delta)
    data = _response_json(response)
    if use_endpoint.protocol is LLMProtocol.OPENAI:
        result = _parse_openai_response(data)
    else:
        result = _parse_anthropic_response(data)
    if callable(on_text_delta) and result.text:
        on_text_delta(result.text)
    return result


def call_text(
    endpoint,
    prompt,
    *,
    system_prompt=None,
    tools=None,
    tool_choice=None,
    temperature=None,
    max_tokens=None,
    timeout=300,
    stream=False,
    on_text_delta: Callable[[str], None] | None = None,
):
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": str(system_prompt)})
    messages.append({"role": "user", "content": str(prompt or "")})
    return call_chat(
        endpoint,
        messages,
        tools=tools,
        tool_choice=tool_choice,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        stream=stream,
        on_text_delta=on_text_delta,
    )


def call_vision(
    endpoint,
    prompt,
    images,
    *,
    system_prompt=None,
    temperature=None,
    max_tokens=None,
    timeout=300,
    stream=False,
    on_text_delta: Callable[[str], None] | None = None,
):
    """调用视觉/全模态端点；图片可为远程 URL、Data URL 或 :class:`LLMImage`。"""

    use_endpoint = _coerce_endpoint(endpoint)
    if use_endpoint.category not in _VISION_CATEGORIES:
        raise LLMEndpointValidationError("该类别端点不能用于视觉调用。")
    use_images = [_coerce_image(image) for image in (images or [])]
    if not use_images:
        raise LLMEndpointValidationError("视觉调用至少需要一张图片。")
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": str(system_prompt)})
    content = [
        {"type": "image_url", "image_url": {"url": image.source}}
        for image in use_images
    ]
    content.append({"type": "text", "text": str(prompt or "")})
    messages.append({"role": "user", "content": content})

    timeout_value = _positive_float(timeout, "timeout")
    use_stream = bool(stream or on_text_delta is not None)
    payload = _build_chat_payload(
        use_endpoint,
        messages,
        temperature=temperature,
        max_tokens=max_tokens,
        stream=use_stream,
    )
    response = _post(use_endpoint, payload, timeout=timeout_value, stream=use_stream)
    content_type = str(getattr(response, "headers", {}).get("Content-Type", "")).lower()
    if use_stream and "text/event-stream" in content_type:
        if use_endpoint.protocol is LLMProtocol.OPENAI:
            return _parse_openai_stream(response, on_text_delta)
        return _parse_anthropic_stream(response, on_text_delta)
    data = _response_json(response)
    if use_endpoint.protocol is LLMProtocol.OPENAI:
        result = _parse_openai_response(data)
    else:
        result = _parse_anthropic_response(data)
    if callable(on_text_delta) and result.text:
        on_text_delta(result.text)
    return result


def create_embeddings(endpoint, texts, *, timeout=120, dimensions=None):
    """通过 OpenAI-compatible ``/embeddings`` 创建向量。"""

    use_endpoint = _coerce_endpoint(endpoint)
    if use_endpoint.category is not LLMEndpointCategory.EMBEDDING:
        raise LLMEndpointValidationError("该类别端点不能用于 Embedding。")
    if use_endpoint.protocol is not LLMProtocol.OPENAI:
        raise LLMEndpointValidationError("Embedding 仅支持 OpenAI-compatible 协议。")
    timeout_value = _positive_float(timeout, "timeout")
    use_texts = [str(text or "") for text in (texts or [])]
    if not use_texts:
        return LLMEmbeddingResult((), model=use_endpoint.model)
    payload = {"model": use_endpoint.model, "input": use_texts}
    if dimensions is not None:
        payload["dimensions"] = _positive_int(dimensions, "dimensions", allow_none=False)
    try:
        response = requests.post(
            endpoint_request_url(use_endpoint, "embedding"),
            headers=_request_headers(use_endpoint),
            json=payload,
            timeout=timeout_value,
        )
    except Exception:
        raise LLMEndpointRequestError("无法连接 Embedding 端点。") from None
    if int(getattr(response, "status_code", 0) or 0) >= 400:
        try:
            response.close()
        except Exception:
            pass
        raise _status_error(response.status_code)
    data = _response_json(response)
    items = data.get("data") if isinstance(data, Mapping) else None
    if not isinstance(items, list) or len(items) != len(use_texts):
        raise LLMEndpointResponseError("Embedding 端点返回的向量数量不匹配。")
    try:
        ordered = sorted(items, key=lambda item: int(item.get("index", 0)))
        vectors = tuple(
            tuple(float(component) for component in item["embedding"])
            for item in ordered
        )
    except (KeyError, TypeError, ValueError):
        raise LLMEndpointResponseError("Embedding 端点返回了无效向量。") from None
    if any(not vector for vector in vectors):
        raise LLMEndpointResponseError("Embedding 端点返回了空向量。")
    return LLMEmbeddingResult(
        vectors=vectors,
        model=str(data.get("model")) if data.get("model") is not None else None,
        usage=_parse_usage(data.get("usage"), LLMProtocol.OPENAI),
    )


def _png_chunk(kind, data):
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def _probe_image():
    width = height = 256
    row = b"\x00" + (b"\xff\xff\xff" * width)
    raw = row * height
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(raw, 9))
        + _png_chunk(b"IEND", b"")
    )
    return LLMImage.from_bytes(png, "image/png")


def probe_endpoint(endpoint, *, timeout=30):
    """按声明类别执行一次真实、最小且不写外部状态的连通性测试。"""

    use_endpoint = _coerce_endpoint(endpoint)
    started = time.monotonic()
    try:
        if use_endpoint.category is LLMEndpointCategory.TEXT:
            result = call_text(
                use_endpoint,
                "只回复 OK。",
                max_tokens=_PROBE_MAX_TOKENS,
                timeout=timeout,
            )
            if not result.text.strip():
                raise LLMEndpointResponseError("文本端点未返回可用文本。")
        elif use_endpoint.category in _VISION_CATEGORIES:
            result = call_vision(
                use_endpoint,
                "只回复这张图片的主要颜色。",
                [_probe_image()],
                max_tokens=_PROBE_MAX_TOKENS,
                timeout=timeout,
            )
            if not result.text.strip():
                raise LLMEndpointResponseError("视觉端点未返回可用文本。")
        else:
            result = create_embeddings(
                use_endpoint,
                ["NumericalOJ endpoint connectivity probe"],
                timeout=timeout,
            )
            if not result.vectors or not result.vectors[0]:
                raise LLMEndpointResponseError("Embedding 端点未返回可用向量。")
    except LLMEndpointError as exc:
        return LLMEndpointProbeResult(
            ok=False,
            category=use_endpoint.category,
            protocol=use_endpoint.protocol,
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
            message=str(exc),
        )
    except Exception:
        return LLMEndpointProbeResult(
            ok=False,
            category=use_endpoint.category,
            protocol=use_endpoint.protocol,
            latency_ms=max(0, int((time.monotonic() - started) * 1000)),
            message="端点测试失败。",
        )
    return LLMEndpointProbeResult(
        ok=True,
        category=use_endpoint.category,
        protocol=use_endpoint.protocol,
        latency_ms=max(0, int((time.monotonic() - started) * 1000)),
        message="端点测试成功。",
    )


def test_endpoint_candidate(candidate, *, timeout=30):
    """可直接注入动态配置服务的同步 tester。

    ``candidate`` 使用配置层的普通字典结构；返回值故意只包含测试状态、
    安全消息和耗时，不回显 API Key 或请求载荷。
    """

    started = time.monotonic()
    try:
        return probe_endpoint(candidate, timeout=timeout).to_tester_result()
    except LLMEndpointError as exc:
        message = str(exc)
    except Exception:
        message = "端点测试失败。"
    return {
        "passed": False,
        "message": message,
        "latency_ms": max(0, int((time.monotonic() - started) * 1000)),
    }


__all__ = [
    "LLMChatResult",
    "LLMEmbeddingResult",
    "LLMEndpointCategory",
    "LLMEndpointError",
    "LLMEndpointProbeResult",
    "LLMEndpointRequestError",
    "LLMEndpointResponseError",
    "LLMEndpointSnapshot",
    "LLMEndpointValidationError",
    "LLMImage",
    "LLMProtocol",
    "LLMToolCall",
    "LLMUsage",
    "OpenAIThinkingWireFormat",
    "call_chat",
    "call_text",
    "call_vision",
    "create_embeddings",
    "endpoint_request_url",
    "probe_endpoint",
    "test_endpoint_candidate",
]
