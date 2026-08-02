#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
from html import unescape

import httpx

from config import DASHSCOPE_API_KEY, MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS


_ALIYUN_WEBSEARCH_MCP_BASE_URL = "https://dashscope.aliyuncs.com/api/v1/mcps/WebSearch/mcp"
_DEFAULT_SEARCH_TOOL_NAME = "bailian_web_search"


def _clamp_int(value, default, min_value=None, max_value=None):
    try:
        val = int(value)
    except Exception:
        val = int(default)
    if min_value is not None and val < int(min_value):
        val = int(min_value)
    if max_value is not None and val > int(max_value):
        val = int(max_value)
    return val


def _is_placeholder_key(value):
    key = str(value or "").strip()
    if not key:
        return True
    upper = key.upper()
    if "YOUR" in upper and "KEY" in upper:
        return True
    return False


def _resolve_runtime_settings(timeout_seconds):
    env = os.environ
    base_url = str(env.get("MODELSCOPE_WEB_SEARCH_MCP_BASE_URL") or "").strip() or _ALIYUN_WEBSEARCH_MCP_BASE_URL
    auth_header = str(env.get("MODELSCOPE_WEB_SEARCH_MCP_AUTHORIZATION") or "").strip()
    if not auth_header:
        key = str(env.get("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY or "").strip()
        if _is_placeholder_key(key):
            key = ""
        if key:
            auth_header = f"Bearer {key}"
    if not auth_header:
        raise RuntimeError("未配置有效的 DASHSCOPE_API_KEY，无法调用阿里云 WebSearch MCP。")

    env_timeout = os.environ.get("MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS")
    timeout_seed = env_timeout if env_timeout is not None else MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS
    use_timeout = _clamp_int(timeout_seconds, timeout_seed, min_value=10, max_value=240)

    configured_tool_name = str(env.get("MODELSCOPE_WEB_SEARCH_MCP_TOOL_NAME") or "").strip()
    if not configured_tool_name:
        configured_tool_name = _DEFAULT_SEARCH_TOOL_NAME
    return base_url, auth_header, configured_tool_name, use_timeout


def _make_http_headers(auth_header):
    return {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }


def _post_jsonrpc(client, base_url, headers, payload):
    resp = client.post(base_url, headers=headers, json=payload)
    status = int(resp.status_code)
    if status < 200 or status >= 300:
        hint = ""
        try:
            hint = resp.text[:800]
        except Exception:
            hint = ""
        raise RuntimeError(f"MCP HTTP 调用失败: status={status}, body={hint}")

    body_text = str(resp.text or "").strip()
    if not body_text:
        return {}

    try:
        msg = json.loads(body_text)
    except Exception as ex:
        raise RuntimeError(f"MCP 返回非 JSON 响应: {body_text[:400]}") from ex

    if isinstance(msg, dict) and msg.get("error"):
        raise RuntimeError(f"MCP JSON-RPC 返回错误: {msg.get('error')}")
    return msg if isinstance(msg, dict) else {}


def _extract_text_blocks_from_tool_response(tool_response):
    content_items = (
        tool_response.get("tool_response", {}).get("result", {}).get("content")
        if isinstance(tool_response.get("tool_response"), dict)
        else None
    )
    if not isinstance(content_items, list):
        content_items = []
    text_blocks = []
    for item in content_items:
        if isinstance(item, dict) and item.get("type") == "text":
            text_blocks.append(str(item.get("text") or ""))
    return "\n".join([x for x in text_blocks if x.strip()]).strip()


def _resolve_search_tool_name(client, base_url, headers, configured_tool_name):
    list_resp = _post_jsonrpc(
        client,
        base_url,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
    )
    tools = list_resp.get("result", {}).get("tools")
    if not isinstance(tools, list):
        tools = []
    names = [str(item.get("name") or "").strip() for item in tools if isinstance(item, dict)]
    names = [x for x in names if x]
    if configured_tool_name in names:
        return configured_tool_name
    if _DEFAULT_SEARCH_TOOL_NAME in names:
        return _DEFAULT_SEARCH_TOOL_NAME
    for name in names:
        if "search" in name.lower():
            return name
    if names:
        return names[0]
    return configured_tool_name


def _call_web_mcp_tool(tool_name, arguments, timeout_seconds=None):
    base_url, auth_header, configured_tool_name, use_timeout = _resolve_runtime_settings(timeout_seconds)
    headers = _make_http_headers(auth_header)
    use_tool_name = str(tool_name or "").strip() or configured_tool_name

    with httpx.Client(timeout=float(use_timeout), follow_redirects=True) as client:
        init_resp = _post_jsonrpc(
            client,
            base_url,
            headers,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "numericaloj-agent", "version": "1.0.0"},
                },
            },
        )
        if not isinstance(init_resp, dict) or not isinstance(init_resp.get("result"), dict):
            raise RuntimeError(f"MCP initialize 失败: {init_resp}")

        _post_jsonrpc(
            client,
            base_url,
            headers,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
        )

        if use_tool_name == configured_tool_name:
            use_tool_name = _resolve_search_tool_name(client, base_url, headers, configured_tool_name)

        tool_resp = _post_jsonrpc(
            client,
            base_url,
            headers,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": use_tool_name,
                    "arguments": arguments if isinstance(arguments, dict) else {},
                },
            },
        )

    return {
        "tool_name": use_tool_name,
        "tool_response": tool_resp,
    }


def web_search_via_modelscope_mcp(query, limit=5, engines=None, timeout_seconds=None):
    use_query = str(query or "").strip()
    if not use_query:
        raise RuntimeError("query 不能为空。")

    use_limit = _clamp_int(limit, 5, min_value=1, max_value=50)
    search_args = {
        "query": use_query,
        "count": use_limit,
    }

    result = _call_web_mcp_tool(
        tool_name="",
        arguments=search_args,
        timeout_seconds=timeout_seconds,
    )

    raw_text = _extract_text_blocks_from_tool_response(result)
    parsed = {}
    if raw_text:
        try:
            parsed = json.loads(raw_text)
        except Exception:
            parsed = {}

    pages = parsed.get("pages") if isinstance(parsed.get("pages"), list) else []
    normalized = []
    for item in pages[:use_limit]:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "title": str(item.get("title") or "").strip(),
                "url": str(item.get("url") or "").strip(),
                "description": str(item.get("snippet") or "").strip(),
                "source": str(item.get("hostname") or "").strip(),
                "engine": str(result.get("tool_name") or "").strip(),
            }
        )

    # Aliyun WebSearch MCP 不支持显式 engine 参数，保留字段以兼容旧调用方。
    _ = engines

    return {
        "query": use_query,
        "limit": use_limit,
        "engines": [str(result.get("tool_name") or "").strip()],
        "total_results": int(len(normalized)),
        "result_count": len(normalized),
        "results": normalized,
        "raw_text": raw_text if not normalized else "",
    }


def _html_to_plain_text(html, max_chars):
    text = str(html or "")
    title = ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if title_match:
        title = unescape(re.sub(r"\s+", " ", title_match.group(1))).strip()

    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", text)
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?is)<noscript[^>]*>.*?</noscript>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars]
    return title, text


def web_fetch_content_via_modelscope_mcp(url, max_chars=30000, timeout_seconds=None):
    use_url = str(url or "").strip()
    if not use_url:
        raise RuntimeError("url 不能为空。")
    use_max_chars = _clamp_int(max_chars, 30000, min_value=1000, max_value=200000)
    use_timeout = _clamp_int(timeout_seconds, MODELSCOPE_WEB_SEARCH_TIMEOUT_SECONDS, min_value=10, max_value=240)

    headers = {
        "User-Agent": "Mozilla/5.0 (NumericalOJ-Agent; +https://example.com)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    status = None
    error = ""
    final_url = use_url
    content_type = ""
    raw_text = ""
    try:
        with httpx.Client(timeout=float(use_timeout), follow_redirects=True, headers=headers) as client:
            resp = client.get(use_url)
            status = int(resp.status_code)
            final_url = str(resp.url)
            content_type = str(resp.headers.get("content-type") or "").lower()
            raw_text = str(resp.text or "")
            if status < 200 or status >= 400:
                body_hint = raw_text[:300]
                error = f"抓取网页失败: status={status}, body={body_hint}"
    except Exception as ex:
        error = f"抓取网页异常: {ex}"

    if "html" in content_type or "<html" in raw_text.lower():
        title, content = _html_to_plain_text(raw_text, use_max_chars)
    else:
        title, content = "", raw_text[:use_max_chars]

    return {
        "url": final_url,
        "title": title,
        "max_chars": use_max_chars,
        "content": content,
        "content_length": len(content),
        "status_code": status,
        "error": error,
        "raw_text": raw_text[:use_max_chars] if not content else "",
    }
