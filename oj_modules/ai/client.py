"""OpenAI 兼容模型端点解析与文本/多模态调用。"""

import requests

from config import DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL, QWEN_TEXT_MODEL

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def _extract_text_from_response_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict) and isinstance(item.get('text'), str):
                parts.append(item['text'])
        return ''.join(parts)
    return ""

def _is_invalid_secret(value):
    text = str(value or "").strip()
    return (not text) or ("YOUR" in text.upper())


def _resolve_dashscope_base_url():
    base_url = str(DASHSCOPE_BASE_URL or "").strip().rstrip("/")
    if not base_url:
        raise RuntimeError("未配置 DASHSCOPE_BASE_URL。")
    return base_url


def _post_chat_completions(base_url, headers, payload, timeout):
    url = f"{str(base_url).rstrip('/')}/chat/completions"
    return requests.post(url, headers=headers, json=payload, timeout=timeout)


def _resolve_chat_endpoint_for_model(model, fallback_api_key=None, fallback_base_url=None):
    # 所有模型一律走普通 DashScope（compatible-mode）端点。
    api_key = fallback_api_key
    if api_key is None:
        api_key = DASHSCOPE_API_KEY
    base_url = fallback_base_url
    if base_url is None:
        base_url = _resolve_dashscope_base_url()
    if _is_invalid_secret(api_key):
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    if not str(base_url or "").strip():
        raise RuntimeError("未配置 DASHSCOPE_BASE_URL。")
    return str(api_key).strip(), str(base_url).rstrip('/')

def _call_qwen_text(
    prompt_text,
    api_key=None,
    base_url=None,
    timeout=300,
    model=None,
    enable_thinking=True,
    resolve_endpoint=True,
    system_prompt=None,
):
    text_model = str(model or QWEN_TEXT_MODEL)
    if resolve_endpoint:
        use_api_key, use_base_url = _resolve_chat_endpoint_for_model(
            text_model,
            fallback_api_key=api_key,
            fallback_base_url=base_url,
        )
    else:
        if not str(api_key or "").strip() or not str(base_url or "").strip():
            raise RuntimeError("缺少模型调用凭证或地址。")
        use_api_key = str(api_key).strip()
        use_base_url = str(base_url).rstrip('/')
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": str(system_prompt)})
    messages.append({"role": "user", "content": prompt_text})

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=use_api_key, base_url=use_base_url)
            kwargs = {
                "model": text_model,
                "messages": messages,
                "stream": True,
            }
            if enable_thinking is not None:
                kwargs["extra_body"] = {"enable_thinking": bool(enable_thinking)}
            stream = client.chat.completions.create(**kwargs)
            parts = []
            reasoning_parts = []
            for chunk in stream:
                if not getattr(chunk, "choices", None):
                    continue
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    parts.append(delta.content)
                if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                    reasoning_parts.append(delta.reasoning_content)
            text = ''.join(parts).strip()
            if text:
                return text
            fallback_text = ''.join(reasoning_parts).strip()
            if fallback_text:
                return fallback_text
        except Exception as e:
            print(f"[Qwen API] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {use_api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": text_model,
        "messages": messages,
    }
    if enable_thinking is not None:
        payload["enable_thinking"] = bool(enable_thinking)
    resp = _post_chat_completions(use_base_url, headers, payload, timeout)
    if resp.status_code >= 400:
        payload.pop("enable_thinking", None)
        resp = _post_chat_completions(use_base_url, headers, payload, timeout)
    resp.raise_for_status()
    result = resp.json()
    choices = result.get('choices') or []
    if not choices:
        raise RuntimeError("模型未返回有效结果。")
    content = (choices[0].get('message') or {}).get('content')
    text = _extract_text_from_response_content(content).strip()
    if not text:
        raise RuntimeError("模型未返回可用文本。")
    return text

def _call_qwen_text_with_images(
    prompt_text,
    image_data_urls,
    api_key=None,
    base_url=None,
    timeout=300,
    model=None,
    enable_thinking=True,
    resolve_endpoint=True,
):
    if resolve_endpoint:
        use_api_key, use_base_url = _resolve_chat_endpoint_for_model(
            model,
            fallback_api_key=api_key,
            fallback_base_url=base_url,
        )
    else:
        if not str(api_key or "").strip() or not str(base_url or "").strip():
            raise RuntimeError("缺少模型调用凭证或地址。")
        use_api_key = str(api_key).strip()
        use_base_url = str(base_url).rstrip('/')

    message_content = [
        {"type": "image_url", "image_url": {"url": str(image_url)}}
        for image_url in (image_data_urls or [])
        if str(image_url or "").strip()
    ]
    message_content.append({"type": "text", "text": str(prompt_text or "").strip()})
    messages = [{"role": "user", "content": message_content}]

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=use_api_key, base_url=use_base_url)
            kwargs = {
                "model": str(model or QWEN_TEXT_MODEL),
                "messages": messages,
                "modalities": ["text"],
                "stream": True,
            }
            if enable_thinking is not None:
                kwargs["extra_body"] = {"enable_thinking": bool(enable_thinking)}
            stream = client.chat.completions.create(**kwargs)
            parts = []
            reasoning_parts = []
            for chunk in stream:
                if not getattr(chunk, "choices", None):
                    continue
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    parts.append(_extract_text_from_response_content(delta.content))
                if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                    reasoning_parts.append(_extract_text_from_response_content(delta.reasoning_content))
            text = ''.join(parts).strip()
            if text:
                return text
            fallback_text = ''.join(reasoning_parts).strip()
            if fallback_text:
                return fallback_text
        except Exception as e:
            print(f"[Qwen Vision Grade] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {use_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": str(model or QWEN_TEXT_MODEL),
        "messages": messages,
        "modalities": ["text"],
    }
    if enable_thinking is not None:
        payload["enable_thinking"] = bool(enable_thinking)
    resp = _post_chat_completions(use_base_url, headers, payload, timeout)
    if resp.status_code >= 400:
        payload.pop("enable_thinking", None)
        resp = _post_chat_completions(use_base_url, headers, payload, timeout)
    resp.raise_for_status()
    result = resp.json()
    choices = result.get("choices") or []
    if not choices:
        raise RuntimeError("模型未返回有效结果。")
    content = (choices[0].get("message") or {}).get("content")
    text = _extract_text_from_response_content(content).strip()
    if not text:
        raise RuntimeError("模型未返回可用文本。")
    return text
