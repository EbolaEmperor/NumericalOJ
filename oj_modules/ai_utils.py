#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import mimetypes
import os
import re
import tempfile
import time

import requests

from config import (
    AI_TUTOR_MODEL,
    AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT,
    CODING_PLAN_KEY,
    CODING_PLAN_URL,
    DASHSCOPE_API_KEY,
    DASHSCOPE_BASE_URL,
    QWEN_CODER_MODEL,
    QWEN_OMNI_MODEL,
    QWEN_TEXT_MODEL,
)

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


def _strip_markdown_code_fence_markers(text):
    raw = str(text or "")
    if not raw.strip():
        return ""
    cleaned_lines = []
    for line in raw.splitlines():
        if re.match(r"^\s*```[^\n`]*\s*$", line):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()


_CODING_PLAN_TARGET_MODELS = {
    "qwen3.5-plus",
    "qwen3-coder-plus",
    str(QWEN_TEXT_MODEL or "").strip(),
    str(QWEN_CODER_MODEL or "").strip(),
}
_WRITTEN_GRADING_MODEL_SPECS = {
    "qwen3.5-plus": ("qwen3.5-plus", False, "coding_plan"),
    "qwen3.5-plus-thinking": ("qwen3.5-plus", True, "coding_plan"),
    "qwen3.5-flash": ("qwen3.5-flash", False, "dashscope"),
    "qwen3.5-flash-thinking": ("qwen3.5-flash", True, "dashscope"),
}
_CONTROL_ESCAPE_TO_LATEX_PREFIX = {
    "\n": "n",
    "\t": "t",
    "\r": "r",
    "\x08": "b",
    "\x0c": "f",
}
_LATEX_ESCAPE_ARTIFACT_PATTERN = re.compile(r"([\n\r\t\x08\x0c])\s*([A-Za-z]{2,})")
_COMMON_LATEX_COMMANDS = {
    "neq", "ne", "leq", "geq", "approx", "sim", "equiv",
    "in", "notin", "subset", "subseteq", "supset", "supseteq",
    "cup", "cap", "to", "rightarrow", "leftarrow", "leftrightarrow",
    "mapsto", "times", "cdot", "pm", "mp", "div",
    "frac", "sqrt", "sum", "prod", "int", "lim",
    "alpha", "beta", "gamma", "delta", "epsilon", "varepsilon",
    "theta", "lambda", "mu", "pi", "sigma", "omega",
    "infty", "forall", "exists", "nabla",
    "begin", "end", "left", "right",
    "mathbb", "mathcal", "mathbf", "mathrm", "text", "operatorname",
}
_COMMON_LATEX_PREFIXES = (
    "math", "text", "begin", "end", "left", "right", "operatorname",
    "mathbf", "mathrm", "mathbb", "mathcal", "underline", "overline",
)


def _looks_like_latex_command(command):
    cmd = str(command or "").strip().lower()
    if len(cmd) < 2:
        return False
    if cmd in _COMMON_LATEX_COMMANDS:
        return True
    return any(cmd.startswith(prefix) and len(cmd) > len(prefix) for prefix in _COMMON_LATEX_PREFIXES)


def _repair_latex_escape_artifacts(text):
    raw = str(text or "")
    if not raw:
        return ""

    def _replace_match(match):
        ctrl = match.group(1)
        tail = match.group(2) or ""
        prefix = _CONTROL_ESCAPE_TO_LATEX_PREFIX.get(ctrl)
        if not prefix:
            return match.group(0)
        command = f"{prefix}{tail}"
        if not _looks_like_latex_command(command):
            return match.group(0)
        return f"\\{command}"

    return _LATEX_ESCAPE_ARTIFACT_PATTERN.sub(_replace_match, raw)


def _is_invalid_secret(value):
    text = str(value or "").strip()
    return (not text) or ("YOUR" in text.upper())


def _resolve_chat_endpoint_for_model(model, fallback_api_key=None, fallback_base_url=None):
    use_model = str(model or "").strip()
    if use_model in _CODING_PLAN_TARGET_MODELS:
        api_key = os.getenv("CODING_PLAN_KEY") or CODING_PLAN_KEY
        base_url = os.getenv("CODING_PLAN_URL") or CODING_PLAN_URL
        if _is_invalid_secret(api_key):
            raise RuntimeError("未配置 CODING_PLAN_KEY。")
        if not str(base_url or "").strip():
            raise RuntimeError("未配置 CODING_PLAN_URL。")
        return str(api_key).strip(), str(base_url).rstrip('/')

    api_key = fallback_api_key
    if api_key is None:
        api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    base_url = fallback_base_url
    if base_url is None:
        base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
    if _is_invalid_secret(api_key):
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    if not str(base_url or "").strip():
        raise RuntimeError("未配置 DASHSCOPE_BASE_URL。")
    return str(api_key).strip(), str(base_url).rstrip('/')


def _parse_written_grading_model_spec(model_spec):
    key = str(model_spec or "qwen3.5-plus-thinking").strip().lower()
    return _WRITTEN_GRADING_MODEL_SPECS.get(key, _WRITTEN_GRADING_MODEL_SPECS["qwen3.5-plus-thinking"])


def _resolve_endpoint_for_written_grading_route(route_key):
    route = str(route_key or "").strip().lower()
    if route == "coding_plan":
        api_key = os.getenv("CODING_PLAN_KEY") or CODING_PLAN_KEY
        base_url = os.getenv("CODING_PLAN_URL") or CODING_PLAN_URL
        if _is_invalid_secret(api_key):
            raise RuntimeError("未配置 CODING_PLAN_KEY。")
        if not str(base_url or "").strip():
            raise RuntimeError("未配置 CODING_PLAN_URL。")
        return str(api_key).strip(), str(base_url).rstrip('/')

    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")
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
    messages = [{"role": "user", "content": prompt_text}]

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
    resp = requests.post(f"{use_base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        payload.pop("enable_thinking", None)
        resp = requests.post(f"{use_base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
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


def _extract_first_json_object(text):
    if not text:
        return None

    candidates = [text.strip()]
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    decoder = json.JSONDecoder()
    for candidate in candidates:
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            pass

        for idx, ch in enumerate(candidate):
            if ch != '{':
                continue
            try:
                obj, _ = decoder.raw_decode(candidate[idx:])
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return None


def _extract_first_json_object_relaxed(text):
    strict_obj = _extract_first_json_object(text)
    if strict_obj is not None:
        return strict_obj

    if not text:
        return None

    candidates = [text.strip()]
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    for candidate in candidates:
        start = candidate.find('{')
        end = candidate.rfind('}')
        if start < 0 or end <= start:
            continue
        body = candidate[start:end + 1]
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', body)
        try:
            obj = json.loads(repaired)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue

    return None


def _repair_grading_json_text_locally(raw_text):
    text = str(raw_text or "").strip()
    if not text:
        return ""

    # 先尝试提取 fenced json 内容
    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()

    # 去掉常见前缀，如“评分结果：”
    text = re.sub(r'^[^\{\["]*?(?="(?:score|deductions|comment|评分|扣分原因|评语)"\s*:)', "", text, flags=re.IGNORECASE | re.DOTALL).strip()
    if not text:
        return ""

    # 缺失外层大括号时补齐；并清理尾逗号
    if not text.startswith("{"):
        text = "{" + text
    if not text.endswith("}"):
        text = text + "}"
    text = re.sub(r',\s*}', '}', text)
    return text


def _repair_grading_json_with_qwen_flash(raw_text):
    prompt = (
        "你是 JSON 修复器。请把下面这段“接近 JSON 但格式错误”的文本整理成合法 JSON 对象。\n"
        "要求：\n"
        "1. 只输出一个 JSON 对象，不要输出任何解释。\n"
        "2. 保留原语义字段，目标字段为 score、deductions、comment。\n"
        "3. deductions 必须是字符串数组。\n"
        "4. score 需是 0-5 的数字（必要时按原文最接近值修正）。\n\n"
        "5. 若字段值中包含 LaTeX 命令，JSON 字符串里的反斜杠必须双写（例如 \"\\\\neq\"、\"\\\\frac{a}{b}\"）。\n\n"
        f"待修复文本：\n```text\n{str(raw_text or '')}\n```"
    )
    api_key, base_url = _resolve_endpoint_for_written_grading_route("dashscope")
    return _call_qwen_text(
        prompt_text=prompt,
        api_key=api_key,
        base_url=base_url,
        timeout=90,
        model="qwen3.5-flash",
        enable_thinking=False,
        resolve_endpoint=False,
    )


def render_pdf_to_images(pdf_path, output_dir):
    try:
        import pypdfium2 as pdfium
    except ImportError as e:
        raise RuntimeError("缺少 pypdfium2 依赖，无法将 PDF 渲染为图片。") from e

    pdf = pdfium.PdfDocument(pdf_path)
    image_paths = []
    try:
        if len(pdf) == 0:
            raise RuntimeError("PDF 文件为空，无法转写。")
        prefix = os.path.splitext(os.path.basename(pdf_path))[0]
        for page_idx in range(len(pdf)):
            page = pdf[page_idx]
            try:
                bitmap = page.render(scale=2.0)
                image = bitmap.to_pil()
                image_filename = f"{prefix}_page_{page_idx + 1:03d}.png"
                image_path = os.path.join(output_dir, image_filename)
                image.save(image_path, format='PNG')
                image_paths.append(image_path)
            finally:
                page.close()
    finally:
        pdf.close()
    return image_paths


def _build_image_data_url(image_path):
    mime_type, _ = mimetypes.guess_type(image_path)
    if not mime_type:
        mime_type = 'image/png'
    with open(image_path, 'rb') as f:
        encoded = base64.b64encode(f.read()).decode('utf-8')
    return f"data:{mime_type};base64,{encoded}"


def _split_image_batches(image_data_urls, max_images_per_request=20):
    if max_images_per_request < 1:
        max_images_per_request = 20
    return [
        image_data_urls[i:i + max_images_per_request]
        for i in range(0, len(image_data_urls), max_images_per_request)
    ]


def _transcribe_image_batch(image_urls, prompt_text, api_key, base_url, on_delta=None):
    message_content = [
        {
            "type": "image_url",
            "image_url": {"url": image_url}
        }
        for image_url in image_urls
    ]
    message_content.append({
        "type": "text",
        "text": prompt_text
    })

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            stream = client.chat.completions.create(
                model="qwen3-omni-flash",
                messages=[{
                    "role": "user",
                    "content": message_content
                }],
                modalities=["text"],
                stream=True,
                stream_options={"include_usage": True},
            )
            parts = []
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta_content = chunk.choices[0].delta.content
                delta_text = _extract_text_from_response_content(delta_content)
                if not delta_text:
                    continue
                parts.append(delta_text)
                if callable(on_delta):
                    try:
                        on_delta(delta_text)
                    except Exception:
                        pass
            latex_text = _strip_markdown_code_fence_markers(''.join(parts))
            if latex_text:
                return latex_text
        except Exception as e:
            print(f"[LaTeX OCR] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "qwen3-omni-flash",
        "messages": [{
            "role": "user",
            "content": message_content
        }],
        "modalities": ["text"]
    }
    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=300)
    resp.raise_for_status()
    result = resp.json()
    choices = result.get('choices') or []
    if not choices:
        raise RuntimeError("模型未返回有效结果。")
    content = (choices[0].get('message') or {}).get('content')
    latex_text = _strip_markdown_code_fence_markers(_extract_text_from_response_content(content))
    if not latex_text:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    if callable(on_delta):
        try:
            on_delta(latex_text)
        except Exception:
            pass
    return latex_text


def transcribe_images_to_latex(image_paths, on_partial_text=None):
    if not image_paths:
        raise RuntimeError("未生成可用于识别的图片。")

    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")

    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip('/')
    prompt = (
        "请将这份书面作业完整转写为 Markdown 内嵌 LaTeX 的格式。"
        "要求："
        "1. 保留原题号、段落和公式结构；"
        "2. 无法识别的内容用 {[无法辨认]} 标注；"
        "3. 行内公式用 $...$ 包裹，行间公式用 $$(换行)...(换行)$$ 包裹；"
        "4. 不要输出任何解释，直接输出 Markdown 源码。"
    )
    image_data_urls = [_build_image_data_url(path) for path in image_paths]
    try:
        max_images_per_request = int(os.getenv("LATEX_OCR_MAX_IMAGES_PER_REQUEST", "20"))
    except ValueError:
        max_images_per_request = 20
    image_batches = _split_image_batches(image_data_urls, max_images_per_request=max_images_per_request)

    transcribed_parts = []
    current_raw_part = []

    def _emit_partial_preview():
        if not callable(on_partial_text):
            return
        preview_parts = list(transcribed_parts)
        if current_raw_part:
            preview_current = _strip_markdown_code_fence_markers(''.join(current_raw_part))
            if preview_current:
                preview_parts.append(preview_current.strip())
        preview_text = "\n\n".join([p for p in preview_parts if str(p or "").strip()]).strip()
        try:
            on_partial_text(preview_text)
        except Exception:
            pass

    total = len(image_batches)
    for idx, batch in enumerate(image_batches, start=1):
        current_raw_part = []
        chunk_prompt = prompt
        if total > 1:
            chunk_prompt += (
                f" 这是第 {idx}/{total} 组页面。"
                "请只输出这一组页面对应的 LaTeX 片段，不要重复其他组内容。"
            )

        def _on_delta(delta_text):
            if not delta_text:
                return
            current_raw_part.append(delta_text)
            _emit_partial_preview()

        part = _transcribe_image_batch(batch, chunk_prompt, api_key, base_url, on_delta=_on_delta)
        if part:
            transcribed_parts.append(part.strip())
            current_raw_part = []
            _emit_partial_preview()

    if not transcribed_parts:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    return "\n\n".join(transcribed_parts).strip()


def _call_qwen_text_with_images(
    prompt_text,
    image_data_urls,
    api_key=None,
    base_url=None,
    timeout=300,
    model="qwen3.5-plus",
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
                "model": str(model or "qwen3.5-plus"),
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
        "model": str(model or "qwen3.5-plus"),
        "messages": messages,
        "modalities": ["text"],
    }
    if enable_thinking is not None:
        payload["enable_thinking"] = bool(enable_thinking)
    resp = requests.post(f"{use_base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        payload.pop("enable_thinking", None)
        resp = requests.post(f"{use_base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
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


def _parse_written_homework_grading_result(response_text):
    data = _extract_first_json_object_relaxed(response_text)
    if not data:
        locally_repaired = _repair_grading_json_text_locally(response_text)
        if locally_repaired:
            data = _extract_first_json_object_relaxed(locally_repaired)
    if not data:
        try:
            model_repaired = _repair_grading_json_with_qwen_flash(response_text)
            data = _extract_first_json_object_relaxed(model_repaired)
        except Exception:
            data = None
    if not data:
        raise RuntimeError(f"评分结果解析失败，模型原始输出：{response_text[:500]}")

    raw_score = data.get('score')
    if raw_score is None:
        raw_score = data.get('评分')
    try:
        score = int(round(float(raw_score)))
    except Exception:
        num_match = re.search(r'([0-5](?:\.\d+)?)', str(response_text))
        if not num_match:
            raise RuntimeError("评分结果中缺少 score 字段。")
        score = int(round(float(num_match.group(1))))
    score = max(0, min(5, score))

    deductions = data.get('deductions')
    if deductions is None:
        deductions = data.get('reasons') or data.get('扣分原因') or []
    if isinstance(deductions, str):
        deductions = [deductions]
    deductions = [_repair_latex_escape_artifacts(str(x).strip()) for x in (deductions or []) if str(x).strip()]

    if score == 5 and deductions:
        score = 4
    if score < 5 and not deductions:
        deductions = ["解答存在步骤不严谨或论证不完整，未达到满分标准。"]

    comment = data.get('comment')
    if comment is None:
        comment = data.get('评语') or ""
    comment = _repair_latex_escape_artifacts(str(comment).strip())
    return score, deductions, comment


def _format_written_homework_comment(score, deductions, comment):
    lines = [f"AI 自动评分：{score}/5"]
    if deductions:
        lines.append("扣分原因：")
        for idx, reason in enumerate(deductions, start=1):
            lines.append(f"{idx}. {reason}")
    if comment:
        lines.append("")
        lines.append(f"评语：{comment}")
    return "\n".join(lines).strip()


def evaluate_written_homework_with_ai(problem, student_latex, grading_model_spec="qwen3.5-plus-thinking"):
    model_name, enable_thinking, route_key = _parse_written_grading_model_spec(grading_model_spec)
    api_key, base_url = _resolve_endpoint_for_written_grading_route(route_key)
    problem_title = (problem or {}).get('title', '')
    problem_content = (problem or {}).get('content', '')

    prompt = (
        "你是严谨的数学书面作业阅卷老师，请从“证明严谨性”角度评分。\n"
        "只允许输出 JSON，不要输出任何额外文字。\n\n"
        "【硬性评分规则】\n"
        "1) 5 分（满分）必须同时满足：\n"
        "- 关键结论都有明确推导，不跳步；\n"
        "- 使用的定理/性质有对应条件并且已验证；\n"
        "- 涉及最值/取等时，明确说明可达性或取等条件；\n"
        "- 记号、逻辑链条完整，无明显歧义。\n"
        "2) 只要出现以下任一情况，最高只能 4 分：\n"
        "- 关键步骤仅口头说明（如“显然”“易得”）但无必要推导；\n"
        "- 缺少条件验证、边界讨论、取等条件说明；\n"
        "- 推理链存在轻微断裂但主思路正确。\n"
        "3) 若存在实质性逻辑错误/结论错误，分数应 <= 2。\n"
        "4) 若 score < 5，deductions 必须至少包含 1 条具体扣分点。\n\n"
        "5) 若 JSON 字符串中包含 LaTeX 命令，反斜杠必须双写（例如 \"\\\\neq\"、\"\\\\frac{a}{b}\"）。\n\n"
        "【输出 JSON 格式】\n"
        "{\"score\": <0-5 的数字>, \"deductions\": [\"扣分原因1\", \"扣分原因2\"], \"comment\": \"总体评语\"}\n\n"
        f"【题目标题】\n{problem_title}\n\n"
        f"【题目内容】\n{problem_content}\n\n"
        f"【学生答案（LaTeX）】\n{student_latex}\n"
    )

    response_text = _call_qwen_text(
        prompt,
        api_key=api_key,
        base_url=base_url,
        timeout=300,
        model=model_name,
        enable_thinking=enable_thinking,
        resolve_endpoint=False,
    )
    score, deductions, comment = _parse_written_homework_grading_result(response_text)
    final_comment = _format_written_homework_comment(score, deductions, comment)
    return score, final_comment


def evaluate_written_homework_with_ai_from_images(
    problem,
    image_paths,
    grading_model_spec="qwen3.5-plus-thinking",
):
    if not image_paths:
        raise RuntimeError("未找到可用于图片批改的页面图片。")

    model_name, enable_thinking, route_key = _parse_written_grading_model_spec(grading_model_spec)
    api_key, base_url = _resolve_endpoint_for_written_grading_route(route_key)
    image_data_urls = [_build_image_data_url(path) for path in image_paths]

    problem_title = (problem or {}).get('title', '')
    problem_content = (problem or {}).get('content', '')

    prompt = (
        "你是严谨的数学书面作业阅卷老师。你将收到题面文本和学生作业图片，请直接根据图片内容完成评分。\n"
        "只允许输出 JSON，不要输出任何额外文字。\n\n"
        "【硬性评分规则】\n"
        "1) 5 分（满分）必须同时满足：\n"
        "- 关键结论都有明确推导，不跳步；\n"
        "- 使用的定理/性质有对应条件并且已验证；\n"
        "- 涉及最值/取等时，明确说明可达性或取等条件；\n"
        "- 记号、逻辑链条完整，无明显歧义。\n"
        "2) 只要出现以下任一情况，最高只能 4 分：\n"
        "- 关键步骤仅口头说明（如“显然”“易得”）但无必要推导；\n"
        "- 缺少条件验证、边界讨论、取等条件说明；\n"
        "- 推理链存在轻微断裂但主思路正确。\n"
        "3) 若存在实质性逻辑错误/结论错误，分数应 <= 2。\n"
        "4) 若 score < 5，deductions 必须至少包含 1 条具体扣分点。\n\n"
        "5) 若 JSON 字符串中包含 LaTeX 命令，反斜杠必须双写（例如 \"\\\\neq\"、\"\\\\frac{a}{b}\"）。\n\n"
        "【输出 JSON 格式】\n"
        "{\"score\": <0-5 的数字>, \"deductions\": [\"扣分原因1\", \"扣分原因2\"], \"comment\": \"总体评语\"}\n\n"
        f"【题目标题】\n{problem_title}\n\n"
        f"【题目内容】\n{problem_content}\n\n"
        "【学生答案】\n"
        "请直接阅读图片中的手写内容进行评分。"
    )

    response_text = _call_qwen_text_with_images(
        prompt_text=prompt,
        image_data_urls=image_data_urls,
        api_key=api_key,
        base_url=base_url,
        timeout=360,
        model=model_name,
        enable_thinking=enable_thinking,
        resolve_endpoint=False,
    )
    score, deductions, comment = _parse_written_homework_grading_result(response_text)
    final_comment = _format_written_homework_comment(score, deductions, comment)
    return score, final_comment


def _atomic_write_text(path, content):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_latex_", suffix=".md", dir=parent, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(str(content or ""))
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def save_transcribed_latex(pdf_path, upload_folder, uploaded_filename, on_partial_latex=None):
    image_paths = render_pdf_to_images(pdf_path, upload_folder)
    markdown_filename = f"{os.path.splitext(uploaded_filename)[0]}.md"
    markdown_path = os.path.join(upload_folder, markdown_filename)
    _atomic_write_text(markdown_path, "")

    try:
        stream_emit_interval = max(0.1, float(os.getenv("LATEX_OCR_STREAM_EMIT_INTERVAL", "0.6")))
    except ValueError:
        stream_emit_interval = 0.6
    try:
        stream_emit_min_delta = max(1, int(os.getenv("LATEX_OCR_STREAM_EMIT_MIN_DELTA", "60")))
    except ValueError:
        stream_emit_min_delta = 60

    last_emit_ts = 0.0
    last_emitted_text = ""

    def _on_partial_text(text):
        nonlocal last_emit_ts, last_emitted_text
        partial = str(text or "")
        if partial == last_emitted_text:
            return
        now = time.monotonic()
        if (
            last_emitted_text
            and (now - last_emit_ts) < stream_emit_interval
            and abs(len(partial) - len(last_emitted_text)) < stream_emit_min_delta
        ):
            return
        _atomic_write_text(markdown_path, partial)
        last_emit_ts = now
        last_emitted_text = partial
        if callable(on_partial_latex):
            try:
                on_partial_latex(partial, markdown_path)
            except Exception:
                pass

    latex_text = transcribe_images_to_latex(image_paths, on_partial_text=_on_partial_text)
    _atomic_write_text(markdown_path, latex_text)
    if callable(on_partial_latex):
        try:
            on_partial_latex(latex_text, markdown_path)
        except Exception:
            pass
    return markdown_path


def _normalize_ai_code_issues(raw_issues, user_code, max_issues=8):
    def visual_line_length(s, tab_size=4):
        visual = 0
        for ch in s:
            if ch == '\t':
                visual += tab_size - (visual % tab_size)
            else:
                visual += 1
        return visual

    lines = user_code.splitlines()
    if not lines:
        lines = [user_code or ""]
    n = len(lines)

    normalized = []
    for item in raw_issues or []:
        if not isinstance(item, dict):
            continue

        reason = str(item.get('reason') or item.get('message') or item.get('desc') or '').strip()
        if not reason:
            continue

        try:
            ls = int(item.get('line_start') or item.get('start_line') or item.get('line') or 1)
            le = int(item.get('line_end') or item.get('end_line') or ls)
        except Exception:
            continue

        if ls > le:
            ls, le = le, ls
        ls = max(1, min(n, ls))
        le = max(1, min(n, le))

        start_visual_len = visual_line_length(lines[ls - 1], tab_size=4)
        end_visual_len = visual_line_length(lines[le - 1], tab_size=4)

        try:
            cs = int(item.get('column_start') or item.get('start_col') or item.get('column') or 1)
        except Exception:
            cs = 1
        try:
            ce = int(item.get('column_end') or item.get('end_col') or max(cs, end_visual_len))
        except Exception:
            ce = max(cs, end_visual_len)

        cs = max(1, min(start_visual_len + 1, cs))
        ce = max(cs, min(end_visual_len + 1, ce))

        normalized.append({
            "line_start": ls,
            "line_end": le,
            "column_start": cs,
            "column_end": ce,
            "reason": reason,
            "severity": str(item.get('severity') or 'error')
        })
        if len(normalized) >= max_issues:
            break

    return normalized


def _parse_test_points_text(test_points_text):
    rows = []
    for line in str(test_points_text or "").splitlines():
        line = str(line or "").strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value or "").strip().lower()
    return text in ("1", "true", "yes", "y", "on")


def _find_submission_output_image_path(submission_id, test_index):
    try:
        sid = int(submission_id)
        idx = max(1, int(test_index))
    except Exception:
        return None

    batch_sid = f"eoj-batch-{sid}"
    batch_image_filename = f"output_{idx - 1}.png"
    individual_sid = f"eoj-{sid}-{idx}"
    individual_image_filename = "output.png"

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cwd = os.getcwd()
    possible_paths = [
        os.path.join(project_root, "judger", batch_sid, batch_image_filename),
        os.path.join(cwd, "judger", batch_sid, batch_image_filename),
        os.path.join("/tmp", batch_sid, batch_image_filename),
        os.path.join(cwd, batch_sid, batch_image_filename),
        os.path.expanduser(os.path.join("~", "oj", "judger", batch_sid, batch_image_filename)),
        os.path.join(project_root, "judger", individual_sid, individual_image_filename),
        os.path.join(cwd, "judger", individual_sid, individual_image_filename),
        os.path.join("/tmp", individual_sid, individual_image_filename),
        os.path.join(cwd, individual_sid, individual_image_filename),
        os.path.expanduser(os.path.join("~", "oj", "judger", individual_sid, individual_image_filename)),
    ]

    seen = set()
    for raw_path in possible_paths:
        path = os.path.abspath(os.path.expanduser(raw_path))
        if path in seen:
            continue
        seen.add(path)
        if os.path.isfile(path):
            return path
    return None


def _call_qwen_omni_with_image(prompt_text, image_data_url, api_key, base_url, timeout=180):
    messages = [{
        "role": "user",
        "content": [
            {"type": "image_url", "image_url": {"url": image_data_url}},
            {"type": "text", "text": str(prompt_text or "").strip()},
        ],
    }]
    model = str(QWEN_OMNI_MODEL)

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            resp = client.chat.completions.create(
                model=model,
                messages=messages,
                modalities=["text"],
                stream=False,
            )
            choices = getattr(resp, "choices", None) or []
            if choices and getattr(choices[0], "message", None):
                text = _extract_text_from_response_content(choices[0].message.content).strip()
                if text:
                    return text
        except Exception as e:
            print(f"[Image Analysis] OpenAI SDK 调用失败，尝试 requests 回退: {e}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "modalities": ["text"],
    }
    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    result = resp.json()
    choices = result.get("choices") or []
    if not choices:
        raise RuntimeError("图片分析模型未返回有效结果。")
    content = (choices[0].get("message") or {}).get("content")
    text = _extract_text_from_response_content(content).strip()
    if not text:
        raise RuntimeError("图片分析模型未返回可用文本。")
    return text


def _analyze_image_mismatch_against_problem(problem_text, submission_id, test_points):
    if not submission_id:
        return "", None
    points = test_points if isinstance(test_points, list) else []
    if not points:
        return "", None
    if not any(_to_bool((tp or {}).get("has_output_image")) for tp in points):
        return "", None

    def is_accepted_status(tp):
        status = str((tp or {}).get("status") or "").strip().lower()
        return status == "accepted"

    preferred_idx = None
    for offset, tp in enumerate(points, start=1):
        if is_accepted_status(tp):
            continue
        try:
            preferred_idx = int((tp or {}).get("test_index") or offset)
        except Exception:
            preferred_idx = offset
        break

    if preferred_idx is None:
        return "", None

    image_path = _find_submission_output_image_path(submission_id, preferred_idx)
    used_idx = preferred_idx

    if not image_path:
        for offset, tp in enumerate(points, start=1):
            if is_accepted_status(tp):
                continue
            if not _to_bool((tp or {}).get("has_output_image")):
                continue
            try:
                test_idx = int((tp or {}).get("test_index") or offset)
            except Exception:
                test_idx = offset
            image_path = _find_submission_output_image_path(submission_id, test_idx)
            if image_path:
                used_idx = test_idx
                break

    if not image_path:
        return "", None

    image_url = _build_image_data_url(image_path)
    prompt = (
        "你是 OJ 评测图片一致性检查助手。请对照题目要求和这张程序输出图片，"
        "找出“不符合题意/与要求不一致”的地方。\n"
        "输出要求：\n"
        "1) 使用中文；\n"
        "2) 先给结论（是否存在明显不符合）；\n"
        "3) 最多列 3 条关键不符合点，每条包含：现象 + 与题目要求冲突点；\n"
        "4) 不要输出代码。\n\n"
        f"[题目要求]\n{problem_text}"
    )

    api_key = DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        return "", None
    base_url = str(DASHSCOPE_BASE_URL).rstrip('/')
    try:
        analysis = _call_qwen_omni_with_image(
            prompt_text=prompt,
            image_data_url=image_url,
            api_key=api_key,
            base_url=base_url,
            timeout=int(AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT),
        )
    except Exception as e:
        print(f"[Image Analysis] 图片一致性分析失败: {e}")
        return "", None

    return str(analysis or "").strip(), used_idx


def generate_ai_code_marks_from_submission_context(
    problem_content,
    user_code,
    test_points_text,
    repository_files=None,
    submission_id=None,
    test_points=None,
    max_issues=8,
    timeout=240,
):
    problem_text = str(problem_content or "").strip()
    code_text = str(user_code or "").replace('\r\n', '\n').replace('\r', '\n')
    if not problem_text:
        raise RuntimeError("缺少题目内容")
    if not code_text.strip():
        raise RuntimeError("缺少用户代码")

    repo_files = repository_files if isinstance(repository_files, dict) else {}
    repository_context = ""
    if repo_files:
        repository_context = "\n\n你可以参考以下同学代码仓库文件：\n"
        for filename, content in repo_files.items():
            repository_context += f"\n[文件] {filename}\n```\n{content}\n```\n"

    numbered_lines = [f"{idx:4d}| {line}" for idx, line in enumerate(code_text.split('\n'), start=1)]
    numbered_code = "\n".join(numbered_lines)

    test_points_rows = test_points if isinstance(test_points, list) else _parse_test_points_text(test_points_text)
    image_mismatch_analysis, image_test_index = _analyze_image_mismatch_against_problem(
        problem_text=problem_text,
        submission_id=submission_id,
        test_points=test_points_rows,
    )
    image_context = ""
    if image_mismatch_analysis:
        image_context = (
            f"\n\n[输出图片一致性分析（由 {QWEN_OMNI_MODEL} 基于测试点#{image_test_index} 输出图片生成）]\n"
            f"{image_mismatch_analysis}\n"
        )

    prompt = f"""你是代码审阅助手。请根据题目、提交代码、评测结果与图片分析结论，定位最关键的问题代码位置。

要求：
1. 只返回 JSON，不要输出任何解释文本，不要使用 Markdown。
2. 返回格式必须是：
{{
  "issues": [
    {{
      "line_start": 10,
      "line_end": 10,
      "reason": "这里数组下标可能越界",
      "severity": "error"
    }}
  ],
  "summary": "一句话总结主要问题"
}}
3. line_start/line_end 都是 1-based。
4. line_start/line_end 必须严格对应下面“带行号代码”左侧的行号数字。
5. 如果评测结果是 Compile Error 或者 Nonzero Exit，那就只分析代码的语法错误，不要分析代码的逻辑错误。
6. 如果是因为用户知识不足导致他不会写，请在 reason 里详细讲解，为用户补充知识。
7. 最多返回 8 个 issues，只保留最重要的。
8. 有可能代码逻辑是正确的，但参数设置不当，导致结果不对。这时候你应该找到用户的参数设置，并在 Issue 里给出参数设置的建议。
9. 只在确实有问题的代码行上标注，不要猜测行号。

[题目]
{problem_text}

[提交代码（带行号）]
{numbered_code}
{repository_context}

[评测结果]
{test_points_text}
{image_context}
"""

    api_key = DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    base_url = str(DASHSCOPE_BASE_URL).rstrip('/')
    response_text = _call_qwen_text(prompt, api_key, base_url, timeout=timeout, model=AI_TUTOR_MODEL)
    data_obj = _extract_first_json_object(response_text)
    if not isinstance(data_obj, dict):
        raise RuntimeError(f"模型返回无法解析为 JSON：{response_text[:300]}")

    issues = _normalize_ai_code_issues(data_obj.get('issues') or [], code_text, max_issues=max_issues)
    summary = str(data_obj.get('summary') or '').strip()
    return {
        "success": True,
        "issues": issues,
        "summary": summary,
        "code_used": code_text,
        "image_mismatch_analysis": image_mismatch_analysis,
        "image_analysis_test_index": image_test_index,
        "source": "generated",
    }
