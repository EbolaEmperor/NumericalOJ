#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import mimetypes
import os
import re

import requests

from config import DASHSCOPE_API_KEY

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


def _call_qwen_text(prompt_text, api_key, base_url, timeout=300):
    text_model = os.getenv("QWEN_TEXT_MODEL", "qwen3.5-plus")
    messages = [{"role": "user", "content": prompt_text}]

    if OpenAI is not None:
        try:
            client = OpenAI(api_key=api_key, base_url=base_url)
            stream = client.chat.completions.create(
                model=text_model,
                messages=messages,
                extra_body={"enable_thinking": False},
                stream=True,
            )
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
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": text_model,
        "messages": messages,
        "enable_thinking": True
    }
    resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
    if resp.status_code >= 400:
        payload.pop("enable_thinking", None)
        resp = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=timeout)
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


def _transcribe_image_batch(image_urls, prompt_text, api_key, base_url):
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
                parts.append(_extract_text_from_response_content(delta_content))
            latex_text = ''.join(parts).strip()
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
    latex_text = _extract_text_from_response_content(content).strip()
    if not latex_text:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    return latex_text


def transcribe_images_to_latex(image_paths):
    if not image_paths:
        raise RuntimeError("未生成可用于识别的图片。")

    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")

    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip('/')
    prompt = (
        "请将这份书面作业完整转写为 LaTeX 源码。"
        "要求：保留原题号、段落和公式结构；"
        "无法识别的内容用\\\\text{[无法辨认]}标注；"
        "只输出 LaTeX，不要任何解释和 Markdown 代码块。"
    )
    image_data_urls = [_build_image_data_url(path) for path in image_paths]
    try:
        max_images_per_request = int(os.getenv("LATEX_OCR_MAX_IMAGES_PER_REQUEST", "20"))
    except ValueError:
        max_images_per_request = 20
    image_batches = _split_image_batches(image_data_urls, max_images_per_request=max_images_per_request)

    transcribed_parts = []
    total = len(image_batches)
    for idx, batch in enumerate(image_batches, start=1):
        chunk_prompt = prompt
        if total > 1:
            chunk_prompt += (
                f" 这是第 {idx}/{total} 组页面。"
                "请只输出这一组页面对应的 LaTeX 片段，不要重复其他组内容。"
            )
        part = _transcribe_image_batch(batch, chunk_prompt, api_key, base_url)
        if part:
            transcribed_parts.append(part.strip())

    if not transcribed_parts:
        raise RuntimeError("模型未返回可用的 LaTeX 文本。")
    return "\n\n".join(transcribed_parts).strip()


def evaluate_written_homework_with_ai(problem, student_latex):
    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")

    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip('/')
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
        "【输出 JSON 格式】\n"
        "{\"score\": <0-5 的数字>, \"deductions\": [\"扣分原因1\", \"扣分原因2\"], \"comment\": \"总体评语\"}\n\n"
        f"【题目标题】\n{problem_title}\n\n"
        f"【题目内容】\n{problem_content}\n\n"
        f"【学生答案（LaTeX）】\n{student_latex}\n"
    )

    response_text = _call_qwen_text(prompt, api_key, base_url, timeout=300)
    data = _extract_first_json_object_relaxed(response_text)
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
    deductions = [str(x).strip() for x in (deductions or []) if str(x).strip()]

    if score == 5 and deductions:
        score = 4
    if score < 5 and not deductions:
        deductions = ["解答存在步骤不严谨或论证不完整，未达到满分标准。"]

    comment = data.get('comment')
    if comment is None:
        comment = data.get('评语') or ""
    comment = str(comment).strip()

    lines = [f"AI 自动评分：{score}/5"]
    if deductions:
        lines.append("扣分原因：")
        for idx, reason in enumerate(deductions, start=1):
            lines.append(f"{idx}. {reason}")
    if comment:
        lines.append("")
        lines.append(f"评语：{comment}")
    final_comment = "\n".join(lines).strip()

    return score, final_comment


def save_transcribed_latex(pdf_path, upload_folder, uploaded_filename):
    image_paths = render_pdf_to_images(pdf_path, upload_folder)
    latex_text = transcribe_images_to_latex(image_paths)
    tex_filename = f"{os.path.splitext(uploaded_filename)[0]}.tex"
    tex_path = os.path.join(upload_folder, tex_filename)
    with open(tex_path, 'w', encoding='utf-8') as f:
        f.write(latex_text)
    return tex_path


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


def generate_ai_code_marks_from_submission_context(
    problem_content,
    user_code,
    test_points_text,
    repository_files=None,
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

    prompt = f"""你是代码审阅助手。请根据题目、提交代码和评测结果，定位最关键的问题代码位置。

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
6. 最多返回 8 个 issues，只保留最重要的。
7. 有可能代码逻辑是正确的，但参数设置不当，导致结果不对。这时候你应该找到用户的参数设置，并在 Issue 里给出参数设置的建议。
8. 只在确实有问题的代码行上标注，不要猜测行号。

[题目]
{problem_text}

[提交代码（带行号）]
{numbered_code}
{repository_context}

[评测结果]
{test_points_text}
"""

    api_key = os.getenv("DASHSCOPE_API_KEY") or DASHSCOPE_API_KEY
    if not api_key or str(api_key).strip() == "" or "YOUR" in str(api_key).upper():
        raise RuntimeError("未配置 DASHSCOPE_API_KEY。")
    base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1").rstrip('/')
    response_text = _call_qwen_text(prompt, api_key, base_url, timeout=timeout)
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
        "source": "generated",
    }
