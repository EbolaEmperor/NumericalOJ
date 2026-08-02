"""提交代码问题定位与程序输出图片一致性反馈。"""

import json
import os

import requests

from config import (
    AI_CODE_MARKS_IMAGE_ANALYSIS_TIMEOUT,
    AI_TUTOR_MODEL,
    DASHSCOPE_API_KEY,
    QWEN_OMNI_MODEL,
)
from oj_modules.ai.client import (
    OpenAI,
    _call_qwen_text,
    _extract_text_from_response_content,
    _resolve_dashscope_base_url,
)
from oj_modules.ai.parsing import _extract_first_json_object
from oj_modules.ai.transcription import _build_image_data_url
from oj_modules.judging import core as judger_core


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


def _find_submission_output_image_path(submission_id, test_index, test_points=None):
    try:
        sid = int(submission_id)
        idx = max(1, int(test_index))
    except Exception:
        return None

    batch_sid = f"eoj-batch-{sid}"
    individual_sid = f"eoj-{sid}-{idx}"
    preferred_filenames = []
    points = test_points if isinstance(test_points, list) else []
    if points and 0 <= idx - 1 < len(points):
        tp = points[idx - 1] or {}
        preferred_name = str(tp.get("output_image_filename") or "").strip()
        if preferred_name:
            preferred_filenames.append(preferred_name)
    preferred_filenames.extend([
        f"output_{idx - 1}.png",
        f"output_{idx - 1}.jpg",
        f"output_{idx - 1}.jpeg",
        f"output_{idx - 1}.webp",
        f"output_{idx - 1}.bmp",
        "output.png",
        "output.jpg",
        "output.jpeg",
        "output.webp",
        "output.bmp",
    ])
    ordered_filenames = []
    seen_names = set()
    for name in preferred_filenames:
        raw_name = str(name or "").strip().replace("\\", "/")
        cleaned = os.path.basename(raw_name)
        if (
            not cleaned
            or cleaned in {".", ".."}
            or cleaned != raw_name
            or cleaned in seen_names
        ):
            continue
        seen_names.add(cleaned)
        ordered_filenames.append(cleaned)

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    cwd = os.getcwd()
    base_dirs = [
        judger_core.JUDGER_RUN_ROOT,
        os.path.join(project_root, "judger"),
        os.path.join(cwd, "judger"),
        "/tmp",
        cwd,
        os.path.expanduser(os.path.join("~", "oj", "judger")),
    ]
    possible_paths = []
    for filename in ordered_filenames:
        for base_dir in base_dirs:
            possible_paths.append(os.path.join(base_dir, batch_sid, filename))
        for base_dir in base_dirs:
            possible_paths.append(os.path.join(base_dir, individual_sid, filename))

    seen = set()
    for raw_path in possible_paths:
        path = os.path.abspath(os.path.expanduser(raw_path))
        if path in seen:
            continue
        seen.add(path)
        if judger_core.is_safe_regular_artifact(path):
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

    image_path = _find_submission_output_image_path(submission_id, preferred_idx, points)
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
            image_path = _find_submission_output_image_path(submission_id, test_idx, points)
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
    base_url = _resolve_dashscope_base_url()
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


def analyze_submission_output_image_against_problem(problem_text, submission_id, test_points):
    text = str(problem_text or "").strip()
    points = test_points if isinstance(test_points, list) else []
    if not text or not points or not submission_id:
        return {
            "has_output_image": False,
            "analysis": "",
            "test_index": None,
        }
    has_output_image = any(_to_bool((tp or {}).get("has_output_image")) for tp in points)
    if not has_output_image:
        return {
            "has_output_image": False,
            "analysis": "",
            "test_index": None,
        }
    analysis, used_idx = _analyze_image_mismatch_against_problem(
        problem_text=text,
        submission_id=submission_id,
        test_points=points,
    )
    return {
        "has_output_image": True,
        "analysis": str(analysis or "").strip(),
        "test_index": used_idx,
    }


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
    base_url = _resolve_dashscope_base_url()
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
