"""Promptly 提示审查与代码生成。"""

import json
import os
import re

from oj_modules.ai.client import (
    _call_llm_text,
    resolve_problem_llm_endpoint_snapshot,
)
from oj_modules.ai.parsing import (
    _extract_first_json_object_relaxed,
    _strip_markdown_code_fence_markers,
)
from oj_modules.problems.promptly import parse_promptly_review_config


PROMPTLY_CODE_GENERATION_SYSTEM_PROMPT = (
    "你是 Promptly 评测模式的代码生成器。学生的自然语言解题思路已经通过前置审查。"
    "请结合完整题面、初始代码和学生 prompt 生成可提交代码。\n"
    "最终只输出代码，不要输出 Markdown 代码围栏、解释、分析或额外文字。"
)


def _extract_code_from_model_text(text):
    raw = str(text or "").strip()
    if not raw:
        return ""

    fenced_blocks = re.findall(r"```[A-Za-z0-9_+-]*\s*(.*?)\s*```", raw, flags=re.DOTALL)
    if fenced_blocks:
        return fenced_blocks[0].strip()
    return _strip_markdown_code_fence_markers(raw)


def _format_promptly_example_replies(example_replies):
    examples = [str(item or "").strip() for item in (example_replies or []) if str(item or "").strip()]
    if not examples:
        return "1. 请补充更具体的算法思路，说明要使用的数据结构、关键步骤和边界处理。"
    return "\n".join(f"{idx}. {text}" for idx, text in enumerate(examples, start=1))


def _fake_promptly_review_from_env(prompt):
    raw_terms = os.getenv("NUMOJ_FAKE_PROMPTLY_REVIEW_REQUIRED_TERMS")
    if raw_terms is None:
        return None
    try:
        parsed_terms = json.loads(raw_terms)
    except Exception:
        parsed_terms = re.split(r"\|\||\n", raw_terms)
    if isinstance(parsed_terms, str):
        terms = [parsed_terms]
    elif isinstance(parsed_terms, (list, tuple)):
        terms = [str(item or "").strip() for item in parsed_terms]
    else:
        terms = []
    terms = [term for term in terms if term]
    normalized_prompt = str(prompt or "").lower()
    nice = all(term.lower() in normalized_prompt for term in terms)
    if nice:
        return True, ""
    reply = (
        os.getenv("NUMOJ_FAKE_PROMPTLY_REVIEW_REPLY")
        or "Please provide a clearer algorithm idea before asking AI to generate code."
    )
    return False, reply


def review_promptly_student_prompt(
    problem,
    student_prompt,
    model_spec=None,
    timeout=120,
    *,
    endpoint=None,
    endpoint_id=None,
):
    """Return (nice, reply) for a Promptly student prompt before code generation."""
    problem = problem or {}
    prompt = str(student_prompt or "").strip()
    if not prompt:
        return False, "请先填写解题思路。"
    fake_review = _fake_promptly_review_from_env(prompt)
    if fake_review is not None:
        return fake_review
    del model_spec  # 兼容旧调用签名；模型选择只来自端点快照。
    use_endpoint = resolve_problem_llm_endpoint_snapshot(
        problem,
        "review_endpoint_id",
        endpoint=endpoint,
        endpoint_id=endpoint_id,
    )

    config = parse_promptly_review_config(problem)
    brief = str(config.get("brief") or "").strip()
    requirements = str(config.get("prompt_requirements") or "").strip()
    examples_text = _format_promptly_example_replies(config.get("example_replies") or [])

    system_prompt = (
        "你是一个编程题阅卷老师，下面是题目的简要描述：\n\n"
        f"{brief or '（管理员未填写简要题意）'}\n\n"
        "你需要判断学生用自然语言描述的解题思路是否清晰、是否符合题目要求、"
        "是否对需要用到的算法或数据结构给出了必要的解释。下面是更加具体的解题思路要求：\n\n"
        f"{requirements or '（管理员未填写具体要求）'}"
    )
    system_prompt += (
        "\n\n如果不符合解题思路要求，或思路简略、不清晰，请你给出你的判断，"
        "并模仿下面的示例回复，给出你的回复。\n\n"
        "示例回复：\n"
        f"{examples_text}\n\n"
        "你必须返回严格的 JSON 格式，不要用代码块包裹，如下：\n\n"
        "{\n"
        "  \"nice\": false,\n"
        "  \"reply\": \"请补充更具体的算法思路。\"\n"
        "}\n\n"
        "其中 nice 表示学生的解题思路是否清晰、是否符合解题思路要求；"
        "如果思路清晰、符合要求、对需要用到的算法或数据结构给出了必要的解释，"
        "就将 nice 设为 true，并且无需填写 reply 字段；反之，就将 nice 设为 false，"
        "并且模仿示例回复，给出一句回复。"
    )
    user_prompt = (
        f"这是学生的解题思路：{prompt}\n\n"
        "请给出你的判断，回复严格的 JSON 格式。"
    )

    raw_text = _call_llm_text(
        user_prompt,
        use_endpoint,
        timeout=timeout,
        system_prompt=system_prompt,
    )
    payload = _extract_first_json_object_relaxed(raw_text)
    if not isinstance(payload, dict):
        raise RuntimeError("Promptly prompt 审查模型未返回有效 JSON。")

    nice_raw = payload.get("nice")
    if isinstance(nice_raw, bool):
        nice = nice_raw
    else:
        nice = str(nice_raw or "").strip().lower() in ("1", "true", "yes", "pass", "accepted")
    reply = str(payload.get("reply") or "").strip()
    if not nice and not reply:
        reply = "请补充更具体的算法思路，说明要使用的数据结构、关键步骤和边界处理。"
    return nice, reply


def generate_promptly_code(
    problem,
    student_prompt,
    model_spec=None,
    timeout=300,
    *,
    endpoint=None,
    endpoint_id=None,
):
    """根据 Promptly 模式的学生 prompt 生成待评测代码。"""
    fake_code = os.getenv("NUMOJ_FAKE_PROMPTLY_CODE")
    if fake_code is not None:
        if fake_code.startswith("@"):
            return open(fake_code[1:], "r", encoding="utf-8").read()
        return fake_code

    problem = problem or {}
    prompt = str(student_prompt or "").strip()
    if not prompt:
        raise RuntimeError("prompt 不能为空。")
    del model_spec  # 兼容旧调用签名；模型选择只来自端点快照。
    use_endpoint = resolve_problem_llm_endpoint_snapshot(
        problem,
        "code_generation_endpoint_id",
        endpoint=endpoint,
        endpoint_id=endpoint_id,
    )

    lang = str(problem.get("lang") or "matlab").strip().lower()

    user_prompt = (
        "你正在为 NumericalOJ 的编程题生成一份学生提交代码。\n"
        "请只输出代码，不要输出 Markdown 代码围栏、解释、分析或额外文字。\n\n"
        f"题目标题：\n{problem.get('title') or ''}\n\n"
        f"题目语言：\n{lang}\n\n"
        f"题面（Markdown）：\n{problem.get('content') or ''}\n\n"
        f"提交页面中学生可见的初始代码：\n{problem.get('initial_code') or ''}\n\n"
        f"学生提交的 prompt：\n{prompt}\n"
    )
    raw_text = _call_llm_text(
        user_prompt,
        use_endpoint,
        timeout=timeout,
        system_prompt=PROMPTLY_CODE_GENERATION_SYSTEM_PROMPT,
    )
    code = _extract_code_from_model_text(raw_text)
    if not code:
        raise RuntimeError("模型未返回可用代码。")
    return code
