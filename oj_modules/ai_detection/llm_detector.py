#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用管理员显式选择的全局端点执行 AI 代码检测。"""

import json
import re
import time

from oj_modules.ai_utils import resolve_llm_endpoint_snapshot
from oj_modules.llm_endpoints import call_text


_MAX_RETRIES = 3
_RETRY_DELAY = 3


class LLMDetectionFailed(Exception):
    pass


_SYSTEM_PROMPT = """\
你是一位经验丰富的大学编程课教师，负责评估学生提交的程序代码是否可能由生成式 AI 辅助生成。

请你根据以下特征综合判断代码由 AI 生成的概率：

**AI 生成代码的常见特征：**
1. 注释过于规范和冗长，几乎每一步都有说明性注释，注释用词“教科书式”
2. 变量命名过于规范和描述性，不像学生常用的短变量名
3. 代码或注释带有“助手式”回复痕迹
4. 包含明显超出课程水平的错误处理或高级写法
5. 代码组织方式像回答问题而非直接解决问题
6. 代码风格与题目规模、课程层次或同一提交内其他部分明显不一致

**学生手写代码的常见特征：**
1. 注释稀少或只在关键处有简短注释
2. 变量名简短，常用单字母或缩写
3. 直接解决问题，没有多余框架代码
4. 可能有注释掉的代码或调试输出等试错痕迹

上述特征都不是单独定论。请结合题目、编程语言和代码本身给出审慎判断，
不要因为代码整洁、变量名清晰或使用某种语言特性就直接判为 AI 生成。

请严格输出以下 JSON 格式（不要输出其他内容）：
{
  "ai_probability": <0.0 到 1.0 的浮点数>,
  "confidence": <0.0 到 1.0 的浮点数>,
  "evidence": [<最多 5 条判断依据，每条是一个字符串>]
}
"""

_USER_PROMPT_TEMPLATE = """\
## 题目描述
{problem_description}

## 编程语言
{language}

## 学生提交的代码
```text
{code}
```

请判断这段代码由 AI 生成的概率。"""


def _sanitize_json(raw):
    def _fix_string(match):
        return (
            match.group(0)
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )

    return re.sub(r'"(?:[^"\\]|\\.)*"', _fix_string, raw, flags=re.DOTALL)


def _parse_llm_response(text):
    """从统一 JSON 响应解析概率、置信度和证据。"""

    raw = str(text or "").strip()
    if not raw:
        return None
    match = re.search(r"```(?:json)?\s*\n?(.*?)```", raw, re.DOTALL)
    if match:
        raw = match.group(1).strip()

    result = None
    for candidate in (raw, _sanitize_json(raw)):
        try:
            result = json.loads(candidate)
            break
        except (json.JSONDecodeError, TypeError):
            continue
    if result is None:
        match = re.search(r'\{[^{}]*"ai_probability"[^{}]*\}', raw, re.DOTALL)
        if match:
            try:
                result = json.loads(_sanitize_json(match.group(0)))
            except json.JSONDecodeError:
                return None
    if not isinstance(result, dict) or result.get("ai_probability") is None:
        return None
    try:
        probability = max(0.0, min(1.0, float(result["ai_probability"])))
        confidence = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
    except (TypeError, ValueError):
        return None
    evidence = result.get("evidence")
    if not isinstance(evidence, list):
        evidence = []
    return {
        "ai_probability": probability,
        "confidence": confidence,
        "evidence": [str(item) for item in evidence[:5]],
    }


def get_available_endpoints():
    """返回 AI 检测可选择的纯文本/全模态端点，不含密钥。"""

    from oj_modules.dynamic_config_services import list_llm_endpoints

    endpoints = list_llm_endpoints(include_secrets=False)
    return [
        {
            "id": int(endpoint["id"]),
            "name": str(endpoint.get("name") or "").strip(),
            "protocol": str(endpoint.get("protocol") or "").strip().lower(),
            "category": str(endpoint.get("category") or "").strip().lower(),
            "model": str(endpoint.get("model") or "").strip(),
        }
        for endpoint in endpoints or []
        if str(endpoint.get("category") or "").strip().lower() in {"omni", "text"}
    ]


def get_available_models():
    """旧路由名的兼容别名；返回值已经是全局端点而不是模型分支。"""

    return [
        {**endpoint, "available": True}
        for endpoint in get_available_endpoints()
    ]


def detect_with_llm(
    code,
    problem_description="",
    *,
    language="未注明",
    endpoint=None,
    endpoint_id=None,
):
    """用固定端点快照检测一份代码；不按厂商或模型名分支。"""

    snapshot = resolve_llm_endpoint_snapshot(
        endpoint,
        endpoint_id=endpoint_id,
        allowed_categories={"omni", "text"},
        purpose="AI 检测",
    )
    prompt = _USER_PROMPT_TEMPLATE.format(
        problem_description=str(problem_description or "")[:3000],
        language=str(language or "未注明")[:64],
        code=str(code or "")[:8000],
    )
    last_error = None
    for attempt in range(1, _MAX_RETRIES + 1):
        raw_text = ""
        try:
            response = call_text(
                snapshot,
                prompt,
                system_prompt=_SYSTEM_PROMPT,
                temperature=0.3,
                max_tokens=1024,
                timeout=120,
            )
            raw_text = response.text or ""
            parsed = _parse_llm_response(raw_text)
            if parsed is None:
                raise ValueError("模型响应不是约定的 JSON 格式")
            return {
                "score": parsed["ai_probability"],
                "confidence": parsed["confidence"],
                "evidence": parsed["evidence"],
                "raw_response": raw_text[:2000],
            }
        except Exception as exc:
            last_error = str(exc)
            if attempt < _MAX_RETRIES:
                time.sleep(_RETRY_DELAY)
    raise LLMDetectionFailed(
        f"AI 检测在 {_MAX_RETRIES} 次尝试后失败：{last_error or '未知错误'}"
    )
