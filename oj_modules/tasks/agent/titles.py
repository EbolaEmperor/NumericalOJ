#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用低价全站节点生成简短的 Agent 会话标题。"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import re

from oj_modules.ai.endpoints import call_text
from oj_modules.site_config.services import list_llm_endpoints


_TITLE_SYSTEM_PROMPT = (
    "你是一个任务意图概括专家。对于用户给定的一段话，请你用 15 字左右的标题精准地"
    "概括用户的任务与意图，作为这个任务的标题。请你直接输出你概括的标题，不要包含任何"
    "其它内容。要精准概括，能概括出用户的具体任务，不要太宽泛。再次强调：直接输出你概括"
    "的标题，15 字左右，不含其它内容。"
)
_TITLE_INPUT_MAX_CHARS = 4_000
_TITLE_MAX_TOKENS = 64


def normalize_agent_title(value, *, fallback="Agent 任务"):
    raw = str(value or "").replace("\x00", " ")
    line = next((item.strip() for item in raw.splitlines() if item.strip()), "")
    line = line.strip(" \t#`*_'\"“”‘’《》<>[]【】()（）。，、；;:：!?！？")
    line = re.sub(r"^(?:标题|任务标题)\s*[:：]\s*", "", line)
    line = line.strip(" \t#`*_'\"“”‘’《》<>[]【】()（）。，、；;:：!?！？")
    line = re.sub(r"\s+", " ", line)
    if not line:
        fallback_text = str(fallback or "Agent 任务").replace("\x00", " ")
        line = next(
            (item.strip() for item in fallback_text.splitlines() if item.strip()),
            "Agent 任务",
        )
        line = re.sub(r"\s+", " ", line).strip()
    return line or "Agent 任务"


def fallback_agent_title(task_prompt):
    """取任务正文前 15 个 Unicode 字符作为确定性标题。"""

    text = str(task_prompt or "").replace("\x00", "").strip()
    return text[:15] or "Agent 任务"


def _title_endpoint_candidates():
    """按输入单价选择至多两个全站文本节点，不使用任务所选节点。"""

    candidates = []
    for endpoint in list_llm_endpoints(include_secrets=True):
        if str(endpoint.get("category") or "").strip().lower() not in {
            "text",
            "omni",
        }:
            continue
        if not str(endpoint.get("api_key") or "").strip():
            continue
        try:
            input_price = Decimal(str(endpoint.get("input_price_per_million")))
        except (InvalidOperation, TypeError, ValueError):
            continue
        if not input_price.is_finite() or input_price < 0:
            continue
        candidates.append((input_price, int(endpoint.get("id") or 0), endpoint))
    candidates.sort(key=lambda item: (item[0], item[1]))
    return [item[2] for item in candidates[:2]]


def _generate_agent_title_once(endpoint, task_prompt):
    try:
        result = call_text(
            endpoint,
            str(task_prompt or "")[:_TITLE_INPUT_MAX_CHARS],
            system_prompt=_TITLE_SYSTEM_PROMPT,
            temperature=0,
            # 标题调用不计入用户账单，因此同时限制输入与输出预算；
            # 64 Token 足以容纳约 15 个汉字的标题及少量模型推理余量。
            max_tokens=_TITLE_MAX_TOKENS,
            timeout=30,
        )
        candidate = normalize_agent_title(result.text, fallback="")
    except Exception:
        return ""
    return candidate if candidate != "Agent 任务" else ""


def generate_agent_title(task_prompt, *, fallback=None):
    """依次尝试输入单价最低的两个全站节点，失败后使用本地标题。"""

    fallback_title = normalize_agent_title(
        fallback_agent_title(task_prompt) if fallback is None else fallback,
        fallback=fallback_agent_title(task_prompt),
    )
    try:
        candidates = _title_endpoint_candidates()
    except Exception:
        candidates = []
    for endpoint in candidates:
        candidate = _generate_agent_title_once(endpoint, task_prompt)
        if candidate:
            return candidate
    return fallback_title


def existing_agent_session_title(session_id):
    """late-ack 重投优先复用已经落库的首轮标题。"""

    try:
        from oj_modules.agents.sessions import get_agent_session

        session = get_agent_session(session_id)
    except Exception:
        return ""
    if not isinstance(session, dict) or session.get("is_legacy"):
        return ""
    return str(session.get("title") or "").strip()


def _initial_agent_session_message(session_id):
    """读取首轮原始用户消息；读取失败时不向 LLM 发送运行期扩展 prompt。"""

    try:
        from oj_modules.agents.sessions import get_agent_session_turns

        turns = get_agent_session_turns(session_id)
    except Exception:
        return ""
    for turn in turns if isinstance(turns, list) else []:
        if not isinstance(turn, dict) or int(turn.get("turn_index") or 0) != 1:
            continue
        message = str(turn.get("user_message") or "")
        return message if message.strip() else ""
    return ""


def generate_initial_agent_session_title(
    session_id,
    task_prompt,
    *,
    fallback=None,
):
    """为首轮会话至多调用一次标题 LLM，并为崩溃窗口保留可读回退。"""

    fallback_title = normalize_agent_title(
        fallback_agent_title(task_prompt) if fallback is None else fallback,
        fallback=fallback_agent_title(task_prompt),
    )
    existing = existing_agent_session_title(session_id)
    if existing:
        return normalize_agent_title(existing, fallback=fallback_title)

    # task_prompt 是发给 harness 的运行 prompt，带附件时会追加 workspace 说明；
    # 标题调用只能使用会话表中持久化的首轮原始消息，不能把这些前后缀带给 LLM。
    first_user_message = _initial_agent_session_message(session_id)

    from oj_modules.agents.sessions import claim_agent_session_title_generation

    if not claim_agent_session_title_generation(session_id, fallback_title):
        return (
            existing_agent_session_title(session_id)
            or fallback_title
        )
    if not first_user_message:
        return fallback_title
    return generate_agent_title(
        first_user_message,
        fallback=fallback_title,
    )


__all__ = [
    "existing_agent_session_title",
    "fallback_agent_title",
    "generate_agent_title",
    "generate_initial_agent_session_title",
    "normalize_agent_title",
]
