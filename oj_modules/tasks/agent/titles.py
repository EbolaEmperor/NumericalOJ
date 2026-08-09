#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用任务所选节点生成简短的 Agent 会话标题。"""

from __future__ import annotations

import re

from oj_modules.ai.endpoints import call_text


_TITLE_SYSTEM_PROMPT = (
    "你是一个任务意图概括专家。对于用户给定的一段话，请你用 15 字左右的标题精准地"
    "概括用户的任务与意图，作为这个任务的标题。请你直接输出你概括的标题，不要包含任何"
    "其它内容。要精准概括，能概括出用户的具体任务，不要太宽泛。再次强调：直接输出你概括"
    "的标题，15 字左右，不含其它内容。"
)


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


def generate_agent_title(endpoint, task_prompt, *, fallback="Agent 任务"):
    """只发起一次标题调用；节点故障时使用确定性的本地回退。"""

    try:
        result = call_text(
            endpoint,
            str(task_prompt or ""),
            system_prompt=_TITLE_SYSTEM_PROMPT,
            temperature=0,
            # 部分节点会把内部推理也计入 completion budget；给足节点可用
            # 预算，标题长度交给 system prompt 约束，不再在收到后硬截断。
            max_tokens=32768,
            timeout=60,
        )
        candidate = result.text
    except Exception:
        candidate = ""
    return normalize_agent_title(candidate, fallback=fallback)


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
    endpoint,
    task_prompt,
    *,
    fallback="Agent 任务",
):
    """为首轮会话至多调用一次标题 LLM，并为崩溃窗口保留可读回退。"""

    fallback_title = normalize_agent_title("", fallback=fallback)
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
        endpoint,
        first_user_message,
        fallback=fallback_title,
    )


__all__ = [
    "existing_agent_session_title",
    "generate_agent_title",
    "generate_initial_agent_session_title",
    "normalize_agent_title",
]
