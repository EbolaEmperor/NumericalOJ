#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""使用任务所选节点生成简短的 Agent 会话标题。"""

from __future__ import annotations

import re

from oj_modules.ai.endpoints import call_text


_MAX_TITLE_CHARS = 15
_TITLE_SYSTEM_PROMPT = (
    "你负责给 Agent 任务命名。只输出一个不超过 15 个汉字或字符的简洁标题，"
    "不要引号、句号、Markdown、解释或前缀。"
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
    return (line or "Agent 任务")[:_MAX_TITLE_CHARS]


def generate_agent_title(endpoint, task_prompt, *, fallback="Agent 任务"):
    """只发起一次标题调用；节点故障时使用确定性的本地回退。"""

    try:
        result = call_text(
            endpoint,
            str(task_prompt or ""),
            system_prompt=_TITLE_SYSTEM_PROMPT,
            temperature=0,
            max_tokens=48,
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
    return str(session.get("title") or "").strip()[:_MAX_TITLE_CHARS]


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

    from oj_modules.agents.sessions import claim_agent_session_title_generation

    if not claim_agent_session_title_generation(session_id, fallback_title):
        return (
            existing_agent_session_title(session_id)
            or fallback_title
        )
    return generate_agent_title(
        endpoint,
        task_prompt,
        fallback=fallback_title,
    )


__all__ = [
    "existing_agent_session_title",
    "generate_agent_title",
    "generate_initial_agent_session_title",
    "normalize_agent_title",
]
