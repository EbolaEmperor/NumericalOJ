#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 单轮对话的轨迹结论投影。"""

from __future__ import annotations

from oj_modules.agents.trace_store import get_last_agent_trace_assistant


_MAX_CONCLUSION_CHARS = 64 * 1024


def extract_agent_conclusion(task_id):
    """返回任务轨迹中最后一条可见 assistant 消息。"""

    try:
        return get_last_agent_trace_assistant(task_id)[:_MAX_CONCLUSION_CHARS]
    except Exception:
        return ""


__all__ = ["extract_agent_conclusion"]
