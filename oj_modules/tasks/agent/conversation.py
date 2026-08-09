#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用 Agent 单轮对话的轨迹结论投影。"""

from __future__ import annotations

from oj_modules.problems.agent_runs import agent_run_trace_dir
from oj_modules.ranking.reverse_judge.traces import collect_agent_trace_messages


_MAX_CONCLUSION_CHARS = 64 * 1024


def extract_agent_conclusion(task_id):
    """返回任务轨迹中最后一条可见 assistant 消息。"""

    try:
        messages = collect_agent_trace_messages(agent_run_trace_dir(task_id))
    except Exception:
        return ""
    for message in reversed(messages or []):
        if not isinstance(message, dict):
            continue
        if str(message.get("kind") or "").strip().lower() != "assistant":
            continue
        text = str(message.get("text") or "").strip()
        if text:
            return text[:_MAX_CONCLUSION_CHARS]
    return ""


__all__ = ["extract_agent_conclusion"]
