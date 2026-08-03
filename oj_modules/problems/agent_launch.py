#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解题/造数据 Agent 的 harness 与全局 LLM 节点选择规则。"""

from __future__ import annotations

import re

from oj_modules.ranking.agent_judge.db import (
    ALLOWED_AGENT_HARNESSES,
    allowed_agent_endpoint_protocols,
    normalize_agent_harness,
)
from oj_modules.site_config.services import get_llm_endpoint, list_llm_endpoints


AGENT_TASK_SOLVE = "solve"
AGENT_TASK_TESTDATA = "testdata"
ALLOWED_AGENT_TASK_KINDS = (AGENT_TASK_SOLVE, AGENT_TASK_TESTDATA)

_HARNESS_LABELS = {
    "claude_code": "Claude Code",
    "codex": "Codex",
    "opencode": "OpenCode",
    "pi": "Pi",
}
_TASK_SKILLS = {
    AGENT_TASK_SOLVE: "numoj-user",
    AGENT_TASK_TESTDATA: "numoj-user",
}
_CHAT_ENDPOINT_CATEGORIES = frozenset({"omni", "text"})


class AgentLaunchValidationError(ValueError):
    """本次 Agent 启动参数不合法。"""


def normalize_agent_task_kind(value):
    task_kind = str(value or "").strip().lower()
    if task_kind not in ALLOWED_AGENT_TASK_KINDS:
        raise AgentLaunchValidationError("Agent 任务类型无效")
    return task_kind


def normalize_launch_harness(value):
    raw = str(value or "").strip().lower().replace("-", "_")
    harness = normalize_agent_harness(raw)
    # ranking 的兼容归一化会把未知值回退到 Claude；普通 Agent 的用户输入必须
    # fail-closed，不能把拼写错误静默解释成另一种 harness。
    if raw == "pi_agent":
        raw = "pi"
    if raw not in ALLOWED_AGENT_HARNESSES or harness != raw:
        raise AgentLaunchValidationError("Agent harness 无效")
    return harness


def skill_for_agent_task(task_kind):
    return _TASK_SKILLS[normalize_agent_task_kind(task_kind)]


def harness_options():
    return [
        {
            "value": harness,
            "label": _HARNESS_LABELS.get(harness, harness),
        }
        for harness in ALLOWED_AGENT_HARNESSES
    ]


def _endpoint_protocol(endpoint):
    return str((endpoint or {}).get("protocol") or "").strip().lower()


def _endpoint_category(endpoint):
    return str((endpoint or {}).get("category") or "").strip().lower()


def _normalize_endpoint_id(value):
    if type(value) is int:
        endpoint_id = value
    elif type(value) is str and re.fullmatch(r"[1-9][0-9]*", value):
        endpoint_id = int(value)
    else:
        raise AgentLaunchValidationError("请选择有效的 LLM 节点")
    if endpoint_id <= 0 or endpoint_id > 9_223_372_036_854_775_807:
        raise AgentLaunchValidationError("请选择有效的 LLM 节点")
    return endpoint_id


def endpoint_supports_harness(endpoint, harness):
    try:
        harness = normalize_launch_harness(harness)
    except AgentLaunchValidationError:
        return False
    return (
        _endpoint_category(endpoint) in _CHAT_ENDPOINT_CATEGORIES
        and _endpoint_protocol(endpoint) in set(allowed_agent_endpoint_protocols(harness))
    )


def _public_launch_endpoint(endpoint):
    return {
        "id": int(endpoint["id"]),
        "model": str(endpoint.get("model") or "").strip(),
        "protocol": _endpoint_protocol(endpoint),
        "category": _endpoint_category(endpoint),
        "thinking_enabled": bool(endpoint.get("thinking_enabled")),
        "test_status": str(endpoint.get("test_status") or "untested"),
    }


def list_launch_endpoints_by_harness():
    """列出各 harness 可用节点；响应不含 URL 和密钥。"""

    endpoints = list_llm_endpoints(include_secrets=False)
    return {
        harness: [
            _public_launch_endpoint(endpoint)
            for endpoint in endpoints
            if bool(endpoint.get("api_key_configured"))
            and endpoint_supports_harness(endpoint, harness)
        ]
        for harness in ALLOWED_AGENT_HARNESSES
    }


def resolve_launch_endpoint(harness, endpoint_id, *, include_secret):
    """读取并验证本次运行冻结使用的全局 LLM 节点。"""

    harness = normalize_launch_harness(harness)
    endpoint_id = _normalize_endpoint_id(endpoint_id)

    try:
        endpoint = get_llm_endpoint(endpoint_id, include_secret=include_secret)
    except Exception as exc:
        raise AgentLaunchValidationError("所选 LLM 节点不存在或已被删除") from exc
    if not endpoint_supports_harness(endpoint, harness):
        raise AgentLaunchValidationError("所选 LLM 节点与 harness 的协议不兼容")
    if include_secret:
        has_api_key = bool(str(endpoint.get("api_key") or "").strip())
    else:
        has_api_key = bool(endpoint.get("api_key_configured"))
    if not has_api_key:
        raise AgentLaunchValidationError("所选 LLM 节点没有可用的 API Key")
    return endpoint


__all__ = [
    "AGENT_TASK_SOLVE",
    "AGENT_TASK_TESTDATA",
    "ALLOWED_AGENT_TASK_KINDS",
    "AgentLaunchValidationError",
    "endpoint_supports_harness",
    "harness_options",
    "list_launch_endpoints_by_harness",
    "normalize_agent_task_kind",
    "normalize_launch_harness",
    "resolve_launch_endpoint",
    "skill_for_agent_task",
]
