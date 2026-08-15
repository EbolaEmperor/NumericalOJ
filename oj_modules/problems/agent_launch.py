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
from oj_modules.site_config.services import (
    DEFAULT_LLM_CONTEXT_WINDOW_TOKENS,
    DEFAULT_LLM_MAX_OUTPUT_TOKENS,
    get_llm_endpoint,
    list_llm_endpoints,
)
from oj_modules.agents.user_endpoints import (
    get_user_agent_endpoint,
    list_user_agent_endpoints,
)


AGENT_TASK_SOLVE = "solve"
AGENT_TASK_TESTDATA = "testdata"
AGENT_TASK_CUSTOM = "custom"
ALLOWED_AGENT_TASK_KINDS = (
    AGENT_TASK_SOLVE,
    AGENT_TASK_TESTDATA,
    AGENT_TASK_CUSTOM,
)

AGENT_ACCESS_ROLE_USER = "user"
AGENT_ACCESS_ROLE_ADMIN = "admin"
ALLOWED_AGENT_ACCESS_ROLES = (
    AGENT_ACCESS_ROLE_USER,
    AGENT_ACCESS_ROLE_ADMIN,
)

AGENT_DEFAULT_REASONING_EFFORT = "high"

_DEFAULT_REASONING_EFFORT = "default"
_REASONING_EFFORT_OPTIONS_BY_HARNESS = {
    "pi": (
        ("off", "关闭"),
        ("minimal", "最少"),
        ("low", "低"),
        ("medium", "中"),
        ("high", "高"),
        ("xhigh", "极高"),
        ("max", "最大"),
    ),
    "claude_code": (
        ("low", "低"),
        ("medium", "中"),
        ("high", "高"),
        ("xhigh", "极高"),
        ("max", "最大"),
    ),
}

_HARNESS_LABELS = {
    "claude_code": "Claude Code",
    "codex": "Codex",
    "opencode": "OpenCode",
    "pi": "Pi",
}
_TASK_SKILLS = {
    AGENT_TASK_SOLVE: "numoj-user",
}
_ACCESS_ROLE_SKILLS = {
    AGENT_ACCESS_ROLE_USER: "numoj-user",
    AGENT_ACCESS_ROLE_ADMIN: "numoj-admin",
}
_CHAT_ENDPOINT_CATEGORIES = frozenset({"omni", "text"})
_TOKEN_PRICE_FIELDS = (
    "input_price_per_million",
    "cached_input_price_per_million",
    "output_price_per_million",
)

SOLUTION_AGENT_PROMPT = (
    "请帮我求解 NumOJ 上的《{problem_title}》这道题，题目编号是 {problem_id}。"
    "请在本地写好 solution 并充分测试，确认无误后用 numoj-user skill "
    "提交到 NumOJ 评测。"
)

TESTDATA_AGENT_PROMPT = (
    "请帮我为 NumOJ 上的《{problem_title}》这道题生成 {test_point_count} 个高质量测试点，"
    "题目编号是 {problem_id}。标准程序已经作为本条消息的附件提供。"
    "{data_requirement}请使用 numoj-admin skill 获取题目和管理员可见的相关资源，"
    "在本地生成并充分验证测试数据，确认无误后用 numoj-admin skill 上传到 NumOJ。"
)


class AgentLaunchValidationError(ValueError):
    """本次 Agent 启动参数不合法。"""


def build_solution_agent_prompt(*, problem_id, problem_title):
    """构造并持久化为首轮用户消息的统一解题指令。"""

    return SOLUTION_AGENT_PROMPT.format(
        problem_id=int(problem_id),
        problem_title=str(problem_title or ""),
    )


def build_testdata_agent_prompt(
    *,
    problem_id,
    problem_title,
    test_point_count,
    data_requirement="",
):
    """构造造数据按钮代发的首轮普通用户消息。"""

    requirement = str(data_requirement or "").strip()
    requirement_text = (
        f"数据要求：{requirement}。"
        if requirement
        else "请自行覆盖边界、典型与压力场景。"
    )
    return TESTDATA_AGENT_PROMPT.format(
        problem_id=int(problem_id),
        problem_title=str(problem_title or ""),
        test_point_count=int(test_point_count),
        data_requirement=requirement_text,
    )


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


def reasoning_effort_options_by_harness():
    """返回前端可展示的 Harness 原生思考深度选项。"""

    return {
        harness: [
            {"value": value, "label": label}
            for value, label in options
        ]
        for harness, options in _REASONING_EFFORT_OPTIONS_BY_HARNESS.items()
    }


def default_reasoning_effort_for_harness(harness):
    """新建网页会话的缺省深度；不支持该能力的 Harness 沿用自身默认。"""

    harness = normalize_launch_harness(harness)
    if harness in _REASONING_EFFORT_OPTIONS_BY_HARNESS:
        return AGENT_DEFAULT_REASONING_EFFORT
    return _DEFAULT_REASONING_EFFORT


def normalize_agent_reasoning_effort(
    value,
    harness,
    *,
    default=_DEFAULT_REASONING_EFFORT,
):
    """校验会话冻结的原生 Harness 思考深度。"""

    harness = normalize_launch_harness(harness)
    effort = str(value or "").strip().lower()
    if not effort:
        effort = str(default or _DEFAULT_REASONING_EFFORT).strip().lower()
    if effort == _DEFAULT_REASONING_EFFORT:
        return effort
    allowed = {
        option_value
        for option_value, _label in _REASONING_EFFORT_OPTIONS_BY_HARNESS.get(
            harness,
            (),
        )
    }
    if effort not in allowed:
        raise AgentLaunchValidationError("所选 Harness 不支持该思考深度")
    return effort


def normalize_agent_access_role(value, *, task_kind=AGENT_TASK_CUSTOM):
    """校验任务执行身份；解题按钮固定使用普通用户权限。"""

    normalized_task_kind = normalize_agent_task_kind(task_kind)
    access_role = str(value or AGENT_ACCESS_ROLE_USER).strip().lower()
    if access_role not in ALLOWED_AGENT_ACCESS_ROLES:
        raise AgentLaunchValidationError("Agent 执行身份无效")
    if (
        normalized_task_kind == AGENT_TASK_SOLVE
        and access_role != AGENT_ACCESS_ROLE_USER
    ):
        raise AgentLaunchValidationError("解题 Agent 只能使用 user 身份")
    return access_role


def skill_for_agent_task(task_kind, access_role=AGENT_ACCESS_ROLE_USER):
    normalized_task_kind = normalize_agent_task_kind(task_kind)
    if normalized_task_kind in _TASK_SKILLS:
        return _TASK_SKILLS[normalized_task_kind]
    normalized_role = normalize_agent_access_role(
        access_role,
        task_kind=normalized_task_kind,
    )
    return _ACCESS_ROLE_SKILLS[normalized_role]


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


def normalize_launch_endpoint_ref(value):
    """规范化节点引用；纯数字沿用升级前的全站节点语义。"""

    if type(value) is int:
        return "global", _normalize_endpoint_id(value)
    if type(value) is str:
        if re.fullmatch(r"[1-9][0-9]*", value):
            return "global", _normalize_endpoint_id(value)
        matched = re.fullmatch(r"(global|user):([1-9][0-9]*)", value)
        if matched:
            return matched.group(1), _normalize_endpoint_id(matched.group(2))
    raise AgentLaunchValidationError("请选择有效的 LLM 节点")


def endpoint_supports_harness(endpoint, harness):
    try:
        harness = normalize_launch_harness(harness)
    except AgentLaunchValidationError:
        return False
    return (
        _endpoint_category(endpoint) in _CHAT_ENDPOINT_CATEGORIES
        and _endpoint_protocol(endpoint) in set(allowed_agent_endpoint_protocols(harness))
    )


def _public_launch_endpoint(endpoint, *, source="global"):
    endpoint_id = int(endpoint["id"])
    result = {
        "id": endpoint_id,
        "ref": f"{source}:{endpoint_id}",
        "source": source,
        "model": str(endpoint.get("model") or "").strip(),
        "protocol": _endpoint_protocol(endpoint),
        "category": _endpoint_category(endpoint),
        "context_window_tokens": int(
            endpoint.get("context_window_tokens")
            or DEFAULT_LLM_CONTEXT_WINDOW_TOKENS
        ),
        "max_output_tokens": int(
            endpoint.get("max_output_tokens")
            or DEFAULT_LLM_MAX_OUTPUT_TOKENS
        ),
        "thinking_enabled": bool(endpoint.get("thinking_enabled")),
        "test_status": str(endpoint.get("test_status") or "untested"),
        "is_personal": source == "user",
        "metered": source == "global",
    }
    if source == "global":
        pricing = token_pricing_from_endpoint(endpoint)
        if pricing:
            result.update(pricing)
    return result


def token_pricing_from_endpoint(endpoint):
    """读取节点完整的人民币 Token 单价。"""

    values = {}
    for field in _TOKEN_PRICE_FIELDS:
        raw = (endpoint or {}).get(field)
        values[field] = "" if raw is None else str(raw).strip()
    if not all(values.values()):
        return None
    return values


def list_launch_endpoints_by_harness(*, user_id=None):
    """列出各 harness 可用节点；响应不含 URL 和密钥。"""

    endpoints = list_llm_endpoints(include_secrets=False)
    personal_endpoints = (
        list_user_agent_endpoints(user_id, include_secrets=False)
        if user_id is not None
        else []
    )
    return {
        harness: (
            [
                _public_launch_endpoint(endpoint, source="user")
                for endpoint in personal_endpoints
                if bool(endpoint.get("api_key_configured"))
                and endpoint_supports_harness(endpoint, harness)
            ]
            + [
                _public_launch_endpoint(endpoint)
                for endpoint in endpoints
                if bool(endpoint.get("api_key_configured"))
                and token_pricing_from_endpoint(endpoint) is not None
                and endpoint_supports_harness(endpoint, harness)
            ]
        )
        for harness in ALLOWED_AGENT_HARNESSES
    }


def resolve_launch_endpoint(
    harness,
    endpoint_ref,
    *,
    include_secret,
    user_id=None,
):
    """读取并验证本次运行冻结使用的全站或用户自有节点。"""

    harness = normalize_launch_harness(harness)
    source, endpoint_id = normalize_launch_endpoint_ref(endpoint_ref)

    try:
        if source == "user":
            if user_id is None:
                raise AgentLaunchValidationError("自有 LLM 节点不属于当前用户")
            endpoint = get_user_agent_endpoint(
                endpoint_id,
                user_id,
                include_secret=include_secret,
            )
        else:
            endpoint = get_llm_endpoint(endpoint_id, include_secret=include_secret)
    except Exception as exc:
        if isinstance(exc, AgentLaunchValidationError):
            raise
        raise AgentLaunchValidationError("所选 LLM 节点不存在或已被删除") from exc
    if not endpoint_supports_harness(endpoint, harness):
        raise AgentLaunchValidationError("所选 LLM 节点与 harness 的协议不兼容")
    if include_secret:
        has_api_key = bool(str(endpoint.get("api_key") or "").strip())
    else:
        has_api_key = bool(endpoint.get("api_key_configured"))
    if not has_api_key:
        raise AgentLaunchValidationError("所选 LLM 节点没有可用的 API Key")
    endpoint = dict(endpoint)
    endpoint["source"] = source
    endpoint["ref"] = f"{source}:{endpoint_id}"
    endpoint["is_personal"] = source == "user"
    endpoint["metered"] = source == "global"
    return endpoint


def validate_launch_endpoint_revision(endpoint, expected_revision):
    """确保排队及后续轮次使用创建会话时选定的节点版本。"""

    current_value = (endpoint or {}).get("revision")
    if isinstance(current_value, bool) or isinstance(expected_revision, bool):
        raise AgentLaunchValidationError("Agent 会话的 LLM 节点版本无效")
    try:
        current = int(current_value)
        expected = int(expected_revision)
    except (TypeError, ValueError):
        raise AgentLaunchValidationError("Agent 会话的 LLM 节点版本无效") from None
    if current <= 0 or expected <= 0 or current != expected:
        raise AgentLaunchValidationError(
            "该 Agent 会话使用的 LLM 节点配置已变化，请新建会话"
        )
    return endpoint


__all__ = [
    "AGENT_ACCESS_ROLE_ADMIN",
    "AGENT_ACCESS_ROLE_USER",
    "AGENT_DEFAULT_REASONING_EFFORT",
    "AGENT_TASK_CUSTOM",
    "AGENT_TASK_SOLVE",
    "AGENT_TASK_TESTDATA",
    "ALLOWED_AGENT_ACCESS_ROLES",
    "ALLOWED_AGENT_TASK_KINDS",
    "AgentLaunchValidationError",
    "SOLUTION_AGENT_PROMPT",
    "TESTDATA_AGENT_PROMPT",
    "build_solution_agent_prompt",
    "build_testdata_agent_prompt",
    "endpoint_supports_harness",
    "default_reasoning_effort_for_harness",
    "harness_options",
    "list_launch_endpoints_by_harness",
    "normalize_agent_access_role",
    "normalize_agent_reasoning_effort",
    "normalize_agent_task_kind",
    "normalize_launch_endpoint_ref",
    "normalize_launch_harness",
    "resolve_launch_endpoint",
    "reasoning_effort_options_by_harness",
    "skill_for_agent_task",
    "token_pricing_from_endpoint",
    "validate_launch_endpoint_revision",
]
