"""通用 Agent 原生思考深度的兼容与校验契约。"""

import pytest

from oj_modules.problems.agent_launch import (
    AGENT_DEFAULT_REASONING_EFFORT,
    AgentLaunchValidationError,
    default_reasoning_effort_for_harness,
    normalize_agent_reasoning_effort,
    reasoning_effort_options_by_harness,
)


def test_reasoning_effort_options_follow_each_harness_interface():
    options = reasoning_effort_options_by_harness()

    assert [item["value"] for item in options["pi"]] == [
        "off",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    ]
    assert [item["value"] for item in options["claude_code"]] == [
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    ]
    assert options["pi"][0] == {"value": "off", "label": "关闭"}
    assert "codex" not in options
    assert "opencode" not in options


@pytest.mark.parametrize("harness", ["pi", "claude_code"])
def test_supported_harness_defaults_to_high_for_new_web_sessions(harness):
    assert AGENT_DEFAULT_REASONING_EFFORT == "high"
    assert default_reasoning_effort_for_harness(harness) == "high"
    assert normalize_agent_reasoning_effort(
        "",
        harness,
        default=default_reasoning_effort_for_harness(harness),
    ) == "high"


@pytest.mark.parametrize("harness", ["codex", "opencode"])
def test_unsupported_harness_only_accepts_native_default(harness):
    assert default_reasoning_effort_for_harness(harness) == "default"
    assert normalize_agent_reasoning_effort(None, harness) == "default"
    with pytest.raises(AgentLaunchValidationError, match="不支持该思考深度"):
        normalize_agent_reasoning_effort("high", harness)


def test_harness_specific_reasoning_effort_values_are_enforced():
    assert normalize_agent_reasoning_effort("minimal", "pi") == "minimal"
    assert normalize_agent_reasoning_effort("XHIGH", "claude-code") == "xhigh"
    with pytest.raises(AgentLaunchValidationError, match="不支持该思考深度"):
        normalize_agent_reasoning_effort("minimal", "claude_code")
