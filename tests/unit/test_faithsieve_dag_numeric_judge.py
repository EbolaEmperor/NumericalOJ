"""节点数值验证由完整 Agent 自主决定，不强制表达式文件或宿主复算。"""

import json

import pytest

from backend.oj_modules.faithsieve import judge
from tests.unit.test_faithsieve_judge import environment, invoke


@pytest.mark.parametrize("status", ["passed", "refuted", "inconclusive"])
def test_v2_numeric_uses_agent_status_and_report_without_code_tool(environment, status):
    env = environment
    arguments = {"role": "numeric-evaluator", "proof_graph_version": 2,
                 "prompt": "完整前提 A、B；验证 A 且 B 是否推出 C。"}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    env.finish(pending.value.session_id, role="numeric-evaluator", status=status,
               artifact="numeric.md", text="自主验证的依据与结论")
    result = invoke(env.agent, **arguments)
    assert result["result"]["status"] == status
    assert result["artifacts"] == {"numeric.md": "自主验证的依据与结论"}
    assert result["execution"]["decision_source"] == "agent"
    assert not set(result["execution"]) & {"verified", "tool_executed", "relations"}
    assert env.tools.calls == []
    assert len(env.submissions) == 1
    instruction = env.submissions[0]["prompt"]
    assert "全部直接前提共同推出完整目标" in instruction
    assert "不要求使用固定表达式协议" in instruction
    assert ".expressions.json" not in instruction
    frozen = json.loads((env.agent.directory / "role-000001-attempt-1.json").read_text())
    assert frozen["proof_graph_version"] == 2
    assert invoke(env.agent, **arguments) == result and len(env.submissions) == 1


def test_changed_numeric_protocol_cannot_resume_same_judge_with_another_contract(environment):
    with pytest.raises(judge.FaithSievePending):
        invoke(environment.agent, role="numeric-evaluator", proof_graph_version=2)
    with pytest.raises(judge.FaithSieveJudgeError, match="持久身份"):
        invoke(environment.agent, role="numeric-evaluator", proof_graph_version=1)
    assert len(environment.submissions) == 1 and environment.tools.calls == []


@pytest.mark.parametrize("raw", [
    '{"status":"passed","status":"refuted","artifact":"numeric.md","report":"重复字段"}',
    '{"status":"passed","artifact":"numeric.md","report":NaN}',
    '{"status":"unknown","artifact":"numeric.md","report":"无效状态"}',
])
def test_v2_numeric_still_requires_unambiguous_result_protocol(environment, raw):
    env = environment
    arguments = {"role": "numeric-evaluator", "proof_graph_version": 2}
    with pytest.raises(judge.FaithSievePending) as pending:
        invoke(env.agent, **arguments)
    sid = pending.value.session_id
    env.finish(sid, role="numeric-evaluator", status="passed", artifact="numeric.md")
    (env.root / "child" / sid / "result.json").write_text(raw)
    with pytest.raises(judge.FaithSieveJudgeError, match="JSON|协议"):
        invoke(env.agent, **arguments)
    assert env.tools.calls == []
