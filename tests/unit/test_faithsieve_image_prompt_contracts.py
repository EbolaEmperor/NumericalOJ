"""直接图片验证的数学上下文、诊断回传与旧提示词兼容契约。"""

import json
from pathlib import Path
import re

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.prompts import (
    IMAGE_PROMPT_ROOT,
    IMAGE_ROLE_NAMES,
    render_image_role_prompt,
)


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("role", sorted(IMAGE_ROLE_NAMES))
def test_image_prompt_mirrors_keep_the_same_mathematical_contract(role):
    runtime = IMAGE_PROMPT_ROOT / f"{role}.md"
    skill = ROOT / "skills/faithsieve/references/image-agents" / runtime.name
    assert runtime.read_bytes() == skill.read_bytes()
    rendered = render_image_role_prompt(role, {"node_id": "N3"})
    assert "{node_id}" not in rendered
    assert "不提取 PDF 文本" in rendered or "不生成转录" in rendered


def test_local_result_examples_expose_graph_defects_without_changing_math_reports():
    prompt = render_image_role_prompt("local-verifier", {"node_id": "N3"})
    examples = [json.loads(text) for text in re.findall(r"```json\n(.*?)\n```", prompt, re.S)]
    assert {item["status"] for item in examples} == {"passed", "graph_defect"}
    for item in examples:
        assert set(item) == {"status", "artifact", "report", "diagnostics"}
        assert item["artifact"] == "faithsieve-work/verification/N3.md"
        assert bool(item["diagnostics"]) is (item["status"] == "graph_defect")
        for diagnostic in item["diagnostics"]:
            assert set(diagnostic) == {"kind", "affected_node_ids", "reason"}
            assert diagnostic["kind"] in {
                "statement_mismatch", "missing_premise", "quantifier_drift", "binding_mismatch",
            }
            assert diagnostic["affected_node_ids"] == ["N3"]
            assert diagnostic["reason"]


def test_fresh_prompts_preserve_the_complete_local_responsibility():
    builder = render_image_role_prompt("tree-builder")
    auditor = render_image_role_prompt("tree-auditor")
    verifier = render_image_role_prompt("local-verifier", {"node_id": "N3"})
    assert "全局定义和全局假设必须用 given" in builder
    assert "只有祖先存在、题面提到或原图使用都不算完整局部上下文" in auditor
    assert "定理不需要事先登记成 DAG 前驱" in verifier
    assert "核对定理原陈述、全部适用条件" in verifier
    assert "无歧义的绑定变量改名不改变命题" in verifier
    assert "原图与 DAG 必须保持相同的量词、作用域和绑定" in verifier
    assert "使用额外假设的 theorem 编译通过不允许 passed" in verifier
    assert "证据未覆盖完整局部蕴含时不能返回 passed" in verifier
    assert "若 DAG 忠实表达了原稿推理，应验证这个完整推理" in verifier


def test_source_conditions_require_connected_sources_for_every_used_assumption():
    resource = IMAGE_PROMPT_ROOT / "source-conditions.md"
    skill = ROOT / "skills/faithsieve/references/image-agents/source-conditions.md"
    assert resource.read_bytes() == skill.read_bytes()
    prompt = resource.read_text(encoding="utf-8")
    for role in ("tree-builder", "tree-auditor", "local-verifier", "verification-auditor"):
        assert f"### {role}\n" in prompt
    assert "实际使用的每项定义和条件，逐项指出" in prompt
    assert "完整直接前驱 statement 或 goal 内封装的哪条局部条件提供" in prompt
    assert "只要没有直接连接本节点，就不算这个局部蕴含的已有前提" in prompt
    assert "goal 中待证的结论不是可使用的局部条件" in prompt
    assert "Lean theorem 中每项假设及定义的来源" in prompt
    assert "原图真实条件被图遗漏时 graph_defect/missing_premise" in prompt
    assert "图忠实而验证者额外加假设时 needs_revision" in prompt
    assert "已有数学定理仍可搜索和使用" in prompt
    assert "允许给出从这些已列明条件推出所需条件的可核对短推导" in prompt


@pytest.mark.parametrize("role", ["tree-builder", "tree-auditor", "local-verifier", "verification-auditor"])
def test_source_conditions_are_only_appended_in_the_frozen_new_sorting_mode(role):
    parameters = {"node_id": "N3"}
    supplement = (IMAGE_PROMPT_ROOT / "source-conditions.md").read_text(encoding="utf-8")
    common = supplement.split("### ", 1)[0].strip()
    historical = render_image_role_prompt(role, parameters)
    assert historical == render_image_role_prompt(role, parameters, node_selection_version=None)
    assert common not in historical
    current = render_image_role_prompt(role, parameters, node_selection_version=1)
    assert current.count(common) == 1
    assert f"### {role}\n" in current
    for other in {"tree-builder", "tree-auditor", "local-verifier", "verification-auditor"} - {role}:
        assert f"### {other}\n" not in current
    assert "{node_id}" not in current


def test_local_judge_receives_no_other_roles_source_condition_responsibilities():
    prompt = render_image_role_prompt("local-verifier", {"node_id": "N3"}, node_selection_version=1)
    assert "报告列明实际使用的全部条件及来源，并核对每项推理的适用条件" in prompt
    assert "构图时逐节点检查以上来源" not in prompt
    assert "对每个节点实际使用的上述条件逐项核对" not in prompt
    assert "逐一核对实际论证和 Lean theorem 中每项假设及定义的来源" not in prompt


@pytest.mark.parametrize("role", ["node-selector", "evidence-mapper", "final-synthesizer", "consistency-auditor"])
def test_source_conditions_do_not_add_an_extra_responsibility_to_other_roles(role):
    historical = render_image_role_prompt(role)
    assert render_image_role_prompt(role, node_selection_version=1) == historical


def test_legacy_image_prompt_resources_preserve_three_field_result_contract():
    legacy = IMAGE_PROMPT_ROOT.parent / "legacy_image_prompts"
    assert {path.stem for path in legacy.glob("*.md")} == {
        "tree-builder", "tree-auditor", "local-verifier", "evidence-mapper",
        "final-synthesizer", "consistency-auditor",
    }
    verifier = (legacy / "local-verifier.md").read_text(encoding="utf-8")
    assert '"status":"passed|refuted|inconclusive"' in verifier
    assert '"diagnostics"' not in verifier
    assert "graph_defect" not in verifier


def test_verification_auditor_does_not_reprove_or_change_the_responsibility():
    original = (IMAGE_PROMPT_ROOT / "verification-auditor.md").read_text(encoding="utf-8")
    prompt = original.replace("{node_id}", "N3")
    assert "不自行重证该命题，不重新构图" in prompt
    assert "不从题面、祖先、其他分支或图片暗中添加数学假设" in prompt
    assert "原有量词、顺序、作用域及共享绑定是否保持" in prompt
    assert "使用额外假设的 theorem 编译成功，不支持 passed" in prompt
    assert "报告是否如实界定其覆盖范围与不确定性" in prompt
    assert "不重新搜索数学资料，不执行数值或 Lean" in prompt
    assert "不能自行将作者的数学结论改成 passed/refuted" in prompt
    examples = [json.loads(text) for text in re.findall(r"```json\n(.*?)\n```", prompt, re.S)]
    assert {item["status"] for item in examples} == {"ok", "graph_defect"}
    for item in examples:
        assert set(item) == {"status", "artifact", "report", "diagnostics"}
        assert item["artifact"] == "faithsieve-work/review/N3-verification.md"
        assert bool(item["diagnostics"]) is (item["status"] == "graph_defect")


@pytest.mark.parametrize("role", ["evidence-mapper", "final-synthesizer", "consistency-auditor"])
def test_final_roles_cannot_use_raw_refutation_that_failed_semantic_audit(role):
    prompt = render_image_role_prompt(role)
    assert "始终以宿主的有效 local_status 为准" in prompt
    assert "agent_status=refuted、semantic_audit_status=needs_revision" in prompt
    assert "宿主 local_status=inconclusive" in prompt
    assert "semantic_audit_artifact" in prompt
    assert "原始报告仅保留审计证据，不能越过审核 ok" in prompt
    assert "不能据原始 refuted 指责作者" in prompt
    assert "原始 passed 同样不能建立节点" in prompt


def test_verification_method_resource_checks_actual_work_without_forcing_a_verdict():
    resource = IMAGE_PROMPT_ROOT / "verification-method-audit.md"
    mirror = ROOT / "skills/faithsieve/references/image-agents" / resource.name
    assert resource.read_bytes() == mirror.read_bytes()
    text = resource.read_text(encoding="utf-8")
    assert text.startswith("## 验证方法与不确定结论\n")
    assert "不需要预先登记为 DAG 前驱" in text
    assert "可以自主检索、核对并应用" in text
    assert "或由它们严格推出，不能补入新假设" in text
    assert "来源、准确陈述、适用条件及其与当前目标的对应关系" in text
    assert "计划搜索、仅提名称或未经核对的猜测不能写成已经核实" in text
    assert "联网不是必需条件，完整独立数学推导同样有效" in text
    assert "证据只能支持其实际覆盖的范围" in text
    assert "须给出足以确认所报结论的误差控制" in text
    assert "保持同一目标和全部直接前驱" in text
    assert "不能把“只澄清、不能强求结论”误读成禁止自主补足验证工作" in text
    assert "不要求必须找到反例或得出 passed/refuted" in text
    assert "不自行重证、重新搜索或执行工具" in text
    assert "对可确认的方法误解返回 needs_revision" in text
    assert "ok 不提升原始 inconclusive 的数学结论" in text
    assert not re.search(r"\bN\d+\b", text)


@pytest.mark.parametrize("role", sorted(IMAGE_ROLE_NAMES))
@pytest.mark.parametrize("mode", [{}, {"node_selection_version": 1}, {
    "node_selection_version": 1, "verification_audit_version": 1,
}])
def test_verification_method_none_preserves_each_existing_prompt_epoch(role, mode):
    parameters = {"node_id": "N3"}
    original = render_image_role_prompt(role, parameters, **mode)
    assert render_image_role_prompt(role, parameters, verification_method_version=None,
                                   **mode) == original
    assert "## 验证方法与不确定结论\n" not in original


@pytest.mark.parametrize("role", sorted(IMAGE_ROLE_NAMES))
def test_verification_method_only_adds_its_resource_to_the_two_verification_roles(role):
    parameters = {"node_id": "N3"}
    mode = {"node_selection_version": 1, "verification_audit_version": 1}
    original = render_image_role_prompt(role, parameters, **mode)
    current = render_image_role_prompt(role, parameters, verification_method_version=1,
                                      **mode)
    if role in {"local-verifier", "verification-auditor"}:
        resource = (IMAGE_PROMPT_ROOT / "verification-method-audit.md").read_text(
            encoding="utf-8",
        )
        assert current == original + "\n\n" + resource
        assert current.count("## 验证方法与不确定结论\n") == 1
    else:
        assert current == original


@pytest.mark.parametrize("role", ["tree-builder", "tree-auditor", "local-verifier",
                                 "evidence-mapper", "final-synthesizer", "consistency-auditor"])
def test_verification_method_none_keeps_the_legacy_image_prompt(role):
    original = render_image_role_prompt(role, {"node_id": "N3"}, legacy=True)
    assert render_image_role_prompt(role, {"node_id": "N3"}, legacy=True,
                                   verification_method_version=None) == original
    assert "## 验证方法与不确定结论\n" not in original


@pytest.mark.parametrize("version", [True, False, 1.0, 0, 2, "1", {}, []])
def test_verification_method_version_rejects_loose_marker_types(version):
    with pytest.raises(FaithSieveProtocolError, match="验证方法审核版本无效"):
        render_image_role_prompt("local-verifier", {"node_id": "N3"},
                                 node_selection_version=1, verification_audit_version=1,
                                 verification_method_version=version)


@pytest.mark.parametrize("mode", [{}, {"node_selection_version": 1}, {
    "legacy": True,
}])
def test_verification_method_cannot_upgrade_an_older_image_protocol(mode):
    with pytest.raises(ValueError, match="验证方法审核必须使用新版图像协议"):
        render_image_role_prompt("local-verifier", {"node_id": "N3"},
                                 verification_method_version=1, **mode)
