"""外部定理明确入图，局部 Lean 只允许为列明前置证据占位。"""

from pathlib import Path

import pytest

from backend.oj_modules.faithsieve.prompts import IMAGE_PROMPT_ROOT, IMAGE_ROLE_NAMES, render_image_role_prompt


ROOT = Path(__file__).resolve().parents[2]
OPTIONS = {"node_selection_version": 1, "verification_audit_version": 1,
           "verification_method_version": 1}


def test_external_resource_and_skill_mirror_preserve_the_same_local_contract():
    runtime = IMAGE_PROMPT_ROOT / "external-results.md"
    skill = ROOT / "skills/faithsieve/references/image-agents/external-results.md"
    assert runtime.read_bytes() == skill.read_bytes()
    source = runtime.read_text(encoding="utf-8")
    for role in IMAGE_ROLE_NAMES:
        assert f"### {role}\n" in source
    assert "statement 给出完整数学陈述" in source
    assert "kind=external" in source
    assert "外部定理自身的适用条件必须完整保留" in source
    assert "不能另用 sorry 假定" in source


@pytest.mark.parametrize("role", sorted(IMAGE_ROLE_NAMES))
def test_frozen_external_version_appends_only_the_current_role(role):
    parameters = {"node_id": "N3"}
    old = render_image_role_prompt(role, parameters, **OPTIONS)
    assert old == render_image_role_prompt(role, parameters, external_results_version=None, **OPTIONS)
    assert "## 外部结果与局部 Lean 验证" not in old
    current = render_image_role_prompt(role, parameters, external_results_version=1, **OPTIONS)
    assert current.startswith(old)
    assert current.count("## 外部结果与局部 Lean 验证") == 1
    assert f"### {role}\n" in current
    supplement = current[len(old):]
    for other in IMAGE_ROLE_NAMES - {role}:
        assert f"### {other}\n" not in supplement
    assert "{node_id}" not in current


def test_current_lean_contract_does_not_confuse_premise_placeholders_with_target_proof():
    prompt = render_image_role_prompt("local-verifier", {"node_id": "N3"},
                                      external_results_version=1, **OPTIONS)
    current = prompt.split("## 外部结果与局部 Lean 验证", 1)[1]
    assert "覆盖前文" in current
    assert "前置结论声明写为 `by sorry`" in current
    assert "直接前驱 ID 及其完整 statement 一一对应" in current
    assert "不能加强前提或改变其量词和作用域" in current
    assert "当前待验证目标的证明必须完整" in current
    assert "新辅助引理、额外条件、定义和对象构造用 sorry" in current
    assert "FaithSieveProof" in current
    assert "编译退出码" in current
    assert "graph_defect/missing_premise" in current
    assert "不能被误当作当前目标用了占位证明" in current
    assert "无需为外部定理补派验证任务" not in current


def test_audit_checks_placeholder_types_and_applicability_without_reproving_premises():
    prompt = render_image_role_prompt("verification-auditor", {"node_id": "N3"},
                                      external_results_version=1, **OPTIONS)
    current = prompt.split("## 外部结果与局部 Lean 验证", 1)[1]
    assert "完整类型、绑定和直接前驱 ID" in current
    assert "完整当前目标及其他非前置辅助结论不能留洞" in current
    assert "全部适用条件必须由原局部前提得到" in current
    assert "必须检查实际代码、完整 theorem 签名、占位声明清单及真实编译结果" in current
    assert "占位覆盖当前目标、额外条件或未登记辅助结论为 needs_revision" in current


def test_skill_main_entry_explicitly_scopes_sorry_and_global_state():
    skill = (ROOT / "skills/faithsieve/SKILL.md").read_text(encoding="utf-8")
    assert "external_results_version=1" in skill
    assert "references/image-agents/external-results.md" in skill
    assert "当前目标以 FaithSieveProof 完整证明" in skill
    assert "前置 claim 在某个局部 Lean 文件中用 sorry 不改变它的建立状态" in skill
    assert "不必登记为 DAG 前驱" not in skill
