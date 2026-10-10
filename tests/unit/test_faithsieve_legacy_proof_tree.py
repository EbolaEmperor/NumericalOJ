"""历史树只读兼容只认明确节点和边，不推断条件、目标或作用域。"""

import pytest

from backend.oj_modules.faithsieve.legacy_proof_tree import parse_legacy_proof_tree


def legacy_tree(version=2, count=32, parents=None):
    """两轮本地树的实际格式，以普通求和替换原论文数学内容。"""
    nodes = []
    for index in range(count):
        if version == 1:
            scope = "作用域：全局。" if index < 12 else ""
            nodes.append(f"- N{index}。Γ{index}=Γ0∪{{a_{index}>0}}。G{index}=G0。{scope}")
        else:
            goal = f"G{index}=G0" if index < 8 else "G8不变" if index == 8 else "G8"
            nodes.append(f"N{index}：Γ{index}=Γ0∪{{a_{index}>0}}；{goal}。")
    blocks = []
    for index in range(1, count):
        parent = parents[index - 1] if parents is not None else index - 1
        if version == 1:
            transition_scope = "推导/范数下界。" if index in {15, 17} else "推导/上界；求和子分支。"
            blocks.append(f"""### E{index}
- 步骤/位置：S{index}，第1页求和。
- 父子：N{parent}->N{index}。
- 输入 Γ/G：Γ_in=Γ0∪{{a_k>0}}；G_in=G0。
- 输出 Γ/G：Γ_out=Γ_in∪{{Σa_k>0}}；G_out=G0。
- 条件变化：保留Γ_in；新增Σa_k>0；消耗无；变换无。
- 目标关系：由正项得到和为正。
- 转换/作用域：{transition_scope}
""")
        else:
            blocks.append(f"""### E{index}（对应 S{index}，第1页求和）
- 父子节点：N{parent}→N{index}
- 输入 Γ/G：Γ{parent}=Γ0∪{{a_k>0}}；G0
- 输出 Γ/G：Γ{index}=Γ{parent}∪{{Σa_k>0}}；G8不变
- 条件变化：新增Σa_k>0；保留Γ{parent}
- 目标关系：由正项得到和为正
- 转换类型：推导/上界
- 分支作用域：求和子分支
""")
    return "# 学生证明状态树\n\n## 节点\n" + "\n".join(nodes) + "\n\n## EdgeUnit\n" + "\n".join(blocks)


def legacy_steps(count=31):
    return "# 待证目标\n证明正数和为正。\n" + "\n".join(f"""## S{index}
- 页码/段落：第{index}页，求和。
- 原稿文本：
a_{index}>0，
故 Σa_k>0。
- 唯一动作：求和。
- 当前分支：求和。
""" for index in range(1, count + 1))


@pytest.mark.parametrize("version", [1, 2])
def test_actual_historical_formats_keep_32_nodes_and_31_explicit_edges(version):
    tree = parse_legacy_proof_tree(legacy_tree(version), legacy_steps())
    assert tree["schema_version"] == 1
    assert tree["format"] == "legacy_markdown"
    assert tree["root_id"] == "N0"
    assert len(tree["nodes"]) == 32 and len(tree["edges"]) == 31
    assert [(edge["from"], edge["to"]) for edge in tree["edges"]] == [(f"N{i}", f"N{i+1}") for i in range(31)]
    assert tree["edges"][7]["step_id"] == "S8"
    assert tree["edges"][7]["source_location"] == "第8页，求和。"
    assert tree["edges"][7]["source_text"] == "a_8>0，\n故 Σa_k>0。"
    assert tree["nodes"][20]["label"] == "N20"
    assert "Γ20=Γ0∪{a_20>0}" in tree["nodes"][20]["raw_state"]
    assert "Γ_in" in tree["edges"][0]["raw_output"] if version == 1 else "Γ0" in tree["edges"][0]["raw_output"]
    assert tree["edges"][0]["transition_type"] == "推导/上界"
    assert any("引用未展开" in message for message in tree["ambiguities"])
    assert any("缺省作用域" in message for message in tree["ambiguities"])
    assert not any("source_text 留空" in message for message in tree["ambiguities"])


def test_state_changes_and_goal_references_are_preserved_instead_of_expanded():
    tree = parse_legacy_proof_tree(legacy_tree())
    assert tree["nodes"][8]["raw_state"] == "Γ8=Γ0∪{a_8>0}；G8不变。"
    assert tree["edges"][0]["raw_output"] == "Γ1=Γ0∪{Σa_k>0}；G8不变"
    assert tree["edges"][0]["raw_changes"] == "新增Σa_k>0；保留Γ0"
    assert tree["edges"][0]["source_location"] == "第1页求和"
    assert tree["edges"][0]["source_text"] == ""
    assert any("未提供同轮" in message for message in tree["ambiguities"])


def test_combined_transition_without_explicit_separator_does_not_invent_scope():
    tree = parse_legacy_proof_tree(legacy_tree(version=1))
    assert tree["edges"][14]["transition_type"] == "推导/范数下界。"
    assert tree["edges"][14]["scope_text"] == ""
    assert any("scope_text 留空" in message for message in tree["ambiguities"])


def test_known_step_ambiguity_footer_is_not_part_of_the_last_source_text():
    steps = legacy_steps() + "\n## 无法辨认或无法安全拆分的内容\n1. 原稿未说明常数选择。"
    tree = parse_legacy_proof_tree(legacy_tree(), steps)
    assert tree["edges"][-1]["source_text"] == "a_31>0，\n故 Σa_k>0。"


def test_missing_scope_stays_empty_and_never_becomes_global():
    text = legacy_tree().replace("- 分支作用域：求和子分支\n", "")
    tree = parse_legacy_proof_tree(text)
    assert all(edge["scope_text"] == "" for edge in tree["edges"])
    assert any("scope_text 留空" in message for message in tree["ambiguities"])


@pytest.mark.parametrize("version", [1, 2])
def test_explicit_parent_relations_can_form_multiple_branches(version):
    tree = parse_legacy_proof_tree(legacy_tree(version, count=5, parents=[0, 0, 1, 1]))
    assert [(edge["from"], edge["to"]) for edge in tree["edges"]] == [
        ("N0", "N1"), ("N0", "N2"), ("N1", "N3"), ("N1", "N4"),
    ]
    assert tree["root_id"] == "N0"


@pytest.mark.parametrize("replacement", [
    ("- 父子节点：N0→N1\n", ""),
    ("- 输入 Γ/G：Γ0=Γ0∪{a_k>0}；G0\n", ""),
    ("- 输出 Γ/G：Γ1=Γ0∪{Σa_k>0}；G8不变\n", ""),
    ("- 条件变化：新增Σa_k>0；保留Γ0\n", ""),
    ("- 目标关系：由正项得到和为正\n", ""),
    ("- 转换类型：推导/上界\n", ""),
    ("N1：Γ1=Γ0∪{a_1>0}；G1=G0。", "N1：Γ1=Γ0∪{a_1>0}。"),
    ("N1：Γ1=Γ0∪{a_1>0}；G1=G0。", "N1：G1=G0。"),
    ("- 输入 Γ/G：Γ0=Γ0∪{a_k>0}；G0", "- 输入 Γ/G：条件略；G0"),
    ("- 输出 Γ/G：Γ1=Γ0∪{Σa_k>0}；G8不变", "- 输出 Γ/G：Γ1=Γ0∪{Σa_k>0}"),
    ("### E1（对应 S1，第1页求和）", "### E1"),
    ("- 父子节点：N0→N1", "- 父子节点：父节点略→N1"),
    ("- 父子节点：N0→N1", "- 父子节点：N0→N999"),
    ("### E2（对应 S2，第1页求和）", "### E1（对应 S2，第1页求和）"),
    ("### E2（对应 S2，第1页求和）", "### E2（对应 S1，第1页求和）"),
    ("N1：Γ1=Γ0∪{a_1>0}；G1=G0。", "N0：Γ1=Γ0∪{a_1>0}；G1=G0。"),
    ("- 目标关系：由正项得到和为正", "- 未知字段：不可忽略\n- 目标关系：由正项得到和为正"),
    ("- 父子节点：N0→N1", "- 父子节点：N0→N1\n- 父子节点：N2→N1"),
    ("- 父子节点：N0→N1", "- 父子节点：N0→N1\n- 父子：N0->N1"),
])
def test_missing_or_unrecognized_structure_fails_closed(replacement):
    original, changed = replacement
    assert original in legacy_tree()
    assert parse_legacy_proof_tree(legacy_tree().replace(original, changed, 1)) is None


@pytest.mark.parametrize("parents", [[1, 0, 1, 1], [0, 3, 2, 1], [0, 0, 1, 4]])
def test_cycles_self_edges_and_disconnected_components_do_not_render(parents):
    assert parse_legacy_proof_tree(legacy_tree(count=5, parents=parents)) is None


def test_conflicting_or_incomplete_step_metadata_fails_closed():
    text = legacy_tree().replace("### E1（对应 S1，第1页求和）", "### E1（对应 S1，第1页求和）\n- 步骤/位置：S2，第1页求和")
    assert parse_legacy_proof_tree(text) is None
    assert parse_legacy_proof_tree(legacy_tree(), legacy_steps(count=30)) is None
    assert parse_legacy_proof_tree(legacy_tree(), "不是步骤工件") is None
    duplicated = legacy_steps() + "\n## S1\n- 页码/段落：第1页\n- 原稿文本：\na>0\n"
    assert parse_legacy_proof_tree(legacy_tree(), duplicated) is None


@pytest.mark.parametrize("value", [None, 12, "", "{\"nodes\": []}", "# 树\n节点未列出", "x" * (2 * 1024 * 1024 + 1), "\ud800"])
def test_invalid_or_excessive_input_returns_none(value):
    assert parse_legacy_proof_tree(value) is None


def test_multiline_step_text_preserves_formula_punctuation_and_read_only_inputs():
    markdown, steps = legacy_tree(), legacy_steps()
    saved = (markdown, steps)
    first = parse_legacy_proof_tree(markdown, steps)
    second = parse_legacy_proof_tree(markdown, steps)
    assert first == second
    assert (markdown, steps) == saved
    assert "\n" in first["edges"][0]["source_text"]
