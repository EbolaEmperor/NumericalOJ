"""状态树只接受完整 JSON；坏结构不发布、不继续。"""

import json
from types import SimpleNamespace

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError, parse_json_response
from backend.oj_modules.faithsieve.proof_tree import edge_contexts, expand_proof_tree_transport, parse_proof_tree, step_ids
from backend.oj_modules.faithsieve import workflow
from backend.oj_modules.faithsieve.prompts import render_role_prompt
from tests.unit.test_faithsieve_workflow import ScriptedRun, _function_payload, _function_response, seeded_workflow, tree_payload


def parse(tree, **kwargs):
    return parse_proof_tree(json.dumps(tree, ensure_ascii=False), **kwargs)


def test_json_tree_preserves_states_and_derives_complete_edge_contexts():
    tree = tree_payload(3)
    tree["edges"][1]["from"] = "N0"
    tree["edges"][2]["from"] = "N1"
    tree["nodes"][2]["conditions"] = ["$x \\in \\mathbb{R}$", "原稿条件"]
    assert parse(tree, expected_steps=["S1", "S2", "S3"]) == tree
    contexts = edge_contexts(tree)
    assert list(contexts) == ["E1", "E2", "E3"]
    assert contexts["E2"] == {"edge": tree["edges"][1], "parent_state": tree["nodes"][0], "child_state": tree["nodes"][2]}


@pytest.mark.parametrize("corrupt", [
    lambda t: t.update(schema_version=True),
    lambda t: t.update(root_id="missing"),
    lambda t: t.update(extra="unsupported"),
    lambda t: t["nodes"][0].update(id="N1"),
    lambda t: t["nodes"][0].update(conditions="条件"),
    lambda t: t["nodes"][0].update(goal=""),
    lambda t: t["nodes"][0].update(label="x" * 20001),
    lambda t: t["nodes"][0].update(label="\ud800"),
    lambda t: t["nodes"][0].update(scope=["作用域"] * 501),
    lambda t: t["edges"][0].update(to="missing"),
    lambda t: t["edges"][1].update(to="N1"),
    lambda t: t["edges"][0].update(id="E2"),
    lambda t: t["edges"][0].update(step_id="S2"),
    lambda t: t["edges"][0].update(source_text=""),
    lambda t: t["edges"][0]["changes"].update(added=[1]),
    lambda t: t["edges"][0]["changes"].update(extra=[]),
    lambda t: t["edges"][0].update(to="N0"),
    lambda t: t["edges"][0].update(**{"from": "N2"}),
])
def test_invalid_json_tree_fails_closed(corrupt):
    tree = tree_payload(2)
    corrupt(tree)
    with pytest.raises(FaithSieveProtocolError):
        parse(tree)


@pytest.mark.parametrize("content", ["# E1\n原有 Markdown", "```json\n{}\n```", '{"schema_version":1,"schema_version":1}', "[1]", "{"])
def test_tree_content_is_pure_json_and_rejects_duplicate_keys(content):
    with pytest.raises(FaithSieveProtocolError):
        parse_proof_tree(content)


def test_json_tree_requires_all_source_steps_and_bounded_file():
    with pytest.raises(FaithSieveProtocolError, match="全部学生步骤"):
        parse(tree_payload(), expected_steps=["S1", "S2"])
    with pytest.raises(FaithSieveProtocolError, match="过大"):
        parse_proof_tree(" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(FaithSieveProtocolError, match="编号"):
        step_ids("## S2\n正文中 S1 不是步骤标题")


def test_tree_protocol_errors_never_publish_bad_artifact_or_complete_checkpoint(tmp_path):
    run = ScriptedRun(tmp_path)
    original = run.chat
    def chat(endpoint, messages, **kwargs):
        response = original(endpoint, messages, **kwargs)
        if messages[0]["content"].startswith("# Tree builder"):
            payload = _function_payload(response)
            payload["artifacts"][workflow.TREE] = "# 旧格式不是 JSON"
            response = _function_response(payload)
        return response
    engine = seeded_workflow(tmp_path, run)
    engine.chat = chat
    assert engine.run()["verdict"] == "inconclusive"
    assert not (tmp_path / workflow.TREE).exists()
    assert "suspicion-scanner" not in run.roles and "tree-auditor" not in run.roles
    records = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    trees = [record for record in records if record["request"].get("role") == "tree-builder"]
    assert len(trees) == 2 and all(record["state"] == "protocol_error" for record in trees)


def test_model_does_not_repeat_control_context_and_code_selects_only_requested_states(tmp_path):
    run = ScriptedRun(tmp_path)
    engine = seeded_workflow(tmp_path, run)
    engine.run()
    tree = parse_proof_tree(engine.store.read(workflow.TREE))
    files = engine._edge_context("E1")
    excerpt = json.loads(files[workflow.TREE])
    assert excerpt == {"schema_version": 1, "edge_contexts": [edge_contexts(tree)["E1"]]}
    requests = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    tree_record = next(record for record in requests if record["request"].get("role") == "tree-builder")
    assert tree_record["response"]["control"]["edge_units"] == ["E1"]


@pytest.mark.parametrize(("claim", "condition"), [
    ("原稿使用比题面更强的假设 H 推出结论。", "作者使用未给定的 H"),
    ("原稿从公式 A 变为公式 B。", "作者声称公式 A 可以变为公式 B"),
    ("原稿中的式子使用未绑定符号 u。", "作者使用未绑定的 u"),
    ("原稿在局部分支外继续使用 a=0。", "作者在外层仍声称 a=0 可用"),
])
def test_student_errors_are_preserved_as_claims_and_do_not_invalidate_json_tree(tmp_path, claim, condition):
    tree = tree_payload()
    tree["nodes"][0]["conditions"] = ["题面给定的条件"]
    tree["nodes"][1]["conditions"] = ["题面给定的条件", condition]
    edge = tree["edges"][0]
    edge.update(source_text=claim, goal_relation="作者声称完成当前目标，数学成立待验证")
    edge["changes"] = {"retained": ["题面给定的条件"], "added": [condition], "consumed": [], "transformed": []}
    tree["ambiguities"] = ["原稿断言尚未验证；不更改作者使用的条件或公式。"]
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "忠实保留原稿错误及状态转换"},
               "artifacts": {workflow.TREE: json.dumps(tree, ensure_ascii=False)}, "control": {}}
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(payload))
    output = engine._invoke("tree-builder", files={"problem.md": "题面条件", workflow.STEPS: "## S1\n" + claim})
    assert output.result["status"] == "ok"
    assert parse_proof_tree(engine.store.read(workflow.TREE)) == tree
    assert output.control["edge_contexts"]["E1"]["edge"]["source_text"] == claim
    assert condition in output.control["edge_contexts"]["E1"]["child_state"]["conditions"]


def test_tree_roles_explicitly_separate_fidelity_from_mathematical_validity():
    builder = render_role_prompt("tree-builder", proof_graph_version=2)
    auditor = render_role_prompt("tree-auditor", proof_graph_version=2)
    assert "不判断命题或推理真假" in builder and "不能用题目修正作者证明" in builder
    assert "表示失真与原稿待验证" in auditor and "恢复歧义" in auditor
    assert "不能" in auditor and "未绑定符号" in auditor
    assert "不能仅因此认为图失真" in auditor
    assert "不表示任一命题成立" in auditor


@pytest.mark.parametrize("structured", [True, False])
@pytest.mark.parametrize("include_control", [True, False])
def test_tree_transport_serializes_object_or_accepts_legacy_text_and_replays(tmp_path, structured, include_control):
    tree = tree_payload()
    tree["nodes"][1]["goal"] = '$x \\in \\mathbb{R}$；原稿写“引号”，保留 \\gamma。'
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "忠实树"},
               "artifacts": {workflow.TREE: tree if structured else json.dumps(tree, ensure_ascii=False)}}
    if include_control:
        payload["control"] = {}
    files = {"problem.md": "题面", workflow.STEPS: "## S1\n原稿"}
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(payload))
    engine._invoke("tree-builder", files=files)
    assert parse_proof_tree(engine.store.read(workflow.TREE)) == tree
    record = json.loads((tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-1.json").read_text())
    assert isinstance(record["response"]["artifacts"][workflow.TREE], str)
    assert record["response"]["control"] == {"edge_units": ["E1"], "edge_contexts": edge_contexts(tree)}
    transport = engine.store.read_json("faithsieve-work/results/tree-builder.json.transport.json")
    assert transport["control"] == record["response"]["control"]
    assert isinstance(payload["artifacts"][workflow.TREE], dict if structured else str)
    def forbidden(*_args, **_kwargs):
        pytest.fail("成功 checkpoint 重放不得再次请求模型")
    replay = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path, chat=forbidden)
    output = replay._invoke("tree-builder", files=files)
    assert output.control["edge_contexts"]["E1"]["child_state"]["goal"] == tree["nodes"][1]["goal"]


def test_control_suffix_after_closed_outer_json_is_still_rejected_without_publishing(tmp_path):
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "忠实树"},
               "artifacts": {workflow.TREE: tree_payload()}}
    response = json.dumps(payload, ensure_ascii=False) + ',"control":{}}'
    with pytest.raises(FaithSieveProtocolError, match="Extra data"):
        parse_json_response(response)
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(response))
    with pytest.raises(FaithSieveProtocolError, match="Extra data"):
        engine._invoke("tree-builder", files={workflow.STEPS: "## S1\n原稿"})
    assert not (tmp_path / workflow.TREE).exists()
    records = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    assert len(records) == 2 and all(record["state"] == "protocol_error" for record in records)


def test_structured_tree_does_not_bypass_schema_steps_or_duplicate_key_checks(tmp_path):
    tree = tree_payload()
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "忠实树"},
               "artifacts": {workflow.TREE: tree}, "control": {}}
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(payload))
    with pytest.raises(FaithSieveProtocolError, match="全部学生步骤"):
        engine._invoke("tree-builder", files={workflow.STEPS: "## S1\n第一步\n## S2\n第二步"})
    assert not (tmp_path / workflow.TREE).exists()
    text = json.dumps(payload).replace('"root_id": "N0"', '"root_id": "N0", "root_id": "N1"')
    with pytest.raises(FaithSieveProtocolError, match="重复字段"):
        parse_json_response(text)


def test_protocol_diagnostic_is_private_bounded_redacted_and_preserves_tail(tmp_path):
    secret = "REAL-ENDPOINT-PRIVATE-KEY"
    response = '{"api_key":"' + secret + '","artifacts":' + "x" * 230000 + '末尾 JSON 未闭合 "'
    model_result = _function_response(response, finish_reason="max_tokens", usage=SimpleNamespace(input_tokens=10, output_tokens=32000, total_tokens=32010))
    engine = workflow.FaithSieveWorkflow(endpoint={"category": "omni", "protocol": "anthropic", "base_url": "https://mock.invalid/v1", "model": "mock-model", "api_key": secret}, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: model_result)
    with pytest.raises(FaithSieveProtocolError, match="截断"):
        engine._invoke("tree-builder", files={"problem.md": "PRIVATE-ORIGINAL-PROMPT", workflow.STEPS: "## S1\n原稿"})
    path = tmp_path / "faithsieve-work/protocol-diagnostics/role-000001-attempt-1.json"
    raw = path.read_text()
    diagnostic = json.loads(raw)
    assert secret not in raw and "PRIVATE-ORIGINAL-PROMPT" not in raw
    assert "<redacted>" in diagnostic["response_head"]
    # 诊断保存工具调用对象，arguments 的尾部只做 JSON 转义，仍可无损恢复原始文本。
    assert diagnostic["response_tail"].endswith('"}]}')
    arguments_tail = json.loads('"' + diagnostic["response_tail"][:-3])
    assert arguments_tail.endswith('末尾 JSON 未闭合 "')
    assert diagnostic["truncated"] and len(diagnostic["response_head"]) <= 65536 and len(diagnostic["response_tail"]) <= 131072
    assert diagnostic["finish_reason"] == "max_tokens" and diagnostic["output_tokens"] == 32000
    assert path.stat().st_mode & 0o077 == 0
    assert not {"request", "prompt", "endpoint"} & set(diagnostic)
    from backend.oj_modules.faithsieve.views import _artifact_allowed
    assert not _artifact_allowed("faithsieve-work/protocol-diagnostics/role-000001-attempt-1.json")


def test_tree_transport_prompt_requires_single_json_object_layer():
    prompt = render_role_prompt("tree-builder", proof_graph_version=2)
    assert "只返回 result 与 artifacts" in prompt
    assert "不返回 control" in prompt
    assert '"control": 流程数据对象' in render_role_prompt("decomposer")
    assert "control 返回 {}" in render_role_prompt("decomposer")
    assert 'artifacts["faithsieve-work/tree.json"] 直接返回 JSON 对象，不再包字符串' in prompt
    assert '"artifacts": {"原输出路径": "完整文件内容"}' not in prompt
    assert "schema_version 必须为 2" in prompt
    assert "局部假设及条件必须封装其中" in prompt
    assert "不要返回 inherit_from 引用" in prompt
    assert "多个直接前驱" in prompt and "直接证明依赖" in prompt
    assert "ambiguities 为字符串数组" in prompt
    assert '"step_ids":["S1"]' in prompt
    assert "共享前提使用同一个节点" in prompt
    assert "允许多个根、多个前驱" in prompt


def reference_tree():
    tree = tree_payload(3)
    tree["nodes"][0].update(conditions=["条件 A", "条件 B", "条件 C"], goal="完整目标 P(A,B,C)")
    tree["nodes"][1].update(conditions={"inherit_from": "N0", "remove": [1], "add": ["原稿新增 D"]},
                            goal={"inherit_from": "N0"})
    tree["nodes"][2].update(conditions={"inherit_from": "N1", "remove": [0, 2], "add": ["原稿新增 E"]},
                            goal="新的完整目标 Q(C,E)")
    tree["edges"][2]["from"] = "N0"
    tree["nodes"][3].update(conditions={"inherit_from": "N0", "remove": [], "add": []},
                            goal={"inherit_from": "N0"})
    return tree


def test_typed_transport_expands_real_parent_states_without_mutating_wire_or_changing_order():
    wire = reference_tree()
    before = json.dumps(wire, ensure_ascii=False)
    wire["nodes"] = list(reversed(wire["nodes"]))
    expanded = expand_proof_tree_transport(wire, expected_steps=["S1", "S2", "S3"])
    assert [node["id"] for node in expanded["nodes"]] == ["N3", "N2", "N1", "N0"]
    by_id = {node["id"]: node for node in expanded["nodes"]}
    assert by_id["N1"]["conditions"] == ["条件 A", "条件 C", "原稿新增 D"]
    assert by_id["N2"]["conditions"] == ["条件 C", "原稿新增 E"]
    assert by_id["N3"]["conditions"] == ["条件 A", "条件 B", "条件 C"]
    assert by_id["N1"]["goal"] == by_id["N3"]["goal"] == "完整目标 P(A,B,C)"
    assert by_id["N2"]["goal"] == "新的完整目标 Q(C,E)"
    assert expanded["edges"] == wire["edges"]
    assert parse(expanded) == expanded
    assert edge_contexts(expanded)["E2"]["parent_state"]["conditions"] == by_id["N1"]["conditions"]
    assert json.dumps({**wire, "nodes": list(reversed(wire["nodes"]))}, ensure_ascii=False) == before


@pytest.mark.parametrize("corrupt", [
    lambda t: t["nodes"][0].update(conditions={"inherit_from": "N1", "remove": [], "add": []}),
    lambda t: t["nodes"][0].update(goal={"inherit_from": "N1"}),
    lambda t: t["nodes"][2]["conditions"].update(inherit_from="N0"),
    lambda t: t["nodes"][2].update(goal={"inherit_from": "N3"}),
    lambda t: t["nodes"][1]["conditions"].update(inherit_from="missing"),
    lambda t: t["nodes"][1]["conditions"].update(remove=[-1]),
    lambda t: t["nodes"][1]["conditions"].update(remove=[3]),
    lambda t: t["nodes"][1]["conditions"].update(remove=[1, 1]),
    lambda t: t["nodes"][1]["conditions"].update(remove=[True]),
    lambda t: t["nodes"][1]["conditions"].update(remove=[1.0]),
    lambda t: t["nodes"][1]["conditions"].update(remove=["条件"]),
    lambda t: t["nodes"][1]["conditions"].update(remove=["1"]),
    lambda t: t["nodes"][1]["conditions"].update(remove="1"),
    lambda t: t["nodes"][1]["conditions"].update(remove=[{}]),
    lambda t: t["nodes"][1]["conditions"].update(remove=[""]),
    lambda t: t["nodes"][1]["conditions"].update(remove=["\ud800"]),
    lambda t: t["nodes"][1]["conditions"].update(remove=["A" * 20001]),
    lambda t: t["nodes"][1]["conditions"].update(add=[""]),
    lambda t: t["nodes"][1]["conditions"].update(extra=[]),
    lambda t: t["nodes"][1]["conditions"].pop("remove"),
    lambda t: t["nodes"][1]["goal"].update(extra="unsupported"),
    lambda t: t["nodes"][1].update(scope={"inherit_from": "N0"}),
    lambda t: t["edges"][1]["changes"].update(retained={"inherit_from": "N0"}),
    lambda t: t["edges"][0].update(**{"from": "N2"}),
    lambda t: t["edges"][2].update(to="N1"),
])
def test_typed_transport_rejects_invalid_references_indices_fields_and_topology(corrupt):
    tree = reference_tree()
    corrupt(tree)
    with pytest.raises(FaithSieveProtocolError):
        expand_proof_tree_transport(tree)


def test_typed_transport_still_requires_all_steps_and_limits_expanded_arrays_and_bytes():
    with pytest.raises(FaithSieveProtocolError, match="全部学生步骤"):
        expand_proof_tree_transport(reference_tree(), expected_steps=["S1"])
    tree = reference_tree()
    tree["nodes"][0]["conditions"] = ["原稿条件"] * 500
    tree["nodes"][1]["conditions"].update(remove=[], add=["新条件"])
    with pytest.raises(FaithSieveProtocolError, match="条件数量"):
        expand_proof_tree_transport(tree)


@pytest.mark.parametrize("selectors,expected", [
    (["条件 B"], ["条件 A", "条件 C", "新增 D"]),
    ([2, "条件 A"], ["条件 B", "新增 D"]),
    (["条件 C", 1], ["条件 A", "新增 D"]),
])
def test_remove_exact_text_and_mixed_indices_are_resolved_against_complete_parent(selectors, expected):
    tree = tree_payload()
    tree["nodes"][0]["conditions"] = ["条件 A", "条件 B", "条件 C"]
    tree["nodes"][1]["conditions"] = {"inherit_from": "N0", "remove": selectors, "add": ["新增 D"]}
    before = json.dumps(tree, ensure_ascii=False)
    expanded = expand_proof_tree_transport(tree)
    assert expanded["nodes"][1]["conditions"] == expected
    assert json.dumps(tree, ensure_ascii=False) == before


@pytest.mark.parametrize("parent_conditions,selectors", [
    (["条件 A", "条件 B"], [0, "条件 A"]),
    (["条件 A", "条件 B"], ["条件 B", 1]),
    (["条件 A", "条件 B"], ["条件 A", "条件 A"]),
    (["条件 A", "条件 A"], ["条件 A"]),
    (["条件 A", "条件 B"], ["条件"]),
    (["条件 A", "条件 B"], ["条件 A "]),
    (["条件 A", "条件 B"], ["条件 a"]),
    (["条件 A", "条件 B"], ["1"]),
])
def test_remove_text_rejects_duplicates_missing_ambiguous_or_nonexact_matches(parent_conditions, selectors):
    tree = tree_payload()
    tree["nodes"][0]["conditions"] = parent_conditions
    tree["nodes"][1]["conditions"] = {"inherit_from": "N0", "remove": selectors, "add": []}
    with pytest.raises(FaithSieveProtocolError):
        expand_proof_tree_transport(tree)


def test_numeric_string_is_only_condition_text_and_duplicate_text_can_be_deleted_by_index():
    tree = tree_payload()
    tree["nodes"][0]["conditions"] = ["1", "条件 A"]
    tree["nodes"][1]["conditions"] = {"inherit_from": "N0", "remove": ["1"], "add": []}
    assert expand_proof_tree_transport(tree)["nodes"][1]["conditions"] == ["条件 A"]
    tree["nodes"][0]["conditions"] = ["条件 A", "条件 A"]
    tree["nodes"][1]["conditions"]["remove"] = [0]
    assert expand_proof_tree_transport(tree)["nodes"][1]["conditions"] == ["条件 A"]


def test_goal_can_restore_real_ancestor_without_inheriting_ancestor_conditions_or_scope():
    tree = reference_tree()
    tree["nodes"][0]["scope"] = ["根作用域"]
    tree["nodes"][1].update(goal="局部目标 Q(A,C,D)", scope=["局部作用域"])
    tree["nodes"][2].update(goal={"inherit_from": "N0"}, scope=["当前作用域"])
    expanded = expand_proof_tree_transport(tree)
    node = expanded["nodes"][2]
    assert node["goal"] == tree["nodes"][0]["goal"]
    assert node["conditions"] == ["条件 C", "原稿新增 E"]
    assert node["scope"] == ["当前作用域"]
    # 祖先本身也使用引用时，复制它已展开的完整 goal。
    tree["nodes"][1]["goal"] = {"inherit_from": "N0"}
    tree["nodes"][2]["goal"] = {"inherit_from": "N1"}
    assert expand_proof_tree_transport(tree)["nodes"][2]["goal"] == tree["nodes"][0]["goal"]


@pytest.mark.parametrize("node_id,reference", [("N1", "N1"), ("N1", "N2"), ("N1", "N3"), ("N2", "N3"), ("N2", "unknown")])
def test_goal_rejects_self_descendant_sibling_other_branch_and_unknown(node_id, reference):
    tree = reference_tree()
    next(node for node in tree["nodes"] if node["id"] == node_id)["goal"] = {"inherit_from": reference}
    with pytest.raises(FaithSieveProtocolError, match="真实祖先"):
        expand_proof_tree_transport(tree)
    tree = reference_tree()
    tree["nodes"][0]["conditions"] = ["文" * 20000] * 30
    tree["nodes"][1]["conditions"].update(remove=[], add=[])
    with pytest.raises(FaithSieveProtocolError, match="展开后的工件过大"):
        expand_proof_tree_transport(tree)


def test_wire_references_are_only_accepted_as_objects_and_checkpoint_and_judge_context_are_complete(tmp_path):
    tree = reference_tree()
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "忠实树"},
               "artifacts": {workflow.TREE: tree}, "control": {}}
    files = {workflow.STEPS: "## S1\n第一步\n## S2\n第二步\n## S3\n第三步"}
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(payload))
    output = engine._invoke("tree-builder", files=files)
    persisted = parse_proof_tree(engine.store.read(workflow.TREE))
    assert persisted == expand_proof_tree_transport(tree)
    assert output.control["edge_contexts"]["E2"]["child_state"]["conditions"] == ["条件 C", "原稿新增 E"]
    checkpoint = json.loads((tmp_path / "faithsieve-work/checkpoints/role-000001-attempt-1.json").read_text())
    assert parse_proof_tree(checkpoint["response"]["artifacts"][workflow.TREE]) == persisted
    replay = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                         chat=lambda *_args, **_kwargs: pytest.fail("已展开的 checkpoint 不得调用模型"))
    assert replay._invoke("tree-builder", files=files).control == output.control
    with pytest.raises(FaithSieveProtocolError):
        parse(tree)


def test_natural_language_inheritance_is_preserved_verbatim_and_never_guessed():
    tree = tree_payload()
    tree["nodes"][1].update(conditions=["继承 N0 全部条件", "原稿新增事实"], goal="同 N0")
    assert expand_proof_tree_transport(tree) == tree


@pytest.mark.parametrize("field,corrupt", [
    ("ambiguities", lambda t: t.update(ambiguities=[{"id": "A1", "location": "第 1 页", "description": "原稿歧义", "resolution": "未解决"}])),
    ("node.scope", lambda t: t["nodes"][1].update(scope=[{"description": "局部范围"}])),
    ("edge.scope", lambda t: t["edges"][0].update(scope=[None])),
    ("changes.added", lambda t: t["edges"][0]["changes"].update(added=[{"condition": "条件 A"}])),
    ("conditions.add", lambda t: t["nodes"][1]["conditions"].update(add=[{"condition": "条件 A"}])),
])
def test_wrong_array_member_types_report_the_required_nonempty_string(field, corrupt):
    tree = reference_tree()
    corrupt(tree)
    with pytest.raises(FaithSieveProtocolError, match=rf"{field} 必须非空字符串"):
        expand_proof_tree_transport(tree)


@pytest.mark.parametrize("invalid", ["cross_parent", "escaped_size", "text_wire"])
def test_invalid_or_oversized_wire_never_publishes_a_tree_or_completed_checkpoint(tmp_path, invalid):
    tree = tree_payload()
    tree["nodes"][0]["conditions"] = ["条件 A"]
    tree["nodes"][1].update(conditions={"inherit_from": "N0", "remove": [], "add": []},
                            goal={"inherit_from": "N0"})
    if invalid == "cross_parent":
        tree["nodes"][1]["goal"]["inherit_from"] = "N1"
    elif invalid == "escaped_size":
        # 原始字节预算低于 2MiB，但 JSON 控制字符转义后的完整工件超过限制。
        tree["nodes"][0]["conditions"] = ["\x00" * 10000 + "A"] * 30
    artifact = json.dumps(tree, ensure_ascii=False) if invalid == "text_wire" else tree
    payload = {"result": {"status": "ok", "artifact": workflow.TREE, "report": "待校验树"},
               "artifacts": {workflow.TREE: artifact}, "control": {}}
    engine = workflow.FaithSieveWorkflow(endpoint=None, verification_agent=None, workspace=tmp_path,
                                        chat=lambda *_args, **_kwargs: _function_response(payload))
    with pytest.raises(FaithSieveProtocolError):
        engine._invoke("tree-builder", files={workflow.STEPS: "## S1\n原稿"})
    assert not (tmp_path / workflow.TREE).exists()
    checkpoints = [json.loads(path.read_text()) for path in (tmp_path / "faithsieve-work/checkpoints").glob("*.json")]
    assert len(checkpoints) == 2 and all(record["state"] == "protocol_error" for record in checkpoints)
