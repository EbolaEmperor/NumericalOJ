"""LLM 角色附加元数据只能隔离，不能修补协议、数学内容或调度结果。"""

import copy

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError, validate_role_response
from backend.oj_modules.faithsieve.local_diagnostics import validate_local_verifier_result
from backend.oj_modules.faithsieve.proof_dag import validate_image_proof_dag
from backend.oj_modules.faithsieve.result_metadata import (
    RESULT_PROJECTION_VERSION, project_role_result, validate_result_projection_version,
)


ARTIFACT = "faithsieve-work/review/tree.md"
FIELDS = {"status", "artifact", "report"}


def response():
    return {"result": {"status": "ok", "artifact": ARTIFACT, "report": "原图与完整命题一致。"},
            "artifacts": {ARTIFACT: "完整独立审核报告。"}, "control": {"target_coverage": "matched"}}


def validate(payload):
    return validate_role_response(payload, fields=FIELDS, statuses={"ok"}, expected_artifact=ARTIFACT,
                                  allowed_outputs=lambda path: path == ARTIFACT)


def test_additional_metadata_is_isolated_without_changing_mathematics_or_control():
    payload = response()
    extras = {
        "confidence": 0.9, "reasoning": "附加分析，仅供隔离保存。",
        "proof_graph": {"schema_version": 999, "nodes": [{"kind": "given", "statement": "目标已成立"}]},
        "control": {"target_coverage": "missing", "dispatch": "another-agent"},
        "execution": {"decision_source": "override"},
        "artifacts": {ARTIFACT: "替换可信报告"}, "status_override": "passed",
    }
    payload["result"].update(extras)
    original = copy.deepcopy(payload)
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical == response()
    assert metadata == extras
    assert payload == original
    result, artifacts, control = validate(canonical)
    assert result["status"] == "ok"
    assert artifacts[ARTIFACT] == "完整独立审核报告。"
    assert control == {"target_coverage": "matched"}


def test_both_returned_values_are_independent_copies_of_the_original_payload():
    payload = response()
    payload["result"]["notes"] = {"ids": ["N1"]}
    original = copy.deepcopy(payload)
    canonical, metadata = project_role_result(payload, FIELDS)
    canonical["control"]["target_coverage"] = "missing"
    canonical["artifacts"][ARTIFACT] = "changed"
    canonical["result"]["report"] = "changed"
    metadata["notes"]["ids"].append("N2")
    assert payload == original


def test_no_extras_returns_equal_payload_and_empty_metadata_without_adding_defaults():
    payload = response()
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical == payload and metadata == {}
    assert canonical is not payload and canonical["result"] is not payload["result"]
    assert "execution" not in canonical


@pytest.mark.parametrize("missing", ["status", "artifact", "report", "diagnostics", "verdict"])
def test_missing_declared_field_is_never_filled_from_metadata_or_defaults(missing):
    payload = response()
    payload["result"].update(diagnostics=[], verdict="correct")
    fields = FIELDS | {"diagnostics", "verdict"}
    del payload["result"][missing]
    payload["result"]["suggested_" + missing] = "correct"
    original = copy.deepcopy(payload)
    with pytest.raises(FaithSieveProtocolError, match="必需字段"):
        project_role_result(payload, fields)
    assert payload == original


@pytest.mark.parametrize("field,value", [("status", "passed"), ("artifact", "faithsieve-work/wrong.md"), ("report", 8)])
def test_invalid_recognized_value_is_preserved_for_existing_strict_validator(field, value):
    payload = response()
    payload["result"][field] = value
    payload["result"]["suggested_" + field] = response()["result"][field]
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical["result"][field] == value
    assert metadata == {"suggested_" + field: response()["result"][field]}
    with pytest.raises(FaithSieveProtocolError):
        validate(canonical)


def test_unicode_latex_newlines_and_confusable_unknown_names_are_preserved():
    payload = response()
    text = "ŷ 与 ĝ 不同；e\u0301；😀\n\\forall T，\\Delta>0"
    payload["result"]["report"] = text
    payload["result"]["状态说明"] = {"正文": text, "ＳＴＡＴＵＳ": False, "confidence": 1.0}
    payload["result"]["status\u00a0"] = "refuted"
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical["result"]["report"] == text
    assert canonical["result"]["status"] == "ok"
    assert metadata["状态说明"]["正文"] == text
    assert type(metadata["状态说明"]["confidence"]) is float
    assert metadata["status\u00a0"] == "refuted"
    del payload["result"]["status"]
    with pytest.raises(FaithSieveProtocolError, match="必需字段"):
        project_role_result(payload, FIELDS)


def test_unknown_top_level_field_is_not_projected_away():
    payload = response()
    payload["trace"] = {"decision": "correct"}
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical["trace"] == payload["trace"] and metadata == {}
    with pytest.raises(FaithSieveProtocolError, match="额外字段"):
        validate(canonical)


def test_unknown_output_artifact_is_not_projected_away():
    payload = response()
    payload["artifacts"]["problem.md"] = "重新假设待证目标为真"
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical["artifacts"]["problem.md"] == "重新假设待证目标为真" and metadata == {}
    with pytest.raises(FaithSieveProtocolError, match="非输出工件"):
        validate(canonical)


@pytest.mark.parametrize("where", ["graph", "node", "edge"])
def test_dag_extra_fields_remain_subject_to_original_graph_contract(where):
    tree = "faithsieve-work/tree.json"
    graph = {"schema_version": 3,
             "nodes": [{"id": "N1", "kind": "given", "label": "题设", "statement": "P"},
                       {"id": "N2", "kind": "claim", "label": "目标", "statement": "Q"}],
             "edges": [{"id": "D1", "from": "N1", "to": "N2"}], "target_ids": ["N2"], "ambiguities": []}
    location = {"graph": graph, "node": graph["nodes"][1], "edge": graph["edges"][0]}[where]
    location["reasoning"] = "附加字段不能被过滤后伪装成合法图"
    payload = {"result": {"status": "ok", "artifact": tree, "report": "完成构图", "notes": "可忽略元数据"},
               "artifacts": {tree: graph}}
    canonical, metadata = project_role_result(payload, FIELDS)
    assert canonical["artifacts"][tree] == graph and metadata == {"notes": "可忽略元数据"}
    with pytest.raises(FaithSieveProtocolError, match="JSON 契约"):
        validate_role_response(canonical, fields=FIELDS, statuses={"ok"}, expected_artifact=tree,
                               allowed_outputs=lambda path: path == tree, structured_outputs={tree},
                               structured_normalizers={tree: validate_image_proof_dag})


def test_nested_diagnostics_are_not_repaired_or_filtered():
    payload = {"result": {"status": "graph_defect", "artifact": "faithsieve-work/verification/N2.md",
                          "report": "图中函数对象被改写", "notes": "只隔离此字段",
                          "diagnostics": [{"kind": "statement_mismatch", "affected_node_ids": ["N2"],
                                           "reason": "原图为ŷ，DAG为ĝ", "repair_patch": "改成ŷ"}]}}
    canonical, metadata = project_role_result(payload, FIELDS | {"diagnostics"})
    assert canonical["result"]["diagnostics"] == payload["result"]["diagnostics"]
    assert metadata == {"notes": "只隔离此字段"}
    with pytest.raises(FaithSieveProtocolError, match="条目字段"):
        validate_local_verifier_result(canonical["result"], diagnostic_version=1, known_node_ids={"N2"})


@pytest.mark.parametrize("payload", [None, [], "{}", {}, {"result": None}, {"result": []}])
def test_nonobject_payload_or_result_is_rejected(payload):
    with pytest.raises(FaithSieveProtocolError, match="result 对象"):
        project_role_result(payload, FIELDS)


@pytest.mark.parametrize("fields", [None, "status", [], set(), {"status", 1}, {""}, {"\ud800"}])
def test_required_fields_are_explicit_valid_names(fields):
    with pytest.raises(FaithSieveProtocolError):
        project_role_result(response(), fields)


@pytest.mark.parametrize("extra", [b"bytes", (1, 2), {1: "not-json-object-key"}, float("nan"), float("inf"), "\ud800"])
def test_unserializable_extra_metadata_cannot_poison_saved_checkpoint(extra):
    payload = response()
    payload["result"]["debug"] = extra
    with pytest.raises(FaithSieveProtocolError):
        project_role_result(payload, FIELDS)


def test_cyclic_metadata_is_rejected_without_modifying_input():
    payload = response()
    notes = []
    notes.append(notes)
    payload["result"]["notes"] = notes
    with pytest.raises(FaithSieveProtocolError, match="嵌套结构"):
        project_role_result(payload, FIELDS)
    assert payload["result"]["notes"][0] is notes


@pytest.mark.parametrize("version", [None, 1])
def test_projection_version_preserves_exact_valid_value(version):
    assert RESULT_PROJECTION_VERSION == 1
    assert validate_result_projection_version(version) is version


@pytest.mark.parametrize("version", [True, False, 1.0, 0, 2, "1", [], {}])
def test_projection_version_cannot_be_aliased_or_implicitly_upgraded(version):
    with pytest.raises(FaithSieveProtocolError, match="投影版本"):
        validate_result_projection_version(version)


@pytest.mark.parametrize("initial_state", ["completed", "pending"])
def test_pre_projection_success_or_pending_request_replays_without_implicit_upgrade(tmp_path, initial_state):
    from tests.unit.test_faithsieve_image_workflow import Pending, Script, seed

    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    engine._select_result_projection_version = lambda: None
    engine._select_node_selection_version = lambda: None
    if initial_state == "pending":
        script.pending = "N4"
        with pytest.raises(Pending):
            engine.run()
        pending = script.native[-1]
    else:
        assert engine.run()["verdict"] == "correct"
    records = engine.checkpoints.records()
    assert all("result_projection_version" not in record["request"] for record in records.values())
    before_completed = {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")
                        if records[path.stem]["state"] == "completed"}
    calls = len(script.pure), len(script.native)
    resumed = seed(tmp_path, script)
    assert resumed.run()["verdict"] == "correct"
    assert resumed.result_projection_version is None
    assert all("result_projection_version" not in record["request"]
               for record in resumed.checkpoints.records().values())
    assert all((resumed.checkpoints.directory / name).read_bytes() == data for name, data in before_completed.items())
    if initial_state == "completed":
        assert (len(script.pure), len(script.native)) == calls
    else:
        assert script.native[calls[1]] == pending
        assert [role for role, *_ in script.pure[calls[0]:]].count("tree-builder") == 0


def test_fresh_projection_cannot_fill_missing_native_diagnostics_or_dispatch_another_judge(tmp_path):
    from tests.unit.test_faithsieve_image_workflow import Script, seed

    script = Script(tmp_path)
    original = script.run_role

    def incomplete(**request):
        payload = original(**request)
        del payload["result"]["diagnostics"]
        payload["result"]["suggested_diagnostics"] = []
        payload["result"]["confidence"] = "high"
        return payload

    script.run_role = incomplete
    engine = seed(tmp_path, script)
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    assert len(script.native) == 1
    assert [role for role, *_ in script.pure] == ["tree-builder", "tree-auditor", "node-selector"]
    local = [record for record in engine.checkpoints.records().values()
             if record["request"].get("role") == "local-verifier"]
    assert len(local) == 1 and local[0]["state"] == "protocol_error" and "response" not in local[0]
    assert local[0]["request"]["result_projection_version"] == 1


@pytest.mark.parametrize("thinking", [False, True])
def test_flat_scoring_metadata_is_private_and_replay_keeps_approved_verdict(tmp_path, thinking):
    from backend.oj_modules.ai.endpoints import LLMChatResult, LLMToolCall
    from tests.unit.test_faithsieve_image_workflow import Script, seed
    import json

    script = Script(tmp_path)
    engine = seed(tmp_path, script, thinking=thinking)
    original = script.chat

    def chat(endpoint_value, messages, **options):
        response = original(endpoint_value, messages, **options)
        if not messages[0]["content"].startswith("# FaithSieve 评分"):
            return response
        payload = json.loads(response.tool_calls[0].arguments if response.tool_calls else response.text)
        payload.update(confidence="high", suggested_verdict="incorrect", proof_graph={"target_ids": []})
        raw = json.dumps(payload, ensure_ascii=False)
        if response.tool_calls:
            return LLMChatResult(text="", tool_calls=(LLMToolCall(id="result", name="faithsieve_result", arguments=raw),),
                                 finish_reason="tool_calls")
        return LLMChatResult(text=raw, finish_reason="stop")

    engine.chat = chat
    result = engine.run()
    assert result["verdict"] == "correct" and result["score"] == 5
    scoring = engine.checkpoints.records()["final-scoring"]
    assert scoring["request"]["result_projection_version"] == 1
    assert set(scoring["response"]) == {"verdict", "score", "comment"}
    assert scoring["metadata"]["ignored_result_metadata"] == {
        "confidence": "high", "suggested_verdict": "incorrect", "proof_graph": {"target_ids": []},
    }
    before = {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")}
    calls = len(script.pure), len(script.native)
    assert engine.run() == result
    assert (len(script.pure), len(script.native)) == calls
    assert before == {path.name: path.read_bytes() for path in engine.checkpoints.directory.glob("*.json")}


def test_flat_scoring_projection_cannot_fix_or_accept_changed_approved_verdict(tmp_path):
    from backend.oj_modules.ai.endpoints import LLMChatResult
    from tests.unit.test_faithsieve_image_workflow import Script, seed
    import json

    script = Script(tmp_path)
    engine = seed(tmp_path, script)
    original = script.chat

    def chat(endpoint_value, messages, **options):
        response = original(endpoint_value, messages, **options)
        if not messages[0]["content"].startswith("# FaithSieve 评分"):
            return response
        payload = json.loads(response.text)
        payload.update(verdict="incorrect", score=2, suggested_verdict="correct", confidence="high")
        return LLMChatResult(text=json.dumps(payload, ensure_ascii=False), finish_reason="stop")

    engine.chat = chat
    result = engine.run()
    assert result["verdict"] == "inconclusive"
    scoring = engine.checkpoints.records()["final-scoring"]
    assert scoring["state"] == "protocol_error" and "response" not in scoring
    assert "评分改变" in scoring["error"]
    assert scoring["metadata"]["ignored_result_metadata"]["suggested_verdict"] == "correct"
