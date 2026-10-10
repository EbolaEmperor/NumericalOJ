"""构图诊断与数学真假分离，冻结旧任务不隐式升级。"""

from copy import deepcopy

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.local_diagnostics import (
    local_diagnostics_schema, validate_graph_diagnostics, validate_local_verifier_result,
    validate_verification_auditor_result,
)
from backend.oj_modules.faithsieve.transport import result_tool_options


def result(status="graph_defect"):
    return {"status": status, "artifact": "faithsieve-work/verification/N6.md",
            "report": "局部目标与原图的数学对象不同。",
            "diagnostics": ([{"kind": "statement_mismatch", "affected_node_ids": ["N6", "N7"],
                              "reason": "原图使用 ŷ；给定目标误写为 ĝ。"}]
                            if status == "graph_defect" else [])}


@pytest.mark.parametrize("status", ["graph_defect", "passed", "refuted", "inconclusive"])
def test_fresh_result_preserves_structured_diagnostics_and_mathematical_verdict(status):
    value = result(status)
    original = deepcopy(value)
    assert validate_local_verifier_result(value, diagnostic_version=1, known_node_ids={"N6", "N7"}) == value
    assert value == original


def test_old_result_remains_exact_three_field_protocol():
    value = result("passed")
    value.pop("diagnostics")
    assert validate_local_verifier_result(value) == value
    with pytest.raises(FaithSieveProtocolError, match="冻结协议"):
        validate_local_verifier_result(result("passed"))
    value["status"] = "graph_defect"
    with pytest.raises(FaithSieveProtocolError, match="状态无效"):
        validate_local_verifier_result(value)


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, 2])
def test_diagnostic_version_is_not_coerced(version):
    with pytest.raises(FaithSieveProtocolError, match="协议版本无效"):
        validate_local_verifier_result(result(), diagnostic_version=version)


@pytest.mark.parametrize("change", [
    "missing_diagnostics", "empty_defect", "defect_as_passed", "diagnostics_object", "extra_result",
    "extra_diagnostic", "unknown_kind", "empty_reason", "nontext_reason", "invalid_unicode_reason",
    "empty_nodes", "nodes_string", "invalid_node", "duplicate_node", "nontext_node", "unknown_node",
])
def test_diagnostic_cannot_hide_a_malformed_or_nonexistent_graph_reference(change):
    value = result()
    if change == "missing_diagnostics":
        value.pop("diagnostics")
    elif change == "empty_defect":
        value["diagnostics"] = []
    elif change == "defect_as_passed":
        value["status"] = "passed"
    elif change == "diagnostics_object":
        value["diagnostics"] = {}
    elif change == "extra_result":
        value["fixed_dag"] = {}
    elif change == "extra_diagnostic":
        value["diagnostics"][0]["replacement_statement"] = "new statement"
    elif change == "unknown_kind":
        value["diagnostics"][0]["kind"] = "proof_is_false"
    elif change.endswith("reason"):
        value["diagnostics"][0]["reason"] = {
            "empty_reason": " \n ", "nontext_reason": 1, "invalid_unicode_reason": "\ud800",
        }[change]
    else:
        value["diagnostics"][0]["affected_node_ids"] = {
            "empty_nodes": [], "nodes_string": "N6", "invalid_node": ["D6"],
            "duplicate_node": ["N6", "N6"], "nontext_node": [True], "unknown_node": ["N99"],
        }[change]
    with pytest.raises(FaithSieveProtocolError):
        validate_local_verifier_result(value, diagnostic_version=1, known_node_ids={"N6", "N7"})


def test_json_schema_carries_only_the_diagnostic_contract():
    endpoint = {"id": 7, "category": "omni", "protocol": "anthropic", "base_url": "https://mock.invalid",
                "api_key": "test-key", "model": "model", "thinking_enabled": False}
    schema = result_tool_options(endpoint, fields={"status", "artifact", "report", "diagnostics"},
                                 statuses={"passed", "refuted", "inconclusive", "graph_defect"},
                                 artifact="faithsieve-work/verification/N6.md", proof_graph_version=3)
    result_schema = schema["tools"][0]["function"]["parameters"]["properties"]["result"]
    assert result_schema["properties"]["diagnostics"] == local_diagnostics_schema()
    assert set(result_schema["required"]) == {"status", "artifact", "report", "diagnostics"}
    assert result_schema["properties"]["diagnostics"]["items"]["additionalProperties"] is False


@pytest.mark.parametrize("status", ["ok", "needs_revision", "graph_defect", "inconclusive"])
def test_verification_auditor_shares_diagnostics_without_becoming_a_mathematical_verdict(status):
    value = result("graph_defect" if status == "graph_defect" else "passed")
    value["status"] = status
    original = deepcopy(value)
    assert validate_verification_auditor_result(value, known_node_ids={"N6", "N7"}) == value
    assert value == original
    assert validate_graph_diagnostics(status, value["diagnostics"], known_node_ids={"N6", "N7"}) == value["diagnostics"]


@pytest.mark.parametrize("status", ["passed", "refuted", "correct", True, None])
def test_verification_auditor_does_not_accept_mathematical_verdicts_or_coerced_statuses(status):
    value = result("passed")
    value["status"] = status
    with pytest.raises(FaithSieveProtocolError, match="验证审核状态无效"):
        validate_verification_auditor_result(value)


@pytest.mark.parametrize("change", ["missing_diagnostics", "empty_defect", "extra_field", "unknown_node",
                                  "mixed_status", "empty_report", "empty_artifact", "extra_diagnostic_field"])
def test_verification_auditor_requires_full_and_consistent_diagnostic_result(change):
    value = result()
    if change == "missing_diagnostics":
        value.pop("diagnostics")
    elif change == "empty_defect":
        value["diagnostics"] = []
    elif change == "extra_field":
        value["verdict"] = "incorrect"
    elif change == "unknown_node":
        value["diagnostics"][0]["affected_node_ids"] = ["N99"]
    elif change == "mixed_status":
        value["status"] = "needs_revision"
    elif change == "empty_report":
        value["report"] = " \n "
    elif change == "empty_artifact":
        value["artifact"] = " \n "
    else:
        value["diagnostics"][0]["fixed_statement"] = "未经审核的新结论"
    with pytest.raises(FaithSieveProtocolError):
        validate_verification_auditor_result(value, known_node_ids={"N6", "N7"})
