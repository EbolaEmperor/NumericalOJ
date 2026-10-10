"""图像原稿图只保存命题与直接依赖，拒绝转录、引文和步骤位置。"""

import json
from copy import deepcopy

import pytest

from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.node_verification import validate_conclusive_node_verdict
from backend.oj_modules.faithsieve.proof_dag import (
    node_contexts, parse_image_proof_dag, propagate_node_verdicts,
    topological_node_ids, validate_image_proof_dag,
)
from tests.unit.test_faithsieve_proof_dag import dag


def image_dag():
    value = dag()
    value["schema_version"] = 3
    value["nodes"] = [{key: item for key, item in node.items() if key in {"id", "kind", "label", "statement"}}
                      for node in value["nodes"]]
    return value


def test_image_dag_joint_premises_and_propagation_do_not_need_text_source_or_step_mapping():
    value = image_dag()
    original = deepcopy(value)
    assert parse_image_proof_dag(json.dumps(value)) == original
    assert topological_node_ids(value) == ["N10", "N40", "N20", "N30", "N70", "N99", "N80"]
    contexts = node_contexts(value)
    assert [p["id"] for p in contexts["N30"]["premises"]] == ["N10", "N20"]
    assert all(set(n) == {"id", "kind", "label", "statement"}
               for context in contexts.values() for n in [context["node"], *context["premises"]])
    contexts["N30"]["node"]["statement"] = "局部副本"
    assert value == original
    states = propagate_node_verdicts(value, {"N20": "inconclusive", "N30": "passed", "N70": "passed"})
    assert states["N30"]["local_status"] == "passed" and not states["N30"]["established"]
    assert states["N30"]["blocking_premise_ids"] == ["N20"]


@pytest.mark.parametrize("field", ["source_text", "source_location", "source_type", "step_ids", "page", "excerpt"])
def test_fresh_image_dag_rejects_transcription_and_quote_fields(field):
    value = image_dag()
    value["nodes"][0][field] = "不作为中间真相"
    with pytest.raises(FaithSieveProtocolError, match="节点字段"):
        validate_image_proof_dag(value)


def test_image_entry_does_not_convert_historical_dag():
    with pytest.raises(FaithSieveProtocolError, match="必须为 3"):
        validate_image_proof_dag(dag())


def test_image_dag_still_rejects_cycles_and_unknown_direct_premises():
    value = image_dag()
    value["edges"].append({"id": "D99", "from": "N80", "to": "N20"})
    with pytest.raises(FaithSieveProtocolError, match="循环"):
        validate_image_proof_dag(value)
    value = image_dag()
    value["edges"][0]["from"] = "N999"
    with pytest.raises(FaithSieveProtocolError, match="未知"):
        validate_image_proof_dag(value)


def _summary(value, statuses):
    states = propagate_node_verdicts(value, statuses)
    return {"schema_version": 1, "proof_dag": value, "nodes": states, "target_ids": value["target_ids"],
            "target_coverage": "matched", "targets_established": all(states[n]["established"] for n in value["target_ids"])}


def test_relevant_refutation_can_finish_image_workflow_without_unnecessary_judges():
    value = image_dag()
    summary = _summary(value, {"N20": "refuted"})
    assert summary["nodes"]["N30"]["local_status"] == "not_checked"
    assert validate_conclusive_node_verdict(summary, value, "incorrect") == summary
    with pytest.raises(FaithSieveProtocolError, match="未审核"):
        validate_conclusive_node_verdict(summary, value, "correct")
    historical = dag()
    with pytest.raises(FaithSieveProtocolError, match="未审核"):
        validate_conclusive_node_verdict(_summary(historical, {"N20": "refuted"}), historical, "incorrect")


def test_unrelated_refutation_cannot_replace_evidence_on_target_dependencies():
    value = image_dag()
    with pytest.raises(FaithSieveProtocolError, match="目标依赖"):
        validate_conclusive_node_verdict(_summary(value, {"N99": "refuted"}), value, "incorrect")
