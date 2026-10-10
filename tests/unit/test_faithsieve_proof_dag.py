"""命题依赖可共享，局部蕴含成立不能自动认证未建立前提下的结论。"""

from copy import deepcopy
import json

import pytest

from backend.oj_modules.faithsieve.artifacts import MAX_ARTIFACT_BYTES, FaithSieveProtocolError
from backend.oj_modules.faithsieve.proof_dag import (
    node_contexts, parse_proof_dag, propagate_node_verdicts, topological_node_ids, validate_proof_dag,
)


def node(identifier, statement, *, given=False, steps=None):
    return {"id": identifier, "kind": "given" if given else "claim", "label": statement,
            "statement": statement, "source_type": "problem" if given else "submission",
            "step_ids": [] if given else list(steps or ["S1"]),
            "source_location": "题面第 1 段" if given else "第 1 页第 1 段",
            "source_text": statement}


def dag():
    # 保留原稿顺序，既有多父节点、共享前驱，也有独立待证声明。
    return {"schema_version": 2,
            "nodes": [node("N30", "C ∧ A → P", steps=["S3"]),
                      node("N10", "A", given=True), node("N40", "B", given=True),
                      node("N20", "C", steps=["S1"]), node("N70", "D", steps=["S2"]),
                      node("N99", "未给出理由的独立断言 Q", steps=["S4"]),
                      node("N80", "最终命题 R", steps=["S5"])],
            "edges": [{"id": "D7", "from": "N10", "to": "N20"},
                      {"id": "D2", "from": "N40", "to": "N20"},
                      {"id": "D42", "from": "N20", "to": "N70"},
                      {"id": "D3", "from": "N20", "to": "N30"},
                      {"id": "D6", "from": "N10", "to": "N30"},
                      {"id": "D18", "from": "N70", "to": "N80"}],
            "target_ids": ["N80", "N30"], "ambiguities": []}


def single_claim():
    return {"schema_version": 2, "nodes": [node("N1", "True")], "edges": [],
            "target_ids": ["N1"], "ambiguities": []}


def test_shared_dependencies_multiple_roots_and_independent_claims_are_valid_without_mutation():
    value, expected = dag(), dag()
    assert validate_proof_dag(value, expected_steps=[f"S{i}" for i in range(1, 6)]) is value
    assert parse_proof_dag(json.dumps(value, ensure_ascii=False), expected_steps=[f"S{i}" for i in range(1, 6)]) == value
    assert value == expected
    assert topological_node_ids(value) == ["N10", "N40", "N20", "N30", "N70", "N99", "N80"]


def test_node_context_contains_all_direct_premises_once_and_no_ancestor_or_unrelated_claim():
    value = dag()
    contexts = node_contexts(value)
    assert list(contexts) == ["N30", "N20", "N70", "N99", "N80"]
    assert [premise["id"] for premise in contexts["N20"]["premises"]] == ["N10", "N40"]
    assert [premise["id"] for premise in contexts["N30"]["premises"]] == ["N10", "N20"]
    assert [premise["id"] for premise in contexts["N70"]["premises"]] == ["N20"]
    assert contexts["N99"]["premises"] == []
    assert set(contexts["N20"]) == {"node", "premises"}
    assert contexts["N20"]["premises"][0] == value["nodes"][1]
    contexts["N70"]["premises"][0]["step_ids"].append("S20")
    assert value["nodes"][3]["step_ids"] == ["S1"]


def test_local_proof_needs_every_direct_premise_established_and_shared_claim_propagates_once():
    value = dag()
    results = propagate_node_verdicts(value, {"N20": "passed", "N30": "passed", "N70": "passed", "N80": "passed"})
    assert list(results) == [item["id"] for item in value["nodes"]]
    assert all(results[identifier]["established"] for identifier in ("N10", "N40", "N20", "N30", "N70", "N80"))
    assert results["N20"] == {"local_status": "passed", "established": True, "status": "established",
                              "premise_ids": ["N10", "N40"], "blocking_premise_ids": []}
    assert results["N99"] == {"local_status": "not_checked", "established": False, "status": "not_checked",
                              "premise_ids": [], "blocking_premise_ids": []}


@pytest.mark.parametrize("upstream", ["inconclusive", "refuted", "not_checked"])
def test_valid_local_implications_do_not_certify_descendants_of_an_unestablished_claim(upstream):
    results = propagate_node_verdicts(dag(), {"N20": upstream, "N30": "passed", "N70": "passed", "N80": "passed"})
    assert not results["N20"]["established"]
    assert results["N20"]["local_status"] == upstream
    assert results["N20"]["status"] == ("not_checked" if upstream == "not_checked" else "not_established")
    for identifier, blockers in (("N30", ["N20"]), ("N70", ["N20"]), ("N80", ["N70"])):
        assert results[identifier]["local_status"] == "passed"
        assert results[identifier]["status"] == "blocked"
        assert results[identifier]["blocking_premise_ids"] == blockers
        assert results[identifier]["established"] is False
    # 局部反驳只能保留在 local_status，不能被提升或传播为命题为假。
    assert all(item["status"] != "refuted" for item in results.values())


def test_unproved_root_claim_is_never_a_given_but_can_be_proved_without_premises():
    value = single_claim()
    assert validate_proof_dag(value) is value
    assert propagate_node_verdicts(value, {})["N1"]["established"] is False
    assert propagate_node_verdicts(value, {"N1": "passed"})["N1"]["established"] is True


def test_statement_with_local_assumption_and_quantifier_is_preserved_as_one_claim():
    value = single_claim()
    statement = r"∀ x ∈ D，A(x) → ∃ y，P(x,y)；见证 y 可以依赖 x。"
    value["nodes"][0]["statement"] = statement
    assert node_contexts(parse_proof_dag(json.dumps(value, ensure_ascii=False)))["N1"]["node"]["statement"] == statement


def test_steps_are_many_to_many_but_each_node_uses_numeric_order_and_exact_complete_coverage():
    value = dag()
    value["nodes"][0]["step_ids"] = ["S1", "S3", "S10"]
    value["nodes"][3]["step_ids"] = ["S1", "S2"]
    assert validate_proof_dag(value, expected_steps=["S1", "S2", "S3", "S4", "S5", "S10"]) is value
    for expected in (["S1", "S2", "S3", "S4", "S5"], ["S1", "S2", "S3", "S4", "S5", "S6", "S10"]):
        with pytest.raises(FaithSieveProtocolError, match="覆盖"):
            validate_proof_dag(value, expected_steps=expected)


@pytest.mark.parametrize("steps", [["S2", "S1"], ["S1", "S1"], ["S10", "S2"], ["S0"], ["S01"], [1], (), []])
def test_claim_steps_must_be_nonempty_unique_numeric_order(steps):
    value = single_claim()
    value["nodes"][0]["step_ids"] = steps
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)


@pytest.mark.parametrize("field,value", [("kind", "assumption"), ("kind", []), ("source_type", "problem"),
                                         ("source_type", {}), ("label", " "), ("statement", None),
                                         ("source_location", ""), ("source_text", ""), ("id", "N0"),
                                         ("id", "N01"), ("id", "E1"), ("id", "N" + "1" * 64)])
def test_invalid_claim_shape_and_sources_fail_closed(field, value):
    graph = single_claim()
    graph["nodes"][0][field] = value
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(graph)


@pytest.mark.parametrize("mutation", ["source", "steps", "incoming"])
def test_given_cannot_be_authors_claim_or_have_proof_inputs(mutation):
    value = dag()
    if mutation == "source":
        value["nodes"][1]["source_type"] = "submission"
    elif mutation == "steps":
        value["nodes"][1]["step_ids"] = ["S1"]
    else:
        value["edges"].append({"id": "D99", "from": "N20", "to": "N10"})
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)


@pytest.mark.parametrize("mutation", ["duplicate_node", "duplicate_edge", "duplicate_pair", "unknown_node", "self_loop", "cycle"])
def test_invalid_dependency_graphs_are_rejected(mutation):
    value = dag()
    if mutation == "duplicate_node":
        value["nodes"].append(deepcopy(value["nodes"][0]))
    elif mutation == "duplicate_edge":
        value["edges"][1]["id"] = value["edges"][0]["id"]
    elif mutation == "duplicate_pair":
        value["edges"].append({"id": "D100", **{key: value["edges"][0][key] for key in ("from", "to")}})
    elif mutation == "unknown_node":
        value["edges"][0]["from"] = "N1000"
    elif mutation == "self_loop":
        value["edges"][0]["from"] = value["edges"][0]["to"]
    else:
        value["edges"].append({"id": "D99", "from": "N80", "to": "N20"})
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)


@pytest.mark.parametrize("targets", [[], ["N30", "N30"], ["N10"], ["N1000"], [True], "N30"])
def test_targets_must_be_nonempty_unique_existing_claims(targets):
    value = dag()
    value["target_ids"] = targets
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)


@pytest.mark.parametrize("where,field", [("root", "root_id"), ("node", "conditions"), ("node", "scope"), ("edge", "changes")])
def test_v1_state_fields_are_not_silently_accepted(where, field):
    value = dag()
    subject = value if where == "root" else value["nodes"][0] if where == "node" else value["edges"][0]
    subject[field] = []
    with pytest.raises(FaithSieveProtocolError, match="契约"):
        validate_proof_dag(value)


@pytest.mark.parametrize("statuses", [[], {"N404": "passed"}, {"N20": "given"}, {"N10": "passed"},
                                      {"N20": True}, {"N20": []}, {"N20": "low_risk"}])
def test_propagation_rejects_unknown_or_untrusted_statuses(statuses):
    with pytest.raises(FaithSieveProtocolError):
        propagate_node_verdicts(dag(), statuses)


@pytest.mark.parametrize("version", [True, 2.0, 1, "2"])
def test_schema_version_is_exact_integer_two(version):
    value = dag()
    value["schema_version"] = version
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)


def test_parser_rejects_duplicate_keys_nonstandard_constants_and_non_json_wrappers():
    text = json.dumps(single_claim())
    values = [text.replace('"schema_version": 2', '"schema_version": 2,"schema_version":2'),
              text.replace('"statement": "True"', '"statement": "True","statement":"False"'),
              text.replace('"ambiguities": []', '"ambiguities": [NaN]'),
              text.replace('"ambiguities": []', '"ambiguities": [Infinity]'),
              "```json\n" + text + "\n```", text + " {}", "[]", "null"]
    for invalid in values:
        with pytest.raises(FaithSieveProtocolError):
            parse_proof_dag(invalid)


def test_existing_text_array_unicode_and_artifact_byte_limits_apply_without_token_limits():
    value = single_claim()
    value["nodes"][0]["statement"] = "x" * 20001
    with pytest.raises(FaithSieveProtocolError, match="过长"):
        validate_proof_dag(value)
    value = single_claim()
    value["ambiguities"] = ["未决"] * 501
    with pytest.raises(FaithSieveProtocolError, match="受限"):
        validate_proof_dag(value)
    value = single_claim()
    value["nodes"][0]["statement"] = "\ud800"
    with pytest.raises(FaithSieveProtocolError):
        validate_proof_dag(value)
    value = {"schema_version": 2, "nodes": [node(f"N{i}", "中" * 20000, steps=[f"S{i}"]) for i in range(1, 22)],
             "edges": [], "target_ids": ["N21"], "ambiguities": []}
    with pytest.raises(FaithSieveProtocolError, match="大小"):
        validate_proof_dag(value)
    with pytest.raises(FaithSieveProtocolError, match="大小"):
        parse_proof_dag(" " * MAX_ARTIFACT_BYTES + json.dumps(single_claim()))


def test_maximum_length_chain_uses_iterative_topological_and_propagation_algorithms():
    count = 1000
    value = {"schema_version": 2,
             "nodes": [node("N1", "A", given=True),
                       *[node(f"N{i}", f"命题 {i}", steps=[f"S{i-1}"]) for i in range(2, count + 1)]],
             "edges": [{"id": f"D{i-1}", "from": f"N{i-1}", "to": f"N{i}"} for i in range(2, count + 1)],
             "target_ids": [f"N{count}"], "ambiguities": []}
    assert topological_node_ids(value) == [f"N{i}" for i in range(1, count + 1)]
    results = propagate_node_verdicts(value, {f"N{i}": "passed" for i in range(2, count + 1)})
    assert results[f"N{count}"]["established"] is True
    assert results[f"N{count}"]["premise_ids"] == [f"N{count-1}"]
