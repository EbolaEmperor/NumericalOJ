"""核对节点传播摘要，不从报告文本猜测数学结论。"""

from .artifacts import FaithSieveProtocolError, parse_json_response
from .json_repair import strict_equal
from .proof_dag import propagate_node_verdicts


NODE_VERIFICATION_PATH = "faithsieve-work/node-verification.json"


def validate_node_verification_summary(value, dag):
    summary = parse_json_response(value, strict_constants=True)
    fields = {"schema_version", "proof_dag", "nodes", "target_ids", "targets_established", "target_coverage"}
    if (set(summary) != fields or type(summary.get("schema_version")) is not int or summary["schema_version"] != 1
            or not strict_equal(summary.get("proof_dag"), dag) or summary.get("target_ids") != dag["target_ids"]
            or not isinstance(summary.get("target_coverage"), str)
            or summary["target_coverage"] not in {"matched", "missing", "inconclusive"}
            or type(summary.get("targets_established")) is not bool or type(summary.get("nodes")) is not dict):
        raise FaithSieveProtocolError("节点验证摘要与完整证明依赖图不一致")
    states = summary["nodes"]
    state_fields = {"local_status", "established", "status", "premise_ids", "blocking_premise_ids"}
    if (set(states) != {node["id"] for node in dag["nodes"]}
            or any(type(state) is not dict or set(state) != state_fields
                   or type(state.get("established")) is not bool
                   or type(state.get("premise_ids")) is not list or type(state.get("blocking_premise_ids")) is not list
                   for state in states.values())):
        raise FaithSieveProtocolError("节点验证摘要字段或节点覆盖无效")
    calculated = propagate_node_verdicts(dag, {identifier: state["local_status"] for identifier, state in states.items()})
    if (calculated != states
            or summary["targets_established"] != all(states[identifier]["established"] for identifier in dag["target_ids"])):
        raise FaithSieveProtocolError("节点验证摘要未按全部直接前提传播证据")
    return summary


def target_dependency_ids(dag):
    parents = {node["id"]: [] for node in dag["nodes"]}
    for edge in dag["edges"]:
        parents[edge["to"]].append(edge["from"])
    required, pending = set(), list(dag["target_ids"])
    while pending:
        identifier = pending.pop()
        if identifier not in required:
            required.add(identifier)
            pending.extend(parents[identifier])
    return required


def validate_conclusive_node_verdict(summary, dag, verdict):
    summary = validate_node_verification_summary(summary, dag)
    required = target_dependency_ids(dag)
    if verdict in {"correct", "incorrect"} and any(
            node["kind"] == "claim" and summary["nodes"][node["id"]]["local_status"] == "not_checked"
            and (dag["schema_version"] == 2 or verdict == "correct" and node["id"] in required)
            for node in dag["nodes"]):
        raise FaithSieveProtocolError("仍有待证节点未审核，不能结束完整验证")
    if verdict == "correct" and (summary["target_coverage"] != "matched" or not summary["targets_established"]):
        raise FaithSieveProtocolError("原题目标尚未完整匹配或建立，不能认证证明")
    if verdict == "incorrect" and not any(summary["nodes"][identifier]["local_status"] == "refuted"
                                          for identifier in required):
        raise FaithSieveProtocolError("目标依赖内没有局部反驳，不能将不确定或无关结论计为学生错误")
    return summary
