"""局部命题验证顺序；排序不能产生数学结论或省略目标依赖。"""

from __future__ import annotations

import re

from .artifacts import FaithSieveProtocolError, parse_json_response
from .proof_dag import topological_node_ids


NODE_SELECTION_VERSION = 1
NODE_SELECTION_PATH = "faithsieve-work/node-selection.json"
NODE_SELECTION_FALLBACK_REASON = "局部命题排序未形成有效结果，使用原有验证顺序。"
_NODE_ID = re.compile(r"N[1-9][0-9]*\Z")


def validate_node_selection_version(version):
    if version is not None and (type(version) is not int or version != NODE_SELECTION_VERSION):
        raise FaithSieveProtocolError("FaithSieve 局部命题排序版本无效")
    return version


def validate_node_selection(value, *, required_node_ids):
    """只接受目标闭包全部待证节点的唯一完整排列，不猜测遗漏节点。"""
    if type(value) is not dict or set(value) != {"node_ids"}:
        raise FaithSieveProtocolError("FaithSieve 局部命题排序字段无效")
    order = value["node_ids"]
    required = set(required_node_ids)
    if (type(order) is not list
            or any(type(identifier) is not str or not _NODE_ID.fullmatch(identifier) for identifier in order)
            or len(set(order)) != len(order) or set(order) != required):
        raise FaithSieveProtocolError("FaithSieve 局部命题排序必须完整且恰好覆盖目标依赖闭包的待证节点")
    return {"node_ids": list(order)}


def parse_node_selection(content, *, required_node_ids):
    if type(content) is not str or not content.lstrip().startswith("{"):
        raise FaithSieveProtocolError("FaithSieve 局部命题排序必须是纯 JSON 对象正文")
    return validate_node_selection(parse_json_response(content, strict_constants=True),
                                   required_node_ids=required_node_ids)


def default_node_selection_order(dag):
    """恢复旧稳定逆拓扑顺序；闭包与待证身份完全由代码从图决定。"""
    nodes = {node["id"]: node for node in dag["nodes"]}
    parents = {identifier: [] for identifier in nodes}
    for edge in dag["edges"]:
        parents[edge["to"]].append(edge["from"])
    required, pending = set(), list(dag["target_ids"])
    while pending:
        identifier = pending.pop()
        if identifier not in required:
            required.add(identifier)
            pending.extend(parents[identifier])
    return [identifier for identifier in reversed(topological_node_ids(dag))
            if identifier in required and nodes[identifier]["kind"] == "claim"]


def validate_node_selection_fallback(value, *, expected_node_ids):
    """重放时核对代码回退的版本、固定说明与精确原顺序，不能省略节点。"""
    if (type(value) is not dict or set(value) != {"version", "code_validated", "node_ids", "reason"}
            or type(value["version"]) is not int or value["version"] != NODE_SELECTION_VERSION
            or type(value["code_validated"]) is not bool or value["code_validated"] is not True
            or value["reason"] != NODE_SELECTION_FALLBACK_REASON):
        raise FaithSieveProtocolError("FaithSieve 冻结局部命题排序回退无效")
    expected = list(expected_node_ids)
    validated = validate_node_selection({"node_ids": value["node_ids"]}, required_node_ids=expected)
    if validated["node_ids"] != expected:
        raise FaithSieveProtocolError("FaithSieve 冻结局部命题排序回退与原稳定顺序不一致")
    return {"version": NODE_SELECTION_VERSION, "code_validated": True,
            "node_ids": validated["node_ids"], "reason": NODE_SELECTION_FALLBACK_REASON}


__all__ = ["NODE_SELECTION_VERSION", "NODE_SELECTION_PATH", "NODE_SELECTION_FALLBACK_REASON",
           "validate_node_selection_version", "validate_node_selection", "parse_node_selection",
           "default_node_selection_order", "validate_node_selection_fallback"]
