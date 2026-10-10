"""证明状态树的 JSON 契约；结构校验先于落盘及数学审计。"""

from __future__ import annotations

import json
import re

from .artifacts import MAX_ARTIFACT_BYTES, FaithSieveProtocolError


TREE_PATH = "faithsieve-work/tree.json"
MAX_NODES = 1000
MAX_TEXT_LENGTH = 20000
MAX_ARRAY_ITEMS = 500
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_NODE_FIELDS = {"id", "label", "conditions", "goal", "scope"}
_EDGE_FIELDS = {"id", "from", "to", "step_id", "source_location", "source_text",
                "changes", "goal_relation", "transition_type", "scope"}
_CHANGES = {"retained", "added", "consumed", "transformed"}


def _object(value, fields, name):
    if not isinstance(value, dict) or set(value) != fields:
        raise FaithSieveProtocolError(f"证明状态树的 {name} 字段不符合 JSON 契约")


def _text(value, name, *, identifier=False):
    if not isinstance(value, str) or not value.strip():
        raise FaithSieveProtocolError(f"证明状态树的 {name} 必须非空字符串")
    if len(value) > MAX_TEXT_LENGTH:
        raise FaithSieveProtocolError(f"证明状态树的 {name} 文本过长")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise FaithSieveProtocolError(f"证明状态树的 {name} 文本不是有效 Unicode") from None
    if identifier and not _ID.fullmatch(value):
        raise FaithSieveProtocolError(f"证明状态树的 {name} ID 无效")


def _texts(value, name):
    if not isinstance(value, list) or len(value) > MAX_ARRAY_ITEMS:
        raise FaithSieveProtocolError(f"证明状态树的 {name} 必须是受限字符串数组")
    for item in value:
        _text(item, name)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FaithSieveProtocolError("证明状态树 JSON 有重复字段")
        value[key] = item
    return value


def step_ids(text):
    """沿用拆分的稳定标题，不把正文中提及的 S 编号算作步骤。"""
    if not isinstance(text, str):
        raise FaithSieveProtocolError("证明拆分缺少步骤原文")
    ids = re.findall(r"(?m)^##\s+(S[1-9][0-9]*)\b[^\n]*$", text)
    if not ids or ids != [f"S{number}" for number in range(1, len(ids) + 1)]:
        raise FaithSieveProtocolError("证明拆分步骤编号不连续或重复")
    return ids


def parse_proof_tree(content, *, expected_steps=None):
    """只接受纯 JSON，不接受围栏、Markdown 或重复键。"""
    if not isinstance(content, str):
        raise FaithSieveProtocolError("证明状态树 JSON 无效或过大")
    try:
        size = len(content.encode("utf-8"))
    except UnicodeError:
        raise FaithSieveProtocolError("证明状态树 JSON 不是有效 Unicode") from None
    if size > MAX_ARTIFACT_BYTES:
        raise FaithSieveProtocolError("证明状态树 JSON 无效或过大")
    try:
        tree = json.loads(content, object_pairs_hook=_unique_object)
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, FaithSieveProtocolError):
            raise
        raise FaithSieveProtocolError("证明状态树必须是可解析的纯 JSON") from None
    return validate_proof_tree(tree, expected_steps=expected_steps)


def _state_fields(node, *, transport):
    conditions, goal = node["conditions"], node["goal"]
    if transport and isinstance(conditions, dict):
        _object(conditions, {"inherit_from", "remove", "add"}, "条件传输引用")
        _text(conditions["inherit_from"], "conditions.inherit_from", identifier=True)
        _texts(conditions["add"], "conditions.add")
        selectors = conditions["remove"]
        if not isinstance(selectors, list) or len(selectors) > MAX_ARRAY_ITEMS:
            raise FaithSieveProtocolError("证明状态树条件引用的 remove 必须是受限选择项数组")
        for selector in selectors:
            if type(selector) is int and selector >= 0:
                continue
            if isinstance(selector, str):
                _text(selector, "conditions.remove")
                continue
            raise FaithSieveProtocolError("证明状态树条件引用的 remove 只能使用非负整数索引或条件精确全文字符串")
    else:
        _texts(conditions, "node.conditions")
    if transport and isinstance(goal, dict):
        _object(goal, {"inherit_from"}, "目标传输引用")
        _text(goal["inherit_from"], "goal.inherit_from", identifier=True)
    else:
        _text(goal, "node.goal")


def _validate_tree_shape(tree, *, expected_steps=None, transport=False):
    _object(tree, {"schema_version", "root_id", "nodes", "edges", "ambiguities"}, "根对象")
    if type(tree["schema_version"]) is not int or tree["schema_version"] != 1:
        raise FaithSieveProtocolError("证明状态树 schema_version 必须为 1")
    _text(tree["root_id"], "root_id", identifier=True)
    _texts(tree["ambiguities"], "ambiguities")
    nodes, edges = tree["nodes"], tree["edges"]
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= MAX_NODES:
        raise FaithSieveProtocolError("证明状态树节点数量无效")
    if not isinstance(edges, list) or len(edges) != len(nodes) - 1:
        raise FaithSieveProtocolError("证明状态树必须满足边数等于节点数减一")
    by_id = {}
    for node in nodes:
        _object(node, _NODE_FIELDS, "节点")
        _text(node["id"], "node.id", identifier=True)
        if node["id"] in by_id:
            raise FaithSieveProtocolError("证明状态树节点 ID 重复")
        by_id[node["id"]] = node
        _text(node["label"], "node.label")
        _texts(node["scope"], "node.scope")
        _state_fields(node, transport=transport)
    if tree["root_id"] not in by_id:
        raise FaithSieveProtocolError("证明状态树根节点不存在")
    parents, children = {}, {identifier: [] for identifier in by_id}
    for number, edge in enumerate(edges, 1):
        _object(edge, _EDGE_FIELDS, "边")
        if edge["id"] != f"E{number}" or edge["step_id"] != f"S{number}":
            raise FaithSieveProtocolError("证明状态树 EdgeUnit 和步骤必须按原证明顺序连续一一对应")
        for field in ("from", "to"):
            _text(edge[field], f"edge.{field}", identifier=True)
            if edge[field] not in by_id:
                raise FaithSieveProtocolError("证明状态树边引用未知节点")
        if edge["to"] in parents:
            raise FaithSieveProtocolError("证明状态树非根节点必须恰有一个父节点")
        parents[edge["to"]] = edge["from"]
        children[edge["from"]].append(edge["to"])
        for field in ("source_location", "source_text", "goal_relation", "transition_type"):
            _text(edge[field], f"edge.{field}")
        _texts(edge["scope"], "edge.scope")
        _object(edge["changes"], _CHANGES, "条件变化")
        for field in _CHANGES:
            _texts(edge["changes"][field], f"changes.{field}")
    if set(by_id) - set(parents) != {tree["root_id"]}:
        raise FaithSieveProtocolError("证明状态树必须只有一个根节点")
    seen, pending = set(), [tree["root_id"]]
    while pending:
        identifier = pending.pop()
        if identifier in seen:
            raise FaithSieveProtocolError("证明状态树包含环")
        seen.add(identifier)
        pending.extend(children[identifier])
    if seen != set(by_id):
        raise FaithSieveProtocolError("证明状态树存在不可达节点或环")
    if expected_steps is not None and [edge["step_id"] for edge in edges] != expected_steps:
        raise FaithSieveProtocolError("证明状态树未与全部学生步骤一一对应")
    return by_id, parents, children


def validate_proof_tree(tree, *, expected_steps=None):
    _validate_tree_shape(tree, expected_steps=expected_steps)
    return tree


def _remove_indices(selectors, parent_conditions):
    removed = set()
    for selector in selectors:
        if type(selector) is int:
            if selector >= len(parent_conditions):
                raise FaithSieveProtocolError("证明状态树条件引用的 remove 索引越界")
            index = selector
        else:
            matches = [index for index, text in enumerate(parent_conditions) if text == selector]
            if len(matches) != 1:
                raise FaithSieveProtocolError("证明状态树 remove 文本必须在父完整 conditions 中精确且唯一匹配")
            index = matches[0]
        if index in removed:
            raise FaithSieveProtocolError("证明状态树 remove 重复删除同一条件")
        removed.add(index)
    return removed


def expand_proof_tree_transport(tree, *, expected_steps=None):
    """仅 wire 对象允许确定性状态引用；展开后仍返回原严格文件契约。"""
    by_id, parents, children = _validate_tree_shape(tree, expected_steps=expected_steps, transport=True)
    root = by_id[tree["root_id"]]
    if not isinstance(root["conditions"], list) or not isinstance(root["goal"], str):
        raise FaithSieveProtocolError("证明状态树根节点不能使用传输引用")
    expanded, pending, state_bytes = {}, [tree["root_id"]], 0
    while pending:
        identifier = pending.pop()
        node = by_id[identifier]
        conditions, goal = node["conditions"], node["goal"]
        parent_id = parents.get(identifier)
        parent = expanded.get(parent_id)
        if isinstance(conditions, dict):
            if conditions["inherit_from"] != parent_id:
                raise FaithSieveProtocolError("证明状态树条件只能引用真实直接父节点")
            removed = _remove_indices(conditions["remove"], parent["conditions"])
            if len(parent["conditions"]) - len(removed) + len(conditions["add"]) > MAX_ARRAY_ITEMS:
                raise FaithSieveProtocolError("证明状态树展开条件数量过多")
            conditions = [text for index, text in enumerate(parent["conditions"]) if index not in removed] + conditions["add"]
        if isinstance(goal, dict):
            reference, ancestor = goal["inherit_from"], parent_id
            while ancestor is not None and ancestor != reference:
                ancestor = parents.get(ancestor)
            if ancestor is None:
                raise FaithSieveProtocolError("证明状态树目标只能引用真实祖先节点，不能引用自身、兄弟或后代")
            goal = expanded[reference]["goal"]
        result = {**node, "conditions": list(conditions), "goal": goal, "scope": list(node["scope"])}
        # 先累计重复状态的原始字节，防止短 wire 在序列化前膨胀成巨大输出；
        # JSON 转义及其余字段的最终总大小还会由工件序列化器检查。
        state_bytes += sum(len(text.encode("utf-8")) for text in
                           [result["id"], result["label"], goal, *conditions, *result["scope"]])
        if state_bytes > MAX_ARTIFACT_BYTES:
            raise FaithSieveProtocolError("证明状态树展开后的工件过大")
        expanded[identifier] = result
        pending.extend(children[identifier])
    result = {**tree, "nodes": [expanded[node["id"]] for node in tree["nodes"]]}
    return validate_proof_tree(result, expected_steps=expected_steps)


def edge_contexts(tree):
    """从已验证树生成自足上下文，避免模型另抄一份状态产生漂移。"""
    by_id = {node["id"]: node for node in tree["nodes"]}
    return {
        edge["id"]: {"edge": edge, "parent_state": by_id[edge["from"]],
                     "child_state": by_id[edge["to"]]}
        for edge in tree["edges"]
    }
