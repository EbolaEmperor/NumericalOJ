"""命题依赖 DAG 的结构契约与局部证据传播，不判断原文的数学语义。"""

from __future__ import annotations

import heapq
import json
import re

from .artifacts import MAX_ARTIFACT_BYTES, FaithSieveProtocolError


MAX_NODES = 1000
MAX_TEXT_LENGTH = 20000
MAX_ARRAY_ITEMS = 500
MAX_ID_LENGTH = 64
_NODE_ID = re.compile(r"N[1-9][0-9]*\Z")
_EDGE_ID = re.compile(r"D[1-9][0-9]*\Z")
_STEP_ID = re.compile(r"S[1-9][0-9]*\Z")
_ROOT_FIELDS = {"schema_version", "nodes", "edges", "target_ids", "ambiguities"}
_NODE_FIELDS = {"id", "kind", "label", "statement", "source_type", "step_ids",
                "source_location", "source_text"}
_IMAGE_NODE_FIELDS = {"id", "kind", "label", "statement"}
_EDGE_FIELDS = {"id", "from", "to"}
_LOCAL_STATUSES = {"passed", "refuted", "inconclusive", "not_checked"}


def _error(message):
    return FaithSieveProtocolError("证明依赖 DAG " + message)


def _object(value, fields, name):
    if type(value) is not dict or set(value) != fields:
        raise _error(f"的{name}字段不符合 JSON 契约")


def _text(value, name, *, pattern=None):
    if not isinstance(value, str) or not value.strip():
        raise _error(f"的{name}必须是非空字符串")
    limit = MAX_ID_LENGTH if pattern is not None else MAX_TEXT_LENGTH
    if len(value) > limit:
        raise _error(f"的{name}过长")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise _error(f"的{name}不是有效 Unicode") from None
    if pattern is not None and not pattern.fullmatch(value):
        raise _error(f"的{name}编号无效")


def _texts(value, name):
    if type(value) is not list or len(value) > MAX_ARRAY_ITEMS:
        raise _error(f"的{name}必须是受限字符串数组")
    for text in value:
        _text(text, name)


def _step_numbers(values, name):
    numbers = []
    for value in values:
        _text(value, name, pattern=_STEP_ID)
        numbers.append(int(value[1:]))
    if numbers != sorted(set(numbers)):
        raise _error(f"的{name}必须按步骤数字正序排列且不能重复")
    return numbers


def _bounded_json(dag):
    size = 0
    try:
        for chunk in json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False).iterencode(dag):
            size += len(chunk.encode("utf-8"))
            if size > MAX_ARTIFACT_BYTES:
                raise _error("工件超过大小限制")
    except FaithSieveProtocolError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise _error("不是受限的有效 JSON") from None


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise _error("JSON 有重复字段")
        value[key] = item
    return value


def _reject_constant(_value):
    raise _error("JSON 含非标准常量")


def parse_proof_dag(content, *, expected_steps=None):
    """只接受完整纯 JSON；字符串内容不会被修改或解释成数学事实。"""
    if not isinstance(content, str):
        raise _error("必须是纯 JSON 文本")
    try:
        if len(content.encode("utf-8")) > MAX_ARTIFACT_BYTES:
            raise _error("工件超过大小限制")
    except UnicodeError:
        raise _error("文本不是有效 Unicode") from None
    try:
        dag = json.loads(content, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except FaithSieveProtocolError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise _error("必须是可解析的纯 JSON") from None
    return validate_proof_dag(dag, expected_steps=expected_steps)


def _validated_index(dag, *, expected_steps=None):
    _object(dag, _ROOT_FIELDS, "顶层")
    if type(dag["schema_version"]) is not int or dag["schema_version"] not in {2, 3}:
        raise _error("的 schema_version 必须为 2 或 3")
    image_native = dag["schema_version"] == 3
    if image_native and expected_steps is not None:
        raise _error("图像原稿依赖图不接受步骤转录映射")
    _bounded_json(dag)
    _texts(dag["ambiguities"], "ambiguities")
    nodes, edges = dag["nodes"], dag["edges"]
    if type(nodes) is not list or not 1 <= len(nodes) <= MAX_NODES:
        raise _error("节点数量无效")
    # 无环简单有向图最多有 n(n-1)/2 条边，不限制合法的共享依赖。
    if type(edges) is not list or len(edges) > len(nodes) * (len(nodes) - 1) // 2:
        raise _error("边数量无效")
    by_id, positions, steps = {}, {}, set()
    for position, node in enumerate(nodes):
        _object(node, _IMAGE_NODE_FIELDS if image_native else _NODE_FIELDS, "节点")
        _text(node["id"], "node.id", pattern=_NODE_ID)
        if node["id"] in by_id:
            raise _error("节点 ID 重复")
        by_id[node["id"]], positions[node["id"]] = node, position
        for field in (("label", "statement") if image_native else ("label", "statement", "source_location", "source_text")):
            _text(node[field], f"node.{field}")
        if not image_native:
            if type(node["step_ids"]) is not list or len(node["step_ids"]) > MAX_ARRAY_ITEMS:
                raise _error("的 node.step_ids 必须是受限步骤数组")
            _step_numbers(node["step_ids"], "node.step_ids")
        if node["kind"] == "given":
            if not image_native and (node["source_type"] != "problem" or node["step_ids"]):
                raise _error("题设节点必须来自 problem 且 step_ids 为空")
        elif node["kind"] == "claim":
            if not image_native and (node["source_type"] != "submission" or not node["step_ids"]):
                raise _error("待证节点必须来自 submission 且 step_ids 非空")
            if not image_native:
                steps.update(node["step_ids"])
        elif node["kind"] == "external" and image_native:
            # 这里只约束结构；已有定理身份、完整陈述和适用条件由看图审核确认。
            pass
        else:
            raise _error("节点 kind 必须为 given、claim 或图像协议的 external")
    parents = {identifier: [] for identifier in by_id}
    children = {identifier: [] for identifier in by_id}
    edge_ids, pairs = set(), set()
    for edge in edges:
        _object(edge, _EDGE_FIELDS, "边")
        _text(edge["id"], "edge.id", pattern=_EDGE_ID)
        if edge["id"] in edge_ids:
            raise _error("边 ID 重复")
        edge_ids.add(edge["id"])
        for field in ("from", "to"):
            _text(edge[field], f"edge.{field}", pattern=_NODE_ID)
            if edge[field] not in by_id:
                raise _error("边引用未知节点")
        pair = (edge["from"], edge["to"])
        if pair[0] == pair[1] or pair in pairs:
            raise _error("边不能自引用或重复同一依赖")
        pairs.add(pair)
        parents[pair[1]].append(pair[0])
        children[pair[0]].append(pair[1])
    for identifier, node in by_id.items():
        if node["kind"] == "given" and parents[identifier]:
            raise _error("题设节点不能有输入依赖")
        if node["kind"] == "external" and parents[identifier]:
            raise _error("外部定理节点不能有输入依赖")
        parents[identifier].sort(key=positions.__getitem__)
    targets = dag["target_ids"]
    if type(targets) is not list or not 1 <= len(targets) <= MAX_NODES:
        raise _error("目标节点数组必须非空且受限")
    target_set = set()
    for identifier in targets:
        _text(identifier, "target_ids", pattern=_NODE_ID)
        if identifier in target_set or identifier not in by_id or by_id[identifier]["kind"] != "claim":
            raise _error("目标节点必须是存在且不重复的 claim")
        target_set.add(identifier)
    if expected_steps is not None:
        if type(expected_steps) not in (list, tuple):
            raise _error("原步骤列表无效")
        _step_numbers(expected_steps, "expected_steps")
        if steps != set(expected_steps):
            raise _error("节点未完整覆盖全部原步骤或引用了额外步骤")
    remaining = {identifier: len(values) for identifier, values in parents.items()}
    pending = [positions[identifier] for identifier, count in remaining.items() if not count]
    heapq.heapify(pending)
    ordered = []
    while pending:
        identifier = nodes[heapq.heappop(pending)]["id"]
        ordered.append(identifier)
        for child in children[identifier]:
            remaining[child] -= 1
            if not remaining[child]:
                heapq.heappush(pending, positions[child])
    if len(ordered) != len(nodes):
        raise _error("包含循环依赖")
    return by_id, parents, ordered


def validate_proof_dag(dag, *, expected_steps=None):
    """校验结构与来源类别；给定条件的真实性、目标等价仍须独立审计。"""
    _validated_index(dag, expected_steps=expected_steps)
    return dag


def validate_image_proof_dag(dag, *, allow_external_results=True):
    """新请求只接受直接从图像生成的命题图，不接收转录或引文字段。"""
    validate_proof_dag(dag)
    if dag["schema_version"] != 3:
        raise _error("图像原稿依赖图的 schema_version 必须为 3")
    if not allow_external_results and any(node["kind"] == "external" for node in dag["nodes"]):
        raise _error("历史图像协议不能增加 external 外部定理节点")
    return dag


def parse_image_proof_dag(content, *, allow_external_results=True):
    return validate_image_proof_dag(parse_proof_dag(content), allow_external_results=allow_external_results)


def topological_node_ids(dag):
    """稳定拓扑顺序；同时可处理的节点按原 nodes 顺序排列。"""
    return _validated_index(dag)[2]


def _copy_node(node):
    copied = dict(node)
    if "step_ids" in node:
        copied["step_ids"] = list(node["step_ids"])
    return copied


def node_contexts(dag):
    """每个 claim 只携带自身及直接前驱，依赖共同构成局部验证输入。"""
    by_id, parents, _ordered = _validated_index(dag)
    return {node["id"]: {"node": _copy_node(node),
                         "premises": [_copy_node(by_id[parent]) for parent in parents[node["id"]]]}
            for node in dag["nodes"] if node["kind"] == "claim"}


def propagate_node_verdicts(dag, local_statuses):
    """来源审计通过后调用；局部关系被反驳不表示命题或定理为假。"""
    by_id, parents, ordered = _validated_index(dag)
    if type(local_statuses) is not dict or any(identifier not in by_id for identifier in local_statuses):
        raise _error("局部验证结果引用未知节点或格式无效")
    for identifier, status in local_statuses.items():
        kind = by_id[identifier]["kind"]
        allowed = {kind} if kind in {"given", "external"} else _LOCAL_STATUSES
        if not isinstance(status, str) or status not in allowed:
            raise _error("局部验证状态与节点类型不符")
    propagated = {}
    for identifier in ordered:
        node, premises = by_id[identifier], parents[identifier]
        blocking = [parent for parent in premises if not propagated[parent]["established"]]
        if node["kind"] in {"given", "external"}:
            local, established, status = node["kind"], True, "established"
        else:
            local = local_statuses.get(identifier, "not_checked")
            established = local == "passed" and not blocking
            status = ("established" if established else "blocked" if local == "passed"
                      else "not_checked" if local == "not_checked" else "not_established")
        propagated[identifier] = {"local_status": local, "established": established, "status": status,
                                  "premise_ids": list(premises), "blocking_premise_ids": blocking}
    return {node["id"]: propagated[node["id"]] for node in dag["nodes"]}


__all__ = ["parse_proof_dag", "validate_proof_dag", "parse_image_proof_dag", "validate_image_proof_dag", "node_contexts", "topological_node_ids",
           "propagate_node_verdicts"]
