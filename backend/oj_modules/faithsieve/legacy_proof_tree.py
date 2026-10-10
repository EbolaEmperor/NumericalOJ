"""旧 Markdown 证明树的只读视图；只提取显式结构，不补全数学状态。"""

from __future__ import annotations

import re

from .artifacts import MAX_ARTIFACT_BYTES


_MAX_NODES = 1000
_MAX_TEXT_LENGTH = 20000
_NODE = re.compile(r"^(?:-\s+)?(N[0-9]+)(?:\s*[：:。]\s*|\s+)(.+)$")
_EDGE = re.compile(r"^###\s+(E[0-9]+)(.*)$")
_HEADER_STEP = re.compile(r"\s*（对应\s+(S[0-9]+)\s*[，,]\s*(.+)）\s*")
_STEP_LOCATION = re.compile(r"(S[0-9]+)\s*[，,]\s*(.+)")
_PARENT = re.compile(r"(N[0-9]+)\s*(?:->|→)\s*(N[0-9]+)[。.]*")
_FIELD = re.compile(r"^-\s+([^：:]+)[：:]\s*(.*)$")
_GAMMA = re.compile(r"Γ(?:[0-9]+|_in|_out)\s*=")
_GOAL = re.compile(r"(?:^|[；;。])\s*G(?:[0-9]+|_in|_out|_prop2)(?=[=不已。；;\s]|$)")
_STEP_HEADER = re.compile(r"^##\s+(S[0-9]+)\s*$")
_FIELDS = {
    "父子", "父子节点", "步骤/位置", "输入 Γ/G", "输出 Γ/G", "条件变化",
    "目标关系", "转换/作用域", "转换类型", "分支作用域",
}


class _UnrecognizedTree(ValueError):
    pass


def _require(condition):
    if not condition:
        raise _UnrecognizedTree


def _state(text):
    # G 的表达式和引用均原样保留；不将“G8 不变”替换为推断的完整目标。
    return bool(_GAMMA.search(text) and _GOAL.search(text))


def _bounded(text):
    return isinstance(text, str) and len(text.encode("utf-8")) <= MAX_ARTIFACT_BYTES


def _step_sources(markdown):
    """仅认历史步骤工件的显式标题与原稿字段，不按边序号补造来源。"""
    if not markdown:
        return {}
    sources, current, lines = {}, None, []

    def save():
        if current is None:
            return
        _require(current not in sources)
        location, source, collecting, seen = None, [], False, set()
        for line in lines:
            field = _FIELD.fullmatch(line)
            if field:
                name, value = field.groups()
                _require(name in {"页码/段落", "原稿文本", "唯一动作", "当前分支"} and name not in seen)
                seen.add(name)
                if name == "页码/段落":
                    _require(location is None and bool(value.strip()))
                    location = value.strip()
                    collecting = False
                elif name == "原稿文本":
                    _require(not source and not collecting)
                    collecting = True
                    if value:
                        source.append(value)
                else:
                    collecting = False
            elif collecting:
                source.append(line)
        original = "\n".join(source).strip()
        _require(location is not None and bool(original))
        _require(len(location) <= _MAX_TEXT_LENGTH and len(original) <= _MAX_TEXT_LENGTH)
        sources[current] = (location, original)

    for line in markdown.splitlines():
        heading = _STEP_HEADER.fullmatch(line)
        if heading:
            save()
            current, lines = heading.group(1), []
        elif line == "## 无法辨认或无法安全拆分的内容":
            save()
            current, lines = None, []
        elif current is not None:
            _require(not line.startswith("## "))
            lines.append(line)
    save()
    _require(bool(sources))
    return sources


def _edge(identifier, suffix, lines, sources):
    fields = {}
    for line in lines:
        if not line.strip():
            continue
        field = _FIELD.fullmatch(line)
        _require(field is not None)
        name, value = field.groups()
        _require(name in _FIELDS and name not in fields and bool(value.strip()))
        _require(len(value) <= _MAX_TEXT_LENGTH)
        fields[name] = value.strip()
    required = {"输入 Γ/G", "输出 Γ/G", "条件变化", "目标关系"}
    _require(required <= fields.keys())
    _require(_state(fields["输入 Γ/G"]) and _state(fields["输出 Γ/G"]))
    parent_fields = [name for name in ("父子", "父子节点") if name in fields]
    _require(len(parent_fields) == 1)
    parent = _PARENT.fullmatch(fields[parent_fields[0]])
    _require(parent is not None)

    heading_step = _HEADER_STEP.fullmatch(suffix) if suffix.strip() else None
    _require(not suffix.strip() or heading_step is not None)
    field_step = _STEP_LOCATION.fullmatch(fields["步骤/位置"]) if "步骤/位置" in fields else None
    _require("步骤/位置" not in fields or field_step is not None)
    _require(heading_step is not None or field_step is not None)
    if heading_step is not None and field_step is not None:
        _require(heading_step.groups() == field_step.groups())
    step_id, location = (heading_step or field_step).groups()
    source_text = ""
    if sources:
        _require(step_id in sources)
        # 原稿和页码均来自调用方提供的同轮步骤快照，不读取当前 workspace。
        location, source_text = sources[step_id]

    combined = fields.get("转换/作用域")
    if combined is not None:
        _require("转换类型" not in fields and "分支作用域" not in fields)
        parts = re.split(r"[；;]", combined, maxsplit=1)
        if len(parts) == 2:
            _require(bool(parts[0].strip()))
            transition, scope = (part.strip() for part in parts)
        else:
            # 旧稿存在“推导/范数下界”，斜杠不是可靠的字段分隔符。
            transition, scope = combined, ""
    else:
        _require("转换类型" in fields)
        transition, scope = fields["转换类型"], fields.get("分支作用域", "")
    return {
        "id": identifier, "from": parent.group(1), "to": parent.group(2),
        "step_id": step_id, "source_location": location, "source_text": source_text,
        "raw_input": fields["输入 Γ/G"], "raw_output": fields["输出 Γ/G"],
        "raw_changes": fields["条件变化"], "goal_relation": fields["目标关系"],
        "transition_type": transition, "scope_text": scope,
    }


def _parse(markdown, steps_markdown):
    _require(_bounded(markdown) and _bounded(steps_markdown))
    lines = markdown.splitlines()
    _require(lines.count("## 节点") == 1 and lines.count("## EdgeUnit") == 1)
    start, end = lines.index("## 节点"), lines.index("## EdgeUnit")
    _require(start < end)
    _require(all(not line.strip() or line.startswith("# ") for line in lines[:start]))
    nodes, scoped_nodes = [], 0
    for line in lines[start + 1:end]:
        if not line.strip():
            continue
        node = _NODE.fullmatch(line)
        _require(node is not None)
        identifier, state = node.groups()
        _require(_state(state) and len(state) <= _MAX_TEXT_LENGTH)
        nodes.append({"id": identifier, "label": identifier, "raw_state": state})
        scoped_nodes += "作用域：" in state or "作用域:" in state
    _require(2 <= len(nodes) <= _MAX_NODES)
    identifiers = {node["id"] for node in nodes}
    _require(len(identifiers) == len(nodes))

    sources = _step_sources(steps_markdown)
    edges, pending, body = [], None, []
    for line in lines[end + 1:]:
        heading = _EDGE.fullmatch(line)
        if heading:
            if pending is not None:
                edges.append(_edge(*pending, body, sources))
            pending, body = heading.groups(), []
        else:
            _require(pending is not None or not line.strip())
            body.append(line)
    _require(pending is not None)
    edges.append(_edge(*pending, body, sources))
    _require(len(edges) == len(nodes) - 1)
    _require(len({edge["id"] for edge in edges}) == len(edges))
    _require(len({edge["step_id"] for edge in edges}) == len(edges))

    parents, children = {}, {identifier: [] for identifier in identifiers}
    for edge in edges:
        parent, child = edge["from"], edge["to"]
        _require(parent in identifiers and child in identifiers and parent != child)
        _require(child not in parents)
        parents[child] = parent
        children[parent].append(child)
    roots = identifiers - parents.keys()
    _require(len(roots) == 1)
    root = roots.pop()
    visited, pending_nodes = set(), [root]
    while pending_nodes:
        identifier = pending_nodes.pop()
        _require(identifier not in visited)
        visited.add(identifier)
        pending_nodes.extend(children[identifier])
    _require(visited == identifiers)

    ambiguities = ["历史 Markdown 只保留原 Γ/G 状态表达式，引用未展开；本视图不用于后续评测。"]
    if scoped_nodes != len(nodes):
        ambiguities.append("历史 Markdown 未逐项给出所有节点的作用域；未将缺省作用域推断为全局。")
    if any(not edge["scope_text"] for edge in edges):
        ambiguities.append("历史 Markdown 部分边未给出作用域原文，scope_text 留空。")
    if not sources:
        ambiguities.append("未提供同轮步骤原文，source_text 留空。")
    return {
        "schema_version": 1, "format": "legacy_markdown", "root_id": root,
        "nodes": nodes, "edges": edges, "ambiguities": ambiguities,
    }


def parse_legacy_proof_tree(markdown: str, steps_markdown: str = "") -> dict | None:
    """识别失败即返回 None；不会写文件、改历史记录或调用模型补全。"""
    try:
        return _parse(markdown, steps_markdown)
    except (_UnrecognizedTree, UnicodeError):
        return None
