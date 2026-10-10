"""宿主冻结的事实性审图意见；不产生数学结果或普通角色阶段。"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta
import re

from .artifacts import FaithSieveProtocolError
from .json_repair import strict_equal
from .node_selection import validate_node_selection_fallback


GRAPH_CONTEXT_REVISION_KEY = "image-graph-context-revision"
GRAPH_CONTEXT_REVISION_VERSION = 1
_REQUEST_FIELDS = {"version", "after_role_counter", "affected_node_ids", "report"}
_RECORD_FIELDS = {"request", "state", "response", "sequence", "created_at", "updated_at"}
_NODE_ID = re.compile(r"N[1-9][0-9]*\Z")
_CHINESE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
_UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                            r"(?:\.[0-9]{1,6})?(?:\+00:00|Z)\Z")
_ROLE_KEY = re.compile(r"role-([0-9]{6,})-attempt-([12])\Z")


def validate_graph_context_revision_request(request, *, after_role_counter=None, known_node_ids=None):
    """只校验指令身份和事实意见的结构；原稿是否支持意见仍由独立审图决定。"""
    if type(request) is not dict or set(request) != _REQUEST_FIELDS:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订指令字段无效")
    if type(request["version"]) is not int or request["version"] != GRAPH_CONTEXT_REVISION_VERSION:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订指令版本无效")
    counter = request["after_role_counter"]
    if type(counter) is not int or counter < 1:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订边界必须是正整数")
    if after_role_counter is not None and (type(after_role_counter) is not int
                                           or after_role_counter < 1 or counter != after_role_counter):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订边界与完整缓存前缀不一致")
    identifiers = request["affected_node_ids"]
    if (type(identifiers) is not list or not identifiers
            or any(type(identifier) is not str or not _NODE_ID.fullmatch(identifier) for identifier in identifiers)
            or len(set(identifiers)) != len(identifiers)):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订必须列出非空且唯一的受影响节点")
    if known_node_ids is not None:
        if (type(known_node_ids) not in {dict, list, tuple, set, frozenset}
                or any(type(identifier) is not str or not _NODE_ID.fullmatch(identifier)
                       for identifier in known_node_ids)):
            raise FaithSieveProtocolError("FaithSieve 当前图节点身份无效")
        if not set(identifiers).issubset(known_node_ids):
            raise FaithSieveProtocolError("FaithSieve 图上下文修订引用了当前图不存在的节点")
    report = request["report"]
    if type(report) is not str or not report.strip() or not _CHINESE.search(report):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订必须提供非空中文审图意见")
    try:
        report.encode("utf-8")
    except UnicodeError:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订意见不是有效文本") from None
    return copy.deepcopy(request)


def _timestamp(value):
    if type(value) is not str or not _UTC_TIMESTAMP.fullmatch(value):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点时间无效")
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.utcoffset() != timedelta(0):
            raise ValueError
    except (ValueError, OverflowError):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点须使用有效 UTC 时间") from None
    return parsed


def validate_graph_context_revision(record, *, after_role_counter=None, known_node_ids=None):
    """只接受完整完成的宿主检查点；ack 不认证任何数学结论。"""
    if type(record) is not dict or set(record) != _RECORD_FIELDS:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点字段无效")
    if type(record["state"]) is not str or record["state"] != "completed":
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点必须已完成")
    response = record["response"]
    if (type(response) is not dict or set(response) != {"accepted"}
            or type(response["accepted"]) is not bool or response["accepted"] is not True):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订确认字段无效")
    if type(record["sequence"]) is not int or record["sequence"] < 1:
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点顺序无效")
    if _timestamp(record["created_at"]) > _timestamp(record["updated_at"]):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点时间顺序无效")
    return validate_graph_context_revision_request(record["request"], after_role_counter=after_role_counter,
                                                   known_node_ids=known_node_ids)


def read_graph_context_revision(checkpoints, *, after_role_counter=None, known_node_ids=None):
    """安全只读可选指令；缺失时不创建文件，也不升级已有工作区。"""
    try:
        record, _size = checkpoints._read_record(GRAPH_CONTEXT_REVISION_KEY, strict=True)
    except FileNotFoundError:
        return None
    request = validate_graph_context_revision(record, after_role_counter=after_role_counter,
                                              known_node_ids=known_node_ids)
    snapshot = copy.deepcopy(record)
    replayed = checkpoints.get(GRAPH_CONTEXT_REVISION_KEY, request)
    if not strict_equal(snapshot, replayed):
        raise FaithSieveProtocolError("FaithSieve 图上下文修订检查点在只读重放时发生变化")
    return request


def _selector_fallback(record):
    request = record["request"]
    metadata = record.get("metadata") or {}
    if (request["role"] != "node-selector" or type(request.get("node_selection_version")) is not int
            or request["node_selection_version"] != 1):
        return False
    fallback = metadata.get("node_selection_fallback")
    if type(fallback) is not dict or type(fallback.get("node_ids")) is not list:
        return False
    # 当时实际 DAG 的完整集合仍由排序阶段重放时再次核对。
    validate_node_selection_fallback(fallback, expected_node_ids=fallback["node_ids"])
    return True


def _completed_prefix_role(record):
    request = record.get("request") if type(record) is dict else None
    if (type(request) is not dict or type(request.get("role")) is not str or not request["role"].strip()
            or type(request.get("proof_graph_version")) is not int or request["proof_graph_version"] != 3):
        raise FaithSieveProtocolError("FaithSieve 看图返修缓存前缀角色身份无效")
    metadata = record.get("metadata")
    if metadata is not None and type(metadata) is not dict:
        raise FaithSieveProtocolError("FaithSieve 看图返修缓存前缀元数据无效")
    metadata = metadata or {}
    # 供应商附加元数据不具备调度意义；只核对实际格式/传输修复子操作。
    for name in ("json_repair", "empty_result_retry"):
        child = metadata.get(name)
        if type(child) is dict and child.get("state") == "pending":
            raise FaithSieveProtocolError("FaithSieve 看图返修缓存前缀仍有待完成的修复子操作")
    if record.get("state") == "completed":
        return
    if record.get("state") in {"protocol_error", "endpoint_error"} and _selector_fallback(record):
        return
    raise FaithSieveProtocolError("FaithSieve 看图返修必须有完整已完成的缓存角色前缀")


def _safe_prefix_boundary(record):
    request = record["request"]
    response = record.get("response")
    result = response.get("result") if type(response) is dict else None
    status = result.get("status") if type(result) is dict else None
    role = request["role"]
    if role == "node-selector":
        if status == "ok" and record["state"] == "completed":
            if "node_selection_fallback" not in (record.get("metadata") or {}):
                return
        elif _selector_fallback(record):
            return
    elif role == "verification-auditor" and status == "ok" and record["state"] == "completed":
        return
    elif (role == "tree-auditor" and status == "ok" and record["state"] == "completed"
          and "node_selection_version" not in request):
        return
    elif (role == "local-verifier" and record["state"] == "completed"
          and "verification_audit_version" not in request):
        if status == "inconclusive" or (status in {"passed", "refuted"} and "local_diagnostic_version" not in request):
            return
    raise FaithSieveProtocolError("FaithSieve 看图返修缓存边界必须是完整已放行且可修图的角色前缀")


def _completed_image_prefix_boundary(checkpoints, after_role_counter):
    """只枚举并核对缓存完整性；调用方另行决定其宿主指令可用的边界。"""
    boundary = after_role_counter
    if type(boundary) is not int or boundary < 1:
        raise FaithSieveProtocolError("FaithSieve 已完成图片角色前缀边界必须是正整数")
    try:
        records = checkpoints.read_records()
    except FileNotFoundError:
        records = {}
    if type(records) is not dict:
        raise FaithSieveProtocolError("FaithSieve 看图返修缓存检查点列表无效")
    grouped = {}
    for key, record in records.items():
        match = _ROLE_KEY.fullmatch(key) if type(key) is str else None
        if match is None:
            continue
        counter, attempt = int(match[1]), int(match[2])
        if counter > boundary:
            continue
        if counter < 1 or attempt in grouped.setdefault(counter, {}):
            raise FaithSieveProtocolError("FaithSieve 看图返修缓存前缀编号无效")
        grouped[counter][attempt] = record
    # 不遍历 range(boundary)，巨大但合法整数也只能核对实际有界记录数量。
    if len(grouped) != boundary:
        raise FaithSieveProtocolError("FaithSieve 看图返修没有完整缓存角色前缀，不能补派数学请求")
    for attempts in grouped.values():
        first = attempts.get(1)
        if type(first) is not dict:
            raise FaithSieveProtocolError("FaithSieve 看图返修缓存前缀缺少首次角色请求")
        if 2 in attempts:
            if first.get("state") != "protocol_error":
                raise FaithSieveProtocolError("FaithSieve 看图返修缓存重试必须来自原协议失败")
            if type(attempts[2]) is not dict or attempts[2].get("state") != "completed":
                raise FaithSieveProtocolError("FaithSieve 看图返修缓存重试尚未完整完成")
            # 即使第二次已完成，也不能将异类首请求混入冻结角色组。
            first_request = first.get("request")
            if (type(first_request) is not dict or type(first_request.get("role")) is not str
                    or not first_request["role"].strip() or type(first_request.get("proof_graph_version")) is not int
                    or first_request["proof_graph_version"] != 3):
                raise FaithSieveProtocolError("FaithSieve 看图返修缓存首次角色身份无效")
            _completed_prefix_role(attempts[2])
            if attempts[2]["request"]["role"] != first_request["role"]:
                raise FaithSieveProtocolError("FaithSieve 看图返修缓存重试角色身份已改变")
        else:
            _completed_prefix_role(first)
    boundary_attempts = grouped[boundary]
    return boundary_attempts.get(2, boundary_attempts[1])


def validate_graph_context_revision_prefix(checkpoints, request):
    """先确认完整缓存前缀，绝不通过新模型或 Judge 请求补齐指令边界。"""
    instruction = validate_graph_context_revision_request(request)
    _safe_prefix_boundary(_completed_image_prefix_boundary(checkpoints, instruction["after_role_counter"]))


def graph_context_revision_input_paths(request):
    """为实际修图对生成固定参考路径；不写工件、不复制指令到模型参数。"""
    validated = validate_graph_context_revision_request(request)
    counter = validated["after_role_counter"]
    return {"previous_graph": f"faithsieve-work/graphs/context-revision-{counter}-previous.json",
            "review": f"faithsieve-work/review/context-revision-{counter}.md"}


__all__ = ["GRAPH_CONTEXT_REVISION_KEY", "GRAPH_CONTEXT_REVISION_VERSION",
           "validate_graph_context_revision_request", "validate_graph_context_revision",
           "read_graph_context_revision", "validate_graph_context_revision_prefix",
           "graph_context_revision_input_paths"]
