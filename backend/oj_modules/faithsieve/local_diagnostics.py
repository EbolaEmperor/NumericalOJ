"""图像局部验证的构图诊断协议；诊断不属于数学真假证据。"""

from __future__ import annotations

import re

from .artifacts import FaithSieveProtocolError


LOCAL_DIAGNOSTIC_VERSION = 1
LOCAL_DIAGNOSTIC_KINDS = frozenset({
    "statement_mismatch", "missing_premise", "quantifier_drift", "binding_mismatch",
})
LOCAL_MATHEMATICAL_STATUSES = frozenset({"passed", "refuted", "inconclusive"})
LOCAL_DIAGNOSTIC_STATUSES = LOCAL_MATHEMATICAL_STATUSES | {"graph_defect"}
VERIFICATION_AUDITOR_STATUSES = frozenset({"ok", "needs_revision", "graph_defect", "inconclusive"})
_NODE_ID = re.compile(r"N[1-9][0-9]*\Z")
_RESULT_FIELDS = {"status", "artifact", "report"}
_DIAGNOSTIC_FIELDS = {"kind", "affected_node_ids", "reason"}


def _error(message):
    return FaithSieveProtocolError("FaithSieve 局部构图诊断 " + message)


def validate_local_diagnostic_version(version):
    """没有声明版本时严格沿用旧协议，不能隐式升级冻结任务。"""
    if version is not None and (type(version) is not int or version != LOCAL_DIAGNOSTIC_VERSION):
        raise _error("协议版本无效")
    return version


def local_diagnostics_schema():
    """结果函数使用的纯 JSON schema；宿主仍逐项验证语义引用。"""
    return {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["kind", "affected_node_ids", "reason"],
        "properties": {
            "kind": {"type": "string", "enum": sorted(LOCAL_DIAGNOSTIC_KINDS)},
            "affected_node_ids": {"type": "array", "minItems": 1, "uniqueItems": True,
                                  "items": {"type": "string", "pattern": r"^N[1-9][0-9]*$"}},
            "reason": {"type": "string", "minLength": 1},
        },
    }}


def validate_local_verifier_result(result, *, diagnostic_version=None, known_node_ids=None):
    """严格区分构图错误和数学结论，不修改回传或补入缺失字段。"""
    validate_local_diagnostic_version(diagnostic_version)
    fields = _RESULT_FIELDS | ({"diagnostics"} if diagnostic_version is not None else set())
    statuses = LOCAL_DIAGNOSTIC_STATUSES if diagnostic_version is not None else LOCAL_MATHEMATICAL_STATUSES
    if type(result) is not dict or set(result) != fields:
        raise _error("结果字段不符合冻结协议")
    if type(result["status"]) is not str or result["status"] not in statuses:
        raise _error("状态无效")
    if type(result["artifact"]) is not str or not result["artifact"]:
        raise _error("数学报告路径无效")
    if type(result["report"]) is not str:
        raise _error("报告必须是字符串")
    if diagnostic_version is None:
        return result
    if not result["report"].strip():
        raise _error("报告不能为空")
    validate_graph_diagnostics(result["status"], result["diagnostics"], known_node_ids=known_node_ids)
    return result


def validate_verification_auditor_result(result, *, known_node_ids=None):
    """独立审核结论只说明报告是否可信，不改变局部数学结论。"""
    if type(result) is not dict or set(result) != _RESULT_FIELDS | {"diagnostics"}:
        raise _error("验证审核结果字段不符合协议")
    if type(result["status"]) is not str or result["status"] not in VERIFICATION_AUDITOR_STATUSES:
        raise _error("验证审核状态无效")
    if type(result["artifact"]) is not str or not result["artifact"].strip():
        raise _error("验证审核报告路径无效")
    if type(result["report"]) is not str or not result["report"].strip():
        raise _error("验证审核报告不能为空")
    validate_graph_diagnostics(result["status"], result["diagnostics"], known_node_ids=known_node_ids)
    return result


def validate_graph_diagnostics(status, diagnostics, *, known_node_ids=None):
    """局部 Judge 和独立审核共用构图诊断形状，保留各自状态协议。"""
    if type(status) is not str:
        raise _error("诊断状态必须是字符串")
    if type(diagnostics) is not list:
        raise _error("diagnostics 必须是数组")
    if bool(diagnostics) != (status == "graph_defect"):
        raise _error("构图错误必须使用 graph_defect，其他结论不得携带构图诊断")
    known = set(known_node_ids) if known_node_ids is not None else None
    for diagnostic in diagnostics:
        if type(diagnostic) is not dict or set(diagnostic) != _DIAGNOSTIC_FIELDS:
            raise _error("条目字段无效")
        if type(diagnostic["kind"]) is not str or diagnostic["kind"] not in LOCAL_DIAGNOSTIC_KINDS:
            raise _error("类型无效")
        reason = diagnostic["reason"]
        if type(reason) is not str or not reason.strip():
            raise _error("理由不能为空")
        try:
            reason.encode("utf-8")
        except UnicodeError:
            raise _error("理由不是有效 Unicode") from None
        affected = diagnostic["affected_node_ids"]
        if (type(affected) is not list or not affected
                or any(type(identifier) is not str or not _NODE_ID.fullmatch(identifier) for identifier in affected)
                or len(set(affected)) != len(affected)):
            raise _error("affected_node_ids 必须是不重复的节点编号数组")
        if known is not None and any(identifier not in known for identifier in affected):
            raise _error("引用了不存在的节点")
    return diagnostics


__all__ = ["LOCAL_DIAGNOSTIC_VERSION", "LOCAL_DIAGNOSTIC_KINDS", "LOCAL_DIAGNOSTIC_STATUSES",
           "VERIFICATION_AUDITOR_STATUSES",
           "LOCAL_MATHEMATICAL_STATUSES", "validate_local_diagnostic_version", "local_diagnostics_schema",
           "validate_local_verifier_result", "validate_verification_auditor_result", "validate_graph_diagnostics"]
