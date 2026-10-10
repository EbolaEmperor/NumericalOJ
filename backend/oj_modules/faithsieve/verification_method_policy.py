"""在真实无结论局部验证之后冻结更严格的方法审核；不改变原数学结果。"""

from __future__ import annotations

from copy import deepcopy

from .artifacts import FaithSieveProtocolError
from .graph_context_revision import _completed_image_prefix_boundary, _timestamp
from .json_repair import strict_equal


VERIFICATION_METHOD_POLICY_KEY = "image-verification-method-policy"
VERIFICATION_METHOD_VERSION = 1
_REQUEST_FIELDS = {"version", "after_role_counter"}
_RECORD_FIELDS = {"request", "state", "response", "sequence", "created_at", "updated_at"}


def validate_verification_method_version(version):
    if version is not None and (type(version) is not int or version != VERIFICATION_METHOD_VERSION):
        raise FaithSieveProtocolError("FaithSieve 验证方法审核版本无效")
    return version


def validate_verification_method_policy_request(request):
    """宿主策略只声明版本和完整前缀边界，不承载任何预期数学结论。"""
    if type(request) is not dict or set(request) != _REQUEST_FIELDS:
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略字段无效")
    if validate_verification_method_version(request["version"]) != VERIFICATION_METHOD_VERSION:
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略必须冻结版本 1")
    if type(request["after_role_counter"]) is not int or request["after_role_counter"] < 1:
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略边界必须是正整数")
    return deepcopy(request)


def validate_verification_method_policy(record):
    """仅接受标准的完整宿主确认；accepted 不认证证明或验证方法。"""
    if type(record) is not dict or set(record) != _RECORD_FIELDS:
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略检查点字段无效")
    if type(record["state"]) is not str or record["state"] != "completed":
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略检查点必须已完成")
    response = record["response"]
    if (type(response) is not dict or set(response) != {"accepted"}
            or type(response["accepted"]) is not bool or response["accepted"] is not True):
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略确认字段无效")
    if type(record["sequence"]) is not int or record["sequence"] < 1:
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略检查点顺序无效")
    if _timestamp(record["created_at"]) > _timestamp(record["updated_at"]):
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略检查点时间顺序无效")
    return validate_verification_method_policy_request(record["request"])


def read_verification_method_policy(checkpoints):
    """缺失时保持原协议；合法策略登记只读重放，并拒绝两次读取漂移。"""
    try:
        record, _size = checkpoints._read_record(VERIFICATION_METHOD_POLICY_KEY, strict=True)
    except FileNotFoundError:
        return None
    request = validate_verification_method_policy(record)
    snapshot = deepcopy(record)
    replayed = checkpoints.get(VERIFICATION_METHOD_POLICY_KEY, request)
    if not strict_equal(snapshot, replayed):
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略检查点在只读重放时发生变化")
    return request


def validate_verification_method_policy_prefix(checkpoints, request):
    """只从已完成且尚待审核的真实无结论验证之后接入，不能假装既有审计已通过。"""
    instruction = validate_verification_method_policy_request(request)
    record = _completed_image_prefix_boundary(checkpoints, instruction["after_role_counter"])
    saved_request = record["request"]
    response = record.get("response")
    result = response.get("result") if type(response) is dict else None
    if (record["state"] != "completed" or saved_request["role"] != "local-verifier"
            or type(saved_request.get("verification_audit_version")) is not int
            or saved_request["verification_audit_version"] != 1
            or type(result) is not dict or type(result.get("status")) is not str
            or result["status"] != "inconclusive"):
        raise FaithSieveProtocolError("FaithSieve 验证方法审核策略边界必须是待真实审核的无结论局部验证")


__all__ = ["VERIFICATION_METHOD_POLICY_KEY", "VERIFICATION_METHOD_VERSION",
           "validate_verification_method_version", "validate_verification_method_policy_request",
           "validate_verification_method_policy", "read_verification_method_policy",
           "validate_verification_method_policy_prefix"]
