"""隔离角色 result 的额外元数据，不改变任何已声明的数学或控制字段。"""

from __future__ import annotations

import copy
import math

from .artifacts import FaithSieveProtocolError


RESULT_PROJECTION_VERSION = 1


def _error(message):
    return FaithSieveProtocolError("FaithSieve 角色结果元数据 " + message)


def validate_result_projection_version(version):
    """旧请求不自动升级；新版标记必须是精确的 JSON 整数 1。"""
    if version is not None and (type(version) is not int or version != RESULT_PROJECTION_VERSION):
        raise _error("投影版本无效")
    return version


def _required_fields(fields):
    if type(fields) not in {set, frozenset, list, tuple} or not fields:
        raise _error("必需字段必须是非空字段集合")
    for field in fields:
        if type(field) is not str or not field:
            raise _error("必需字段名称无效")
        try:
            field.encode("utf-8")
        except UnicodeError:
            raise _error("必需字段名称不是有效 Unicode") from None
    return set(fields)


def _validate_metadata_value(value):
    """隔离数据仍须能按原值保存为 JSON，不转换未知对象或修补字符串。"""
    kind = type(value)
    if value is None or kind in {bool, int}:
        return
    if kind is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise _error("附加元数据不是有效 Unicode") from None
        return
    if kind is float:
        if not math.isfinite(value):
            raise _error("附加元数据含非标准 JSON 数字")
        return
    if kind is list:
        for item in value:
            _validate_metadata_value(item)
        return
    if kind is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise _error("附加元数据对象的键必须是字符串")
            _validate_metadata_value(key)
            _validate_metadata_value(item)
        return
    raise _error("附加元数据必须是 JSON 值")


def project_role_result(payload, fields):
    """只投影 result 子对象，返回独立副本及其原样隔离的附加元数据。

    缺失必需字段一律报错。必需字段的值、其余顶层字段及所有工件正文均保持
    原值，由原严格验证器判断合法性；未知字段不会被搬入 control 或 execution。
    本函数不修复 JSON、数学内容、诊断，也不补入任何默认结论。
    """
    required = _required_fields(fields)
    if type(payload) is not dict or type(payload.get("result")) is not dict:
        raise _error("回传必须含 result 对象")
    result = payload["result"]
    for key in result:
        if type(key) is not str:
            raise _error("result 字段名称必须是字符串")
        try:
            key.encode("utf-8")
        except UnicodeError:
            raise _error("result 字段名称不是有效 Unicode") from None
    if not required <= result.keys():
        raise _error("result 缺少已声明的必需字段")
    metadata = {key: value for key, value in result.items() if key not in required}
    try:
        _validate_metadata_value(metadata)
        canonical = copy.deepcopy(payload)
        discarded = copy.deepcopy(metadata)
    except RecursionError:
        raise _error("回传嵌套结构无法安全复制") from None
    canonical["result"] = {key: value for key, value in canonical["result"].items() if key in required}
    return canonical, discarded


__all__ = ["RESULT_PROJECTION_VERSION", "validate_result_projection_version", "project_role_result"]
