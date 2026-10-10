"""无结论报告的来源与分类审核版本；不升级历史冻结任务。"""

from .artifacts import FaithSieveProtocolError


VERIFICATION_AUDIT_VERSION = 1


def validate_verification_audit_version(version):
    if version is not None and (type(version) is not int or version != VERIFICATION_AUDIT_VERSION):
        raise FaithSieveProtocolError("FaithSieve 局部验证报告审核版本无效")
    return version


__all__ = ["VERIFICATION_AUDIT_VERSION", "validate_verification_audit_version"]
