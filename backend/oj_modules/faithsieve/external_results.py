"""显式外部定理与局部 Lean 假设协议；不升级已冻结的历史运行。"""

from .artifacts import FaithSieveProtocolError


EXTERNAL_RESULTS_VERSION = 1


def validate_external_results_version(version):
    if version is not None and (type(version) is not int or version != EXTERNAL_RESULTS_VERSION):
        raise FaithSieveProtocolError("FaithSieve 外部结果协议版本无效")
    return version


__all__ = ["EXTERNAL_RESULTS_VERSION", "validate_external_results_version"]
