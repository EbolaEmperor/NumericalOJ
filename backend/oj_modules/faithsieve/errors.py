"""模型调用失败的受限摘要；不保存或展示供应商响应原文。"""

from backend.oj_modules.ai.endpoints import (
    LLMEndpointRequestError, LLMEndpointValidationError,
)

from .artifacts import FaithSieveProtocolError


def endpoint_error_metadata(error):
    if isinstance(error, LLMEndpointRequestError):
        code = error.status_code
        code = code if type(code) is int and 400 <= code <= 599 else None
        metadata = {"kind": "request", "status_code": code}
        request_failure = getattr(error, "request_failure", None)
        if (code is None and type(request_failure) is str
                and request_failure in {"timeout", "connection", "other"}):
            metadata["request_failure"] = request_failure
        provider_reason = getattr(error, "provider_reason", None)
        if (code == 403 and request_failure is None and type(provider_reason) is str
                and provider_reason in {"service_not_enabled", "free_tier_exhausted"}):
            metadata["provider_reason"] = provider_reason
        return metadata
    return {"kind": "configuration" if isinstance(error, LLMEndpointValidationError) else "response",
            "status_code": None}


def endpoint_error_message(metadata):
    if (not isinstance(metadata, dict) or set(metadata) not in (
                {"kind", "status_code"}, {"kind", "status_code", "request_failure"},
                {"kind", "status_code", "provider_reason"},
            )
            or not isinstance(metadata["kind"], str)
            or metadata["kind"] not in {"request", "response", "configuration"}):
        raise FaithSieveProtocolError("FaithSieve 模型失败摘要无效")
    kind, code = metadata["kind"], metadata["status_code"]
    if code is not None and (kind != "request" or type(code) is not int or not 400 <= code <= 599):
        raise FaithSieveProtocolError("FaithSieve 模型失败摘要无效")
    if "request_failure" in metadata:
        request_failure = metadata["request_failure"]
        if (kind != "request" or code is not None or type(request_failure) is not str
                or request_failure not in {"timeout", "connection", "other"}):
            raise FaithSieveProtocolError("FaithSieve 模型失败摘要无效")
        return {
            "timeout": "模型端点响应超时。",
            "connection": "模型端点连接失败。",
            "other": "模型端点请求失败。",
        }[request_failure]
    if "provider_reason" in metadata:
        provider_reason = metadata["provider_reason"]
        if (kind != "request" or type(code) is not int or code != 403
                or type(provider_reason) is not str
                or provider_reason not in {"service_not_enabled", "free_tier_exhausted"}):
            raise FaithSieveProtocolError("FaithSieve 模型失败摘要无效")
        return {
            "service_not_enabled": "模型端点服务未开通或不具备调用资格（HTTP 403）。",
            "free_tier_exhausted": "模型端点免费额度已耗尽，当前仅允许使用免费额度（HTTP 403）。",
        }[provider_reason]
    if kind == "configuration":
        return "模型端点配置无效。"
    if kind == "response":
        return "模型端点返回的响应无效。"
    if code is None:
        return "无法连接模型端点。"
    if code in {401, 403}:
        return f"模型端点鉴权失败（HTTP {code}）。"
    if code == 402:
        return "模型端点余额不足或需要付费（HTTP 402）。"
    if code == 404:
        return "模型端点请求地址或模型不存在（HTTP 404）。"
    if code == 429:
        return "模型端点触发限流（HTTP 429）。"
    if code >= 500:
        return f"模型端点服务异常（HTTP {code}）。"
    return f"模型端点请求失败（HTTP {code}）。"


class FaithSieveEndpointError(ValueError):
    """携带固定安全摘要，交给宿主保存执行失败终态。"""

    def __init__(self, label, metadata):
        try:
            message = endpoint_error_message(metadata)
        except FaithSieveProtocolError:
            # 失败终态缺少可靠摘要仍然是执行失败，不能转成协议重试
            # 再次调用模型，也不能形成学生证明的数学结论。
            message = "模型端点调用失败。"
        super().__init__(f"{label}失败：{message}未覆盖原人工成绩。")


__all__ = ["FaithSieveEndpointError", "endpoint_error_metadata", "endpoint_error_message"]
