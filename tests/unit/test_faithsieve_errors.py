import json

import pytest

from backend.oj_modules.ai.endpoints import (
    LLMEndpointRequestError, LLMEndpointResponseError, LLMEndpointValidationError,
)
from backend.oj_modules.faithsieve.artifacts import FaithSieveProtocolError
from backend.oj_modules.faithsieve.errors import (
    FaithSieveEndpointError, endpoint_error_message, endpoint_error_metadata,
)


@pytest.mark.parametrize(("failure", "message"), [
    ("timeout", "模型端点响应超时。"),
    ("connection", "模型端点连接失败。"),
    ("other", "模型端点请求失败。"),
])
def test_transport_failure_has_only_fixed_metadata_and_public_text(failure, message):
    error = LLMEndpointRequestError("SECRET-UPSTREAM-MESSAGE", request_failure=failure)
    metadata = endpoint_error_metadata(error)
    assert metadata == {"kind": "request", "status_code": None, "request_failure": failure}
    assert endpoint_error_message(metadata) == message
    assert message in str(FaithSieveEndpointError("状态树生成", metadata))
    assert "SECRET" not in json.dumps(metadata) + str(FaithSieveEndpointError("状态树生成", metadata))


@pytest.mark.parametrize(("error", "metadata", "message"), [
    (LLMEndpointRequestError("SECRET"), {"kind": "request", "status_code": None}, "无法连接模型端点。"),
    (LLMEndpointRequestError("SECRET", status_code=402), {"kind": "request", "status_code": 402},
     "模型端点余额不足或需要付费（HTTP 402）。"),
    (LLMEndpointRequestError("SECRET", status_code=503), {"kind": "request", "status_code": 503},
     "模型端点服务异常（HTTP 503）。"),
    (LLMEndpointResponseError("SECRET"), {"kind": "response", "status_code": None}, "模型端点返回的响应无效。"),
    (LLMEndpointValidationError("SECRET"), {"kind": "configuration", "status_code": None}, "模型端点配置无效。"),
])
def test_legacy_two_field_error_metadata_remains_exactly_compatible(error, metadata, message):
    assert endpoint_error_metadata(error) == metadata
    assert endpoint_error_message(metadata) == message


@pytest.mark.parametrize("failure", [None, True, 1, [], {}, "", "Timeout", "SECRET-FAILURE"])
def test_invalid_optional_failure_cannot_become_public_text(failure):
    metadata = {"kind": "request", "status_code": None, "request_failure": failure}
    with pytest.raises(FaithSieveProtocolError, match="摘要无效"):
        endpoint_error_message(metadata)
    public_error = str(FaithSieveEndpointError("状态树生成", metadata))
    assert "模型端点调用失败。" in public_error and "SECRET" not in public_error


@pytest.mark.parametrize("metadata", [
    {"kind": "response", "status_code": None, "request_failure": "timeout"},
    {"kind": "configuration", "status_code": None, "request_failure": "connection"},
    {"kind": "request", "status_code": 402, "request_failure": "timeout"},
    {"kind": "request", "status_code": None, "request_failure": "other", "message": "SECRET"},
    {"request_failure": "timeout"},
])
def test_optional_failure_requires_the_complete_request_transport_shape(metadata):
    with pytest.raises(FaithSieveProtocolError, match="摘要无效"):
        endpoint_error_message(metadata)
    assert "SECRET" not in str(FaithSieveEndpointError("状态树生成", metadata))


@pytest.mark.parametrize("malformed", ["SECRET-FAILURE", ["timeout"], True])
def test_mutated_exception_cannot_write_arbitrary_failure_metadata(malformed):
    error = LLMEndpointRequestError("SECRET-UPSTREAM")
    error.request_failure = malformed
    assert endpoint_error_metadata(error) == {"kind": "request", "status_code": None}


@pytest.mark.parametrize(("reason", "message"), [
    ("service_not_enabled", "模型端点服务未开通或不具备调用资格（HTTP 403）。"),
    ("free_tier_exhausted", "模型端点免费额度已耗尽，当前仅允许使用免费额度（HTTP 403）。"),
])
def test_403_fixed_provider_reason_survives_safe_checkpoint_summary(reason, message):
    error = LLMEndpointRequestError("SECRET-UPSTREAM-BODY", status_code=403, provider_reason=reason)
    metadata = endpoint_error_metadata(error)
    assert metadata == {"kind": "request", "status_code": 403, "provider_reason": reason}
    assert endpoint_error_message(json.loads(json.dumps(metadata))) == message
    public = str(FaithSieveEndpointError("局部复核", metadata))
    assert message in public and "SECRET" not in public + json.dumps(metadata)


def test_old_403_checkpoint_without_reason_keeps_exact_legacy_message():
    metadata = {"kind": "request", "status_code": 403}
    assert endpoint_error_metadata(LLMEndpointRequestError("SECRET", status_code=403)) == metadata
    assert endpoint_error_message(metadata) == "模型端点鉴权失败（HTTP 403）。"


@pytest.mark.parametrize("reason", [None, True, 1, [], {}, "SECRET", "Arrearage", ""])
def test_invalid_provider_reason_summary_is_terminal_and_never_public(reason):
    metadata = {"kind": "request", "status_code": 403, "provider_reason": reason}
    with pytest.raises(FaithSieveProtocolError, match="摘要无效"):
        endpoint_error_message(metadata)
    public = str(FaithSieveEndpointError("局部复核", metadata))
    assert "模型端点调用失败。" in public and "SECRET" not in public


@pytest.mark.parametrize("metadata", [
    {"kind": "response", "status_code": 403, "provider_reason": "service_not_enabled"},
    {"kind": "configuration", "status_code": None, "provider_reason": "service_not_enabled"},
    {"kind": "request", "status_code": None, "provider_reason": "service_not_enabled"},
    {"kind": "request", "status_code": 401, "provider_reason": "service_not_enabled"},
    {"kind": "request", "status_code": 403.0, "provider_reason": "service_not_enabled"},
    {"kind": "request", "status_code": "403", "provider_reason": "service_not_enabled"},
    {"kind": "request", "status_code": 403, "provider_reason": "service_not_enabled", "request_failure": "timeout"},
    {"kind": "request", "status_code": 403, "provider_reason": "service_not_enabled", "message": "SECRET"},
])
def test_provider_reason_only_allows_the_exact_three_field_http_403_shape(metadata):
    with pytest.raises(FaithSieveProtocolError, match="摘要无效"):
        endpoint_error_message(metadata)
    assert "SECRET" not in str(FaithSieveEndpointError("局部复核", metadata))


@pytest.mark.parametrize("malformed", ["SECRET", ["service_not_enabled"], True])
def test_mutated_exception_cannot_persist_untrusted_provider_reason(malformed):
    error = LLMEndpointRequestError("SECRET", status_code=403)
    error.provider_reason = malformed
    assert endpoint_error_metadata(error) == {"kind": "request", "status_code": 403}
