"""教学作品的通用进程资源协议，不承载题目、语言接口或评分规则。

请求校验与限额来自可直接发送到容器的独立执行脚本，避免两侧协议漂移。
程序输出只是有界的字节结果，成绩必须由固定版本作品的内部 grade 计算。
"""

from __future__ import annotations

import base64

from backend.oj_modules.vibehub.edu_process_runner import (
    MAX_COMPILE_OUTPUT_BYTES,
    MAX_ERROR_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_PAYLOAD_BYTES,
    validate_request,
)


MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def _stage(value, *, stdout_limit):
    if not isinstance(value, dict) or set(value) != {
        "returncode", "stdout_b64", "stderr_b64", "stdout_truncated", "stderr_truncated"
    } or type(value["returncode"]) is not int or any(
        type(value[name]) is not bool for name in ("stdout_truncated", "stderr_truncated")
    ):
        raise ValueError("执行阶段响应无效")
    for name, maximum in (("stdout_b64", stdout_limit), ("stderr_b64", MAX_ERROR_BYTES)):
        encoded = value[name]
        if not isinstance(encoded, str) or len(encoded) > ((maximum + 2) // 3) * 4:
            raise ValueError("执行阶段输出超过限制")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError("执行阶段输出编码无效") from exc
        if len(content) > maximum:
            raise ValueError("执行阶段输出超过限制")
    return dict(value)


def validate_response(response):
    if not isinstance(response, dict) or set(response) not in ({"compile"}, {"compile", "run"}):
        raise ValueError("执行响应字段无效")
    compiled = _stage(response["compile"], stdout_limit=MAX_COMPILE_OUTPUT_BYTES)
    result = {"compile": compiled}
    successful = compiled["returncode"] == 0 and not (compiled["stdout_truncated"] or compiled["stderr_truncated"])
    if successful != ("run" in response):
        raise ValueError("执行响应阶段不一致")
    if "run" in response:
        result["run"] = _stage(response["run"], stdout_limit=MAX_OUTPUT_BYTES)
    return result


__all__ = ["MAX_PAYLOAD_BYTES", "MAX_RESPONSE_BYTES", "validate_request", "validate_response"]
