#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""题目级 LLM 端点软绑定的解析与校验。

绑定仅保存全局端点 ID，不建立外键，也不在题目保存时检查端点是否仍存在。
这样删除全局端点后，题目仍能保留悬空 ID，并由实际调用路径给出明确错误。
"""

from __future__ import annotations

import json
from collections.abc import Mapping


OUTPUT_IMAGE_GRADING_ENDPOINT_ID = "output_image_grading_endpoint_id"
OCR_ENDPOINT_ID = "ocr_endpoint_id"
TEXT_GRADING_ENDPOINT_ID = "text_grading_endpoint_id"
DIRECT_IMAGE_GRADING_ENDPOINT_ID = "direct_image_grading_endpoint_id"
REVIEW_ENDPOINT_ID = "review_endpoint_id"
CODE_GENERATION_ENDPOINT_ID = "code_generation_endpoint_id"

ALL_PROBLEM_LLM_BINDING_KEYS = frozenset(
    {
        OUTPUT_IMAGE_GRADING_ENDPOINT_ID,
        OCR_ENDPOINT_ID,
        TEXT_GRADING_ENDPOINT_ID,
        DIRECT_IMAGE_GRADING_ENDPOINT_ID,
        REVIEW_ENDPOINT_ID,
        CODE_GENERATION_ENDPOINT_ID,
    }
)

PROGRAMMING_BINDING_KEYS = frozenset({OUTPUT_IMAGE_GRADING_ENDPOINT_ID})
WRITTEN_BINDING_KEYS = frozenset(
    {
        OCR_ENDPOINT_ID,
        TEXT_GRADING_ENDPOINT_ID,
        DIRECT_IMAGE_GRADING_ENDPOINT_ID,
    }
)
PROMPTLY_BINDING_KEYS = frozenset({REVIEW_ENDPOINT_ID, CODE_GENERATION_ENDPOINT_ID})

# 供题目编辑页按用途过滤候选。题目保存仍不检查类别；类别只用于 UI 和运行时。
PROBLEM_LLM_BINDING_CATEGORIES = {
    OUTPUT_IMAGE_GRADING_ENDPOINT_ID: frozenset({"omni", "vision"}),
    OCR_ENDPOINT_ID: frozenset({"omni", "vision"}),
    TEXT_GRADING_ENDPOINT_ID: frozenset({"omni", "text"}),
    DIRECT_IMAGE_GRADING_ENDPOINT_ID: frozenset({"omni", "vision"}),
    REVIEW_ENDPOINT_ID: frozenset({"omni", "text"}),
    CODE_GENERATION_ENDPOINT_ID: frozenset({"omni", "text"}),
}


class ProblemLlmBindingsError(ValueError):
    """题目级端点绑定格式或题型约束不合法。"""


def allowed_problem_llm_binding_keys(problem_type, programming_grading_mode=1):
    """返回当前题型允许保存的绑定键。"""

    try:
        normalized_type = int(problem_type)
    except (TypeError, ValueError) as exc:
        raise ProblemLlmBindingsError("题目类型不合法") from exc

    if normalized_type == 2:
        return WRITTEN_BINDING_KEYS
    if normalized_type != 1:
        return frozenset()

    try:
        normalized_mode = int(programming_grading_mode)
    except (TypeError, ValueError):
        normalized_mode = 1
    if normalized_mode == 3:
        return PROMPTLY_BINDING_KEYS
    return PROGRAMMING_BINDING_KEYS


def _parse_binding_object(value):
    if value is None or value == "":
        return {}
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise ProblemLlmBindingsError("LLM 端点绑定必须是合法的 JSON 对象") from exc
        if not isinstance(parsed, dict):
            raise ProblemLlmBindingsError("LLM 端点绑定必须是 JSON 对象")
        return parsed
    raise ProblemLlmBindingsError("LLM 端点绑定必须是 JSON 对象")


def _normalize_endpoint_id(value, *, key):
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
    if isinstance(value, bool):
        raise ProblemLlmBindingsError(f"{key} 必须是正整数端点 ID")
    try:
        endpoint_id = int(value)
    except (TypeError, ValueError) as exc:
        raise ProblemLlmBindingsError(f"{key} 必须是正整数端点 ID") from exc
    if str(value).strip() != str(endpoint_id) and not isinstance(value, int):
        raise ProblemLlmBindingsError(f"{key} 必须是正整数端点 ID")
    # `llm_endpoints.id` 是 MySQL 有符号 BIGINT；题目 JSON 必须覆盖同一 ID 空间，
    # 不能在表单解析层悄悄截成 32 位整数。
    if endpoint_id <= 0 or endpoint_id > 9_223_372_036_854_775_807:
        raise ProblemLlmBindingsError(f"{key} 必须是正整数端点 ID")
    return endpoint_id


def normalize_problem_llm_bindings(
    value,
    *,
    problem_type,
    programming_grading_mode=1,
):
    """严格归一化题目绑定，并拒绝当前题型不允许的键。"""

    parsed = _parse_binding_object(value)
    allowed = allowed_problem_llm_binding_keys(problem_type, programming_grading_mode)
    unknown = set(parsed) - set(allowed)
    if unknown:
        names = "、".join(sorted(str(item) for item in unknown))
        raise ProblemLlmBindingsError(f"当前题型不允许这些 LLM 端点绑定：{names}")

    normalized = {}
    for key, raw_value in parsed.items():
        endpoint_id = _normalize_endpoint_id(raw_value, key=key)
        if endpoint_id is not None:
            normalized[key] = endpoint_id
    return normalized


def deserialize_problem_llm_bindings(value):
    """从 MySQL JSON/文本读取绑定；损坏数据按空对象处理并由运行时明确失败。"""

    try:
        parsed = _parse_binding_object(value)
    except ProblemLlmBindingsError:
        return {}

    normalized = {}
    for key, raw_value in parsed.items():
        if key not in ALL_PROBLEM_LLM_BINDING_KEYS:
            continue
        try:
            endpoint_id = _normalize_endpoint_id(raw_value, key=key)
        except ProblemLlmBindingsError:
            continue
        if endpoint_id is not None:
            normalized[key] = endpoint_id
    return normalized


def serialize_problem_llm_bindings(value):
    """序列化已归一化绑定；空绑定用 SQL NULL 表示。"""

    if not value:
        return None
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def problem_llm_bindings_from_form(
    form,
    *,
    problem_type,
    programming_grading_mode=1,
    existing=None,
):
    """汇总页面的六个独立选择器，也兼容直接提交完整 JSON。

    编辑页完全未提交任何绑定字段时保留原值；只要提交了任一独立字段，就以当前
    题型允许的字段为一个完整表单集合，空值表示解除绑定。
    """

    if "llm_endpoint_bindings" in form:
        return normalize_problem_llm_bindings(
            form.get("llm_endpoint_bindings"),
            problem_type=problem_type,
            programming_grading_mode=programming_grading_mode,
        )

    submitted_keys = ALL_PROBLEM_LLM_BINDING_KEYS.intersection(form.keys())
    if not submitted_keys:
        return normalize_problem_llm_bindings(
            existing or {},
            problem_type=problem_type,
            programming_grading_mode=programming_grading_mode,
        )

    allowed = allowed_problem_llm_binding_keys(problem_type, programming_grading_mode)
    # 页面同时渲染六个选择器；非当前题型的空选择器不会构成 JSON 键。
    # 非空的越界字段仍保留给严格校验拒绝，不能借隐藏控件绕过题型约束。
    submitted = {
        key: form.get(key)
        for key in submitted_keys
        if key in allowed or str(form.get(key) or "").strip()
    }
    return normalize_problem_llm_bindings(
        submitted,
        problem_type=problem_type,
        programming_grading_mode=programming_grading_mode,
    )


def build_problem_llm_endpoint_candidates(endpoints):
    """为模板生成按用途分组且不含密钥的候选列表。"""

    safe_endpoints = []
    for endpoint in endpoints or []:
        if not isinstance(endpoint, Mapping):
            continue
        try:
            endpoint_id = int(endpoint.get("id"))
        except (TypeError, ValueError):
            continue
        category = str(endpoint.get("category") or "").strip().lower()
        if category not in {"omni", "text", "vision", "embedding"}:
            continue
        safe_endpoints.append(
            {
                "id": endpoint_id,
                "name": str(endpoint.get("name") or "").strip(),
                "protocol": str(endpoint.get("protocol") or "").strip().lower(),
                "category": category,
                "model": str(endpoint.get("model") or "").strip(),
            }
        )

    return {
        key: [
            dict(endpoint)
            for endpoint in safe_endpoints
            if endpoint["category"] in categories
        ]
        for key, categories in PROBLEM_LLM_BINDING_CATEGORIES.items()
    }
