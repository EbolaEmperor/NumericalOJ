"""站点 LLM 端点解析与厂商无关的调用入口。

本模块负责把数据库配置或题目软绑定解析为不可变端点快照。协议适配和实际
HTTP 调用统一委托给 ai.endpoints；调用链拿到快照后必须继续向下传递，避免
运行过程中重新读取配置而发生漂移。
"""

from oj_modules.ai.endpoints import (
    LLMEndpointCategory,
    LLMEndpointSnapshot,
    LLMEndpointValidationError,
    call_text,
    call_vision,
)
from oj_modules.problems.llm_bindings import (
    PROBLEM_LLM_BINDING_CATEGORIES,
    deserialize_problem_llm_bindings,
)


_PROBLEM_ENDPOINT_LABELS = {
    "output_image_grading_endpoint_id": "程序输出图片批改",
    "ocr_endpoint_id": "书面作业 OCR",
    "text_grading_endpoint_id": "书面作业文本批改",
    "direct_image_grading_endpoint_id": "书面作业图片批改",
    "review_endpoint_id": "Promptly 思路审查",
    "code_generation_endpoint_id": "Promptly 代码生成",
}


def resolve_llm_endpoint_snapshot(
    endpoint=None,
    *,
    endpoint_id=None,
    feature_key=None,
    allowed_categories=None,
    purpose="LLM",
):
    """解析一次运行时端点并返回不可变快照。

    调用方必须在 endpoint、endpoint_id、feature_key 三种来源中恰选一种。
    数据库访问只发生在这里；把返回快照向下传即可保证运行中的配置不漂移。
    """

    source_count = sum(
        value is not None
        for value in (endpoint, endpoint_id, feature_key)
    )
    if source_count != 1:
        raise RuntimeError(f"{purpose}必须且只能指定一个端点来源。")

    raw_endpoint = endpoint
    if endpoint_id is not None:
        if isinstance(endpoint_id, bool):
            raise RuntimeError(f"{purpose}端点 ID 无效。")
        try:
            use_endpoint_id = int(endpoint_id)
        except (TypeError, ValueError):
            raise RuntimeError(f"{purpose}端点 ID 无效。") from None
        if use_endpoint_id <= 0:
            raise RuntimeError(f"{purpose}端点 ID 无效。")

        from oj_modules.site_config.services import (
            DynamicConfigNotFoundError,
            get_llm_endpoint,
        )

        try:
            raw_endpoint = get_llm_endpoint(use_endpoint_id, include_secret=True)
        except DynamicConfigNotFoundError:
            raise RuntimeError(
                f"{purpose}端点不存在或已删除（ID: {use_endpoint_id}）。"
            ) from None
    elif feature_key is not None:
        use_feature_key = str(feature_key or "").strip()
        if not use_feature_key:
            raise RuntimeError(f"{purpose}功能绑定键不能为空。")

        from oj_modules.site_config.services import (
            DynamicConfigNotFoundError,
            resolve_feature_endpoint,
        )

        try:
            raw_endpoint = resolve_feature_endpoint(use_feature_key)
        except DynamicConfigNotFoundError as exc:
            # 配置层会区分“从未绑定”和“绑定 ID 已被删除”。这里必须保留原始
            # 诊断，尤其不能吞掉悬空 ID，否则管理员无法定位删除后果。
            raise RuntimeError(f"{purpose}：{exc}") from None

    try:
        snapshot = (
            raw_endpoint
            if isinstance(raw_endpoint, LLMEndpointSnapshot)
            else LLMEndpointSnapshot.from_mapping(raw_endpoint)
        )
    except (LLMEndpointValidationError, TypeError, ValueError) as exc:
        raise RuntimeError(f"{purpose}端点配置无效：{exc}") from None

    if allowed_categories is not None:
        try:
            normalized_categories = {
                item
                if isinstance(item, LLMEndpointCategory)
                else LLMEndpointCategory(str(item or "").strip().lower())
                for item in allowed_categories
            }
        except (TypeError, ValueError):
            raise RuntimeError(f"{purpose}允许的端点类别配置无效。") from None
        if snapshot.category not in normalized_categories:
            allowed_text = "、".join(
                sorted(item.value for item in normalized_categories)
            )
            raise RuntimeError(
                f"{purpose}端点类别不兼容：需要 {allowed_text}，"
                f"实际为 {snapshot.category.value}。"
            )
    return snapshot


def resolve_problem_llm_endpoint_snapshot(
    problem,
    binding_key,
    *,
    endpoint=None,
    endpoint_id=None,
):
    """解析题目软绑定；缺失或悬空时给出可诊断错误。"""

    key = str(binding_key or "").strip()
    if key not in PROBLEM_LLM_BINDING_CATEGORIES:
        raise RuntimeError("未知的题目 LLM 端点绑定。")
    purpose = _PROBLEM_ENDPOINT_LABELS.get(key, "题目 LLM")
    if endpoint is not None and endpoint_id is not None:
        raise RuntimeError(f"{purpose}不能同时指定 endpoint 和 endpoint_id。")
    if endpoint is None and endpoint_id is None:
        raw_bindings = (problem or {}).get("llm_endpoint_bindings")
        bindings = deserialize_problem_llm_bindings(raw_bindings)
        endpoint_id = bindings.get(key)
        if endpoint_id is None:
            raise RuntimeError(f"题目尚未配置{purpose}端点。")
    return resolve_llm_endpoint_snapshot(
        endpoint,
        endpoint_id=endpoint_id,
        allowed_categories=PROBLEM_LLM_BINDING_CATEGORIES[key],
        purpose=purpose,
    )


def _safe_delta_callback(callback):
    if not callable(callback):
        return None

    def _emit(delta_text):
        try:
            callback(delta_text)
        except Exception:
            pass

    return _emit


def _call_llm_text(
    prompt_text,
    endpoint,
    *,
    timeout=300,
    system_prompt=None,
    on_delta=None,
    on_reasoning_delta=None,
):
    result = call_text(
        endpoint,
        str(prompt_text or ""),
        system_prompt=system_prompt,
        timeout=timeout,
        on_text_delta=_safe_delta_callback(on_delta),
        on_reasoning_delta=_safe_delta_callback(on_reasoning_delta),
    )
    text = str(result.text or "").strip()
    if not text:
        raise RuntimeError("模型未返回可用文本。")
    return text


def _call_llm_vision(
    prompt_text,
    image_data_urls,
    endpoint,
    *,
    timeout=300,
    system_prompt=None,
    on_delta=None,
    on_reasoning_delta=None,
):
    result = call_vision(
        endpoint,
        str(prompt_text or ""),
        list(image_data_urls or []),
        system_prompt=system_prompt,
        timeout=timeout,
        on_text_delta=_safe_delta_callback(on_delta),
        on_reasoning_delta=_safe_delta_callback(on_reasoning_delta),
    )
    text = str(result.text or "").strip()
    if not text:
        raise RuntimeError("模型未返回可用文本。")
    return text
