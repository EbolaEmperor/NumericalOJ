# -*- coding: utf-8 -*-

from types import SimpleNamespace

import pytest

from oj_modules.ai import client, code_feedback
from oj_modules.ai.endpoints import LLMEndpointCategory, LLMEndpointSnapshot


def endpoint_mapping(*, endpoint_id=7, category="text", protocol="openai"):
    return {
        "id": endpoint_id,
        "category": category,
        "protocol": protocol,
        "base_url": "https://llm.example.test/v1",
        "api_key": "secret-key",
        "model": f"{category}-model",
        "thinking_enabled": False,
        "thinking_format": "none",
    }


def test_direct_endpoint_is_frozen_and_category_checked():
    snapshot = client.resolve_llm_endpoint_snapshot(
        endpoint_mapping(),
        allowed_categories={"text", "omni"},
        purpose="测试文本",
    )

    assert isinstance(snapshot, LLMEndpointSnapshot)
    assert snapshot.category is LLMEndpointCategory.TEXT
    assert "secret-key" not in repr(snapshot)

    with pytest.raises(RuntimeError, match="类别不兼容"):
        client.resolve_llm_endpoint_snapshot(
            endpoint_mapping(category="vision"),
            allowed_categories={"text"},
            purpose="测试文本",
        )


def test_endpoint_source_must_be_unambiguous():
    with pytest.raises(RuntimeError, match="必须且只能"):
        client.resolve_llm_endpoint_snapshot(purpose="测试")
    with pytest.raises(RuntimeError, match="必须且只能"):
        client.resolve_llm_endpoint_snapshot(
            endpoint_mapping(),
            endpoint_id=7,
            purpose="测试",
        )


def test_feature_binding_resolves_once(monkeypatch):
    from oj_modules.site_config import services as dynamic_config_services

    calls = []

    def fake_resolve(feature_key):
        calls.append(feature_key)
        return endpoint_mapping()

    monkeypatch.setattr(
        dynamic_config_services,
        "resolve_feature_endpoint",
        fake_resolve,
    )

    snapshot = client.resolve_llm_endpoint_snapshot(
        feature_key="ai_code_annotation",
        allowed_categories={"text", "omni"},
        purpose="AI 代码批注",
    )

    assert snapshot.model == "text-model"
    assert calls == ["ai_code_annotation"]


def test_dangling_feature_binding_preserves_deleted_endpoint_id(monkeypatch):
    from oj_modules.site_config import services as dynamic_config_services

    def missing(_feature_key):
        raise dynamic_config_services.DynamicConfigNotFoundError(
            "该功能绑定的 LLM 端点不存在（ID: 654）"
        )

    monkeypatch.setattr(dynamic_config_services, "resolve_feature_endpoint", missing)

    with pytest.raises(RuntimeError, match=r"不存在（ID: 654）"):
        client.resolve_llm_endpoint_snapshot(
            feature_key="ai_code_annotation",
            purpose="AI 代码批注",
        )


def test_dangling_problem_endpoint_reports_id(monkeypatch):
    from oj_modules.site_config import services as dynamic_config_services

    def missing(_endpoint_id, *, include_secret=False):
        del include_secret
        raise dynamic_config_services.DynamicConfigNotFoundError("not found")

    monkeypatch.setattr(dynamic_config_services, "get_llm_endpoint", missing)
    problem = {"llm_endpoint_bindings": {"review_endpoint_id": 987}}

    with pytest.raises(RuntimeError, match=r"不存在或已删除（ID: 987）"):
        client.resolve_problem_llm_endpoint_snapshot(
            problem,
            "review_endpoint_id",
        )


def test_missing_problem_binding_is_explicit():
    with pytest.raises(RuntimeError, match="尚未配置Promptly 思路审查端点"):
        client.resolve_problem_llm_endpoint_snapshot(
            {"llm_endpoint_bindings": {}},
            "review_endpoint_id",
        )


def test_generic_text_and_vision_helpers_forward_snapshot(monkeypatch):
    text_endpoint = LLMEndpointSnapshot.from_mapping(endpoint_mapping())
    vision_endpoint = LLMEndpointSnapshot.from_mapping(
        endpoint_mapping(endpoint_id=8, category="vision")
    )
    calls = []

    def fake_text(endpoint, prompt, **kwargs):
        calls.append(("text", endpoint, prompt, kwargs))
        return SimpleNamespace(text=" text result ")

    def fake_vision(endpoint, prompt, images, **kwargs):
        calls.append(("vision", endpoint, prompt, images, kwargs))
        return SimpleNamespace(text=" vision result ")

    monkeypatch.setattr(client, "call_text", fake_text)
    monkeypatch.setattr(client, "call_vision", fake_vision)

    assert client._call_llm_text(
        "prompt",
        text_endpoint,
        timeout=12,
        system_prompt="system",
    ) == "text result"
    assert client._call_llm_vision(
        "look",
        ["https://images.example.test/a.png"],
        vision_endpoint,
        timeout=13,
    ) == "vision result"
    assert calls[0][1] is text_endpoint
    assert calls[0][3]["system_prompt"] == "system"
    assert calls[1][1] is vision_endpoint


def test_code_marks_resolves_global_text_endpoint_once(monkeypatch):
    snapshot = LLMEndpointSnapshot.from_mapping(endpoint_mapping())
    resolved = []

    def fake_resolve(*args, **kwargs):
        resolved.append((args, kwargs))
        return snapshot

    monkeypatch.setattr(code_feedback, "resolve_llm_endpoint_snapshot", fake_resolve)
    monkeypatch.setattr(
        code_feedback,
        "_call_llm_text",
        lambda _prompt, endpoint, **_kwargs: (
            '{"issues": [], "summary": "ok"}'
            if endpoint is snapshot
            else pytest.fail("快照未向下传递")
        ),
    )

    result = code_feedback.generate_ai_code_marks_from_submission_context(
        problem_content="题目",
        user_code="int main() { return 0; }",
        test_points_text="",
        test_points=[],
    )

    assert result["summary"] == "ok"
    assert len(resolved) == 1
    assert resolved[0][1]["feature_key"] == "ai_code_annotation"
