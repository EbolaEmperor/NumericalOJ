# -*- coding: utf-8 -*-

from types import SimpleNamespace

import pytest

from oj_modules.ai_detection import detector, llm_detector
from oj_modules.tasks import ai_detection_tasks


def _snapshot(endpoint_id=7):
    return SimpleNamespace(id=endpoint_id)


def test_available_detection_endpoints_filters_categories_and_secrets(monkeypatch):
    monkeypatch.setattr(
        "oj_modules.site_config.services.list_llm_endpoints",
        lambda **_kwargs: [
            {"id": 1, "protocol": "anthropic", "category": "text", "model": "t", "api_key": "secret"},
            {"id": 2, "protocol": "openai", "category": "omni", "model": "o", "api_key": "secret"},
            {"id": 3, "protocol": "openai", "category": "vision", "model": "v", "api_key": "secret"},
            {"id": 4, "protocol": "openai", "category": "embedding", "model": "e", "api_key": "secret"},
        ],
    )

    endpoints = llm_detector.get_available_endpoints()
    assert [item["id"] for item in endpoints] == [1, 2]
    assert all("api_key" not in item for item in endpoints)
    assert all("name" not in item for item in endpoints)


def test_detect_with_llm_uses_one_unified_prompt_and_parser(monkeypatch):
    snapshot = _snapshot()
    calls = []
    monkeypatch.setattr(
        llm_detector,
        "resolve_llm_endpoint_snapshot",
        lambda endpoint, **kwargs: snapshot,
    )

    def fake_call(endpoint, prompt, **kwargs):
        calls.append((endpoint, prompt, kwargs))
        return SimpleNamespace(
            text='{"ai_probability":0.72,"confidence":0.8,"evidence":["注释异常"]}'
        )

    monkeypatch.setattr(llm_detector, "call_text", fake_call)
    result = llm_detector.detect_with_llm(
        "print(1)",
        "题面",
        language="python",
        endpoint=snapshot,
    )

    assert result["score"] == 0.72
    assert result["confidence"] == 0.8
    assert result["evidence"] == ["注释异常"]
    assert calls[0][0] is snapshot
    assert "题面" in calls[0][1]
    assert "python" in calls[0][1]
    assert "MATLAB" not in calls[0][2]["system_prompt"]
    assert "通义千问" not in calls[0][2]["system_prompt"]
    assert calls[0][2]["system_prompt"] == llm_detector._SYSTEM_PROMPT


def test_run_detection_passes_fixed_snapshot_without_model_branch(monkeypatch):
    snapshot = _snapshot(11)
    seen = []

    def fake_detect(*_args, **kwargs):
        seen.append(kwargs)
        return {"score": 0.2, "confidence": 0.9, "evidence": [], "raw_response": ""}

    monkeypatch.setattr(detector, "detect_with_llm", fake_detect)
    monkeypatch.setattr(detector, "detect_behavior", lambda *_args: None)
    detector.run_detection(
        {"id": 1, "username": "u", "problem_id": 2, "code": "x=1;"},
        {"id": 2, "content": "题面"},
        endpoint=snapshot,
    )
    assert seen == [{
        "language": "未注明",
        "endpoint": snapshot,
        "endpoint_id": None,
    }]


def test_batch_workers_share_task_start_endpoint_snapshot(monkeypatch):
    snapshot = _snapshot(19)
    seen = []
    monkeypatch.setattr(
        ai_detection_tasks,
        "run_detection",
        lambda submission, problem, **kwargs: (
            seen.append(kwargs["endpoint"])
            or {"submission_id": submission["id"]}
        ),
    )
    monkeypatch.setattr(ai_detection_tasks, "upsert_ai_detection_result", lambda _result: None)
    monkeypatch.setattr(ai_detection_tasks, "record_task_running", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ai_detection_tasks, "record_task_progress", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(ai_detection_tasks, "record_task_done", lambda *_args, **_kwargs: None)

    result = ai_detection_tasks._run_batch(
        "task",
        [
            {"id": 1, "problem_id": 3},
            {"id": 2, "problem_id": 3},
        ],
        lambda _problem_id: {"id": 3},
        snapshot,
    )
    assert result == {"total": 2, "processed": 2}
    assert seen == [snapshot, snapshot]


def test_detection_endpoint_resolver_restricts_text_or_omni(monkeypatch):
    seen = {}

    def fake_resolve(endpoint, **kwargs):
        seen.update(kwargs)
        return _snapshot(23)

    monkeypatch.setattr(ai_detection_tasks, "resolve_llm_endpoint_snapshot", fake_resolve)
    assert ai_detection_tasks._resolve_detection_endpoint(23).id == 23
    assert seen["endpoint_id"] == 23
    assert seen["allowed_categories"] == {"omni", "text"}


@pytest.mark.parametrize("payload", [{}, {"endpoint_id": ""}, {"endpoint_id": "x"}])
def test_route_requires_explicit_detection_endpoint(monkeypatch, payload):
    from flask import Flask
    from oj_modules.routes import ai_detection_routes

    app = Flask(__name__)
    monkeypatch.setattr(
        ai_detection_routes,
        "get_available_endpoints",
        lambda: [{"id": 5}],
    )
    with app.test_request_context("/", method="POST", json=payload):
        with pytest.raises(ValueError, match="请选择"):
            ai_detection_routes._get_endpoint_id_from_request()
