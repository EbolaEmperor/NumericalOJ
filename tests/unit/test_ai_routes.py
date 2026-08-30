import json

import pytest
from flask import Flask

from backend.oj_modules.infrastructure.mysql import MySQLPoolExhausted
from backend.oj_modules.routes import ai_routes


def decode_sse(chunks):
    events = []
    for chunk in chunks:
        lines = chunk.strip().splitlines()
        name = next(line.split(":", 1)[1].strip() for line in lines if line.startswith("event:"))
        data = next(line.split(":", 1)[1].strip() for line in lines if line.startswith("data:"))
        events.append((name, json.loads(data)))
    return events


def prepared_request():
    return {
        "sid": 45880,
        "submission": {},
        "problem_content": "题目",
        "user_code": "x = 1",
        "test_points": [],
        "test_points_text": "",
        "repository_files": {},
        "cached_result": None,
        "marks_endpoint": None,
        "image_endpoint": None,
    }


def test_stream_prepared_code_marks_separates_reasoning_and_result(monkeypatch):
    def fake_generate(prepared, *, timeout, on_text_delta=None, on_reasoning_delta=None):
        assert prepared["sid"] == 45880
        assert timeout is None
        on_reasoning_delta("先检查失败测试点")
        on_text_delta("{")
        return {
            "success": True,
            "issues": [],
            "summary": "没有明确问题",
            "code_used": "x = 1",
            "image_mismatch_analysis": "",
            "image_analysis_test_index": None,
            "source": "generated",
        }

    monkeypatch.setattr(
        ai_routes,
        "_generate_prepared_ai_code_marks",
        fake_generate,
    )

    app = Flask(__name__)
    with app.test_request_context("/ask_ai_code_marks_stream"):
        events = decode_sse(
            list(ai_routes._stream_prepared_ai_code_marks(prepared_request()))
        )

    assert [name for name, _payload in events] == [
        "ready",
        "reasoning",
        "progress",
        "result",
        "done",
    ]
    assert events[1][1] == {"delta": "先检查失败测试点"}
    assert events[3][1]["success"] is True


def test_stream_prepared_code_marks_returns_cached_result_without_worker():
    prepared = prepared_request()
    prepared["cached_result"] = {
        "success": True,
        "issues": [],
        "summary": "缓存结果",
        "code_used": "x = 1",
    }

    events = decode_sse(list(ai_routes._stream_prepared_ai_code_marks(prepared)))

    assert [name for name, _payload in events] == ["ready", "result", "done"]
    assert events[1][1]["source"] == "cache"


def test_sync_code_marks_preserves_mysql_pool_backpressure(monkeypatch):
    monkeypatch.setattr(
        ai_routes,
        "_prepare_ai_code_marks_request",
        lambda _payload: prepared_request(),
    )
    monkeypatch.setattr(
        ai_routes,
        "_generate_prepared_ai_code_marks",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            MySQLPoolExhausted(1040, "pool busy")
        ),
    )

    app = Flask(__name__)
    with app.test_request_context(
        "/ask_ai_code_marks",
        method="POST",
        json={},
    ), pytest.raises(MySQLPoolExhausted):
        ai_routes.ask_ai_code_marks()
