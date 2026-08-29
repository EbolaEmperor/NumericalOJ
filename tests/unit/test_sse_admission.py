import ast
from pathlib import Path

import pytest

from oj_modules.shared.sse import (
    SSEConnectionLimiter,
    guard_sse_stream,
    sse_capacity_response,
)


ROOT = Path(__file__).resolve().parents[2]


def test_sse_limiter_rejects_overload_and_reuses_released_slot():
    limiter = SSEConnectionLimiter(2)
    first = limiter.try_acquire()
    second = limiter.try_acquire()

    assert first is not None
    assert second is not None
    assert limiter.active == 2
    assert limiter.try_acquire() is None

    first.release()
    replacement = limiter.try_acquire()
    assert replacement is not None
    assert limiter.active == 2

    replacement.release()
    second.release()
    assert limiter.active == 0


def test_guard_releases_slot_after_normal_completion():
    limiter = SSEConnectionLimiter(1)
    lease = limiter.try_acquire()
    stream = guard_sse_stream(iter(("one", "two")), lease)

    assert list(stream) == ["one", "two"]
    assert limiter.active == 0


def test_guard_releases_unstarted_stream_when_response_closes():
    limiter = SSEConnectionLimiter(1)
    lease = limiter.try_acquire()
    stream = guard_sse_stream(iter(("unused",)), lease)

    stream.close()
    stream.close()

    assert limiter.active == 0


def test_guard_releases_slot_when_generator_raises():
    limiter = SSEConnectionLimiter(1)
    lease = limiter.try_acquire()

    def broken():
        yield "first"
        raise RuntimeError("stream failed")

    stream = guard_sse_stream(broken(), lease)
    assert next(stream) == "first"
    with pytest.raises(RuntimeError, match="stream failed"):
        next(stream)
    assert limiter.active == 0


def test_capacity_response_is_retryable_503():
    from flask import Flask

    app = Flask(__name__)
    with app.app_context():
        response = sse_capacity_response()

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.get_json()["code"] == "sse_capacity_exhausted"


@pytest.mark.parametrize(
    ("relative_path", "function_name"),
    (
        ("oj_modules/routes/submission_routes.py", "submission_status_stream"),
        ("oj_modules/routes/problem_core_routes.py", "agent_run_stream"),
        ("oj_modules/routes/problem_core_routes.py", "agent_task_message_stream"),
        ("oj_modules/routes/ai_routes.py", "ask_ai_code_marks_stream"),
        ("oj_modules/routes/ranking_routes.py", "ranking_judge_stream"),
        ("oj_modules/routes/ranking_routes.py", "ranking_reverse_judge_stream"),
    ),
)
def test_hot_sse_routes_share_admission_guard(relative_path, function_name):
    source = (ROOT / relative_path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    called_names = {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert {
        "try_acquire_sse_slot",
        "sse_capacity_response",
        "guard_sse_stream",
    } <= called_names
