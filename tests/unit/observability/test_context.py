"""结构化日志上下文的白名单、恢复和并发隔离契约。"""

from __future__ import annotations

import asyncio

import pytest

from backend.oj_modules.observability import context


@pytest.fixture(autouse=True)
def _clean_observability_context():
    context.clear_context()
    yield
    context.clear_context()


def test_current_context_returns_defensive_mapping_copy():
    context.replace_context(request_id="request-original")

    snapshot = context.current_context()
    snapshot["request_id"] = "request-mutated"
    snapshot["trace_id"] = "trace-injected"

    assert context.current_context() == {"request_id": "request-original"}


def test_replace_context_filters_fields_and_replaces_existing_state():
    context.replace_context(request_id="request-old", user_id=7)

    token = context.replace_context(
        trace_id="trace-new",
        username="alice",
        task_id=None,
        task_name="",
        password="must-not-enter-context",
    )

    assert context.current_context() == {
        "trace_id": "trace-new",
        "username": "alice",
    }

    context.reset_context(token)
    assert context.current_context() == {
        "request_id": "request-old",
        "user_id": 7,
    }


def test_replace_context_preserves_valid_falsey_values():
    context.replace_context(user_id=0, request_id=False, username=None)

    assert context.current_context() == {"user_id": 0, "request_id": False}


def test_bind_context_merges_whitelisted_nonempty_fields_and_can_reset():
    context.replace_context(request_id="request-1", user_id=11)

    token = context.bind_context(
        task_id="task-1",
        task_name="judge",
        username="",
        secret="not-allowed",
    )

    assert context.current_context() == {
        "request_id": "request-1",
        "user_id": 11,
        "task_id": "task-1",
        "task_name": "judge",
    }

    context.reset_context(token)
    assert context.current_context() == {
        "request_id": "request-1",
        "user_id": 11,
    }


def test_bind_context_keeps_valid_falsey_values():
    context.replace_context(request_id="request-1")

    context.bind_context(user_id=0, trace_id=False)

    assert context.current_context() == {
        "request_id": "request-1",
        "user_id": 0,
        "trace_id": False,
    }


def test_reset_context_restores_nested_tokens_in_stack_order():
    outer_token = context.replace_context(request_id="request-outer")
    inner_token = context.bind_context(task_id="task-inner")

    context.reset_context(inner_token)
    assert context.current_context() == {"request_id": "request-outer"}

    context.reset_context(outer_token)
    assert context.current_context() == {}


def test_clear_context_removes_all_bound_fields_and_allows_rebinding():
    context.replace_context(
        request_id="request-1",
        trace_id="trace-1",
        task_id="task-1",
    )

    context.clear_context()
    assert context.current_context() == {}

    context.bind_context(username="alice")
    assert context.current_context() == {"username": "alice"}


def test_propagation_context_returns_only_cross_process_fields():
    context.replace_context(
        request_id="request-1",
        trace_id="trace-1",
        user_id=0,
        username="alice",
        task_id="task-1",
        task_name="judge",
        root_task_id="root-1",
        parent_task_id="parent-1",
    )

    assert context.propagation_context() == {
        "request_id": "request-1",
        "trace_id": "trace-1",
        "user_id": 0,
        "username": "alice",
    }


def test_contextvars_isolate_concurrent_async_tasks_and_restore_parent():
    context.replace_context(request_id="parent")

    async def worker(request_id: str):
        token = context.replace_context(request_id=request_id)
        await asyncio.sleep(0)
        observed = context.current_context()
        context.reset_context(token)
        return observed, context.current_context()

    async def run_workers():
        return await asyncio.gather(worker("child-a"), worker("child-b"))

    results = asyncio.run(run_workers())

    assert results == [
        ({"request_id": "child-a"}, {"request_id": "parent"}),
        ({"request_id": "child-b"}, {"request_id": "parent"}),
    ]
    assert context.current_context() == {"request_id": "parent"}
