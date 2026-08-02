from dataclasses import FrozenInstanceError

import pytest

from oj_modules.ai.endpoints import LLMEndpointSnapshot
from oj_modules.tasks.agent import shared as agent_shared
from oj_modules.tasks.agent import solve as agent_solve_task
from oj_modules.tasks.agent import solve_helpers as agent_solve_helpers


def _endpoint(endpoint_id, *, model="model-a"):
    return {
        "id": endpoint_id,
        "name": f"endpoint-{endpoint_id}",
        "category": "text",
        "protocol": "openai",
        "base_url": "https://llm.example/v1",
        "api_key": "test-secret",
        "model": model,
        "thinking_enabled": False,
        "thinking_format": "none",
    }


def test_task_endpoint_resolution_deduplicates_and_freezes_snapshots(monkeypatch):
    calls = []
    rows = {
        "solution_agent": _endpoint(1, model="solve-model"),
        "agent_summary": _endpoint(2, model="summary-model"),
    }

    def fake_resolve(feature_key):
        calls.append(feature_key)
        return rows[feature_key]

    monkeypatch.setattr(agent_shared, "resolve_feature_endpoint", fake_resolve)

    snapshots = agent_shared._resolve_agent_endpoint_snapshots(
        "solution_agent",
        "agent_summary",
        "solution_agent",
    )

    assert calls == ["solution_agent", "agent_summary"]
    assert snapshots["solution_agent"].model == "solve-model"
    assert snapshots["agent_summary"].model == "summary-model"
    rows["solution_agent"]["model"] = "edited-after-task-start"
    assert snapshots["solution_agent"].model == "solve-model"
    with pytest.raises(FrozenInstanceError):
        snapshots["solution_agent"].model = "edited"


def test_task_endpoint_resolution_reports_missing_feature(monkeypatch):
    def missing(_feature_key):
        raise RuntimeError("该功能尚未绑定可用的 LLM 端点")

    monkeypatch.setattr(agent_shared, "resolve_feature_endpoint", missing)

    with pytest.raises(RuntimeError, match="解题 Agent.*尚未绑定.*运行中不会"):
        agent_shared._resolve_agent_endpoint_snapshots("solution_agent")


def test_optional_endpoint_resolution_freezes_available_snapshot_and_error(monkeypatch):
    calls = []
    current_rows = {
        "agent_summary": _endpoint(21, model="summary-at-start"),
    }

    def fake_resolve(feature_key):
        calls.append(feature_key)
        row = current_rows.get(feature_key)
        if row is None:
            raise RuntimeError("绑定为空或指向已删除端点")
        return row

    monkeypatch.setattr(agent_shared, "resolve_feature_endpoint", fake_resolve)
    resolutions = agent_shared._resolve_agent_endpoint_resolutions(
        "agent_summary",
        "repository_embedding",
        "agent_summary",
    )

    current_rows["agent_summary"]["model"] = "summary-edited-later"
    current_rows["repository_embedding"] = _endpoint(
        22,
        model="configured-after-task-start",
    )

    assert calls == ["agent_summary", "repository_embedding"]
    assert resolutions["agent_summary"].available is True
    assert resolutions["agent_summary"].endpoint.model == "summary-at-start"
    assert resolutions["repository_embedding"].available is False
    with pytest.raises(RuntimeError, match="绑定为空或指向已删除端点.*运行中不会"):
        resolutions["repository_embedding"].require("仓库代码检索")
    with pytest.raises(FrozenInstanceError):
        resolutions["repository_embedding"].error = "changed"


def test_web_search_settings_are_frozen_at_task_start(monkeypatch):
    settings = {
        "base_url": "https://search.example/mcp",
        "authorization": "Bearer task-secret",
    }
    monkeypatch.setattr(
        agent_shared,
        "get_web_search_settings",
        lambda **_kwargs: settings,
    )

    snapshot = agent_shared._resolve_web_search_settings_snapshot()
    settings["base_url"] = "https://edited.example/mcp"

    assert snapshot["base_url"] == "https://search.example/mcp"
    with pytest.raises(TypeError):
        snapshot["base_url"] = "https://cannot-edit.example/mcp"


def test_agent_chat_uses_supplied_snapshot_and_preserves_tool_protocol(monkeypatch):
    endpoint = LLMEndpointSnapshot.from_mapping(_endpoint(7))
    captured = {}

    class Result:
        def to_openai_message(self):
            return {
                "role": "assistant",
                "content": "done",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "submit_code", "arguments": "{}"},
                    }
                ],
            }

    def fake_call_chat(use_endpoint, messages, **kwargs):
        captured.update(endpoint=use_endpoint, messages=messages, kwargs=kwargs)
        return Result()

    monkeypatch.setattr(agent_shared, "call_chat", fake_call_chat)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "submit_code",
                "parameters": {"type": "object", "properties": {}},
            },
        }
    ]

    message = agent_shared._call_agent_chat_completion(
        endpoint,
        [{"role": "memory", "content": "remember"}],
        tools=tools,
    )

    assert captured["endpoint"] is endpoint
    assert captured["messages"] == [
        {"role": "system", "content": "[memory]\\nremember"}
    ]
    assert captured["kwargs"]["tools"] == tools
    assert captured["kwargs"]["tool_choice"] == "auto"
    assert message["tool_calls"][0]["function"]["name"] == "submit_code"


def test_history_compaction_receives_explicit_summary_snapshot(monkeypatch):
    endpoint = LLMEndpointSnapshot.from_mapping(_endpoint(9, model="summary-model"))
    captured = {}

    def fake_summary(history_messages, target_chars, summary_endpoint, **kwargs):
        captured.update(
            history_messages=history_messages,
            target_chars=target_chars,
            summary_endpoint=summary_endpoint,
        )
        return "固定摘要"

    monkeypatch.setattr(agent_shared, "_summarize_agent_history", fake_summary)
    conversation = [
        {"role": "user", "content": "x" * 700},
        {"role": "assistant", "content": "y" * 700},
    ]

    compacted = agent_shared._trim_conversation_by_budget(
        conversation,
        max_chars=800,
        keep_rounds=1,
        summary_endpoint=endpoint,
    )

    assert captured["summary_endpoint"] is endpoint
    assert compacted == [
        {
            "role": "assistant",
            "content": "【历史信息摘要（summary-model）】\n固定摘要",
        }
    ]


def test_history_compaction_skips_frozen_unavailable_summary_only_when_needed(
    monkeypatch,
):
    events = []
    unavailable = agent_shared.AgentEndpointResolution(
        feature_key="agent_summary",
        error="任务启动时绑定为空",
    )
    monkeypatch.setattr(
        agent_shared,
        "_push_agent_event",
        lambda _state, message, **kwargs: events.append((message, kwargs)),
    )
    monkeypatch.setattr(
        agent_shared,
        "_summarize_agent_history",
        lambda *_args, **_kwargs: pytest.fail("不可用端点不应发起摘要请求"),
    )
    conversation = [{"role": "user", "content": "x" * 900}]

    untouched = agent_shared._trim_conversation_by_budget(
        conversation,
        max_chars=1200,
        keep_rounds=1,
        summary_endpoint=unavailable,
        state={},
        round_idx=1,
    )
    assert untouched == conversation
    assert events == []

    skipped = agent_shared._trim_conversation_by_budget(
        conversation,
        max_chars=600,
        keep_rounds=1,
        summary_endpoint=unavailable,
        state={},
        round_idx=2,
    )
    assert skipped == conversation
    assert "已跳过 Agent 上下文摘要" in events[0][0]
    assert "任务启动时绑定为空" in events[0][0]
    assert "运行中不会重新读取配置" in events[0][0]


class _FakeCelery:
    tasks = {}

    def task(self, **_kwargs):
        return lambda function: function


class _FakeTaskSelf:
    class request:
        id = "agent-snapshot-test"


def test_solution_task_freezes_all_endpoints_but_only_requires_solution_at_start(
    monkeypatch,
):
    requested_keys = []
    web_reads = []
    solution_snapshot = LLMEndpointSnapshot.from_mapping(_endpoint(1))

    def resolve_once(*feature_keys):
        requested_keys.append(feature_keys)
        return {
            key: agent_shared.AgentEndpointResolution(
                feature_key=key,
                endpoint=solution_snapshot if key == "solution_agent" else None,
                error=(
                    "任务启动时没有配置该可选端点"
                    if key != "solution_agent"
                    else ""
                ),
            )
            for key in feature_keys
        }

    monkeypatch.setattr(agent_solve_task, "_push_agent_event", lambda *_a, **_k: None)
    monkeypatch.setattr(
        agent_solve_task,
        "get_user_by_username",
        lambda _username: {"id": 3, "is_admin": 1},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "get_problem",
        lambda _problem_id: {
            "id": 5,
            "type": 1,
            "title": "snapshot",
            "lang": "cpp",
            "content": "problem",
            "initial_code": "",
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_agent_endpoint_resolutions",
        resolve_once,
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_web_search_settings_snapshot",
        lambda: web_reads.append(True) or {},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_initialize_solver_workspace",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("stop-after-snapshots")),
    )

    task = agent_solve_task.register_agent_solve_problem_task(
        _FakeCelery(),
        evaluate_submission_task=object(),
    )
    with pytest.raises(RuntimeError, match="stop-after-snapshots"):
        task(_FakeTaskSelf(), 5, "admin")

    assert requested_keys == [
        (
            "solution_agent",
            "agent_summary",
            "repository_query_summary",
            "repository_embedding",
            "code_image_analysis",
        )
    ]
    assert web_reads == [True]


def test_solution_task_still_requires_solution_endpoint_at_start(monkeypatch):
    workspace_calls = []
    events = []

    monkeypatch.setattr(
        agent_solve_task,
        "_push_agent_event",
        lambda _state, message, **kwargs: events.append((message, kwargs)),
    )
    monkeypatch.setattr(
        agent_solve_task,
        "get_user_by_username",
        lambda _username: {"id": 3, "is_admin": 1},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "get_problem",
        lambda _problem_id: {
            "id": 5,
            "type": 1,
            "title": "snapshot",
            "lang": "cpp",
            "content": "problem",
            "initial_code": "",
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_agent_endpoint_resolutions",
        lambda *feature_keys: {
            key: agent_shared.AgentEndpointResolution(
                feature_key=key,
                error="任务启动时未配置",
            )
            for key in feature_keys
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_web_search_settings_snapshot",
        lambda: {},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_initialize_solver_workspace",
        lambda **_kwargs: workspace_calls.append(True),
    )

    task = agent_solve_task.register_agent_solve_problem_task(
        _FakeCelery(),
        evaluate_submission_task=object(),
    )
    result = task(_FakeTaskSelf(), 5, "admin")

    assert result["success"] is False
    assert "解题 Agent不可用" in result["message"]
    assert "运行中不会重新读取配置" in result["message"]
    assert workspace_calls == []
    assert events[-1][1]["status"] == "Failed"


def test_solution_task_skips_unavailable_repository_auto_enhancement(monkeypatch):
    events = []
    solution_snapshot = LLMEndpointSnapshot.from_mapping(_endpoint(31))

    monkeypatch.setattr(
        agent_solve_task,
        "_push_agent_event",
        lambda _state, message, **kwargs: events.append((message, kwargs)),
    )
    monkeypatch.setattr(
        agent_solve_task,
        "get_user_by_username",
        lambda _username: {"id": 3, "is_admin": 1},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "get_problem",
        lambda _problem_id: {
            "id": 5,
            "type": 1,
            "title": "snapshot",
            "lang": "cpp",
            "content": "problem",
            "initial_code": "",
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_agent_endpoint_resolutions",
        lambda *feature_keys: {
            key: agent_shared.AgentEndpointResolution(
                feature_key=key,
                endpoint=solution_snapshot if key == "solution_agent" else None,
                error="任务启动时可选端点悬空",
            )
            for key in feature_keys
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_resolve_web_search_settings_snapshot",
        lambda: {},
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_initialize_solver_workspace",
        lambda **_kwargs: {
            "workspace_dir": "/tmp/frozen-agent-workspace",
            "main_code_path": "main.cpp",
            "synced_files": [],
        },
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_build_repository_knn_memory_message",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("仓库检索问题摘要不可用：任务启动时可选端点悬空")
        ),
    )
    monkeypatch.setattr(
        agent_solve_task,
        "_build_initial_prompt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("stop-after-repository-skip")
        ),
    )

    task = agent_solve_task.register_agent_solve_problem_task(
        _FakeCelery(),
        evaluate_submission_task=object(),
    )
    with pytest.raises(RuntimeError, match="stop-after-repository-skip"):
        task(_FakeTaskSelf(), 5, "admin")

    skip_events = [
        message
        for message, _kwargs in events
        if "已跳过代码仓库向量记忆" in message
    ]
    assert skip_events == [
        "已跳过代码仓库向量记忆：仓库检索问题摘要不可用：任务启动时可选端点悬空"
    ]


def test_repository_operations_use_frozen_unavailable_results_without_reread(
    monkeypatch,
):
    missing_summary = agent_shared.AgentEndpointResolution(
        feature_key="repository_query_summary",
        error="启动时摘要端点悬空",
    )
    missing_embedding = agent_shared.AgentEndpointResolution(
        feature_key="repository_embedding",
        error="启动时 Embedding 端点悬空",
    )
    monkeypatch.setattr(
        agent_solve_helpers,
        "_summarize_problem_for_repository_search",
        lambda *_args, **_kwargs: pytest.fail("不可用端点不得触发摘要调用"),
    )
    monkeypatch.setattr(
        agent_solve_helpers,
        "encode_texts_with_repository_embedding",
        lambda *_args, **_kwargs: pytest.fail("不可用端点不得触发 Embedding 调用"),
    )

    with pytest.raises(RuntimeError, match="仓库检索问题摘要.*启动时摘要端点悬空"):
        agent_solve_helpers._build_repository_knn_memory_message(
            user_id=3,
            problem={"title": "problem", "content": "statement"},
            summary_endpoint=missing_summary,
            embedding_endpoint=missing_embedding,
        )

    with pytest.raises(RuntimeError, match="仓库代码检索.*Embedding 端点悬空"):
        agent_solve_helpers._tool_search_useful_code(
            user_id=3,
            description="binary search",
            embedding_endpoint=missing_embedding,
        )


def test_image_analysis_reports_frozen_unavailable_endpoint_only_for_images(
    monkeypatch,
):
    missing_image = agent_shared.AgentEndpointResolution(
        feature_key="code_image_analysis",
        error="启动时图片端点已被删除",
    )
    monkeypatch.setattr(
        agent_solve_helpers,
        "analyze_submission_output_image_against_problem",
        lambda **_kwargs: pytest.fail("不可用端点不得触发图片模型调用"),
    )

    no_image = agent_solve_helpers._analyze_submission_output_image_for_agent(
        problem={"content": "draw a curve"},
        submission_id=9,
        test_points=[{"test_index": 1, "has_output_image": False}],
        endpoint_snapshot=missing_image,
    )
    assert no_image == ("", None, False, "")

    with_image = agent_solve_helpers._analyze_submission_output_image_for_agent(
        problem={"content": "draw a curve"},
        submission_id=9,
        test_points=[{"test_index": 1, "has_output_image": "true"}],
        endpoint_snapshot=missing_image,
    )
    assert with_image[0:3] == ("", None, True)
    assert "启动时图片端点已被删除" in with_image[3]
    assert "运行中不会重新读取配置" in with_image[3]


def test_repository_memory_reuses_one_embedding_snapshot(monkeypatch):
    import numpy as np

    summary_endpoint = LLMEndpointSnapshot.from_mapping(_endpoint(11))
    embedding_row = _endpoint(12, model="embedding-model")
    embedding_row["category"] = "embedding"
    embedding_endpoint = LLMEndpointSnapshot.from_mapping(embedding_row)
    seen = []

    monkeypatch.setattr(
        agent_solve_helpers,
        "_summarize_problem_for_repository_search",
        lambda _source, endpoint: (
            seen.append(("summary", endpoint)) or "query"
        ),
    )

    def fake_encode(_texts, *, endpoint):
        seen.append(("encode", endpoint))
        return np.asarray([[1.0, 0.0]], dtype=np.float32), endpoint.model

    def fake_search(**kwargs):
        seen.append(("search", kwargs["endpoint"]))
        return {"hits": []}

    monkeypatch.setattr(
        agent_solve_helpers,
        "encode_texts_with_repository_embedding",
        fake_encode,
    )
    monkeypatch.setattr(
        agent_solve_helpers,
        "search_repository_chunks",
        fake_search,
    )

    agent_solve_helpers._build_repository_knn_memory_message(
        user_id=3,
        problem={"title": "problem", "content": "statement"},
        summary_endpoint=summary_endpoint,
        embedding_endpoint=embedding_endpoint,
    )

    assert seen == [
        ("summary", summary_endpoint),
        ("encode", embedding_endpoint),
        ("search", embedding_endpoint),
    ]
