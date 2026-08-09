from copy import deepcopy
import inspect
from types import SimpleNamespace

import pytest

from oj_modules.tasks.agent import generic
from oj_modules.tasks.agent.harness_runtime import (
    AgentHarnessCleanupError,
    HarnessRunResult,
)


class _FakeCelery:
    def __init__(self):
        self.tasks = {}
        self.options = []

    def task(self, **kwargs):
        self.options.append(kwargs)
        return lambda function: function


def _task_self(task_id):
    return SimpleNamespace(request=SimpleNamespace(id=task_id))


def _endpoint():
    return {
        "id": 8,
        "revision": 4,
        "protocol": "openai",
        "category": "text",
        "base_url": "https://model.example/v1",
        "api_key": "secret",
        "model": "model-a",
        "thinking_enabled": False,
        "thinking_format": "none",
    }


def _patch_generic(monkeypatch, session):
    snapshots = []
    monkeypatch.setattr(
        generic,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(generic, "prepare_agent_trace_dir", lambda _task_id: None)
    monkeypatch.setattr(generic, "_publish_agent_trace", lambda _state: None)
    monkeypatch.setattr(generic, "agent_run_is_canceled", lambda _task_id: False)
    monkeypatch.setattr(
        generic,
        "get_user_by_username",
        lambda _username: {"id": 1, "is_admin": 1},
    )
    monkeypatch.setattr(generic, "get_agent_session", lambda _session_id: session)

    def update(state, message=None, **updates):
        state.update(updates)
        if message is not None:
            state["message"] = message
        snapshots.append(deepcopy(state))

    monkeypatch.setattr(generic, "_update_agent_state", update)
    return snapshots


def test_generic_task_has_stable_celery_name_and_exact_signature():
    celery = _FakeCelery()
    task = generic.register_agent_run_turn_task(celery)

    assert celery.options == [{"bind": True, "name": "oj.agent.run_turn"}]
    assert str(inspect.signature(task)) == (
        "(self, session_id, requested_by, access_role, harness, endpoint_id, "
        "session_cookie, prompt, session_cookie_name='session', "
        "resume_session_id='', generate_title=False, "
        "restore_runtime_checkpoint_id='')"
    )


def test_generic_outer_boundary_finalizes_trace_prepare_failure(monkeypatch):
    snapshots = _patch_generic(monkeypatch, None)
    monkeypatch.setattr(
        generic,
        "prepare_agent_trace_dir",
        lambda _task_id: (_ for _ in ()).throw(OSError("trace disk offline")),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self("trace-prepare-failed"),
        "trace-session",
        "admin",
        "admin",
        "pi",
        8,
        "session-cookie",
        "执行任务",
    )

    assert result["success"] is False
    assert "trace disk offline" in result["message"]
    assert snapshots[-1]["status"] == "Failed"
    assert snapshots[-1]["stage"] == "finished"
    assert snapshots[-1]["session_id"] == "trace-session"


def test_generic_outer_boundary_retries_failed_initial_state_write(monkeypatch):
    updates = []
    monkeypatch.setattr(
        generic,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(generic, "prepare_agent_trace_dir", lambda _task_id: None)
    monkeypatch.setattr(generic, "agent_run_is_canceled", lambda _task_id: False)

    def update(state, message=None, **values):
        updates.append((message, dict(values)))
        if len(updates) == 1:
            raise RuntimeError("transient mysql failure")
        state.update(values)
        if message is not None:
            state["message"] = message

    monkeypatch.setattr(generic, "_update_agent_state", update)

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self("initial-write-failed"),
        "write-session",
        "admin",
        "admin",
        "pi",
        8,
        "session-cookie",
        "执行任务",
    )

    assert result["success"] is False
    assert "transient mysql failure" in result["message"]
    assert len(updates) == 2
    assert updates[-1][1]["status"] == "Failed"


def test_generic_outer_boundary_finalizes_user_lookup_failure(monkeypatch):
    snapshots = _patch_generic(monkeypatch, None)
    monkeypatch.setattr(
        generic,
        "get_user_by_username",
        lambda _username: (_ for _ in ()).throw(RuntimeError("user db offline")),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self("user-lookup-failed"),
        "user-session",
        "admin",
        "admin",
        "pi",
        8,
        "session-cookie",
        "执行任务",
    )

    assert result["success"] is False
    assert "user db offline" in result["message"]
    assert snapshots[-1]["status"] == "Failed"


def test_generic_outer_boundary_finalizes_title_generation_failure(monkeypatch):
    task_id = "title-generation-failed"
    session = {
        "session_id": "title-session",
        "current_task_id": task_id,
        "title": "",
        "task_kind": "custom",
        "problem_id": None,
        "problem_title": None,
        "access_role": "admin",
        "harness": "pi",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": "",
        "turn_count": 1,
        "is_legacy": False,
    }
    snapshots = _patch_generic(monkeypatch, session)
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: _endpoint(),
    )
    monkeypatch.setattr(
        generic,
        "generate_initial_agent_session_title",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("title llm offline")
        ),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "title-session",
        "admin",
        "admin",
        "pi",
        8,
        "session-cookie",
        "执行任务",
        generate_title=True,
    )

    assert result["success"] is False
    assert "title llm offline" in result["message"]
    assert snapshots[-1]["status"] == "Failed"


def test_unhandled_failure_returns_existing_terminal_without_failed_write(
        monkeypatch):
    state = generic._initial_generic_state(
        "already-completed",
        session_id="terminal-session",
        requested_by="admin",
        access_role="admin",
        harness="pi",
        endpoint_id=8,
    )
    monkeypatch.setattr(
        generic,
        "existing_agent_terminal_result",
        lambda _task_id: {
            "success": True,
            "message": "已经完成",
            "task_id": "already-completed",
        },
    )
    monkeypatch.setattr(
        generic,
        "_update_agent_state",
        lambda *_args, **_kwargs: pytest.fail("已终态不得写入 Failed"),
    )

    result = generic._finalize_unhandled_generic_failure(
        state,
        RuntimeError("late exception"),
    )

    assert result["success"] is True
    assert result["message"] == "已经完成"
    assert result["session_id"] == "terminal-session"


def test_unhandled_failure_returns_cancellation_without_failed_write(monkeypatch):
    state = generic._initial_generic_state(
        "already-canceled",
        session_id="canceled-session",
        requested_by="admin",
        access_role="admin",
        harness="pi",
        endpoint_id=8,
    )
    monkeypatch.setattr(
        generic,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(generic, "agent_run_is_canceled", lambda _task_id: True)
    monkeypatch.setattr(
        generic,
        "_update_agent_state",
        lambda *_args, **_kwargs: pytest.fail("取消态不得写入 Failed"),
    )

    result = generic._finalize_unhandled_generic_failure(
        state,
        RuntimeError("late exception"),
    )

    assert result["canceled"] is True
    assert result["session_id"] == "canceled-session"


def test_unhandled_failure_falls_back_to_direct_session_projection(monkeypatch):
    from oj_modules.agents import sessions as agent_sessions

    projected = []
    state = generic._initial_generic_state(
        "persistent-run-write-failure",
        session_id="fallback-session",
        requested_by="admin",
        access_role="admin",
        harness="pi",
        endpoint_id=8,
    )
    monkeypatch.setattr(
        generic,
        "existing_agent_terminal_result",
        lambda _task_id: None,
    )
    monkeypatch.setattr(generic, "agent_run_is_canceled", lambda _task_id: False)
    monkeypatch.setattr(
        generic,
        "_update_agent_state",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("run table offline")
        ),
    )
    monkeypatch.setattr(
        agent_sessions,
        "sync_agent_session_state",
        lambda value: projected.append(deepcopy(value)) or True,
    )

    result = generic._finalize_unhandled_generic_failure(
        state,
        RuntimeError("unexpected startup failure"),
    )

    assert result["success"] is False
    assert projected[-1]["status"] == "Failed"
    assert projected[-1]["session_id"] == "fallback-session"
    assert projected[-1]["task_id"] == "persistent-run-write-failure"


def test_generic_first_turn_generates_title_on_frozen_endpoint_and_records_session(
        monkeypatch):
    task_id = "custom-first-turn"
    session = {
        "session_id": "custom-session",
        "current_task_id": task_id,
        "title": "",
        "task_kind": "custom",
        "problem_id": None,
        "problem_title": None,
        "access_role": "admin",
        "harness": "opencode",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": "",
        "turn_count": 1,
        "is_legacy": False,
    }
    snapshots = _patch_generic(monkeypatch, session)
    endpoint = _endpoint()
    title_calls = []
    harness_calls = []
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda harness, endpoint_id, **kwargs: (
            endpoint
            if (harness, endpoint_id, kwargs) == (
                "opencode", 8, {"include_secret": True},
            )
            else pytest.fail("端点解析参数不一致")
        ),
    )
    monkeypatch.setattr(
        generic,
        "generate_initial_agent_session_title",
        lambda session_id, selected_endpoint, prompt, **kwargs: (
            title_calls.append((session_id, selected_endpoint, prompt, kwargs))
            or "整理附件"
        ),
    )
    monkeypatch.setattr(
        generic,
        "extract_agent_conclusion",
        lambda _task_id: "附件已经整理完成。",
    )
    monkeypatch.setattr(
        generic,
        "run_agent_harness",
        lambda **kwargs: (
            harness_calls.append(kwargs)
            or HarnessRunResult(
                0,
                False,
                "",
                "",
                native_session_id="ses_MixedCase_19-Z",
            )
        ),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "custom-session",
        "admin",
        "admin",
        "opencode",
        8,
        "session-cookie",
        "请整理附件",
        "numoj_session",
        "",
        True,
    )

    assert result == {
        "success": True,
        "message": "Agent 已完成本轮任务",
        "task_id": task_id,
        "session_id": "custom-session",
        "title": "整理附件",
        "native_session_id": "ses_MixedCase_19-Z",
        "conclusion": "附件已经整理完成。",
    }
    assert len(title_calls) == 1
    assert title_calls[0][0] == "custom-session"
    assert title_calls[0][1] is endpoint
    assert title_calls[0][2] == "请整理附件"
    assert harness_calls[0]["session_id"] == "custom-session"
    assert harness_calls[0]["task_kind"] == "custom"
    assert harness_calls[0]["access_role"] == "admin"
    assert harness_calls[0]["resume_session_id"] == ""
    assert snapshots[-1]["status"] == "Completed"
    assert snapshots[-1]["native_session_id"] == "ses_MixedCase_19-Z"


def test_generic_resume_preserves_problem_task_scope_and_normalizes_uuid(
        monkeypatch):
    task_id = "solve-second-turn"
    frozen_native_id = "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    session = {
        "session_id": "solve-session",
        "current_task_id": task_id,
        "title": "解决矩阵题",
        "task_kind": "solve",
        "problem_id": 17,
        "problem_title": "矩阵题",
        "access_role": "user",
        "harness": "codex",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": frozen_native_id,
        "turn_count": 2,
        "is_legacy": False,
    }
    _patch_generic(monkeypatch, session)
    harness_calls = []
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: _endpoint(),
    )
    monkeypatch.setattr(
        generic,
        "generate_initial_agent_session_title",
        lambda *_args, **_kwargs: pytest.fail("续聊不得再次生成标题"),
    )
    monkeypatch.setattr(
        generic,
        "extract_agent_conclusion",
        lambda _task_id: "继续修复完成。",
    )
    monkeypatch.setattr(
        generic,
        "run_agent_harness",
        lambda **kwargs: (
            harness_calls.append(kwargs)
            or HarnessRunResult(
                0,
                False,
                "",
                "",
                native_session_id=frozen_native_id.lower(),
            )
        ),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "solve-session",
        "admin",
        "user",
        "codex",
        8,
        "session-cookie",
        "继续优化",
        "session",
        frozen_native_id.lower(),
        False,
    )

    assert result["success"] is True
    assert result["title"] == "解决矩阵题"
    assert harness_calls[0]["task_kind"] == "solve"
    assert harness_calls[0]["problem_id"] == 17
    assert harness_calls[0]["access_role"] == "user"
    assert harness_calls[0]["resume_session_id"] == frozen_native_id.lower()


def test_generic_resume_rejects_session_without_native_restore_point(monkeypatch):
    task_id = "failed-second-turn"
    session = {
        "session_id": "failed-session",
        "current_task_id": task_id,
        "title": "失败任务",
        "task_kind": "custom",
        "problem_id": None,
        "access_role": "user",
        "harness": "codex",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": "",
        "turn_count": 2,
        "is_legacy": False,
    }
    snapshots = _patch_generic(monkeypatch, session)
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: pytest.fail("无恢复点不得解析端点"),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "failed-session",
        "admin",
        "user",
        "codex",
        8,
        "session-cookie",
        "继续",
    )

    assert result["success"] is False
    assert "未记录可恢复" in result["message"]
    assert snapshots[-1]["status"] == "Failed"


def test_generic_retry_can_restore_first_turn_without_native_session(monkeypatch):
    task_id = "first-turn-retry"
    session = {
        "session_id": "retry-session",
        "current_task_id": task_id,
        "title": "重试任务",
        "task_kind": "custom",
        "problem_id": None,
        "problem_title": None,
        "access_role": "admin",
        "harness": "claude_code",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": "",
        # 物理尝试已经是第二轮，但 checkpoint 表示逻辑首轮的空会话基线。
        "turn_count": 2,
        "is_legacy": False,
    }
    _patch_generic(monkeypatch, session)
    endpoint = {**_endpoint(), "protocol": "anthropic"}
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: endpoint,
    )
    monkeypatch.setattr(
        generic,
        "extract_agent_conclusion",
        lambda _task_id: "已经从空会话重新完成。",
    )
    harness_calls = []
    monkeypatch.setattr(
        generic,
        "run_agent_harness",
        lambda **kwargs: (
            harness_calls.append(kwargs)
            or HarnessRunResult(
                0,
                False,
                "",
                "",
                native_session_id="11111111-1111-1111-1111-111111111111",
            )
        ),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "retry-session",
        "admin",
        "admin",
        "claude_code",
        8,
        "session-cookie",
        "重新执行首轮消息",
        "session",
        "",
        False,
        "empty-first-turn-checkpoint",
    )

    assert result["success"] is True
    assert harness_calls[0]["resume_session_id"] == ""
    assert (
        harness_calls[0]["restore_runtime_checkpoint_id"]
        == "empty-first-turn-checkpoint"
    )


def test_generic_cleanup_failure_stays_nonterminal(monkeypatch):
    task_id = "cleanup-first-turn"
    session = {
        "session_id": "cleanup-session",
        "current_task_id": task_id,
        "title": "清理任务",
        "task_kind": "custom",
        "problem_id": None,
        "access_role": "user",
        "harness": "codex",
        "endpoint_id": 8,
        "endpoint_revision": 4,
        "native_session_id": "",
        "turn_count": 1,
        "is_legacy": False,
    }
    snapshots = _patch_generic(monkeypatch, session)
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: _endpoint(),
    )
    monkeypatch.setattr(
        generic,
        "extract_agent_conclusion",
        lambda _task_id: "",
    )

    def fail_cleanup(**_kwargs):
        raise AgentHarnessCleanupError("容器清理状态未知")

    monkeypatch.setattr(generic, "run_agent_harness", fail_cleanup)

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "cleanup-session",
        "admin",
        "user",
        "codex",
        8,
        "session-cookie",
        "执行任务",
    )

    assert result["success"] is False
    assert snapshots[-1]["status"] == "CleanupFailed"
    assert snapshots[-1]["harness_status"] == "cleanup_failed"


def test_generic_rejects_changed_endpoint_revision_before_harness(monkeypatch):
    task_id = "revision-changed"
    session = {
        "session_id": "revision-session",
        "current_task_id": task_id,
        "title": "固定节点",
        "task_kind": "custom",
        "problem_id": None,
        "access_role": "user",
        "harness": "codex",
        "endpoint_id": 8,
        "endpoint_revision": 3,
        "native_session_id": "",
        "turn_count": 1,
        "is_legacy": False,
    }
    snapshots = _patch_generic(monkeypatch, session)
    monkeypatch.setattr(
        generic,
        "resolve_launch_endpoint",
        lambda *_args, **_kwargs: _endpoint(),
    )
    monkeypatch.setattr(
        generic,
        "run_agent_harness",
        lambda **_kwargs: pytest.fail("节点 revision 不同不得启动 harness"),
    )

    task = generic.register_agent_run_turn_task(_FakeCelery())
    result = task(
        _task_self(task_id),
        "revision-session",
        "admin",
        "user",
        "codex",
        8,
        "session-cookie",
        "执行任务",
    )

    assert result["success"] is False
    assert "配置已变化" in result["message"]
    assert snapshots[-1]["status"] == "Failed"
