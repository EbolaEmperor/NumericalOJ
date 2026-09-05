"""Judge 复用通用 Agent 的权限、持久投递和 workspace 契约。"""

from types import SimpleNamespace

from flask import Flask
import pytest

from backend.oj_modules.agents import judge, sessions, workspace
from backend.oj_modules.routes import problem_core_routes as routes
from tests.unit.test_agent_sessions import _ScriptedConnection


def _session(kind="reverse_answer", **extra):
    return {
        "session_id": "jd-test", "current_task_id": "jd-test-turn",
        "task_kind": "judge", "judge_kind": kind, "requested_by": "owner",
        "submission_id": 12, "attempt_id": "attempt-1", "competition_id": 3,
        "endpoint_id": 8, "harness": "pi", "access_role": "user",
        "turn_count": 1, "status": "Completed", **extra,
    }


@pytest.mark.parametrize("kind", ["agent_judge", "reverse_quality", "reverse_answer"])
@pytest.mark.parametrize("username,is_admin", [("owner", False), ("other", False), ("admin", True)])
def test_judge_view_policy_applies_to_direct_workspace_url(monkeypatch, kind, username, is_admin):
    user = {"id": 1, "username": username, "is_admin": int(is_admin)}
    monkeypatch.setattr(routes, "current_user", lambda: user)
    monkeypatch.setattr(routes, "get_agent_session", lambda _: _session(kind))
    monkeypatch.setattr(routes, "build_agent_workspace_tree", lambda _: [])
    app = Flask(__name__)
    app.register_blueprint(routes.problem_core_bp)
    response = app.test_client().get("/api/agent/sessions/jd-test/workspace")
    allowed = is_admin or (username == "owner" and kind == "reverse_answer")
    assert response.status_code == (200 if allowed else 403)
    assert sessions.can_view_agent_session(_session(kind), username=username, is_admin=is_admin) == allowed


@pytest.mark.parametrize("username,is_admin", [("owner", False), ("admin", True)])
@pytest.mark.parametrize("path,method", [
    ("/api/agent/sessions/jd-test", "post"),
    ("/agent/tasks/jd-test", "post"),
    ("/api/agent/sessions/jd-test/messages/msg/update", "post"),
    ("/api/agent/sessions/jd-test/messages/msg/delete", "post"),
    ("/api/agent/sessions/jd-test/messages/msg/send-now", "post"),
    ("/api/agent/sessions/jd-test/queue/resume", "post"),
    ("/api/agent/sessions/jd-test/queue/reorder", "post"),
    ("/api/agent/sessions/jd-test/title", "patch"),
    ("/agent/runs/jd-test-turn/cancel", "post"),
])
def test_judge_human_mutations_are_forbidden_even_to_admin(monkeypatch, username, is_admin, path, method):
    monkeypatch.setattr(routes, "current_user", lambda: {"id": 1, "username": username, "is_admin": int(is_admin)})
    monkeypatch.setattr(routes, "get_agent_session", lambda _: _session())
    monkeypatch.setattr(routes, "get_agent_session_by_task_id", lambda _: _session())
    app = Flask(__name__)
    app.register_blueprint(routes.problem_core_bp)
    response = getattr(app.test_client(), method)(path, json={"retry_last": 1, "delivery_mode": "steer"})
    assert response.status_code == 403


def test_judge_list_scope_requires_admin(monkeypatch):
    monkeypatch.setattr(routes, "current_user", lambda: {"id": 1, "username": "owner", "is_admin": 0})
    app = Flask(__name__)
    app.register_blueprint(routes.problem_core_bp)
    assert app.test_client().get("/api/agent/sessions?scope=judge").status_code == 403


@pytest.mark.parametrize("judge_only", [False, True])
def test_session_lists_exclude_or_select_judge_explicitly(monkeypatch, judge_only):
    conn = _ScriptedConnection(one_values=[{"total": 0}])
    monkeypatch.setattr(sessions, "get_db_connection", lambda: conn)
    sessions.get_agent_sessions_paginated(judge_only=judge_only)
    sql = conn.cursor_instance.calls[-1][0]
    assert ("s.task_kind='judge'" if judge_only else "s.task_kind<>'judge'") in sql
    if judge_only:
        assert "WHERE 1=0 AND NOT EXISTS" in sql


def test_internal_continuation_is_only_writer_of_judge_turns(monkeypatch):
    for internal in (False, True):
        conn = _ScriptedConnection(one_values=[_session()])
        monkeypatch.setattr(sessions, "get_db_connection", lambda: conn)
        if internal:
            sessions.begin_agent_session_turn("jd-test", task_id="next", user_message="下一条规则", internal_judge=True)
            assert conn.commits == 1
        else:
            with pytest.raises(PermissionError):
                sessions.begin_agent_session_turn("jd-test", task_id="next", user_message="人工消息")
            assert conn.rollbacks == 1


def test_internal_submit_replay_never_rewrites_workspace_or_creates_turn(monkeypatch):
    conn = _ScriptedConnection(one_values=[{"acquired": 1}])
    monkeypatch.setattr(judge, "get_db_connection", lambda: conn)
    monkeypatch.setattr(judge, "get_agent_session", lambda _: _session())
    monkeypatch.setattr(judge, "get_agent_session_turns", lambda _: [{"task_id": "jd-test-turn", "user_message": "执行"}])
    monkeypatch.setattr(judge, "inject_agent_workspace_files", lambda *_: pytest.fail("重复投递不能写 workspace"))
    monkeypatch.setattr(judge, "begin_agent_session_turn", lambda *_args, **_kwargs: pytest.fail("重复投递不能创建轮次"))
    calls = []
    result = judge.submit_judge_turn(
        session_id="jd-test", task_id="jd-test-turn", requested_by="owner",
        judge_kind="reverse_answer", submission_id=12, attempt_id="attempt-1",
        competition_id=3, harness="pi", endpoint={"id": 8}, prompt="执行",
        files={"problem.md": "重复材料"}, celery_app=SimpleNamespace(send_task=lambda *args, **kw: calls.append((args, kw))),
    )
    assert result["current_task_id"] == "jd-test-turn"
    assert calls[0][0] == ("oj.agent.dispatch_session_queue",)
    assert calls[0][1]["queue"] == "celery"
    assert conn.closed


def test_judge_input_and_output_are_independent_copies(monkeypatch, tmp_path):
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", tmp_path / "workspaces")
    source = tmp_path / "original.txt"
    source.write_text("original")
    workspace.inject_agent_workspace_files("jd-files", {"template/answer.txt": source})
    target = workspace.get_existing_agent_workspace_path("jd-files") / "template/answer.txt"
    target.write_text("answer")
    destination = tmp_path / "result"
    workspace.export_agent_workspace_directory("jd-files", "template", destination)
    assert source.read_text() == "original"
    assert (destination / "answer.txt").read_text() == "answer"
    target.write_text("late change")
    assert (destination / "answer.txt").read_text() == "answer"


def test_judge_workspace_export_rejects_links(monkeypatch, tmp_path):
    monkeypatch.setattr(workspace, "AGENT_WORKSPACE_ROOT", tmp_path / "workspaces")
    workspace.inject_agent_workspace_files("jd-links", {"result/normal": b"safe"})
    root = workspace.get_existing_agent_workspace_path("jd-links")
    (root / "result/escape").symlink_to(tmp_path)
    with pytest.raises(workspace.AgentWorkspaceSecurityError):
        workspace.export_agent_workspace_directory("jd-links", "result", tmp_path / "export")
    with pytest.raises(workspace.AgentWorkspacePathError):
        workspace.inject_agent_workspace_files("jd-links", {"../escape": "no"})


def test_judge_endpoint_uses_private_pool_and_its_explicit_price(monkeypatch):
    monkeypatch.setattr(judge, "get_agent_session_runtime_config", lambda _: {"endpoint_source": "competition"})
    private = {
        "id": 8, "harness": "pi", "effective_protocol": "openai",
        "base_url": "https://private.example/v1", "api_key": "secret", "model": "private",
        "input_price_per_million": "3", "cached_input_price_per_million": "1",
        "output_price_per_million": "9",
    }
    monkeypatch.setattr(judge, "list_quality_gate_endpoints", lambda _: [private])
    monkeypatch.setattr(judge, "list_llm_endpoints", lambda **_: [])
    endpoint = judge.resolve_judge_endpoint(_session("reverse_quality"))
    price = judge.judge_endpoint_pricing(endpoint)
    assert price["endpoint_id"] is None
    assert price["pricing"]["output_price_per_million"] == "9"
    assert endpoint["api_key"] == "secret"
    assert "secret" not in str(price)
