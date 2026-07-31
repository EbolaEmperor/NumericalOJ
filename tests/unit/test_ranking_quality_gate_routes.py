from types import SimpleNamespace

from flask import Flask

from oj_modules.api import ranking_api
from oj_modules.api.ranking_api import _public_answer_endpoints, _safe_competition
from oj_modules.routes import ranking_routes as routes


def _app():
    app = Flask(__name__)
    app.secret_key = "test"
    return app


def test_quality_gate_readiness_uses_independent_pool(monkeypatch):
    comp = {
        "reverse_quality_gate_enabled": 1,
        "reverse_quality_gate_prompt": "不得隐藏私有协议",
    }
    monkeypatch.setattr(
        routes,
        "list_quality_gate_endpoints",
        lambda competition_id, enabled_only=False: ([{"id": 8}] if enabled_only else []),
    )

    assert routes._reverse_quality_gate_block_reason(5, comp) == ""

    monkeypatch.setattr(routes, "list_quality_gate_endpoints", lambda *args, **kwargs: [])
    assert "质量门禁端点" in routes._reverse_quality_gate_block_reason(5, comp)


def test_disabled_quality_gate_does_not_require_prompt_or_pool(monkeypatch):
    monkeypatch.setattr(
        routes,
        "list_quality_gate_endpoints",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("不应读取端点池")),
    )
    assert routes._reverse_quality_gate_block_reason(
        5,
        {"reverse_quality_gate_enabled": 0, "reverse_quality_gate_prompt": ""},
    ) == ""


def test_reverse_stream_timeout_covers_abort_retry_and_optional_gate():
    comp = {
        "scoring_script_timeout_seconds": 401,
        "agent_judge_timeout_seconds": 2201,
        "reverse_judge_finalize_timeout_seconds": 601,
        "reverse_quality_gate_enabled": True,
    }

    assert routes._reverse_judge_stream_timeout_seconds(comp) == (
        401 * 2
        + 2201 * 2
        + 601
        + routes.REVERSE_QUALITY_GATE_TIMEOUT_DEFAULT
        + routes.REVERSE_STREAM_TIMEOUT_BUFFER_SECONDS
    )

    comp["reverse_quality_gate_enabled"] = False
    assert routes._reverse_judge_stream_timeout_seconds(comp) == (
        401 * 2
        + 2201 * 2
        + 601
        + routes.REVERSE_STREAM_TIMEOUT_BUFFER_SECONDS
    )


def test_reverse_stream_timeout_never_drops_below_previous_one_hour_floor():
    assert routes._reverse_judge_stream_timeout_seconds({
        "scoring_script_timeout_seconds": 5,
        "agent_judge_timeout_seconds": 60,
        "reverse_judge_finalize_timeout_seconds": 30,
        "reverse_quality_gate_enabled": 0,
    }) == routes.REVERSE_STREAM_MIN_TIMEOUT_SECONDS


def test_quality_gate_partial_update_uses_atomic_merged_state_validation(monkeypatch):
    comp = {
        "id": 7,
        "scoring_mode": "reverse_judge",
        "reverse_quality_gate_enabled": 1,
        "reverse_quality_gate_prompt": "审核标准",
    }
    calls = []
    monkeypatch.setattr(routes, "_admin_json_guard", lambda: ({"is_admin": 1}, None))
    monkeypatch.setattr(routes, "get_competition", lambda competition_id: comp)
    def reject_invalid_merged_state(competition_id, **fields):
        calls.append((competition_id, fields))
        raise ValueError("启用质量门禁前必须配置至少一个启用端点")

    monkeypatch.setattr(
        routes,
        "save_reverse_quality_gate_configuration",
        reject_invalid_merged_state,
    )

    with _app().test_request_context(json={"endpoints": []}):
        response, status = routes.ranking_save_reverse_quality_gate(7)

    assert status == 400
    assert "至少一个启用端点" in response.get_json()["message"]
    assert calls == [(7, {"endpoints": []})]


def test_quality_gate_save_returns_masked_endpoints(monkeypatch):
    comp = {
        "id": 7,
        "scoring_mode": "reverse_judge",
        "reverse_quality_gate_enabled": 0,
        "reverse_quality_gate_prompt": "",
    }
    saved = []

    def save_configuration(competition_id, **fields):
        comp["reverse_quality_gate_enabled"] = 1 if fields.get("enabled") else 0
        comp["reverse_quality_gate_prompt"] = fields.get("prompt", "")
        endpoints = fields.get("endpoints", [])
        saved[:] = [{
            "id": 21,
            "harness": endpoints[0]["harness"],
            "base_url": endpoints[0]["base_url"],
            "api_key": "secret",
            "model": endpoints[0]["model"],
            "concurrency_limit": endpoints[0]["concurrency_limit"],
            "status": "enabled",
            "enabled": 1,
        }]

    monkeypatch.setattr(routes, "_admin_json_guard", lambda: ({"is_admin": 1}, None))
    monkeypatch.setattr(routes, "get_competition", lambda competition_id: comp)
    monkeypatch.setattr(
        routes,
        "list_quality_gate_endpoints",
        lambda competition_id, enabled_only=False: list(saved),
    )
    monkeypatch.setattr(
        routes,
        "save_reverse_quality_gate_configuration",
        save_configuration,
    )

    payload = {
        "enabled": True,
        "prompt": "不得隐藏私有协议",
        "endpoints": [{
            "harness": "codex",
            "base_url": "https://gate.example/v1",
            "api_key": "secret",
            "model": "gate-model",
            "concurrency_limit": 2,
            "status": "enabled",
        }],
    }
    with _app().test_request_context(json=payload):
        response = routes.ranking_save_reverse_quality_gate(7)

    data = response.get_json()
    assert data["success"] is True
    assert data["enabled"] is True
    assert data["enabled_count"] == 1
    assert data["total_concurrency"] == 2
    assert data["quality_gate_endpoints"][0]["has_key"] is True
    assert "api_key" not in data["quality_gate_endpoints"][0]


def test_quality_gate_prompt_has_20000_character_limit(monkeypatch):
    comp = {
        "id": 7,
        "scoring_mode": "reverse_judge",
        "reverse_quality_gate_enabled": 0,
        "reverse_quality_gate_prompt": "",
    }
    monkeypatch.setattr(routes, "_admin_json_guard", lambda: ({"is_admin": 1}, None))
    monkeypatch.setattr(routes, "get_competition", lambda competition_id: comp)
    monkeypatch.setattr(routes, "list_quality_gate_endpoints", lambda *args, **kwargs: [])

    with _app().test_request_context(json={"prompt": "x" * 20001}):
        response, status = routes.ranking_save_reverse_quality_gate(7)

    assert status == 400
    assert "20000" in response.get_json()["message"]


def test_public_ranking_api_never_exposes_quality_gate_configuration():
    comp = {
        "id": 3,
        "title": "反向评测",
        "answer_format": "json",
        "scoring_mode": "reverse_judge",
        "reverse_quality_gate_enabled": 1,
        "reverse_quality_gate_prompt": "private audit prompt",
        "agent_judge_api_key": "secret",
    }

    public = _safe_competition(comp, include_admin=False)
    admin = _safe_competition(comp, include_admin=True)

    assert "reverse_quality_gate_enabled" not in public
    assert "reverse_quality_gate_prompt" not in public
    assert admin["reverse_quality_gate_enabled"] == 1
    assert admin["reverse_quality_gate_prompt"] == "private audit prompt"
    assert "agent_judge_api_key" not in admin


def test_public_answer_endpoints_are_enabled_primary_pool_whitelist():
    endpoints = [
        {
            "id": 11,
            "pool_kind": "primary",
            "harness": "codex",
            "base_url": "https://answer.example/v1",
            "api_key": "answer-secret",
            "model": "answer-model",
            "concurrency_limit": 3,
            "status": "enabled",
        },
        {
            "id": 12,
            "pool_kind": "primary",
            "harness": "claude_code",
            "model": "paused-model",
            "status": "paused",
        },
        {
            "id": 13,
            "pool_kind": "quality_gate",
            "harness": "opencode",
            "model": "private-gate-model",
            "status": "enabled",
        },
        {
            "id": 14,
            "pool_kind": "primary",
            "harness": "pi",
            "model": "pi-answer-model",
            "status": "enabled",
        },
    ]

    assert _public_answer_endpoints(endpoints) == [
        {
            "id": 11,
            "harness": "codex",
            "model": "answer-model",
            "label": "Codex (answer-model)",
        },
        {
            "id": 14,
            "harness": "pi",
            "model": "pi-answer-model",
            "label": "Pi (pi-answer-model)",
        },
    ]


def test_public_competition_detail_exposes_safe_reverse_answer_endpoints(monkeypatch):
    comp = {
        "id": 3,
        "title": "反向评测",
        "description": "公开题面",
        "answer_format": "zip",
        "scoring_mode": "reverse_judge",
        "submission_method": "zip",
        "is_active": 1,
    }
    calls = []

    monkeypatch.setattr(
        ranking_api,
        "current_user",
        lambda: {"username": "student", "is_admin": 0},
    )
    monkeypatch.setattr(ranking_api, "get_competition", lambda competition_id: comp)
    monkeypatch.setattr(ranking_api, "list_competition_files", lambda competition_id: [])
    monkeypatch.setattr(ranking_api, "_agent_judge_endpoint_ready", lambda *args: True)
    monkeypatch.setattr(ranking_api, "_reverse_quality_gate_ready", lambda *args: True)
    monkeypatch.setattr(ranking_api, "_render_description", lambda text: text)

    def list_primary_endpoints(competition_id, enabled_only=False):
        calls.append((competition_id, enabled_only))
        return [{
            "id": 21,
            "competition_id": competition_id,
            "pool_kind": "primary",
            "harness": "claude_code",
            "base_url": "https://answer.example/v1",
            "api_key": "answer-secret",
            "model": "answer-model",
            "status": "enabled",
        }]

    monkeypatch.setattr(ranking_api, "list_agent_judge_endpoints", list_primary_endpoints)

    with _app().test_request_context("/api/ranking/competitions/3"):
        response = ranking_api.competition_detail(3)

    data = response.get_json()
    assert calls == [(3, True)]
    assert data["answer_endpoints"] == [{
        "id": 21,
        "harness": "claude_code",
        "model": "answer-model",
        "label": "Claude Code (answer-model)",
    }]
    serialized = response.get_data(as_text=True)
    assert "answer-secret" not in serialized
    assert "answer.example" not in serialized
    assert "quality_gate_endpoints" not in data


class _AsyncTask:
    def __init__(self, task_id):
        self.task_id = task_id
        self.calls = []

    def apply_async(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(id=self.task_id)


def test_single_rejudge_dispatches_reverse_task_and_atomically_clears_reverse_steps(monkeypatch):
    reverse_task = _AsyncTask("reverse-task-1")
    attempts = []
    saved_task_ids = []
    monkeypatch.setattr(routes, "_require_admin", lambda: ({"is_admin": 1}, None))
    monkeypatch.setattr(
        routes,
        "get_ranking_submission",
        lambda submission_id: {"id": submission_id, "competition_id": 7, "username": "u1"},
    )
    monkeypatch.setattr(
        routes, "get_competition", lambda competition_id: {"id": 7, "scoring_mode": "reverse_judge"},
    )
    monkeypatch.setattr(
        routes,
        "begin_agent_judge_attempt",
        lambda sid, **kwargs: attempts.append((sid, kwargs)) or "attempt-r1",
    )
    monkeypatch.setattr(
        routes,
        "set_agent_judge_task_id",
        lambda sid, attempt_id, task_id: saved_task_ids.append((sid, attempt_id, task_id)),
    )
    monkeypatch.setattr(routes, "_reverse_judge_task", reverse_task)

    with _app().test_request_context(headers={"Accept": "application/json"}):
        response = routes.ranking_rejudge_agent(7, 31)

    assert response.get_json()["success"] is True
    assert attempts == [(31, {
        "status": "Queued",
        "reset_result": True,
        "clear_reverse_steps": True,
    })]
    assert reverse_task.calls == [{"args": [31, "attempt-r1"]}]
    assert saved_task_ids == [(31, "attempt-r1", "reverse-task-1")]


def test_single_rejudge_preserves_agent_judge_dispatch(monkeypatch):
    agent_task = _AsyncTask("agent-task-1")
    attempts = []
    monkeypatch.setattr(routes, "_require_admin", lambda: ({"is_admin": 1}, None))
    monkeypatch.setattr(
        routes,
        "get_ranking_submission",
        lambda submission_id: {"id": submission_id, "competition_id": 7, "username": "u1"},
    )
    monkeypatch.setattr(
        routes, "get_competition", lambda competition_id: {"id": 7, "scoring_mode": "agent_judge"},
    )
    monkeypatch.setattr(
        routes,
        "begin_agent_judge_attempt",
        lambda sid, **kwargs: attempts.append((sid, kwargs)) or "attempt-a1",
    )
    monkeypatch.setattr(routes, "set_agent_judge_task_id", lambda *args: None)
    monkeypatch.setattr(routes, "_agent_judge_task", agent_task)

    with _app().test_request_context(headers={"Accept": "application/json"}):
        response = routes.ranking_rejudge_agent(7, 32)

    assert response.get_json()["success"] is True
    assert attempts == [(32, {
        "status": "Queued",
        "reset_result": True,
        "clear_agent_results": True,
    })]
    assert agent_task.calls == [{"args": [32, "attempt-a1"]}]


def _private_gate_snapshot():
    return {
        "submission_id": 41,
        "status": "Finished",
        "error_message": "质量门禁未通过：命中私有规则 sesame",
        "steps": [{
            "step_key": "quality_gate",
            "status": "failed",
            "result": {
                "passed": False,
                "verdict": "reject",
                "summary": "命中私有规则：不得使用暗号",
                "criteria_sha256": "private-criteria-hash",
                "reviewed_file_count": 4,
                "violations": [{
                    "rule": "不得使用暗号",
                    "reason": "发现私有暗号 sesame",
                    "evidence": [{
                        "path": "judge.sh",
                        "line": 7,
                        "excerpt": "私有标准要求禁止 sesame",
                    }],
                }],
            },
            "stdout": "private gate stdout",
            "stderr": "private gate stderr",
            "trace_files": [{"path": "private.jsonl", "content": "不得使用暗号"}],
            "trace_messages": [{"text": "private criteria"}],
            "error_message": "质量门禁未通过：不得使用暗号 sesame",
        }],
    }


def test_reverse_stream_projects_private_gate_result_for_submission_owner(monkeypatch):
    snapshot = _private_gate_snapshot()
    monkeypatch.setattr(routes, "_require_user", lambda: ({"username": "u1", "is_admin": 0}, None))
    monkeypatch.setattr(
        routes,
        "get_ranking_submission",
        lambda submission_id: {"id": submission_id, "competition_id": 7, "username": "u1"},
    )
    monkeypatch.setattr(routes, "get_competition", lambda competition_id: {"id": competition_id})
    monkeypatch.setattr(routes, "get_reverse_judge_progress_snapshot", lambda sid: snapshot)

    with _app().test_request_context():
        response = routes.ranking_reverse_judge_stream(7, 41)
        body = response.get_data(as_text=True)

    assert "题目未通过质量门禁" in body
    assert "private-criteria-hash" not in body
    assert "不得使用暗号" not in body
    assert "sesame" not in body
    assert "private gate stdout" not in body
    assert "private criteria" not in body
    assert "criteria_sha256" not in body
    assert '"rule"' not in body


def test_reverse_stream_keeps_gate_internals_for_admin(monkeypatch):
    snapshot = _private_gate_snapshot()
    monkeypatch.setattr(
        routes, "_require_user", lambda: ({"username": "admin", "is_admin": 1}, None),
    )
    monkeypatch.setattr(
        routes,
        "get_ranking_submission",
        lambda submission_id: {"id": submission_id, "competition_id": 7, "username": "u1"},
    )
    monkeypatch.setattr(routes, "get_competition", lambda competition_id: {"id": competition_id})
    monkeypatch.setattr(routes, "get_reverse_judge_progress_snapshot", lambda sid: snapshot)

    with _app().test_request_context():
        response = routes.ranking_reverse_judge_stream(7, 41)
        body = response.get_data(as_text=True)

    assert "private-criteria-hash" in body
    assert "不得使用暗号" in body
    assert "private gate stdout" in body


def test_reverse_snapshot_projects_historical_quality_gate_as_skipped():
    projected = routes._project_reverse_judge_snapshot({
        "submission_id": 51,
        "status": "Accepted",
        "steps": [{
            "step_key": "quality_gate",
            "status": "skipped",
            "result": {
                "skipped": True,
                "summary": "历史评测未执行质量门禁",
            },
        }],
    })

    gate = projected["steps"][0]["result"]
    assert gate == {
        "passed": None,
        "verdict": "skipped",
        "summary": "本次评测未执行质量门禁",
        "violations": [],
    }
