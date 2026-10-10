"""FaithSieve workflow 与站内 Judge 使用同一套运行参数校验。"""

from flask import Flask
import pytest

from backend.oj_modules.problems import agent_launch
from backend.oj_modules.routes import grading_routes


@pytest.fixture
def launch_runtime(monkeypatch):
    endpoint = {
        "id": 7, "category": "omni", "protocol": "openai",
        "model": "qwen-text", "api_key_configured": True,
        "input_price_per_million": "1",
        "cached_input_price_per_million": "0.1",
        "output_price_per_million": "2",
    }
    monkeypatch.setattr(agent_launch, "get_llm_endpoint", lambda *_args, **_kwargs: endpoint)
    saved = []
    monkeypatch.setattr(
        grading_routes, "save_agent_launch_preference",
        lambda *args: saved.append(args),
    )
    return Flask(__name__), endpoint, saved


def test_workflow_preserves_selected_harness_and_model(launch_runtime):
    app, _endpoint, saved = launch_runtime
    with app.test_request_context("/", method="POST", json={"harness": "pi", "endpoint_id": 7}):
        assert grading_routes._faithsieve_runtime({"id": 17}) == ("pi", 7, "workflow")
    assert saved == [(17, "pi", 7)]


def test_workflow_normalizes_existing_harness_alias(launch_runtime):
    app, endpoint, saved = launch_runtime
    endpoint["protocol"] = "anthropic"
    with app.test_request_context("/", method="POST", json={"harness": "claude-code", "endpoint_id": "7"}):
        assert grading_routes._faithsieve_runtime({"id": 17}) == ("claude_code", 7, "workflow")
    assert saved == [(17, "claude_code", 7)]


@pytest.mark.parametrize(
    "change, harness, message",
    [
        ({"protocol": "openai"}, "claude_code", "协议不兼容"),
        ({"api_key_configured": False}, "pi", "API Key"),
        ({"output_price_per_million": None}, "pi", "完整价格"),
        ({"category": "text"}, "pi", "图像核对需要全模态"),
        ({"category": "vision"}, "pi", "协议不兼容"),
    ],
)
def test_workflow_rejects_unusable_judge_endpoint(launch_runtime, change, harness, message):
    app, endpoint, saved = launch_runtime
    endpoint.update(change)
    with app.test_request_context("/", method="POST", json={"harness": harness, "endpoint_id": 7}):
        with pytest.raises(agent_launch.AgentLaunchValidationError, match=message):
            grading_routes._faithsieve_runtime({"id": 17})
    assert saved == []


@pytest.mark.parametrize("endpoint_id", [True, 7.0, "7.0", "user:7"])
def test_workflow_rejects_invalid_or_personal_endpoint_reference(launch_runtime, endpoint_id):
    app, _endpoint, saved = launch_runtime
    with app.test_request_context("/", method="POST", json={"harness": "pi", "endpoint_id": endpoint_id}):
        with pytest.raises(agent_launch.AgentLaunchValidationError):
            grading_routes._faithsieve_runtime({"id": 17})
    assert saved == []


@pytest.mark.parametrize("mode", ["workflow", "skill"])
def test_launch_freezes_requested_execution_mode(launch_runtime, mode):
    app, _endpoint, saved = launch_runtime
    with app.test_request_context("/", method="POST", json={"harness": "pi", "endpoint_id": 7, "execution_mode": mode}):
        assert grading_routes._faithsieve_runtime({"id": 17}) == ("pi", 7, mode)
    assert saved == [(17, "pi", 7)]


@pytest.mark.parametrize("mode", ["", "agent", False, [], {}])
def test_launch_rejects_invalid_execution_mode_before_saving_preference(launch_runtime, mode):
    app, _endpoint, saved = launch_runtime
    with app.test_request_context("/", method="POST", json={"harness": "pi", "endpoint_id": 7, "execution_mode": mode}):
        with pytest.raises(agent_launch.AgentLaunchValidationError):
            grading_routes._faithsieve_runtime({"id": 17})
    assert saved == []


@pytest.mark.parametrize("mode", ["workflow", "skill"])
@pytest.mark.parametrize("batch", [False, True])
def test_http_launch_passes_mode_to_durable_queue(monkeypatch, launch_runtime, mode, batch):
    app, _endpoint, _saved = launch_runtime
    app.register_blueprint(grading_routes.grading_bp)
    problem = {"id": 7, "type": 2, "written_grading_mode": 4}
    submission = {"id": 12, "problem_id": 7, "problem_type": 2}
    monkeypatch.setattr(grading_routes, "current_user", lambda: {"id": 17, "username": "admin", "is_admin": 1})
    monkeypatch.setattr(grading_routes, "get_problem", lambda _pid: problem)
    monkeypatch.setattr(grading_routes, "get_submission_by_id", lambda _sid: submission)
    monkeypatch.setattr(grading_routes, "latest_submissions_for_problem", lambda _pid: [submission])
    calls = []

    def queue(submissions, **options):
        calls.append((submissions, options))
        return [{"attempt_id": "a" * 32, "submission_id": 12}], []

    class Task:
        def apply_async(self, **_options):
            return type("Result", (), {"id": "queued-task"})()

    monkeypatch.setattr(grading_routes, "queue_runs", queue)
    monkeypatch.setattr(grading_routes, "_faithsieve_grading_task", Task())
    monkeypatch.setattr(grading_routes, "set_run_task_id", lambda *_args: None)
    path = "/api/admin/problems/7/faithsieve" if batch else "/api/admin/submissions/12/faithsieve"
    response = app.test_client().post(path, json={"harness": "pi", "endpoint_id": 7, "execution_mode": mode})
    assert response.status_code == 200
    assert response.get_json()["queued"] == 1
    assert calls == [([submission], {"requested_by": "admin", "harness": "pi", "endpoint_id": 7, "execution_mode": mode})]
