from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_agent_run_detail_is_a_shared_trace_modal_on_the_task_list():
    task_list = _read("templates/admin/agent_tasks.html")
    modal = _read("templates/agents/run_detail_modal.html")
    controller = _read("static/app/agents/run-detail-modal.js")
    styles = _read("static/app/agents/run-detail-modal.css")

    assert not (ROOT / "templates/agents/run.html").exists()
    assert task_list.count("{% include 'agents/run_detail_modal.html' %}") == 1
    assert "data-agent-task-detail" in task_list
    assert "problem_core.admin_agent_tasks" in task_list

    shared_trace = "{% include 'components/agents/execution_trace_assets.html' %}"
    assert modal.count(shared_trace) == 1
    assert "app/agents/run-detail-modal.css" in modal
    assert "app/agents/run-detail-modal.js" in modal
    assert len(modal.splitlines()) <= 100
    assert "<style>" not in modal
    assert "(function () {" not in modal
    assert "window.AgentExecutionTrace.create" in controller
    assert ".agent-task-modal-content" in styles
    assert "data-agent-task-modal" in modal
    assert "data-agent-task-trace" in modal
    assert "activeSource.addEventListener('status'" in controller
    assert "activeSource.addEventListener('done'" in controller
    assert "activeSource.addEventListener('timeout'" in controller
    assert "startPolling(taskId, generation)" in controller
    assert "generation !== liveGeneration" in controller
    assert "source === activeSource" in controller


def test_agent_run_modal_consumes_only_the_canonical_execution_trace():
    controller = _read("static/app/agents/run-detail-modal.js")

    assert "state.execution_trace" in controller
    assert "renderer.render(traceRoot, trace" in controller
    assert "scope: expectedTaskId" in controller
    assert "source: String(trace.trace_id || expectedTaskId)" in controller
    assert "state.events" not in controller
    assert "function executionTrace(" not in controller
    assert "function eventDetails(" not in controller
    assert "function eventTitle(" not in controller
    assert "agent-task-events" not in controller


def test_agent_run_modal_displays_usage_and_only_reveals_configured_cost():
    modal = _read("templates/agents/run_detail_modal.html")
    controller = _read("static/app/agents/run-detail-modal.js")

    assert modal.index("data-agent-task-input") < modal.index("BEST SCORE")
    assert modal.index("data-agent-task-input") < modal.index("data-agent-task-cached")
    assert modal.index("data-agent-task-cached") < modal.index("data-agent-task-output")
    assert modal.index("data-agent-task-output") < modal.index("BEST SCORE")
    assert "data-agent-task-updated" not in modal
    assert "data-agent-task-updated" not in controller
    assert 'data-agent-task-cost-fact hidden' in modal
    assert "trace.token_usage" in controller
    assert "cachedEl.textContent = cachedPercent.toFixed(2) + '%'" in controller
    assert "tokens < 10000" in controller
    assert "tokens / 1000" in controller
    assert "tokens / 1000000" in controller
    assert "value >= 1 ? value.toFixed(2) : value.toPrecision(2)" in controller
    assert "costFactEl.hidden = !hasCost" in controller


def test_agent_run_modal_only_links_a_terminal_final_submission():
    modal = _read("templates/agents/run_detail_modal.html")
    controller = _read("static/app/agents/run-detail-modal.js")

    assert "data-agent-task-final-link" in modal
    assert "var finalId = Number(state.final_submission_id || 0);" in controller
    assert "var finalUrl = finished ? submissionUrl(finalId) : '';" in controller
    assert "latest_submission_id" not in controller
    assert "agentSubmissionFrame" not in modal + controller


def test_agent_task_list_does_not_render_react_rounds():
    template = _read("templates/admin/agent_tasks.html")

    assert "运行轮数" not in template
    assert "display_rounds" not in template
