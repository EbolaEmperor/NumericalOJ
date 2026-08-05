import json
from pathlib import Path
import shutil
import subprocess

from jinja2 import Environment, nodes
import pytest


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _called_template_macros(relative_path):
    parsed = Environment().parse(_read(relative_path))
    return {
        node.node.name
        for node in parsed.find_all(nodes.Call)
        if isinstance(node.node, nodes.Name)
    }


def test_agent_tasks_and_ranking_submissions_share_one_card_shell():
    shared = _read("templates/components/execution_record_card.html")
    ranking = _read("templates/ranking/components/submission_card.html")
    agent = _read("templates/agents/task_card.html")
    task_list = _read("templates/admin/agent_tasks.html")

    assert "data-execution-record-card" in shared
    assert "render_execution_record_card" in _called_template_macros(
        "templates/ranking/components/submission_card.html"
    )
    assert "render_execution_record_card" in _called_template_macros(
        "templates/agents/task_card.html"
    )
    assert "app/ranking/content-v2.css" in task_list
    assert "ranking-v2-detail" in task_list
    assert "<table" not in task_list


def test_agent_task_card_links_the_latest_submission_and_preserves_detail_hook():
    card = _read("templates/agents/task_card.html")
    task_list = _read("templates/admin/agent_tasks.html")
    navigation = _read("templates/components/layout/navigation.html")

    assert "run.latest_submission_id" in card
    assert "submission.submission_detail" in card
    assert "harness_logo(run.harness)" in card
    assert "run.endpoint_model" in card
    assert "app/ranking/harness-logos.css" in task_list
    assert "fa-fingerprint" not in card
    assert "task_id[:8]" not in card
    assert 'data-avatar-seed="{{ run.requested_by or \'numericaloj\' }}"' in card
    assert 'data-avatar-seed="{{ user.username }}"' in navigation
    assert 'data-avatar-seed="{{ run.display_problem_title }}"' not in card
    assert "data-agent-task-detail" in card
    assert 'data-task-id="{{ task_id }}"' in card


def test_agent_run_detail_is_a_shared_trace_modal_on_the_task_list():
    task_list = _read("templates/admin/agent_tasks.html")
    task_card = _read("templates/agents/task_card.html")
    modal = _read("templates/agents/run_detail_modal.html")
    controller = _read("static/app/agents/run-detail-modal.js")
    styles = _read("static/app/agents/run-detail-modal.css")

    assert not (ROOT / "templates/agents/run.html").exists()
    assert task_list.count("{% include 'agents/run_detail_modal.html' %}") == 1
    assert "data-agent-task-detail" in task_card
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
    assert "activeSource.addEventListener('timeout'" not in controller
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


def test_agent_run_modal_cancels_active_tasks_with_inline_confirmation():
    modal = _read("templates/agents/run_detail_modal.html")
    controller = _read("static/app/agents/run-detail-modal.js")
    styles = _read("static/app/agents/run-detail-modal.css")

    assert "data-cancel-url-template" in modal
    assert "data-agent-task-cancel" in modal
    assert "return key === 'pending' || key === 'running'" in controller
    assert "cancelButtonEl.dataset.confirming = '1'" in controller
    assert "再次点击确认" in controller
    assert "method: 'POST'" in controller
    assert "applyState(state, taskId, generation)" in controller
    assert "error.agentState = payload && payload.state" in controller
    assert "window.confirm" not in controller
    assert ".agent-task-cancel-button" in styles


def test_agent_run_modal_preserves_terminal_state_from_failed_cancel_response():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    controller = _read("static/app/agents/run-detail-modal.js")
    helper = controller.split("// CANCEL_RESPONSE_HELPER_START", 1)[1].split(
        "// CANCEL_RESPONSE_HELPER_END",
        1,
    )[0]
    script = helper + r"""
try {
  parseCancelResponse(
    {ok: false, status: 500},
    {
      success: false,
      message: '任务已标记为终止，但运行时清理失败',
      state: {status: 'Canceled', task_id: 'task-1'}
    }
  );
} catch (error) {
  process.stdout.write(JSON.stringify({
    message: error.message,
    state: error.agentState
  }));
}
"""

    result = subprocess.run(
        [node, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "message": "任务已标记为终止，但运行时清理失败",
        "state": {"status": "Canceled", "task_id": "task-1"},
    }


def test_agent_task_list_does_not_render_react_rounds():
    template = _read("templates/admin/agent_tasks.html")

    assert "运行轮数" not in template
    assert "display_rounds" not in template
