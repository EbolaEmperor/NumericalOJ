from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_agent_run_detail_is_a_shared_trace_modal_on_the_task_list():
    task_list = _read("templates/admin/agent_tasks.html")
    modal = _read("templates/agents/run_detail_modal.html")

    assert not (ROOT / "templates/agents/run.html").exists()
    assert task_list.count("{% include 'agents/run_detail_modal.html' %}") == 1
    assert "data-agent-task-detail" in task_list
    assert "problem_core.admin_agent_tasks" in task_list

    shared_trace = "{% include 'ranking/scripts/execution_trace.html' %}"
    assert modal.count(shared_trace) == 1
    assert "window.AgentExecutionTrace.create" in modal
    assert "data-agent-task-modal" in modal
    assert "data-agent-task-trace" in modal
    assert "activeSource.addEventListener('status'" in modal
    assert "activeSource.addEventListener('done'" in modal
    assert "activeSource.addEventListener('timeout'" in modal
    assert "startPolling(taskId, generation)" in modal
    assert "generation !== liveGeneration" in modal
    assert "source === activeSource" in modal


def test_agent_run_modal_only_links_a_terminal_final_submission():
    modal = _read("templates/agents/run_detail_modal.html")

    assert "data-agent-task-final-link" in modal
    assert "var finalId = Number(state.final_submission_id || 0);" in modal
    assert "var finalUrl = finished ? submissionUrl(finalId) : '';" in modal
    assert "latest_submission_id" not in modal
    assert "agentSubmissionFrame" not in modal


def test_agent_task_list_does_not_render_react_rounds():
    template = _read("templates/admin/agent_tasks.html")

    assert "运行轮数" not in template
    assert "display_rounds" not in template
