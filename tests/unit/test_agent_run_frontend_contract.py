from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_agent_run_page_uses_generic_harness_log_details():
    template = _read("templates/agents/run.html")

    for stale_fragment in (
        'id="agentProgressText"',
        "state.max_rounds",
        "state.round",
        "request_body",
        "model_tool_call",
        "ai_tutor_feedback",
        "API 请求体",
        "工具调用 JSON",
    ):
        assert stale_fragment not in template

    assert "const isClickable = details !== null;" in template
    assert "if (details === null) return;" in template
    assert "点击查看日志详情" in template


def test_agent_task_list_does_not_render_react_rounds():
    template = _read("templates/admin/agent_tasks.html")

    assert "运行轮数" not in template
    assert "display_rounds" not in template
