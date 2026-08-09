from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_agent_home_uses_a_dedicated_conversation_composer_and_history():
    template = _read("templates/admin/agent_tasks.html")
    controller = _read("static/app/agents/task-list.js")
    styles = _read("static/app/agents/task-list.css")

    assert "data-agent-create-form" in template
    assert 'enctype="multipart/form-data"' in template
    for field in ("message", "attachments", "harness", "endpoint_id", "access_role"):
        assert f"'{field}'" in template or f'name="{field}"' in template
    assert "choice_picker(" in template
    assert "data-agent-harnesses-json" in template
    assert "data-agent-endpoints-json" in template
    assert "data-agent-preference-json" in template
    assert "data-agent-task-list" in template
    assert "agent-history-row" in template
    assert "harness_logo(session.harness)" in template
    assert "session.endpoint_model" in template
    assert "data-avatar-seed" in template
    assert "agents/run_detail_modal.html" not in template
    assert "ranking-v2-detail" not in template
    assert "app/ranking/content-v2.css" not in template
    assert "new FormData(form)" in controller
    assert "payload.detail_url" in controller
    assert ".numoj-content.container-fluid.agent-home-shell" in styles
    assert ".agent-composer" in styles
    assert ".agent-history-row" in styles


def test_agent_detail_is_a_standalone_conversation_and_workspace_page():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    assert "data-agent-session" in template
    assert "data-agent-conversation-scroll" in template
    assert "data-agent-file-pane" in template
    assert "data-agent-workspace" in template
    assert 'data-agent-splitter="conversation"' in template
    assert 'data-agent-splitter="workspace"' in template
    assert 'role="separator"' in template
    assert "components/editor/monaco.html" in template
    assert "app/markdown-rendering.js" in template
    assert "app/agents/conversation.js" in template
    assert "components/agents/execution_trace_assets.html" not in template
    assert "AgentExecutionTrace" not in controller
    assert ".numoj-content.container-fluid.agent-session-shell" in styles
    assert ".agent-session.has-file" in styles
    assert "4.5fr" in styles
    assert "agent-file-image-stage" in styles


def test_agent_detail_supports_resume_stop_and_live_state_without_interruption():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    assert "data-agent-resume-form" in template
    assert "data-agent-resume-file" in template
    assert "data-agent-resume-send" in template
    assert "data-agent-stop" in template
    assert "data-status-url-template" in template
    assert "data-stream-url-template" in template
    assert "data-cancel-url-template" in template
    assert "new global.EventSource" in controller
    assert "addEventListener('status'" in controller
    assert "addEventListener('done'" in controller
    assert "startPolling(taskId, generation)" in controller
    assert "taskId !== currentTaskId || generation !== liveGeneration" in controller
    assert "resumeSend.disabled = running || blocked" in controller
    assert "cleanupfailed" in controller
    assert "清理失败，需管理员处理" in template
    assert "data-can-resume" in template
    assert "|| !canResume" in controller


def test_agent_detail_keeps_file_preview_and_workspace_accessible():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    assert 'role="tree"' not in template
    assert "details.setAttribute('role', 'treeitem')" not in controller
    assert "filePane.setAttribute('aria-modal', 'true')" in controller
    assert "event.key === 'Escape'" in controller
    assert "filePreviewReturnFocus.focus()" in controller
    assert "trapMobileFilePreviewFocus" in controller
    assert "statusChip.setAttribute('aria-label', item.label)" in controller
    assert "clip: rect(0, 0, 0, 0)" in styles


def test_agent_trace_prefers_server_normalized_titles():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    assert "message.title|default(message.name" in template
    assert "message.title || message.name || message.tool_name" in controller
    assert "message.title || message.name || '子 Agent'" in controller
    assert "message.title|default('工具执行失败' if result_error else '工具结果'" in template
    assert "message.is_error === true" in controller
    assert "resultError ? 'error' : 'result'" in controller
    assert "resultError ? '工具执行失败' : '工具结果'" in controller


def test_agent_detail_archives_each_live_response_before_starting_the_next_turn():
    controller = _read("static/app/agents/conversation.js")

    assert "function archiveLiveResponse()" in controller
    assert "target.appendChild(historicalResponse(currentState))" in controller
    assert "target.dataset.agentResponseArchived = 'true'" in controller
    assert "archiveLiveResponse();\n        appendOptimisticUserMessage(" in controller
    assert "function resetLiveResponse()" in controller
    assert "details.append(summary, trace)" in controller


def test_agent_detail_only_consumes_server_html_for_rich_trace_kinds():
    controller = _read("static/app/agents/conversation.js")

    assert "function isRichTraceKind(kind)" in controller
    assert "kind === 'assistant' || kind === 'thinking' || kind === 'reasoning'" in controller
    assert "if (html && isRichTraceKind(kind))" in controller
    assert "setServerHtml(element, conclusion.html)" in controller


def test_agent_workspace_preview_covers_required_formats_and_safe_downloads():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    assert "problem_core.admin_agent_workspace_tree" in template
    assert "problem_core.admin_agent_workspace_file" in template
    assert "raw: 1" in controller
    assert "download: 1" in controller
    assert "renderCode" in controller
    assert "preview_kind" in controller
    assert "agent-file-markdown" in controller
    assert "agent-file-pdf" in controller
    assert "imageViewer" in controller
    assert "agent-file-text" in controller
    assert "无法预览的文件格式" in controller
    assert "context: 'agent-workspace'" in controller
    assert "documentId: function (model)" in controller
    assert "readOnly: true" in controller
    assert "domReadOnly: true" in controller


def test_agent_frontend_javascript_has_valid_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    for relative_path in (
        "static/app/agents/task-list.js",
        "static/app/agents/conversation.js",
        "static/app/code-editor-runtime.js",
    ):
        subprocess.run(
            [node, "--check", str(ROOT / relative_path)],
            check=True,
            capture_output=True,
            text=True,
        )
