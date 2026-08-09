from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _read(relative_path):
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _css_rule(styles, selector):
    start = styles.index(selector)
    body_start = styles.index("{", start) + 1
    body_end = styles.index("}", body_start)
    return styles[body_start:body_end]


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


def test_agent_home_runtime_choices_are_compact_and_share_one_mobile_row():
    template = _read("templates/admin/agent_tasks.html")
    styles = _read("static/app/agents/task-list.css")

    for modifier in ("harness", "endpoint", "role"):
        assert f"agent-composer-choice--{modifier}" in template

    assert ".agent-composer-choice--harness { width: 124px; }" in styles
    assert ".agent-composer-choice--endpoint { width: 170px; }" in styles
    assert ".agent-composer-choice--role { width: 126px; }" in styles

    tablet = styles.split("@media (max-width: 900px)", 1)[1].split(
        "@media (max-width: 575.98px)", 1
    )[0]
    assert "flex-wrap: wrap;" not in tablet
    assert "flex: 1 1 30%;" not in tablet

    compact = styles.split("@media (max-width: 640px)", 1)[1].split(
        "@media (max-width: 575.98px)", 1
    )[0]
    assert (
        "grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.3fr) "
        "minmax(0, 0.95fr);"
    ) in compact
    assert "grid-column: 1 / -1; grid-row: 1;" not in compact
    assert "max-width: calc(100vw - 32px);" in compact

    endpoint_menu = _css_rule(
        compact,
        ".agent-choice--endpoint .rk-choice-menu {",
    )
    assert "left: 50%;" in endpoint_menu
    assert "transform: translateX(-50%);" in endpoint_menu

    role_menu = _css_rule(compact, ".agent-choice--role .rk-choice-menu {")
    assert "right: 0;" in role_menu
    assert "left: auto;" in role_menu

    mobile = styles.split("@media (max-width: 575.98px)", 1)[1].split(
        "@media (prefers-reduced-motion: reduce)", 1
    )[0]
    assert ".agent-choice .rk-choice-caret { display: none; }" in mobile


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


def test_agent_detail_header_shows_requester_avatar_and_session_token_usage():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    header_start = template.index('<header class="agent-session-header">')
    header_end = template.index("</header>", header_start)
    header = template[header_start:header_end]
    assert "agent-session-runtime" not in header
    assert "harness_logo(" not in header
    assert "agent_session.endpoint_model" not in header
    assert 'class="numoj-avatar agent-session-avatar"' in header
    assert 'data-agent-session-avatar' in header
    assert 'data-avatar-seed="{{ agent_session.requested_by }}"' in header
    assert 'data-avatar-label="{{ agent_session.requested_by }}"' in header
    assert 'aria-label="发起者：{{ agent_session.requested_by }}"' in header
    for field in ("input", "cached", "output", "cost"):
        assert f"data-agent-usage-{field}" in header
    assert "会话累计 Token 用量" in header
    assert "缓存输入占比" in header

    composer_start = template.index('<footer class="agent-resume-dock">')
    composer_end = template.index("</footer>", composer_start)
    composer = template[composer_start:composer_end]
    assert "harness_logo(agent_session.harness)" in composer
    assert "agent_session.endpoint_model" in composer

    assert "querySelectorAll('[data-agent-session-avatar]')" in controller
    assert "identicon.paint(avatar, identicon.cellsForSeed(seed), label)" in controller
    assert "function formatMeasuredValue(value)" in controller
    assert "function formatTokenCount(tokens)" in controller
    assert "function renderHeaderTokenUsage(usage)" in controller
    assert "state.session_token_usage" in controller
    assert "Number(usage.input_total_tokens)" in controller
    assert "Number(usage.input_cached_tokens)" in controller
    assert "Number(usage.output_tokens)" in controller
    assert "usage.cost_rmb" in controller
    assert "if (tokens < 10000)" in controller
    assert "formatMeasuredValue(tokens / 1000) + ' K'" in controller
    assert "formatMeasuredValue(tokens / 1000000) + ' M'" in controller
    assert "Math.min(100, cachedTokens / inputTokens * 100)" in controller
    assert "setUsageValue(usageCached, cachedPercent.toFixed(2) + '%');" in controller
    assert "formatMeasuredValue(Number(usage.cost_rmb)) + ' RMB'" in controller
    assert "renderHeaderTokenUsage(state.session_token_usage);" in controller
    assert "renderHeaderTokenUsage(null);" not in controller
    assert (
        "renderHeaderTokenUsage(currentState && currentState.session_token_usage);"
        in controller
    )

    assert "container-name: agent-conversation;" in styles
    assert "@container agent-conversation" in styles
    assert ".agent-session .agent-session-avatar" in styles
    assert ".agent-session-usage-fact dd" in styles
    assert "font-variant-numeric: tabular-nums;" in styles
    assert ".agent-session-usage-fact--cost { display: none; }" not in styles
    assert ".agent-session-usage-fact--cached { display: none; }" not in styles
    assert ".agent-session-usage { display: none; }" not in styles
    desktop_preview = styles.split("@media (min-width: 992px)", 1)[1]
    assert ".agent-session.has-file .agent-session-header-side" in desktop_preview
    assert "display: none;" in desktop_preview


def test_agent_detail_supports_resume_stop_and_live_state_without_interruption():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    assert "data-agent-resume-form" in template
    assert "data-agent-resume-file" in template
    assert "data-agent-resume-send" in template
    assert "data-agent-stop" in template
    assert "data-agent-retry-last" in template
    assert "data-agent-expected-task-id" in template
    assert 'aria-label="重试上一条消息"' in template
    assert "fa-redo-alt" in template
    assert "data-status-url-template" in template
    assert "data-stream-url-template" in template
    assert "data-cancel-url-template" in template
    assert "new global.EventSource" in controller
    assert "addEventListener('status'" in controller
    assert "addEventListener('done'" in controller
    assert "startPolling(taskId, generation)" in controller
    assert "taskId !== currentTaskId || generation !== liveGeneration" in controller
    assert "resumeSend.disabled = running || blocked" in controller
    assert "error.detailUrl = asText(payload && payload.detail_url).trim();" in controller
    assert "global.location.assign(error.detailUrl);" in controller
    assert "cleanupfailed" in controller
    assert "清理失败，需管理员处理" in template
    assert "data-can-resume" in template
    assert "|| !canResume" in controller
    assert "body.append('retry_last', '1');" in controller
    assert "body.append('expected_task_id', expectedTaskId);" in controller
    assert "payload.replaced_task_id || options.expectedTaskId" in controller
    assert "removeTurnByTaskId" in controller
    message_row_start = template.index('class="agent-user-message-row"')
    retry_index = template.index('class="agent-message-retry"', message_row_start)
    bubble_index = template.index('class="agent-user-bubble', message_row_start)
    assert retry_index < bubble_index
    assert "messageRow.append(createRetryButton(taskId), bubble);" in controller
    assert "messageRow.append(bubble, createRetryButton(taskId));" not in controller
    assert ".agent-message-retry" in styles
    retry_rule = _css_rule(styles, ".agent-message-retry {")
    assert "width: 24px;" in retry_rule
    assert "height: 24px;" in retry_rule
    assert "background: transparent;" in retry_rule


def test_agent_detail_keeps_file_preview_and_workspace_accessible():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    assert 'role="tree"' not in template
    assert "details.setAttribute('role', 'treeitem')" not in controller
    assert "filePane.setAttribute('aria-modal', 'true')" in controller
    assert "var wasFilePaneHidden = filePane.hidden;" in controller
    assert "if (wasFilePaneHidden) initializeFileLayout();" in controller
    assert "minmax(300px, 4.5fr)" in styles
    assert "event.key === 'Escape'" in controller
    assert "filePreviewReturnFocus.focus()" in controller
    assert "trapMobileFilePreviewFocus" in controller
    assert "statusChip.setAttribute('aria-label', item.label)" in controller
    assert "clip: rect(0, 0, 0, 0)" in styles


def test_agent_markdown_code_stays_compact_and_scrollable_in_narrow_panes():
    template = _read("templates/admin/agent_task_detail.html")
    styles = _read("static/app/agents/conversation.css")

    assert template.index("app/markdown-rendering.css") < template.index(
        "app/agents/conversation.css"
    )

    frame_rule = _css_rule(
        styles,
        ".agent-session .numoj-markdown .codehilite {",
    )
    assert "max-width: 100%;" in frame_rule
    assert "overflow: hidden;" in frame_rule
    assert "border-radius: 6px;" in frame_rule

    pre_rule = _css_rule(styles, ".agent-session .numoj-markdown pre {")
    for declaration in (
        "box-sizing: border-box;",
        "max-width: 100%;",
        "overflow-x: auto;",
        "white-space: pre;",
        "overflow-wrap: normal;",
        "word-break: normal;",
        "border-radius: 6px;",
    ):
        assert declaration in pre_rule

    inline_code_rule = _css_rule(styles, ".agent-session .numoj-markdown code {")
    assert "border-radius: 3px;" in inline_code_rule
    assert "overflow-wrap: anywhere;" in inline_code_rule

    copy_rule = _css_rule(
        styles,
        ".agent-session .numoj-markdown .numoj-code-copy {",
    )
    assert "width: 30px;" in copy_rule
    assert "height: 30px;" in copy_rule
    assert "border-radius: 5px;" in copy_rule
    assert "box-shadow: none;" in copy_rule

    assert "padding: 38px clamp(16px, 5%, 50px) 28px;" in styles
    assert (
        "padding: clamp(22px, 5%, 42px) clamp(18px, 7%, 42px) 42px;"
        in styles
    )
    assert "padding-right: 44px;" in styles


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
    dispatch_start = controller.index("function dispatchAgentTurn(options)")
    archive_index = controller.index("archiveLiveResponse();", dispatch_start)
    append_index = controller.index("appendOptimisticUserMessage(", archive_index)
    assert archive_index < append_index
    assert "function resetLiveResponse()" in controller
    assert "details.append(summary, trace)" in controller


def test_agent_detail_only_consumes_server_html_for_rich_trace_kinds():
    controller = _read("static/app/agents/conversation.js")

    assert "function isRichTraceKind(kind)" in controller
    assert "kind === 'assistant' || kind === 'thinking' || kind === 'reasoning'" in controller
    assert "if (html && isRichTraceKind(kind))" in controller
    assert "setServerHtml(element, conclusion.html)" in controller


def test_agent_thinking_markdown_uses_compact_paragraph_spacing():
    styles = _read("static/app/agents/conversation.css")

    markdown_rule = _css_rule(
        styles,
        ".agent-trace-event--thinking .agent-trace-copy.numoj-markdown {",
    )
    paragraph_rule = _css_rule(
        styles,
        ".agent-trace-event--thinking .agent-trace-copy > p {",
    )
    last_paragraph_rule = _css_rule(
        styles,
        ".agent-trace-event--thinking .agent-trace-copy > p:last-child {",
    )

    assert "white-space: normal;" in markdown_rule
    assert "margin: 0 0 .45em;" in paragraph_rule
    assert "margin-bottom: 0;" in last_paragraph_rule


def test_agent_workspace_preview_covers_required_formats_and_safe_downloads():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")
    editor_runtime = _read("static/app/code-editor-runtime.js")

    assert "problem_core.admin_agent_workspace_tree" in template
    assert "problem_core.admin_agent_workspace_file" in template
    assert "raw: 1" in controller
    assert "download: 1" in controller
    assert "renderCode" in controller
    assert "preview_kind" in controller
    assert 'download data-agent-file-download' in template
    assert "download.download = name;" in controller
    assert "agent-file-markdown" in controller
    assert "agent-file-pdf" in controller
    assert "imageViewer" in controller
    assert "agent-file-text" in controller
    assert "无法预览的文件格式" in controller
    assert "context: 'agent-workspace'" in controller
    assert "documentId: function (model)" in controller
    assert "readOnly: true" in controller
    assert "domReadOnly: true" in controller

    render_code = controller.split("async function renderCode", 1)[1].split(
        "function imageViewer", 1
    )[0]
    assert "fontSize: 12.5," in render_code
    assert "lineHeight: 20," in render_code

    conclusion_rule = _css_rule(styles, ".agent-conclusion {")
    assert "font-size: 12.5px;" in conclusion_rule
    block_code_rule = _css_rule(
        styles,
        ".agent-session .numoj-markdown pre code {",
    )
    assert "font-size: inherit;" in block_code_rule
    assert "fontSize: 14," in editor_runtime
    assert "lineHeight: 22," in editor_runtime


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
