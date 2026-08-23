from pathlib import Path
import shutil
import subprocess

from jinja2 import Environment
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
    for field in (
        "message",
        "attachments",
        "harness",
        "endpoint_id",
        "reasoning_effort",
        "access_role",
    ):
        assert f"'{field}'" in template or f'name="{field}"' in template
    assert "choice_picker(" in template
    assert "data-agent-harnesses-json" in template
    assert "data-agent-endpoints-json" in template
    assert "data-agent-launch-options-url" in template
    assert "data-agent-reasoning-efforts-json" in template
    assert "data-agent-preference-json" in template
    assert "data-agent-task-list" in template
    assert "agent-history-row" in template
    assert "harness_logo(session.harness)" in template
    assert "session.endpoint_model" in template
    assert "data-avatar-seed" in template
    assert "new FormData(form)" in controller
    assert "payload.detail_url" in controller
    assert 'aria-keyshortcuts="Enter Shift+Enter Control+Enter Meta+Enter"' in template
    assert "event.key !== 'Enter' || event.isComposing || event.keyCode === 229" in controller
    assert "if (event.shiftKey) return;" in controller
    assert "if (submit.disabled) return;" in controller
    assert "form.requestSubmit(submit)" in controller
    assert "refreshEndpointCatalog" in controller
    assert "cache: 'no-store'" in controller
    assert "endpointsByHarness = endpointCatalog(payload.endpoints_by_harness)" in controller
    assert ".numoj-content.container-fluid.agent-home-shell" in styles
    assert ".agent-composer" in styles
    assert ".agent-history-row" in styles


def test_agent_home_runtime_choices_fit_content_and_share_one_mobile_row():
    template = _read("templates/admin/agent_tasks.html")
    styles = _read("static/app/agents/task-list.css")

    for modifier in ("harness", "endpoint", "effort", "role"):
        assert f"agent-composer-choice--{modifier}" in template

    assert template.index("agent-composer-choice--endpoint") < template.index(
        "agent-composer-choice--effort"
    ) < template.index("agent-composer-choice--role")

    assert "width: fit-content;" in styles
    assert ".agent-composer-choice--harness { max-width: 150px; }" in styles
    assert ".agent-composer-choice--endpoint { max-width: 260px; }" in styles
    assert ".agent-composer-choice--effort { max-width: 108px; }" in styles
    assert ".agent-composer-choice--role { max-width: 160px; }" in styles

    harness_menu = _css_rule(styles, ".agent-choice .rk-choice-menu {")
    endpoint_menu = _css_rule(styles, ".agent-choice--endpoint .rk-choice-menu {")
    effort_menu = _css_rule(styles, ".agent-choice--effort .rk-choice-menu {")
    role_menu = _css_rule(styles, ".agent-choice--role .rk-choice-menu {")
    assert "width: 230px;" in harness_menu
    assert "width: 290px;" in endpoint_menu
    assert "width: 184px;" in effort_menu
    assert "width: 280px;" in role_menu

    tablet = styles.split("@media (max-width: 900px)", 1)[1].split(
        "@media (max-width: 575.98px)", 1
    )[0]

    compact = styles.split("@media (max-width: 640px)", 1)[1].split(
        "@media (max-width: 575.98px)", 1
    )[0]
    footer_mobile = _css_rule(compact, ".agent-composer-footer {")
    controls_mobile = _css_rule(compact, ".agent-composer-controls {")
    choice_mobile = _css_rule(compact, ".agent-composer-choice {")
    actions_mobile = _css_rule(compact, ".agent-composer-actions {")
    assert "display: flex;" in footer_mobile
    assert "justify-content: flex-start;" in footer_mobile
    assert "flex-wrap: nowrap;" in footer_mobile
    assert "flex: 1 1 0;" in controls_mobile
    assert "flex-wrap: nowrap;" in controls_mobile
    assert "gap: 5px;" in controls_mobile
    assert "flex: 0 1 auto;" in choice_mobile
    assert "width: auto;" in choice_mobile
    assert "margin-left: auto;" in actions_mobile
    assert "flex-wrap: nowrap;" in actions_mobile
    assert "white-space: nowrap;" in actions_mobile
    assert "max-width: calc(100vw - 32px);" in compact

    endpoint_mobile_menu = _css_rule(
        compact,
        ".agent-choice--endpoint .rk-choice-menu {",
    )
    assert "left: 50%;" in endpoint_mobile_menu
    assert "transform: translateX(-50%);" in endpoint_mobile_menu

    effort_mobile_menu = _css_rule(
        compact,
        ".agent-choice--effort .rk-choice-menu {",
    )
    assert "left: 50%;" in effort_mobile_menu
    assert "transform: translateX(-50%);" in effort_mobile_menu

    role_mobile_menu = _css_rule(compact, ".agent-choice--role .rk-choice-menu {")
    assert "right: 0;" in role_mobile_menu
    assert "left: auto;" in role_mobile_menu

    mobile = styles.split("@media (max-width: 575.98px)", 1)[1].split(
        "@media (prefers-reduced-motion: reduce)", 1
    )[0]
    assert ".agent-choice .rk-choice-caret { display: none; }" in mobile


def test_agent_home_prioritizes_personal_endpoints_and_marks_them_as_self_paid():
    controller = _read("static/app/agents/task-list.js")
    styles = _read("static/app/agents/task-list.css")

    assert "Number(right.isPersonal) - Number(left.isPersonal)" in controller
    assert "endpointPaidBadge.textContent = '自费'" in controller
    assert "badge.textContent = '自费'" in controller
    assert "option.classList.add('is-personal-endpoint')" in controller
    assert "endpointChoice.classList.toggle('is-personal-endpoint', isPersonal)" in controller
    assert "endpoint.model + (isPersonal ? '，自费' : '')" in controller
    assert ".agent-endpoint-paid-badge" in styles
    assert ".agent-choice--endpoint .rk-choice-option.is-personal-endpoint" in styles


def test_agent_home_marks_current_peak_or_offpeak_prices_with_a_colored_dot():
    controller = _read("static/app/agents/task-list.js")
    styles = _read("static/app/agents/task-list.css")

    assert "peakPricingEnabled: item.peak_pricing_enabled === true" in controller
    assert "pricingPeriod: asText(item.pricing_period)" in controller
    assert "agent-endpoint-pricing-period" in controller
    assert "高峰期" in controller and "低谷期" in controller
    assert ".agent-endpoint-pricing-period > i" in styles
    assert '[data-pricing-period="peak"] > i' in styles


def test_agent_home_reasoning_effort_is_dynamic_and_part_of_submission_identity():
    template = _read("templates/admin/agent_tasks.html")
    controller = _read("static/app/agents/task-list.js")
    styles = _read("static/app/agents/task-list.css")

    assert "data-agent-reasoning-effort-choice" in template
    assert "reasoning_efforts_by_harness" in template
    assert "'agentReasoningEffort', 'reasoning_effort', 'high'" in template
    assert "not reasoning_effort_options" in template
    assert "['pi', 'claude_code'].forEach" in controller
    assert "rawReasoningEfforts" in controller
    assert "normalizeReasoningEffort" in controller
    assert "reasoningEffortWrapper.hidden = efforts.length === 0" in controller
    assert "global.ChoicePicker.configure(" in controller
    assert "reasoningEffortController.setDisabled(" in controller
    assert "selectedReasoningEffort()," in controller
    assert "agent-effort-logo agent-effort-logo--choice" in template
    assert "agent-effort-logo agent-effort-logo--choice" in controller
    assert "reasoning-depth.svg" in styles
    assert ".agent-composer-choice[hidden] { display: none; }" in styles




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
    assert ".numoj-content.container-fluid.agent-session-shell" in styles
    assert ".agent-session.has-file" in styles
    assert "消息已" + "加入队列" not in controller
    assert "4.5fr" in styles
    assert "agent-file-image-stage" in styles


def test_agent_detail_header_shows_requester_avatar_and_session_token_usage():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")
    routes = _read("oj_modules/routes/problem_core_routes.py")

    header_start = template.index('<header class="agent-session-header">')
    header_end = template.index("</header>", header_start)
    header = template[header_start:header_end]
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
    assert "agent_session.reasoning_effort" in template
    assert "reasoning_effort_label" in composer
    assert "data-agent-reasoning-effort" in composer
    assert "agent-resume-effort" in composer
    assert "agent-effort-logo" in composer
    assert "data-agent-context-meter" in composer
    assert "data-agent-context-value" in composer
    assert 'role="tooltip"' in composer
    assert 'aria-describedby="agentContextTooltip"' in composer
    meter_start = composer.index('class="agent-context-meter"')
    meter_end = composer.index("</button>", meter_start)
    model_start = composer.index('class="agent-resume-model"')
    effort_start = composer.index('class="agent-resume-effort"')
    effort_end = composer.index("</span>", effort_start)
    assert model_start < effort_start < meter_start
    effort = composer[effort_start:effort_end]
    assert "agent_context_window_tokens=int(" in routes
    assert "DEFAULT_LLM_CONTEXT_WINDOW_TOKENS" in routes

    assert "querySelectorAll('[data-agent-session-avatar]')" in controller
    assert "identicon.paint(avatar, identicon.cellsForSeed(seed), label)" in controller
    assert "function formatMeasuredValue(value)" in controller
    assert "function formatTokenCount(tokens)" in controller
    assert "function formatMoneyValue(value)" in controller
    assert "function renderHeaderTokenUsage(usage)" in controller
    assert "state.session_token_usage" in controller
    assert "Number(usage.input_total_tokens)" in controller
    assert "Number(usage.input_cached_tokens)" in controller
    assert "Number(usage.output_tokens)" in controller
    assert "usage.cost_rmb" in controller
    assert "if (tokens < 1000)" in controller
    assert "formatMeasuredValue(tokens / 1000) + ' K'" in controller
    assert "formatMeasuredValue(tokens / 1000000) + ' M'" in controller
    assert "formatMeasuredValue(tokens / 1000000000000) + ' T'" in controller
    assert "cached_fallback_request_count" in controller
    assert "90% 的默认命中率来计费" in controller
    assert "Math.min(100, cachedTokens / inputTokens * 100)" in controller
    assert "setUsageValue(usageCached, cachedPercent.toFixed(2) + '%');" in controller
    assert "formatMoneyValue(usage.cost_rmb) + ' 元'" in controller
    assert "usesPersonalEndpoint ? '用户自费' : '—'" in controller
    assert "'用户自费' if uses_personal_endpoint else '—'" in template
    assert "renderHeaderTokenUsage(state.session_token_usage);" in controller
    assert "function renderContextUsage(contextUsage)" in controller
    assert "Math.round(tokens / 1000) + 'k'" in controller
    assert "Math.min(100, Math.max(0, usedTokens / windowTokens * 100))" in controller
    assert "renderContextUsage(state.context_usage);" in controller
    assert "renderContextUsage(currentState && currentState.context_usage);" in controller
    assert (
        "renderHeaderTokenUsage(currentState && currentState.session_token_usage);"
        in controller
    )

    assert "container-name: agent-conversation;" in styles
    assert "@container agent-conversation" in styles
    assert ".agent-session .agent-session-avatar" in styles
    assert ".agent-session-usage-fact dd" in styles
    assert "font-variant-numeric: tabular-nums;" in styles
    requester_label_rule = _css_rule(
        styles, ".agent-session-requester-copy small {"
    )
    assert "font: 550 7px/1.35 var(--agent-mono);" in requester_label_rule
    assert ".agent-context-meter-value" in styles
    assert ".agent-context-tooltip" in styles
    assert ".agent-context-meter:hover .agent-context-tooltip" in styles
    assert ".agent-context-meter:focus-visible .agent-context-tooltip" in styles
    assert ".agent-resume-runtime > .agent-resume-effort" in styles
    runtime_icon = _css_rule(styles, ".agent-resume-runtime > span > i {")
    assert "display: inline-flex;" in runtime_icon
    assert "align-items: center;" in runtime_icon
    assert "justify-content: center;" in runtime_icon
    effort_icon = _css_rule(styles, ".agent-effort-logo {")
    assert "width: 10px;" in effort_icon
    assert "height: 10px;" in effort_icon
    assert "flex: 0 0 10px;" in effort_icon
    mobile = styles.split("@media (max-width: 575.98px)", 1)[1].split(
        "@media (hover: none)", 1
    )[0]
    mobile_footer = _css_rule(mobile, ".agent-resume-footer {")
    assert "flex-wrap: wrap;" in mobile_footer
    mobile_runtime = _css_rule(mobile, ".agent-resume-runtime {")
    assert "flex: 1 1 170px;" in mobile_runtime
    assert ".agent-resume-actions { margin-left: auto; }" in mobile
    assert (
        ".agent-resume-composer.is-running .agent-resume-runtime { flex-basis: 100%; }"
        in mobile
    )
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
    assert "resumeSend.disabled = blocked || resumePending" in controller
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
    assert ".agent-message-retry" in styles
    retry_rule = _css_rule(styles, ".agent-message-retry {")
    assert "width: 24px;" in retry_rule
    assert "height: 24px;" in retry_rule
    assert "background: transparent;" in retry_rule


def test_agent_detail_live_refreshes_do_not_overlap_or_poll_beside_healthy_sse():
    controller = _read("static/app/agents/conversation.js")

    assert "if (workspaceFetchPending) return workspaceFetchPending;" in controller
    assert "if (workspaceFetchPending) {" in controller
    assert "if (normalizedDelay === 0) workspaceFinalRefreshPending = true;" in controller
    assert "if (workspaceFetchPending === request) workspaceFetchPending = null;" in controller
    assert "messageStreamHealthy = true;" in controller
    assert "stopMessageStatePolling();" in controller
    poll_finally = controller.split(
        "refreshMessageState().catch(function () {}).finally(function () {", 1
    )[1].split("});", 1)[0]
    assert "if (!messageStream || !messageStreamHealthy)" in poll_finally


def test_agent_detail_falls_back_when_task_stream_has_no_first_payload():
    controller = _read("static/app/agents/conversation.js")

    assert "var streamFirstPayloadTimer = null;" in controller
    assert "function clearStreamFirstPayloadTimer()" in controller
    assert "function stopTaskPolling()" in controller
    assert "var receivedPayload = false;" in controller
    assert "markStreamPayloadReceived()" in controller
    assert "streamFirstPayloadTimer = global.setTimeout(function ()" in controller
    assert "receivedPayload || !isCurrent(taskId, generation, activeStream)" in controller
    assert "activeStream.close();" in controller
    assert "startPolling(taskId, generation);" in controller
    assert "}, 2000);" in controller
    assert "clearStreamFirstPayloadTimer();\n    stopTaskPolling();" in controller


def test_agent_detail_fetches_each_work_block_only_on_first_expand():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    assert "data-agent-lazy-trace" not in template
    assert "data-agent-lazy-trace-body" not in template
    assert "turn.has_detail|default(false)" in template
    assert "data-work-block-url-template" in template
    assert "data-agent-work-block" in template
    assert "function loadWorkBlock(details)" in controller
    assert "var workBlockCache = new Map();" in controller
    assert "workBlockCache.set(workBlockCacheKey(taskId, blockId), fold);" in controller
    assert "details.dataset.agentWorkBlockLoaded === 'true'" in controller
    assert "details.dataset.agentWorkBlockLoaded = 'true';" in controller
    assert "if (fold.open) loadWorkBlock(fold);" in controller
    assert "function bindTurnDetails(scope)" in controller
    assert "syncTurnDetailState(details)" in controller
    assert "function loadHistoricalTrace(details)" not in controller


def test_agent_detail_uses_one_running_action_for_stop_or_queue_send():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    for contract in (
        "data-session-state-url",
        "data-session-stream-url",
        "data-queue-update-url-template",
        "data-queue-delete-url-template",
        "data-queue-send-now-url-template",
        "data-queue-resume-url",
        "data-agent-message-state-json",
    ):
        assert contract in template
    assert "data-agent-queue-panel" in template
    assert "data-agent-queue-list" in template
    assert "data-agent-queue-resume" in template
    assert '{% if is_running %}hidden{% endif %}' in template
    assert 'aria-label="停止任务" title="停止任务"' in template

    assert "var computedDeliveryMode = submitIntent === 'steer'" in controller
    assert "((running || queuePaused || queuedMessages(messageState).length) ? 'queue' : 'turn')" in controller
    assert "body.set('delivery_mode', deliveryMode)" in controller
    assert "resumeSend.hidden = running && (!hasMessage || stopPending);" in controller
    assert "stopButton.hidden = !running || (hasMessage && !stopPending);" in controller
    assert "安排下一条消息…" in controller
    assert "function renderMessageQueue(state)" in controller
    assert "function renderSteerMessages(state)" in controller
    assert "if (result.sessionState) applyMessageState(result.sessionState);" in controller
    assert "message.target_task_id || message.final_task_id || message.task_id" in controller
    assert "=== currentTaskId" in controller
    assert (
        "turn.steer_messages and not (is_running and turn.task_id == current_task_id)"
        in template
    )
    assert "function sendQueueMessageNow(item, message)" in controller
    assert "body.append('expected_task_id', currentTaskId)" in controller
    assert "data-agent-queue-send-now" in controller
    assert "'fas fa-paper-plane', '立刻发送'" in controller
    assert "function queueEditor(item, message)" in controller
    assert "body.append('remove_attachment', path)" in controller
    assert "function persistQueueOrder(messageIds)" not in controller
    assert "function moveQueueMessage(messageId, direction)" not in controller
    assert "function sentSteerMessages(state, taskId)" in controller
    assert "function userTimelineMessage(message, extraClass)" in controller
    assert "messageKind(message) === 'user'" in controller
    assert "agent-trace-event--before-steer" not in controller
    assert "new global.EventSource(endpoint)" in controller
    assert "transitionToTask(taskId, state)" in controller
    assert 'aria-keyshortcuts="Enter Shift+Enter Control+Enter Meta+Enter"' in template
    assert "event.key !== 'Enter' || event.isComposing || event.keyCode === 229" in controller
    assert "if (event.shiftKey) return;" in controller
    assert "var wantsSteer = running && (event.metaKey || event.ctrlKey);" in controller
    assert "resumeSubmitIntent = wantsSteer ? 'steer' : 'send';" in controller
    assert "var submitIntent = resumeSubmitIntent === 'steer' ? 'steer' : 'send';" in controller

    assert ".agent-message-queue" in styles
    assert ".agent-queue-item" in styles
    assert ".agent-resume-send[hidden] { display: none; }" in styles
    assert ".agent-timeline-steer" in styles
    assert ".agent-turn.is-detail-expanded" in styles
    assert "grid-template-columns: repeat(3, 34px);" in styles


def test_paused_queue_without_native_session_keeps_queue_controls_available():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")

    # CleanupFailed、旧会话和非发起者仍是硬阻断；缺少 native session
    # 只阻止普通空闲续聊，不得抵消后端从 fresh native 启动暂停队列的能力。
    assert "var hardBlocked = !canResume || legacySession" in controller
    assert (
        "blocked = hardBlocked || (!running && !nativeSessionId && !queueMode);"
        in controller
    )
    assert (
        "queueResumeButton.disabled = hardBlocked || resumePending;"
        in controller
    )
    queue_renderer = controller.split(
        "function renderMessageQueue(state)", 1
    )[1].split("];", 1)[0]
    assert "hardBlocked," in queue_renderer
    assert "queuePaused," in queue_renderer
    assert "edit.disabled = remove.disabled = hardBlocked || !queued;" in controller
    assert "not queue_paused and not has_queued_messages" in template
    assert "is_hard_blocked or (not is_running and not has_resume_point" in template


def test_agent_detail_renders_all_message_mutation_urls_from_mapping_keys():
    template = _read("templates/admin/agent_task_detail.html")
    start = template.index('<main class="agent-session"')
    opening_tag = template[start:template.index(">", start) + 1]
    environment = Environment(autoescape=True)
    environment.globals["url_for"] = lambda endpoint, **_kwargs: f"/{endpoint}"
    message_urls = {
        "state": "/admin/agent_tasks/session-1/state",
        "stream": "/admin/agent_tasks/session-1/stream",
        "update": (
            "/admin/agent_tasks/session-1/messages/__MESSAGE_ID__/update"
        ),
        "delete": (
            "/admin/agent_tasks/session-1/messages/__MESSAGE_ID__/delete"
        ),
        "send_now": (
            "/admin/agent_tasks/session-1/messages/__MESSAGE_ID__/send-now"
        ),
        "resume": "/admin/agent_tasks/session-1/queue/resume",
    }

    rendered = environment.from_string(opening_tag).render(
        session_id="session-1",
        current_task_id="task-1",
        is_running=True,
        is_blocked=False,
        can_resume=True,
        can_retry=False,
        agent_session={"is_legacy": False, "steer_unavailable_reason": ""},
        has_resume_point="native-session-1",
        state_status="running",
        message_urls=message_urls,
        queue_paused=False,
        steer_supported=True,
        message_state={"steer_unavailable_reason": ""},
    )

    expected_attributes = {
        "data-session-state-url": message_urls["state"],
        "data-session-stream-url": message_urls["stream"],
        "data-queue-update-url-template": message_urls["update"],
        "data-queue-delete-url-template": message_urls["delete"],
        "data-queue-send-now-url-template": message_urls["send_now"],
        "data-queue-resume-url": message_urls["resume"],
    }
    for attribute, expected in expected_attributes.items():
        assert f'{attribute}="{expected}"' in rendered

    for key in message_urls:
        assert f"message_urls['{key}']" in opening_tag


def test_agent_detail_keeps_idempotency_and_task_transitions_bound_to_one_turn():
    controller = _read("static/app/agents/conversation.js")

    # 自动选择的 queue/turn 模式可能在请求重试前变化；同一草稿仍须复用首个
    # message_id 与投递目标，收到成功响应后则必须释放幂等键。
    assert "function newClientMessageId(prefix)" in controller
    assert "resumeDeliveryMode = computedDeliveryMode;" in controller
    assert "resumeExpectedTaskId = computedDeliveryMode === 'steer'" in controller
    assert "body.set('expected_task_id', resumeExpectedTaskId)" in controller
    assert "var deliveryMode = resumeDeliveryMode || computedDeliveryMode;" in controller
    dispatch_start = controller.index("function dispatchAgentTurn(options)")
    optimistic_turn = controller.index("appendOptimisticUserMessage(", dispatch_start)
    turn_pending_reset = controller.index(
        "setResumePending(false)", optimistic_turn
    )
    assert "clearResumeComposer();" in controller[optimistic_turn:turn_pending_reset]
    assert "function resetResumeAttempt()" in controller

    # session SSE 先看到下一轮时，先确认旧轮终态；startStream 也要把
    # currentState 绑定到新 task，避免极速连续轮次串用上一轮结论。
    assert "taskTransitionProbePending = true;" in controller
    assert "fetchState(previousTaskId, generation)" in controller
    assert "if (previousTaskId !== taskId || !isRunningStatus" in controller
    assert "task_id: taskId" in controller
    assert "messagePollingDueAt" in controller


def test_agent_detail_keeps_file_preview_and_workspace_accessible():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

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
    controller = _read("static/app/agents/conversation.js")
    routes = _read("oj_modules/routes/problem_core_routes.py")

    assert "message.title || message.name || message.tool_name" in controller
    assert "message.title || message.name || '子 Agent'" in controller
    assert "message.is_error === true" in controller
    assert "resultError ? 'error' : 'result'" in controller
    assert "resultError ? '工具执行失败' : '工具结果'" in controller
    assert "get_agent_trace_work_block(task_id, block_id)" in routes


def test_agent_trace_keeps_replies_visible_and_collapses_working_details():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")

    # 运行中主时间线只接收主动回复、插话和工作块摘要；内部事件必须等
    # 用户展开某一块后单独请求。完成后外层工作详情收起，只露出 conclude。
    assert '<details class="agent-turn-details"' in template
    assert 'data-agent-live-details {% if is_running %}open{% endif %}' in template
    assert 'class="agent-work-block' in template
    assert 'class="agent-trace-reply"' in template
    assert 'data-agent-live-conclusion hidden' in template
    assert 'class="agent-trace-fold"' not in template

    append_public = controller.split(
        "function appendTraceMessages(element, messages, taskId)", 1
    )[1].split("function renderTrace(state)", 1)[0]
    assert "kind === 'assistant' || kind === 'user'" in append_public
    assert "kind === 'work_summary'" in append_public
    assert "thinking/tool/tool_result" in append_public
    assert "traceWorkDetail" not in append_public
    assert "function traceWorkBlock(message, taskId)" in controller
    assert "function loadWorkBlock(details)" in controller
    assert "function appendTraceEventContent(body, message, kind)" in controller

    for selector in (
        ".agent-work-block {",
        ".agent-work-block > summary {",
        ".agent-work-block-body {",
        ".agent-work-detail {",
    ):
        assert selector in styles


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
        ".agent-work-detail--thinking .agent-trace-copy.numoj-markdown,",
    )
    paragraph_rule = _css_rule(
        styles,
        ".agent-work-detail--thinking .agent-trace-copy > p,",
    )
    last_paragraph_rule = _css_rule(
        styles,
        ".agent-work-detail--thinking .agent-trace-copy > p:last-child,",
    )

    assert "white-space: normal;" in markdown_rule
    assert "margin: 0 0 .45em;" in paragraph_rule
    assert "margin-bottom: 0;" in last_paragraph_rule


def test_agent_workspace_preview_covers_required_formats_and_safe_downloads():
    template = _read("templates/admin/agent_task_detail.html")
    controller = _read("static/app/agents/conversation.js")
    styles = _read("static/app/agents/conversation.css")
    editor_runtime = _read("static/app/code-editor-runtime.js")

    assert "problem_core.agent_workspace_tree" in template
    assert "problem_core.agent_workspace_file" in template
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

    # Lean 预览复用 Problem Detail 的同一个同步 Monaco/TextMate
    # 运行时；Agent 预览不注册 Lean 语义服务，也不加载 Goal 面板。
    assert 'lean: "lean4"' in editor_runtime
    assert "registerLean4(monaco);" in editor_runtime
    assert "var theme = await runtime.prepareMonaco(monaco);" in controller
    semantic_provider = controller.split("function ensureSemanticProvider", 1)[1].split(
        "function encodedMonacoPath", 1
    )[0]

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
        "static/app/agents/access-control.js",
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
