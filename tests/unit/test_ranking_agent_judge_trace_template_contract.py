"""Agent Judge 执行轨迹标签、默认视图与共享 renderer 的前端契约。"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RANKING = (ROOT / "templates" / "ranking" / "detail.html").read_text(encoding="utf-8")
JUDGE_MODAL = (
    ROOT / "templates" / "ranking" / "modals" / "judge_detail.html"
).read_text(encoding="utf-8")
REVERSE_MODAL = (
    ROOT / "templates" / "ranking" / "modals" / "reverse_judge_detail.html"
).read_text(encoding="utf-8")
AGENT_TASK_MODAL = (
    ROOT / "templates" / "agents" / "run_detail_modal.html"
).read_text(encoding="utf-8")
TRACE_ASSETS = (
    ROOT / "templates" / "components" / "agents" / "execution_trace_assets.html"
).read_text(encoding="utf-8")
TRACE_RENDERER = (ROOT / "static" / "app" / "agents" / "execution-trace.js").read_text(
    encoding="utf-8",
)
TRACE_STYLES = (ROOT / "static" / "app" / "agents" / "execution-trace.css").read_text(
    encoding="utf-8",
)
SUB_CARD = (
    ROOT / "templates" / "ranking" / "components" / "submission_card.html"
).read_text(encoding="utf-8")


def _assert_three_tabs_in_order(template):
    assert re.search(
        r'data-judge-view="topo"[^>]*>拓扑</button>\s*'
        r'<button[^>]+data-judge-view="detail"[^>]*>详情</button>\s*'
        r'<button[^>]+data-judge-view="trace"[^>]*>执行轨迹</button>',
        template,
    )


def test_shared_agent_judge_modal_adds_trace_tab_to_the_right_of_detail():
    _assert_three_tabs_in_order(JUDGE_MODAL)
    assert 'id="judgeModalTopo"' in JUDGE_MODAL
    assert 'id="judgeModalRules"' in JUDGE_MODAL
    assert 'id="judgeModalTrace"' in JUDGE_MODAL


def test_reverse_and_agent_judge_use_one_shared_trace_renderer():
    trace_include = "{% include 'components/agents/execution_trace_assets.html' %}"
    assert trace_include in REVERSE_MODAL
    assert trace_include in JUDGE_MODAL
    assert trace_include in AGENT_TASK_MODAL
    assert "app/agents/execution-trace.css" in TRACE_ASSETS
    assert "app/agents/execution-trace.js" in TRACE_ASSETS
    assert not (ROOT / "templates" / "ranking" / "scripts" / "execution_trace.html").exists()
    assert "{% include 'ranking/modals/judge_detail.html' %}" in RANKING
    assert "{% include 'ranking/modals/reverse_judge_detail.html' %}" in RANKING
    assert "keyPrefix:'reverse-judge', showThinkingLoader:true" in REVERSE_MODAL
    assert (
        "keyPrefix:'agent-judge', showThinkingLoader:true, "
        "showPendingLoader:true"
    ) in JUDGE_MODAL
    assert "function renderMessageHtml" not in REVERSE_MODAL


def test_agent_judge_trace_uses_bottom_thinking_and_large_pending_loaders():
    assert "function thinkingLoaderHtml(word)" in TRACE_RENDERER
    assert "function pendingLoaderHtml(context, trace)" in TRACE_RENDERER
    assert "data-agent-trace-activity" in TRACE_RENDERER
    assert "trace.status === 'running' && showThinking" in TRACE_RENDERER
    assert "trace.status === 'pending' && showPending" in TRACE_RENDERER
    assert 'class="agent-trace-pending"' in TRACE_RENDERER
    assert 'data-icon-only="true" data-size="lg"' in TRACE_RENDERER
    assert 'class="agent-trace-thinking"' in TRACE_RENDERER
    assert "thinkingLoaderHtml(thinkingWord)" in TRACE_RENDERER
    assert "status: snap.status === 'Judging' ? 'running'" in JUDGE_MODAL
    assert "? 'pending' : (snap.status === 'Error'" in JUDGE_MODAL


def test_judging_status_shows_stable_inline_loader_before_progress_bar():
    assert "function renderJudgeStatus(element, snap)" in JUDGE_MODAL
    assert "snap.status !== 'Judging'" in JUDGE_MODAL
    assert "data-judge-status-loader" in JUDGE_MODAL
    assert 'data-icon-only="true" data-size="xs"' in JUDGE_MODAL
    assert "element.querySelector('[data-judge-status-text]').textContent = text" in JUDGE_MODAL
    assert "renderJudgeStatus(status, snap)" in JUDGE_MODAL
    assert "d-inline-flex align-items-center gap-1" in JUDGE_MODAL


def test_shared_renderer_reconciles_by_stable_source_offset_identity():
    assert "function reconcileMessageOrder(existingKeys, incomingKeys)" in TRACE_RENDERER
    assert "function reconcileMessages(root, trace, context)" in TRACE_RENDERER
    assert "'source:' + source" in TRACE_RENDERER
    assert "'offset:' + String(offset)" in TRACE_RENDERER
    assert "'event:' + String" in TRACE_RENDERER
    assert "feed.insertAdjacentHTML(" in TRACE_RENDERER
    assert "'beforeend', messageHtml(" in TRACE_RENDERER
    assert "feed.appendChild(element)" in TRACE_RENDERER
    assert "data-agent-trace-message-key" in TRACE_RENDERER
    assert "var hasMessages = !!(feed && feed.children.length)" in TRACE_RENDERER
    assert "typesetMath(addedElements)" in TRACE_RENDERER
    assert "querySelectorAll('[id], [name]')" in TRACE_RENDERER


def test_shared_renderer_supports_escaped_pi_tool_results():
    assert "if (message.kind === 'tool_result') return 'tool_result';" in TRACE_RENDERER
    assert "if (kind === 'tool_result') return 'fa-square-check';" in TRACE_RENDERER
    assert "kind === 'tool_result' ? '工具结果'" in TRACE_RENDERER
    assert ".rj-msg.tool-result" in TRACE_STYLES
    assert ".rj-tool-result-summary" in TRACE_STYLES
    assert ".rj-tool-result-text" in TRACE_STYLES
    assert "message.is_error ? ' error' : ''" in TRACE_RENDERER
    # tool_result 只走纯文本转义；Markdown HTML 入口仍仅限服务端已清洗的回复/思考。
    assert (
        "'<div class=\"rj-msg-body rj-tool-result-text\">' + "
        "esc(message.text || '') + '</div>'"
    ) in TRACE_RENDERER
    rich_html_guard = (
        "if ((kind === 'assistant' || kind === 'thinking') && message.html)"
    )
    assert rich_html_guard in TRACE_RENDERER


def test_shared_renderer_repairs_backfill_and_keeps_sliding_window_history():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    helper = TRACE_RENDERER.split("// TRACE_ORDER_HELPER_START", 1)[1].split(
        "// TRACE_ORDER_HELPER_END", 1,
    )[0]
    script = helper + r"""
const cases = {
  backfill: reconcileMessageOrder(['rule17', 'rule19'], ['setup', 'rule17', 'rule18', 'rule19']),
  reorder: reconcileMessageOrder(['rule17', 'rule19', 'setup'], ['setup', 'rule17', 'rule18', 'rule19']),
  sliding: reconcileMessageOrder(['setup', 'rule1', 'rule2'], ['rule2', 'rule3']),
  stale: reconcileMessageOrder(['setup', 'rule1', 'rule2'], ['setup', 'rule1'])
};
process.stdout.write(JSON.stringify(cases));
"""
    result = subprocess.run(
        [node, "-e", script], check=True, capture_output=True, text=True,
    )

    assert result.stdout == (
        '{"backfill":["setup","rule17","rule18","rule19"],'
        '"reorder":["setup","rule17","rule18","rule19"],'
        '"sliding":["setup","rule1","rule2","rule3"],'
        '"stale":["setup","rule1","rule2"]}'
    )


def test_trace_window_keeps_first_seven_and_live_last_two_until_expanded():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")
    helper = TRACE_RENDERER.split("// TRACE_WINDOW_HELPER_START", 1)[1].split(
        "// TRACE_WINDOW_HELPER_END", 1,
    )[0]
    script = helper + r"""
const keys = Array.from({length: 12}, (_, index) => 'm' + (index + 1));
const cases = {
  nine: visibleMessageKeys(keys.slice(0, 9), false),
  ten: visibleMessageKeys(keys.slice(0, 10), false),
  twelve: visibleMessageKeys(keys, false),
  expanded: visibleMessageKeys(keys, true)
};
process.stdout.write(JSON.stringify(cases));
"""
    result = subprocess.run(
        [node, "-e", script], check=True, capture_output=True, text=True,
    )

    assert json.loads(result.stdout) == {
        "nine": [f"m{index}" for index in range(1, 10)],
        "ten": ["m1", "m2", "m3", "m4", "m5", "m6", "m7", "m9", "m10"],
        "twelve": ["m1", "m2", "m3", "m4", "m5", "m6", "m7", "m11", "m12"],
        "expanded": [f"m{index}" for index in range(1, 13)],
    }


def test_trace_window_state_survives_incremental_events_and_keeps_history_off_dom():
    assert "var traceExpanded = false" in TRACE_RENDERER
    assert "var messageOrder = []" in TRACE_RENDERER
    assert "var messageRecords = Object.create(null)" in TRACE_RENDERER
    assert "reconcileMessageOrder(messageOrder, incomingKeys)" in TRACE_RENDERER
    assert "visibleMessageKeys(messageOrder, traceExpanded)" in TRACE_RENDERER
    assert "traceExpanded = true" in TRACE_RENDERER
    assert "messageOrder.length > 9 && !traceExpanded" in TRACE_RENDERER
    assert "收起中间执行记录" not in TRACE_RENDERER
    assert "data-agent-trace-toggle" in TRACE_RENDERER
    assert "feed.insertBefore(toggle, eighthMessage || null)" in TRACE_RENDERER
    assert "latestTrace = trace" in TRACE_RENDERER
    assert "latestContext = context" in TRACE_RENDERER
    assert TRACE_RENDERER.index("data-agent-trace-activity") < TRACE_RENDERER.index(
        "data-agent-trace-raw"
    )


def test_default_view_tracks_status_without_overriding_manual_selection():
    assert "['Judging', 'Queued', 'Pending']" in JUDGE_MODAL
    assert "? 'trace' : 'detail'" in JUDGE_MODAL
    assert "if (!judgeViewManuallySelected)" in JUDGE_MODAL
    assert "setJudgeView(tab.dataset.judgeView, true)" in JUDGE_MODAL
    assert "applyDefaultJudgeView(snap.status)" in JUDGE_MODAL
    assert "var executionTrace = snap.execution_trace" in JUDGE_MODAL
    assert "currentJudgeResultSignature" in JUDGE_MODAL
    assert "signature === currentJudgeResultSignature" in JUDGE_MODAL
    assert "trace.trace_id" not in JUDGE_MODAL
    assert "executionTrace.trace_id || snap.attempt_trace_id" in JUDGE_MODAL
    assert 'data-submission-status="{{ s.status }}"' in SUB_CARD
