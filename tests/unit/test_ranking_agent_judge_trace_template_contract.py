"""Agent Judge 执行轨迹标签、默认视图与共享 renderer 的前端契约。"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RANKING = (ROOT / "templates" / "ranking_detail.html").read_text(encoding="utf-8")
JUDGE_MODAL = (ROOT / "templates" / "_judge_detail_modal.html").read_text(encoding="utf-8")
REVERSE_MODAL = (ROOT / "templates" / "_reverse_judge_detail_modal.html").read_text(encoding="utf-8")
TRACE_RENDERER = (ROOT / "templates" / "_agent_execution_trace.html").read_text(encoding="utf-8")
SUB_CARD = (ROOT / "templates" / "_ranking_sub_card.html").read_text(encoding="utf-8")


def _assert_three_tabs_in_order(template):
    assert re.search(
        r'data-judge-view="topo"[^>]*>拓扑</button>\s*'
        r'<button[^>]+data-judge-view="detail"[^>]*>详情</button>\s*'
        r'<button[^>]+data-judge-view="trace"[^>]*>执行轨迹</button>',
        template,
    )


def test_both_agent_judge_modals_add_trace_tab_to_the_right_of_detail():
    _assert_three_tabs_in_order(RANKING)
    _assert_three_tabs_in_order(JUDGE_MODAL)
    for template in (RANKING, JUDGE_MODAL):
        assert 'id="judgeModalTopo"' in template
        assert 'id="judgeModalRules"' in template
        assert 'id="judgeModalTrace"' in template


def test_reverse_and_agent_judge_use_one_shared_trace_renderer():
    assert "{% include '_agent_execution_trace.html' %}" in REVERSE_MODAL
    assert "{% include '_agent_execution_trace.html' %}" in JUDGE_MODAL
    assert "{% include '_agent_execution_trace.html' %}" in RANKING
    assert "keyPrefix:'reverse-judge', showThinkingLoader:true" in REVERSE_MODAL
    for template in (JUDGE_MODAL, RANKING):
        assert (
            "keyPrefix:'agent-judge', showThinkingLoader:true, "
            "showPendingLoader:true"
        ) in template
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
    for template in (JUDGE_MODAL, RANKING):
        assert "status: snap.status === 'Judging' ? 'running'" in template
        assert "? 'pending' : (snap.status === 'Error'" in template


def test_judging_status_shows_stable_inline_loader_before_progress_bar():
    for template in (JUDGE_MODAL, RANKING):
        assert "function renderJudgeStatus(element, snap)" in template
        assert "snap.status !== 'Judging'" in template
        assert "data-judge-status-loader" in template
        assert 'data-icon-only="true" data-size="xs"' in template
        assert "element.querySelector('[data-judge-status-text]').textContent = text" in template
        assert "renderJudgeStatus(status, snap)" in template
        assert "d-inline-flex align-items-center gap-1" in template


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
    for template in (RANKING, JUDGE_MODAL):
        assert "['Judging', 'Queued', 'Pending']" in template
        assert "? 'trace' : 'detail'" in template
        assert "if (!judgeViewManuallySelected)" in template
        assert "setJudgeView(tab.dataset.judgeView, true)" in template
        assert "applyDefaultJudgeView(snap.status)" in template
        assert "var executionTrace = snap.execution_trace" in template
        assert "currentJudgeResultSignature" in template
        assert "signature === currentJudgeResultSignature" in template
        assert "trace.trace_id" not in template
        assert "executionTrace.trace_id || snap.attempt_trace_id" in template
    assert 'data-submission-status="{{ s.status }}"' in SUB_CARD
