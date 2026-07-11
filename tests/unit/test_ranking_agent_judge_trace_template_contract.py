"""Agent Judge 执行轨迹标签、默认视图与共享 renderer 的前端契约。"""

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
    assert "window.AgentExecutionTrace.create({keyPrefix:'reverse-judge'})" in REVERSE_MODAL
    assert "window.AgentExecutionTrace.create({keyPrefix:'agent-judge'})" in JUDGE_MODAL
    assert "window.AgentExecutionTrace.create({keyPrefix:'agent-judge'})" in RANKING
    assert "function renderMessageHtml" not in REVERSE_MODAL


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
