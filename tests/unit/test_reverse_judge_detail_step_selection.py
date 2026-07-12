"""反向评测详情默认步骤选择的前端逻辑契约。"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODAL = (ROOT / "templates" / "_reverse_judge_detail_modal.html").read_text(
    encoding="utf-8",
)


def _selector_helper():
    return MODAL.split("// REVERSE_JUDGE_STEP_SELECTOR_START", 1)[1].split(
        "// REVERSE_JUDGE_STEP_SELECTOR_END", 1,
    )[0]


def test_reverse_detail_selector_tracks_progress_and_terminal_step():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is unavailable")

    helper = _selector_helper()
    script = helper + r"""
const pending = key => ({step_key:key, status:'pending'});
const step = (key, status, result) => ({step_key:key, status, result:result || {}});
const keys = ['solution_check', 'quality_gate', 'agent_answer', 'ai_judge'];
const allPending = keys.map(pending);

const progress = [];
let current = 'solution_check';
[
  [step('solution_check', 'running'), pending('quality_gate'), pending('agent_answer'), pending('ai_judge')],
  [step('solution_check', 'passed'), step('quality_gate', 'running'), pending('agent_answer'), pending('ai_judge')],
  [step('solution_check', 'passed'), step('quality_gate', 'passed'), step('agent_answer', 'running'), pending('ai_judge')],
  [step('solution_check', 'passed'), step('quality_gate', 'passed'), step('agent_answer', 'passed'), step('ai_judge', 'running')]
].forEach(steps => {
  current = selectReverseJudgeStep('Judging', steps, current, false);
  progress.push(current);
});

const cases = {
  pending: selectReverseJudgeStep('Queued', allPending, 'solution_check', false),
  progress,
  accepted: selectReverseJudgeStep('Accepted', [
    step('solution_check', 'passed'),
    step('quality_gate', 'skipped', {skipped:true}),
    step('agent_answer', 'passed'),
    step('ai_judge', 'passed')
  ], 'solution_check', false),
  acceptedLastExecuted: selectReverseJudgeStep('Accepted', [
    step('solution_check', 'passed'),
    step('quality_gate', 'skipped', {skipped:true}),
    step('agent_answer', 'passed'),
    pending('ai_judge')
  ], 'solution_check', false),
  acceptedUsesStepOrder: selectReverseJudgeStep('Accepted', [
    {step_key:'ai_judge', status:'passed', step_order:4},
    {step_key:'solution_check', status:'passed', step_order:1},
    {step_key:'agent_answer', status:'passed', step_order:3},
    {step_key:'quality_gate', status:'skipped', step_order:2, result:{skipped:true}}
  ], 'solution_check', false),
  failedGate: selectReverseJudgeStep('Error', [
    step('solution_check', 'passed'),
    step('quality_gate', 'failed'),
    pending('agent_answer'),
    pending('ai_judge')
  ], 'solution_check', false),
  erroredAgent: selectReverseJudgeStep('Error', [
    step('solution_check', 'passed'),
    step('quality_gate', 'skipped', {skipped:true}),
    step('agent_answer', 'error'),
    pending('ai_judge')
  ], 'solution_check', false),
  erroredWhileRunning: selectReverseJudgeStep('Error', [
    step('solution_check', 'passed'),
    step('quality_gate', 'passed'),
    step('agent_answer', 'passed'),
    step('ai_judge', 'running')
  ], 'solution_check', false),
  manualSelection: selectReverseJudgeStep('Judging', [
    step('solution_check', 'passed'),
    step('quality_gate', 'passed'),
    step('agent_answer', 'running'),
    pending('ai_judge')
  ], 'solution_check', true),
  hiddenManualSelection: selectReverseJudgeStep('Judging', [
    step('solution_check', 'passed'),
    step('quality_gate', 'skipped', {skipped:true}),
    step('agent_answer', 'running'),
    pending('ai_judge')
  ], 'quality_gate', true)
};
process.stdout.write(JSON.stringify(cases));
"""
    result = subprocess.run(
        [node, "-e", script], check=True, capture_output=True, text=True,
    )

    assert json.loads(result.stdout) == {
        "pending": "solution_check",
        "progress": [
            "solution_check",
            "quality_gate",
            "agent_answer",
            "ai_judge",
        ],
        "accepted": "ai_judge",
        "acceptedLastExecuted": "agent_answer",
        "acceptedUsesStepOrder": "ai_judge",
        "failedGate": "quality_gate",
        "erroredAgent": "agent_answer",
        "erroredWhileRunning": "ai_judge",
        "manualSelection": "solution_check",
        "hiddenManualSelection": "agent_answer",
    }


def test_reverse_detail_manual_selection_state_resets_for_each_open():
    assert "activeStepManuallySelected = true;" in MODAL
    assert "activeStepManuallySelected = false;" in MODAL
    assert "activeStepManuallySelected\n    );" in MODAL
    assert "function shouldRenderStep(key, step){ return isReverseJudgeStepVisible(key, step); }" in MODAL


def test_reverse_detail_keeps_event_source_reconnectable_before_terminal_state():
    timeout_handler = MODAL.split(
        "source.addEventListener('timeout'", 1,
    )[1].split("source.addEventListener('error'", 1)[0]
    error_handler = MODAL.split(
        "source.addEventListener('error'", 1,
    )[1].split("if (modalEl)", 1)[0]

    assert "renderSnap(JSON.parse(ev.data))" in timeout_handler
    assert "closeSource()" not in timeout_handler
    assert "source.readyState === EventSource.CLOSED" in error_handler
    assert "closeSource()" in error_handler
