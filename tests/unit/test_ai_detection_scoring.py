# -*- coding: utf-8 -*-
"""Task 17 — AI 检测分数合成（detector.run_detection）的纯函数单测。

参考 §6a：
    final = min(1.0, llm + beh * W_BEHAVIOR_BONUS)，W_BEHAVIOR_BONUS = 0.3
    - llm is not None: min(1.0, llm + beh*0.3)
    - elif beh > 0:    beh*0.3
    - else:            0.0
    结果 round 到 4 位小数。
风险分级阈值以源码为准（detector.py）：>=0.7 high；>=0.4 medium；否则 low。

这些用例通过 monkeypatch detector.detect_with_llm / detector.detect_behavior
注入确定的分数，因此不触碰 DB / 网络，确定性、自包含。
"""
import pytest

from oj_modules.ai_detection import detector


# detector.RISK_HIGH / RISK_MEDIUM 是源码常量；这里读出来供分级断言使用，
# 避免把阈值硬编码（同时仍验证 0.7 / 0.4 这两个值符合预期）。
def test_module_thresholds_match_source():
    assert detector.W_BEHAVIOR_BONUS == 0.3
    assert detector.RISK_HIGH == 0.7
    assert detector.RISK_MEDIUM == 0.4


def _patch_scores(monkeypatch, llm_score, beh_score):
    """注入 detect_with_llm / detect_behavior 的返回。

    llm_score=None 表示让 detect_with_llm 返回 None（未配置/无结论），
    此时 run_detection 不会写 llm_score。
    """
    if llm_score is None:
        monkeypatch.setattr(detector, 'detect_with_llm', lambda *a, **k: None)
    else:
        monkeypatch.setattr(
            detector, 'detect_with_llm',
            lambda *a, **k: {
                'score': llm_score,
                'confidence': 0.9,
                'evidence': [],
                'raw_response': '',
            },
        )
    monkeypatch.setattr(
        detector, 'detect_behavior',
        lambda *a, **k: {'score': beh_score, 'signals': []},
    )


_SUBMISSION = {
    'id': 1, 'username': 'u', 'problem_id': 1,
    'code': 'x = 1;', 'status': 'Accepted',
}
_PROBLEM = {'id': 1, 'content': '', 'lang': 'matlab', 'type': 1}


def _run(monkeypatch, llm_score, beh_score):
    _patch_scores(monkeypatch, llm_score, beh_score)
    return detector.run_detection(dict(_SUBMISSION), dict(_PROBLEM))


# --- final_score 合成向量（来自 §6a / plan Task 17）---

def test_final_score_llm_and_behavior_additive(monkeypatch):
    # llm=0.6, beh=0.5 → min(1.0, 0.6 + 0.5*0.3) = 0.75 → high
    out = _run(monkeypatch, 0.6, 0.5)
    assert abs(out['final_score'] - 0.75) < 1e-6
    assert out['risk_level'] == 'high'


def test_final_score_no_llm_behavior_only(monkeypatch):
    # llm=None, beh=0.8 → 0.8*0.3 = 0.24 → low
    out = _run(monkeypatch, None, 0.8)
    assert abs(out['final_score'] - 0.24) < 1e-6
    assert out['risk_level'] == 'low'
    # detect_with_llm 返回 None 时不写 llm_score
    assert out['llm_score'] is None


def test_final_score_both_zeroish(monkeypatch):
    # llm=None, beh=0 → 0.0 → low
    out = _run(monkeypatch, None, 0.0)
    assert out['final_score'] == 0.0
    assert out['risk_level'] == 'low'
    assert out['llm_score'] is None


def test_final_score_capped_at_one(monkeypatch):
    # llm=0.95, beh=1.0 → min(1.0, 0.95 + 0.3) = 1.0
    out = _run(monkeypatch, 0.95, 1.0)
    assert out['final_score'] == 1.0
    assert out['risk_level'] == 'high'


def test_final_score_rounded_to_four_decimals(monkeypatch):
    # llm=0.1, beh=0.3333 → 0.1 + 0.3333*0.3 = 0.19999 → round(.,4)=0.2
    out = _run(monkeypatch, 0.1, 0.3333)
    assert out['final_score'] == round(0.1 + 0.3333 * 0.3, 4)


# --- 风险分级阈值（以源码常量为准）---

def test_risk_level_medium_at_lower_bound(monkeypatch):
    # 选 llm 使 final 恰好等于 RISK_MEDIUM（0.4），beh=0 → final=0.4 → medium
    out = _run(monkeypatch, detector.RISK_MEDIUM, 0.0)
    assert abs(out['final_score'] - detector.RISK_MEDIUM) < 1e-6
    assert out['risk_level'] == 'medium'


def test_risk_level_high_at_lower_bound(monkeypatch):
    # final 恰好等于 RISK_HIGH（0.7） → high
    out = _run(monkeypatch, detector.RISK_HIGH, 0.0)
    assert abs(out['final_score'] - detector.RISK_HIGH) < 1e-6
    assert out['risk_level'] == 'high'


def test_risk_level_low_below_medium(monkeypatch):
    # final 略低于 medium 阈值 → low
    out = _run(monkeypatch, detector.RISK_MEDIUM - 0.1, 0.0)
    assert out['final_score'] < detector.RISK_MEDIUM
    assert out['risk_level'] == 'low'


# --- 结果字典形状与回填字段 ---

def test_run_detection_result_shape_and_passthrough(monkeypatch):
    _patch_scores(monkeypatch, 0.6, 0.5)
    out = detector.run_detection(
        {'id': 42, 'username': 'bob', 'problem_id': 7,
         'code': 'y=2;', 'status': 'Accepted'},
        {'id': 7, 'content': '题面', 'lang': 'matlab', 'type': 1},
        model_id='qwen', task_id='task-xyz',
    )
    # 透传的标识字段
    assert out['submission_id'] == 42
    assert out['username'] == 'bob'
    assert out['problem_id'] == 7
    assert out['task_id'] == 'task-xyz'
    # 分数回填（round 到 4 位）
    assert out['llm_score'] == 0.6
    assert out['behavior_score'] == 0.5
    # 结果包含全部约定键
    for key in (
        'submission_id', 'username', 'problem_id',
        'llm_score', 'llm_evidence',
        'behavior_score', 'behavior_detail',
        'final_score', 'risk_level', 'task_id',
    ):
        assert key in out
