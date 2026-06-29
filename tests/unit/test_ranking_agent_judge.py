# -*- coding: utf-8 -*-
"""agent_judge 纯逻辑单测：DAG 校验、拓扑序、effective/score 裁决、result 行解析。"""
import pytest

from oj_modules import ranking_agent_judge as aj


def _rules(*specs):
    """specs: (rule_id, value, [deps]) → 归一前的规则 dict 列表。"""
    return [{'rule_id': rid, 'rule_text': f'规则{rid}', 'value': val, 'dependencies': list(deps)}
            for (rid, val, deps) in specs]


# ---- normalize_rules ----
def test_normalize_accepts_valid_dag():
    rules = _rules((1, 10, []), (2, 20, [1]), (3, 5, [1, 2]))
    out = aj.normalize_rules(rules)
    assert [r['rule_id'] for r in out] == [1, 2, 3]
    assert out[1]['dependencies'] == [1]


def test_normalize_preserves_optional_rule_name():
    out = aj.normalize_rules([
        {'rule_id': 1, 'rule_name': '基础正确性', 'rule_text': '能编译运行',
         'value': 10, 'dependencies': []},
    ])
    assert out[0]['rule_name'] == '基础正确性'


def test_normalize_rejects_unknown_dependency():
    with pytest.raises(ValueError):
        aj.normalize_rules(_rules((1, 10, [99])))


def test_normalize_rejects_self_dependency():
    with pytest.raises(ValueError):
        aj.normalize_rules(_rules((1, 10, [1])))


def test_normalize_rejects_cycle():
    with pytest.raises(ValueError):
        aj.normalize_rules(_rules((1, 10, [2]), (2, 10, [1])))


def test_normalize_rejects_negative_value():
    with pytest.raises(ValueError):
        aj.normalize_rules(_rules((1, -1, [])))


def test_normalize_rejects_duplicate_rule_id():
    with pytest.raises(ValueError):
        aj.normalize_rules(_rules((1, 10, []), (1, 5, [])))


# ---- topo_order ----
def test_topo_order_deps_before_dependents():
    rules = aj.normalize_rules(_rules((1, 10, [2]), (2, 10, [3]), (3, 10, [])))
    order = aj.topo_order(rules)
    assert order.index(3) < order.index(2) < order.index(1)


def test_normalize_orchestration_mode():
    assert aj.normalize_orchestration_mode('topo') == aj.ORCH_TOPOLOGICAL
    assert aj.normalize_orchestration_mode('topological') == aj.ORCH_TOPOLOGICAL
    assert aj.normalize_orchestration_mode('anything-else') == aj.ORCH_SINGLE


# ---- compute_results ----
def test_compute_pass_and_failed_scores():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [])))
    res = aj.compute_results(rules, {1: 'pass', 2: 'failed'})
    assert res[1] == {'effective': 'pass', 'score': 10.0}
    assert res[2] == {'effective': 'failed', 'score': 0.0}


def test_compute_dependency_gate_skips_dependent():
    # 规则2 依赖规则1；规则1 failed → 规则2 即便 raw=pass 也被判 skipped、0 分
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [1])))
    res = aj.compute_results(rules, {1: 'failed', 2: 'pass'})
    assert res[1]['effective'] == 'failed'
    assert res[2] == {'effective': 'skipped', 'score': 0.0}


def test_compute_gate_propagates_transitively():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [1]), (3, 5, [2])))
    res = aj.compute_results(rules, {1: 'failed', 2: 'pass', 3: 'pass'})
    assert res[2]['effective'] == 'skipped'
    assert res[3]['effective'] == 'skipped'


def test_compute_live_pending_for_unreported():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [])))
    res = aj.compute_results(rules, {1: 'pass'}, finalize=False)
    assert res[2]['effective'] == 'pending'
    assert res[2]['score'] == 0.0


def test_compute_finalize_marks_unreported_as_error():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [])))
    res = aj.compute_results(rules, {1: 'pass'}, finalize=True)
    assert res[2]['effective'] == 'error'


def test_compute_pending_dependency_keeps_dependent_pending():
    # 依赖尚未上报（pending）时，依赖项保持 pending（live 阶段不提前跳过）
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [1])))
    res = aj.compute_results(rules, {2: 'pass'}, finalize=False)
    assert res[1]['effective'] == 'pending'
    assert res[2]['effective'] == 'pending'


# ---- max/total ----
def test_max_and_total_score():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, []), (3, 5, [])))
    assert aj.max_score(rules) == 35.0
    res = aj.compute_results(rules, {1: 'pass', 2: 'failed', 3: 'pass'}, finalize=True)
    assert aj.total_score(res) == 15.0


# ---- parse_result_line ----
def test_parse_valid_line():
    assert aj.parse_result_line('{"rule_id": 2, "result": "pass", "evidence": "x"}') == \
        {'rule_id': 2, 'result': 'pass', 'evidence': 'x'}


def test_parse_failed_no_evidence():
    out = aj.parse_result_line('{"rule_id": 3, "result": "failed"}')
    assert out['rule_id'] == 3 and out['result'] == 'failed' and out['evidence'] == ''


@pytest.mark.parametrize('bad', [
    '', 'not json', '{"rule_id": "x", "result": "pass"}',
    '{"result": "pass"}', '{"rule_id": 1, "result": "maybe"}', '[]',
])
def test_parse_invalid_returns_none(bad):
    assert aj.parse_result_line(bad) is None


# ---- build_rules_json ----
def test_build_rules_json_shape():
    rules = aj.normalize_rules(_rules((1, 10, []), (2, 20, [1])))
    out = aj.build_rules_json(rules)
    assert out[1] == {'rule_id': 2, 'rule': '规则2', 'value': 20.0, 'dependence': [1]}


# ---- render_md_math ----
def test_render_md_bold_and_code():
    out = aj.render_md_math('**粗体** 与 `code`')
    assert '<strong>粗体</strong>' in out
    assert '<code>code</code>' in out


def test_render_md_preserves_inline_latex():
    out = aj.render_md_math('误差 $L^2$ 约为 $a_b$，应当收敛')
    # 行内公式原样保留（含下划线不被当作 markdown 斜体），交给 MathJax
    assert '$L^2$' in out
    assert '$a_b$' in out
    assert '<em>' not in out


def test_render_md_preserves_display_latex_and_escapes_lt():
    out = aj.render_md_math(r'收敛阶：$$ \|e\|_{L^2} \le C h^2 $$ 其中 $a < b$')
    assert r'\|e\|_{L^2} \le C h^2' in out
    # 行内 $a < b$ 的 < 被转义，避免破坏 HTML；MathJax 仍能从 textContent 读取
    assert '$a &lt; b$' in out


def test_render_md_empty():
    assert aj.render_md_math('') == ''
    assert aj.render_md_math(None) == ''


def test_render_md_loosens_tight_lists():
    # LLM 紧凑 markdown：段落后紧跟 - 列表（无空行）应渲染成 <ul>
    out = aj.render_md_math('配置如下：\n- 第一项\n- 第二项')
    assert out.count('<li>') == 2 and '<ul>' in out


def test_render_snapshot_html_adds_html_fields_without_mutating():
    snap = {'submission_id': 1, 'status': 'Accepted',
            'rules': [{'rule_id': 1, 'rule_text': '**粗体规则**', 'evidence': '## 标题\n- a'}]}
    out = aj.render_snapshot_html(snap)
    r = out['rules'][0]
    assert '<strong>粗体规则</strong>' in r['rule_html']
    assert '<h2' in r['evidence_html']
    # 原对象不被改动（不持久化 HTML）
    assert 'rule_html' not in snap['rules'][0]
    assert r['evidence'] == '## 标题\n- a'  # 原始 markdown 仍在


# ---- build_prompt ----
def test_build_prompt_mentions_files_and_gate():
    p = aj.build_prompt('我的打榜赛')
    assert 'rules.json' in p and 'result.jsonl' in p and 'report' in p
    assert 'dependence' in p
    assert '我的打榜赛' in p


def test_build_topological_prompts_split_setup_and_single_rule():
    setup = aj.build_setup_prompt('拓扑赛')
    assert '不要调用 report' in setup
    rule = aj.normalize_rules([
        {'rule_id': 2, 'rule_name': '输出', 'rule_text': '输出正确', 'value': 20, 'dependencies': [1]},
        {'rule_id': 1, 'rule_text': '可运行', 'value': 10, 'dependencies': []},
    ])[0]
    p = aj.build_rule_prompt('拓扑赛', rule, 'result_x.jsonl')
    assert '只判定下面这一条评分规则' in p
    assert 'result_x.jsonl' in p
    assert 'report <rule_id> <pass|failed>' in p
