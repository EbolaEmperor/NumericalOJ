# -*- coding: utf-8 -*-
"""agent_judge DB 层：规则保存(含 DAG 校验)、结果 upsert、快照构造。"""
import pytest

from backend.oj_modules.ranking import db as ranking_db
from backend.oj_modules.ranking.agent_judge import db as ajdb


def _make_comp():
    cid = ranking_db.create_competition(title='aj', description='d', max_score=100,
                                        created_by='admin', summary='s')
    ranking_db.update_competition(cid, scoring_mode='agent_judge')
    return cid


def test_replace_and_list_rules(client):  # client fixture 触发 app/db 初始化
    cid = _make_comp()
    ajdb.replace_competition_rules(cid, [
        {'rule_id': 1, 'rule_name': '编译', 'rule_text': '能编译', 'value': 10, 'dependencies': []},
        {'rule_id': 2, 'rule_text': '输出正确', 'value': 20, 'dependencies': [1]},
    ])
    rules = ajdb.list_competition_rules(cid)
    assert [r['rule_id'] for r in rules] == [1, 2]
    assert rules[1]['dependencies'] == [1]
    assert rules[0]['rule_name'] == '编译'
    assert rules[0]['rule_text'] == '能编译'


def test_replace_rules_rejects_cycle(client):
    cid = _make_comp()
    with pytest.raises(ValueError):
        ajdb.replace_competition_rules(cid, [
            {'rule_id': 1, 'rule_text': 'a', 'value': 1, 'dependencies': [2]},
            {'rule_id': 2, 'rule_text': 'b', 'value': 1, 'dependencies': [1]},
        ])
    assert ajdb.list_competition_rules(cid) == []


def test_replace_rules_overwrites(client):
    cid = _make_comp()
    ajdb.replace_competition_rules(cid, [{'rule_id': 1, 'rule_text': 'a', 'value': 1, 'dependencies': []}])
    ajdb.replace_competition_rules(cid, [
        {'rule_id': 1, 'rule_text': 'x', 'value': 5, 'dependencies': []},
        {'rule_id': 2, 'rule_text': 'y', 'value': 5, 'dependencies': []},
    ])
    rules = ajdb.list_competition_rules(cid)
    assert len(rules) == 2 and rules[0]['rule_text'] == 'x'


def test_upsert_and_list_results(client):
    cid = _make_comp()
    sid = ranking_db.create_ranking_submission(cid, 'u1')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 10.0, '证据A')
    ajdb.upsert_judge_result(sid, 1, 'failed', 'failed', 0.0, '改判')  # 同 rule_id 覆盖
    ajdb.upsert_judge_result(sid, 2, 'pass', 'pass', 20.0, '证据B')
    rows = ajdb.list_judge_results(sid)
    by = {r['rule_id']: r for r in rows}
    assert by[1]['raw_result'] == 'failed' and by[1]['evidence'] == '改判'
    assert by[2]['score'] == 20.0


def test_build_snapshot_live_and_gate(client):
    cid = _make_comp()
    ajdb.replace_competition_rules(cid, [
        {'rule_id': 1, 'rule_text': 'a', 'value': 10, 'dependencies': []},
        {'rule_id': 2, 'rule_text': 'b', 'value': 20, 'dependencies': [1]},
    ])
    sid = ranking_db.create_ranking_submission(cid, 'u1')
    ranking_db.update_submission_files(sid, None, None, 'code.zip', '/tmp/x', base_model='m')
    ajdb.upsert_judge_result(sid, 1, 'failed', 'failed', 0.0, 'no')
    snap = ajdb.build_judge_snapshot(sid)
    assert snap['max_score'] == 30.0
    rule2 = next(r for r in snap['rules'] if r['rule_id'] == 2)
    assert rule2['effective'] == 'skipped'   # 依赖失败 → 跳过
    assert snap['status'] == 'Judging'


def test_build_snapshot_stores_raw_markdown_not_html(client):
    cid = _make_comp()
    ajdb.replace_competition_rules(cid, [
        {'rule_id': 1, 'rule_text': '**规则一**', 'value': 10, 'dependencies': []},
    ])
    sid = ranking_db.create_ranking_submission(cid, 'u1')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 10.0, '## 证据标题\n- 步骤')
    snap = ajdb.build_judge_snapshot(sid)
    r = snap['rules'][0]
    # 只存 markdown 源，不持久化渲染后的 HTML
    assert r['evidence'] == '## 证据标题\n- 步骤'
    assert 'evidence_html' not in r
    assert 'rule_html' not in r


def test_clear_results(client):
    cid = _make_comp()
    sid = ranking_db.create_ranking_submission(cid, 'u1')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 1.0, '')
    ajdb.clear_judge_results(sid)
    assert ajdb.list_judge_results(sid) == []


def test_agent_judge_endpoints_store_one_contract_for_all_harnesses(client):
    cid = _make_comp()
    ajdb.save_agent_judge_endpoints(cid, [
        {'harness': 'codex', 'base_url': 'https://gw/openai/v1', 'api_key': 'k1',
         'model': 'model-a', 'context_window_tokens': 200000,
         'max_output_tokens': 50000, 'thinking_compatibility': False,
         'concurrency_limit': 3, 'enabled': True},
        {'harness': 'opencode', 'base_url': 'https://open.example/v1', 'api_key': 'k2',
         'model': 'open-model', 'concurrency_limit': 2, 'enabled': True},
        {'harness': 'codex', 'base_url': 'https://paused/v1', 'api_key': 'k3',
         'model': 'model-c', 'concurrency_limit': 4, 'status': 'paused', 'enabled': True},
    ])
    eps = ajdb.list_agent_judge_endpoints(cid)
    assert eps[0]['harness'] == 'codex'
    assert eps[0]['base_url'] == 'https://gw/openai/v1'
    assert eps[0]['context_window_tokens'] == 200000
    assert eps[0]['max_output_tokens'] == 50000
    assert eps[0]['thinking_compatibility'] is False
    assert eps[1]['harness'] == 'opencode'
    assert eps[1]['base_url'] == 'https://open.example/v1'
    assert eps[1]['model'] == 'open-model'
    assert eps[1]['context_window_tokens'] == 1_000_000
    assert eps[1]['max_output_tokens'] == 384_000
    assert eps[1]['thinking_compatibility'] is True
    assert eps[2]['status'] == 'paused'
    assert eps[2]['enabled'] == 0
    assert [e['id'] for e in ajdb.list_agent_judge_endpoints(cid, enabled_only=True)] == [
        eps[0]['id'], eps[1]['id'],
    ]


def test_agent_judge_endpoint_status_transitions_respect_manual_disabled(client):
    cid = _make_comp()
    ajdb.save_agent_judge_endpoints(cid, [
        {'harness': 'codex', 'base_url': 'https://enabled/v1', 'api_key': 'k1',
         'model': 'model-a', 'concurrency_limit': 1, 'status': 'enabled'},
        {'harness': 'codex', 'base_url': 'https://disabled/v1', 'api_key': 'k2',
         'model': 'model-b', 'concurrency_limit': 1, 'status': 'disabled'},
    ])
    eps = ajdb.list_agent_judge_endpoints(cid)
    enabled_id, disabled_id = eps[0]['id'], eps[1]['id']

    assert ajdb.pause_agent_judge_endpoint(enabled_id) == 1
    assert ajdb.pause_agent_judge_endpoint(disabled_id) == 0
    by_id = {e['id']: e for e in ajdb.list_agent_judge_endpoints(cid)}
    assert by_id[enabled_id]['status'] == 'paused'
    assert by_id[disabled_id]['status'] == 'disabled'

    assert ajdb.resume_paused_agent_judge_endpoint(disabled_id) == 0
    assert ajdb.resume_paused_agent_judge_endpoint(enabled_id) == 1
    by_id = {e['id']: e for e in ajdb.list_agent_judge_endpoints(cid)}
    assert by_id[enabled_id]['status'] == 'enabled'
    assert by_id[disabled_id]['status'] == 'disabled'


def test_existing_endpoint_edit_without_capabilities_preserves_saved_values(client):
    cid = _make_comp()
    ajdb.save_agent_judge_endpoints(cid, [{
        'harness': 'pi',
        'protocol': 'openai',
        'base_url': 'https://models.example/v1',
        'api_key': 'k1',
        'model': 'custom-thinking-model',
        'context_window_tokens': 262_144,
        'max_output_tokens': 65_536,
        'thinking_compatibility': False,
        'concurrency_limit': 1,
        'status': 'enabled',
    }])
    saved = ajdb.list_agent_judge_endpoints(cid)[0]

    # 模拟尚未认识新字段的旧前端/CLI：只回传旧契约字段，并留空密钥沿用。
    ajdb.save_agent_judge_endpoints(cid, [{
        'id': saved['id'],
        'harness': saved['harness'],
        'base_url': saved['base_url'],
        'api_key': '',
        'model': saved['model'],
        'concurrency_limit': 2,
        'status': 'paused',
    }])

    updated = ajdb.list_agent_judge_endpoints(cid)[0]
    assert updated['context_window_tokens'] == 262_144
    assert updated['max_output_tokens'] == 65_536
    assert updated['thinking_compatibility'] is False
    assert updated['concurrency_limit'] == 2
    assert updated['status'] == 'paused'
