# -*- coding: utf-8 -*-
"""agent_judge 集成测试：提交分派、规则保存、配置编辑、SSE 快照。"""
import io

import pytest

from oj_modules import ranking_db
from oj_modules import ranking_agent_judge_db as ajdb
from oj_modules.routes import ranking_routes
from tests import helpers as h


class _FakeTask:
    def __init__(self):
        self.delay_calls = []

    def delay(self, *a, **k):
        self.delay_calls.append((a, k))
        return None


def _make_aj_comp(configured=True, with_rules=True):
    cid = ranking_db.create_competition(title='AJ赛', description='desc', max_score=100,
                                        created_by='admin', summary='s')
    fields = {'is_active': 1, 'scoring_mode': 'agent_judge'}
    if configured:
        fields.update(agent_judge_base_url='https://x/anthropic',
                      agent_judge_api_key='k-123', agent_judge_model='mimo-v2.5-pro')
    ranking_db.update_competition(cid, **fields)
    if with_rules:
        ajdb.replace_competition_rules(cid, [
            {'rule_id': 1, 'rule_text': '能运行', 'value': 10, 'dependencies': []},
            {'rule_id': 2, 'rule_text': '输出正确', 'value': 20, 'dependencies': [1]},
        ])
    return cid


def _zip(name='code.zip', content=b'PK\x03\x04'):
    return (io.BytesIO(content), name)


def test_submit_agent_judge_enqueues_task(client, login, monkeypatch):
    h.make_user('ajstud')
    cid = _make_aj_comp()
    login('ajstud')
    fake = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', fake)
    r = client.post(f'/ranking/{cid}/submit',
                    data={'base_model': 'm', 'code_file': _zip()},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert len(fake.delay_calls) == 1
    subs = ranking_db.list_user_submissions(cid, 'ajstud')
    assert len(subs) == 1
    assert subs[0]['status'] == 'Judging'
    assert (subs[0].get('answer_path') in (None, ''))


def test_submit_blocked_without_config(client, login, monkeypatch):
    h.make_user('ajnoconf')
    cid = _make_aj_comp(configured=False)
    login('ajnoconf')
    fake = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', fake)
    r = client.post(f'/ranking/{cid}/submit',
                    data={'base_model': 'm', 'code_file': _zip()},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert fake.delay_calls == []
    assert ranking_db.list_user_submissions(cid, 'ajnoconf') == []


def test_submit_blocked_without_rules(client, login, monkeypatch):
    h.make_user('ajnorule')
    cid = _make_aj_comp(with_rules=False)
    login('ajnorule')
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', _FakeTask())
    r = client.post(f'/ranking/{cid}/submit',
                    data={'base_model': 'm', 'code_file': _zip()},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert ranking_db.list_user_submissions(cid, 'ajnorule') == []


def test_save_rules_endpoint(client, admin_login):
    cid = ranking_db.create_competition(title='r', description='d', max_score=1,
                                        created_by='admin', summary='s')
    ranking_db.update_competition(cid, scoring_mode='agent_judge')
    r = client.post(f'/ranking/{cid}/agent_judge/rules', json={'rules': [
        {'rule_id': 1, 'rule_text': 'a', 'value': 10, 'dependencies': []},
        {'rule_id': 2, 'rule_text': 'b', 'value': 30, 'dependencies': [1]},
    ]})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] and body['count'] == 2 and body['max_score'] == 40.0
    assert int(ranking_db.get_competition(cid)['max_score']) == 40


def test_save_rules_rejects_cycle(client, admin_login):
    cid = ranking_db.create_competition(title='r', description='d', max_score=1,
                                        created_by='admin', summary='s')
    ranking_db.update_competition(cid, scoring_mode='agent_judge')
    r = client.post(f'/ranking/{cid}/agent_judge/rules', json={'rules': [
        {'rule_id': 1, 'rule_text': 'a', 'value': 1, 'dependencies': [2]},
        {'rule_id': 2, 'rule_text': 'b', 'value': 1, 'dependencies': [1]},
    ]})
    assert r.status_code == 400
    assert ajdb.list_competition_rules(cid) == []


def test_edit_saves_config_without_echoing_key(client, admin_login):
    cid = _make_aj_comp(configured=False, with_rules=False)
    r = client.post(f'/ranking/{cid}/edit', data={
        'title': 'AJ', 'summary': 's', 'description': 'd', 'max_score': '100',
        'is_active': '1', 'scoring_mode': 'agent_judge', 'answer_format': 'json',
        'agent_judge_base_url': 'https://gw/anthropic',
        'agent_judge_model': 'mimo-v2.5-pro',
        'agent_judge_api_key': 'secret-key',
        'agent_judge_timeout_seconds': '900',
    })
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    assert comp['agent_judge_base_url'] == 'https://gw/anthropic'
    assert comp['agent_judge_model'] == 'mimo-v2.5-pro'
    assert comp['agent_judge_api_key'] == 'secret-key'
    assert int(comp['agent_judge_timeout_seconds']) == 900
    # 再次编辑时 api_key 留空 → 不变
    client.post(f'/ranking/{cid}/edit', data={
        'title': 'AJ', 'scoring_mode': 'agent_judge', 'agent_judge_api_key': '',
        'agent_judge_base_url': 'https://gw2/anthropic', 'max_score': '100',
    })
    comp2 = ranking_db.get_competition(cid)
    assert comp2['agent_judge_api_key'] == 'secret-key'
    assert comp2['agent_judge_base_url'] == 'https://gw2/anthropic'


def test_judge_stream_emits_done_for_finished(client, login):
    h.make_user('ajstream')
    cid = _make_aj_comp()
    login('ajstream')
    sid = ranking_db.create_ranking_submission(cid, 'ajstream')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 10.0, 'ok')
    ranking_db.update_submission_result(sid, 10.0, 'Accepted',
                                        grade_details={'total_score': 10, 'max_score': 30})
    r = client.get(f'/ranking/{cid}/judge_stream/{sid}')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert 'event: progress' in body
    assert 'event: done' in body


def test_rejudge_agent_requeues(client, admin_login, monkeypatch):
    cid = _make_aj_comp()
    sid = ranking_db.create_ranking_submission(cid, 'admin')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 10.0, 'ok')
    fake = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', fake)
    r = client.post(f'/ranking/{cid}/submission/{sid}/rejudge_agent')
    assert r.status_code in (301, 302)
    assert len(fake.delay_calls) == 1
    assert ajdb.list_judge_results(sid) == []
    assert ranking_db.get_ranking_submission(sid)['status'] == 'Judging'


def test_admin_can_submit_to_inactive_competition(client, admin_login, monkeypatch):
    # 已下线比赛 + 评分配置正确 → 管理员仍可提交
    cid = _make_aj_comp()
    ranking_db.update_competition(cid, is_active=0)
    fake = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', fake)
    r = client.post(f'/ranking/{cid}/submit',
                    data={'base_model': 'm', 'code_file': _zip()},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert len(fake.delay_calls) == 1
    assert len(ranking_db.list_user_submissions(cid, 'admin')) == 1


def test_non_admin_blocked_on_inactive_competition(client, login, monkeypatch):
    h.make_user('inactstud')
    cid = _make_aj_comp()
    ranking_db.update_competition(cid, is_active=0)
    login('inactstud')
    fake = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_agent_judge_task', fake)
    r = client.post(f'/ranking/{cid}/submit',
                    data={'base_model': 'm', 'code_file': _zip()},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert fake.delay_calls == []
    assert ranking_db.list_user_submissions(cid, 'inactstud') == []
