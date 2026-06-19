# -*- coding: utf-8 -*-
"""agent_judge 集成测试：提交分派、规则保存、配置编辑、SSE 快照。"""
import io
import os

import pytest

from oj_modules import db_services as db
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


class _FakeApplyAsyncTask:
    def __init__(self):
        self.apply_async_calls = []

    def apply_async(self, *a, **k):
        self.apply_async_calls.append((a, k))
        return None


def _make_aj_comp(configured=True, with_rules=True):
    cid = ranking_db.create_competition(title='AJ赛', description='desc', max_score=100,
                                        created_by='admin', summary='s')
    fields = {'is_active': 1, 'scoring_mode': 'agent_judge'}
    if configured:
        fields.update(agent_judge_base_url='https://x/anthropic',
                      agent_judge_api_key='k-123', agent_judge_model='mimo-v2.5-pro')
    ranking_db.update_competition(cid, **fields)
    if configured:
        ajdb.save_agent_judge_endpoints(cid, [{
            'harness': 'claude_code',
            'base_url': 'https://x/anthropic',
            'api_key': 'k-123',
            'model': 'mimo-v2.5-pro',
            'concurrency_limit': 1,
            'enabled': True,
        }])
    if with_rules:
        ajdb.replace_competition_rules(cid, [
            {'rule_id': 1, 'rule_text': '能运行', 'value': 10, 'dependencies': []},
            {'rule_id': 2, 'rule_text': '输出正确', 'value': 20, 'dependencies': [1]},
        ])
    return cid


def _set_rank_created_at(sid, value):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE ranking_submissions SET created_at=%s WHERE id=%s", (value, sid))
        conn.commit()
    finally:
        conn.close()


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
    assert subs[0]['status'] == 'Queued'
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


def test_judge_stream_blocks_other_users_submission(client, login):
    h.make_user('owner')
    h.make_user('viewer')
    cid = _make_aj_comp()
    sid = ranking_db.create_ranking_submission(cid, 'owner')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')
    login('viewer')
    r = client.get(f'/ranking/{cid}/judge_stream/{sid}')
    assert r.status_code == 403


def test_submit_history_has_judge_detail_modal_button(client, login):
    h.make_user('ajhist')
    cid = _make_aj_comp()
    sid = ranking_db.create_ranking_submission(cid, 'ajhist')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')
    login('ajhist')
    r = client.get(f'/ranking/{cid}/?tab=submit')
    body = r.get_data(as_text=True)
    assert r.status_code == 200
    assert f'data-submission-id="{sid}"' in body
    assert f'/ranking/{cid}/judge_stream/{sid}' in body
    assert 'id="judgeDetailModal"' in body
    assert 'judge-detail-btn' in body


def test_judge_stream_renders_markdown_at_serve_time(client, login):
    # 证据存 markdown 源，SSE 下发时实时渲染为 HTML（修复旧提交证据显示源码的 bug）
    h.make_user('ajmd')
    cid = _make_aj_comp()
    login('ajmd')
    sid = ranking_db.create_ranking_submission(cid, 'ajmd')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')
    ajdb.upsert_judge_result(sid, 1, 'pass', 'pass', 10.0, '## 证据\n- **要点**')
    ranking_db.update_submission_result(sid, 10.0, 'Accepted',
                                        grade_details={'total_score': 10, 'max_score': 30})
    r = client.get(f'/ranking/{cid}/judge_stream/{sid}')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    # 下发的快照里 evidence 已渲染（heading + 列表 + 加粗），而非原始 ## 源码
    assert '<h2' in body and '<strong>' in body
    assert 'evidence_html' in body


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
    assert ranking_db.get_ranking_submission(sid)['status'] == 'Queued'


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


def test_save_agent_config_preserves_description_summary_and_online(client, admin_login):
    # 专用端点只改 Agent 配置，不应清空描述/摘要/上线状态（原 bug：经 /edit 保存会清空）
    cid = _make_aj_comp()  # description='desc', summary='s', is_active=1, api_key='k-123'
    r = client.post(f'/ranking/{cid}/agent_judge/config', data={
        'agent_judge_base_url': 'https://gw2/anthropic',
        'agent_judge_model': 'mimo-v2.5-pro',
        'agent_judge_api_key': '',            # 留空 → 不变
        'agent_judge_timeout_seconds': '600',
    })
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    assert comp['description'] == 'desc'
    assert comp['summary'] == 's'
    assert int(comp['is_active']) == 1
    assert comp['agent_judge_base_url'] == 'https://gw2/anthropic'
    assert comp['agent_judge_api_key'] == 'k-123'   # 留空未覆盖
    assert int(comp['agent_judge_timeout_seconds']) == 600


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


def test_ranking_bulk_rejudge_filter_combines_time_user_status(client, admin_login):
    cid = _make_aj_comp()
    sid_ok = ranking_db.create_ranking_submission(cid, 'bulk_owner')
    sid_err = ranking_db.create_ranking_submission(cid, 'bulk_owner')
    sid_wait = ranking_db.create_ranking_submission(cid, 'bulk_owner')
    sid_other = ranking_db.create_ranking_submission(cid, 'bulk_other')
    ranking_db.update_submission_result(sid_ok, 10.0, 'Accepted')
    ranking_db.update_submission_result(sid_err, None, 'Error')
    ranking_db.set_submission_status(sid_wait, 'Queued')
    ranking_db.update_submission_result(sid_other, 9.0, 'Accepted')
    _set_rank_created_at(sid_ok, '2026-03-01 10:00:00')
    _set_rank_created_at(sid_err, '2026-03-01 10:01:00')
    _set_rank_created_at(sid_wait, '2026-03-01 10:02:00')
    _set_rank_created_at(sid_other, '2026-03-01 10:03:00')

    r = client.post(f'/ranking/{cid}/bulk_rejudge/filter', json={
        'start': '2026-03-01T00:00',
        'end': '2026-03-02T00:00',
        'username': 'bulk_owner',
        'statuses': ['accepted', 'abnormal'],
    })
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['too_many'] is False
    ids = [row['id'] for row in data['submissions']]
    assert ids == [sid_err, sid_ok]
    assert sid_wait not in ids
    assert sid_other not in ids


def test_ranking_bulk_rejudge_start_enqueues_creator_task(client, admin_login, monkeypatch):
    cid = _make_aj_comp()
    sid1 = ranking_db.create_ranking_submission(cid, 'bulk_start')
    sid2 = ranking_db.create_ranking_submission(cid, 'bulk_start')
    fake = _FakeApplyAsyncTask()
    saved = {}

    def fake_save(job_id, payload):
        saved[job_id] = dict(payload)

    monkeypatch.setattr(ranking_routes, '_bulk_rejudge_task', fake)
    monkeypatch.setattr(ranking_routes, 'save_bulk_rejudge_job', fake_save)

    r = client.post(f'/ranking/{cid}/bulk_rejudge/start',
                    json={'submission_ids': [sid1, sid2, sid1, 'bad', -1]})
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['total'] == 2
    assert data['interval_seconds'] == ranking_routes._BULK_REJUDGE_INTERVAL_SECONDS
    assert len(fake.apply_async_calls) == 1
    assert data['job_id'] in saved
    assert saved[data['job_id']]['total'] == 2
    assert saved[data['job_id']]['processed'] == 0

    _, kwargs = fake.apply_async_calls[0]
    assert kwargs['args'] == [cid, [sid1, sid2], data['job_id'], 'admin']


def test_ranking_bulk_rejudge_status_reads_progress(client, admin_login, monkeypatch):
    cid = _make_aj_comp()
    job = {
        'competition_id': cid,
        'status': 'finished',
        'total': 2,
        'processed': 2,
        'requeued': 2,
        'created': 0,
        'failed': 0,
        'progress': 100,
        'requeued_ids': [101, 102],
        'created_ids': [],
    }
    monkeypatch.setattr(ranking_routes, 'get_bulk_rejudge_job', lambda job_id: job)
    r = client.get(f'/ranking/{cid}/bulk_rejudge/status/job123')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['done'] is True
    assert data['requeued'] == 2
    assert data['requeued_ids'] == [101, 102]
    assert data['created'] == 0
    assert data['progress'] == 100


def test_clone_ranking_submission_for_rejudge_copies_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cid = _make_aj_comp()
    sid = ranking_db.create_ranking_submission(cid, 'bulk_clone')
    src_dir = ranking_db.submission_dir(sid)
    os.makedirs(src_dir, exist_ok=True)
    answer_path = os.path.join(src_dir, 'answer.json')
    code_path = os.path.join(src_dir, 'code.zip')
    with open(answer_path, 'w', encoding='utf-8') as f:
        f.write('{"score": 1}\n')
    with open(code_path, 'wb') as f:
        f.write(b'PK\x03\x04')
    ranking_db.update_submission_files(
        sid, 'answer.json', answer_path, 'code.zip', code_path, base_model='m',
    )
    ranking_db.update_submission_result(sid, 10.0, 'Accepted')

    new_id, _ = ranking_db.clone_ranking_submission_for_rejudge(
        sid, competition_id=cid, status='Queued',
    )
    cloned = ranking_db.get_ranking_submission(new_id)
    assert cloned['id'] != sid
    assert cloned['competition_id'] == cid
    assert cloned['username'] == 'bulk_clone'
    assert cloned['status'] == 'Queued'
    assert cloned['score'] is None
    assert cloned['base_model'] == 'm'
    assert os.path.isfile(cloned['answer_path'])
    assert os.path.isfile(cloned['code_path'])
    assert cloned['answer_path'] != answer_path
    assert cloned['code_path'] != code_path
