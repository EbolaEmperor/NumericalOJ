# -*- coding: utf-8 -*-
"""打榜赛（ranking）集成测试。

覆盖 ranking_routes.py + ranking_db.py：
- ranking_list：普通用户只见 active，admin 见全部。
- ranking_create：admin 校验（标题/满分），建库 + 重定向。
- ranking_detail：各 tab（description / submit / leaderboard / matches / all_submissions / edit）；
  inactive 比赛对普通用户 403（重定向）。
- ranking_submit：absolute 模式拦截 _evaluate_ranking_task.delay；
  ELO 模式拦截 _elo_initial_burst_task.apply_async + init_submission_elo_state + retire_excess。
- ranking_edit：ELO 参数范围 clamp 校验。
- ELO start / stop / reset / rebuild：脚本存在校验 + 状态变化。
- delete_match：撤销 ELO 分数变动。
- 附件 upload / download / delete。
- 提交答案/代码下载（owner/admin），删除提交，删除比赛。

约定：
- 任务对象注入在路由模块 oj_modules.routes.ranking_routes 上（_evaluate_ranking_task /
  _elo_initial_burst_task），用 FakeTask 记录 .delay / .apply_async 调用。
- 文件上传用 (BytesIO, filename) 元组走 multipart。
- 字段名 / 中文文案以源码为准。
"""
import io
import os

import pytest

from oj_modules import ranking_db
from oj_modules.routes import ranking_routes
from tests import helpers as h


# --------------------------- 工具 ---------------------------

class _FakeTask:
    """记录 .delay / .apply_async 调用的假任务对象。"""

    def __init__(self):
        self.delay_calls = []
        self.apply_async_calls = []

    def delay(self, *args, **kwargs):
        self.delay_calls.append((args, kwargs))
        return None

    def apply_async(self, *args, **kwargs):
        self.apply_async_calls.append((args, kwargs))
        return None


def _make_competition(scoring_mode='absolute', is_active=1, with_script=False,
                      answer_format='json', elo_initial_rating=1500,
                      elo_k_factor=32, max_score=100):
    """直接经 ranking_db 建一个比赛并按需配置，返回 competition_id。"""
    cid = ranking_db.create_competition(
        title='竞赛-' + scoring_mode, description='desc',
        max_score=max_score, created_by='admin', summary='摘要',
    )
    fields = {'is_active': is_active, 'scoring_mode': scoring_mode,
              'answer_format': answer_format,
              'elo_initial_rating': elo_initial_rating,
              'elo_k_factor': elo_k_factor}
    ranking_db.update_competition(cid, **fields)
    if with_script:
        # 给一个真实存在的脚本文件路径，满足 has_script 判定
        target_dir = ranking_db.competition_scoring_dir(cid)
        os.makedirs(target_dir, exist_ok=True)
        script_path = os.path.join(target_dir, 'score.py')
        with open(script_path, 'w', encoding='utf-8') as fh:
            fh.write("print('{\"winner\":1}')\n")
        ranking_db.update_competition_scoring_script(cid, script_path, 'score.py')
    return cid


def _file(content=b'{}', name='answer.json'):
    return (io.BytesIO(content), name)


# --------------------------- ranking_list ---------------------------

def test_ranking_list_requires_login(client):
    r = client.get('/ranking/')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


def test_ranking_list_normal_user_sees_only_active(client, login):
    h.make_user('lister')
    active = _make_competition(is_active=1)
    inactive = _make_competition(is_active=0)
    login('lister')
    r = client.get('/ranking/')
    assert r.status_code == 200
    # 普通用户走 list_competitions(include_inactive=False)
    visible = ranking_db.list_competitions(include_inactive=False)
    ids = {c['id'] for c in visible}
    assert active in ids
    assert inactive not in ids


def test_ranking_list_admin_sees_inactive(client, admin_login):
    active = _make_competition(is_active=1)
    inactive = _make_competition(is_active=0)
    r = client.get('/ranking/')
    assert r.status_code == 200
    all_comps = ranking_db.list_competitions(include_inactive=True)
    ids = {c['id'] for c in all_comps}
    assert active in ids and inactive in ids


# --------------------------- ranking_create ---------------------------

def test_ranking_create_non_admin_redirected(client, login):
    h.make_user('plain')
    login('plain')
    before = len(ranking_db.list_competitions(include_inactive=True))
    r = client.post('/ranking/create', data={'title': 'x', 'max_score': '100'})
    assert r.status_code in (301, 302)
    # 普通用户被 _require_admin 拒绝，不应建库
    after = len(ranking_db.list_competitions(include_inactive=True))
    assert after == before


def test_ranking_create_empty_title_rejected(client, admin_login):
    before = len(ranking_db.list_competitions(include_inactive=True))
    r = client.post('/ranking/create', data={'title': '   ', 'max_score': '100'})
    assert r.status_code in (301, 302)
    assert after_count() == before


def after_count():
    return len(ranking_db.list_competitions(include_inactive=True))


def test_ranking_create_bad_max_score_rejected(client, admin_login):
    before = after_count()
    r = client.post('/ranking/create', data={'title': '比赛A', 'max_score': '0'})
    assert r.status_code in (301, 302)
    assert after_count() == before
    r2 = client.post('/ranking/create', data={'title': '比赛A', 'max_score': 'abc'})
    assert r2.status_code in (301, 302)
    assert after_count() == before


def test_ranking_create_success(client, admin_login):
    before = after_count()
    r = client.post('/ranking/create',
                    data={'title': '我的打榜赛', 'summary': '摘要内容',
                          'description': '说明', 'max_score': '150'})
    assert r.status_code in (301, 302)
    comps = ranking_db.list_competitions(include_inactive=True)
    assert len(comps) == before + 1
    created = [c for c in comps if c['title'] == '我的打榜赛']
    assert created and created[0]['max_score'] == 150


# --------------------------- ranking_detail tabs ---------------------------

def test_ranking_detail_inactive_blocks_normal_user(client, login):
    h.make_user('viewer')
    cid = _make_competition(is_active=0)
    login('viewer')
    r = client.get(f'/ranking/{cid}/')
    # 普通用户看未开放的比赛 → 重定向回列表
    assert r.status_code in (301, 302)


def test_ranking_detail_description_tab(client, login):
    h.make_user('reader')
    cid = _make_competition(is_active=1)
    login('reader')
    r = client.get(f'/ranking/{cid}/?tab=description')
    assert r.status_code == 200


def test_ranking_detail_submit_tab(client, login):
    h.make_user('submitter')
    cid = _make_competition(is_active=1)
    login('submitter')
    r = client.get(f'/ranking/{cid}/?tab=submit')
    assert r.status_code == 200


def test_ranking_detail_leaderboard_tab(client, login):
    h.make_user('lbuser')
    cid = _make_competition(is_active=1)
    login('lbuser')
    r = client.get(f'/ranking/{cid}/?tab=leaderboard')
    assert r.status_code == 200


def test_ranking_detail_matches_tab(client, login):
    h.make_user('matchuser')
    cid = _make_competition(scoring_mode='elo', is_active=1)
    login('matchuser')
    r = client.get(f'/ranking/{cid}/?tab=matches')
    assert r.status_code == 200


def test_ranking_detail_admin_tabs(client, admin_login):
    cid = _make_competition(is_active=1)
    for tab in ('all_submissions', 'edit'):
        r = client.get(f'/ranking/{cid}/?tab={tab}')
        assert r.status_code == 200, tab


def test_ranking_detail_missing_competition_redirects(client, login):
    h.make_user('nouser')
    login('nouser')
    r = client.get('/ranking/999999/')
    assert r.status_code in (301, 302)


# --------------------------- ranking_submit ---------------------------

def test_ranking_submit_absolute_enqueues_evaluate(client, login, monkeypatch):
    h.make_user('absstud')
    cid = _make_competition(scoring_mode='absolute', is_active=1, answer_format='json')
    login('absstud')

    fake_eval = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', fake_eval)

    data = {
        'base_model': 'qwen3.6-plus',
        'answer_file': _file(b'{"a":1}', 'answer.json'),
        'code_file': _file(b'PK\x03\x04code', 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    # 绝对分模式应入队评测任务，传入 submission_id
    assert len(fake_eval.delay_calls) == 1
    args, _ = fake_eval.delay_calls[0]
    assert isinstance(args[0], int)
    # 提交记录已落库
    subs = ranking_db.list_user_submissions(cid, 'absstud')
    assert len(subs) == 1
    assert subs[0]['base_model'] == 'qwen3.6-plus'


def test_ranking_submit_missing_base_model_rejected(client, login, monkeypatch):
    h.make_user('nobase')
    cid = _make_competition(scoring_mode='absolute', is_active=1)
    login('nobase')
    fake_eval = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', fake_eval)
    data = {
        'answer_file': _file(b'{}', 'answer.json'),
        'code_file': _file(b'PK', 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    # 没填基座模型 → 拒绝，不入队、不建提交
    assert fake_eval.delay_calls == []
    assert ranking_db.list_user_submissions(cid, 'nobase') == []


def test_ranking_submit_wrong_answer_ext_rejected(client, login, monkeypatch):
    h.make_user('wrongext')
    cid = _make_competition(scoring_mode='absolute', is_active=1, answer_format='json')
    login('wrongext')
    fake_eval = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', fake_eval)
    data = {
        'base_model': 'm1',
        'answer_file': _file(b'{}', 'answer.txt'),   # 应为 .json
        'code_file': _file(b'PK', 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert fake_eval.delay_calls == []


def test_ranking_submit_elo_initializes_state_and_bursts(client, login, monkeypatch):
    h.make_user('elostud')
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True,
                            answer_format='json', elo_initial_rating=1500)
    login('elostud')

    fake_burst = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_elo_initial_burst_task', fake_burst)

    data = {
        'base_model': 'qwen',
        'answer_file': _file(b'{"x":1}', 'answer.json'),
        'code_file': _file(b'PKcode', 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    # ELO 模式应调度即时补战，args=[competition_id, submission_id]
    assert len(fake_burst.apply_async_calls) == 1
    aa_args, aa_kwargs = fake_burst.apply_async_calls[0]
    burst_args = aa_kwargs.get('args') if 'args' in aa_kwargs else (aa_args[0] if aa_args else None)
    assert burst_args and int(burst_args[0]) == cid

    subs = ranking_db.list_user_submissions(cid, 'elostud')
    assert len(subs) == 1
    sub = subs[0]
    # init_submission_elo_state：状态 Active、入池、初始分写入
    assert sub['status'] == 'Active'
    assert int(sub['elo_in_pool']) == 1
    assert float(sub['elo_rating']) == 1500.0


def test_ranking_submit_elo_without_script_rejected(client, login, monkeypatch):
    h.make_user('eloreject')
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=False)
    login('eloreject')
    fake_burst = _FakeTask()
    monkeypatch.setattr(ranking_routes, '_elo_initial_burst_task', fake_burst)
    data = {
        'base_model': 'm',
        'answer_file': _file(b'{}', 'answer.json'),
        'code_file': _file(b'PK', 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    # ELO 缺脚本 → 拒绝，不补战、不建提交
    assert fake_burst.apply_async_calls == []
    assert ranking_db.list_user_submissions(cid, 'eloreject') == []


def test_ranking_submit_elo_retires_excess(client, login, monkeypatch):
    """连续 3 次 ELO 提交后，retire_excess_user_submissions(keep_count=2) 只保留最新 2 份在池。"""
    h.make_user('retstud')
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True)
    login('retstud')
    monkeypatch.setattr(ranking_routes, '_elo_initial_burst_task', _FakeTask())

    for i in range(3):
        data = {
            'base_model': f'm{i}',
            'answer_file': _file(b'{}', 'answer.json'),
            'code_file': _file(b'PK', 'code.zip'),
        }
        r = client.post(f'/ranking/{cid}/submit', data=data,
                        content_type='multipart/form-data')
        assert r.status_code in (301, 302)

    subs = ranking_db.list_user_submissions(cid, 'retstud')
    in_pool = [s for s in subs if int(s['elo_in_pool']) == 1]
    retired = [s for s in subs if s['status'] == 'Retired']
    assert len(subs) == 3
    assert len(in_pool) == 2
    assert len(retired) == 1


# --------------------------- ranking_edit ELO 范围校验 ---------------------------

def test_ranking_edit_clamps_elo_params(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1)
    r = client.post(f'/ranking/{cid}/edit', data={
        'title': '编辑后的标题',
        'summary': 's',
        'description': 'd',
        'max_score': '100',
        'is_active': '1',
        'scoring_mode': 'elo',
        'answer_format': 'json',
        'elo_initial_rating': '999999',   # > 5000 上限
        'elo_k_factor': '0',              # < 1 下限
        'elo_max_matches': '5',
        'elo_match_interval_seconds': '1',  # < 5 下限
        'elo_initial_burst': '999',       # > 50 上限
        'elo_max_pairs_per_round': '100', # > 8 上限
        'scoring_script_timeout_seconds': '1',  # < 5 下限
    })
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    # 范围 clamp 验证（见 ranking_routes ELO_*_RANGE）
    assert float(comp['elo_initial_rating']) == 5000.0
    assert float(comp['elo_k_factor']) == 1.0
    assert int(comp['elo_match_interval_seconds']) == 5
    assert int(comp['elo_initial_burst']) == 50
    assert int(comp['elo_max_pairs_per_round']) == 8
    assert int(comp['scoring_script_timeout_seconds']) == 5
    assert comp['title'] == '编辑后的标题'


def test_ranking_edit_empty_title_rejected(client, admin_login):
    cid = _make_competition(is_active=1)
    r = client.post(f'/ranking/{cid}/edit', data={'title': '   ', 'max_score': '100'})
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    assert comp['title'] != '   '


# --------------------------- ELO start / stop / reset / rebuild ---------------------------

def test_elo_start_requires_script(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=False)
    r = client.post(f'/ranking/{cid}/elo/start')
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    # 无脚本不应启动
    assert int(comp['elo_running']) == 0


def test_elo_start_and_stop_toggles_running(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True)
    r = client.post(f'/ranking/{cid}/elo/start')
    assert r.status_code in (301, 302)
    assert int(ranking_db.get_competition(cid)['elo_running']) == 1

    r2 = client.post(f'/ranking/{cid}/elo/stop')
    assert r2.status_code in (301, 302)
    assert int(ranking_db.get_competition(cid)['elo_running']) == 0


def test_elo_start_rejected_for_non_elo(client, admin_login):
    cid = _make_competition(scoring_mode='absolute', is_active=1, with_script=True)
    r = client.post(f'/ranking/{cid}/elo/start')
    assert r.status_code in (301, 302)
    # 非 ELO 模式 → 不启动
    assert int(ranking_db.get_competition(cid)['elo_running']) == 0


def test_elo_reset_clears_matches_and_resets_scores(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True,
                            elo_initial_rating=1500)
    # 造两份在池提交 + 一场对战
    sub_a = ranking_db.create_ranking_submission(cid, 'pa')
    sub_b = ranking_db.create_ranking_submission(cid, 'pb')
    ranking_db.init_submission_elo_state(sub_a, 1500)
    ranking_db.init_submission_elo_state(sub_b, 1500)
    ranking_db.record_elo_match(cid, sub_a, sub_b, winner=1,
                                rating_a_before=1500, rating_b_before=1500,
                                rating_a_after=1516, rating_b_after=1484)
    ranking_db.set_elo_running(cid, True)

    r = client.post(f'/ranking/{cid}/elo/reset')
    assert r.status_code in (301, 302)

    comp = ranking_db.get_competition(cid)
    assert int(comp['elo_running']) == 0
    matches, _, total = ranking_db.list_competition_matches(cid)
    assert total == 0
    # 在池提交分数恢复到初始分
    a = ranking_db.get_ranking_submission(sub_a)
    assert float(a['elo_rating']) == 1500.0
    assert int(a['elo_match_count']) == 0


def test_elo_rebuild_history_replays_matches(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True,
                            elo_initial_rating=1500, elo_k_factor=32)
    sub_a = ranking_db.create_ranking_submission(cid, 'ra')
    sub_b = ranking_db.create_ranking_submission(cid, 'rb')
    ranking_db.init_submission_elo_state(sub_a, 1500)
    ranking_db.init_submission_elo_state(sub_b, 1500)
    # 写入一条快照被人为扰乱的对战（after 不符合公式），rebuild 应纠正
    ranking_db.record_elo_match(cid, sub_a, sub_b, winner=1,
                                rating_a_before=1500, rating_b_before=1500,
                                rating_a_after=9999, rating_b_after=-9999)

    r = client.post(f'/ranking/{cid}/elo/rebuild')
    assert r.status_code in (301, 302)

    # winner=1, K=32, 初始 1500 平手期望 0.5 → A +16, B -16
    a = ranking_db.get_ranking_submission(sub_a)
    b = ranking_db.get_ranking_submission(sub_b)
    assert abs(float(a['elo_rating']) - 1516.0) < 1e-6
    assert abs(float(b['elo_rating']) - 1484.0) < 1e-6


def test_elo_rebuild_rejected_for_non_elo(client, admin_login):
    cid = _make_competition(scoring_mode='absolute', is_active=1)
    r = client.post(f'/ranking/{cid}/elo/rebuild')
    assert r.status_code in (301, 302)  # flash 该比赛不是 ELO 模式 + redirect


# --------------------------- delete_match 回滚 ---------------------------

def test_delete_match_reverts_scores(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1, with_script=True)
    sub_a = ranking_db.create_ranking_submission(cid, 'da')
    sub_b = ranking_db.create_ranking_submission(cid, 'db')
    ranking_db.init_submission_elo_state(sub_a, 1500)
    ranking_db.init_submission_elo_state(sub_b, 1500)
    # record_elo_match 会把 A/B 的 elo_rating 设为 after，并各 +1 match_count
    ranking_db.record_elo_match(cid, sub_a, sub_b, winner=1,
                                rating_a_before=1500, rating_b_before=1500,
                                rating_a_after=1516, rating_b_after=1484)
    match_row, _, total = ranking_db.list_competition_matches(cid)
    assert total == 1
    match_id = match_row[0]['id']

    r = client.post(f'/ranking/{cid}/match/{match_id}/delete')
    assert r.status_code in (301, 302)

    # 对战删除
    _, _, total_after = ranking_db.list_competition_matches(cid)
    assert total_after == 0
    # 分数回滚到对战前（delta_a = +16，撤销后回 1500），match_count -1 → 0
    a = ranking_db.get_ranking_submission(sub_a)
    b = ranking_db.get_ranking_submission(sub_b)
    assert abs(float(a['elo_rating']) - 1500.0) < 1e-6
    assert abs(float(b['elo_rating']) - 1500.0) < 1e-6
    assert int(a['elo_match_count']) == 0
    assert int(b['elo_match_count']) == 0


def test_delete_match_missing_redirects(client, admin_login):
    cid = _make_competition(scoring_mode='elo', is_active=1)
    r = client.post(f'/ranking/{cid}/match/999999/delete')
    assert r.status_code in (301, 302)  # 对战记录不存在 + redirect


# --------------------------- 附件 upload / download / delete ---------------------------

def test_attachment_upload_and_download(client, admin_login):
    cid = _make_competition(is_active=1)
    r = client.post(f'/ranking/{cid}/upload_attachment',
                    data={'attachment': _file(b'hello-data', 'note.txt')},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    files = ranking_db.list_competition_files(cid)
    assert len(files) == 1
    fid = files[0]['id']
    assert files[0]['filename'] == 'note.txt'

    # 下载（登录用户即可）
    rd = client.get(f'/ranking/{cid}/attachment/{fid}/download')
    assert rd.status_code == 200
    assert rd.data == b'hello-data'


def test_attachment_upload_empty_rejected(client, admin_login):
    cid = _make_competition(is_active=1)
    r = client.post(f'/ranking/{cid}/upload_attachment',
                    data={'attachment': _file(b'', '')},
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert ranking_db.list_competition_files(cid) == []


def test_attachment_delete(client, admin_login):
    cid = _make_competition(is_active=1)
    client.post(f'/ranking/{cid}/upload_attachment',
                data={'attachment': _file(b'x', 'a.bin')},
                content_type='multipart/form-data')
    fid = ranking_db.list_competition_files(cid)[0]['id']
    r = client.post(f'/ranking/{cid}/attachment/{fid}/delete')
    assert r.status_code in (301, 302)
    assert ranking_db.list_competition_files(cid) == []


def test_attachment_download_requires_login(client):
    cid = _make_competition(is_active=1)
    r = client.get(f'/ranking/{cid}/attachment/1/download')
    assert r.status_code in (301, 302)  # 未登录重定向到 login


def test_clear_scoring_script(client, admin_login):
    cid = _make_competition(scoring_mode='absolute', is_active=1, with_script=True,
                            answer_format='json')
    assert (ranking_db.get_competition(cid)['scoring_script_path'] or '').strip()
    r = client.post(f'/ranking/{cid}/clear_scoring_script')
    assert r.status_code in (301, 302)
    comp = ranking_db.get_competition(cid)
    assert not (comp['scoring_script_path'] or '')


# --------------------------- 提交文件下载 / 删除提交 ---------------------------

def test_download_submission_answer_owner_and_other(client, login, monkeypatch):
    h.make_user('owner1')
    h.make_user('other1')
    cid = _make_competition(scoring_mode='absolute', is_active=1, answer_format='json')
    login('owner1')
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', _FakeTask())
    client.post(f'/ranking/{cid}/submit',
                data={'base_model': 'm',
                      'answer_file': _file(b'{"k":1}', 'answer.json'),
                      'code_file': _file(b'PK', 'code.zip')},
                content_type='multipart/form-data')
    sub = ranking_db.list_user_submissions(cid, 'owner1')[0]
    sid = sub['id']

    # owner 可下载答案
    r = client.get(f'/ranking/submission/{sid}/answer')
    assert r.status_code == 200
    assert r.data == b'{"k":1}'

    # 他人不可下载 → 404
    login('other1')
    r2 = client.get(f'/ranking/submission/{sid}/answer')
    assert r2.status_code == 404


def test_download_submission_code_admin(client, login, admin_login, monkeypatch):
    h.make_user('codeowner')
    cid = _make_competition(scoring_mode='absolute', is_active=1)
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', _FakeTask())
    login('codeowner')
    client.post(f'/ranking/{cid}/submit',
                data={'base_model': 'm',
                      'answer_file': _file(b'{}', 'answer.json'),
                      'code_file': _file(b'ZIPBYTES', 'code.zip')},
                content_type='multipart/form-data')
    sid = ranking_db.list_user_submissions(cid, 'codeowner')[0]['id']
    # admin 可下载任意人的代码
    login('admin')
    r = client.get(f'/ranking/submission/{sid}/code')
    assert r.status_code == 200
    assert r.data == b'ZIPBYTES'


def test_ranking_delete_submission(client, login, admin_login, monkeypatch):
    h.make_user('delsub')
    cid = _make_competition(scoring_mode='absolute', is_active=1)
    monkeypatch.setattr(ranking_routes, '_evaluate_ranking_task', _FakeTask())
    login('delsub')
    client.post(f'/ranking/{cid}/submit',
                data={'base_model': 'm',
                      'answer_file': _file(b'{}', 'answer.json'),
                      'code_file': _file(b'PK', 'code.zip')},
                content_type='multipart/form-data')
    sid = ranking_db.list_user_submissions(cid, 'delsub')[0]['id']

    login('admin')
    r = client.post(f'/ranking/{cid}/submission/{sid}/delete')
    assert r.status_code in (301, 302)
    assert ranking_db.get_ranking_submission(sid) is None
    assert ranking_db.list_user_submissions(cid, 'delsub') == []


# --------------------------- 删除比赛 ---------------------------

def test_ranking_delete_competition(client, admin_login):
    cid = _make_competition(is_active=1)
    r = client.post(f'/ranking/{cid}/delete')
    assert r.status_code in (301, 302)
    assert ranking_db.get_competition(cid) is None


def test_ranking_delete_competition_non_admin(client, login):
    h.make_user('deldenied')
    cid = _make_competition(is_active=1)
    login('deldenied')
    r = client.post(f'/ranking/{cid}/delete')
    assert r.status_code in (301, 302)
    # 普通用户无权删除
    assert ranking_db.get_competition(cid) is not None


# --------------------------- ELO 井字棋打榜赛端到端 ---------------------------

# 井字棋评分脚本：读入两名选手的策略（answer.json 的 strategy 字段），对战两局
# （交换先后手）后输出 {"winner": 0|1|2}（0 平局 / 1 第一个选手胜 / 2 第二个选手胜）。
_TICTACTOE_SCORER = '''
import sys, json

WINS = [(0,1,2),(3,4,5),(6,7,8),(0,3,6),(1,4,7),(2,5,8),(0,4,8),(2,4,6)]


def load_strategy(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return str(json.load(f).get("strategy", "first_empty"))
    except Exception:
        return "first_empty"


def winner_of(board):
    for a, b, c in WINS:
        if board[a] != " " and board[a] == board[b] == board[c]:
            return board[a]
    return None


def choose(board, strat):
    empties = [i for i, c in enumerate(board) if c == " "]
    if strat == "center_first" and 4 in empties:
        return 4
    return empties[0]


def play(strat_x, strat_o):
    board = [" "] * 9
    strat = {"X": strat_x, "O": strat_o}
    turn = "X"
    for _ in range(9):
        mv = choose(board, strat[turn])
        if board[mv] != " ":
            return "O" if turn == "X" else "X"
        board[mv] = turn
        w = winner_of(board)
        if w:
            return w
        turn = "O" if turn == "X" else "X"
    return "draw"


def main():
    sa = load_strategy(sys.argv[1])
    sb = load_strategy(sys.argv[2])
    g1 = play(sa, sb)
    g2 = play(sb, sa)
    a = b = 0
    if g1 == "X":
        a += 1
    elif g1 == "O":
        b += 1
    if g2 == "X":
        b += 1
    elif g2 == "O":
        a += 1
    winner = 1 if a > b else (2 if b > a else 0)
    print(json.dumps({"winner": winner, "details": {"g1": g1, "g2": g2}}))


main()
'''


def _submit_strategy(client, login, cid, username, strategy):
    """让 username 以某策略提交一份 ELO 答案，返回 submission_id。"""
    h.make_user(username)
    login(username)
    data = {
        'base_model': 'ttt-bot',
        'answer_file': (io.BytesIO(('{"strategy": "%s"}' % strategy).encode()), 'answer.json'),
        'code_file': (io.BytesIO(b'PKdummyzip'), 'code.zip'),
    }
    r = client.post(f'/ranking/{cid}/submit', data=data,
                    content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    subs = ranking_db.list_user_submissions(cid, username)
    assert subs, f'{username} 的提交未落库'
    return subs[0]['id']


def test_elo_tictactoe_competition_runs_rounds_without_errors(client, login, monkeypatch):
    """ELO 井字棋打榜赛：两个用户提交不同策略，ELO 系统跑若干轮匹配，全程无报错。

    评分脚本让两名选手对战两局（交换先后手）后给出胜/负/平；ELO 任务据此调分。
    """
    import oj

    # 1) 建 ELO 比赛
    cid = ranking_db.create_competition(
        title='井字棋 ELO 赛', description='固定交互：每方一个策略，对战两局交换先后手',
        max_score=100, created_by='admin', summary='井字棋',
    )
    ranking_db.update_competition(
        cid, is_active=1, scoring_mode='elo', answer_format='json',
        elo_initial_rating=1500, elo_k_factor=32,
    )

    # 2) 写入井字棋评分脚本并登记（ELO 提交要求脚本已存在）
    sdir = ranking_db.competition_scoring_dir(cid)
    os.makedirs(sdir, exist_ok=True)
    spath = os.path.join(sdir, 'score.py')
    with open(spath, 'w', encoding='utf-8') as fh:
        fh.write(_TICTACTOE_SCORER)
    ranking_db.update_competition_scoring_script(cid, spath, 'score.py')

    # 3) 开启 ELO 动态评分（match 任务要求 elo_running==1）
    ranking_db.set_elo_running(cid, True)

    # 提交时的“即时补战”任务不真正入队（测试无 worker）
    monkeypatch.setattr(ranking_routes, '_elo_initial_burst_task', _FakeTask())

    # 4) 两个用户提交两份不同策略
    sub_a = _submit_strategy(client, login, cid, 'ttt_alice', 'center_first')
    sub_b = _submit_strategy(client, login, cid, 'ttt_bob', 'first_empty')
    assert sub_a != sub_b

    # 5) 让 ELO 系统进行若干轮匹配（交替先后手，模拟匹配器自然调度的多轮对战）
    rounds = 5
    for i in range(rounds):
        a, b = (sub_a, sub_b) if i % 2 == 0 else (sub_b, sub_a)
        res = oj.ranking_elo_match.apply(args=[cid, a, b]).get()
        assert res.get('success') is True, res
        assert res.get('winner') in (0, 1, 2), res

    # 6) 检查无报错：对局正常记录，没有 winner=-1 的“评测失败”占位行
    rows, _page, total = ranking_db.list_competition_matches(cid, per_page=100)
    assert total >= rounds
    assert all(int(m['winner']) in (0, 1, 2) for m in rows), rows

    # 7) ELO 分数被正常更新（零和；first_empty 先手能连成 0-3-6，bob 占优）
    ra = float(ranking_db.get_ranking_submission(sub_a)['elo_rating'])
    rb = float(ranking_db.get_ranking_submission(sub_b)['elo_rating'])
    assert abs((ra - 1500) + (rb - 1500)) < 1e-6      # 零和
    assert rb >= ra                                    # bob 策略更强，分数不低于 alice

    # 8) 排行榜可正常生成
    lb = ranking_db.get_leaderboard(cid)
    assert isinstance(lb, list) and len(lb) >= 2


def test_ranking_match_delete_ajax_keeps_page_and_returns_json(client, admin_login):
    """对战数据页删除逻辑：AJAX 删除返回 JSON（不重定向）；matches_json 按传入 page
    返回列表片段，供前端就地刷新当前页（不跳回第 1 页）。非 AJAX 仍走重定向兜底。"""
    cid = ranking_db.create_competition(
        title='删除对战测试', description='d', max_score=100,
        created_by='admin', summary='s')
    ranking_db.update_competition(cid, is_active=1, scoring_mode='elo')
    h.make_user('mj_a')
    h.make_user('mj_b')
    sa = ranking_db.create_ranking_submission(cid, 'mj_a')
    sb = ranking_db.create_ranking_submission(cid, 'mj_b')
    ranking_db.init_submission_elo_state(sa, 1500)
    ranking_db.init_submission_elo_state(sb, 1500)
    for _ in range(3):
        ranking_db.record_elo_match(cid, sa, sb, 1, 1500, 1500, 1516, 1484)

    rows0, _p0, total0 = ranking_db.list_competition_matches(cid, per_page=100)
    assert total0 == 3

    # matches_json：保持传入 page，返回 html/total/page 片段
    r = client.get(f'/ranking/{cid}/matches_json?page=1',
                   headers={'X-Requested-With': 'XMLHttpRequest'})
    assert r.status_code == 200
    data = r.get_json()
    assert data['total'] == 3 and data['page'] == 1
    assert 'html' in data and 'mj_a' in data['html']

    # AJAX 删除：返回 JSON（不是 302 重定向），对战被删除
    mid = rows0[0]['id']
    r2 = client.post(f'/ranking/{cid}/match/{mid}/delete',
                     headers={'X-Requested-With': 'XMLHttpRequest'})
    assert r2.status_code == 200
    assert r2.get_json()['success'] is True
    _r1, _p1, total1 = ranking_db.list_competition_matches(cid, per_page=100)
    assert total1 == 2

    # 非 AJAX 删除仍走重定向（无 JS 兜底，向后兼容）
    mid2 = _r1[0]['id']
    r3 = client.post(f'/ranking/{cid}/match/{mid2}/delete')
    assert r3.status_code in (301, 302)
