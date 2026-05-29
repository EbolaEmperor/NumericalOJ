# -*- coding: utf-8 -*-
"""集成测试：rejudge_routes.py（§4i）。

覆盖：
- rejudge_problem（admin 鉴权；拦截 _rejudge_task.apply_async 断言按 idx*_REJUDGE_STAGGER_SECONDS
  设置 countdown；提交被重置为 Pending；Redis rejudge:{pid} 写入 {total,done}；无提交 400）
- rejudge_status（progress = int(done/total*100)；未在重测文案）
- rejudge_time_range（缺时间 400；start>end 400；区间无提交 400；预览 too_many；
  超 500 限制 400；confirm 入队）
- rejudge_time_range_status（progress 计算；无进行中重测文案）

约定见 tests/conftest.py、tests/helpers.py。
- 任务对象注入在路由模块 oj_modules.routes.rejudge_routes 上（_rejudge_task），
  用 _FakeTask 记录 .apply_async 调用。
- Redis 客户端 _rds 在跑测时也注入在该模块上；由于真实 Redis 不随 DB 重置而清空，
  这里对涉及 Redis 读写的用例统一用内存假客户端 _FakeRedis 替换 _rds，保证确定性。
源码以 oj_modules/routes/rejudge_routes.py 为准。
"""
from oj_modules import db_services as db
from oj_modules.routes import rejudge_routes
from tests import helpers as h


# --------------------------------------------------------------------------- #
# 测试替身
# --------------------------------------------------------------------------- #
class _FakeTask:
    """记录 .apply_async 调用的假任务对象。"""

    def __init__(self):
        self.apply_async_calls = []

    def apply_async(self, *args, **kwargs):
        self.apply_async_calls.append((args, kwargs))


class _FakeRedis:
    """支持 rejudge_routes 用到的 hset(mapping=)/hincrby/exists/hgetall 的内存假 Redis。"""

    def __init__(self):
        self.store = {}

    def hset(self, key, mapping=None, **kwargs):
        h = self.store.setdefault(key, {})
        if mapping:
            for k, v in mapping.items():
                h[str(k)] = str(v)
        for k, v in kwargs.items():
            h[str(k)] = str(v)

    def hincrby(self, key, field, amount=1):
        h = self.store.setdefault(key, {})
        cur = int(h.get(str(field), 0)) + amount
        h[str(field)] = str(cur)
        return cur

    def exists(self, key):
        return 1 if key in self.store else 0

    def hgetall(self, key):
        return dict(self.store.get(key, {}))


def _patch_fakes(monkeypatch):
    """把路由模块的任务对象与 Redis 客户端替换为测试替身，返回 (fake_task, fake_rds)。"""
    fake_task = _FakeTask()
    fake_rds = _FakeRedis()
    monkeypatch.setattr(rejudge_routes, '_rejudge_task', fake_task)
    monkeypatch.setattr(rejudge_routes, '_rds', fake_rds)
    return fake_task, fake_rds


def _make_submissions(problem_id, owner, n, status=None):
    """造 n 条属于 owner 的程序题提交，返回升序 id 列表。"""
    ids = []
    for _ in range(n):
        ids.append(h.make_submission(problem_id, owner, code='print(1)\n',
                                      problem_title='题目X', status=status))
    return sorted(ids)


# --------------------------------------------------------------------------- #
# rejudge_problem
# --------------------------------------------------------------------------- #
def test_rejudge_problem_requires_admin(client, login, monkeypatch):
    fake_task, _ = _patch_fakes(monkeypatch)
    user = h.make_user('stud_rp')
    pid = h.make_problem(lang='python', type=1)
    _make_submissions(pid, user['username'], 1)
    login(user['username'])

    r = client.post(f'/admin/rejudge_problem/{pid}')
    assert r.status_code == 403
    assert r.get_json()['success'] is False
    assert r.get_json()['message'] == '无权限'
    assert fake_task.apply_async_calls == []


def test_rejudge_problem_no_submissions_returns_400(client, admin_login, monkeypatch):
    _patch_fakes(monkeypatch)
    pid = h.make_problem(lang='python', type=1)
    r = client.post(f'/admin/rejudge_problem/{pid}')
    assert r.status_code == 400
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '该题暂无提交'


def test_rejudge_problem_enqueues_with_stagger_and_resets_pending(client, admin_login, monkeypatch):
    fake_task, fake_rds = _patch_fakes(monkeypatch)
    owner = h.make_user('stud_rp2')
    pid = h.make_problem(lang='python', type=1)
    # 造 3 条并先置成终态，确认重测会把它们重置回 Pending
    ids = _make_submissions(pid, owner['username'], 3, status='Accepted')

    r = client.post(f'/admin/rejudge_problem/{pid}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['message'] == '已开始重测'

    # 入队：每条一次，countdown=idx*_REJUDGE_STAGGER_SECONDS（id 升序对应 idx 升序）
    assert len(fake_task.apply_async_calls) == 3
    seen_ids = []
    for idx, (args, kwargs) in enumerate(fake_task.apply_async_calls):
        sub_id, progress_key = kwargs['args']
        seen_ids.append(sub_id)
        assert progress_key == f'rejudge:{pid}'
        assert kwargs['countdown'] == idx * rejudge_routes._REJUDGE_STAGGER_SECONDS
    assert seen_ids == ids  # 升序入队

    # Redis 进度键写入 total/done
    info = fake_rds.hgetall(f'rejudge:{pid}')
    assert int(info['total']) == 3
    assert int(info['done']) == 0

    # 全部提交已重置为 Pending
    for sid in ids:
        assert db.get_submission_by_id(sid)['status'] == 'Pending'


# --------------------------------------------------------------------------- #
# rejudge_status
# --------------------------------------------------------------------------- #
def test_rejudge_status_not_running(client, monkeypatch):
    _patch_fakes(monkeypatch)
    r = client.get('/admin/rejudge_status/123456')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '该题未在重测或已结束'


def test_rejudge_status_progress_computation(client, monkeypatch):
    _, fake_rds = _patch_fakes(monkeypatch)
    pid = 4242
    # total=4, done=1 → progress = int(1/4*100) = 25
    fake_rds.hset(f'rejudge:{pid}', mapping={'total': 4, 'done': 1})
    r = client.get(f'/admin/rejudge_status/{pid}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['total'] == 4
    assert data['done'] == 1
    assert data['progress'] == 25


# --------------------------------------------------------------------------- #
# rejudge_time_range
# --------------------------------------------------------------------------- #
def test_rejudge_time_range_requires_admin(client, login, monkeypatch):
    fake_task, _ = _patch_fakes(monkeypatch)
    user = h.make_user('stud_tr')
    login(user['username'])
    r = client.post('/admin/rejudge_time_range',
                    json={'start': '2026-01-01T00:00', 'end': '2026-12-31T23:59'})
    assert r.status_code == 403
    assert r.get_json()['message'] == '无权限'
    assert fake_task.apply_async_calls == []


def test_rejudge_time_range_missing_times_returns_400(client, admin_login, monkeypatch):
    _patch_fakes(monkeypatch)
    r = client.post('/admin/rejudge_time_range', json={'start': '', 'end': ''})
    assert r.status_code == 400
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '请提供有效的起始与结束时间'


def test_rejudge_time_range_start_after_end_returns_400(client, admin_login, monkeypatch):
    _patch_fakes(monkeypatch)
    r = client.post('/admin/rejudge_time_range',
                    json={'start': '2026-12-31T23:59', 'end': '2026-01-01T00:00'})
    assert r.status_code == 400
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '起始时间不能晚于结束时间'


def test_rejudge_time_range_empty_range_returns_400(client, admin_login, monkeypatch):
    _patch_fakes(monkeypatch)
    # 久远的窗口里没有任何提交
    r = client.post('/admin/rejudge_time_range',
                    json={'start': '2000-01-01T00:00', 'end': '2000-01-02T00:00'})
    assert r.status_code == 400
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '该时间范围内没有提交'


def test_rejudge_time_range_preview_then_confirm_enqueues(client, admin_login, monkeypatch):
    fake_task, fake_rds = _patch_fakes(monkeypatch)
    owner = h.make_user('stud_tr2')
    pid = h.make_problem(lang='python', type=1)
    ids = _make_submissions(pid, owner['username'], 2)

    window = {'start': '2000-01-01T00:00', 'end': '2099-12-31T23:59'}

    # 1) 预览：不带 confirm_total → preview=true，not too_many
    r1 = client.post('/admin/rejudge_time_range', json=dict(window))
    assert r1.status_code == 200
    p = r1.get_json()
    assert p['success'] is True
    assert p['preview'] is True
    assert p['too_many'] is False
    assert p['total'] == 2
    assert p['max_total'] == rejudge_routes._TIME_RANGE_MAX_TOTAL
    # 规整后的时间（'T'→' '、补秒）回显
    assert p['start'] == '2000-01-01 00:00:00'
    assert p['end'] == '2099-12-31 23:59:00'
    assert 'min_created_at' in p and 'max_created_at' in p
    # 预览阶段不入队
    assert fake_task.apply_async_calls == []

    # 2) 确认：confirm_total == 实际条数 → 入队
    confirm = dict(window)
    confirm['confirm_total'] = 2
    r2 = client.post('/admin/rejudge_time_range', json=confirm)
    assert r2.status_code == 200
    c = r2.get_json()
    assert c['success'] is True
    assert c['message'] == '已开始重测'
    assert c['total'] == 2

    # 入队：每条一次，progress_key 为时间范围共用键
    assert len(fake_task.apply_async_calls) == 2
    for idx, (args, kwargs) in enumerate(fake_task.apply_async_calls):
        sub_id, progress_key = kwargs['args']
        assert progress_key == rejudge_routes._TIME_RANGE_PROGRESS_KEY
        assert kwargs['countdown'] == idx * rejudge_routes._REJUDGE_STAGGER_SECONDS

    # Redis 进度写入 + 提交重置 Pending
    info = fake_rds.hgetall(rejudge_routes._TIME_RANGE_PROGRESS_KEY)
    assert int(info['total']) == 2
    assert int(info['done']) == 0
    for sid in ids:
        assert db.get_submission_by_id(sid)['status'] == 'Pending'


def test_rejudge_time_range_too_many_blocks_confirm(client, admin_login, monkeypatch):
    """超过 _TIME_RANGE_MAX_TOTAL 时：预览 too_many=true；confirm 返回 400 拒绝入队。

    不真造 500+ 条提交（成本高）——把 get_submissions_in_time_range 打桩成返回 501 行。
    """
    fake_task, _ = _patch_fakes(monkeypatch)
    over = rejudge_routes._TIME_RANGE_MAX_TOTAL + 1
    fake_rows = [{'id': i, 'problem_type': 1, 'status': 'Accepted', 'created_at': None}
                 for i in range(1, over + 1)]
    monkeypatch.setattr(rejudge_routes, 'get_submissions_in_time_range',
                        lambda start, end: list(fake_rows))

    window = {'start': '2000-01-01T00:00', 'end': '2099-12-31T23:59'}

    # 预览：too_many=true
    r1 = client.post('/admin/rejudge_time_range', json=dict(window))
    assert r1.status_code == 200
    p = r1.get_json()
    assert p['preview'] is True
    assert p['too_many'] is True
    assert p['total'] == over
    assert p['max_total'] == rejudge_routes._TIME_RANGE_MAX_TOTAL

    # confirm（confirm_total 匹配）但超限 → 400，不入队
    confirm = dict(window)
    confirm['confirm_total'] = over
    r2 = client.post('/admin/rejudge_time_range', json=confirm)
    assert r2.status_code == 400
    c = r2.get_json()
    assert c['success'] is False
    assert str(rejudge_routes._TIME_RANGE_MAX_TOTAL) in c['message']
    assert fake_task.apply_async_calls == []


# --------------------------------------------------------------------------- #
# rejudge_time_range_status
# --------------------------------------------------------------------------- #
def test_rejudge_time_range_status_not_running(client, monkeypatch):
    _patch_fakes(monkeypatch)
    r = client.get('/admin/rejudge_time_range_status')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '当前没有进行中的时间范围重测'


def test_rejudge_time_range_status_progress(client, monkeypatch):
    _, fake_rds = _patch_fakes(monkeypatch)
    # total=3, done=3 → progress=100
    fake_rds.hset(rejudge_routes._TIME_RANGE_PROGRESS_KEY,
                  mapping={'total': 3, 'done': 3})
    r = client.get('/admin/rejudge_time_range_status')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['total'] == 3
    assert data['done'] == 3
    assert data['progress'] == 100
