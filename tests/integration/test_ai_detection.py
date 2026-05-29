# -*- coding: utf-8 -*-
"""集成测试：AI 代码检测后台（ai_detection_routes.py）。

覆盖（参考 §6e / §6d / §6b）：
- dashboard 200（仅 MATLAB type1 题目）
- preview（total + samples≤20）
- run_filtered / run / run_single / run_user：拦截路由注入的任务 `.delay`，
  断言调用参数 + 返回 JSON 含 task_id
- problem/<id>、student/<u> 视图
- api/available_models、api/summary、api/tasks
- delete_task（running/pending → 400）
- stop（revoke 被尝试，标记 failed）
- 真实检测 .apply：monkeypatch llm_detector._call_openai_api +
  behavior_detector._get_user_submission_history，断言对 matlab/type1 落库

所有路由要求管理员；未登录/非管理员另行断言。
"""
import json

import pytest

import oj
import oj_modules.routes.ai_detection_routes as ai_routes
from oj_modules import db_services as db
from tests import helpers as h


# --------------------------------------------------------------------------- #
# Fake task：记录 .delay 调用并返回带 .id 的结果对象（路由会读取 task.id）。
# --------------------------------------------------------------------------- #
class _FakeResult:
    def __init__(self, task_id):
        self.id = task_id


class _FakeTask:
    def __init__(self, task_id='fake-task-id'):
        self._task_id = task_id
        self.calls = []

    def delay(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return _FakeResult(self._task_id)


@pytest.fixture
def matlab_problem():
    """一道 MATLAB 程序题（type=1），仪表盘 / 过滤检测都依赖它。"""
    return h.make_problem(title='矩阵求解', lang='matlab', type=1)


def _matlab_submission(problem_id, username='stud_md', score=100, status='Accepted'):
    """造一条 problem_type=1 的 MATLAB 提交，带分数与状态。"""
    h.make_user(username)
    sid = h.make_submission(
        problem_id, username, code='A = [1 2; 3 4];\nx = A\\b;\n',
        score=score, problem_title='矩阵求解', status=status)
    return sid


# --------------------------------------------------------------------------- #
# 权限：未登录 / 非管理员
# --------------------------------------------------------------------------- #
def test_dashboard_requires_admin_redirects_anonymous(client):
    r = client.get('/admin/ai_detection')
    # _require_admin 在页面路由上返回 redirect(auth.login)
    assert r.status_code in (301, 302)


def test_preview_non_admin_unauthorized(client, login):
    h.make_user('plain_user')
    login('plain_user')
    r = client.post('/admin/ai_detection/preview', json={})
    assert r.status_code == 401
    assert r.get_json()['success'] is False


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
def test_dashboard_ok_for_admin(client, admin_login, matlab_problem):
    r = client.get('/admin/ai_detection')
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# preview：total + samples（≤20）
# --------------------------------------------------------------------------- #
def test_preview_returns_total_and_samples(client, admin_login, matlab_problem):
    sid = _matlab_submission(matlab_problem, username='alice_md', score=100)

    r = client.post('/admin/ai_detection/preview', json={'problem_id': matlab_problem})
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['total'] >= 1
    assert isinstance(data['samples'], list)
    assert len(data['samples']) <= 20
    sample = next(s for s in data['samples'] if s['id'] == sid)
    assert sample['username'] == 'alice_md'
    assert sample['problem_id'] == matlab_problem
    # 字段形状：id/username/problem_id/problem_title/score/status
    assert set(sample.keys()) == {
        'id', 'username', 'problem_id', 'problem_title', 'score', 'status'}


def test_preview_samples_capped_at_20(client, admin_login, matlab_problem):
    # 25 个不同用户各一条提交 → total=25 但 samples<=20
    for i in range(25):
        _matlab_submission(matlab_problem, username=f'u_cap_{i}', score=100)

    r = client.post('/admin/ai_detection/preview', json={'problem_id': matlab_problem})
    data = r.get_json()
    assert data['total'] == 25
    assert len(data['samples']) == 20


# --------------------------------------------------------------------------- #
# run_filtered / run / run_single / run_user：拦截 .delay
# --------------------------------------------------------------------------- #
def test_run_filtered_enqueues_task(client, admin_login, monkeypatch):
    fake = _FakeTask('filtered-tid')
    monkeypatch.setattr(ai_routes, '_detect_filtered_task', fake)

    r = client.post('/admin/ai_detection/run_filtered',
                    json={'problem_id': 7, 'username': 'bob', 'deduplicate': '1'})
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['task_id'] == 'filtered-tid'

    assert len(fake.calls) == 1
    args, _ = fake.calls[0]
    filters, model_id = args
    # filters 为 dict，含解析后的 problem_id/username + lang 强制 matlab
    assert filters['problem_id'] == 7
    assert filters['username'] == 'bob'
    assert filters['lang'] == 'matlab'
    # model_id 非法回退 'qwen'
    assert model_id == 'qwen'


def test_run_filtered_no_task_registered_500(client, admin_login, monkeypatch):
    monkeypatch.setattr(ai_routes, '_detect_filtered_task', None)
    r = client.post('/admin/ai_detection/run_filtered', json={})
    assert r.status_code == 500
    assert r.get_json()['success'] is False


def test_run_batch_for_problem_enqueues_task(client, admin_login, matlab_problem, monkeypatch):
    fake = _FakeTask('batch-tid')
    monkeypatch.setattr(ai_routes, '_detect_batch_task', fake)

    r = client.post(f'/admin/ai_detection/run/{matlab_problem}', json={'model_id': 'qwen'})
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['task_id'] == 'batch-tid'

    args, _ = fake.calls[0]
    assert args[0] == matlab_problem
    assert args[1] == 'qwen'


def test_run_batch_problem_not_found_404(client, admin_login, monkeypatch):
    monkeypatch.setattr(ai_routes, '_detect_batch_task', _FakeTask())
    r = client.post('/admin/ai_detection/run/999999', json={})
    assert r.status_code == 404
    assert r.get_json()['success'] is False


def test_run_single_enqueues_task(client, admin_login, monkeypatch):
    fake = _FakeTask('single-tid')
    monkeypatch.setattr(ai_routes, '_detect_single_task', fake)

    r = client.post('/admin/ai_detection/run_single/42', json={'model_id': 'matlab_ai_detect'})
    assert r.status_code == 200
    data = r.get_json()
    assert data['task_id'] == 'single-tid'

    args, _ = fake.calls[0]
    assert args[0] == 42
    # config.ci.py 配了非空 MATLAB_AI_DETECT_API_KEY → matlab_ai_detect 可用，model_id 保留
    assert args[1] == 'matlab_ai_detect'


def test_run_user_enqueues_task(client, admin_login, monkeypatch):
    fake = _FakeTask('user-tid')
    monkeypatch.setattr(ai_routes, '_detect_user_task', fake)

    r = client.post('/admin/ai_detection/run_user/carol', json={})
    assert r.status_code == 200
    data = r.get_json()
    assert data['task_id'] == 'user-tid'

    args, _ = fake.calls[0]
    assert args[0] == 'carol'
    assert args[1] == 'qwen'


# --------------------------------------------------------------------------- #
# problem/<id> 与 student/<u> 视图
# --------------------------------------------------------------------------- #
def test_problem_detail_view_ok(client, admin_login, matlab_problem):
    sid = _matlab_submission(matlab_problem, username='dora_md', score=100)
    # 落一条检测结果，使视图有数据可解析 _evidence/_signals
    db.upsert_ai_detection_result({
        'submission_id': sid,
        'username': 'dora_md',
        'problem_id': matlab_problem,
        'llm_score': 0.9,
        'llm_evidence': json.dumps(['注释过于规范'], ensure_ascii=False),
        'behavior_score': 0.0,
        'behavior_detail': json.dumps([], ensure_ascii=False),
        'final_score': 0.9,
        'risk_level': 'high',
        'task_id': None,
    })
    r = client.get(f'/admin/ai_detection/problem/{matlab_problem}')
    assert r.status_code == 200


def test_problem_detail_not_found_404(client, admin_login):
    r = client.get('/admin/ai_detection/problem/888888')
    assert r.status_code == 404


def test_student_detail_view_ok(client, admin_login, matlab_problem):
    sid = _matlab_submission(matlab_problem, username='evan_md', score=100)
    db.upsert_ai_detection_result({
        'submission_id': sid,
        'username': 'evan_md',
        'problem_id': matlab_problem,
        'final_score': 0.3,
        'risk_level': 'low',
    })
    r = client.get('/admin/ai_detection/student/evan_md')
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# api/available_models, api/summary, api/tasks
# --------------------------------------------------------------------------- #
def test_api_available_models(client, admin_login):
    r = client.get('/admin/ai_detection/api/available_models')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    ids = {m['id'] for m in data['models']}
    assert 'qwen' in ids
    assert 'matlab_ai_detect' in ids
    # qwen 总是可用
    qwen = next(m for m in data['models'] if m['id'] == 'qwen')
    assert qwen['available'] is True


def test_api_summary(client, admin_login, matlab_problem):
    sid = _matlab_submission(matlab_problem, username='frank_md', score=100)
    db.upsert_ai_detection_result({
        'submission_id': sid,
        'username': 'frank_md',
        'problem_id': matlab_problem,
        'final_score': 0.85,
        'risk_level': 'high',
    })
    r = client.get('/admin/ai_detection/api/summary')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    summary = data['summary']
    assert 'level_counts' in summary
    assert 'flagged_users' in summary
    assert 'problem_stats' in summary
    assert summary['level_counts'].get('high') == 1
    assert any(u['username'] == 'frank_md' for u in summary['flagged_users'])


def test_api_tasks(client, admin_login):
    # 先入队一个任务以产生记录（持久化到 MySQL ai_detection_tasks）
    from oj_modules.ai_detection.task_tracker import record_task_submitted
    record_task_submitted('tlist-1', 'single', '提交=1')

    r = client.get('/admin/ai_detection/api/tasks')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert isinstance(data['tasks'], list)
    found = [t for t in data['tasks'] if t.get('task_id') == 'tlist-1']
    assert found
    # type_label 注入（single → 单条检测）
    assert found[0]['type_label'] == '单条检测'


# --------------------------------------------------------------------------- #
# delete_task：running/pending → 400；done → 删除记录
# --------------------------------------------------------------------------- #
def test_delete_task_running_refused_400(client, admin_login):
    from oj_modules.ai_detection.task_tracker import _save
    _save('running-task', {'task_id': 'running-task', 'status': 'running'})

    r = client.post('/admin/ai_detection/api/delete_task/running-task')
    assert r.status_code == 400
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '任务仍在运行中，请先停止再删除'


def test_delete_task_done_deletes_results(client, admin_login, matlab_problem):
    from oj_modules.ai_detection.task_tracker import _save
    sid = _matlab_submission(matlab_problem, username='gwen_md', score=100)
    db.upsert_ai_detection_result({
        'submission_id': sid,
        'username': 'gwen_md',
        'problem_id': matlab_problem,
        'final_score': 0.5,
        'risk_level': 'medium',
        'task_id': 'done-task',
    })
    _save('done-task', {'task_id': 'done-task', 'status': 'done', 'task_type': 'batch'})

    r = client.post('/admin/ai_detection/api/delete_task/done-task')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['deleted_results'] == 1
    # 记录已删除
    assert db.get_ai_detection_result_by_submission(sid) is None


# --------------------------------------------------------------------------- #
# stop：尝试 revoke（FakeTask 无 .app → 异常被吞），把 pending/running 标记 failed
# --------------------------------------------------------------------------- #
def test_stop_marks_failed(client, admin_login, monkeypatch):
    from oj_modules.ai_detection.task_tracker import _save, _load
    # 注入一个简单的 task_ref（route 取第一个非 None 的）
    monkeypatch.setattr(ai_routes, '_detect_single_task', _FakeTask())
    _save('stop-task', {'task_id': 'stop-task', 'status': 'running'})

    r = client.post('/admin/ai_detection/api/stop/stop-task')
    assert r.status_code == 200
    assert r.get_json()['success'] is True

    after = _load('stop-task')
    assert after['status'] == 'failed'
    assert after['error'] == '管理员手动停止'


# --------------------------------------------------------------------------- #
# 真实检测 .apply：单条检测任务同步执行，断言落库（仅 matlab/type1）
# --------------------------------------------------------------------------- #
def test_detect_single_apply_persists_for_matlab(monkeypatch, matlab_problem):
    import oj_modules.ai_detection.llm_detector as llm
    import oj_modules.ai_detection.behavior_detector as beh

    sid = _matlab_submission(matlab_problem, username='harry_md', score=100, status='Accepted')

    # LLM 接缝：固定返回高 ai 概率
    monkeypatch.setattr(
        llm, '_call_openai_api',
        lambda *a, **k: {'score': 0.9, 'confidence': 0.95,
                         'evidence': ['变量命名过于规范'], 'raw_response': 'mock'},
    )
    # 行为接缝：无历史 → behavior_score=0
    monkeypatch.setattr(beh, '_get_user_submission_history', lambda *a, **k: [])

    oj.detect_single_submission.apply(args=[sid, 'qwen']).get()

    row = db.get_ai_detection_result_by_submission(sid)
    assert row is not None
    assert row['username'] == 'harry_md'
    assert row['problem_id'] == matlab_problem
    # final = min(1.0, 0.9 + 0*0.3) = 0.9 → high
    assert abs(float(row['final_score']) - 0.9) < 1e-3
    assert row['risk_level'] == 'high'
    assert abs(float(row['llm_score']) - 0.9) < 1e-3


def test_detect_single_apply_skips_non_matlab(monkeypatch):
    import oj_modules.ai_detection.llm_detector as llm
    import oj_modules.ai_detection.behavior_detector as beh

    # python 题（非 matlab）→ 任务应跳过，不落库
    pid = h.make_problem(title='py题', lang='python', type=1)
    sid = _matlab_submission(pid, username='ivy_py', score=100)

    called = {'llm': False}

    def _fake_llm(*a, **k):
        called['llm'] = True
        return {'score': 0.9, 'confidence': 0.9, 'evidence': [], 'raw_response': ''}

    monkeypatch.setattr(llm, '_call_openai_api', _fake_llm)
    monkeypatch.setattr(beh, '_get_user_submission_history', lambda *a, **k: [])

    oj.detect_single_submission.apply(args=[sid, 'qwen']).get()

    # 非 matlab → 既不调用 LLM，也不落库
    assert called['llm'] is False
    assert db.get_ai_detection_result_by_submission(sid) is None
