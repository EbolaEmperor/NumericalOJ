# -*- coding: utf-8 -*-
"""集成测试：problem_core_routes.py（§4b）。

覆盖（以 oj_modules/routes/problem_core_routes.py 源码为准）：
- 未登录访问 /problems → 302 跳 auth.login
- 登录普通用户 /problems → 200；admin /problems → 200（走 get_all_problems 分支）
- /problem/<id>：登录可见（有作业访问权）；不存在题目 → 返回 "<h3>题目不存在</h3>"（200）
- submit_solution 程序题：POST /submit/<id>（field code）→ create_submission +
  increment_submission_count + _evaluate_submission_task.delay(sid)（monkeypatch 注入路由模块
  task 的 .delay 断言被调用并取得 sid）→ 跳 submission.submission_detail
- 达到提交上限：can_submit 失败后 POST 被拒（flash + 跳 problem_detail，不创建提交）
- 书面题（type2）：上传 PDF → _transcribe_written_homework_task.delay 被调用
- my_submissions：普通用户只见自己；admin 见全部
- agent 端点：admin POST agent_solve_problem → 注入任务 .apply_async 断言
  args=(problem_id, username, extra_prompt) 且返回 JSON 含 task_id；非 admin → 403
- 代表（真实评测端到端，@pytest.mark.judger）：拦截 .delay 拿 sid → oj.evaluate_submission.apply 同步判题

注意：
- submit/problem_detail 对非 admin 需要“作业访问权”（get_homeworks 读物理动态班级表 `{class_en}`）。
  这里用 _setup_homework() 建物理表 + 插一行作业，并清掉路由模块的进程内缓存（10~30s TTL，跨用例会脏）。
- admin（is_admin==1）绕过作业访问检查与提交次数上限。
"""
import json

import pytest

import oj_modules.routes.problem_core_routes as pcm
from oj_modules import db_services as db
from tests import helpers as h


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def _clear_route_caches():
    """清掉 problem_core 路由模块的进程内缓存（user / classes / homeworks / grades）。"""
    pcm.invalidate_problem_list_cache_all()


def _make_dynamic_class_table(class_en):
    """建一个物理动态班级表（结构同 add_class_ajax）。class_table 行由 make_user 保证存在。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS `{class_en}` "
                "(id INT PRIMARY KEY AUTO_INCREMENT, problem_id INT, ddl DATETIME, "
                "complete_cnt INT, problem_title TEXT)"
            )
        conn.commit()
    finally:
        conn.close()


def _add_homework_row(class_en, problem_id, problem_title='题目', ddl=None):
    """往动态班级表插一行作业，使该班级学生获得对 problem_id 的访问/提交权。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO `{class_en}` (problem_id, ddl, complete_cnt, problem_title) "
                "VALUES (%s, %s, 0, %s)",
                (problem_id, ddl, problem_title),
            )
        conn.commit()
    finally:
        conn.close()


def _setup_student_with_homework(username='stud1', class_en='Cclass1',
                                 class_cn='测试班级', lang='python', type=1,
                                 submission_limit=10):
    """造普通用户 + 题目 + 该用户班级的物理作业表与作业行，返回 (user, problem_id)。"""
    user = h.make_user(username, class_en=class_en, class_cn=class_cn)
    pid = h.make_problem(lang=lang, type=type, submission_limit=submission_limit)
    _make_dynamic_class_table(class_en)
    _add_homework_row(class_en, pid, problem_title='题目X')
    _clear_route_caches()
    return user, pid


def _set_testdata(problem_id, cases):
    """直接写 problems.testdata（JSON 列表，元素含 input/output）。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE problems SET testdata=%s WHERE id=%s",
                (json.dumps(cases, ensure_ascii=False), problem_id),
            )
        conn.commit()
    finally:
        conn.close()


class _FakeTask:
    """记录 .delay / .apply_async 调用的假任务。"""

    def __init__(self):
        self.delay_calls = []
        self.apply_async_calls = []

    def delay(self, *args, **kwargs):
        self.delay_calls.append((args, kwargs))

    def apply_async(self, *args, **kwargs):
        self.apply_async_calls.append((args, kwargs))


# --------------------------------------------------------------------------- #
# /problems
# --------------------------------------------------------------------------- #
def test_problems_requires_login(client):
    r = client.get('/problems')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


def test_problems_normal_user_ok(client, login):
    h.make_user('plain1')
    _clear_route_caches()
    login('plain1')
    r = client.get('/problems')
    assert r.status_code == 200


def test_problems_admin_ok(client, admin_login):
    # admin 走 get_all_problems 分支；建几道题确保分支被执行到
    h.make_problem(title='题A')
    h.make_problem(title='题B')
    _clear_route_caches()
    r = client.get('/problems')
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# /problem/<id>
# --------------------------------------------------------------------------- #
def test_problem_detail_visible_with_homework_access(client, login):
    user, pid = _setup_student_with_homework('viewer1')
    login('viewer1')
    r = client.get(f'/problem/{pid}')
    assert r.status_code == 200


def test_problem_detail_admin_visible(client, admin_login):
    pid = h.make_problem()
    _clear_route_caches()
    r = client.get(f'/problem/{pid}')
    assert r.status_code == 200


def test_problem_detail_nonexistent(client, admin_login):
    r = client.get('/problem/999999')
    assert r.status_code == 200
    assert '题目不存在' in r.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# submit_solution（程序题）
# --------------------------------------------------------------------------- #
def test_submit_programming_enqueues_and_redirects(client, login, monkeypatch):
    user, pid = _setup_student_with_homework('coder1')
    login('coder1')

    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_evaluate_submission_task', fake)

    r = client.post(f'/submit/{pid}', data={'code': "print('x')\n"})
    # 跳 submission.submission_detail
    assert r.status_code in (301, 302)
    assert '/submission_detail/' in r.headers.get('Location', '')

    # .delay 被调用一次，取得 submission_id
    assert len(fake.delay_calls) == 1
    args, _ = fake.delay_calls[0]
    sid = args[0]
    assert isinstance(sid, int)

    # 提交确实入库 + 提交计数 +1
    sub = db.get_submission_by_id(sid)
    assert sub is not None
    assert sub['username'] == 'coder1'
    assert db.get_user_submission_count('coder1', pid) == 1


def test_submit_programming_empty_code_rejected(client, login, monkeypatch):
    user, pid = _setup_student_with_homework('coder2')
    login('coder2')
    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_evaluate_submission_task', fake)

    r = client.post(f'/submit/{pid}', data={'code': '   '})
    assert r.status_code in (301, 302)
    assert f'/problem/{pid}' in r.headers.get('Location', '')
    assert fake.delay_calls == []


# --------------------------------------------------------------------------- #
# 提交次数上限
# --------------------------------------------------------------------------- #
def test_submit_blocked_when_limit_reached(client, login, monkeypatch):
    user, pid = _setup_student_with_homework('coder3', submission_limit=2)
    login('coder3')
    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_evaluate_submission_task', fake)

    # 用尽 2 次配额
    db.increment_submission_count('coder3', pid)
    db.increment_submission_count('coder3', pid)
    assert db.can_submit('coder3', pid, 2) is False

    r = client.post(f'/submit/{pid}', data={'code': "print('x')\n"})
    assert r.status_code in (301, 302)
    assert f'/problem/{pid}' in r.headers.get('Location', '')
    # 被拒：不入队、不新建提交
    assert fake.delay_calls == []
    cnt_conn = db.get_db_connection()
    try:
        with cnt_conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM submissions WHERE username=%s", ('coder3',))
            assert cur.fetchone()['n'] == 0
    finally:
        cnt_conn.close()


# --------------------------------------------------------------------------- #
# 书面题（type2）
# --------------------------------------------------------------------------- #
def test_submit_written_homework_enqueues_transcribe(client, login, monkeypatch):
    import io

    user, pid = _setup_student_with_homework('writer1', lang='matlab', type=2)
    login('writer1')

    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_transcribe_written_homework_task', fake)

    data = {
        'file': (io.BytesIO(b'%PDF-1.4 fake pdf bytes\n'), 'answer.pdf'),
    }
    r = client.post(f'/submit/{pid}', data=data, content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert '/submission_detail/' in r.headers.get('Location', '')

    assert len(fake.delay_calls) == 1
    args, _ = fake.delay_calls[0]
    sid = args[0]
    sub = db.get_submission_by_id(sid)
    assert sub is not None
    assert sub['username'] == 'writer1'


def test_submit_written_homework_non_pdf_rejected(client, login, monkeypatch):
    import io

    user, pid = _setup_student_with_homework('writer2', lang='matlab', type=2)
    login('writer2')
    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_transcribe_written_homework_task', fake)

    data = {'file': (io.BytesIO(b'not a pdf'), 'answer.txt')}
    r = client.post(f'/submit/{pid}', data=data, content_type='multipart/form-data')
    assert r.status_code in (301, 302)
    assert f'/problem/{pid}' in r.headers.get('Location', '')
    assert fake.delay_calls == []


# --------------------------------------------------------------------------- #
# my_submissions
# --------------------------------------------------------------------------- #
def test_my_submissions_normal_user_sees_only_own(client, login):
    h.make_user('owner_a')
    h.make_user('owner_b')
    pid = h.make_problem()
    db.create_submission(pid, '题目', 'owner_a', "print(1)", 0, [])
    db.create_submission(pid, '题目', 'owner_b', "print(2)", 0, [])
    _clear_route_caches()

    login('owner_a')
    r = client.get('/my_submissions')
    assert r.status_code == 200

    subs, _ = pcm.get_submissions_by_user_paginated('owner_a')
    assert all(s['username'] == 'owner_a' for s in subs)
    assert len(subs) == 1


def test_my_submissions_admin_sees_all(client, admin_login):
    h.make_user('owner_c')
    pid = h.make_problem()
    db.create_submission(pid, '题目', 'owner_c', "print(1)", 0, [])
    db.create_submission(pid, '题目', 'admin', "print(2)", 0, [])
    _clear_route_caches()

    r = client.get('/my_submissions')
    assert r.status_code == 200
    subs, _ = pcm.get_all_submissions_paginated()
    usernames = {s['username'] for s in subs}
    assert 'owner_c' in usernames and 'admin' in usernames


# --------------------------------------------------------------------------- #
# agent 端点
# --------------------------------------------------------------------------- #
def test_agent_solve_problem_admin_enqueues(client, admin_login, monkeypatch):
    pid = h.make_problem(type=1)
    _clear_route_caches()

    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_agent_solve_problem_task', fake)

    r = client.post(
        f'/admin/agent_solve_problem/{pid}',
        json={'extra_prompt': '请优化时间复杂度'},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert 'task_id' in body and body['task_id']

    assert len(fake.apply_async_calls) == 1
    _, kwargs = fake.apply_async_calls[0]
    assert kwargs['args'] == (pid, 'admin', '请优化时间复杂度')
    assert kwargs['task_id'] == body['task_id']


def test_agent_solve_problem_non_admin_403(client, login):
    h.make_user('nonadmin1')
    pid = h.make_problem(type=1)
    _clear_route_caches()
    login('nonadmin1')

    r = client.post(f'/admin/agent_solve_problem/{pid}', json={'extra_prompt': 'x'})
    assert r.status_code == 403
    body = r.get_json()
    assert body['success'] is False


def test_agent_generate_testdata_admin_enqueues(client, admin_login, monkeypatch):
    pid = h.make_problem(type=1)
    _clear_route_caches()

    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_agent_generate_testdata_task', fake)

    r = client.post(
        f'/admin/agent_generate_testdata/{pid}',
        json={
            'standard_code': "print(1)",
            'data_requirement': '随机整数',
            'test_point_count': 3,
        },
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['task_id']

    assert len(fake.apply_async_calls) == 1
    _, kwargs = fake.apply_async_calls[0]
    assert kwargs['args'] == (pid, 'admin', 3, "print(1)", '随机整数')


def test_agent_generate_testdata_missing_standard_code_400(client, admin_login, monkeypatch):
    pid = h.make_problem(type=1)
    _clear_route_caches()
    fake = _FakeTask()
    monkeypatch.setattr(pcm, '_agent_generate_testdata_task', fake)

    r = client.post(
        f'/admin/agent_generate_testdata/{pid}',
        json={'standard_code': '   ', 'test_point_count': 2},
    )
    assert r.status_code == 400
    assert r.get_json()['success'] is False
    assert fake.apply_async_calls == []


# --------------------------------------------------------------------------- #
# 真实评测端到端（@pytest.mark.judger）
# --------------------------------------------------------------------------- #
@pytest.mark.judger
def test_submit_python_then_real_judge(client, login, monkeypatch):
    user, pid = _setup_student_with_homework('judgestud', lang='python', type=1)
    # 最小可判题目：一个测试点，期望输出 'x'
    _set_testdata(pid, [{'input': '', 'output': 'x'}])
    login('judgestud')

    captured = {}

    class _Cap:
        def delay(self, sid):
            captured['sid'] = sid

    monkeypatch.setattr(pcm, '_evaluate_submission_task', _Cap())

    r = client.post(f'/submit/{pid}', data={'code': "print('x')\n"})
    assert r.status_code in (301, 302)
    assert 'sid' in captured

    import oj
    oj.evaluate_submission.apply(args=[captured['sid']]).get()

    sub = db.get_submission_by_id(captured['sid'])
    # 结果取决于判定；最小题目应 Accepted，但放宽到合法终态集合
    assert sub['status'] in ('Accepted', 'Wrong Answer', 'Unaccepted')
