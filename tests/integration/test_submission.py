# -*- coding: utf-8 -*-
"""集成测试：submission_routes.py（§4c）。

覆盖：
- submission_list（未登录跳 login；登录 200）
- submission_detail（owner 可见 / 他人无权 / admin 可见 / 不存在）
- submission_status（JSON is_judging 逻辑：Pending→True；终态有分→False；401 未登录；他人 403）
- get_last_submission_code（无记录 404；有记录返回 code）
- get_submission_output_image（无图 404；他人 403）
- submission_status_stream（SSE 取首帧即断开）

约定见 tests/conftest.py、tests/helpers.py。源码以 oj_modules/routes/submission_routes.py 为准：
submission_detail 对非 owner/非 admin 返回的是 200 + 文案字符串（非 HTTP 403），
而 submission_status / get_submission_output_image 返回真实 JSON 403。
"""
import json
import os

import pytest

from oj_modules import db_services as db
from tests import helpers as h


def _make_owned_submission(owner='stud_a', code="print('hi')\n", lang='python',
                           type=1):
    """造一个属于 owner 的程序题提交，返回 (problem_id, submission_id, owner)。"""
    h.make_user(owner)
    pid = h.make_problem(lang=lang, type=type)
    sid = h.make_submission(pid, owner, code=code, problem_title='题目X')
    return pid, sid, owner


# --------------------------------------------------------------------------- #
# submission_list
# --------------------------------------------------------------------------- #
def test_submission_list_requires_login(client):
    pid, sid, _ = _make_owned_submission()
    r = client.get(f'/submissionslist/{pid}')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


def test_submission_list_logged_in_ok(client, login):
    pid, sid, owner = _make_owned_submission()
    login(owner)
    r = client.get(f'/submissionslist/{pid}')
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# submission_detail（owner / 他人 / admin / 不存在）
# --------------------------------------------------------------------------- #
def test_submission_detail_owner_can_view(client, login):
    pid, sid, owner = _make_owned_submission()
    login(owner)
    r = client.get(f'/submission_detail/{sid}')
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert '无权查看他人提交' not in body


def test_submission_detail_other_user_denied(client, login):
    pid, sid, owner = _make_owned_submission()
    other = h.make_user('stud_other')
    login(other['username'])
    r = client.get(f'/submission_detail/{sid}')
    # 源码对非 owner/非 admin 返回 200 + 文案字符串
    assert r.status_code == 200
    assert '无权查看他人提交' in r.get_data(as_text=True)


def test_submission_detail_admin_can_view(client, admin_login):
    pid, sid, owner = _make_owned_submission()
    r = client.get(f'/submission_detail/{sid}')
    assert r.status_code == 200
    assert '无权查看他人提交' not in r.get_data(as_text=True)


def test_submission_detail_not_found(client, login):
    owner = h.make_user('stud_nf')
    login(owner['username'])
    r = client.get('/submission_detail/9999999')
    assert r.status_code == 200
    assert '提交记录不存在' in r.get_data(as_text=True)


# --------------------------------------------------------------------------- #
# submission_status（JSON + is_judging）
# --------------------------------------------------------------------------- #
def test_submission_status_pending_is_judging(client, login):
    pid, sid, owner = _make_owned_submission()
    login(owner)
    r = client.get(f'/submission_status/{sid}')
    assert r.status_code == 200
    data = r.get_json()
    # 新建提交 status='Pending' → is_judging True
    assert data['status'] == 'Pending'
    assert data['is_judging'] is True
    assert 'test_points_count' in data
    assert 'test_points' in data


def test_submission_status_terminal_not_judging(client, login):
    pid, sid, owner = _make_owned_submission()
    db.update_submission_evaluation(sid, [], 100, 'Accepted')
    login(owner)
    r = client.get(f'/submission_status/{sid}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['status'] == 'Accepted'
    assert data['score'] == 100
    assert data['is_judging'] is False


def test_submission_status_unauthorized(client):
    pid, sid, owner = _make_owned_submission()
    r = client.get(f'/submission_status/{sid}')
    assert r.status_code == 401


def test_submission_status_other_user_forbidden(client, login):
    pid, sid, owner = _make_owned_submission()
    other = h.make_user('stud_status_other')
    login(other['username'])
    r = client.get(f'/submission_status/{sid}')
    assert r.status_code == 403


def test_submission_status_not_found(client, login):
    owner = h.make_user('stud_status_nf')
    login(owner['username'])
    r = client.get('/submission_status/9999999')
    assert r.status_code == 404


# --------------------------------------------------------------------------- #
# get_last_submission_code
# --------------------------------------------------------------------------- #
def test_get_last_submission_code_none_returns_404(client, login):
    owner = h.make_user('stud_code_nf')
    pid = h.make_problem(lang='python', type=1)
    login(owner['username'])
    r = client.get(f'/api/get_last_submission_code/{pid}')
    assert r.status_code == 404
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '没有找到之前的提交记录'


def test_get_last_submission_code_returns_code(client, login):
    pid, sid, owner = _make_owned_submission(code="print('saved')\n")
    login(owner)
    r = client.get(f'/api/get_last_submission_code/{pid}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['code'] == "print('saved')\n"
    assert data['submission_id'] == sid


def test_get_last_submission_code_unauthorized(client):
    pid = h.make_problem(lang='python', type=1)
    r = client.get(f'/api/get_last_submission_code/{pid}')
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# get_submission_output_image
# --------------------------------------------------------------------------- #
def test_get_submission_output_image_missing_returns_404(client, login):
    pid, sid, owner = _make_owned_submission()
    login(owner)
    r = client.get(f'/submission_output_image/{sid}/1')
    assert r.status_code == 404
    assert r.get_json()['error'] == 'Output image not found'


def test_get_submission_output_image_other_user_forbidden(client, login):
    pid, sid, owner = _make_owned_submission()
    other = h.make_user('stud_img_other')
    login(other['username'])
    r = client.get(f'/submission_output_image/{sid}/1')
    assert r.status_code == 403


def test_get_submission_output_image_submission_not_found(client, login):
    owner = h.make_user('stud_img_nf')
    login(owner['username'])
    r = client.get('/submission_output_image/9999999/1')
    assert r.status_code == 404
    assert r.get_json()['error'] == 'Submission not found'


# --------------------------------------------------------------------------- #
# submission_status_stream（SSE 取首帧）
# --------------------------------------------------------------------------- #
def test_submission_status_stream_first_frame(client, login):
    """终态提交：首帧立即推 status，并紧跟 done（is_judging=False 时直接结束流）。"""
    pid, sid, owner = _make_owned_submission()
    db.update_submission_evaluation(sid, [], 100, 'Accepted')
    login(owner)
    r = client.get(f'/submission_status_stream/{sid}')
    assert r.status_code == 200
    assert r.mimetype == 'text/event-stream'
    text = r.get_data(as_text=True)
    # 首帧 status 事件 + 终态 done 事件
    assert 'event: status' in text
    assert 'event: done' in text
    # data 行可被解析为 JSON，含 is_judging=False
    data_line = None
    for line in text.splitlines():
        if line.startswith('data: '):
            data_line = line[len('data: '):]
            break
    assert data_line is not None
    payload = json.loads(data_line)
    assert payload['submission_id'] == sid
    assert payload['is_judging'] is False


def test_submission_status_stream_unauthorized(client):
    pid, sid, owner = _make_owned_submission()
    r = client.get(f'/submission_status_stream/{sid}')
    assert r.status_code == 401


def test_submission_status_stream_other_user_forbidden(client, login):
    pid, sid, owner = _make_owned_submission()
    other = h.make_user('stud_stream_other')
    login(other['username'])
    r = client.get(f'/submission_status_stream/{sid}')
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# 提交一段会生成 output.png 的代码 → 真实评测后，submissions 端点能正常返回图片
# --------------------------------------------------------------------------- #
_PNG_CODE = (
    "from PIL import Image\n"
    "Image.new('RGB', (24, 24), (10, 200, 90)).save('output.png')\n"
    "print('done')\n"
)


@pytest.mark.judger
def test_submit_generates_output_image_and_served(client, admin_login, monkeypatch):
    """图片评测模式(mode=2)的 Python 题：提交会生成 output.png 的代码，真实评测后
    捕获到图片，submission 详情页可访问，输出图片端点返回有效 PNG（魔数校验）。"""
    import oj
    import oj_modules.routes.problem_core_routes as pcm
    import oj_modules.tasks.evaluate_tasks as et
    from oj_modules import judger_core

    pid = h.make_problem(title='图片题', lang='python', type=1)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE problems SET programming_grading_mode=2, "
                "programming_output_filename='output.png' WHERE id=%s", (pid,))
        conn.commit()
    finally:
        conn.close()

    # AI 图片批改 mock 成“通过”（只关心图片是否产生并可访问，不打真实网络）
    monkeypatch.setattr(et, 'evaluate_program_output_image_with_ai',
                        lambda **k: (1, '图片符合要求'), raising=False)

    # 拦截评测任务的 .delay/.apply_async 以取得 submission_id（不真正入队）
    captured = {}

    class _FakeTask:
        def delay(self, sid):
            captured['sid'] = sid

        def apply_async(self, args=None, **k):
            captured['sid'] = (args or [None])[0]

    monkeypatch.setattr(pcm, '_evaluate_submission_task', _FakeTask())

    # 以 admin 提交（绕过作业访问与提交次数限制）
    r = client.post(f'/submit/{pid}', data={'code': _PNG_CODE})
    assert r.status_code in (301, 302)
    sid = captured.get('sid')
    assert sid, '提交未触发评测任务入队'

    # 同步走真实沙箱评测：运行代码 → 生成并捕获 output.png
    oj.evaluate_submission.apply(args=[sid]).get()

    sub = db.get_submission_by_id(sid)
    tps = sub['test_points'] if isinstance(sub.get('test_points'), list) else []
    assert tps, '评测未产生测试点'
    assert tps[0].get('has_output_image') is True
    assert tps[0].get('output_image_filename')

    # 评测目录确实生成了图片文件
    run_dir = judger_core.run_dir_for(f'eoj-{sid}-1')
    assert os.path.isfile(os.path.join(run_dir, 'output.png'))

    # submissions 详情页正常打开
    assert client.get(f'/submission_detail/{sid}').status_code == 200

    # 输出图片端点返回有效 PNG（校验 PNG 魔数）
    img = client.get(f'/submission_output_image/{sid}/1')
    assert img.status_code == 200, img.get_data(as_text=True)
    assert img.get_data()[:8] == b'\x89PNG\r\n\x1a\n'
