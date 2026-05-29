# -*- coding: utf-8 -*-
"""grading_routes.py 集成测试（§4h）。

覆盖：
- submit_grading：score 0–5 合法（==5→Accepted，否则→Unaccepted），越界→400，
  非管理员→403，提交不存在→404。
- get_next_pending_submission：有/无待批 type2 提交的两种文案；非管理员→403。
- invalidate_invalid_submissions：同一用户多条 Pending，保留最新一条其余置 Unaccepted。
- download_submission_file：提交不存在→404；非书面题（type!=2）→400；
  书面题但无上传文件→404。

约定（见 conftest）：
- admin_login fixture 已登录种子 admin('admin'/'admin123')，is_admin=1。
- DB 每个测试 truncate+reseed；直接查库走 db_services.get_db_connection()。
- 以 admin 用户名造 type2 提交：create_submission 对 type==2 + is_admin 用户会
  跳过动态班级表的 complete_cnt 自增分支，因此无需物理动态班级表即可建库。
"""
import pytest

from oj_modules import db_services as db
from tests import helpers as h


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def _make_written_submission(score=0, status=None, username='admin', test_points=None):
    """造一条 type2（书面作业）提交，返回 submission id。

    用 admin 作为提交人：create_submission 对 type==2 的非管理员会去 UPDATE 动态
    班级物理表（测试里不存在），admin(is_admin=1) 则跳过该分支。
    """
    pid = h.make_problem(title=h._uniq('书面题'), type=2)
    return h.make_submission(
        pid, username, code='', score=score,
        test_points=test_points if test_points is not None else [],
        problem_title='书面题', status=status)


def _make_program_submission(username='admin'):
    """造一条 type1（程序题）提交，返回 submission id。"""
    pid = h.make_problem(title=h._uniq('程序题'), type=1)
    return h.make_submission(pid, username, code='print(1)', problem_title='程序题')


def _fetch_submission_row(submission_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT score, status, code FROM submissions WHERE id=%s",
                (submission_id,))
            return cur.fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# submit_grading
# ---------------------------------------------------------------------------
def test_submit_grading_score_5_marks_accepted(client, admin_login):
    sid = _make_written_submission()
    r = client.post(f'/submit_grading/{sid}',
                    data={'score': '5', 'comment': '满分评语'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '批改结果已提交'

    row = _fetch_submission_row(sid)
    assert row['score'] == 5
    assert row['status'] == 'Accepted'
    # comment 被写入 code 列
    assert row['code'] == '满分评语'


@pytest.mark.parametrize('score', [0, 1, 4])
def test_submit_grading_score_below_5_marks_unaccepted(client, admin_login, score):
    sid = _make_written_submission()
    r = client.post(f'/submit_grading/{sid}',
                    data={'score': str(score), 'comment': '需改进'})
    assert r.status_code == 200
    assert r.get_json()['success'] is True

    row = _fetch_submission_row(sid)
    assert row['score'] == score
    assert row['status'] == 'Unaccepted'


@pytest.mark.parametrize('score', ['6', '-1', '100', 'abc', ''])
def test_submit_grading_out_of_range_returns_400(client, admin_login, score):
    sid = _make_written_submission()
    r = client.post(f'/submit_grading/{sid}', data={'score': score})
    assert r.status_code == 400
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '得分必须在 0 到 5 之间'

    # 提交未被改动（仍是初始 Pending / score 0）
    row = _fetch_submission_row(sid)
    assert row['score'] == 0
    assert row['status'] == 'Pending'


def test_submit_grading_missing_score_returns_400(client, admin_login):
    sid = _make_written_submission()
    r = client.post(f'/submit_grading/{sid}', data={'comment': '没给分'})
    assert r.status_code == 400
    assert r.get_json()['success'] is False


def test_submit_grading_nonexistent_submission_returns_404(client, admin_login):
    r = client.post('/submit_grading/999999', data={'score': '3'})
    assert r.status_code == 404
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '提交记录不存在'


def test_submit_grading_requires_admin(client, login):
    h.make_user('grad_stud1')
    login('grad_stud1')
    # 仍需一条存在的提交不重要——权限校验先于一切
    r = client.post('/submit_grading/1', data={'score': '5'})
    assert r.status_code == 403
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '无权限批改作业'


# ---------------------------------------------------------------------------
# get_next_pending_submission
# ---------------------------------------------------------------------------
def test_get_next_pending_returns_url_when_more_pending(client, admin_login):
    # 两条 Pending 的 type2 提交，对第一条问 next → 返回第二条 URL
    sid1 = _make_written_submission(status='Pending')
    sid2 = _make_written_submission(status='Pending')
    assert sid2 > sid1

    r = client.get(f'/get_next_pending_submission/{sid1}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert 'next_submission_url' in body
    # URL 指向更大 id 的下一条待批提交
    assert str(sid2) in body['next_submission_url']


def test_get_next_pending_wraps_around_to_earliest(client, admin_login):
    # 仅一条 Pending；对它本身问 next（id>current 无结果）→ wrap-around 回到自己
    sid = _make_written_submission(status='Pending')
    r = client.get(f'/get_next_pending_submission/{sid}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert str(sid) in body['next_submission_url']


def test_get_next_pending_none_left_message(client, admin_login):
    # 当前这条已批（非 Pending），且没有其它 Pending type2 → 文案“无待批改的书面作业”
    sid = _make_written_submission(status='Accepted')
    r = client.get(f'/get_next_pending_submission/{sid}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '无待批改的书面作业'


def test_get_next_pending_nonexistent_submission_404(client, admin_login):
    r = client.get('/get_next_pending_submission/999999')
    assert r.status_code == 404
    assert r.get_json()['success'] is False


def test_get_next_pending_requires_admin(client, login):
    h.make_user('grad_stud2')
    login('grad_stud2')
    r = client.get('/get_next_pending_submission/1')
    assert r.status_code == 403
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '无权限查看待批改作业'


# ---------------------------------------------------------------------------
# invalidate_invalid_submissions
# ---------------------------------------------------------------------------
def test_invalidate_keeps_latest_pending_per_user(client, admin_login):
    pid = h.make_problem(title='重复提交题', type=2)
    # 同一用户三条 Pending（admin）
    s1 = h.make_submission(pid, 'admin', code='', problem_title='重复提交题', status='Pending')
    s2 = h.make_submission(pid, 'admin', code='', problem_title='重复提交题', status='Pending')
    s3 = h.make_submission(pid, 'admin', code='', problem_title='重复提交题', status='Pending')

    r = client.post(f'/invalidate_invalid_submissions/{pid}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '无效提交已移除'

    # 按 created_at DESC 排序后保留首条，其余置 Unaccepted。
    # 三条同 problem_id 同用户：恰好保留 1 条 Pending，另 2 条 Unaccepted。
    # （created_at 可能同秒并列、无 id 兜底排序，故只断言数量而非具体保留哪条。）
    statuses = {sid: _fetch_submission_row(sid)['status'] for sid in (s1, s2, s3)}
    pending = [sid for sid, st in statuses.items() if st == 'Pending']
    unacc = [sid for sid, st in statuses.items() if st == 'Unaccepted']
    assert len(pending) == 1
    assert len(unacc) == 2


def test_invalidate_single_pending_unchanged(client, admin_login):
    pid = h.make_problem(title='单条题', type=2)
    s1 = h.make_submission(pid, 'admin', code='', problem_title='单条题', status='Pending')
    r = client.post(f'/invalidate_invalid_submissions/{pid}')
    assert r.status_code == 200
    assert r.get_json()['success'] is True
    # 只有一条不会被失效
    assert _fetch_submission_row(s1)['status'] == 'Pending'


def test_invalidate_requires_admin(client, login):
    h.make_user('grad_stud3')
    login('grad_stud3')
    r = client.post('/invalidate_invalid_submissions/1')
    assert r.status_code == 403
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '无权限'


# ---------------------------------------------------------------------------
# download_submission_file
# ---------------------------------------------------------------------------
def test_download_nonexistent_submission_404(client, admin_login):
    r = client.get('/download_submission_file/999999')
    assert r.status_code == 404
    assert '提交记录不存在' in r.get_data(as_text=True)


def test_download_non_written_submission_400(client, admin_login):
    # type1（程序题）提交 → 不是书面作业题 → 400
    sid = _make_program_submission()
    r = client.get(f'/download_submission_file/{sid}')
    assert r.status_code == 400
    assert '不是书面作业题' in r.get_data(as_text=True)


def test_download_written_submission_no_file_404(client, admin_login):
    # type2 提交但没有 uploads/<id>/ 目录与 PDF → 文件不存在 → 404
    sid = _make_written_submission(test_points=['answer.png'])
    r = client.get(f'/download_submission_file/{sid}')
    assert r.status_code == 404
    assert '文件不存在' in r.get_data(as_text=True)
