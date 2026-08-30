# -*- coding: utf-8 -*-
"""DB 层：提交（submissions）相关函数的真实 DB 测试。

覆盖 db_services 的：
- create_submission（status='Pending'，返回 lastrowid，test_points 序列化往返）
- get_submission_by_id（解析 test_points / None / []）
- update_submission_status / update_submission_evaluation
- get_user_submission_count / reserve_submission_quota / can_submit / get_remaining_submissions
  （默认上限 10；problem['submission_limit'] 作为参数覆盖）
- get_incomplete_submissions（Pending/Waiting/Running，id 升序）
- get_submissions_in_time_range
- daily-stats：bump_daily_submission_count / get_today_submission_total_from_counter /
  get_last_10_days_counts_from_counter

约定：autouse 的 db_reset 每个测试前 truncate+reseed；用 tests.helpers 工厂造数据。
"""
from backend.oj_modules import db_services as db
from tests import helpers as h


# ---------------------------------------------------------------------------
# create_submission
# ---------------------------------------------------------------------------

def test_create_submission_status_pending_and_returns_id():
    h.make_user('subuser1')
    pid = h.make_problem(lang='python', type=1)
    sid = db.create_submission(pid, '题目A', 'subuser1', "print(1)\n", 0, [])
    assert isinstance(sid, int) and sid > 0
    sub = db.get_submission_by_id(sid)
    assert sub is not None
    assert sub['status'] == 'Pending'
    assert sub['username'] == 'subuser1'
    assert sub['problem_id'] == pid
    assert sub['score'] == 0


def test_create_submission_serializes_test_points_roundtrip():
    h.make_user('subuser2')
    pid = h.make_problem(lang='python', type=1)
    tps = [{'status': 'Pending', 'index': 0}, {'status': 'Pending', 'index': 1}]
    sid = db.create_submission(pid, '题目B', 'subuser2', "code\n", 0, tps)
    sub = db.get_submission_by_id(sid)
    # test_points 应被解析回 list[dict]，每行一个 JSON
    assert sub['test_points'] == tps


# ---------------------------------------------------------------------------
# get_submission_by_id
# ---------------------------------------------------------------------------

def test_get_submission_by_id_none_when_missing():
    assert db.get_submission_by_id(999999) is None


def test_get_submission_by_id_empty_test_points_stays_empty():
    h.make_user('subuser3')
    pid = h.make_problem(lang='python', type=1)
    sid = db.create_submission(pid, '题目C', 'subuser3', "x", 0, [])
    sub = db.get_submission_by_id(sid)
    # 没有 test_points → 解析逻辑不触发，保持空（''/None/[]）
    assert not sub['test_points']


# ---------------------------------------------------------------------------
# update_submission_status / update_submission_evaluation
# ---------------------------------------------------------------------------

def test_update_submission_status():
    h.make_user('subuser4')
    pid = h.make_problem(lang='python', type=1)
    sid = db.create_submission(pid, '题目D', 'subuser4', "x", 0, [])
    db.update_submission_status(sid, 'Running')
    assert db.get_submission_by_id(sid)['status'] == 'Running'


def test_update_submission_evaluation_writes_points_score_status():
    h.make_user('subuser5')
    pid = h.make_problem(lang='python', type=1)
    sid = db.create_submission(pid, '题目E', 'subuser5', "x", 0, [])
    statuses = [{'status': 'Accepted'}, {'status': 'Wrong Answer'}]
    db.update_submission_evaluation(sid, statuses, 50, 'Unaccepted')
    sub = db.get_submission_by_id(sid)
    assert sub['score'] == 50
    assert sub['status'] == 'Unaccepted'
    assert sub['test_points'] == statuses


# ---------------------------------------------------------------------------
# submission count / can_submit / remaining
# ---------------------------------------------------------------------------

def test_submission_count_default_zero():
    h.make_user('countuser1')
    pid = h.make_problem(lang='python', type=1)
    assert db.get_user_submission_count('countuser1', pid) == 0


def test_reserve_submission_quota_increments_count():
    h.make_user('countuser2')
    pid = h.make_problem(lang='python', type=1)
    assert db.reserve_submission_quota('countuser2', pid) == 1
    assert db.reserve_submission_quota('countuser2', pid) == 2
    assert db.get_user_submission_count('countuser2', pid) == 2


def test_can_submit_and_remaining_default_cap_10():
    h.make_user('countuser3')
    pid = h.make_problem(lang='python', type=1)
    # 默认上限 10
    assert db.can_submit('countuser3', pid) is True
    assert db.get_remaining_submissions('countuser3', pid) == 10
    for _ in range(10):
        db.reserve_submission_quota('countuser3', pid, max_submissions=10)
    assert db.get_user_submission_count('countuser3', pid) == 10
    assert db.can_submit('countuser3', pid) is False
    assert db.get_remaining_submissions('countuser3', pid) == 0


def test_can_submit_uses_problem_submission_limit_override():
    h.make_user('countuser4')
    # 题目 submission_limit=3，调用方将其作为 max_submissions 传入
    pid = h.make_problem(lang='python', type=1, submission_limit=3)
    problem = db.get_problem(pid)
    limit = problem['submission_limit']
    assert limit == 3
    for _ in range(2):
        db.reserve_submission_quota('countuser4', pid, max_submissions=limit)
    assert db.can_submit('countuser4', pid, max_submissions=limit) is True
    assert db.get_remaining_submissions('countuser4', pid, max_submissions=limit) == 1
    db.reserve_submission_quota('countuser4', pid, max_submissions=limit)
    assert db.can_submit('countuser4', pid, max_submissions=limit) is False
    assert db.get_remaining_submissions('countuser4', pid, max_submissions=limit) == 0


# ---------------------------------------------------------------------------
# get_incomplete_submissions
# ---------------------------------------------------------------------------

def test_get_incomplete_submissions_filters_and_orders():
    h.make_user('incuser')
    pid = h.make_problem(lang='python', type=1)
    # 三条不同最终态
    s_pending = db.create_submission(pid, 't', 'incuser', 'a', 0, [])  # Pending
    s_waiting = db.create_submission(pid, 't', 'incuser', 'b', 0, [])
    db.update_submission_status(s_waiting, 'Waiting')
    s_running = db.create_submission(pid, 't', 'incuser', 'c', 0, [])
    db.update_submission_status(s_running, 'Running')
    s_done = db.create_submission(pid, 't', 'incuser', 'd', 0, [])
    db.update_submission_status(s_done, 'Accepted')

    rows = db.get_incomplete_submissions()
    ids = [r['id'] for r in rows]
    # 仅 Pending/Waiting/Running，且不含已完成的
    assert s_pending in ids
    assert s_waiting in ids
    assert s_running in ids
    assert s_done not in ids
    # id 升序
    assert ids == sorted(ids)
    for r in rows:
        assert r['status'] in ('Pending', 'Waiting', 'Running')


# ---------------------------------------------------------------------------
# get_submissions_in_time_range
# ---------------------------------------------------------------------------

def test_get_submissions_in_time_range_includes_recent():
    h.make_user('rangeuser')
    pid = h.make_problem(lang='python', type=1)
    s1 = db.create_submission(pid, 't', 'rangeuser', 'a', 0, [])
    s2 = db.create_submission(pid, 't', 'rangeuser', 'b', 0, [])
    # 用一个足够宽的时间窗口覆盖刚创建的提交
    rows = db.get_submissions_in_time_range('1970-01-01 00:00:00', '2999-12-31 23:59:59')
    ids = [r['id'] for r in rows]
    assert s1 in ids and s2 in ids
    assert ids == sorted(ids)


def test_get_submissions_in_time_range_excludes_outside_window():
    h.make_user('rangeuser2')
    pid = h.make_problem(lang='python', type=1)
    sid = db.create_submission(pid, 't', 'rangeuser2', 'a', 0, [])
    # 一个远早于现在的窗口，不应包含刚创建的提交
    rows = db.get_submissions_in_time_range('1970-01-01 00:00:00', '1970-01-02 00:00:00')
    assert sid not in [r['id'] for r in rows]


# ---------------------------------------------------------------------------
# daily submission stats
# ---------------------------------------------------------------------------

def test_bump_daily_submission_count_increments_today():
    before = db.get_today_submission_total_from_counter()
    db.bump_daily_submission_count()
    after = db.get_today_submission_total_from_counter()
    assert after == before + 1


def test_create_submission_bumps_daily_counter():
    h.make_user('dailyuser')
    pid = h.make_problem(lang='python', type=1)
    before = db.get_today_submission_total_from_counter()
    db.create_submission(pid, 't', 'dailyuser', 'x', 0, [])
    after = db.get_today_submission_total_from_counter()
    assert after == before + 1


def test_last_10_days_counts_shape_and_today_bump():
    db.bump_daily_submission_count()
    labels, counts = db.get_last_10_days_counts_from_counter()
    assert len(labels) == 10
    assert len(counts) == 10
    # 最后一个 label 是今天，且其计数 >= 1（刚 bump 过）
    from datetime import date
    assert labels[-1] == date.today().strftime('%Y-%m-%d')
    assert counts[-1] >= 1
    assert all(isinstance(c, int) for c in counts)
