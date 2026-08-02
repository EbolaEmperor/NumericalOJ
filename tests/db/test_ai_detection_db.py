# -*- coding: utf-8 -*-
"""DB 层测试：AI 检测结果 / 任务持久化（oj_modules/db_services.py）。

覆盖（参考计划 Task 24 / 契约 §1c）：
- upsert_ai_detection_result（REPLACE，必填键 + 可选键 + 同 submission_id 覆盖）
- get_ai_detection_result_by_submission
- get_ai_detection_results_for_problem（risk 过滤 + final_score DESC）
- get_ai_detection_results_for_user
- get_ai_detection_dashboard_summary
- get_undetected_submissions_for_problem / _for_user
- get_filtered_submissions_for_detection（type=1 + 可选 lang 过滤 + 去重取每 (user,problem) 最高分最新 id）
- upsert_ai_detection_task / get_ai_detection_tasks

所有提交用真实 helpers.make_submission（写入 problems/submissions 真实行），
检测结果 submission_id 引用真实提交 id。autouse 的 db_reset 保证隔离。
"""
from oj_modules import db_services as db
from tests import helpers as h


def _result(submission_id, username, problem_id, final_score, risk_level,
            llm_score=None, behavior_score=None, task_id=None,
            llm_evidence=None, behavior_detail=None):
    """构造一个最小合法的 detection result dict。"""
    r = {
        'submission_id': submission_id,
        'username': username,
        'problem_id': problem_id,
        'final_score': final_score,
        'risk_level': risk_level,
    }
    if llm_score is not None:
        r['llm_score'] = llm_score
    if behavior_score is not None:
        r['behavior_score'] = behavior_score
    if task_id is not None:
        r['task_id'] = task_id
    if llm_evidence is not None:
        r['llm_evidence'] = llm_evidence
    if behavior_detail is not None:
        r['behavior_detail'] = behavior_detail
    return r


def _make_matlab_problem_and_sub(username, score=100, lang='matlab'):
    """造一个 type=1 程序题 + 该用户一条提交，返回 (problem_id, submission_id)。"""
    pid = h.make_problem(lang=lang, type=1)
    sid = h.make_submission(pid, username, code='x = 1;', score=score)
    return pid, sid


# ---------------------------------------------------------------------------
# upsert_ai_detection_result
# ---------------------------------------------------------------------------

def test_upsert_result_inserts_required_keys():
    u = h.make_user('det_u1')
    pid, sid = _make_matlab_problem_and_sub('det_u1')
    db.upsert_ai_detection_result(_result(sid, 'det_u1', pid, 0.42, 'low'))

    row = db.get_ai_detection_result_by_submission(sid)
    assert row is not None
    assert row['submission_id'] == sid
    assert row['username'] == 'det_u1'
    assert row['problem_id'] == pid
    assert abs(row['final_score'] - 0.42) < 1e-5
    assert row['risk_level'] == 'low'
    # 未提供的可选键为 NULL
    assert row['llm_score'] is None
    assert row['behavior_score'] is None
    assert row['task_id'] is None


def test_upsert_result_stores_optional_keys():
    u = h.make_user('det_u2')
    pid, sid = _make_matlab_problem_and_sub('det_u2')
    db.upsert_ai_detection_result(_result(
        sid, 'det_u2', pid, 0.9, 'high',
        llm_score=0.8, behavior_score=0.3, task_id='task-abc',
        llm_evidence='looks generated', behavior_detail='fast typing'))

    row = db.get_ai_detection_result_by_submission(sid)
    assert abs(row['llm_score'] - 0.8) < 1e-5
    assert abs(row['behavior_score'] - 0.3) < 1e-5
    assert row['task_id'] == 'task-abc'
    assert row['llm_evidence'] == 'looks generated'
    assert row['behavior_detail'] == 'fast typing'


def test_upsert_result_replaces_on_same_submission():
    u = h.make_user('det_u3')
    pid, sid = _make_matlab_problem_and_sub('det_u3')
    db.upsert_ai_detection_result(_result(sid, 'det_u3', pid, 0.1, 'low'))
    db.upsert_ai_detection_result(_result(sid, 'det_u3', pid, 0.95, 'high',
                                          task_id='t2'))

    # REPLACE INTO + UNIQUE(submission_id) → 只剩一行，值为最新
    rows = db.get_ai_detection_results_for_problem(pid)
    assert len(rows) == 1
    assert rows[0]['risk_level'] == 'high'
    assert abs(rows[0]['final_score'] - 0.95) < 1e-5
    assert rows[0]['task_id'] == 't2'


def test_get_result_by_submission_missing_returns_none():
    assert db.get_ai_detection_result_by_submission(99999999) is None


# ---------------------------------------------------------------------------
# get_ai_detection_results_for_problem (risk filter + ordering)
# ---------------------------------------------------------------------------

def test_results_for_problem_orders_by_final_score_desc():
    pid = h.make_problem(lang='matlab', type=1)
    for name, score in (('p_a', 0.2), ('p_b', 0.8), ('p_c', 0.5)):
        h.make_user(name)
        sid = h.make_submission(pid, name, code='x=1;', score=100)
        risk = 'high' if score >= 0.7 else 'low'
        db.upsert_ai_detection_result(_result(sid, name, pid, score, risk))

    rows = db.get_ai_detection_results_for_problem(pid)
    assert [r['username'] for r in rows] == ['p_b', 'p_c', 'p_a']
    # JOIN submissions 带出 code / submission_status / submission_score 列
    assert 'code' in rows[0]
    assert 'submission_status' in rows[0]
    assert 'submission_score' in rows[0]


def test_results_for_problem_filters_by_risk_level():
    pid = h.make_problem(lang='matlab', type=1)
    specs = [('r_hi1', 0.9, 'high'), ('r_hi2', 0.85, 'high'),
             ('r_lo1', 0.1, 'low')]
    for name, score, risk in specs:
        h.make_user(name)
        sid = h.make_submission(pid, name, code='x=1;', score=100)
        db.upsert_ai_detection_result(_result(sid, name, pid, score, risk))

    high = db.get_ai_detection_results_for_problem(pid, risk_level='high')
    assert len(high) == 2
    assert all(r['risk_level'] == 'high' for r in high)
    assert {r['username'] for r in high} == {'r_hi1', 'r_hi2'}

    low = db.get_ai_detection_results_for_problem(pid, risk_level='low')
    assert len(low) == 1
    assert low[0]['username'] == 'r_lo1'


# ---------------------------------------------------------------------------
# get_ai_detection_results_for_user
# ---------------------------------------------------------------------------

def test_results_for_user_returns_only_that_users_rows():
    h.make_user('owner_x')
    h.make_user('other_y')
    pid1, sid1 = _make_matlab_problem_and_sub('owner_x')
    pid2, sid2 = _make_matlab_problem_and_sub('owner_x')
    pid3, sid3 = _make_matlab_problem_and_sub('other_y')
    db.upsert_ai_detection_result(_result(sid1, 'owner_x', pid1, 0.3, 'low'))
    db.upsert_ai_detection_result(_result(sid2, 'owner_x', pid2, 0.7, 'medium'))
    db.upsert_ai_detection_result(_result(sid3, 'other_y', pid3, 0.9, 'high'))

    rows = db.get_ai_detection_results_for_user('owner_x')
    assert len(rows) == 2
    assert all(r['username'] == 'owner_x' for r in rows)
    # JOIN problems 带出 problem_title 列
    assert 'problem_title' in rows[0]
    assert 'submission_status' in rows[0]


# ---------------------------------------------------------------------------
# get_ai_detection_dashboard_summary
# ---------------------------------------------------------------------------

def test_dashboard_summary_level_counts_and_flagged_users():
    # flagged_user: 至少一条 high 或 medium
    h.make_user('flagged1')
    h.make_user('clean1')
    p_f, s_f = _make_matlab_problem_and_sub('flagged1')
    p_c, s_c = _make_matlab_problem_and_sub('clean1')
    db.upsert_ai_detection_result(_result(s_f, 'flagged1', p_f, 0.95, 'high'))
    db.upsert_ai_detection_result(_result(s_c, 'clean1', p_c, 0.05, 'low'))

    summary = db.get_ai_detection_dashboard_summary()
    assert summary['level_counts'].get('high') == 1
    assert summary['level_counts'].get('low') == 1

    flagged_names = {u['username'] for u in summary['flagged_users']}
    # 只含有 high/medium 的用户才会被标记
    assert 'flagged1' in flagged_names
    assert 'clean1' not in flagged_names

    # problem_stats 聚合每题
    prob_ids = {ps['problem_id'] for ps in summary['problem_stats']}
    assert p_f in prob_ids and p_c in prob_ids


def test_dashboard_summary_empty_when_no_results():
    summary = db.get_ai_detection_dashboard_summary()
    assert dict(summary['level_counts']) == {}
    assert list(summary['flagged_users']) == []
    assert list(summary['problem_stats']) == []


# ---------------------------------------------------------------------------
# get_undetected_submissions_for_problem / _for_user
# ---------------------------------------------------------------------------

def test_undetected_for_problem_excludes_already_detected():
    pid = h.make_problem(lang='matlab', type=1)
    h.make_user('undet_a')
    h.make_user('undet_b')
    sid_a = h.make_submission(pid, 'undet_a', code='x=1;', score=100)
    sid_b = h.make_submission(pid, 'undet_b', code='y=2;', score=100)

    # 给 a 写入检测结果 → a 不应再出现在 undetected 列表
    db.upsert_ai_detection_result(_result(sid_a, 'undet_a', pid, 0.4, 'low'))

    rows = db.get_undetected_submissions_for_problem(pid)
    names = {r['username'] for r in rows}
    assert 'undet_b' in names
    assert 'undet_a' not in names


def test_undetected_for_problem_picks_latest_among_max_score():
    pid = h.make_problem(lang='matlab', type=1)
    h.make_user('undet_rep')
    # 两条满分提交：代表应为 id 更大的那条（latest among max-score）
    low_sid = h.make_submission(pid, 'undet_rep', code='v1;', score=100)
    high_sid = h.make_submission(pid, 'undet_rep', code='v2;', score=100)
    # 另有一条低分提交不应被选作代表
    h.make_submission(pid, 'undet_rep', code='v0;', score=10)

    rows = db.get_undetected_submissions_for_problem(pid)
    reps = [r for r in rows if r['username'] == 'undet_rep']
    assert len(reps) == 1
    assert reps[0]['id'] == high_sid
    assert high_sid > low_sid


def test_undetected_for_user_includes_all_programming_languages():
    h.make_user('undet_user')
    mat_pid = h.make_problem(lang='matlab', type=1)
    py_pid = h.make_problem(lang='python', type=1)
    mat_sid = h.make_submission(mat_pid, 'undet_user', code='x=1;', score=100)
    py_sid = h.make_submission(py_pid, 'undet_user', code='print(1)', score=100)

    rows = db.get_undetected_submissions_for_user('undet_user')
    pids = {r['problem_id'] for r in rows}
    assert mat_pid in pids
    assert py_pid in pids
    assert any(r['id'] == mat_sid for r in rows)
    assert any(r['id'] == py_sid for r in rows)


# ---------------------------------------------------------------------------
# get_filtered_submissions_for_detection
# ---------------------------------------------------------------------------

def test_filtered_all_languages_but_only_type1_by_default():
    h.make_user('filt_u')
    mat_pid = h.make_problem(lang='matlab', type=1)
    py_pid = h.make_problem(lang='python', type=1)
    written_pid = h.make_problem(lang='matlab', type=2)
    mat_sid = h.make_submission(mat_pid, 'filt_u', code='x=1;', score=50)
    py_sid = h.make_submission(py_pid, 'filt_u', code='print(1)', score=50)
    # type=2 书面题提交，create_submission 会写 problem_type=2 → 应被过滤掉

    rows = db.get_filtered_submissions_for_detection()
    sids = {r['id'] for r in rows}
    assert mat_sid in sids
    assert py_sid in sids
    # type2 写面题不应出现
    assert all(r['problem_id'] != written_pid for r in rows)


def test_filtered_optional_language_filter_remains_generic():
    h.make_user('filt_lang_u')
    matlab_pid = h.make_problem(lang='matlab', type=1)
    python_pid = h.make_problem(lang='python', type=1)
    h.make_submission(matlab_pid, 'filt_lang_u', code='x=1;', score=50)
    python_sid = h.make_submission(python_pid, 'filt_lang_u', code='print(1)', score=50)

    rows = db.get_filtered_submissions_for_detection(lang='python')

    assert [row['id'] for row in rows if row['username'] == 'filt_lang_u'] == [python_sid]


def test_filtered_dedup_keeps_highest_score_then_latest_id():
    pid = h.make_problem(lang='matlab', type=1)
    h.make_user('dedup_u')
    # 三条同用户同题提交，最高分 80 出现两次，应保留 id 更大的那条
    h.make_submission(pid, 'dedup_u', code='a;', score=30)
    first_80 = h.make_submission(pid, 'dedup_u', code='b;', score=80)
    last_80 = h.make_submission(pid, 'dedup_u', code='c;', score=80)

    rows = db.get_filtered_submissions_for_detection(lang='matlab',
                                                     deduplicate=True)
    dedup = [r for r in rows if r['username'] == 'dedup_u' and r['problem_id'] == pid]
    assert len(dedup) == 1
    assert dedup[0]['id'] == last_80
    assert dedup[0]['score'] == 80
    assert last_80 > first_80


def test_filtered_no_dedup_returns_all_matching():
    pid = h.make_problem(lang='matlab', type=1)
    h.make_user('nodedup_u')
    h.make_submission(pid, 'nodedup_u', code='a;', score=10)
    h.make_submission(pid, 'nodedup_u', code='b;', score=20)
    h.make_submission(pid, 'nodedup_u', code='c;', score=20)

    rows = db.get_filtered_submissions_for_detection(lang='matlab',
                                                     deduplicate=False)
    mine = [r for r in rows if r['username'] == 'nodedup_u' and r['problem_id'] == pid]
    assert len(mine) == 3
    # 不去重时按 s.id ASC 返回
    ids = [r['id'] for r in mine]
    assert ids == sorted(ids)


def test_filtered_username_filter():
    pid = h.make_problem(lang='matlab', type=1)
    h.make_user('only_me')
    h.make_user('not_me')
    mine_sid = h.make_submission(pid, 'only_me', code='x=1;', score=50)
    h.make_submission(pid, 'not_me', code='y=2;', score=50)

    rows = db.get_filtered_submissions_for_detection(username='only_me',
                                                     lang='matlab')
    assert len(rows) == 1
    assert rows[0]['id'] == mine_sid
    assert rows[0]['username'] == 'only_me'
    # 带出 problem_title 列
    assert 'problem_title' in rows[0]


def test_filtered_by_class_join():
    cls_en, cls_cn = h.make_class('Cdetect', '检测班')
    h.make_user('cls_member', class_en=cls_en, class_cn=cls_cn)
    h.make_user('outsider')  # 默认 Cclass1
    pid = h.make_problem(lang='matlab', type=1)
    in_sid = h.make_submission(pid, 'cls_member', code='x=1;', score=50)
    h.make_submission(pid, 'outsider', code='y=2;', score=50)

    rows = db.get_filtered_submissions_for_detection(class_en=cls_en,
                                                     lang='matlab')
    assert len(rows) == 1
    assert rows[0]['id'] == in_sid
    assert rows[0]['username'] == 'cls_member'


# ---------------------------------------------------------------------------
# upsert_ai_detection_task / get_ai_detection_tasks
# ---------------------------------------------------------------------------

def test_upsert_task_inserts_with_defaults():
    db.upsert_ai_detection_task({
        'task_id': 'task-1',
        'task_type': 'problem',
        'params_summary': 'problem_id=1',
        'submitted_at': '2026-05-29 10:00:00',
        'total': 5,
    })
    tasks = db.get_ai_detection_tasks()
    by_id = {t['task_id']: t for t in tasks}
    assert 'task-1' in by_id
    t = by_id['task-1']
    assert t['task_type'] == 'problem'
    assert t['status'] == 'pending'   # 默认值
    assert t['processed'] == 0        # 默认 0
    assert t['total'] == 5


def test_upsert_task_updates_on_conflict():
    db.upsert_ai_detection_task({
        'task_id': 'task-upd',
        'task_type': 'user',
        'submitted_at': '2026-05-29 09:00:00',
        'status': 'pending',
        'total': 10,
        'processed': 0,
    })
    db.upsert_ai_detection_task({
        'task_id': 'task-upd',
        'task_type': 'user',
        'submitted_at': '2026-05-29 09:00:00',
        'status': 'completed',
        'finished_at': '2026-05-29 09:30:00',
        'total': 10,
        'processed': 10,
    })
    tasks = db.get_ai_detection_tasks()
    matching = [t for t in tasks if t['task_id'] == 'task-upd']
    assert len(matching) == 1   # ON DUPLICATE KEY UPDATE → 仍只一行
    assert matching[0]['status'] == 'completed'
    assert matching[0]['processed'] == 10
    assert matching[0]['finished_at'] == '2026-05-29 09:30:00'


def test_get_tasks_orders_newest_first_and_respects_limit():
    db.upsert_ai_detection_task({
        'task_id': 'old', 'task_type': 'problem',
        'submitted_at': '2026-05-01 08:00:00', 'total': 1})
    db.upsert_ai_detection_task({
        'task_id': 'mid', 'task_type': 'problem',
        'submitted_at': '2026-05-15 08:00:00', 'total': 1})
    db.upsert_ai_detection_task({
        'task_id': 'new', 'task_type': 'problem',
        'submitted_at': '2026-05-29 08:00:00', 'total': 1})

    tasks = db.get_ai_detection_tasks()
    order = [t['task_id'] for t in tasks]
    assert order == ['new', 'mid', 'old']
    # datetime 列被格式化成字符串
    assert isinstance(tasks[0]['submitted_at'], str)

    limited = db.get_ai_detection_tasks(limit=1)
    assert len(limited) == 1
    assert limited[0]['task_id'] == 'new'
