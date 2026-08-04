# -*- coding: utf-8 -*-
"""Task 25 — agent_task_runs 数据层单测（§1c）。

覆盖：
- upsert_agent_run_snapshot：需要非空 task_id；attempts 序列化为 JSON；
  best_score = max(state.best_score, _best_score_from_attempts(attempts))；
  INSERT...ON DUPLICATE KEY UPDATE（同一 task_id 覆盖更新）。
- get_agent_run_by_task_id：坏 JSON → []；datetime 格式化为 'YYYY-MM-DD HH:MM:SS'；
  不存在返回 None。
- get_agent_runs_paginated：返回 (rows, total_pages)。

论坛 threads/replies 数据层在路由层（Task 33）覆盖；此处只测 agent_runs。
"""
import json
import re

from oj_modules import db_services as db


def _fetch_raw(task_id):
    """直接读 agent_task_runs 一行（绕过 db_services 解析），用于断言写入内容。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM agent_task_runs WHERE task_id=%s LIMIT 1",
                (task_id,),
            )
            return cur.fetchone()
    finally:
        conn.close()


def _set_raw_json(task_id, attempts_json=None):
    """直接写坏 JSON 文本，用于测试解析容错。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE agent_task_runs SET attempts_json=%s WHERE task_id=%s",
                (attempts_json, task_id),
            )
        conn.commit()
    finally:
        conn.close()


def _count_rows():
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM agent_task_runs")
            return int(cur.fetchone()['n'])
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# upsert_agent_run_snapshot
# ---------------------------------------------------------------------------
def test_upsert_requires_task_id():
    """无 task_id（或空白 task_id）一律 no-op，不写库。"""
    db.upsert_agent_run_snapshot({})
    db.upsert_agent_run_snapshot({'task_id': ''})
    db.upsert_agent_run_snapshot({'task_id': '   '})
    assert _count_rows() == 0


def test_upsert_non_dict_is_noop():
    """非 dict 入参被静默忽略。"""
    db.upsert_agent_run_snapshot(None)
    db.upsert_agent_run_snapshot("not-a-dict")
    db.upsert_agent_run_snapshot(123)
    assert _count_rows() == 0


def test_upsert_basic_insert_and_json_serialization():
    """正常插入：attempts 以 JSON 文本落库，标量字段正确。"""
    attempts = [{'submission_id': 1, 'summary': {'score': 40}}]
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-basic',
        'problem_id': 7,
        'problem_title': '示例题目',
        'requested_by': 'admin',
        'status': 'running',
        'message': '进行中',
        'best_score': 0,
        'final_submission_id': 11,
        'latest_submission_id': 12,
        'attempts': attempts,
    })

    row = _fetch_raw('tk-basic')
    assert row is not None
    assert row['problem_id'] == 7
    assert row['problem_title'] == '示例题目'
    assert row['requested_by'] == 'admin'
    assert row['status'] == 'running'
    assert 'rounds_run' not in row
    assert 'max_rounds' not in row
    assert row['final_submission_id'] == 11
    assert row['latest_submission_id'] == 12

    assert json.loads(row['attempts_json']) == attempts


def test_upsert_best_score_is_max_of_state_and_attempts():
    """best_score = max(state.best_score, attempts 里 summary.score 的最大值)。
    这里 attempts 里最高 60 > state 给的 30，应取 60。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-bestscore',
        'best_score': 30,
        'attempts': [
            {'summary': {'score': 20}},
            {'summary': {'score': 60}},
            {'summary': {'score': 55}},
        ],
    })
    row = _fetch_raw('tk-bestscore')
    assert row['best_score'] == 60


def test_upsert_best_score_uses_state_when_higher():
    """当 state.best_score 高于 attempts 推断值时取 state 的值。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-bestscore-state',
        'best_score': 90,
        'attempts': [{'summary': {'score': 10}}],
    })
    row = _fetch_raw('tk-bestscore-state')
    assert row['best_score'] == 90


def test_upsert_non_list_attempts_defaults_empty():
    """attempts 非 list 时落库为 '[]'，best_score 退化为 state.best_score。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-bad-types',
        'best_score': 5,
        'attempts': {'not': 'a list'},
    })
    row = _fetch_raw('tk-bad-types')
    assert json.loads(row['attempts_json']) == []
    assert row['best_score'] == 5


def test_upsert_on_duplicate_key_update():
    """同一 task_id 二次 upsert 覆盖更新，行数仍为 1。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-dup',
        'status': 'running',
        'best_score': 10,
        'message': 'first',
    })
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-dup',
        'status': 'completed',
        'best_score': 88,
        'message': 'second',
    })
    assert _count_rows() == 1
    row = _fetch_raw('tk-dup')
    assert row['status'] == 'completed'
    assert row['best_score'] == 88
    assert row['message'] == 'second'


def test_upsert_status_default_pending_when_missing():
    """缺省 status 时落库为 'Pending'。"""
    db.upsert_agent_run_snapshot({'task_id': 'tk-default-status'})
    row = _fetch_raw('tk-default-status')
    assert row['status'] == 'Pending'


# ---------------------------------------------------------------------------
# get_agent_run_by_task_id
# ---------------------------------------------------------------------------
def test_get_by_task_id_roundtrip():
    """写入后能读回，attempts 解析为 Python 对象，标量字段映射正确。"""
    attempts = [{'submission_id': 1, 'summary': {'score': 70}}]
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-read',
        'problem_id': 3,
        'problem_title': '读回题',
        'requested_by': 'admin',
        'status': 'completed',
        'message': '完成',
        'best_score': 0,
        'attempts': attempts,
    })

    got = db.get_agent_run_by_task_id('tk-read')
    assert got is not None
    assert got['task_id'] == 'tk-read'
    assert got['problem_id'] == 3
    assert got['problem_title'] == '读回题'
    assert got['requested_by'] == 'admin'
    assert got['status'] == 'completed'
    assert 'round' not in got
    assert 'max_rounds' not in got
    # best_score 由 attempts 推断（70 > 0）
    assert got['best_score'] == 70
    assert got['attempts'] == attempts
    assert 'events' not in got


def test_get_by_task_id_missing_returns_none():
    """不存在的 task_id 返回 None；空 task_id 也返回 None。"""
    assert db.get_agent_run_by_task_id('does-not-exist') is None
    assert db.get_agent_run_by_task_id('') is None
    assert db.get_agent_run_by_task_id(None) is None


def test_get_by_task_id_bad_json_defaults_to_empty_list():
    """attempts_json 为坏 JSON 时解析为 []。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-badjson',
        'attempts': [{'summary': {'score': 1}}],
    })
    # 直接把库里 JSON 文本改坏
    _set_raw_json('tk-badjson', attempts_json='{not json')

    got = db.get_agent_run_by_task_id('tk-badjson')
    assert got['attempts'] == []


def test_get_by_task_id_null_json_defaults_to_empty_list():
    """attempts_json 为 NULL 时解析为 []。"""
    db.upsert_agent_run_snapshot({'task_id': 'tk-nulljson'})
    _set_raw_json('tk-nulljson', attempts_json=None)

    got = db.get_agent_run_by_task_id('tk-nulljson')
    assert got['attempts'] == []


def test_get_by_task_id_datetime_format():
    """created_at/updated_at 被格式化为 'YYYY-MM-DD HH:MM:SS' 字符串。"""
    db.upsert_agent_run_snapshot({'task_id': 'tk-dt'})
    got = db.get_agent_run_by_task_id('tk-dt')
    dt_re = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
    assert isinstance(got['created_at'], str)
    assert dt_re.match(got['created_at']), got['created_at']
    assert isinstance(got['updated_at'], str)
    assert dt_re.match(got['updated_at']), got['updated_at']


# ---------------------------------------------------------------------------
# get_agent_runs_paginated
# ---------------------------------------------------------------------------
def test_paginated_empty():
    """空表：返回 ([], 1)（total_pages 至少为 1）。"""
    rows, total_pages = db.get_agent_runs_paginated(page=1, per_page=20)
    assert list(rows) == []
    assert total_pages == 1


def test_paginated_returns_rows_and_total_pages():
    """插入 3 行、per_page=2：第一页 2 行，total_pages=2；第二页 1 行。"""
    for i in range(3):
        db.upsert_agent_run_snapshot({
            'task_id': f'tk-page-{i}',
            'status': 'completed',
            'best_score': i,
        })

    rows_p1, total_pages = db.get_agent_runs_paginated(page=1, per_page=2)
    assert total_pages == 2
    assert len(rows_p1) == 2

    rows_p2, total_pages2 = db.get_agent_runs_paginated(page=2, per_page=2)
    assert total_pages2 == 2
    assert len(rows_p2) == 1


def test_paginated_order_by_id_desc():
    """结果按 id DESC 排序：最后插入的 task_id 在最前。"""
    for i in range(3):
        db.upsert_agent_run_snapshot({'task_id': f'tk-order-{i}'})
    rows, _ = db.get_agent_runs_paginated(page=1, per_page=20)
    task_ids = [r['task_id'] for r in rows]
    assert task_ids[0] == 'tk-order-2'
    assert task_ids[-1] == 'tk-order-0'


def test_paginated_row_shape():
    """分页行包含列表页所需字段（不含 attempts_json）。"""
    db.upsert_agent_run_snapshot({
        'task_id': 'tk-shape',
        'problem_id': 9,
        'problem_title': '形状题',
        'requested_by': 'admin',
        'status': 'completed',
        'best_score': 42,
        'latest_submission_id': 77,
    })
    rows, _ = db.get_agent_runs_paginated(page=1, per_page=20)
    assert len(rows) == 1
    row = rows[0]
    for key in ('task_id', 'problem_id', 'problem_title', 'requested_by',
                'status', 'best_score', 'latest_submission_id',
                'problem_max_score', 'created_at', 'updated_at'):
        assert key in row
    assert 'attempts_json' not in row
    assert row['problem_id'] == 9
    assert row['best_score'] == 42
    assert row['latest_submission_id'] == 77
