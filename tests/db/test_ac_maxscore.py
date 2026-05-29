# -*- coding: utf-8 -*-
"""DB 层测试：ac_record / max_score 的写入与读回（参考 §1b / Task 22）。

被测函数（oj_modules/db_services.py）：
- insert_user_problem_ac_record_if_absent(user_id, problem_id) -> bool
    INSERT IGNORE INTO ac_record(userid, problem_id, is_ac) VALUES(..,..,1)；
    首次插入返回 True，重复（已存在主键）返回 False。
- upsert_user_problem_max_score(user_id, problem_id, score)
    INSERT ... ON DUPLICATE KEY UPDATE score=VALUES(score)（无条件覆盖）。
- upsert_user_problem_max_score_if_higher(user_id, problem_id, score)
    ON DUPLICATE KEY UPDATE score = IF(score < VALUES(score), VALUES(score), score)
    （只升不降）。
- delete_user_problem_max_score(user_id, problem_id)

无 public getter，全部用直接 SQL 读回校验。
表列：ac_record(userid, problem_id, is_ac)、max_score(userid, problem_id, score)。
"""
from oj_modules import db_services as db
from tests import helpers as h


def _ac_row(user_id, problem_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT userid, problem_id, is_ac FROM ac_record "
                "WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
            return cur.fetchone()
    finally:
        conn.close()


def _ac_count(user_id, problem_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM ac_record "
                "WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
            return cur.fetchone()['n']
    finally:
        conn.close()


def _max_score(user_id, problem_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT score FROM max_score WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
            row = cur.fetchone()
            return row['score'] if row else None
    finally:
        conn.close()


def _max_score_count(user_id, problem_id):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM max_score "
                "WHERE userid=%s AND problem_id=%s",
                (user_id, problem_id),
            )
            return cur.fetchone()['n']
    finally:
        conn.close()


# ---------------- insert_user_problem_ac_record_if_absent ----------------

def test_insert_ac_record_first_time_returns_true_and_persists():
    u = h.make_user('acuser1')
    pid = h.make_problem(title='ac题1')

    first = db.insert_user_problem_ac_record_if_absent(u['id'], pid)
    assert first is True

    row = _ac_row(u['id'], pid)
    assert row is not None
    assert row['userid'] == u['id']
    assert row['problem_id'] == pid
    assert row['is_ac'] == 1


def test_insert_ac_record_duplicate_returns_false_no_extra_row():
    u = h.make_user('acuser2')
    pid = h.make_problem(title='ac题2')

    assert db.insert_user_problem_ac_record_if_absent(u['id'], pid) is True
    # 重复插入应被 INSERT IGNORE 吃掉 → False
    assert db.insert_user_problem_ac_record_if_absent(u['id'], pid) is False
    # 仍然只有一行
    assert _ac_count(u['id'], pid) == 1


def test_insert_ac_record_distinct_user_problem_independent():
    u1 = h.make_user('acuser3a')
    u2 = h.make_user('acuser3b')
    pid = h.make_problem(title='ac题3')

    assert db.insert_user_problem_ac_record_if_absent(u1['id'], pid) is True
    # 不同用户同题 → 不同主键 → 仍是首次 True
    assert db.insert_user_problem_ac_record_if_absent(u2['id'], pid) is True
    assert _ac_count(u1['id'], pid) == 1
    assert _ac_count(u2['id'], pid) == 1


# ---------------- upsert_user_problem_max_score ----------------

def test_upsert_max_score_insert_then_overwrite_down():
    u = h.make_user('msuser1')
    pid = h.make_problem(title='ms题1')

    db.upsert_user_problem_max_score(u['id'], pid, 80)
    assert _max_score(u['id'], pid) == 80

    # 无条件覆盖：即便更低也写入
    db.upsert_user_problem_max_score(u['id'], pid, 30)
    assert _max_score(u['id'], pid) == 30
    # 始终单行（主键 userid+problem_id）
    assert _max_score_count(u['id'], pid) == 1


def test_upsert_max_score_overwrite_up():
    u = h.make_user('msuser2')
    pid = h.make_problem(title='ms题2')

    db.upsert_user_problem_max_score(u['id'], pid, 40)
    db.upsert_user_problem_max_score(u['id'], pid, 100)
    assert _max_score(u['id'], pid) == 100
    assert _max_score_count(u['id'], pid) == 1


# ---------------- upsert_user_problem_max_score_if_higher ----------------

def test_upsert_if_higher_inserts_when_absent():
    u = h.make_user('msuser3')
    pid = h.make_problem(title='ms题3')

    db.upsert_user_problem_max_score_if_higher(u['id'], pid, 55)
    assert _max_score(u['id'], pid) == 55


def test_upsert_if_higher_raises_but_never_lowers():
    u = h.make_user('msuser4')
    pid = h.make_problem(title='ms题4')

    db.upsert_user_problem_max_score_if_higher(u['id'], pid, 50)
    assert _max_score(u['id'], pid) == 50

    # 更高 → 升到 90
    db.upsert_user_problem_max_score_if_higher(u['id'], pid, 90)
    assert _max_score(u['id'], pid) == 90

    # 更低 → 保持 90（只升不降）
    db.upsert_user_problem_max_score_if_higher(u['id'], pid, 10)
    assert _max_score(u['id'], pid) == 90

    # 相等 → 仍 90
    db.upsert_user_problem_max_score_if_higher(u['id'], pid, 90)
    assert _max_score(u['id'], pid) == 90

    assert _max_score_count(u['id'], pid) == 1


# ---------------- delete_user_problem_max_score ----------------

def test_delete_max_score_removes_row():
    u = h.make_user('msuser5')
    pid = h.make_problem(title='ms题5')

    db.upsert_user_problem_max_score(u['id'], pid, 70)
    assert _max_score_count(u['id'], pid) == 1

    db.delete_user_problem_max_score(u['id'], pid)
    assert _max_score(u['id'], pid) is None
    assert _max_score_count(u['id'], pid) == 0


def test_delete_max_score_absent_is_noop():
    u = h.make_user('msuser6')
    pid = h.make_problem(title='ms题6')

    # 不存在时删除不应报错
    db.delete_user_problem_max_score(u['id'], pid)
    assert _max_score_count(u['id'], pid) == 0
