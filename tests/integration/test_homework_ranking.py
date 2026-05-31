# -*- coding: utf-8 -*-
"""布置「打榜赛」作为作业 + 学生首页显示（集成）。

覆盖：班级动态表新增 ranking_competition_id 列；admin_add_homework 两类型分支与校验；
_get_homeworks_for_classes 对打榜赛作业的完成判定（需有成功评分）与最高分；学生 /problems 渲染。
"""
from oj_modules import db_services as db
from oj_modules import ranking_db
import oj_modules.routes.problem_core_routes as pc
from tests import helpers as h


def _make_dynamic_class(client, short_en, class_cn):
    r = client.post('/admin/add_class_ajax', data={'class_en': short_en, 'class_cn': class_cn})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['class_en']


def _rows(class_en):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(f"SELECT * FROM {class_en} ORDER BY id ASC")
            return c.fetchall()
    finally:
        conn.close()


def _make_comp(title='打榜赛作业', mode='absolute', max_score=100):
    cid = ranking_db.create_competition(title=title, description='d', max_score=max_score,
                                        created_by='admin', summary='s')
    ranking_db.update_competition(cid, scoring_mode=mode)
    return cid


def _insert_ranking_hw(class_en, cid, title='打榜赛作业', ddl='2030-01-01 00:00:00'):
    db.ensure_class_homework_columns(class_en)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(
                f"INSERT INTO {class_en} (ranking_competition_id, ddl, complete_cnt, problem_title) "
                "VALUES (%s, %s, 0, %s)", (cid, ddl, title))
        conn.commit()
    finally:
        conn.close()


# ---- 班级表迁移 ----
def test_new_class_table_has_ranking_column(client, admin_login):
    class_en = _make_dynamic_class(client, 'rkcol', '列班')
    conn = db.get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(f"SHOW COLUMNS FROM {class_en} LIKE 'ranking_competition_id'")
            assert c.fetchone() is not None
    finally:
        conn.close()


def test_ensure_class_homework_columns_idempotent_and_migrates(client, admin_login):
    # 用 helpers.make_class 建的旧结构表（无该列），ensure 后应补上
    h.make_class('Cmig', '迁移班')
    db.ensure_class_homework_columns('Cmig')
    db.ensure_class_homework_columns('Cmig')  # 幂等
    conn = db.get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("SHOW COLUMNS FROM Cmig LIKE 'ranking_competition_id'")
            assert c.fetchone() is not None
    finally:
        conn.close()


# ---- 布置作业（两类型） ----
def test_assign_ranking_homework(client, admin_login):
    class_en = _make_dynamic_class(client, 'rkhw', '打榜作业班')
    cid = _make_comp(title='打榜赛作业')
    r = client.post('/admin/add_homework',
                    data={'class_en': class_en, 'ranking_competition_id': str(cid),
                          'ddl': '2030-06-01 12:00:00'})
    assert r.status_code in (301, 302)
    rows = _rows(class_en)
    assert len(rows) == 1
    assert rows[0]['ranking_competition_id'] == cid
    assert rows[0]['problem_id'] is None
    assert rows[0]['problem_title'] == '打榜赛作业'


def test_assign_problem_homework_still_works(client, admin_login):
    class_en = _make_dynamic_class(client, 'rkprob', '题目作业班')
    pid = h.make_problem(title='普通题')
    r = client.post('/admin/add_homework',
                    data={'class_en': class_en, 'problem_id': str(pid),
                          'ddl': '2030-06-01 12:00:00'})
    assert r.status_code in (301, 302)
    rows = _rows(class_en)
    assert len(rows) == 1 and rows[0]['problem_id'] == pid
    assert rows[0]['ranking_competition_id'] is None


def test_assign_homework_requires_exactly_one(client, admin_login):
    class_en = _make_dynamic_class(client, 'rkxor', 'XOR班')
    pid = h.make_problem(title='题Y')
    cid = _make_comp()
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'problem_id': str(pid),
                      'ranking_competition_id': str(cid), 'ddl': '2030-01-01 00:00:00'})
    assert len(_rows(class_en)) == 0  # 两者都给 → 拒绝
    client.post('/admin/add_homework', data={'class_en': class_en, 'ddl': '2030-01-01 00:00:00'})
    assert len(_rows(class_en)) == 0  # 都不给 → 拒绝


def test_assign_ranking_homework_nonexistent(client, admin_login):
    class_en = _make_dynamic_class(client, 'rknone', '坏赛班')
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'ranking_competition_id': '999999',
                      'ddl': '2030-01-01 00:00:00'})
    assert len(_rows(class_en)) == 0


# ---- 学生侧：完成判定 + 最高分 ----
def test_ranking_homework_completed_when_scored(client):
    u = h.make_user('rkdone')  # 默认在 Cclass1
    cid = _make_comp(title='RK已完成', max_score=40)
    _insert_ranking_hw('Cclass1', cid, title='RK已完成')
    sid = ranking_db.create_ranking_submission(cid, 'rkdone')
    ranking_db.update_submission_result(sid, 33.0, 'Accepted')  # 成功评分
    pc._homeworks_cache.clear()
    m = pc._get_homeworks_for_classes(u['id'], ['Cclass1'], username='rkdone')
    rk = [x for x in m['Cclass1'] if x.get('kind') == 'ranking']
    assert len(rk) == 1
    hw = rk[0]
    assert hw['competition_id'] == cid
    assert hw['is_completed'] is True
    assert hw['max_score'] == 33.0
    assert hw['total_score'] == 40


def test_ranking_homework_not_completed_when_only_judging(client):
    u = h.make_user('rkjud')
    cid = _make_comp(title='RK评测中', max_score=30)
    _insert_ranking_hw('Cclass1', cid, title='RK评测中')
    sid = ranking_db.create_ranking_submission(cid, 'rkjud')
    ranking_db.update_submission_files(sid, None, None, 'c.zip', '/tmp/c', base_model='m')  # status Judging, score NULL
    pc._homeworks_cache.clear()
    m = pc._get_homeworks_for_classes(u['id'], ['Cclass1'], username='rkjud')
    hw = [x for x in m['Cclass1'] if x.get('kind') == 'ranking'][0]
    assert hw['is_completed'] is False
    assert hw['max_score'] is None


def test_student_homepage_shows_ranking_homework(client, login):
    h.make_user('rkpage')
    cid = _make_comp(title='RK首页展示', max_score=50)
    _insert_ranking_hw('Cclass1', cid, title='RK首页展示')
    sid = ranking_db.create_ranking_submission(cid, 'rkpage')
    ranking_db.update_submission_result(sid, 42.0, 'Accepted')
    pc._homeworks_cache.clear()
    login('rkpage')
    r = client.get('/problems')
    body = r.get_data(as_text=True)
    assert r.status_code == 200
    assert 'RK首页展示' in body
    assert '打榜赛' in body                       # 标签
    assert f'/ranking/{cid}/' in body             # 链接到打榜赛
    assert '42' in body and '/ 50' in body        # 最高分 / 满分
