# -*- coding: utf-8 -*-
"""集成测试：admin_user_routes.py（参考 §4e / Task 30）。

被测路由（oj_modules/routes/admin_user_routes.py）：
- user_management        GET  /admin/users                       筛选 username/class + 分页
- edit_user_ajax         POST /admin/edit_user_ajax              改主班级；Cadmin→is_admin=1；无变化文案
- edit_username_ajax     POST /admin/edit_username_ajax          改名；重名 400
- get_user_grades        GET  /admin/get_user_grades            problems LEFT JOIN max_score
- update_user_grade      POST /admin/update_user_grade          ''→删除；越界拒绝；正常 upsert
- get_problem_scores     GET  /admin/problem_scores/<id>        users JOIN max_score
- add_class_ajax         POST /admin/add_class_ajax             prepend 'C'；建表；重复 400

约定：
- 鉴权走 session['username']；admin_login fixture 自动登录种子 admin。
- DB 每个用例 truncate+reseed（conftest db_reset autouse）。种子：admin、Cadmin/Cclass1。
- 直接 SQL 读回校验落库状态。
"""
import pytest

from oj_modules import db_services as db
from tests import helpers as h


def _grades_of(user_id):
    """直接查 max_score 行，返回 {problem_id: score}。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT problem_id, score FROM max_score WHERE userid=%s",
                (user_id,))
            return {r['problem_id']: r['score'] for r in cur.fetchall()}
    finally:
        conn.close()


def _table_exists(name):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM information_schema.tables "
                "WHERE table_schema=DATABASE() AND table_name=%s", (name,))
            return cur.fetchone()['n'] > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 鉴权：非 admin 一律被拒
# ---------------------------------------------------------------------------
def test_user_management_requires_admin(client, login):
    h.make_user('plainuser')
    login('plainuser')
    resp = client.get('/admin/users')
    # 普通用户：路由直接返回 '<h3>无权限</h3>'（200 文本，不是 JSON）
    assert b'\xe6\x97\xa0\xe6\x9d\x83\xe9\x99\x90' in resp.data  # “无权限”


def test_edit_user_ajax_requires_admin_403(client, login):
    u = h.make_user('plain2')
    login('plain2')
    resp = client.post('/admin/edit_user_ajax',
                       data={'user_id': u['id'], 'class': 'Cclass1'})
    assert resp.status_code == 403
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# user_management：筛选 username / class、分页
# ---------------------------------------------------------------------------
def test_user_management_lists_users(client, admin_login):
    h.make_user('alice', class_en='Cclass1', class_cn='测试班级')
    h.make_user('bob', class_en='Cclass1', class_cn='测试班级')
    resp = client.get('/admin/users')
    assert resp.status_code == 200
    body = resp.data
    assert 'alice'.encode() in body
    assert 'bob'.encode() in body


def test_user_management_filter_by_username(client, admin_login):
    h.make_user('alice', class_en='Cclass1', class_cn='测试班级')
    h.make_user('bob', class_en='Cclass1', class_cn='测试班级')
    resp = client.get('/admin/users', query_string={'username': 'alic'})
    assert resp.status_code == 200
    assert 'alice'.encode() in resp.data
    # 模糊匹配只命中 alice，不应出现 bob
    assert 'bob'.encode() not in resp.data


def test_user_management_filter_by_class(client, admin_login):
    h.make_class('Cother', '别的班')
    h.make_user('inclass1', class_en='Cclass1', class_cn='测试班级')
    h.make_user('inother', class_en='Cother', class_cn='别的班')
    resp = client.get('/admin/users', query_string={'class': 'Cother'})
    assert resp.status_code == 200
    assert 'inother'.encode() in resp.data
    assert 'inclass1'.encode() not in resp.data


def test_user_management_pagination_second_page(client, admin_login):
    # per_page=50；造 51 个用户使第二页存在 1 个用户
    for i in range(51):
        h.make_user(f'pageuser{i:03d}', class_en='Cclass1', class_cn='测试班级')
    page1 = client.get('/admin/users', query_string={'page': 1})
    page2 = client.get('/admin/users', query_string={'page': 2})
    assert page1.status_code == 200
    assert page2.status_code == 200
    # 第一页 50 个 + admin（id 最小，排第一），第 51 个普通用户落到第二页
    assert 'pageuser050'.encode() in page2.data


# ---------------------------------------------------------------------------
# edit_user_ajax：改主班级 / Cadmin→is_admin / 无变化文案 / 缺参 / 不存在
# ---------------------------------------------------------------------------
def test_edit_user_change_primary_class(client, admin_login):
    h.make_class('Cnew', '新班级')
    u = h.make_user('mover', class_en='Cclass1', class_cn='测试班级')
    resp = client.post('/admin/edit_user_ajax',
                       data={'user_id': u['id'], 'class': 'Cnew'})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['user_id'] == u['id']
    assert j['new_class']['class_en'] == 'Cnew'

    after = db.get_user_by_id(u['id'])
    assert after['class'] == 'Cnew'
    assert after['class_cn'] == '新班级'
    # 普通班级不授予管理员
    assert after['is_admin'] == 0
    # user_class_map 主班级翻新
    cls = db.get_user_classes(u['id'])
    assert any(c['class_en'] == 'Cnew' and c['is_primary'] == 1 for c in cls)


def test_edit_user_to_cadmin_grants_admin(client, admin_login):
    u = h.make_user('promoteme', class_en='Cclass1', class_cn='测试班级')
    assert u['is_admin'] == 0
    resp = client.post('/admin/edit_user_ajax',
                       data={'user_id': u['id'], 'class': 'Cadmin'})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    after = db.get_user_by_id(u['id'])
    assert after['class'] == 'Cadmin'
    assert after['is_admin'] == 1


def test_edit_user_no_change_message(client, admin_login):
    # 种子 admin 已在 Cadmin、is_admin=1，再把它改成 Cadmin → 无变化
    admin = db.get_user_by_username('admin')
    resp = client.post('/admin/edit_user_ajax',
                       data={'user_id': admin['id'], 'class': 'Cadmin'})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['message'] == '主班级未变化'


def test_edit_user_missing_params_400(client, admin_login):
    resp = client.post('/admin/edit_user_ajax', data={'user_id': ''})
    assert resp.status_code == 400
    assert resp.get_json()['success'] is False


def test_edit_user_target_class_not_exist_400(client, admin_login):
    u = h.make_user('noclassuser', class_en='Cclass1', class_cn='测试班级')
    resp = client.post('/admin/edit_user_ajax',
                       data={'user_id': u['id'], 'class': 'Cdoesnotexist'})
    assert resp.status_code == 400
    assert resp.get_json()['message'] == '目标班级不存在'


# ---------------------------------------------------------------------------
# edit_username_ajax：改名成功 / 重名 400
# ---------------------------------------------------------------------------
def test_edit_username_success(client, admin_login):
    u = h.make_user('oldname', class_en='Cclass1', class_cn='测试班级')
    resp = client.post('/admin/edit_username_ajax',
                       data={'user_id': u['id'], 'new_username': 'newname'})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['new_username'] == 'newname'
    assert db.get_user_by_username('newname') is not None
    assert db.get_user_by_username('oldname') is None


def test_edit_username_duplicate_400(client, admin_login):
    h.make_user('taken', class_en='Cclass1', class_cn='测试班级')
    u = h.make_user('renameme', class_en='Cclass1', class_cn='测试班级')
    resp = client.post('/admin/edit_username_ajax',
                       data={'user_id': u['id'], 'new_username': 'taken'})
    assert resp.status_code == 400
    j = resp.get_json()
    assert j['success'] is False
    assert j['message'] == '用户名已存在'


def test_edit_username_missing_params_400(client, admin_login):
    resp = client.post('/admin/edit_username_ajax', data={'user_id': '5'})
    assert resp.status_code == 400
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# get_user_grades：仅返回有成绩（score NOT NULL）的题目
# ---------------------------------------------------------------------------
def test_get_user_grades_returns_only_scored(client, admin_login):
    u = h.make_user('graded', class_en='Cclass1', class_cn='测试班级')
    p_written = h.make_problem(title='书面题', type=2)   # max_score=5
    h.make_problem(title='无成绩题', type=1)             # 不写 max_score 行
    db.upsert_user_problem_max_score(u['id'], p_written, 4)

    resp = client.get('/admin/get_user_grades',
                      query_string={'user_id': u['id']})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    grades = j['grades']
    assert len(grades) == 1
    g = grades[0]
    assert g['problem_id'] == p_written
    assert g['problem_title'] == '书面题'
    assert g['user_score'] == 4
    assert g['max_score'] == 5


def test_get_user_grades_missing_user_id_400(client, admin_login):
    resp = client.get('/admin/get_user_grades')
    assert resp.status_code == 400
    assert resp.get_json()['success'] is False


def test_get_user_grades_user_not_found_404(client, admin_login):
    resp = client.get('/admin/get_user_grades',
                      query_string={'user_id': 99999999})
    assert resp.status_code == 404
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# update_user_grade：'' → 删除；越界拒绝；正常 upsert
# ---------------------------------------------------------------------------
def test_update_user_grade_upsert(client, admin_login):
    u = h.make_user('scoreme', class_en='Cclass1', class_cn='测试班级')
    pid = h.make_problem(title='打分题', type=2)  # max_score=5
    resp = client.post('/admin/update_user_grade',
                       data={'user_id': u['id'], 'problem_id': pid, 'score': '3'})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['message'] == '成绩更新成功'
    assert _grades_of(u['id']).get(pid) == 3


def test_update_user_grade_empty_deletes(client, admin_login):
    u = h.make_user('delgrade', class_en='Cclass1', class_cn='测试班级')
    pid = h.make_problem(title='可删题', type=2)
    db.upsert_user_problem_max_score(u['id'], pid, 5)
    assert _grades_of(u['id']).get(pid) == 5

    resp = client.post('/admin/update_user_grade',
                       data={'user_id': u['id'], 'problem_id': pid, 'score': ''})
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    # 空分数 → 删除该 max_score 行
    assert pid not in _grades_of(u['id'])


def test_update_user_grade_out_of_range_rejected(client, admin_login):
    u = h.make_user('overscore', class_en='Cclass1', class_cn='测试班级')
    pid = h.make_problem(title='越界题', type=2)  # max_score=5
    resp = client.post('/admin/update_user_grade',
                       data={'user_id': u['id'], 'problem_id': pid, 'score': '6'})
    assert resp.status_code == 400
    j = resp.get_json()
    assert j['success'] is False
    assert j['message'] == '分数必须在 0 到 5 之间'
    # 拒绝后不应落库
    assert pid not in _grades_of(u['id'])


def test_update_user_grade_problem_not_found_404(client, admin_login):
    u = h.make_user('nogradep', class_en='Cclass1', class_cn='测试班级')
    resp = client.post('/admin/update_user_grade',
                       data={'user_id': u['id'], 'problem_id': 99999999, 'score': '1'})
    assert resp.status_code == 404
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# get_problem_scores：仅非 admin 且 score NOT NULL
# ---------------------------------------------------------------------------
def test_get_problem_scores(client, admin_login):
    pid = h.make_problem(title='成绩榜题', type=2)  # max_score=5
    u1 = h.make_user('stud1', class_en='Cclass1', class_cn='测试班级')
    u2 = h.make_user('stud2', class_en='Cclass1', class_cn='测试班级')
    db.upsert_user_problem_max_score(u1['id'], pid, 5)
    db.upsert_user_problem_max_score(u2['id'], pid, 2)
    # admin 也有成绩，但 is_admin=0 过滤应排除它
    admin = db.get_user_by_username('admin')
    db.upsert_user_problem_max_score(admin['id'], pid, 5)

    resp = client.get(f'/admin/problem_scores/{pid}')
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['problem_id'] == pid
    assert j['problem_title'] == '成绩榜题'
    assert j['max_score'] == 5
    scores = j['scores']
    usernames = {s['username'] for s in scores}
    assert usernames == {'stud1', 'stud2'}
    by_user = {s['username']: s['score'] for s in scores}
    assert by_user['stud1'] == 5
    assert by_user['stud2'] == 2


def test_get_problem_scores_problem_not_found_404(client, admin_login):
    resp = client.get('/admin/problem_scores/99999999')
    assert resp.status_code == 404
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# add_class_ajax：prepend 'C'、建物理表、重复 400、非法字符建表失败 500
# ---------------------------------------------------------------------------
def test_add_class_success_prepends_c_and_creates_table(client, admin_login):
    resp = client.post('/admin/add_class_ajax',
                       data={'class_en': 'grp42', 'class_cn': '小组42'})
    assert resp.status_code == 200
    j = resp.get_json()
    assert j['success'] is True
    assert j['class_en'] == 'Cgrp42'   # 前缀 'C'
    assert j['class_cn'] == '小组42'
    # class_table 落库
    assert db.get_class_by_en('Cgrp42') is not None
    # 动态物理表被创建
    assert _table_exists('Cgrp42')


def test_add_class_duplicate_en_400(client, admin_login):
    # Cclass1 已是种子班级 → 再加（class_en='class1' → 'Cclass1'）应重复
    resp = client.post('/admin/add_class_ajax',
                       data={'class_en': 'class1', 'class_cn': '另一个中文名'})
    assert resp.status_code == 400
    j = resp.get_json()
    assert j['success'] is False
    assert j['message'] == '已存在以这个英文名命名的班级，请修改'


def test_add_class_duplicate_cn_400(client, admin_login):
    # 中文名与种子 Cclass1 的 class_cn '测试班级' 冲突
    resp = client.post('/admin/add_class_ajax',
                       data={'class_en': 'freshen', 'class_cn': '测试班级'})
    assert resp.status_code == 400
    j = resp.get_json()
    assert j['success'] is False
    assert j['message'] == '已存在以这个中文名命名的班级，请修改'


def test_add_class_illegal_chars_fail(client, admin_login):
    # 源码 `re.match(...) is False` 恒为 False（match 返回 None/Match，永不为 False），
    # 故 regex 分支永不触发；非法字符 'a-b' → 'Ca-b' → CREATE TABLE 语法错误 → 500。
    resp = client.post('/admin/add_class_ajax',
                       data={'class_en': 'a-b', 'class_cn': '带横线的班'})
    assert resp.status_code == 500
    assert resp.get_json()['success'] is False
    # 非法名不应残留物理表
    assert not _table_exists('Ca-b')
