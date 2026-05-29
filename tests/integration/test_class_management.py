# -*- coding: utf-8 -*-
"""集成测试：oj_modules/routes/class_management_routes.py（§4g）。

覆盖：upload_exam_scores（openpyxl 生成 xlsx BytesIO → final_exam_scores 入库）；
add_user_to_class / remove_user_from_class（主班级不可移除 400）；get_my_classes；
join_class / leave_class / set_primary_class（开关 403 / Cadmin 拒 / 离开主班级需 >1 班级）。

所有断言围绕状态码、JSON 键/布尔、DB 状态与可从源码逐字引用的中文文案。
"""
import io

import openpyxl
import pytest

from oj_modules import db_services
from tests import helpers


def _query_one(sql, params=()):
    conn = db_services.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()
    finally:
        conn.close()


def _map_row(user_id, class_en):
    return _query_one(
        "SELECT is_primary FROM user_class_map WHERE user_id=%s AND class_en=%s",
        (user_id, class_en),
    )


def _make_xlsx_bytes(rows, header=True):
    """用 openpyxl 在内存里生成 xlsx，返回 BytesIO。"""
    wb = openpyxl.Workbook()
    sheet = wb.active
    if header:
        sheet.append(['学号', '平时成绩', '期末成绩'])
    for r in rows:
        sheet.append(list(r))
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# upload_exam_scores
# ---------------------------------------------------------------------------

def test_upload_exam_scores_writes_final_exam_scores(client, admin_login):
    helpers.make_class('Cgrade', '成绩班')
    buf = _make_xlsx_bytes([('2024001', 80, 90.5), ('2024002', 70, 60)])

    resp = client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cgrade', 'file': (buf, 'scores.xlsx')},
        content_type='multipart/form-data',
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['message'] == '成绩上传成功'

    row = _query_one(
        "SELECT regular_score, final_score FROM final_exam_scores "
        "WHERE class_en=%s AND student_id=%s",
        ('Cgrade', '2024001'),
    )
    assert row is not None
    assert row['regular_score'] == pytest.approx(80.0)
    assert row['final_score'] == pytest.approx(90.5)

    cnt = _query_one(
        "SELECT COUNT(*) AS n FROM final_exam_scores WHERE class_en=%s", ('Cgrade',)
    )
    assert cnt['n'] == 2


def test_upload_exam_scores_on_duplicate_updates(client, admin_login):
    helpers.make_class('Cgrade', '成绩班')
    client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cgrade', 'file': (_make_xlsx_bytes([('s1', 10, 20)]), 'a.xlsx')},
        content_type='multipart/form-data',
    )
    # 同一 (class_en, student_id) 再次上传 → ON DUPLICATE KEY UPDATE 覆盖
    resp = client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cgrade', 'file': (_make_xlsx_bytes([('s1', 55, 66)]), 'b.xlsx')},
        content_type='multipart/form-data',
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True

    row = _query_one(
        "SELECT regular_score, final_score FROM final_exam_scores "
        "WHERE class_en=%s AND student_id=%s",
        ('Cgrade', 's1'),
    )
    assert row['regular_score'] == pytest.approx(55.0)
    assert row['final_score'] == pytest.approx(66.0)
    cnt = _query_one(
        "SELECT COUNT(*) AS n FROM final_exam_scores WHERE class_en=%s", ('Cgrade',)
    )
    assert cnt['n'] == 1


def test_upload_exam_scores_requires_admin(client, login):
    helpers.make_user('stu_upload')
    login('stu_upload')
    resp = client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cclass1', 'file': (_make_xlsx_bytes([('1', 1, 1)]), 'x.xlsx')},
        content_type='multipart/form-data',
    )
    assert resp.status_code == 403
    assert resp.get_json()['success'] is False


def test_upload_exam_scores_unknown_class_400(client, admin_login):
    resp = client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cnope', 'file': (_make_xlsx_bytes([('1', 1, 1)]), 'x.xlsx')},
        content_type='multipart/form-data',
    )
    assert resp.status_code == 400
    assert resp.get_json()['success'] is False


def test_upload_exam_scores_bad_extension_400(client, admin_login):
    helpers.make_class('Cgrade', '成绩班')
    resp = client.post(
        '/admin/upload_exam_scores',
        data={'class_en': 'Cgrade', 'file': (io.BytesIO(b'not excel'), 'scores.txt')},
        content_type='multipart/form-data',
    )
    assert resp.status_code == 400
    assert resp.get_json()['message'] == '仅支持 .xlsx/.xls 文件'


# ---------------------------------------------------------------------------
# add_user_to_class / remove_user_from_class
# ---------------------------------------------------------------------------

def test_add_user_to_class_inserts_non_primary(client, admin_login):
    user = helpers.make_user('add_target')  # 主班级 Cclass1
    helpers.make_class('Cextra', '附加班')

    resp = client.post(
        '/admin/add_user_to_class',
        data={'user_id': user['id'], 'class_en': 'Cextra'},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['added'] is True

    row = _map_row(user['id'], 'Cextra')
    assert row is not None
    assert row['is_primary'] == 0


def test_add_user_to_class_already_primary(client, admin_login):
    user = helpers.make_user('add_primary')  # 主班级 Cclass1
    resp = client.post(
        '/admin/add_user_to_class',
        data={'user_id': user['id'], 'class_en': 'Cclass1'},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['added'] is False
    assert body['reason'] == 'already_primary'


def test_remove_user_from_class_secondary_ok(client, admin_login):
    user = helpers.make_user('rm_target')
    helpers.make_class('Cextra', '附加班')
    client.post(
        '/admin/add_user_to_class',
        data={'user_id': user['id'], 'class_en': 'Cextra'},
    )
    assert _map_row(user['id'], 'Cextra') is not None

    resp = client.post(
        '/admin/remove_user_from_class',
        data={'user_id': user['id'], 'class_en': 'Cextra'},
    )
    assert resp.status_code == 200
    assert resp.get_json()['success'] is True
    assert _map_row(user['id'], 'Cextra') is None


def test_remove_user_from_class_primary_rejected_400(client, admin_login):
    user = helpers.make_user('rm_primary')  # Cclass1 是主班级（is_primary=1）
    resp = client.post(
        '/admin/remove_user_from_class',
        data={'user_id': user['id'], 'class_en': 'Cclass1'},
    )
    assert resp.status_code == 400
    body = resp.get_json()
    assert body['success'] is False
    assert body['message'] == '不能移除主班级，请使用修改主班级功能'
    # 主班级映射仍在
    assert _map_row(user['id'], 'Cclass1') is not None


# ---------------------------------------------------------------------------
# get_my_classes
# ---------------------------------------------------------------------------

def test_get_my_classes_returns_memberships(client, login):
    user = helpers.make_user('mc_user')
    helpers.make_class('Cextra', '附加班')
    login('mc_user')
    # 通过路由加入第二个班级
    client.post('/me/join_class', data={'class_en': 'Cextra'})

    resp = client.get('/me/classes')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['primary_en'] == 'Cclass1'
    member_ens = {m['class_en'] for m in body['memberships']}
    assert 'Cclass1' in member_ens
    assert 'Cextra' in member_ens
    # all_classes 不含 Cadmin
    all_ens = {c['class_en'] for c in body['all_classes']}
    assert 'Cadmin' not in all_ens


def test_get_my_classes_requires_login(client):
    resp = client.get('/me/classes')
    assert resp.status_code == 401
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# join_class
# ---------------------------------------------------------------------------

def test_join_class_success(client, login):
    helpers.make_user('jc_user')
    helpers.make_class('Cextra', '附加班')
    login('jc_user')

    resp = client.post('/me/join_class', data={'class_en': 'Cextra'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['message'] == '成功加入班级'
    assert body['class_cn'] == '附加班'

    user = db_services.get_user_by_username('jc_user')
    row = _map_row(user['id'], 'Cextra')
    assert row is not None
    assert row['is_primary'] == 0


def test_join_class_rejects_cadmin(client, login):
    helpers.make_user('jc_admin')
    login('jc_admin')
    resp = client.post('/me/join_class', data={'class_en': 'Cadmin'})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body['success'] is False
    assert body['message'] == '不能加入管理员班级'


def test_join_class_disabled_403(client, login):
    helpers.make_user('jc_off')
    helpers.make_class('Cextra', '附加班')
    db_services.set_setting('class_adjust_enabled', '0')
    login('jc_off')
    try:
        resp = client.post('/me/join_class', data={'class_en': 'Cextra'})
    finally:
        db_services.set_setting('class_adjust_enabled', '1')
    assert resp.status_code == 403
    assert resp.get_json()['success'] is False


def test_join_class_requires_login(client):
    helpers.make_class('Cextra', '附加班')
    resp = client.post('/me/join_class', data={'class_en': 'Cextra'})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# leave_class
# ---------------------------------------------------------------------------

def test_leave_class_needs_more_than_one(client, login):
    helpers.make_user('lc_single')  # 仅 Cclass1
    login('lc_single')
    resp = client.post('/me/leave_class', data={'class_en': 'Cclass1'})
    assert resp.status_code == 400
    body = resp.get_json()
    assert body['success'] is False
    assert body['message'] == '至少需要保留一个班级'


def test_leave_primary_reassigns_primary(client, login):
    helpers.make_user('lc_multi')  # 主班级 Cclass1
    helpers.make_class('Cextra', '附加班')
    login('lc_multi')
    client.post('/me/join_class', data={'class_en': 'Cextra'})

    user = db_services.get_user_by_username('lc_multi')
    # 离开主班级 Cclass1 → 应重指 Cextra 为主班级
    resp = client.post('/me/leave_class', data={'class_en': 'Cclass1'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['message'] == '成功退出班级'
    assert body['primary_en'] == 'Cextra'

    assert _map_row(user['id'], 'Cclass1') is None
    new_primary = _map_row(user['id'], 'Cextra')
    assert new_primary is not None
    assert new_primary['is_primary'] == 1
    refreshed = db_services.get_user_by_username('lc_multi')
    assert refreshed['class'] == 'Cextra'


def test_leave_class_disabled_403(client, login):
    helpers.make_user('lc_off')
    helpers.make_class('Cextra', '附加班')
    login('lc_off')
    client.post('/me/join_class', data={'class_en': 'Cextra'})
    db_services.set_setting('class_adjust_enabled', '0')
    try:
        resp = client.post('/me/leave_class', data={'class_en': 'Cextra'})
    finally:
        db_services.set_setting('class_adjust_enabled', '1')
    assert resp.status_code == 403
    assert resp.get_json()['success'] is False


# ---------------------------------------------------------------------------
# set_primary_class
# ---------------------------------------------------------------------------

def test_set_primary_class_switches(client, login):
    helpers.make_user('sp_user')  # 主班级 Cclass1
    helpers.make_class('Cextra', '附加班')
    login('sp_user')
    client.post('/me/join_class', data={'class_en': 'Cextra'})

    resp = client.post('/me/set_primary_class', data={'class_en': 'Cextra'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['message'] == '主班级设置成功'

    user = db_services.get_user_by_username('sp_user')
    assert user['class'] == 'Cextra'
    assert _map_row(user['id'], 'Cextra')['is_primary'] == 1
    assert _map_row(user['id'], 'Cclass1')['is_primary'] == 0


def test_set_primary_class_already_primary(client, login):
    helpers.make_user('sp_same')  # 主班级 Cclass1
    login('sp_same')
    resp = client.post('/me/set_primary_class', data={'class_en': 'Cclass1'})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['success'] is True
    assert body['message'] == '已经是主班级'


def test_set_primary_class_disabled_403(client, login):
    helpers.make_user('sp_off')
    helpers.make_class('Cextra', '附加班')
    login('sp_off')
    client.post('/me/join_class', data={'class_en': 'Cextra'})
    db_services.set_setting('class_adjust_enabled', '0')
    try:
        resp = client.post('/me/set_primary_class', data={'class_en': 'Cextra'})
    finally:
        db_services.set_setting('class_adjust_enabled', '1')
    assert resp.status_code == 403
    assert resp.get_json()['success'] is False
