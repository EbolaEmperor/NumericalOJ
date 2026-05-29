# -*- coding: utf-8 -*-
"""homework_routes.py 集成测试（§4f）。

覆盖：admin_homework / class_adjust(set_setting) / update_ddl / add+delete_homework
（先 add_class_ajax 建动态班级表）/ export_scores CSV / export_student_codes
（拦截 _export_task.delay）→ export_progress（Redis）→ download_export（Redis binary）。

约定（见 conftest）：
- admin_login fixture 已登录种子 admin('admin'/'admin123')。
- DB 每个测试 truncate+reseed；动态班级表（^C\\w+）会被 DROP。
- 直接 SQL 查库走 db_services.get_db_connection()。
- 拦截任务用 monkeypatch 路由模块注入的任务对象 _export_task。
"""
import io
import json
import uuid

import pytest

from oj_modules import db_services as db
import oj_modules.routes.homework_routes as hw
from tests import helpers as h


# ---------------------------------------------------------------------------
# 辅助：用 add_class_ajax 建一个动态班级表（route 会把 'C' 前缀加上）。
# 传入 short_en='hw' → 实际 class_en='Chw'，并物理创建表 Chw。
# ---------------------------------------------------------------------------
def _make_dynamic_class(client, short_en, class_cn):
    r = client.post('/admin/add_class_ajax',
                    data={'class_en': short_en, 'class_cn': class_cn})
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    assert body['success'] is True
    return body['class_en']  # e.g. 'Chw'


def _count_homework_rows(class_en):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) AS n FROM {class_en}")
            return cur.fetchone()['n']
    finally:
        conn.close()


def _first_homework_row(class_en):
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM {class_en} ORDER BY id ASC LIMIT 1")
            return cur.fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# admin_homework 列表
# ---------------------------------------------------------------------------
def test_admin_homework_no_class_selected(client, admin_login):
    r = client.get('/admin/homework')
    assert r.status_code == 200


def test_admin_homework_requires_admin(client, login):
    u = h.make_user('stud_hw1')
    login('stud_hw1')
    r = client.get('/admin/homework')
    # 非管理员返回 <h3>无权限</h3>（200，但内容是无权限提示）
    assert '无权限' in r.get_data(as_text=True)


def test_admin_homework_invalid_class_redirects(client, admin_login):
    # 不存在的班级 → flash + 重定向回 admin_homework
    r = client.get('/admin/homework?sclass=CnotExist')
    assert r.status_code in (301, 302)


def test_admin_homework_lists_selected_class(client, admin_login):
    class_en = _make_dynamic_class(client, 'hwlist', '作业列表班')
    pid = h.make_problem(title='作业题A')
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'problem_id': str(pid), 'ddl': '2030-01-01 00:00:00'})
    r = client.get(f'/admin/homework?sclass={class_en}')
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# class_adjust → set_setting
# ---------------------------------------------------------------------------
def test_class_adjust_disable_then_enable(client, admin_login):
    r = client.post('/admin/class_adjust', data={'enabled': '0'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['enabled'] is False
    # 持久化到 site_settings：is_class_adjust_enabled 应为 False
    assert db.is_class_adjust_enabled() is False

    r = client.post('/admin/class_adjust', data={'enabled': '1'})
    assert r.get_json()['enabled'] is True
    assert db.is_class_adjust_enabled() is True


def test_class_adjust_requires_admin(client, login):
    h.make_user('stud_hw2')
    login('stud_hw2')
    r = client.post('/admin/class_adjust', data={'enabled': '0'})
    assert r.status_code == 403
    assert r.get_json()['success'] is False


# ---------------------------------------------------------------------------
# add_homework / update_ddl / delete_homework （动态表）
# ---------------------------------------------------------------------------
def test_add_homework_inserts_row(client, admin_login):
    class_en = _make_dynamic_class(client, 'add', '加作业班')
    pid = h.make_problem(title='被布置的题')
    r = client.post('/admin/add_homework',
                    data={'class_en': class_en, 'problem_id': str(pid),
                          'ddl': '2030-06-01 12:00:00'})
    # 成功后重定向回 admin_homework
    assert r.status_code in (301, 302)
    assert _count_homework_rows(class_en) == 1
    row = _first_homework_row(class_en)
    assert row['problem_id'] == pid
    assert row['problem_title'] == '被布置的题'


def test_add_homework_nonexistent_problem(client, admin_login):
    class_en = _make_dynamic_class(client, 'addbad', '坏题班')
    r = client.post('/admin/add_homework',
                    data={'class_en': class_en, 'problem_id': '999999',
                          'ddl': '2030-06-01 12:00:00'})
    assert r.status_code in (301, 302)
    assert _count_homework_rows(class_en) == 0


def test_update_ddl_updates_dynamic_table(client, admin_login):
    class_en = _make_dynamic_class(client, 'ddl', '改DDL班')
    pid = h.make_problem(title='改DDL题')
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'problem_id': str(pid),
                      'ddl': '2030-01-01 00:00:00'})
    hw_row = _first_homework_row(class_en)
    homework_id = hw_row['id']

    r = client.post('/admin/update_ddl',
                    json={'class_en': class_en, 'homework_id': homework_id,
                          'new_ddl': '2031-12-31 23:59:59'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == 'DDL更新成功'

    updated = _first_homework_row(class_en)
    assert str(updated['ddl']).startswith('2031-12-31')


def test_update_ddl_missing_params(client, admin_login):
    r = client.post('/admin/update_ddl', json={'class_en': 'Cwhatever'})
    assert r.status_code == 400
    assert r.get_json()['success'] is False


def test_update_ddl_unknown_class(client, admin_login):
    r = client.post('/admin/update_ddl',
                    json={'class_en': 'CnoSuch', 'homework_id': 1,
                          'new_ddl': '2030-01-01 00:00:00'})
    assert r.status_code == 400
    assert r.get_json()['success'] is False


def test_delete_homework_removes_row(client, admin_login):
    class_en = _make_dynamic_class(client, 'del', '删作业班')
    pid = h.make_problem(title='删作业题')
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'problem_id': str(pid),
                      'ddl': '2030-01-01 00:00:00'})
    homework_id = _first_homework_row(class_en)['id']
    assert _count_homework_rows(class_en) == 1

    r = client.post('/admin/delete_homework',
                    json={'class_en': class_en, 'homework_id': homework_id})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '删除成功'
    assert _count_homework_rows(class_en) == 0


def test_delete_homework_requires_admin(client, login):
    h.make_user('stud_hw3')
    login('stud_hw3')
    r = client.post('/admin/delete_homework',
                    json={'class_en': 'Cx', 'homework_id': 1})
    assert r.status_code == 403
    assert r.get_json()['success'] is False


# ---------------------------------------------------------------------------
# export_scores → CSV(GBK)
# ---------------------------------------------------------------------------
def test_export_scores_csv(client, admin_login):
    class_en = _make_dynamic_class(client, 'exp', '导出班')
    pid = h.make_problem(title='导出题')
    client.post('/admin/add_homework',
                data={'class_en': class_en, 'problem_id': str(pid),
                      'ddl': '2030-01-01 00:00:00'})

    # make_user 已把该学生设为 class_en 的主班级成员（user_class_map 已建），这里只补成绩
    u = h.make_user('expstud', class_en=class_en, class_cn='导出班')
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            # 给该学生一个该题成绩
            cur.execute(
                "INSERT INTO max_score (userid, problem_id, score) VALUES (%s,%s,%s)",
                (u['id'], pid, 80))
        conn.commit()
    finally:
        conn.close()

    r = client.get(f'/export_scores?sclass={class_en}')
    assert r.status_code == 200
    assert 'text/csv' in r.headers.get('Content-Type', '')
    assert f'{class_en}_scores.csv' in r.headers.get('Content-Disposition', '')
    text = r.get_data().decode('gbk')
    # 表头列含 用户名 与 总分；数据行含学生名与分数
    assert '用户名' in text
    assert '总分' in text
    assert 'expstud' in text
    assert '80' in text


def test_export_scores_missing_class_param(client, admin_login):
    r = client.get('/export_scores')
    assert r.status_code == 400


def test_export_scores_unknown_class(client, admin_login):
    r = client.get('/export_scores?sclass=CnoSuch')
    assert r.status_code == 404


def test_export_scores_requires_admin(client, login):
    h.make_user('stud_hw4')
    login('stud_hw4')
    r = client.get('/export_scores?sclass=Cclass1')
    # 非管理员重定向到登录页
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


# ---------------------------------------------------------------------------
# export_student_codes（拦截 _export_task.delay）→ export_progress → download_export
# ---------------------------------------------------------------------------
class _FakeTask:
    """记录 .delay 调用，返回带 .id 的假 AsyncResult。"""

    def __init__(self, task_id):
        self.task_id = task_id
        self.calls = []

    def delay(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return type('R', (), {'id': self.task_id})()


def test_export_student_codes_enqueues_task(client, admin_login, monkeypatch):
    fake = _FakeTask('task-export-abc')
    monkeypatch.setattr(hw, '_export_task', fake)

    r = client.get('/export_student_codes?sclass=Cclass1')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['task_id'] == 'task-export-abc'
    assert body['message'] == '导出任务已启动'
    # delay 被调用且参数是所选班级
    assert fake.calls == [(('Cclass1',), {})]


def test_export_student_codes_missing_class(client, admin_login, monkeypatch):
    monkeypatch.setattr(hw, '_export_task', _FakeTask('x'))
    r = client.get('/export_student_codes')
    assert r.status_code == 400
    assert r.get_json()['success'] is False


def test_export_student_codes_requires_admin(client, login):
    h.make_user('stud_hw5')
    login('stud_hw5')
    r = client.get('/export_student_codes?sclass=Cclass1')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')


def test_export_progress_reads_redis(client, admin_login):
    task_id = 'progress-' + uuid.uuid4().hex
    # update_export_progress 直接写 Redis（_rds 已由 init_homework_module 注入）
    hw.update_export_progress(task_id, 'collecting', 30, 100, '收集中')
    try:
        r = client.get(f'/export_progress/{task_id}')
        assert r.status_code == 200
        body = r.get_json()
        assert body['success'] is True
        prog = body['progress']
        assert prog['stage'] == 'collecting'
        assert prog['current'] == 30
        assert prog['total'] == 100
        assert prog['percentage'] == 30
        assert prog['message'] == '收集中'
    finally:
        hw._rds.delete(f'export_progress:{task_id}')


def test_export_progress_not_found(client, admin_login):
    r = client.get(f'/export_progress/missing-{uuid.uuid4().hex}')
    assert r.status_code == 404
    assert r.get_json()['success'] is False


def test_export_progress_requires_admin(client, login):
    h.make_user('stud_hw6')
    login('stud_hw6')
    r = client.get('/export_progress/anything')
    assert r.status_code == 403
    assert r.get_json()['success'] is False


def test_download_export_serves_zip(client, admin_login):
    task_id = 'zip-' + uuid.uuid4().hex
    zip_bytes = b'PK\x03\x04fakezipcontent'
    # 写入二进制缓存（_rds_binary 由 init_homework_module 注入）
    hw._rds_binary.setex(f'export_zip:{task_id}', 600, zip_bytes)
    try:
        r = client.get(f'/download_export/{task_id}')
        assert r.status_code == 200
        assert r.headers.get('Content-Type') == 'application/zip'
        assert 'student_codes.zip' in r.headers.get('Content-Disposition', '')
        assert r.get_data() == zip_bytes
    finally:
        hw._rds_binary.delete(f'export_zip:{task_id}')


def test_download_export_not_found(client, admin_login):
    r = client.get(f'/download_export/missing-{uuid.uuid4().hex}')
    assert r.status_code == 404


def test_download_export_requires_admin(client, login):
    h.make_user('stud_hw7')
    login('stud_hw7')
    r = client.get('/download_export/anything')
    assert r.status_code in (301, 302)
    assert '/login' in r.headers.get('Location', '')
