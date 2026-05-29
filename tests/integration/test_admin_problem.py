# -*- coding: utf-8 -*-
"""集成测试：admin_problem_routes.py（建题/改题/上传测试数据/删题）。

参考契约 §4d：
- add_problem  GET/POST /admin/add_problem      → admin；create_problem()；POST 成功跳 problem_list
- edit_problem GET/POST /admin/edit_problem/<id> → admin；get_problem()/update_problem()；POST 成功跳 problem_detail
- upload_testdata POST /admin/upload_testdata/<id> → admin；testdata_zip（仅 zip）；成功 flash '测试数据上传成功。'
- delete_problem DELETE /admin/delete_problem/<id> → admin（非 admin 403）；成功 JSON '题目删除成功'；不存在 404

非 admin 行为（以源码为准 admin_problem_routes.py）：
- add_problem / edit_problem 非 admin → 返回 "<h3>无权限</h3>"（HTTP 200，非 403）
- upload_testdata 非 admin → flash '无权限进行此操作。' + 302 redirect
- delete_problem 非 admin → JSON {success:false, message:'无权限'} + 403
"""
import io
import zipfile

import pytest

from oj_modules import db_services as db
from tests import helpers as h


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------
def _get_problem_row(problem_id):
    """直接读 problems 行（含 testdata 列，get_problem 不返回 testdata）。"""
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM problems WHERE id=%s", (problem_id,))
            return cur.fetchone()
    finally:
        conn.close()


def _make_valid_testdata_zip():
    """构造一个最小合法 testdata zip：成对的 1.in / 1.out。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('1.in', '3 4\n')
        zf.writestr('1.out', '7\n')
        zf.writestr('2.in', '1 1\n')
        zf.writestr('2.out', '2\n')
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# add_problem
# ---------------------------------------------------------------------------
def test_add_problem_admin_creates_and_redirects(client, admin_login):
    r = client.post('/admin/add_problem', data={
        'title': '加法题',
        'content': '计算 a+b。',
        'type': '1',
        'lang': 'python',
        'submission_limit': '10',
    })
    # 成功 → 302 重定向到 problem_core.problem_list（即 /problems）
    assert r.status_code == 302
    assert '/problems' in r.headers['Location']

    # DB 里应有该题
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM problems WHERE title=%s", ('加法题',))
            row = cur.fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row['content'] == '计算 a+b。'
    assert row['lang'] == 'python'
    # type=1（程序题）→ max_score 初始为 0（见 create_problem）
    assert int(row['type']) == 1
    assert int(row['max_score']) == 0


def test_add_problem_missing_title_renders_error(client, admin_login):
    # 标题为空 → 重新渲染 add_problem.html，error_message='标题和内容不能为空'
    r = client.post('/admin/add_problem', data={
        'title': '',
        'content': '有内容',
        'type': '1',
    })
    assert r.status_code == 200
    assert '标题和内容不能为空' in r.get_data(as_text=True)
    # 未入库
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM problems WHERE content=%s", ('有内容',))
            assert cur.fetchone()['n'] == 0
    finally:
        conn.close()


def test_add_problem_get_renders_form(client, admin_login):
    r = client.get('/admin/add_problem')
    assert r.status_code == 200


def test_add_problem_non_admin_denied(client, login):
    h.make_user('stud_add')
    login('stud_add')
    r = client.post('/admin/add_problem', data={
        'title': '不该建成',
        'content': 'x',
        'type': '1',
    })
    # 非 admin → "<h3>无权限</h3>"（HTTP 200）
    assert r.status_code == 200
    assert '无权限' in r.get_data(as_text=True)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM problems WHERE title=%s", ('不该建成',))
            assert cur.fetchone()['n'] == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# edit_problem
# ---------------------------------------------------------------------------
def test_edit_problem_admin_updates_and_redirects(client, admin_login):
    pid = h.make_problem(title='旧标题', content='旧内容', lang='python', type=1)
    r = client.post(f'/admin/edit_problem/{pid}', data={
        'title': '新标题',
        'content': '新内容',
        'lang': 'c',
        'submission_limit': '7',
    })
    assert r.status_code == 302
    # 成功 → 跳 problem_detail
    assert f'/problem' in r.headers['Location'] or str(pid) in r.headers['Location']

    p = db.get_problem(pid)
    assert p['title'] == '新标题'
    assert p['content'] == '新内容'
    assert p['lang'] == 'c'
    assert int(p['submission_limit']) == 7


def test_edit_problem_missing_content_renders_error(client, admin_login):
    pid = h.make_problem(title='保持原样', content='原内容', lang='python', type=1)
    r = client.post(f'/admin/edit_problem/{pid}', data={
        'title': '改了标题',
        'content': '',
    })
    assert r.status_code == 200
    assert '标题和内容不能为空' in r.get_data(as_text=True)
    # 未更新
    p = db.get_problem(pid)
    assert p['title'] == '保持原样'
    assert p['content'] == '原内容'


def test_edit_problem_nonexistent(client, admin_login):
    r = client.get('/admin/edit_problem/999999')
    assert r.status_code == 200
    assert '题目不存在' in r.get_data(as_text=True)


def test_edit_problem_non_admin_denied(client, login):
    pid = h.make_problem(title='受保护', content='c', lang='python', type=1)
    h.make_user('stud_edit')
    login('stud_edit')
    r = client.post(f'/admin/edit_problem/{pid}', data={
        'title': '黑客改的',
        'content': 'evil',
    })
    assert r.status_code == 200
    assert '无权限' in r.get_data(as_text=True)
    p = db.get_problem(pid)
    assert p['title'] == '受保护'


# ---------------------------------------------------------------------------
# upload_testdata
# ---------------------------------------------------------------------------
def test_upload_testdata_valid_zip(client, admin_login):
    pid = h.make_problem(title='上传题', content='c', lang='python', type=1)
    buf = _make_valid_testdata_zip()
    r = client.post(
        f'/admin/upload_testdata/{pid}',
        data={'testdata_zip': (buf, 'data.zip')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert '测试数据上传成功。' in body

    # DB：testdata 写入，max_score 变为测试点数（2）
    row = _get_problem_row(pid)
    assert row['testdata'] is not None and row['testdata'].strip() != ''
    assert int(row['max_score']) == 2


def test_upload_testdata_non_zip_rejected(client, admin_login):
    pid = h.make_problem(title='拒绝非zip', content='c', lang='python', type=1)
    bad = io.BytesIO(b'this is not a zip')
    r = client.post(
        f'/admin/upload_testdata/{pid}',
        data={'testdata_zip': (bad, 'notes.txt')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert r.status_code == 200
    # 扩展名非 .zip → '只允许上传 ZIP 文件。'
    assert '只允许上传 ZIP 文件。' in r.get_data(as_text=True)
    # testdata 未写入
    row = _get_problem_row(pid)
    assert not row['testdata']


def test_upload_testdata_bad_zip_bytes_rejected(client, admin_login):
    pid = h.make_problem(title='坏zip', content='c', lang='python', type=1)
    bad = io.BytesIO(b'corrupt-bytes-not-a-real-zip')
    r = client.post(
        f'/admin/upload_testdata/{pid}',
        data={'testdata_zip': (bad, 'broken.zip')},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert r.status_code == 200
    # .zip 扩展名但内容损坏 → zipfile.BadZipFile → '上传的文件不是有效的 ZIP 压缩包。'
    assert '上传的文件不是有效的 ZIP 压缩包。' in r.get_data(as_text=True)
    row = _get_problem_row(pid)
    assert not row['testdata']


def test_upload_testdata_non_admin_denied(client, login):
    pid = h.make_problem(title='守护题', content='c', lang='python', type=1)
    h.make_user('stud_upload')
    login('stud_upload')
    buf = _make_valid_testdata_zip()
    r = client.post(
        f'/admin/upload_testdata/{pid}',
        data={'testdata_zip': (buf, 'data.zip')},
        content_type='multipart/form-data',
    )
    # 非 admin → flash '无权限进行此操作。' + 302 重定向
    assert r.status_code == 302
    # 测试数据未被导入
    row = _get_problem_row(pid)
    assert not row['testdata']


# ---------------------------------------------------------------------------
# delete_problem
# ---------------------------------------------------------------------------
def test_delete_problem_admin_success(client, admin_login):
    pid = h.make_problem(title='待删除', content='c', lang='python', type=1)
    r = client.delete(f'/admin/delete_problem/{pid}')
    assert r.status_code == 200
    data = r.get_json()
    assert data['success'] is True
    assert data['message'] == '题目删除成功'
    # DB 已删
    assert _get_problem_row(pid) is None


def test_delete_problem_non_admin_403(client, login):
    pid = h.make_problem(title='删不掉', content='c', lang='python', type=1)
    h.make_user('stud_del')
    login('stud_del')
    r = client.delete(f'/admin/delete_problem/{pid}')
    assert r.status_code == 403
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '无权限'
    # 题目仍在
    assert _get_problem_row(pid) is not None


def test_delete_problem_nonexistent_404(client, admin_login):
    r = client.delete('/admin/delete_problem/987654')
    assert r.status_code == 404
    data = r.get_json()
    assert data['success'] is False
    assert data['message'] == '题目不存在'
