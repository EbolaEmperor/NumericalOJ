# -*- coding: utf-8 -*-
"""集成测试：用户头文件仓库（user_code_repository）+ 结构化索引/检索路由。

被测：oj_modules/routes/repository_routes.py
- 文件 list / read / save（扩展名、文件名字符、100KB 上限）/ delete / upload
- 索引 build（拦截 _repository_build_index_task.delay；active job 409）
- 索引 status / status active
- 索引 search（mock _load_faiss_index → faiss hits 结构）
- 索引 classes

约定见 tests/conftest.py：client / login / admin_login / helpers 工厂；
DB 每个测试 truncate+reseed；AI/embedding/SMTP 已 autouse mock。
"""
import io

import pytest

from tests import helpers as h


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------

def _seed_user_and_login(login, username='repouser'):
    """建普通用户并登录，返回 user dict（含 id）。"""
    user = h.make_user(username)
    login(username)
    return user


def _insert_file(user_id, filename='util.h', content='int add(int,int);\n'):
    """直接入库一个仓库文件，返回 file_id。"""
    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO user_code_repository (user_id, filename, file_content, file_size) "
                "VALUES (%s, %s, %s, %s)",
                (user_id, filename, content, len(content.encode('utf-8'))),
            )
            fid = cur.lastrowid
        conn.commit()
    finally:
        conn.close()
    return fid


# --------------------------------------------------------------------------
# 鉴权：未登录一律 401
# --------------------------------------------------------------------------

def test_files_requires_login(client):
    r = client.get('/api/repository/files')
    assert r.status_code == 401
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '未登录'


def test_search_requires_login(client):
    r = client.post('/api/repository/index/search', json={'query': 'x'})
    assert r.status_code == 401
    assert r.get_json()['success'] is False


# --------------------------------------------------------------------------
# 文件列表 / 读取
# --------------------------------------------------------------------------

def test_list_files_returns_user_files(client, login):
    user = _seed_user_and_login(login)
    _insert_file(user['id'], 'a.h', 'aaa')
    _insert_file(user['id'], 'b.cpp', 'bbb')

    r = client.get('/api/repository/files')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    names = sorted(f['filename'] for f in body['files'])
    assert names == ['a.h', 'b.cpp']
    # 每个文件含格式化字段
    f0 = body['files'][0]
    assert 'file_size_kb' in f0 and 'created_at' in f0 and 'updated_at' in f0


def test_list_files_isolated_per_user(client, login):
    other = h.make_user('otheruser')
    _insert_file(other['id'], 'secret.h', 'top secret')
    _seed_user_and_login(login, 'mineuser')

    r = client.get('/api/repository/files')
    assert r.status_code == 200
    assert r.get_json()['files'] == []


def test_read_file_ok(client, login):
    user = _seed_user_and_login(login)
    fid = _insert_file(user['id'], 'lib.hpp', '// header\nclass A {};\n')

    r = client.get(f'/api/repository/file/{fid}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['filename'] == 'lib.hpp'
    assert body['content'] == '// header\nclass A {};\n'


def test_read_file_not_found(client, login):
    _seed_user_and_login(login)
    r = client.get('/api/repository/file/999999')
    assert r.status_code == 404
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '文件不存在'


def test_read_file_other_user_404(client, login):
    other = h.make_user('owner1')
    fid = _insert_file(other['id'], 'priv.h', 'x')
    _seed_user_and_login(login, 'intruder1')

    r = client.get(f'/api/repository/file/{fid}')
    assert r.status_code == 404


# --------------------------------------------------------------------------
# 文件保存（新建 / 更新 / 校验）
# --------------------------------------------------------------------------

def test_save_new_file_ok(client, login):
    user = _seed_user_and_login(login)
    r = client.post('/api/repository/file',
                    json={'filename': 'new.h', 'content': '#pragma once\n'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '文件创建成功'

    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT filename, file_content, file_size FROM user_code_repository "
                "WHERE user_id=%s", (user['id'],))
            row = cur.fetchone()
    finally:
        conn.close()
    assert row['filename'] == 'new.h'
    assert row['file_content'] == '#pragma once\n'
    assert row['file_size'] == len('#pragma once\n'.encode('utf-8'))


def test_save_update_existing_file(client, login):
    user = _seed_user_and_login(login)
    fid = _insert_file(user['id'], 'edit.h', 'old')
    r = client.post('/api/repository/file',
                    json={'filename': 'edit.h', 'content': 'new content', 'file_id': fid})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '文件更新成功'

    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT file_content FROM user_code_repository WHERE id=%s", (fid,))
            row = cur.fetchone()
    finally:
        conn.close()
    assert row['file_content'] == 'new content'


def test_save_empty_filename_rejected(client, login):
    _seed_user_and_login(login)
    r = client.post('/api/repository/file', json={'filename': '', 'content': 'x'})
    assert r.status_code == 400
    assert r.get_json()['message'] == '文件名不能为空'


def test_save_bad_extension_rejected(client, login):
    _seed_user_and_login(login)
    r = client.post('/api/repository/file', json={'filename': 'evil.py', 'content': 'x'})
    assert r.status_code == 400
    assert r.get_json()['message'] == '只允许上传 .h, .hpp, .c, .cpp 文件'


def test_save_bad_filename_chars_rejected(client, login):
    _seed_user_and_login(login)
    # 含空格 → 通过扩展名校验后被字符正则拦截
    r = client.post('/api/repository/file', json={'filename': 'bad name.h', 'content': 'x'})
    assert r.status_code == 400
    assert r.get_json()['message'] == '文件名只能包含字母、数字、下划线、连字符和点'


def test_save_over_100kb_rejected(client, login):
    _seed_user_and_login(login)
    big = 'a' * (100 * 1024 + 1)
    r = client.post('/api/repository/file', json={'filename': 'big.h', 'content': big})
    assert r.status_code == 400
    assert r.get_json()['message'] == '文件大小不能超过100KB'


def test_save_exactly_100kb_ok(client, login):
    _seed_user_and_login(login)
    exact = 'a' * (100 * 1024)
    r = client.post('/api/repository/file', json={'filename': 'edge.h', 'content': exact})
    assert r.status_code == 200
    assert r.get_json()['success'] is True


def test_save_duplicate_filename_conflict(client, login):
    user = _seed_user_and_login(login)
    _insert_file(user['id'], 'dup.h', 'first')
    r = client.post('/api/repository/file', json={'filename': 'dup.h', 'content': 'second'})
    assert r.status_code == 409
    assert r.get_json()['message'] == '文件名已存在'


def test_save_update_nonexistent_file_404(client, login):
    _seed_user_and_login(login)
    r = client.post('/api/repository/file',
                    json={'filename': 'ghost.h', 'content': 'x', 'file_id': 987654})
    assert r.status_code == 404
    assert r.get_json()['message'] == '文件不存在或无权限'


# --------------------------------------------------------------------------
# 文件删除
# --------------------------------------------------------------------------

def test_delete_file_ok(client, login):
    user = _seed_user_and_login(login)
    fid = _insert_file(user['id'], 'del.h', 'x')
    r = client.delete(f'/api/repository/file/{fid}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '文件删除成功'

    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM user_code_repository WHERE id=%s", (fid,))
            assert cur.fetchone()['n'] == 0
    finally:
        conn.close()


def test_delete_file_not_found(client, login):
    _seed_user_and_login(login)
    r = client.delete('/api/repository/file/424242')
    assert r.status_code == 404
    assert r.get_json()['message'] == '文件不存在或无权限'


# --------------------------------------------------------------------------
# 文件上传（multipart）
# --------------------------------------------------------------------------

def test_upload_file_ok(client, login):
    user = _seed_user_and_login(login)
    data = {'file': (io.BytesIO(b'#pragma once\nint f();\n'), 'helper.h')}
    r = client.post('/api/repository/upload', data=data,
                    content_type='multipart/form-data')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '文件上传成功'

    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT filename FROM user_code_repository WHERE user_id=%s", (user['id'],))
            row = cur.fetchone()
    finally:
        conn.close()
    assert row['filename'] == 'helper.h'


def test_upload_no_file_rejected(client, login):
    _seed_user_and_login(login)
    r = client.post('/api/repository/upload', data={},
                    content_type='multipart/form-data')
    assert r.status_code == 400
    assert r.get_json()['message'] == '没有选择文件'


def test_upload_bad_extension_rejected(client, login):
    _seed_user_and_login(login)
    data = {'file': (io.BytesIO(b'print(1)'), 'script.py')}
    r = client.post('/api/repository/upload', data=data,
                    content_type='multipart/form-data')
    assert r.status_code == 400
    assert r.get_json()['message'] == '只允许上传 .h, .hpp, .c, .cpp 文件'


def test_upload_over_100kb_rejected(client, login):
    _seed_user_and_login(login)
    big = b'a' * (100 * 1024 + 1)
    data = {'file': (io.BytesIO(big), 'big.cpp')}
    r = client.post('/api/repository/upload', data=data,
                    content_type='multipart/form-data')
    assert r.status_code == 400
    assert r.get_json()['message'] == '文件大小不能超过100KB'


# --------------------------------------------------------------------------
# 索引构建（build）：拦截注入到路由模块的任务对象 .delay
# --------------------------------------------------------------------------

class _FakeAsyncResult:
    def __init__(self, task_id='fake-task-id'):
        self.id = task_id


class _FakeBuildTask:
    """记录 .delay(*args) 调用，返回带 .id 的 AsyncResult。"""
    def __init__(self, task_id='fake-task-id'):
        self.calls = []
        self._task_id = task_id

    def delay(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return _FakeAsyncResult(self._task_id)


def test_build_index_enqueues_task(client, login, monkeypatch):
    user = _seed_user_and_login(login)
    import oj_modules.routes.repository_routes as m
    fake = _FakeBuildTask('built-123')
    monkeypatch.setattr(m, '_repository_build_index_task', fake)

    r = client.post('/api/repository/index/build', json={})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['message'] == '已开始结构化整理'
    assert body['task_id'] == 'built-123'
    assert isinstance(body['job_id'], int)
    assert body['replaced_job_id'] is None

    # 任务确被入队，且首个位置参数为 user_id
    assert len(fake.calls) == 1
    args, _ = fake.calls[0]
    assert args[0] == user['id']

    # 库里产生了 job 行，且写回了 task_id
    job = m.get_repository_index_job(job_id=body['job_id'], user_id=user['id'])
    assert job is not None
    assert job['task_id'] == 'built-123'


def test_build_index_blocks_when_active_job_present(client, login, monkeypatch):
    user = _seed_user_and_login(login)
    import oj_modules.routes.repository_routes as m
    fake = _FakeBuildTask()
    monkeypatch.setattr(m, '_repository_build_index_task', fake)

    # 预置一个活跃 job（status=running, cancel_requested=0）
    from oj_modules.repository_index_services import create_repository_index_job, update_repository_index_job
    active_id = create_repository_index_job(user['id'])
    update_repository_index_job(active_id, status='running')

    r = client.post('/api/repository/index/build', json={})
    assert r.status_code == 409
    body = r.get_json()
    assert body['success'] is False
    assert body['need_confirm'] is True
    assert body['active_job_id'] == active_id
    # 被拦截 → 没有入队新任务
    assert fake.calls == []


def test_build_index_force_restart_replaces_active(client, login, monkeypatch):
    user = _seed_user_and_login(login)
    import oj_modules.routes.repository_routes as m
    fake = _FakeBuildTask('new-task-9')
    monkeypatch.setattr(m, '_repository_build_index_task', fake)

    from oj_modules.repository_index_services import create_repository_index_job, update_repository_index_job
    active_id = create_repository_index_job(user['id'])
    update_repository_index_job(active_id, status='running')

    r = client.post('/api/repository/index/build', json={'force_restart': True})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['replaced_job_id'] == active_id
    assert body['job_id'] != active_id
    assert len(fake.calls) == 1


def test_build_index_task_not_initialized_500(client, login, monkeypatch):
    _seed_user_and_login(login)
    import oj_modules.routes.repository_routes as m
    monkeypatch.setattr(m, '_repository_build_index_task', None)
    r = client.post('/api/repository/index/build', json={})
    assert r.status_code == 500
    body = r.get_json()
    assert body['success'] is False
    assert body['message'] == '结构化整理任务未初始化'


# --------------------------------------------------------------------------
# 索引状态：单个 job / 活跃 job
# --------------------------------------------------------------------------

def test_index_status_returns_job(client, login):
    user = _seed_user_and_login(login)
    from oj_modules.repository_index_services import create_repository_index_job
    job_id = create_repository_index_job(user['id'])

    r = client.get(f'/api/repository/index/status/{job_id}')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['job']['id'] == job_id
    assert 'progress' in body['job']


def test_index_status_not_found(client, login):
    _seed_user_and_login(login)
    r = client.get('/api/repository/index/status/777777')
    assert r.status_code == 404
    assert r.get_json()['message'] == '任务不存在'


def test_index_status_active_none(client, login):
    _seed_user_and_login(login)
    r = client.get('/api/repository/index/status/active')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['has_active'] is False
    assert body['job'] is None


def test_index_status_active_present(client, login):
    user = _seed_user_and_login(login)
    from oj_modules.repository_index_services import create_repository_index_job, update_repository_index_job
    job_id = create_repository_index_job(user['id'])
    update_repository_index_job(job_id, status='running')

    r = client.get('/api/repository/index/status/active')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['has_active'] is True
    assert body['job']['id'] == job_id


# --------------------------------------------------------------------------
# 索引检索（search）
# --------------------------------------------------------------------------

def test_search_empty_query_rejected(client, login):
    _seed_user_and_login(login)
    r = client.post('/api/repository/index/search', json={'query': '   '})
    assert r.status_code == 400
    assert r.get_json()['message'] == 'query 不能为空'


def test_search_no_index_returns_empty_hits(client, login):
    """无 faiss 索引时返回空 hits（不报错）。"""
    _seed_user_and_login(login)
    r = client.post('/api/repository/index/search', json={'query': 'matrix multiply'})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['hits'] == []
    assert 'embedding_model' in body
    assert 'vector_db_backend' in body


class _FakeFaissIndex:
    """最小 faiss 索引替身：固定维度 + 返回固定 (scores, indexes)。"""
    def __init__(self, dim):
        self.d = dim

    def search(self, q, k):
        import numpy as np
        # 命中 chunk_ids[0]，分数 0.95（高于默认阈值）
        scores = np.array([[0.95]], dtype='float32')
        indexes = np.array([[0]], dtype='int64')
        return scores, indexes


def _seed_chunk(user_id, chunk_id='chunk-1'):
    """入库一个 function chunk + embedding 行，供 _load_chunk_details_by_ids 命中。"""
    from oj_modules import db_services as db
    import config
    dim = int(getattr(config, 'REPOSITORY_EMBEDDING_DIM', 1024))
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO repository_function_chunks
                    (chunk_id, user_id, filename, language, kind, qualified_name,
                     class_name, access_modifier, signature, summary, start_line,
                     end_line, source_hash, code, json_data)
                VALUES (%s,%s,%s,'cpp','function',%s,%s,'public',%s,%s,%s,%s,%s,%s,%s)
                """,
                (chunk_id, user_id, 'mathlib.h', 'mathlib::add',
                 'mathlib', 'int add(int a, int b)', '两数相加', 1, 3,
                 'hash-1', 'int add(int a,int b){return a+b;}', '{}'),
            )
            cur.execute(
                """
                INSERT INTO repository_chunk_embeddings
                    (chunk_id, user_id, embedding_model, vector_dim, vector_json)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (chunk_id, user_id, 'fake-embed', dim, '[]'),
            )
        conn.commit()
    finally:
        conn.close()


def test_search_returns_hits_structure(client, login, monkeypatch):
    """mock faiss 索引 + 入库 chunk → 返回结构化 hits。embedding 已在 conftest mock。"""
    user = _seed_user_and_login(login)
    _seed_chunk(user['id'], 'chunk-1')

    import config
    dim = int(getattr(config, 'REPOSITORY_EMBEDDING_DIM', 1024))
    import oj_modules.repository_index_services as ris
    fake_index = _FakeFaissIndex(dim)
    fake_meta = {'chunk_ids': ['chunk-1'], 'embedding_model': 'fake-embed'}
    monkeypatch.setattr(ris, '_load_faiss_index', lambda uid: (fake_index, fake_meta))

    r = client.post('/api/repository/index/search',
                    json={'query': 'add two ints', 'top_k': 5})
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['query'] == 'add two ints'
    assert len(body['hits']) == 1
    hit = body['hits'][0]
    assert hit['chunk_id'] == 'chunk-1'
    assert hit['filename'] == 'mathlib.h'
    assert hit['qualified_name'] == 'mathlib::add'
    assert hit['signature'] == 'int add(int a, int b)'
    assert hit['code'].startswith('int add')
    assert hit['score'] > 0
    assert 'embedding_model' in body
    assert 'vector_db_backend' in body


# --------------------------------------------------------------------------
# 索引类结构（classes）
# --------------------------------------------------------------------------

def test_classes_empty(client, login):
    _seed_user_and_login(login)
    r = client.get('/api/repository/index/classes')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['classes'] == []
    assert body['count'] == 0


def test_classes_returns_seeded_metadata(client, login):
    user = _seed_user_and_login(login)
    from oj_modules import db_services as db
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO repository_class_metadata
                    (class_id, user_id, filename, kind, class_name, qualified_name,
                     source_hash, json_data)
                VALUES (%s,%s,%s,'class',%s,%s,%s,%s)
                """,
                ('cls-1', user['id'], 'shapes.hpp', 'Circle', 'geom::Circle',
                 'h1', '{"bases":["Shape"],"member_variables":[],"member_methods":[]}'),
            )
        conn.commit()
    finally:
        conn.close()

    r = client.get('/api/repository/index/classes?limit=50')
    assert r.status_code == 200
    body = r.get_json()
    assert body['success'] is True
    assert body['count'] == 1
    cls = body['classes'][0]
    assert cls['class_id'] == 'cls-1'
    assert cls['class_name'] == 'Circle'
    assert cls['qualified_name'] == 'geom::Circle'
    assert cls['bases'] == ['Shape']
