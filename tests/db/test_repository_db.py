# -*- coding: utf-8 -*-
"""DB 层测试：repository 索引任务 + 类元数据 + 仓库文件查询。

覆盖（参考 §1c）：
- create_repository_index_job / update_repository_index_job（白名单字段，unknown 忽略）
- get_repository_index_job（progress = round(done/total*100)，或 status=='success' → 100）
- get_latest_active_repository_index_job（queued/running 在取消确认前保持 active）
- list_repository_classes（只读已发布 generation，limit 夹紧 min(max(1,limit),2000)）
- get_user_repository_files_by_names（{filename: content}）

注意：表结构由测试会话启动时的统一数据库初始化脚本保证，测试本身不再补表补列。
"""
import json

from oj_modules import db_services as db
from oj_modules.repository import includes as rsvc
from oj_modules.repository import index as ris
from oj_modules.repository import tree as tree_services
from tests import helpers as h


def _ensure_active_index_generation(user_id):
    """为直接 SQL 测试建立一个已发布的索引 generation。"""
    state = tree_services.get_repository_state(int(user_id))
    active_generation = state.get('active_index_generation')
    if active_generation is not None:
        return int(active_generation)

    generation = ris.create_repository_index_job(int(user_id))
    ris.update_repository_index_job(
        generation,
        status='success',
        base_repository_generation=state['repository_generation'],
    )
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE repository_states
                SET active_index_generation = %s, index_status = 'ready'
                WHERE user_id = %s
                """,
                (generation, int(user_id)),
            )
        conn.commit()
    finally:
        conn.close()
    return generation


def _insert_class_metadata(user_id, class_id, filename, class_name,
                           qualified_name='', kind='class', source_hash='hh',
                           json_data=None, index_generation=None):
    """直接 SQL 写入一行 repository_class_metadata（绕过 LLM 结构化路径）。"""
    generation = (
        _ensure_active_index_generation(user_id)
        if index_generation is None
        else int(index_generation)
    )
    payload = json.dumps(json_data or {}, ensure_ascii=False)
    conn = db.get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO repository_class_metadata
                    (class_id, user_id, index_generation, repo_file_id, filename, kind,
                     class_name, qualified_name, source_hash,
                     bases_json, members_json, json_data)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (class_id, int(user_id), generation, None, filename, kind, class_name,
                 qualified_name or class_name, source_hash, '[]', '[]', payload),
            )
        conn.commit()
    finally:
        conn.close()


def _insert_repo_file(user_id, filename, content):
    state = tree_services.get_repository_state(int(user_id))
    tree_services.upsert_repository_file_by_path(
        int(user_id),
        filename,
        content,
        expected_structure_version=state["structure_version"],
    )


# ---------------------------------------------------------------------------
# create / update / get repository_index_job
# ---------------------------------------------------------------------------
def test_create_repository_index_job_initial_state():
    u = h.make_user('repouser1')
    job_id = ris.create_repository_index_job(u['id'])
    assert isinstance(job_id, int) and job_id > 0

    job = ris.get_repository_index_job(job_id, u['id'])
    assert job is not None
    assert job['status'] == 'queued'
    assert job['total_files'] == 0
    assert job['processed_files'] == 0
    # 新建未开始：progress 既非 success 也无 total → 0
    assert job['progress'] == 0


def test_get_repository_index_job_scoped_to_user():
    owner = h.make_user('repoowner')
    other = h.make_user('repoother')
    job_id = ris.create_repository_index_job(owner['id'])
    # 用错误的 user_id 取不到
    assert ris.get_repository_index_job(job_id, other['id']) is None
    # 正确的 user_id 取得到
    assert ris.get_repository_index_job(job_id, owner['id']) is not None


def test_update_repository_index_job_whitelist_and_progress():
    u = h.make_user('repouser2')
    job_id = ris.create_repository_index_job(u['id'])

    # 白名单字段生效；非白名单 'bogus_field' 被静默忽略（否则 SQL 会报未知列）
    ris.update_repository_index_job(
        job_id,
        status='running',
        total_files=4,
        processed_files=1,
        task_id='task-xyz',
        progress_message='处理中',
        bogus_field='应被忽略',
    )
    job = ris.get_repository_index_job(job_id, u['id'])
    assert job['status'] == 'running'
    assert job['total_files'] == 4
    assert job['processed_files'] == 1
    assert job['task_id'] == 'task-xyz'
    # progress = round(1/4*100) = 25
    assert job['progress'] == 25


def test_update_repository_index_job_progress_rounding():
    u = h.make_user('repouser3')
    job_id = ris.create_repository_index_job(u['id'])
    # 1/3 → round(33.33..) = 33
    ris.update_repository_index_job(job_id, total_files=3, processed_files=1, status='running')
    assert ris.get_repository_index_job(job_id, u['id'])['progress'] == 33
    # 2/3 → round(66.66..) = 67
    ris.update_repository_index_job(job_id, total_files=3, processed_files=2)
    assert ris.get_repository_index_job(job_id, u['id'])['progress'] == 67


def test_update_repository_index_job_unknown_only_is_noop():
    u = h.make_user('repouser4')
    job_id = ris.create_repository_index_job(u['id'])
    before = ris.get_repository_index_job(job_id, u['id'])
    # 全部字段都不在白名单 → 直接 return，无 SQL 执行、无异常
    ris.update_repository_index_job(job_id, totally_unknown=1, another_bad='x')
    after = ris.get_repository_index_job(job_id, u['id'])
    assert after['status'] == before['status']
    assert after['total_files'] == before['total_files']


def test_get_repository_index_job_success_forces_full_progress():
    u = h.make_user('repouser5')
    job_id = ris.create_repository_index_job(u['id'])
    # success 但 total_files 仍为 0 → progress 应被强制为 100
    ris.update_repository_index_job(job_id, status='success', total_files=0, processed_files=0)
    job = ris.get_repository_index_job(job_id, u['id'])
    assert job['status'] == 'success'
    assert job['progress'] == 100


def test_get_repository_index_job_missing_returns_none():
    u = h.make_user('repouser6')
    assert ris.get_repository_index_job(999999, u['id']) is None


# ---------------------------------------------------------------------------
# get_latest_active_repository_index_job
# ---------------------------------------------------------------------------
def test_latest_active_returns_newest_active_job():
    u = h.make_user('repoactive1')
    old_id = ris.create_repository_index_job(u['id'])
    new_id = ris.create_repository_index_job(u['id'])
    assert new_id > old_id

    active = ris.get_latest_active_repository_index_job(u['id'])
    assert active is not None
    # 两个都是 queued（active）→ 取 id 最大者
    assert active['id'] == new_id


def test_latest_active_excludes_finished_but_keeps_running_cancel_request():
    u = h.make_user('repoactive2')
    job_id = ris.create_repository_index_job(u['id'])

    # success 不算 active
    ris.update_repository_index_job(job_id, status='success')
    assert ris.get_latest_active_repository_index_job(u['id']) is None

    # running 的取消请求在 worker 确认终态前仍算 active，避免并发启动第二个 job。
    running = ris.create_repository_index_job(u['id'])
    ris.update_repository_index_job(running, status='running')
    ris.request_cancel_repository_index_job(running, user_id=u['id'])
    active = ris.get_latest_active_repository_index_job(u['id'])
    assert active is not None and active['id'] == running
    assert active['status'] == 'running'
    assert active['cancel_requested'] == 1

    ris.update_repository_index_job(running, status='canceled')
    assert ris.get_latest_active_repository_index_job(u['id']) is None


def test_latest_active_none_for_user_without_jobs():
    u = h.make_user('repoactive3')
    assert ris.get_latest_active_repository_index_job(u['id']) is None


# ---------------------------------------------------------------------------
# list_repository_classes
# ---------------------------------------------------------------------------
def test_list_repository_classes_returns_and_parses_json():
    u = h.make_user('repocls1')
    _insert_class_metadata(
        u['id'], class_id='cid-a', filename='a.hpp', class_name='Alpha',
        json_data={
            'bases': [{'base_name': 'Base', 'access': 'public'}],
            'member_variables': [{'name': 'x', 'type': 'int'}],
            'member_methods': [{'name': 'run', 'signature': 'void run()'}],
        },
    )
    rows = ris.list_repository_classes(u['id'])
    assert len(rows) == 1
    item = rows[0]
    assert item['class_id'] == 'cid-a'
    assert item['class_name'] == 'Alpha'
    assert item['filename'] == 'a.hpp'
    # json_data 被解析展开
    assert item['bases'] == [{'base_name': 'Base', 'access': 'public'}]
    assert item['member_variables'] == [{'name': 'x', 'type': 'int'}]
    assert item['member_methods'] == [{'name': 'run', 'signature': 'void run()'}]


def test_list_repository_classes_orders_by_filename_then_classname():
    u = h.make_user('repocls2')
    _insert_class_metadata(u['id'], 'c1', 'b.hpp', 'Zed')
    _insert_class_metadata(u['id'], 'c2', 'a.hpp', 'Beta')
    _insert_class_metadata(u['id'], 'c3', 'a.hpp', 'Alpha')
    rows = ris.list_repository_classes(u['id'])
    # ORDER BY filename ASC, class_name ASC
    assert [(r['filename'], r['class_name']) for r in rows] == [
        ('a.hpp', 'Alpha'),
        ('a.hpp', 'Beta'),
        ('b.hpp', 'Zed'),
    ]


def test_list_repository_classes_scoped_to_user():
    owner = h.make_user('repocls3a')
    other = h.make_user('repocls3b')
    _insert_class_metadata(owner['id'], 'own-1', 'x.hpp', 'Owned')
    _insert_class_metadata(other['id'], 'oth-1', 'y.hpp', 'Foreign')
    rows = ris.list_repository_classes(owner['id'])
    assert len(rows) == 1
    assert rows[0]['class_name'] == 'Owned'


def test_list_repository_classes_hides_unpublished_generation():
    u = h.make_user('repocls3c')
    _insert_class_metadata(u['id'], 'published-1', 'stable.hpp', 'Published')
    candidate_generation = ris.create_repository_index_job(u['id'])
    _insert_class_metadata(
        u['id'],
        'candidate-1',
        'candidate.hpp',
        'Candidate',
        index_generation=candidate_generation,
    )

    rows = ris.list_repository_classes(u['id'])
    assert [(row['filename'], row['class_name']) for row in rows] == [
        ('stable.hpp', 'Published'),
    ]


def test_list_repository_classes_limit_clamped(monkeypatch):
    u = h.make_user('repocls4')
    _ensure_active_index_generation(u['id'])
    captured = {}

    real_get_conn = db.get_db_connection

    class _CursorWrap:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, params=None):
            if 'repository_class_metadata' in sql:
                captured['params'] = params
            return self._inner.execute(sql, params)

        def fetchall(self):
            return self._inner.fetchall()

        def fetchone(self):
            return self._inner.fetchone()

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

    class _ConnWrap:
        def __init__(self, inner):
            self._inner = inner

        def cursor(self, *a, **k):
            return _CursorWrap(self._inner.cursor(*a, **k))

        def commit(self):
            return self._inner.commit()

        def close(self):
            return self._inner.close()

    def _fake_get_conn():
        return _ConnWrap(real_get_conn())

    monkeypatch.setattr(ris, 'get_db_connection', _fake_get_conn)

    # limit 过大 → 夹到 2000
    ris.list_repository_classes(u['id'], limit=999999)
    assert captured['params'][-1] == 2000

    # limit < 1 → 夹到 1
    ris.list_repository_classes(u['id'], limit=0)
    assert captured['params'][-1] == 1

    # 普通值原样
    ris.list_repository_classes(u['id'], limit=50)
    assert captured['params'][-1] == 50


# ---------------------------------------------------------------------------
# get_user_repository_files_by_names
# ---------------------------------------------------------------------------
def test_get_user_repository_files_by_names_returns_map():
    u = h.make_user('repofiles1')
    _insert_repo_file(u['id'], 'util.h', '#pragma once\nint f();\n')
    _insert_repo_file(u['id'], 'extra.hpp', 'struct S{};\n')

    out = rsvc.get_user_repository_files_by_names(u['id'], ['util.h', 'extra.hpp'])
    assert out == {
        'util.h': '#pragma once\nint f();\n',
        'extra.hpp': 'struct S{};\n',
    }


def test_get_user_repository_files_by_names_only_matching_names():
    u = h.make_user('repofiles2')
    _insert_repo_file(u['id'], 'a.h', 'AAA')
    _insert_repo_file(u['id'], 'b.h', 'BBB')
    out = rsvc.get_user_repository_files_by_names(u['id'], ['a.h', 'missing.h'])
    assert out == {'a.h': 'AAA'}


def test_get_user_repository_files_by_names_empty_list():
    u = h.make_user('repofiles3')
    _insert_repo_file(u['id'], 'a.h', 'AAA')
    # 空 filenames → 直接返回 {}
    assert rsvc.get_user_repository_files_by_names(u['id'], []) == {}


def test_get_user_repository_files_by_names_scoped_to_user():
    owner = h.make_user('repofiles4a')
    other = h.make_user('repofiles4b')
    _insert_repo_file(owner['id'], 'shared.h', 'OWNER')
    _insert_repo_file(other['id'], 'shared.h', 'OTHER')
    out = rsvc.get_user_repository_files_by_names(owner['id'], ['shared.h'])
    assert out == {'shared.h': 'OWNER'}
