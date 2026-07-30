# -*- coding: utf-8 -*-
"""共享 fixtures：基础设施就绪、DB 重置+种子、Flask client、登录、AI/SMTP mock。

端到端 smoke 不再使用 Flask test_client 直打路由；统一放在 tests/e2e，
由本地 Flask 服务 + numoj-admin / numoj-user CLI 驱动。

要点：
- `db_services` 的连接池按首次取连接创建，`oj.py` 的恢复与自调度工作也必须由显式
  启动入口触发；导入模块本身不得连接基础设施或投递任务。
- DB 隔离用 truncate+reseed（每个 db_services 函数各自 commit，事务回滚不可行）。
"""
import hashlib
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time

import pymysql
import pytest

OJ_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OJ_ROOT))

import config  # noqa: E402
from tests.environment_guard import (  # noqa: E402
    DestructiveTestTarget,
    UnsafeTestEnvironmentError,
    assert_disposable_test_target,
)

MYSQL_HOST = getattr(config, 'MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(getattr(config, 'MYSQL_PORT', 3306))
MYSQL_DB = getattr(config, 'MYSQL_DB', 'myojdb')
REDIS_HOST = getattr(config, 'REDIS_HOST', '127.0.0.1')
REDIS_DB = int(getattr(config, 'REDIS_DB', 0))

# 需要 truncate 的核心业务表（动态班级表 ^C\w+ 另行 DROP）
CORE_TABLES = [
    'submission_test_points', 'submission_repository_snapshots',
    'repository_delete_confirmations', 'repository_upload_sessions',
    'repository_fs_journal', 'repository_chunk_embeddings',
    'repository_function_chunks', 'repository_class_metadata',
    'repository_index_jobs', 'repository_entries',
    'repository_states',
    'submissions', 'submission_limits',
    'ac_record', 'max_score', 'user_class_map', 'users', 'class_table',
    'problems', 'agent_task_runs', 'forum_replies', 'forum_threads',
    'verification_codes', 'ai_detection_results', 'ai_detection_tasks',
    'daily_submission_stats', 'site_settings',
    'final_exam_scores',
]

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'
SEED_CLASSES = [('Cclass1', '测试班级')]
TEST_FILESYSTEM_ROOTS = ('ranking_uploads', 'repository_storage')


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _assert_destructive_test_environment():
    """在任何测试数据写入/清理前证明目标是一次性环境。"""
    target = DestructiveTestTarget(
        test_env=os.environ.get('NUMOJ_TEST_ENV'),
        hostname=socket.gethostname(),
        checkout_path=str(OJ_ROOT.resolve()),
        mysql_host=str(MYSQL_HOST),
        mysql_db=str(MYSQL_DB),
        redis_host=str(REDIS_HOST),
        redis_db=REDIS_DB,
    )
    try:
        assert_disposable_test_target(target)
    except UnsafeTestEnvironmentError as exc:
        pytest.fail(str(exc), pytrace=False)


def _raw_conn(db=None):
    return pymysql.connect(
        host=MYSQL_HOST, port=MYSQL_PORT,
        user=config.MYSQL_USERNAME, password=config.MYSQL_PASSWORD,
        database=db, charset='utf8mb4', autocommit=True,
        cursorclass=pymysql.cursors.DictCursor,
    )


def _wait_for_mysql(timeout=90):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            c = _raw_conn(db=None)
            c.close()
            return
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2)
    raise RuntimeError(f"MySQL 在 {timeout}s 内不可用: {last}")


def _table_exists(cur, name):
    cur.execute(
        "SELECT COUNT(*) AS n FROM information_schema.tables "
        "WHERE table_schema=%s AND table_name=%s", (MYSQL_DB, name))
    return cur.fetchone()['n'] > 0


def _ensure_schema():
    _assert_destructive_test_environment()
    # 确保库存在
    root = _raw_conn(db=None)
    with root.cursor() as cur:
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS {MYSQL_DB} "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci")
    root.close()

    conn = _raw_conn(db=MYSQL_DB)
    with conn.cursor() as cur:
        need_load = not _table_exists(cur, 'users')
    conn.close()

    if need_load:
        dump = OJ_ROOT / 'database' / 'bootstrap.sql'
        # 优先用 mysql CLI 导入（镜像内已装 default-mysql-client）
        with open(dump, 'rb') as fh:
            subprocess.run(
                ['mysql', '-h', MYSQL_HOST, '-P', str(MYSQL_PORT),
                 '-u', config.MYSQL_USERNAME,
                 f'-p{config.MYSQL_PASSWORD}', MYSQL_DB],
                stdin=fh, check=True)

    from scripts.init_db_schema import init_schema
    init_schema()


def _all_tables(cur):
    cur.execute(
        "SELECT table_name AS t FROM information_schema.tables "
        "WHERE table_schema=%s AND table_type='BASE TABLE'", (MYSQL_DB,))
    return [r['t'] for r in cur.fetchall()]


_DYN_CLASS_RE = re.compile(r'^C[A-Za-z0-9_]+$')


def _flush_redis():
    """清空测试用 Redis（提交状态快照、对战列表缓存、锁、ELO owner 等），避免跨用例脏数据。"""
    _assert_destructive_test_environment()
    try:
        import redis as _redis
        _redis.StrictRedis(
            host=REDIS_HOST, port=int(config.REDIS_PORT),
            db=REDIS_DB,
        ).flushdb()
    except Exception:
        pass


def _reset_test_filesystem_artifacts():
    """清空与已重置数据库 ID 绑定的测试文件，避免跨用例目录冲突。"""
    _assert_destructive_test_environment()
    for relative_path in TEST_FILESYSTEM_ROOTS:
        root = OJ_ROOT / relative_path
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            pytest.fail(f"拒绝清理异常测试产物根目录：{root}", pytrace=False)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(mode=0o700, parents=True)


def _reset_db():
    _assert_destructive_test_environment()
    _flush_redis()
    _reset_test_filesystem_artifacts()
    conn = _raw_conn(db=MYSQL_DB)
    try:
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            for t in _all_tables(cur):
                if _DYN_CLASS_RE.match(t) and t not in CORE_TABLES:
                    # 动态班级物理表（测试或 dump 残留）→ 直接删
                    cur.execute(f"DROP TABLE IF EXISTS `{t}`")
                else:
                    cur.execute(f"TRUNCATE TABLE `{t}`")
            cur.execute("SET FOREIGN_KEY_CHECKS=1")

            # 重新种子：班级、admin、site_settings
            for en, cn in SEED_CLASSES:
                cur.execute(
                    "INSERT INTO class_table (class_en, class_cn, class_cnt) "
                    "VALUES (%s,%s,0)", (en, cn))
                # 物理动态班级表（作业表），与 add_class_ajax 建的结构一致
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS `{en}` ("
                    "id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, problem_id INT, "
                    "ddl DATETIME, complete_cnt INT DEFAULT 0, problem_title TEXT, "
                    "ranking_competition_id INT DEFAULT NULL) "
                    "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
            cur.execute(
                "INSERT INTO users "
                "(username, password_hash, is_admin, email) "
                "VALUES (%s,%s,1,%s)",
                (
                    ADMIN_USERNAME,
                    sha256_hex(ADMIN_PASSWORD),
                    'admin@example.com',
                ),
            )
            cur.execute(
                "INSERT INTO site_settings (k, v) VALUES "
                "('class_adjust_enabled','1') "
                "ON DUPLICATE KEY UPDATE v=VALUES(v)")
    finally:
        conn.close()


def _is_infra_free_test(request):
    """tests/unit/ 下均为纯逻辑单测，不连 MySQL/Redis。GitHub Actions 的 unit 门禁也不
    提供这些基础设施，故这些用例必须能在无 DB 环境下运行——不能被 autouse 的 DB 重置拖垮。"""
    path = str(getattr(request.node, "fspath", "")).replace("\\", "/")
    return (
        "/tests/unit/" in path
        or path.endswith("/tests/e2e/test_cli_help.py")
        or path.endswith("/tests/e2e/test_pi_agent_judge_image.py")
    )


@pytest.fixture(scope='session')
def _infra():
    # 先校验，后连接；错误配置不能通过等待超时掩盖真正的安全问题。
    _assert_destructive_test_environment()
    _wait_for_mysql()
    _ensure_schema()
    yield


@pytest.fixture(scope='session')
def app(_infra):
    # `oj` 导入只做应用装配；恢复/调度任务由显式启动入口负责，不会在测试中投递。
    import oj as ojmod
    ojmod.app.config.update(TESTING=True)
    return ojmod.app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def db_reset(request):
    # 纯逻辑单测（tests/unit/）跳过基础设施等待与 DB 重置，使其在无 MySQL/Redis 的环境也能跑
    # （修复 CI unit 门禁每次推送都因连不上 MySQL 超时失败、误报邮件）。其余测试照常 reset。
    # 注：显式请求 client/app 的用例仍会经 app→_infra 按需拉起基础设施，不受此影响。
    if _is_infra_free_test(request):
        yield
        return
    request.getfixturevalue('_infra')
    _reset_db()
    yield


@pytest.fixture
def login(client):
    def _login(username):
        with client.session_transaction() as sess:
            sess['username'] = username
    return _login


@pytest.fixture
def admin_login(login):
    login(ADMIN_USERNAME)
    return ADMIN_USERNAME


# ---- AI / SMTP 防护：默认 mock 掉所有网络 AI 接缝，单测可再覆盖 ----
@pytest.fixture(autouse=True)
def mock_ai(monkeypatch, request):
    # 带 live_ai 标记的用例要打真实 AI 接口，不 mock 这三个调用接缝；其余
    # 用例（绝大多数）仍 mock，保持快速与确定。SMTP / embedding 始终 mock。
    live_ai = request.node.get_closest_marker('live_ai') is not None
    import oj_modules.ai_utils as ai
    if not live_ai:
        monkeypatch.setattr(ai, '_call_qwen_text', lambda *a, **k: '{}', raising=False)
        monkeypatch.setattr(ai, '_call_qwen_text_with_images', lambda *a, **k: '{}', raising=False)
        monkeypatch.setattr(ai, '_call_qwen_omni_with_image', lambda *a, **k: '{}', raising=False)
    try:
        from oj_modules.repository import index as ris
        import numpy as np

        def _fake_encode(texts, model_name=None):
            n = len(list(texts))
            dim = int(getattr(config, 'REPOSITORY_EMBEDDING_DIM', 1024))
            vecs = np.ones((n, dim), dtype='float32')
            vecs = vecs / np.linalg.norm(vecs, axis=1, keepdims=True)
            return vecs, (model_name or 'fake-embed')
        monkeypatch.setattr(ris, '_encode_with_qwen_embedding', _fake_encode, raising=False)
    except Exception:
        pass

    import smtplib

    class _FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def login(self, *a, **k):
            pass

        def sendmail(self, *a, **k):
            pass

        def quit(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass
    monkeypatch.setattr(smtplib, 'SMTP_SSL', _FakeSMTP, raising=False)
    yield


@pytest.fixture(autouse=True)
def _skip_live_ai_without_keys(request):
    """带 live_ai 标记的用例只在 OJ_LIVE_AI=1（CI 注入线上 key 后）时真跑；
    否则自动 skip——本地或无 key 环境不会因缺真实 API 而失败。"""
    if request.node.get_closest_marker('live_ai') is None:
        return
    if os.environ.get('OJ_LIVE_AI') != '1':
        pytest.skip('需要真实 AI 配置（设置 OJ_LIVE_AI=1，CI 会注入线上 key）')
