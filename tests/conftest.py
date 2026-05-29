# -*- coding: utf-8 -*-
"""共享 fixtures：基础设施就绪、DB 重置+种子、Flask client、登录、AI/SMTP mock。

要点：
- import db_services 即连 MySQL；oj.py import 时跑 seed_*。因此先确保 infra，再在
  monkeypatch 掉 seed_* 之后 import oj。
- DB 隔离用 truncate+reseed（每个 db_services 函数各自 commit，事务回滚不可行）。
"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import time

import pymysql
import pytest

OJ_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(OJ_ROOT))

import config  # noqa: E402

MYSQL_HOST = getattr(config, 'MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(getattr(config, 'MYSQL_PORT', 3306))
MYSQL_DB = getattr(config, 'MYSQL_DB', 'myojdb')

# 需要 truncate 的核心业务表（动态班级表 ^C\w+ 另行 DROP）
CORE_TABLES = [
    'submission_test_points', 'submissions', 'submission_limits',
    'ac_record', 'max_score', 'user_class_map', 'users', 'class_table',
    'problems', 'agent_task_runs', 'forum_replies', 'forum_threads',
    'verification_codes', 'ai_detection_results', 'ai_detection_tasks',
    'user_code_repository', 'repository_chunk_embeddings',
    'repository_function_chunks', 'repository_class_metadata',
    'repository_index_jobs', 'daily_submission_stats', 'site_settings',
    'final_exam_scores',
]

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin123'
SEED_CLASSES = [('Cadmin', '管理员'), ('Cclass1', '测试班级')]


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


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
        dump = OJ_ROOT / 'myojdb.sql'
        # 优先用 mysql CLI 导入（镜像内已装 default-mysql-client）
        with open(dump, 'rb') as fh:
            subprocess.run(
                ['mysql', '-h', MYSQL_HOST, '-P', str(MYSQL_PORT),
                 '-u', config.MYSQL_USERNAME,
                 f'-p{config.MYSQL_PASSWORD}', MYSQL_DB],
                stdin=fh, check=True)

    # site_settings 不在 dump 里，按需创建
    conn = _raw_conn(db=MYSQL_DB)
    with conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS site_settings ("
            "k VARCHAR(191) NOT NULL PRIMARY KEY, v TEXT) "
            "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
        # AI 代码点评缓存列（生产里手动加过，dump 里没有）——按需补上
        cur.execute(
            "SELECT COUNT(*) AS n FROM information_schema.columns "
            "WHERE table_schema=%s AND table_name='submissions' "
            "AND column_name='ai_code_marks_json'", (MYSQL_DB,))
        if cur.fetchone()['n'] == 0:
            cur.execute("ALTER TABLE submissions ADD COLUMN ai_code_marks_json LONGTEXT NULL")
    conn.close()


def _all_tables(cur):
    cur.execute(
        "SELECT table_name AS t FROM information_schema.tables "
        "WHERE table_schema=%s AND table_type='BASE TABLE'", (MYSQL_DB,))
    return [r['t'] for r in cur.fetchall()]


_DYN_CLASS_RE = re.compile(r'^C[A-Za-z0-9_]+$')


def _flush_redis():
    """清空测试用 Redis（提交状态快照、对战列表缓存、锁、ELO owner 等），避免跨用例脏数据。"""
    try:
        import redis as _redis
        _redis.StrictRedis(
            host=config.REDIS_HOST, port=int(config.REDIS_PORT),
            db=int(config.REDIS_DB),
        ).flushdb()
    except Exception:
        pass


def _reset_db():
    _flush_redis()
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
                    "ddl DATETIME, complete_cnt INT DEFAULT 0, problem_title TEXT) "
                    "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
            cur.execute(
                "INSERT INTO users (username, password_hash, is_admin, email, "
                "class, class_cn) VALUES (%s,%s,1,%s,%s,%s)",
                (ADMIN_USERNAME, sha256_hex(ADMIN_PASSWORD),
                 'admin@example.com', 'Cadmin', '管理员'))
            admin_id = cur.lastrowid
            cur.execute(
                "INSERT INTO user_class_map (user_id, class_en, is_primary) "
                "VALUES (%s,'Cadmin',1)", (admin_id,))
            cur.execute("UPDATE class_table SET class_cnt=1 WHERE class_en='Cadmin'")
            cur.execute(
                "INSERT INTO site_settings (k, v) VALUES "
                "('class_adjust_enabled','1') "
                "ON DUPLICATE KEY UPDATE v=VALUES(v)")
    finally:
        conn.close()


@pytest.fixture(scope='session', autouse=True)
def _infra():
    _wait_for_mysql()
    _ensure_schema()
    yield


@pytest.fixture(scope='session')
def app(_infra):
    # 在 import oj 之前禁掉自调度链路
    import oj_modules.tasks as _tasks
    import oj_modules.startup_requeue as _sr
    _tasks.seed_elo_matchmaker_tick = lambda *a, **k: None
    _sr.seed_pending_requeue_watchdog = lambda *a, **k: None
    import oj as ojmod
    ojmod.app.config.update(TESTING=True)
    return ojmod.app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def db_reset(_infra):
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
def mock_ai(monkeypatch):
    import oj_modules.ai_utils as ai
    monkeypatch.setattr(ai, '_call_qwen_text', lambda *a, **k: '{}', raising=False)
    monkeypatch.setattr(ai, '_call_qwen_text_with_images', lambda *a, **k: '{}', raising=False)
    monkeypatch.setattr(ai, '_call_qwen_omni_with_image', lambda *a, **k: '{}', raising=False)
    try:
        import oj_modules.repository_index_services as ris
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
