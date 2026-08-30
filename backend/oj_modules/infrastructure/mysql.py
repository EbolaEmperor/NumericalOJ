#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MySQL 连接、惰性连接池与动态表名安全原语。

导入本模块不会连接数据库；连接池只在第一次调用 ``get_db_connection`` 时创建。
Celery prefork 子进程会丢弃父进程遗留的空闲 socket，再按需建立自己的连接。
"""

import atexit
import contextvars
import os
import queue
import re
import threading
import time

import pymysql

from backend.oj_modules import config as _config
from backend.oj_modules.config import (
    MYSQL_CONNECT_TIMEOUT,
    MYSQL_PASSWORD,
    MYSQL_POOL_MAX_SIZE,
    MYSQL_POOL_MIN_SIZE,
    MYSQL_POOL_RECYCLE_SECONDS,
    MYSQL_POOL_WAIT_TIMEOUT,
    MYSQL_WEB_POOL_MAX_SIZE,
    MYSQL_WEB_POOL_WAIT_TIMEOUT_SECONDS,
    MYSQL_USERNAME,
)


# CI / 多环境可通过 config 覆盖 MySQL 连接目标；生产配置缺少键时保留历史默认值。
_MYSQL_HOST = getattr(_config, "MYSQL_HOST", "127.0.0.1")
_MYSQL_PORT = int(getattr(_config, "MYSQL_PORT", 3306))
_MYSQL_DB = getattr(_config, "MYSQL_DB", "myojdb")

_VALID_TABLE_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")

# 连接池异常经常需要穿过多层业务代码才能到达 Flask。部分旧路由会把
# ``pymysql.Error`` 转换成自己的 JSON 错误响应，因此仅靠全局 error handler
# 无法判断这次失败实际来自连接池背压。这里用执行上下文隔离的标记记录请求
# 作用域内最近一次池耗尽；未显式开启跟踪的 Celery/CLI 上下文不保留异常对象。
_MYSQL_POOL_EXHAUSTION_UNTRACKED = object()
_mysql_pool_exhaustion_context = contextvars.ContextVar(
    "numoj_mysql_pool_exhaustion",
    default=_MYSQL_POOL_EXHAUSTION_UNTRACKED,
)


class MySQLPoolExhausted(pymysql.err.OperationalError):
    """Web 请求在有限等待后仍无法取得连接；调用方应返回可重试的 503。"""

    def __init__(self, *args):
        super().__init__(*args)
        if (
            _mysql_pool_exhaustion_context.get()
            is not _MYSQL_POOL_EXHAUSTION_UNTRACKED
        ):
            _mysql_pool_exhaustion_context.set(self)


def begin_mysql_pool_exhaustion_tracking():
    """开启一个可嵌套的池耗尽跟踪作用域，并返回用于恢复的 token。"""
    return _mysql_pool_exhaustion_context.set(None)


def end_mysql_pool_exhaustion_tracking(token):
    """恢复进入跟踪作用域前的上下文，避免线程复用时泄漏状态。"""
    _mysql_pool_exhaustion_context.reset(token)


def current_mysql_pool_exhaustion():
    """返回当前跟踪作用域内最近一次池耗尽异常。"""
    error = _mysql_pool_exhaustion_context.get()
    return error if isinstance(error, MySQLPoolExhausted) else None


def safe_table_name(name):
    """校验动态表名仅由字母、数字、下划线构成；非法时抛 ValueError。"""
    value = "" if name is None else str(name)
    if not _VALID_TABLE_NAME_RE.match(value):
        raise ValueError(f"非法的表名: {name!r}")
    return value


def _create_raw_mysql_connection():
    return pymysql.connect(
        host=_MYSQL_HOST,
        port=_MYSQL_PORT,
        user=MYSQL_USERNAME,
        password=MYSQL_PASSWORD,
        database=_MYSQL_DB,
        charset="utf8mb4",
        connect_timeout=int(MYSQL_CONNECT_TIMEOUT),
        cursorclass=pymysql.cursors.DictCursor,
    )


class _PooledConnectionProxy:
    """把 ``close()`` 转换为归还池，并允许显式物理丢弃异常连接。"""

    def __init__(self, pool, raw_conn):
        self._pool = pool
        self._raw_conn = raw_conn
        self._closed = False

    def __getattr__(self, item):
        return getattr(self._raw_conn, item)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._pool.release(self._raw_conn)

    def discard(self):
        """物理丢弃异常连接，不把连接级状态（例如 advisory lock）带回池中。"""
        if self._closed:
            return
        self._closed = True
        self._pool._discard(self._raw_conn)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class _MySQLConnectionPool:
    def __init__(
        self,
        min_size=2,
        max_size=6,
        wait_timeout=5,
        recycle_seconds=1200,
    ):
        self._min_size = max(1, int(min_size))
        self._max_size = max(self._min_size, int(max_size))
        self._wait_timeout = max(0.01, float(wait_timeout))
        self._recycle_seconds = max(60, int(recycle_seconds))

        self._idle = queue.Queue(maxsize=self._max_size)
        self._lock = threading.Lock()
        self._created = 0
        self._conn_birth = {}
        self._pid = os.getpid()

        self._warm_up()
        atexit.register(self.close_idle_connections)

    def _ensure_fork_safe(self):
        """Celery prefork 子进程不能复用父进程打开的 MySQL socket。"""
        current_pid = os.getpid()
        if current_pid == self._pid:
            return

        with self._lock:
            if current_pid == self._pid:
                return
            while not self._idle.empty():
                try:
                    conn = self._idle.get_nowait()
                except queue.Empty:
                    break
                try:
                    conn.close()
                except Exception:
                    pass
            self._conn_birth.clear()
            self._created = 0
            self._pid = current_pid

    def _warm_up(self):
        target = self._min_size
        for _ in range(target):
            try:
                conn = _create_raw_mysql_connection()
            except Exception:
                # 启动阶段不因预热失败中断，后续按需创建。
                break
            with self._lock:
                conn_id = id(conn)
                now = time.monotonic()
                self._conn_birth[conn_id] = now
                self._idle.put_nowait(conn)
                self._created += 1

    def _should_recycle(self, conn):
        born_at = self._conn_birth.get(id(conn), 0)
        return (time.monotonic() - born_at) >= self._recycle_seconds

    def _register_created_connection(self, conn):
        now = time.monotonic()
        with self._lock:
            conn_id = id(conn)
            self._conn_birth[conn_id] = now

    def _release_reserved_slot(self):
        with self._lock:
            if self._created > 0:
                self._created -= 1

    def _create_for_reserved_slot(self):
        """为已计入 ``_created`` 的槽位建连；慢网络 I/O 不持有池锁。"""
        try:
            conn = _create_raw_mysql_connection()
        except Exception as exc:
            self._release_reserved_slot()
            if (
                isinstance(exc, pymysql.err.OperationalError)
                and exc.args
                and exc.args[0] in {1040, 1203}
            ):
                raise MySQLPoolExhausted(*exc.args) from exc
            raise
        self._register_created_connection(conn)
        return conn

    def _discard(self, conn):
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            self._conn_birth.pop(id(conn), None)
            if self._created > 0:
                self._created -= 1

    def _replace_reserved_connection(self, conn):
        """替换坏连接，同时保留它已经占用的容量槽，避免并发突破上限。"""
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            self._conn_birth.pop(id(conn), None)
        return self._create_for_reserved_slot()

    def _prepare_for_checkout(self, conn):
        if self._should_recycle(conn):
            return self._replace_reserved_connection(conn)

        # ``release()`` 成功回滚只能证明连接在归还当时可用；它进入空闲队列后
        # 仍可能被服务端 KILL、重启或网络断开。``open`` 先覆盖本地已知关闭，
        # pre-ping 再覆盖 PyMySQL 尚未感知的远端断链，避免首个业务 SQL 失败。
        if not conn.open:
            return self._replace_reserved_connection(conn)

        try:
            conn.ping()
            return conn
        except Exception:
            return self._replace_reserved_connection(conn)

    def acquire(self):
        self._ensure_fork_safe()
        conn = None
        create_new = False
        with self._lock:
            if not self._idle.empty():
                conn = self._idle.get_nowait()
            elif self._created < self._max_size:
                # 先预占容量，再在锁外建连。否则一次最长 5 秒的连接握手会
                # 阻塞所有其它线程取得已经归还的健康连接。
                self._created += 1
                create_new = True

        if create_new:
            conn = self._create_for_reserved_slot()
            # 新握手本身已经验证连接；只有从空闲队列复用的 socket 需要 pre-ping。
            return _PooledConnectionProxy(self, conn)

        if conn is None:
            try:
                conn = self._idle.get(timeout=self._wait_timeout)
            except queue.Empty as exc:
                raise MySQLPoolExhausted(
                    1040,
                    "MySQL 连接池耗尽，请稍后重试",
                ) from exc

        prepared = self._prepare_for_checkout(conn)
        return _PooledConnectionProxy(self, prepared)

    def release(self, conn):
        try:
            # 避免事务泄露到下一次使用。
            conn.rollback()
        except Exception:
            self._discard(conn)
            return

        if self._should_recycle(conn):
            self._discard(conn)
            return

        try:
            self._idle.put_nowait(conn)
        except queue.Full:
            self._discard(conn)

    def close_idle_connections(self):
        while not self._idle.empty():
            conn = self._idle.get_nowait()
            try:
                conn.close()
            except Exception:
                pass
        with self._lock:
            self._conn_birth.clear()
            self._created = 0


_db_pool = None
_db_pool_init_lock = threading.Lock()


def _get_db_pool():
    """按需创建连接池，避免导入模块时就访问 MySQL。"""
    global _db_pool
    if _db_pool is None:
        with _db_pool_init_lock:
            if _db_pool is None:
                is_web_process = (
                    os.environ.get("NUMOJ_SERVICE_NAME", "").strip().lower()
                    == "web"
                )
                _db_pool = _MySQLConnectionPool(
                    min_size=int(MYSQL_POOL_MIN_SIZE),
                    max_size=(
                        int(MYSQL_WEB_POOL_MAX_SIZE)
                        if is_web_process
                        else int(MYSQL_POOL_MAX_SIZE)
                    ),
                    wait_timeout=(
                        float(MYSQL_WEB_POOL_WAIT_TIMEOUT_SECONDS)
                        if is_web_process
                        else float(MYSQL_POOL_WAIT_TIMEOUT)
                    ),
                    recycle_seconds=int(MYSQL_POOL_RECYCLE_SECONDS),
                )
    return _db_pool


def get_db_connection():
    """返回一个连接池代理连接（``close()`` 时归还池）。"""
    return _get_db_pool().acquire()


__all__ = [
    "MySQLPoolExhausted",
    "begin_mysql_pool_exhaustion_tracking",
    "current_mysql_pool_exhaustion",
    "end_mysql_pool_exhaustion_tracking",
    "get_db_connection",
    "safe_table_name",
]
