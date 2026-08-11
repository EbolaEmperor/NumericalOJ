#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MySQL 连接、惰性连接池与动态表名安全原语。

导入本模块不会连接数据库；连接池只在第一次调用 ``get_db_connection`` 时创建。
Celery prefork 子进程会丢弃父进程遗留的空闲 socket，再按需建立自己的连接。
"""

import atexit
import os
import queue
import re
import threading
import time

import pymysql

from oj_modules import config as _config
from oj_modules.config import (
    MYSQL_CONNECT_TIMEOUT,
    MYSQL_PASSWORD,
    MYSQL_POOL_MAX_SIZE,
    MYSQL_POOL_MIN_SIZE,
    MYSQL_POOL_RECYCLE_SECONDS,
    MYSQL_POOL_WAIT_TIMEOUT,
    MYSQL_USERNAME,
)


# CI / 多环境可通过 config 覆盖 MySQL 连接目标；生产配置缺少键时保留历史默认值。
_MYSQL_HOST = getattr(_config, "MYSQL_HOST", "127.0.0.1")
_MYSQL_PORT = int(getattr(_config, "MYSQL_PORT", 3306))
_MYSQL_DB = getattr(_config, "MYSQL_DB", "myojdb")

_VALID_TABLE_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


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
        self._wait_timeout = max(1, int(wait_timeout))
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
                self._conn_birth[conn_id] = time.time()
                self._idle.put_nowait(conn)
                self._created += 1

    def _should_recycle(self, conn):
        born_at = self._conn_birth.get(id(conn), 0)
        return (time.time() - born_at) >= self._recycle_seconds

    def _discard(self, conn):
        try:
            conn.close()
        except Exception:
            pass
        with self._lock:
            self._conn_birth.pop(id(conn), None)
            if self._created > 0:
                self._created -= 1

    def _prepare_for_checkout(self, conn):
        if self._should_recycle(conn):
            self._discard(conn)
            new_conn = _create_raw_mysql_connection()
            with self._lock:
                self._created += 1
            return new_conn

        try:
            conn.ping(reconnect=True)
            return conn
        except Exception:
            self._discard(conn)
            new_conn = _create_raw_mysql_connection()
            with self._lock:
                self._created += 1
            return new_conn

    def acquire(self):
        self._ensure_fork_safe()
        conn = None
        with self._lock:
            if not self._idle.empty():
                conn = self._idle.get_nowait()
            elif self._created < self._max_size:
                conn = _create_raw_mysql_connection()
                self._created += 1

        if conn is None:
            try:
                conn = self._idle.get(timeout=self._wait_timeout)
            except queue.Empty as exc:
                raise pymysql.err.OperationalError(
                    1040,
                    "MySQL 连接池耗尽，请稍后重试",
                ) from exc

        prepared = self._prepare_for_checkout(conn)
        with self._lock:
            if id(prepared) not in self._conn_birth:
                self._conn_birth[id(prepared)] = time.time()
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
                _db_pool = _MySQLConnectionPool(
                    min_size=int(MYSQL_POOL_MIN_SIZE),
                    max_size=int(MYSQL_POOL_MAX_SIZE),
                    wait_timeout=int(MYSQL_POOL_WAIT_TIMEOUT),
                    recycle_seconds=int(MYSQL_POOL_RECYCLE_SECONDS),
                )
    return _db_pool


def get_db_connection():
    """返回一个连接池代理连接（``close()`` 时归还池）。"""
    return _get_db_pool().acquire()


__all__ = ["get_db_connection", "safe_table_name"]
