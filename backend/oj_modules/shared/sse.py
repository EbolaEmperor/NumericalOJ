#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""页面 SSE 的进程内准入与确定性释放原语。"""

from __future__ import annotations

import threading

from backend.oj_modules import config as _config


class SSEConnectionLimiter:
    """用非阻塞信号量限制长连接，避免 SSE 吃光全部 gthread。"""

    def __init__(self, limit):
        self.limit = int(limit)
        if self.limit <= 0:
            raise ValueError("SSE 连接上限必须为正整数")
        self._slots = threading.BoundedSemaphore(self.limit)
        self._state_lock = threading.Lock()
        self._active = 0

    @property
    def active(self):
        with self._state_lock:
            return self._active

    def try_acquire(self):
        if not self._slots.acquire(blocking=False):
            return None
        with self._state_lock:
            self._active += 1
        return _SSEConnectionLease(self)

    def _release(self):
        with self._state_lock:
            self._active -= 1
        self._slots.release()


class _SSEConnectionLease:
    def __init__(self, limiter):
        self._limiter = limiter
        self._release_lock = threading.Lock()
        self._released = False

    def release(self):
        with self._release_lock:
            if self._released:
                return
            self._released = True
        self._limiter._release()


class _LeasedSSEIterator:
    """在完成、异常或客户端断开触发 ``close`` 时归还 SSE 槽。"""

    def __init__(self, iterable, lease):
        self._iterator = iter(iterable)
        self._lease = lease
        self._closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self._closed:
            raise StopIteration
        try:
            return next(self._iterator)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            close = getattr(self._iterator, "close", None)
            if callable(close):
                close()
        finally:
            self._lease.release()


_configured_threads = int(getattr(_config, "WEB_GUNICORN_THREADS", 256))
_configured_limit = int(getattr(_config, "WEB_SSE_MAX_CONNECTIONS", 192))
if not 1 <= _configured_limit < _configured_threads:
    raise ValueError(
        "WEB_SSE_MAX_CONNECTIONS 必须大于等于 1，且小于 "
        "WEB_GUNICORN_THREADS"
    )
_process_limiter = SSEConnectionLimiter(_configured_limit)


def try_acquire_sse_slot():
    return _process_limiter.try_acquire()


def guard_sse_stream(iterable, lease):
    """绑定已取得的 lease；返回值可直接交给 Flask ``Response``。"""
    return _LeasedSSEIterator(iterable, lease)


def sse_capacity_response():
    """返回 EventSource 可识别并按浏览器策略重连的过载响应。"""
    from flask import jsonify

    response = jsonify(
        success=False,
        code="sse_capacity_exhausted",
        message="实时连接较多，请稍后重试",
    )
    response.status_code = 503
    response.headers["Retry-After"] = "1"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Connection"] = "close"
    return response


__all__ = [
    "SSEConnectionLimiter",
    "guard_sse_stream",
    "sse_capacity_response",
    "try_acquire_sse_slot",
]
