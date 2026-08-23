#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局 · 评分脚本（裁判容器）侧的主机 API。

隔离运行时（``elo_runtime_mode = isolated``）下，评分脚本不直接读写两份
作品目录，而是通过本模块经宿主仲裁者调用两个独立的工作容器：

  - ``call_bot(side, payload, timeout_ms)``：向某方 bot 下发一行 JSON 局面，
    并在对方容器内限时等待一行 JSON 决策。单回合计时在工作容器内完成，
    通信开销不占用 bot 的思考时间。
  - ``run_worker(side, argv, timeout_ms, ...)``：在某方隔离工作容器内执行一条
    命令（例如编译），并可按白名单取回产物文件（base64）。
  - ``bot_status(side)``：查询某方 bot 的就绪状态（启动握手错误等）。

请求经 stderr 上的前缀帧发给仲裁者，响应经 stdin 收回；因此隔离模式下评分
脚本不得自行读取 stdin。所有调用线程安全（内部串行化），但同一时刻只有一个
请求在途。

本文件会被复制进裁判容器，与评分脚本同目录；只使用 Python 标准库。
"""

from __future__ import annotations

import itertools
import json
import os
import select
import sys
import threading
import time

RPC_PREFIX = "__NUMOJ_ELO_RPC_V1__"
DEFAULT_CALL_GRACE_SECONDS = 8.0    # 客户端侧宽限：仲裁者路由 + 外层看门的余量
MAX_RESPONSE_LINE_BYTES = 96 * 1024 * 1024

_id_counter = itertools.count(1)
_lock = threading.Lock()
_stdin_fd = int(os.environ.get("NUMOJ_ELO_STDIN_FD", "0"))
_stdout_fd_for_rpc = int(os.environ.get("NUMOJ_ELO_STDERR_FD", "2"))
_buffer = b""


class EloHostApiError(RuntimeError):
    """仲裁通道不可用（仲裁者退出、管道关闭或等待响应超时）。"""


def _readline(deadline):
    global _buffer
    while True:
        if b"\n" in _buffer:
            raw, _buffer = _buffer.split(b"\n", 1)
            if len(raw) > MAX_RESPONSE_LINE_BYTES:
                raise EloHostApiError("仲裁响应帧超过上限")
            return raw
        if len(_buffer) > MAX_RESPONSE_LINE_BYTES:
            raise EloHostApiError("仲裁响应帧超过上限")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EloHostApiError("等待仲裁响应超时")
        readable, _, _ = select.select([_stdin_fd], [], [], min(remaining, 0.5))
        if not readable:
            continue
        try:
            chunk = os.read(_stdin_fd, 65536)
        except OSError as exc:
            raise EloHostApiError(f"仲裁通道已关闭：{exc}") from exc
        if not chunk:
            raise EloHostApiError("仲裁通道已关闭")
        _buffer += chunk


def _rpc(method, deadline, **params):
    request = {"id": next(_id_counter), "method": method}
    request.update(params)
    line = RPC_PREFIX + json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n"
    with _lock:
        try:
            os.write(_stdout_fd_for_rpc, line.encode("utf-8"))
        except OSError as exc:
            raise EloHostApiError(f"无法向仲裁者发送请求：{exc}") from exc
        expected_id = request["id"]
        while True:
            raw = _readline(deadline)
            if not raw.strip():
                continue
            try:
                response = json.loads(raw.decode("utf-8", "strict"))
            except (ValueError, UnicodeError):
                continue
            if not isinstance(response, dict) or response.get("id") != expected_id:
                continue
            return response


def call_bot(side, payload, timeout_ms=1000):
    """向 A/B 方 bot 下发局面并等待决策。

    返回 dict：
      成功：{"ok": True, "response": {...}, "elapsed_ms": x}
      失败：{"ok": False, "error": "timeout|bad_output|oversize|bot_exited|
             bot_not_running|worker_unavailable|worker_unresponsive", ...}
    其中 ``elapsed_ms`` 由工作容器内测得，只包含 bot 的思考时间。
    """
    side = str(side or "").strip().upper()
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    timeout_ms = max(1, int(timeout_ms))
    deadline = time.monotonic() + timeout_ms / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("call_bot", deadline, side=side, payload=payload, timeout_ms=timeout_ms)
    except EloHostApiError as exc:
        return {"ok": False, "error": "worker_unresponsive", "message": str(exc)}


def run_worker(side, argv, timeout_ms=30000, workdir=None, export_files=None,
               stream_limit_bytes=None):
    """在某方隔离工作容器内执行命令（作品根目录为默认工作目录）。

    返回 dict：成功时含 ``exit_code``、``stdout``、``stderr``、``timed_out``、
    可选 ``files``（文件名 → base64 内容）。通道异常时 ``ok`` 为 False。
    """
    side = str(side or "").strip().upper()
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    timeout_ms = max(1, int(timeout_ms))
    deadline = time.monotonic() + timeout_ms / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    params = {"side": side, "argv": list(argv), "timeout_ms": timeout_ms}
    if workdir:
        params["workdir"] = workdir
    if export_files:
        params["export_files"] = list(export_files)
    if stream_limit_bytes:
        params["stream_limit_bytes"] = int(stream_limit_bytes)
    try:
        return _rpc("run_worker", deadline, **params)
    except EloHostApiError as exc:
        return {"ok": False, "error": "worker_unresponsive", "message": str(exc)}


def bot_status(side):
    """查询某方 bot 的就绪状态；未就绪时包含启动错误说明。"""
    side = str(side or "").strip().upper()
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    deadline = time.monotonic() + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("bot_status", deadline, side=side)
    except EloHostApiError as exc:
        return {"ok": False, "error": "worker_unresponsive", "message": str(exc)}


def wait_ready(side, timeout_ms=15000):
    """阻塞等待某方工作容器完成（或判定失败）bot 启动握手。

    返回结构与 ``bot_status`` 相同：就绪时 ``ready`` 为 True 并附带
    ``handshake_ms``；握手失败时 ``ready`` 为 False 并附带错误说明。
    超时仍未判定则返回 ``worker_unresponsive`` 错误。
    """
    side = str(side or "").strip().upper()
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    timeout_ms = max(1, int(timeout_ms))
    deadline = time.monotonic() + timeout_ms / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("wait_ready", deadline, side=side, timeout_ms=timeout_ms)
    except EloHostApiError as exc:
        return {"ok": False, "error": "worker_unresponsive", "message": str(exc)}
