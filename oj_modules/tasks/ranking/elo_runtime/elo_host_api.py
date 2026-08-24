#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELO 隔离对局 · 评分脚本（裁判容器）侧的主机 API。

隔离运行时（``elo_runtime_mode = isolated``）下，评分脚本不直接读写两份
作品目录，而是通过本模块经宿主仲裁者调用两个独立的工作容器。作品文件、
入口程序、语言与交互协议全部由评分脚本自行决定：

原语（自由组合，对应工作容器内的受监管进程）：

  - ``spawn(side, argv, env=None, workdir=None)``：在某方断网工作容器内启动
    被测进程（入口文件、解释器、参数任选）；已有进程会先被终止。
  - ``interact(side, data=None, timeout_ms=1000, until="newline")``：向被测
    进程写入数据（可选）并限时读取输出。**计时在工作容器内完成**（只覆盖
    被测进程本身），通信开销不占用比赛时限；``until`` 支持 ``"newline"``、
    ``"eof"`` 或 ``{"bytes": K}``。超时/超限时运行器会终止被测进程。
  - ``kill(side)`` / ``proc_status(side)``：终止 / 查询被测进程。
  - ``run_worker(side, argv, timeout_ms, ...)``：执行一条一次性命令（编译、
    静态分析等），可按白名单取回产物文件（base64）。
  - ``fetch_files(side, paths)``：不执行命令，直接按白名单读取作品文件
    （单文件 8MiB、合计 16MiB，base64 返回）。

请求经 stderr 上的前缀帧发给仲裁者，响应经 stdin 收回；因此隔离模式下评分
脚本不得自行读取 stdin。所有调用线程安全（内部串行化），但同一时刻只有一个
请求在途。每一方同一时刻只有一个受监管进程。

本文件会被复制进裁判容器，与评分脚本同目录；只使用 Python 标准库。
"""

from __future__ import annotations

import base64
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


def _normalize_side(side):
    return str(side or "").strip().upper()


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


def _channel_error(exc):
    return {"ok": False, "error": "worker_unresponsive", "message": str(exc)}


# ---------------------------------------------------------------------------
# 原语
# ---------------------------------------------------------------------------

def spawn(side, argv, env=None, workdir=None, timeout_ms=10000):
    """在某方断网工作容器内启动被测进程（已有进程会先被终止）。

    ``argv``/``env``/``workdir`` 完全由评分脚本决定：入口文件可以是任意
    名字、任意语言（工作容器镜像内可用的解释器/编译器均可）。
    返回 ``{"ok": True, "pid": ...}`` 或错误 dict。
    """
    side = _normalize_side(side)
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    params = {"side": side, "argv": list(argv), "timeout_ms": int(timeout_ms)}
    if env:
        params["env"] = dict(env)
    if workdir:
        params["workdir"] = workdir
    try:
        return _rpc("spawn", deadline, **params)
    except EloHostApiError as exc:
        return _channel_error(exc)


def interact(side, data=None, timeout_ms=1000, until="newline"):
    """向某方被测进程写入数据（可选）并限时读取输出。

    计时在工作容器内执行：从 ``data`` 完整写入被测进程标准输入之后开始，
    到满足 ``until`` 条件为止，通信开销不占该预算。``until``：

      - ``"newline"``：读到第一行（不含换行符）；单行上限 16 KiB；
      - ``"eof"``：读到进程退出，返回全部输出（附带 ``exit_code``）；
      - ``{"bytes": K}``：读满 K 字节（累计上限 4 MiB）。

    返回成功：``{"ok": True, "output": "<str>", "elapsed_ms": x}``；
    失败：``{"ok": False, "error": "timeout|oversize|bot_exited|
    bot_not_running|...", ...}``。超时/超限后运行器会终止被测进程。
    """
    side = _normalize_side(side)
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    timeout_ms = max(1, int(timeout_ms))
    deadline = time.monotonic() + timeout_ms / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    params = {"side": side, "timeout_ms": timeout_ms, "until": until}
    if data is not None:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        params["input"] = base64.b64encode(raw).decode("ascii")
    try:
        reply = _rpc("interact", deadline, **params)
    except EloHostApiError as exc:
        return _channel_error(exc)
    output_b64 = reply.get("output")
    if reply.get("ok") and isinstance(output_b64, str):
        try:
            reply["output"] = base64.b64decode(output_b64).decode("utf-8", errors="replace")
        except Exception:
            reply["output"] = ""
    return reply


def kill(side, timeout_ms=5000):
    """终止某方的被测进程（若存活）。"""
    side = _normalize_side(side)
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("kill", deadline, side=side, timeout_ms=int(timeout_ms))
    except EloHostApiError as exc:
        return _channel_error(exc)


def proc_status(side, timeout_ms=5000):
    """查询某方被测进程状态：``{"ok": True, "alive": bool, "exit_code": ...}``。"""
    side = _normalize_side(side)
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("proc_status", deadline, side=side, timeout_ms=int(timeout_ms))
    except EloHostApiError as exc:
        return _channel_error(exc)


def run_worker(side, argv, timeout_ms=30000, workdir=None, export_files=None,
               stream_limit_bytes=None):
    """在某方隔离工作容器内执行一次性命令（作品根目录为默认工作目录）。

    返回 dict：成功时含 ``exit_code``、``stdout``、``stderr``、``timed_out``、
    可选 ``files``（文件名 → base64 内容）。通道异常时 ``ok`` 为 False。
    """
    side = _normalize_side(side)
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
        return _channel_error(exc)


def fetch_files(side, paths, timeout_ms=10000):
    """不执行命令，直接读取某方作品目录内的文件。

    返回 ``{"ok": True, "files": {文件名: base64}}``；不存在或越界的路径会被
    跳过（单文件 8MiB、合计 16MiB 上限）。
    """
    side = _normalize_side(side)
    if side not in ("A", "B"):
        return {"ok": False, "error": "bad_request", "message": "side 必须是 A 或 B"}
    deadline = time.monotonic() + max(1, int(timeout_ms)) / 1000.0 + DEFAULT_CALL_GRACE_SECONDS
    try:
        return _rpc("fetch_files", deadline, side=side, paths=list(paths),
                    timeout_ms=int(timeout_ms))
    except EloHostApiError as exc:
        return _channel_error(exc)
