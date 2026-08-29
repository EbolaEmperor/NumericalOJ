#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""NumericalOJ 生产 Gunicorn 配置。"""

from oj_modules import config as _config


def _bounded_setting(name, minimum, maximum):
    value = int(getattr(_config, name))
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum}–{maximum} 之间")
    return value


# clangd/BasedPyright/Octave 进程池与 Lean 交互会话仍由 Web 进程持有；直接增加
# worker 会把语言服务进程和会话上限按 worker 倍增，并让同一浏览器请求落到不同状态。
# 在语言服务独立部署或具备粘性路由前，保持单 worker，以线程扩展 I/O 并发。
bind = "0.0.0.0:2025"
worker_class = "gthread"
workers = 1

# 提交、Agent 与打榜赛页面使用长连接 SSE。每条连接会独占一个 gthread，线程数必须
# 覆盖课堂并发，而不能沿用只适合普通短请求的低值。
# 256 在线是常态容量、512 在线是非同时请求的峰值容量。SSE 另有 192 条准入上限，
# 因此至少保留 64 个并发槽位处理普通页面、静态资源和健康检查。每个浏览器可能同时
# 持有一条 SSE 和一条空闲 HTTP keep-alive，客户端连接上限按峰值在线数的两倍预留。
MIN_ORDINARY_REQUEST_SLOTS = 64
threads = _bounded_setting("WEB_GUNICORN_THREADS", 128, 512)
worker_connections = _bounded_setting("WEB_GUNICORN_CONNECTIONS", 256, 4096)
if worker_connections < threads:
    raise RuntimeError(
        "WEB_GUNICORN_CONNECTIONS 必须大于等于 "
        f"WEB_GUNICORN_THREADS（{threads}）"
    )
backlog = _bounded_setting("WEB_GUNICORN_BACKLOG", 128, 8192)
sse_capacity = min(threads, worker_connections) - MIN_ORDINARY_REQUEST_SLOTS
sse_max_connections = int(getattr(_config, "WEB_SSE_MAX_CONNECTIONS"))
if not 1 <= sse_max_connections <= sse_capacity:
    raise RuntimeError(
        f"WEB_SSE_MAX_CONNECTIONS 必须在 1–{sse_capacity} 之间，"
        f"为普通请求保留至少 {MIN_ORDINARY_REQUEST_SLOTS} 个并发槽位"
    )
timeout = 600
graceful_timeout = 30
keepalive = 5

# Gunicorn worker 心跳默认会在磁盘临时目录执行 fchmod；放到 tmpfs，避免磁盘抖动
# 让主进程误判繁忙 worker 超时。生产目标为 Linux，/dev/shm 由系统提供。
worker_tmp_dir = "/dev/shm"

# 单 worker 下按请求数回收会同时切断全部 SSE 并制造无服务窗口。需要回收内存时应先
# 消除单 worker 约束，再以多 worker 滚动替换。
max_requests = 0
max_requests_jitter = 0

# Flask 请求钩子已经输出不含查询串、Referer、Cookie 的结构化访问事件。
# 关闭 Gunicorn 文本 access log，避免重复记录和 URL 中的敏感参数泄漏。
accesslog = None
errorlog = "-"


def post_worker_init(worker):
    """应用装载完成后，幂等确保回收器与非破坏性调度链存在。"""
    # oj:app 已在当前 worker 中导入；这里命中 sys.modules，不会再做一次完整应用导入。
    from oj import (
        ensure_background_schedulers,
        ensure_vibehub_runtime_reaper,
        ensure_vibehub_storage_gc,
    )

    worker.log.info(
        "Ensuring VibeHub reapers and NumericalOJ background schedulers in the Web worker"
    )
    ensure_vibehub_runtime_reaper()
    ensure_vibehub_storage_gc()
    ensure_background_schedulers()
