#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""NumericalOJ 生产 Gunicorn 配置。"""

# 当前应用仍有少量进程内缓存和连接状态；在这些状态迁入 Redis 或数据库前，
# 不得通过增加 workers 横向扩容。
bind = "0.0.0.0:2025"
worker_class = "gthread"
workers = 1

# 提交、Agent 与打榜赛页面使用长连接 SSE。每条连接会独占一个 gthread，线程数必须
# 覆盖课堂并发，而不能沿用只适合普通短请求的低值。
threads = 64
timeout = 600
graceful_timeout = 30
keepalive = 5

# 单 worker 下按请求数回收会同时切断全部 SSE 并制造无服务窗口。需要回收内存时应先
# 消除单 worker 约束，再以多 worker 滚动替换。
max_requests = 0
max_requests_jitter = 0

accesslog = "-"
errorlog = "-"


def post_worker_init(worker):
    """应用装载完成后，幂等确保非破坏性的后台调度链存在。"""
    # oj:app 已在当前 worker 中导入；这里命中 sys.modules，不会再做一次完整应用导入。
    from oj import ensure_background_schedulers

    worker.log.info("Ensuring NumericalOJ background schedulers in the Web worker")
    ensure_background_schedulers()
