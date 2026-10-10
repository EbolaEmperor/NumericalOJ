"""FaithSieve 本机隔离入口；不适用于生产或其他本地运行目录。

Web：Gunicorn ``scripts.local_faithsieve_app:app``。
任务：Celery ``-A scripts.local_faithsieve_app:celery``。
采集器：``python -m scripts.local_faithsieve_app --logs``。

所有进程须先加载同一份本地环境，再切换到 ``tmp/local-faithsieve``。
本地 FaithSieve 环境不提供 VibeHub 作品功能；后台维护只允许访问本地
隔离目录，绝不能用新数据库的 live-set 回收仓库旧 VibeHub 文件。
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_ROOT = PROJECT_ROOT / "tmp" / "local-faithsieve"
LOG_SOCKET = LOCAL_ROOT / "logs" / "run" / "events.sock"


def _is_loopback_host(value: str) -> bool:
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _require_local_environment() -> None:
    """配置错误时在应用装配前拒绝启动，不输出凭证或环境值。"""
    if os.environ.get("NUMOJ_LOCAL_FAITHSIEVE_ROOT") != str(LOCAL_ROOT):
        raise RuntimeError("NUMOJ_LOCAL_FAITHSIEVE_ROOT 必须为仓库的 tmp/local-faithsieve 绝对路径")
    if Path.cwd() != LOCAL_ROOT:
        raise RuntimeError("本地 FaithSieve 进程必须在 tmp/local-faithsieve 目录中启动")
    if os.environ.get("MYSQL_DB") != "faithsieve_local_test":
        raise RuntimeError("本地 FaithSieve 必须使用 faithsieve_local_test 数据库")
    if not _is_loopback_host(os.environ.get("MYSQL_HOST", "")):
        raise RuntimeError("本地 FaithSieve MySQL 只能连接本机 loopback")
    if not _is_loopback_host(os.environ.get("REDIS_HOST", "")):
        raise RuntimeError("本地 FaithSieve Redis 只能连接本机 loopback")
    if os.environ.get("REDIS_PORT") != "6389" or os.environ.get("REDIS_DB") != "15":
        raise RuntimeError("本地 FaithSieve 必须使用 Redis 6389 端口的 15 号数据库")


_require_local_environment()

# 先设置独立日志 socket；backend.oj 的幂等日志装配保留当前进程的设置。
from backend.oj_modules import config as _cfg
from backend.oj_modules.observability import configure_logging


def _configure_local_logging(**_kwargs) -> None:
    configure_logging(level=_cfg.LOG_LEVEL, socket_path=LOG_SOCKET, force=True)


_configure_local_logging()


def _serve_logs() -> None:
    from backend.oj_modules.observability.collector import serve_collector

    serve_collector(
        root=LOCAL_ROOT / "logs", max_bytes=1024 * 1024,
        backups=2, collect_journal=False,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FaithSieve 本机隔离日志采集器")
    parser.add_argument("--logs", action="store_true", help="启动隔离目录中的日志采集器")
    arguments = parser.parse_args()
    if not arguments.logs:
        parser.error("Web 与任务请使用 Gunicorn/Celery 入口；日志采集器需传 --logs")
    _serve_logs()
    raise SystemExit(0)


from backend.oj import app, celery
from celery import signals
from backend.oj_modules.vibehub.maintenance import (
    get_storage_gc,
    register_storage_gc_config,
    shutdown_vibehub_storage_gc,
)

# 组合根只做惰性注册，尚未启动维护线程。通过公开生命周期 API 替换其默认
# 注册；目录选择必须在任何 Web 后台服务启动之前完成。
if get_storage_gc().is_running():
    raise RuntimeError("已有 VibeHub GC 线程运行，拒绝替换其他环境的后台服务")
shutdown_vibehub_storage_gc(reset_config=True)
register_storage_gc_config({
    **vars(_cfg), "VIBEHUB_UPLOAD_ROOT": LOCAL_ROOT / "uploads" / "vibehub",
})

# 通用 setup_logging hook 会强制恢复默认 socket；本地 hook 在它之后注册。
# prefork 子进程再次强制安装，避免继承其他进程已有的 Unix socket 连接。
signals.setup_logging.connect(
    _configure_local_logging, weak=False,
    dispatch_uid="numoj.local-faithsieve.setup-logging",
)
signals.worker_process_init.connect(
    _configure_local_logging, weak=False,
    dispatch_uid="numoj.local-faithsieve.worker-process-logging",
)


def start_web_background_services() -> None:
    """仅由本地 Gunicorn post_worker_init 显式启动后台服务。"""
    _require_local_environment()
    from backend.oj import (
        ensure_background_schedulers,
        ensure_vibehub_runtime_reaper,
        ensure_vibehub_storage_gc,
    )

    ensure_vibehub_runtime_reaper()
    ensure_vibehub_storage_gc()
    ensure_background_schedulers()


__all__ = ["app", "celery", "start_web_background_services"]
