#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""将站点级 Agent 并发上限同步到 Celery agent worker。"""

from __future__ import annotations

import logging

from celery import signals

from oj_modules.agents.runtime_settings import (
    AGENT_CONCURRENCY_MAX,
    AGENT_CONCURRENCY_MIN,
    get_agent_concurrency_limit,
)


AGENT_WORKER_PATTERN = "agent@*"
AGENT_WORKER_MIN_CONCURRENCY = AGENT_CONCURRENCY_MIN
AGENT_WORKER_CONTROL_TIMEOUT_SECONDS = 1.0

logger = logging.getLogger(__name__)


def _validated_limit(value):
    error = (
        "Agent 并发上限必须是 "
        f"{AGENT_CONCURRENCY_MIN} 到 {AGENT_CONCURRENCY_MAX} 之间的整数"
    )
    if isinstance(value, bool):
        raise ValueError(error)
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc
    if not AGENT_CONCURRENCY_MIN <= limit <= AGENT_CONCURRENCY_MAX:
        raise ValueError(error)
    return limit


def configure_ready_agent_worker(sender, *, limit_reader=get_agent_concurrency_limit):
    """在 agent worker ready 时恢复数据库中的 autoscale 上限。"""

    hostname = str(getattr(sender, "hostname", "") or "")
    if not hostname.startswith("agent@"):
        return False
    autoscaler = getattr(getattr(sender, "controller", None), "autoscaler", None)
    if autoscaler is None:
        logger.error("Agent worker 未启用 autoscale", extra={"worker": hostname})
        return False
    try:
        limit = _validated_limit(limit_reader())
        autoscaler.update(max=limit, min=AGENT_WORKER_MIN_CONCURRENCY)
    except Exception:
        # Supervisor 以 1 个进程安全启动；数据库暂不可用或配置异常时保留
        # 这一保守上限，不能阻止 worker 就绪。
        logger.exception(
            "恢复 Agent worker 并发上限失败",
            extra={"worker": hostname},
        )
        return False
    logger.info(
        "Agent worker 并发上限已恢复",
        extra={"worker": hostname, "concurrency_limit": limit},
    )
    return True


def _agent_worker_ready(sender=None, **_kwargs):
    configure_ready_agent_worker(sender)


def install_agent_concurrency_control():
    """注册无导入期外部操作的 worker-ready 同步钩子。"""

    signals.worker_ready.connect(
        _agent_worker_ready,
        weak=False,
        dispatch_uid="numoj.agent.concurrency.worker-ready",
    )


def apply_agent_concurrency_limit(celery_app, limit):
    """尽力把新上限即时应用到运行中的 agent worker。

    设置值已经由调用方持久化；broker 或 worker 暂不可用时返回 ``False``，
    后续 worker 启动仍会通过 :func:`configure_ready_agent_worker` 自动恢复。
    """

    normalized = _validated_limit(limit)
    try:
        replies = celery_app.control.autoscale(
            normalized,
            AGENT_WORKER_MIN_CONCURRENCY,
            pattern=AGENT_WORKER_PATTERN,
            matcher="glob",
            reply=True,
            timeout=AGENT_WORKER_CONTROL_TIMEOUT_SECONDS,
        )
    except Exception:
        logger.warning(
            "即时应用 Agent worker 并发上限失败，将在 worker 重启时恢复",
            extra={"concurrency_limit": normalized},
            exc_info=True,
        )
        return False

    applied = any(
        isinstance(worker_reply, dict)
        and any(
            str(worker).startswith("agent@")
            and isinstance(result, dict)
            and "ok" in result
            for worker, result in worker_reply.items()
        )
        for worker_reply in (replies or ())
    )
    if not applied:
        logger.warning(
            "未收到 Agent worker 并发上限应用回执，将在 worker 重启时恢复",
            extra={"concurrency_limit": normalized},
        )
    return applied


__all__ = [
    "AGENT_WORKER_PATTERN",
    "apply_agent_concurrency_limit",
    "configure_ready_agent_worker",
    "install_agent_concurrency_control",
]
