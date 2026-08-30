"""Celery 日志上下文传播与任务生命周期事件。"""

from __future__ import annotations

import logging
import time
from typing import Any, Mapping

from celery import signals

from .context import propagation_context, replace_context, reset_context
from .events import configure_logging, content_fingerprint, emit_event


_HEADER = "numoj_observability"
_UNSAFE_LIFECYCLE_LOGGERS = ("celery.app.trace",)


class _UnsafeTaskTraceFilter(logging.Filter):
    """丢弃已被安全 signal 事件替代的 Celery 默认任务记录。"""

    def filter(self, record: logging.LogRecord) -> bool:
        template = record.msg
        return not (
            record.name in _UNSAFE_LIFECYCLE_LOGGERS
            and isinstance(template, str)
            and template.startswith("Task %(")
        )


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _error_metadata(value: Any) -> dict[str, Any]:
    """记录可定位但不可还原的异常元数据。

    Celery 的异常消息可能嵌入任务 stdout/stderr、用户代码或密钥，
    因此只保留完整类型名与消息指纹。
    """
    if value is None:
        qualified_type = None
        message = None
    else:
        value_type = type(value)
        qualified_type = f"{value_type.__module__}.{value_type.__qualname__}"
        try:
            message = str(value)
        except Exception:
            message = None
    fingerprint = content_fingerprint(message)
    return {
        "type": qualified_type,
        "message": {
            "bytes": fingerprint["bytes"],
            "sha256": fingerprint["sha256"],
        },
    }


def _suppress_unsafe_lifecycle_loggers() -> None:
    """由结构化 signal 代替 Celery 自带的原始异常生命周期日志。"""
    for logger_name in _UNSAFE_LIFECYCLE_LOGGERS:
        logger = logging.getLogger(logger_name)
        if not any(isinstance(item, _UnsafeTaskTraceFilter) for item in logger.filters):
            logger.addFilter(_UnsafeTaskTraceFilter())


def install_celery_observability(celery_app, *, level: str | int = "INFO") -> None:
    """为一个 Celery app 幂等安装日志配置和生命周期 signals。"""
    if getattr(celery_app, "_numoj_observability_installed", False):
        return
    celery_app._numoj_observability_installed = True
    celery_app.conf.worker_hijack_root_logger = False
    celery_app.conf.worker_redirect_stdouts = True
    celery_app.conf.worker_redirect_stdouts_level = "INFO"

    @signals.setup_logging.connect(
        weak=False,
        dispatch_uid="numoj.observability.setup_logging",
    )
    def _setup_logging(**_kwargs):
        configure_logging(level=level, force=True)
        _suppress_unsafe_lifecycle_loggers()

    @signals.before_task_publish.connect(
        weak=False,
        dispatch_uid="numoj.observability.before_task_publish",
    )
    def _before_task_publish(headers=None, **_kwargs):
        if isinstance(headers, dict):
            propagated = propagation_context()
            if propagated:
                headers[_HEADER] = propagated

    @signals.after_task_publish.connect(
        weak=False,
        dispatch_uid="numoj.observability.after_task_publish",
    )
    def _after_task_publish(sender=None, headers=None, **_kwargs):
        headers = _mapping(headers)
        emit_event(
            "task.lifecycle",
            action="task.published",
            outcome="success",
            message="Celery 任务已发布",
            task={
                "id": headers.get("id"),
                "name": sender or headers.get("task"),
                "root_id": headers.get("root_id"),
                "parent_id": headers.get("parent_id"),
                "retries": headers.get("retries"),
                "eta": headers.get("eta"),
            },
        )

    @signals.task_prerun.connect(
        weak=False,
        dispatch_uid="numoj.observability.task_prerun",
    )
    def _task_prerun(task_id=None, task=None, **_kwargs):
        request = getattr(task, "request", None)
        propagated = _mapping(_mapping(getattr(request, "headers", None)).get(_HEADER))
        token = replace_context(
            **propagated,
            task_id=task_id,
            task_name=getattr(task, "name", None),
            root_task_id=getattr(request, "root_id", None),
            parent_task_id=getattr(request, "parent_id", None),
        )
        if request is not None:
            request._numoj_context_token = token
            request._numoj_started_at = time.monotonic()
        delivery = _mapping(getattr(request, "delivery_info", None))
        emit_event(
            "task.lifecycle",
            action="task.started",
            outcome="unknown",
            message="Celery 任务开始执行",
            task={
                "id": task_id,
                "name": getattr(task, "name", None),
                "root_id": getattr(request, "root_id", None),
                "parent_id": getattr(request, "parent_id", None),
                "retries": getattr(request, "retries", None),
                "queue": delivery.get("routing_key"),
            },
        )

    @signals.task_retry.connect(
        weak=False,
        dispatch_uid="numoj.observability.task_retry",
    )
    def _task_retry(request=None, reason=None, **_kwargs):
        emit_event(
            "task.lifecycle",
            action="task.retried",
            outcome="failure",
            message="Celery 任务准备重试",
            level=logging.WARNING,
            task={
                "id": getattr(request, "id", None),
                "name": getattr(request, "task", None),
                "retries": getattr(request, "retries", None),
            },
            failure={"exception": _error_metadata(reason)},
        )

    @signals.task_failure.connect(
        weak=False,
        dispatch_uid="numoj.observability.task_failure",
    )
    def _task_failure(task_id=None, exception=None, sender=None, **_kwargs):
        emit_event(
            "task.lifecycle",
            action="task.failed",
            outcome="failure",
            message="Celery 任务执行失败",
            level=logging.ERROR,
            task={
                "id": task_id,
                "name": getattr(sender, "name", None),
            },
            failure={"exception": _error_metadata(exception)},
        )

    @signals.task_postrun.connect(
        weak=False,
        dispatch_uid="numoj.observability.task_postrun",
    )
    def _task_postrun(task_id=None, task=None, state=None, **_kwargs):
        request = getattr(task, "request", None)
        started = getattr(request, "_numoj_started_at", None)
        duration_ms = (
            round((time.monotonic() - started) * 1000, 3)
            if started is not None
            else None
        )
        emit_event(
            "task.lifecycle",
            action="task.completed",
            outcome="success" if str(state).upper() == "SUCCESS" else "failure",
            message="Celery 任务执行结束",
            task={
                "id": task_id,
                "name": getattr(task, "name", None),
                "state": state,
                "retries": getattr(request, "retries", None),
            },
            duration={"milliseconds": duration_ms},
        )
        token = getattr(request, "_numoj_context_token", None)
        if token is not None:
            try:
                reset_context(token)
            except (LookupError, RuntimeError, ValueError):
                pass
            request._numoj_context_token = None

    @signals.task_revoked.connect(
        weak=False,
        dispatch_uid="numoj.observability.task_revoked",
    )
    def _task_revoked(request=None, terminated=None, signum=None, expired=None, **_kwargs):
        emit_event(
            "task.lifecycle",
            action="task.revoked",
            outcome="failure",
            message="Celery 任务被撤销",
            level=logging.WARNING,
            task={
                "id": getattr(request, "id", None),
                "name": getattr(request, "task", None),
            },
            revoke={
                "terminated": bool(terminated),
                "signal": signum,
                "expired": bool(expired),
            },
        )
