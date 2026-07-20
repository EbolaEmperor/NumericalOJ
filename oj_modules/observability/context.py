"""跨 Web 请求与 Celery 任务传播的日志上下文。"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Any


_CONTEXT: ContextVar[dict[str, Any]] = ContextVar(
    "numericaloj_observability_context",
    default={},
)

_ALLOWED_FIELDS = frozenset({
    "request_id",
    "trace_id",
    "user_id",
    "username",
    "task_id",
    "task_name",
    "root_task_id",
    "parent_task_id",
})


def current_context() -> dict[str, Any]:
    """返回当前上下文的副本，防止调用方原地污染 ContextVar。"""
    return dict(_CONTEXT.get())


def replace_context(**fields: Any) -> Token:
    """以经过白名单过滤的新上下文替换当前上下文。"""
    return _CONTEXT.set({
        key: value
        for key, value in fields.items()
        if key in _ALLOWED_FIELDS and value not in (None, "")
    })


def bind_context(**fields: Any) -> Token:
    """在当前上下文之上绑定字段，并返回可用于恢复的 token。"""
    merged = current_context()
    merged.update({
        key: value
        for key, value in fields.items()
        if key in _ALLOWED_FIELDS and value not in (None, "")
    })
    return _CONTEXT.set(merged)


def reset_context(token: Token) -> None:
    _CONTEXT.reset(token)


def clear_context() -> None:
    _CONTEXT.set({})


def propagation_context() -> dict[str, Any]:
    """返回允许跨进程传播的最小上下文。"""
    context = current_context()
    return {
        key: context[key]
        for key in (
            "request_id",
            "trace_id",
            "user_id",
            "username",
        )
        if context.get(key) not in (None, "")
    }
