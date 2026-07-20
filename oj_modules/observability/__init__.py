"""NumericalOJ 可观测性公共 API。

框架集成采用惰性导入，使日志目录管理和基础设施采集器无需安装 Flask/Celery，
也不会为了采集系统日志而导入应用配置。
"""

from .context import bind_context, current_context
from .events import (
    EVENT_SOCKET,
    LOG_ROOT,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    build_event_envelope,
    configure_logging,
    configure_redaction,
    content_fingerprint,
    emit_audit,
    emit_event,
    file_fingerprint,
    redact_text,
    safe_file_fingerprint,
    sanitize,
    validate_event_payload,
)


def install_celery_observability(*args, **kwargs):
    from .celery import install_celery_observability as install

    return install(*args, **kwargs)


def install_flask_observability(*args, **kwargs):
    from .web import install_flask_observability as install

    return install(*args, **kwargs)


def client_ip(*args, **kwargs):
    from .web import client_ip as resolve

    return resolve(*args, **kwargs)


def client_source(*args, **kwargs):
    from .web import client_source as resolve

    return resolve(*args, **kwargs)


def request_audit_fields(*args, **kwargs):
    from .web import request_audit_fields as resolve

    return resolve(*args, **kwargs)


def user_agent_metadata(*args, **kwargs):
    from .web import user_agent_metadata as resolve

    return resolve(*args, **kwargs)


__all__ = [
    "EVENT_SOCKET",
    "LOG_ROOT",
    "SCHEMA_NAME",
    "SCHEMA_VERSION",
    "bind_context",
    "build_event_envelope",
    "client_ip",
    "client_source",
    "configure_logging",
    "configure_redaction",
    "content_fingerprint",
    "current_context",
    "emit_audit",
    "emit_event",
    "file_fingerprint",
    "install_celery_observability",
    "install_flask_observability",
    "redact_text",
    "request_audit_fields",
    "safe_file_fingerprint",
    "sanitize",
    "user_agent_metadata",
    "validate_event_payload",
]
