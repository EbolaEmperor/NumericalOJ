"""NumericalOJ 版本化 JSON 日志事件与安全输出处理器。"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from itertools import islice
import json
import logging
import os
from pathlib import Path
import re
import socket
import sys
import traceback
from typing import Any, Mapping
from uuid import uuid4

from .context import current_context
from backend.oj_modules.project_paths import PROJECT_ROOT


SCHEMA_NAME = "numericaloj.log"
SCHEMA_VERSION = 1
MAX_DATAGRAM_BYTES = 60_000
MAX_TEXT_CHARS = 8_192
LOG_ROOT = PROJECT_ROOT / "logs"
EVENT_SOCKET = LOG_ROOT / "run" / "events.sock"

_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|authorization|cookie|session|api[_-]?key|"
    r"verification[_-]?code|smtp|credential|private[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_TEXT_KEY = (
    r"(?:password|passwd|secret|token|authorization|cookie|session|api[_-]?key|"
    r"verification[_-]?code|credential|private[_-]?key)"
)
_AUTH_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_URL_USERINFO_RE = re.compile(r"(://)[^\s/@:]+:[^\s/@]+@")
_QUERY_SECRET_RE = re.compile(
    rf"([?&#]{_SENSITIVE_TEXT_KEY}=)[^&#\s]+",
    re.IGNORECASE,
)
_KEY_VALUE_SECRET_RE = re.compile(
    rf"\b({_SENSITIVE_TEXT_KEY})(\s*[:=]\s*)[\"']?[^,;\s\"']+",
    re.IGNORECASE,
)
_JSON_SECRET_RE = re.compile(
    rf'(["\']{_SENSITIVE_TEXT_KEY}["\']\s*[:=]\s*)(["\'])[^"\']*\2',
    re.IGNORECASE,
)
_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)
_PROTECTED_PAYLOAD_FIELDS = frozenset({
    "@timestamp",
    "schema",
    "event",
    "log",
    "service",
    "process",
    "message",
    "error",
    "trace",
})
_CRITICAL_EVENT_LOGGERS = (
    "numoj.audit",
    "numoj.access",
    "numoj.task",
)
_EXTRA_IDENTIFIER_FIELDS = (
    "request_id",
    "task_id",
    "submission_id",
    "competition_id",
    "problem_id",
    "user_id",
    "username",
)

_secret_values: tuple[str, ...] = ()
_configured_pid: int | None = None


def _discover_secret_values(environment: Mapping[str, str]) -> tuple[str, ...]:
    values = {
        str(value)
        for key, value in environment.items()
        if _SENSITIVE_KEY_RE.search(str(key))
        and value is not None
        and len(str(value)) >= 8
    }
    return tuple(sorted(values, key=len, reverse=True))


def configure_redaction(environment: Mapping[str, str] | None = None) -> None:
    """注册当前进程已知密钥，仅用于内容替换，不保留键名或来源。"""
    global _secret_values
    _secret_values = _discover_secret_values(environment or os.environ)


def redact_text(value: Any, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    """脱敏并限制任意外部文本；永不返回配置中的已知密钥。"""
    text = str(value)
    for secret in _secret_values:
        text = text.replace(secret, "<redacted>")
    text = _AUTH_RE.sub(r"\1 <redacted>", text)
    text = _URL_USERINFO_RE.sub(r"\1<redacted>@", text)
    text = _QUERY_SECRET_RE.sub(r"\1<redacted>", text)
    text = _KEY_VALUE_SECRET_RE.sub(r"\1\2<redacted>", text)
    text = _JSON_SECRET_RE.sub(r"\1\2<redacted>\2", text)
    if len(text) > max_chars:
        return f"{text[:max_chars]}…<truncated:{len(text) - max_chars}>"
    return text


def sanitize(
    value: Any,
    *,
    key: str = "",
    depth: int = 0,
    max_depth: int = 6,
) -> Any:
    """递归转换为有界 JSON 值，并按字段名与内容双重脱敏。"""
    if key and _SENSITIVE_KEY_RE.search(str(key)):
        return "<redacted>"
    if depth >= max_depth:
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else str(value)
    if isinstance(value, (str, bytes, bytearray)):
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).decode("utf-8", errors="replace")
        return redact_text(value)
    if isinstance(value, Mapping):
        items = list(islice(value.items(), 101))
        result = {
            redact_text(item_key, max_chars=128): sanitize(
                item_value,
                key=str(item_key),
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item_key, item_value in items[:100]
        }
        total = len(value)
        if total > 100:
            result["_truncated_fields"] = total - 100
        return result
    if isinstance(value, (list, tuple)):
        total = len(value)
        items = value[:50]
        result = [
            sanitize(item, depth=depth + 1, max_depth=max_depth)
            for item in items
        ]
        if total > 50:
            result.append(f"<truncated-items:{total - 50}>")
        return result
    if isinstance(value, (set, frozenset)):
        total = len(value)
        items = islice(value, 50)
        result = [
            sanitize(item, depth=depth + 1, max_depth=max_depth)
            for item in items
        ]
        if total > 50:
            result.append(f"<truncated-items:{total - 50}>")
        return result
    if isinstance(value, Path):
        return redact_text(str(value))
    return redact_text(repr(value))


def content_fingerprint(value: Any) -> dict[str, Any]:
    """返回内容的长度与摘要，不把内容本身写入日志。"""
    if value is None:
        return {"present": False, "bytes": 0, "sha256": None}
    if isinstance(value, bytes):
        raw = value
    else:
        raw = str(value).encode("utf-8", errors="replace")
    return {
        "present": True,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def file_fingerprint(path: os.PathLike[str] | str) -> dict[str, Any]:
    """流式计算文件长度与摘要；路径、文件名和内容都不会进入结果。"""
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def safe_file_fingerprint(
    path: os.PathLike[str] | str | None,
    *,
    artifact_type: str,
) -> dict[str, Any] | None:
    """返回枚举化文件类型与指纹；文件不可读时仍生成不含路径的元数据。"""
    if not path:
        return None
    metadata: dict[str, Any] = {
        "type": redact_text(artifact_type, max_chars=64),
    }
    try:
        metadata.update(file_fingerprint(path))
    except OSError:
        metadata["available"] = False
    return metadata


def _utc_timestamp(created: float) -> str:
    return datetime.fromtimestamp(created, tz=timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def build_event_envelope(
    dataset: str,
    *,
    action: str,
    outcome: str,
    level: str,
    logger_name: str,
    component: str,
    message: str,
    timestamp: str | None = None,
    event_id: str | None = None,
    environment: str | None = None,
    process: Mapping[str, Any] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """构造统一事件信封，供应用进程与外部日志采集器共同使用。"""
    payload: dict[str, Any] = {
        "@timestamp": timestamp or _utc_timestamp(datetime.now(timezone.utc).timestamp()),
        "schema": {"name": SCHEMA_NAME, "version": SCHEMA_VERSION},
        "event": {
            "id": event_id or uuid4().hex,
            "dataset": dataset,
            "action": action,
            "outcome": outcome,
        },
        "log": {"level": level, "logger": logger_name},
        "service": {
            "name": "numericaloj",
            "component": component,
            "environment": environment or os.environ.get(
                "NUMOJ_ENVIRONMENT",
                "development",
            ),
        },
        "process": dict(process or {"pid": os.getpid(), "name": component}),
        "message": message,
    }
    payload.update(fields)
    return sanitize(payload)


def validate_event_payload(payload: Any) -> bool:
    """验证当前版本事件信封；历史 CLI 与采集入口共享同一事实来源。"""
    if not isinstance(payload, Mapping):
        return False
    schema = payload.get("schema")
    return bool(
        isinstance(schema, Mapping)
        and schema.get("name") == SCHEMA_NAME
        and schema.get("version") == SCHEMA_VERSION
    )


def _exception_payload(record: logging.LogRecord) -> dict[str, Any] | None:
    if not record.exc_info:
        return None
    exc_type, exc_value, exc_traceback = record.exc_info
    stack = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
    return sanitize({
        "type": (
            f"{exc_type.__module__}.{exc_type.__name__}"
            if exc_type is not None
            else "unknown"
        ),
        "message": str(exc_value or ""),
        "stack_trace": stack,
    })


def _record_identifiers(record: logging.LogRecord) -> dict[str, Any]:
    return {
        key: getattr(record, key)
        for key in _EXTRA_IDENTIFIER_FIELDS
        if getattr(record, key, None) not in (None, "")
    }


def build_payload(record: logging.LogRecord) -> dict[str, Any]:
    cached = getattr(record, "_numoj_payload", None)
    if isinstance(cached, dict):
        return cached

    context = current_context()
    event_fields = getattr(record, "event_fields", {})
    if not isinstance(event_fields, Mapping):
        event_fields = {"value": event_fields}
    event_id = getattr(record, "event_id", None) or uuid4().hex
    dataset = str(getattr(record, "event_dataset", "numoj.runtime.application"))
    payload = build_event_envelope(
        dataset,
        action=getattr(record, "event_action", record.name),
        outcome=getattr(record, "event_outcome", "unknown"),
        level=record.levelname.lower(),
        logger_name=record.name,
        component=os.environ.get("NUMOJ_SERVICE_NAME", "application"),
        environment=os.environ.get("NUMOJ_ENVIRONMENT", "development"),
        message=record.getMessage(),
        timestamp=_utc_timestamp(record.created),
        event_id=event_id,
        process={
            "pid": record.process,
            "name": record.processName,
            "thread": {
                "id": record.thread,
                "name": record.threadName,
            },
        },
    )

    trace_id = context.get("trace_id") or context.get("request_id")
    if trace_id:
        payload["trace"] = {"id": redact_text(trace_id, max_chars=128)}
    if context.get("request_id"):
        payload["request"] = {"id": redact_text(context["request_id"], max_chars=128)}
    if context.get("task_id") or context.get("task_name"):
        payload["task"] = sanitize({
            "id": context.get("task_id"),
            "name": context.get("task_name"),
            "root_id": context.get("root_task_id"),
            "parent_id": context.get("parent_task_id"),
        })
    if context.get("user_id") or context.get("username"):
        payload["user"] = sanitize({
            "id": context.get("user_id"),
            "name": context.get("username"),
        })

    identifiers = _record_identifiers(record)
    if identifiers:
        payload["labels"] = sanitize(identifiers)
    for field_name, value in event_fields.items():
        safe_name = str(field_name)
        if (
            safe_name in _STANDARD_RECORD_FIELDS
            or safe_name in _PROTECTED_PAYLOAD_FIELDS
            or safe_name.startswith("_")
        ):
            continue
        payload[redact_text(safe_name, max_chars=128)] = sanitize(
            value,
            key=safe_name,
        )
    error = _exception_payload(record)
    if error:
        payload["error"] = error
    record._numoj_payload = payload
    return payload


def encode_payload(payload: Mapping[str, Any], *, max_bytes: int | None = None) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="replace")
    if max_bytes is None or len(encoded) <= max_bytes:
        return encoded

    compact = deepcopy(dict(payload))
    compact["message"] = redact_text(compact.get("message", ""), max_chars=2_048)
    compact["event"] = dict(compact.get("event") or {})
    compact["event"]["original_bytes"] = len(encoded)
    compact["event"]["truncated"] = True
    if isinstance(compact.get("error"), dict):
        compact["error"] = {
            "type": compact["error"].get("type"),
            "message": redact_text(compact["error"].get("message", ""), max_chars=2_048),
            "stack_trace": redact_text(
                compact["error"].get("stack_trace", ""),
                max_chars=8_192,
            ),
        }
    allowed = {
        "@timestamp",
        "schema",
        "event",
        "log",
        "service",
        "process",
        "message",
        "trace",
        "request",
        "task",
        "user",
        "source",
        "submission",
        "problem",
        "competition",
        "error",
    }
    compact = {key: value for key, value in compact.items() if key in allowed}
    encoded = json.dumps(
        compact,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return encoded

    emergency = {
        "@timestamp": compact.get("@timestamp"),
        "schema": compact.get("schema"),
        "event": compact.get("event"),
        "log": compact.get("log"),
        "service": compact.get("service"),
        "message": redact_text(compact.get("message", ""), max_chars=1_024),
    }
    return json.dumps(
        emergency,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8", errors="replace")[:max_bytes]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return encode_payload(build_payload(record)).decode("utf-8")


class _ConfiguredLevelFilter(logging.Filter):
    """运行日志服从 LOG_LEVEL，审计/访问/任务事件至少保留 INFO。"""

    def __init__(self, runtime_level: int):
        super().__init__()
        self.runtime_level = int(runtime_level)
        self.event_level = min(logging.INFO, self.runtime_level)

    def filter(self, record: logging.LogRecord) -> bool:
        is_critical_event = any(
            record.name == namespace or record.name.startswith(f"{namespace}.")
            for namespace in _CRITICAL_EVENT_LOGGERS
        )
        required = (
            self.event_level
            if is_critical_event
            else self.runtime_level
        )
        return record.levelno >= required


class UnixDatagramHandler(logging.Handler):
    """非阻塞 Unix datagram 输出；采集器不可用时不影响业务。"""

    def __init__(self, path: os.PathLike[str] | str = EVENT_SOCKET):
        super().__init__()
        self.path = str(path)
        self._socket: socket.socket | None = None
        self._pid: int | None = None

    def _connection(self) -> socket.socket:
        pid = os.getpid()
        if self._socket is not None and self._pid == pid:
            return self._socket
        self._close_socket()
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        connection.setblocking(False)
        connection.connect(self.path)
        self._socket = connection
        self._pid = pid
        return connection

    def emit(self, record: logging.LogRecord) -> None:
        try:
            packet = encode_payload(build_payload(record), max_bytes=MAX_DATAGRAM_BYTES)
            self._connection().send(packet)
        except (FileNotFoundError, ConnectionError, OSError):
            self._close_socket()

    def _close_socket(self) -> None:
        connection, self._socket = self._socket, None
        self._pid = None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass

    def close(self) -> None:
        self._close_socket()
        super().close()


def configure_logging(
    *,
    level: str | int = "INFO",
    socket_path: os.PathLike[str] | str = EVENT_SOCKET,
    force: bool = False,
) -> None:
    """幂等配置根 logger；业务始终有 stdout，采集器在线时再分类落盘。"""
    global _configured_pid
    pid = os.getpid()
    root = logging.getLogger()
    if _configured_pid == pid and not force:
        return

    configure_redaction()
    normalized_level = logging.getLevelNamesMapping().get(str(level).upper(), level)
    if not isinstance(normalized_level, int):
        normalized_level = logging.INFO

    for handler in tuple(root.handlers):
        if getattr(handler, "_numoj_handler", False):
            root.removeHandler(handler)
            handler.close()

    formatter = JsonFormatter()
    level_filter = _ConfiguredLevelFilter(normalized_level)
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler._numoj_handler = True
    stdout_handler.setFormatter(formatter)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.addFilter(level_filter)

    socket_handler = UnixDatagramHandler(socket_path)
    socket_handler._numoj_handler = True
    socket_handler.setLevel(logging.DEBUG)
    socket_handler.addFilter(level_filter)

    root.addHandler(stdout_handler)
    root.addHandler(socket_handler)
    root.setLevel(normalized_level)
    for logger_name in _CRITICAL_EVENT_LOGGERS:
        logging.getLogger(logger_name).setLevel(level_filter.event_level)
    logging.captureWarnings(True)
    _configured_pid = pid


def emit_event(
    dataset: str,
    *,
    action: str,
    outcome: str = "unknown",
    message: str,
    level: int = logging.INFO,
    logger_name: str | None = None,
    exception: BaseException | None = None,
    **fields: Any,
) -> None:
    """以稳定公共 API 发事件；日志故障永不改变业务事务结果。"""
    logger = logging.getLogger(logger_name or f"numoj.{dataset}")
    extra = {
        "event_dataset": f"numoj.{dataset}",
        "event_action": action,
        "event_outcome": outcome,
        "event_fields": fields,
    }
    exc_info = None
    if exception is not None:
        exc_info = (type(exception), exception, exception.__traceback__)
    try:
        logger.log(level, message, extra=extra, exc_info=exc_info)
    except Exception:
        # 可观测性必须 fail-open，不能让已提交的数据库事务向调用方伪装成失败。
        pass


def emit_audit(
    domain: str,
    *,
    action: str,
    outcome: str,
    message: str,
    **fields: Any,
) -> None:
    emit_event(
        f"audit.{domain}",
        action=action,
        outcome=outcome,
        message=message,
        **fields,
    )
