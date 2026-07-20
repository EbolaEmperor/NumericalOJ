"""统一日志事件层的安全性、结构契约与降级行为。"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from oj_modules.observability import context
from oj_modules.observability import events


@pytest.fixture(autouse=True)
def _restore_observability_globals():
    previous_secrets = events._secret_values
    previous_pid = events._configured_pid
    context.clear_context()
    yield
    context.clear_context()
    events._secret_values = previous_secrets
    events._configured_pid = previous_pid


def _record(
    message="日志消息",
    *,
    level=logging.INFO,
    name="numoj.test",
    exc_info=None,
    created=1_704_067_200.1234,
    **attributes,
):
    record = logging.LogRecord(
        name=name,
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=(),
        exc_info=exc_info,
    )
    record.created = created
    for key, value in attributes.items():
        setattr(record, key, value)
    return record


class _FakeDatagramSocket:
    def __init__(self, *, send_error=None):
        self.send_error = send_error
        self.blocking = None
        self.connected_to = None
        self.packets = []
        self.closed = False

    def setblocking(self, value):
        self.blocking = value

    def connect(self, path):
        self.connected_to = path

    def send(self, packet):
        if self.send_error is not None:
            raise self.send_error
        self.packets.append(packet)
        return len(packet)

    def close(self):
        self.closed = True


class _SocketFactory:
    def __init__(self, sockets=None, *, error=None):
        self.available = list(sockets or [])
        self.error = error
        self.created = []
        self.calls = []

    def __call__(self, family, kind):
        self.calls.append((family, kind))
        if self.error is not None:
            raise self.error
        sock = self.available.pop(0) if self.available else _FakeDatagramSocket()
        self.created.append(sock)
        return sock


@contextmanager
def _isolated_logging_tree():
    root = logging.Logger("numoj-test-root", logging.NOTSET)
    children = {}

    def get_logger(name=None):
        if name is None:
            return root
        if name not in children:
            child = logging.Logger(name, logging.NOTSET)
            ancestors = [
                candidate
                for candidate in children
                if name.startswith(candidate + ".")
            ]
            child.parent = children[max(ancestors, key=len)] if ancestors else root
            child.propagate = True
            children[name] = child
        return children[name]

    capture_warnings = MagicMock()
    with (
        patch.object(events.logging, "getLogger", side_effect=get_logger),
        patch.object(events.logging, "captureWarnings", capture_warnings),
    ):
        yield root, children, capture_warnings
    for handler in tuple(root.handlers):
        handler.close()


def _base_payload(**overrides):
    payload = {
        "@timestamp": "2024-01-01T00:00:00.000Z",
        "schema": {"name": events.SCHEMA_NAME, "version": events.SCHEMA_VERSION},
        "event": {
            "id": "event-id",
            "dataset": "numoj.test",
            "action": "tested",
            "outcome": "success",
        },
        "log": {"level": "info", "logger": "numoj.test"},
        "service": {"name": "numericaloj", "component": "test"},
        "message": "测试消息",
    }
    payload.update(overrides)
    return payload


def test_unix_datagram_handler_init_and_close_are_idempotent(tmp_path):
    socket_path = tmp_path / "events.sock"
    handler = events.UnixDatagramHandler(socket_path)

    assert handler.path == str(socket_path)
    assert handler._socket is None
    assert handler._pid is None

    handler.close()
    handler.close()
    assert handler._socket is None
    assert handler._pid is None


def test_discover_secret_values_filters_deduplicates_and_sorts():
    environment = {
        "NORMAL_SETTING": "ordinary-value",
        "PASSWORD": "1234567",
        "mysql_password": "long-secret-value",
        "API-KEY": "another-secret",
        "SESSION_TOKEN": "another-secret",
        "PRIVATE_KEY_PATH": "the-longest-secret-value",
    }

    result = events._discover_secret_values(environment)

    assert set(result) == {
        "long-secret-value",
        "another-secret",
        "the-longest-secret-value",
    }
    assert [len(item) for item in result] == sorted(
        (len(item) for item in result), reverse=True
    )
    assert "ordinary-value" not in result
    assert "1234567" not in result


def test_configure_redaction_uses_explicit_mapping_and_real_environment():
    events.configure_redaction({"MYSQL_PASSWORD": "mapping-secret-123"})
    assert "mapping-secret-123" not in events.redact_text("mapping-secret-123")

    with patch.dict(
        os.environ,
        {"DASHSCOPE_API_KEY": "environment-secret-456"},
        clear=True,
    ):
        events.configure_redaction()
        redacted = events.redact_text("key=environment-secret-456")

    assert "environment-secret-456" not in redacted
    assert "<redacted>" in redacted


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("Authorization: Bearer abc.DEF-123_~=", "abc.DEF-123_~="),
        ("proxy-authorization=Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ("mysql://alice:super-password@db.internal/schema", "alice:super-password"),
        ("https://example.test/cb?token=query-secret-123&page=1", "query-secret-123"),
        ("password = plain-secret-123; mode=safe", "plain-secret-123"),
        ('{"api_key": "json-secret-123", "safe": 1}', "json-secret-123"),
    ],
)
def test_redact_text_covers_auth_url_query_and_key_value_patterns(raw, secret):
    result = events.redact_text(raw)

    assert secret not in result
    assert "<redacted>" in result


def test_redact_text_prefers_longest_known_secret_and_truncates_unicode():
    events.configure_redaction({
        "API_KEY": "abcdefgh",
        "SECOND_API_KEY": "abcdefghijklmnop",
    })

    result = events.redact_text("abcdefghijklmnop / abcdefgh / 雪" * 20, max_chars=40)

    assert "abcdefghijklmnop" not in result
    assert "abcdefgh" not in result
    assert result.endswith(">")
    assert "…<truncated:" in result
    assert len(result) < 80


@pytest.mark.parametrize(
    "value, forbidden",
    [
        ("?verification_code=123456", "123456"),
        ("#session=opaque-session-value", "opaque-session-value"),
        ("Cookie: session=browser-cookie-value", "browser-cookie-value"),
        ('{"private_key":"private-material"}', "private-material"),
        ("credential=database-credential", "database-credential"),
    ],
)
def test_redact_text_covers_authentication_and_session_secret_forms(value, forbidden):
    assert forbidden not in events.redact_text(value)


def test_redact_text_decodes_bytes_and_replaces_invalid_utf8():
    assert events.redact_text(b"hello\xff") == "b'hello\\xff'"
    assert "雪" in events.redact_text("雪")


def test_sanitize_recursively_bounds_and_normalizes_json_values(tmp_path):
    class SecretObject:
        def __repr__(self):
            return "SecretObject(environment-secret-789)"

    events.configure_redaction({"API_TOKEN": "environment-secret-789"})
    value = {
        "password": "must-not-survive",
        "nested": {
            "auth": "Bearer opaque-token-123",
            "path": tmp_path / "文件.txt",
            "bytes": b"hello\xff",
            "object": SecretObject(),
        },
        "sequence": (1, True, None, {"x", "y"}),
        "nan": math.nan,
        "positive_inf": math.inf,
        "negative_inf": -math.inf,
    }

    result = events.sanitize(value)

    assert result["password"] == "<redacted>"
    assert result["nested"]["auth"] == "Bearer <redacted>"
    assert result["nested"]["path"] == str(tmp_path / "文件.txt")
    assert result["nested"]["bytes"] == "hello�"
    assert result["nested"]["object"] == "SecretObject(<redacted>)"
    assert set(result["sequence"][3]) == {"x", "y"}
    assert result["nan"] == "nan"
    assert result["positive_inf"] == "inf"
    assert result["negative_inf"] == "-inf"
    json.dumps(result, ensure_ascii=False)


def test_sanitize_applies_depth_mapping_and_sequence_limits():
    mapping = {f"field_{index}": index for index in range(105)}
    sequence = list(range(55))

    result = events.sanitize({
        "deep": {"one": {"two": {"three": "hidden"}}},
        "mapping": mapping,
        "sequence": sequence,
    }, max_depth=4)

    assert result["deep"]["one"]["two"]["three"] == "<max-depth>"
    assert len(result["mapping"]) == 101
    assert result["mapping"]["_truncated_fields"] == 5
    assert result["sequence"][:50] == list(range(50))
    assert result["sequence"][-1] == "<truncated-items:5>"


@pytest.mark.parametrize(
    ("value", "expected_present", "expected_raw"),
    [
        (None, False, None),
        ("", True, b""),
        ("你好", True, "你好".encode("utf-8")),
        (b"\x00\xff", True, b"\x00\xff"),
    ],
)
def test_content_fingerprint_is_content_free_and_byte_accurate(
    value, expected_present, expected_raw
):
    result = events.content_fingerprint(value)

    assert result["present"] is expected_present
    if expected_raw is None:
        assert result == {"present": False, "bytes": 0, "sha256": None}
    else:
        assert result["bytes"] == len(expected_raw)
        assert result["sha256"] == hashlib.sha256(expected_raw).hexdigest()
        assert set(result) == {"present", "bytes", "sha256"}


def test_file_fingerprint_streams_large_file_and_hides_path(tmp_path):
    raw = b"a" * (1024 * 1024) + "尾部".encode("utf-8")
    source = tmp_path / "private-source.bin"
    source.write_bytes(raw)

    result = events.file_fingerprint(source)

    assert result == {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    assert str(tmp_path) not in json.dumps(result)


def test_safe_file_fingerprint_adds_only_enumerated_type_and_handles_failures(
    monkeypatch,
    tmp_path,
):
    source = tmp_path / "source.bin"
    source.write_bytes(b"payload")

    result = events.safe_file_fingerprint(source, artifact_type="answer")

    assert result == {
        "type": "answer",
        "bytes": 7,
        "sha256": hashlib.sha256(b"payload").hexdigest(),
    }
    assert events.safe_file_fingerprint(None, artifact_type="answer") is None

    monkeypatch.setattr(
        events,
        "file_fingerprint",
        MagicMock(side_effect=OSError("permission denied")),
    )
    assert events.safe_file_fingerprint(
        "/private/storage/name.pdf",
        artifact_type="written",
    ) == {"type": "written", "available": False}


def test_build_event_envelope_and_validator_are_the_schema_source():
    payload = events.build_event_envelope(
        "numoj.infrastructure.mysql",
        action="daemon.message",
        outcome="unknown",
        level="warning",
        logger_name="numoj.infrastructure.collector",
        component="mysql",
        environment="test",
        message="数据库事件",
        timestamp="2026-02-03T04:05:06.789Z",
        event_id="event-1",
        process={"pid": 123, "name": "collector"},
        infrastructure={"unit": "mysql.service"},
    )

    assert payload["schema"] == {
        "name": events.SCHEMA_NAME,
        "version": events.SCHEMA_VERSION,
    }
    assert payload["event"] == {
        "id": "event-1",
        "dataset": "numoj.infrastructure.mysql",
        "action": "daemon.message",
        "outcome": "unknown",
    }
    assert payload["service"]["environment"] == "test"
    assert payload["infrastructure"] == {"unit": "mysql.service"}
    assert events.validate_event_payload(payload) is True
    assert events.validate_event_payload([]) is False
    assert events.validate_event_payload({"schema": {"name": "other", "version": 1}}) is False


@pytest.mark.parametrize(
    ("created", "expected"),
    [
        (0, "1970-01-01T00:00:00.000Z"),
        (1_704_067_200.1234, "2024-01-01T00:00:00.123Z"),
        (
            datetime(2024, 2, 29, 23, 59, 59, 999000, tzinfo=timezone.utc).timestamp(),
            "2024-02-29T23:59:59.999Z",
        ),
    ],
)
def test_utc_timestamp_is_utc_with_millisecond_precision(created, expected):
    assert events._utc_timestamp(created) == expected


def test_record_identifiers_only_keeps_nonempty_allowlisted_values():
    record = _record(
        request_id="req-1",
        task_id="",
        submission_id=42,
        competition_id=None,
        problem_id=0,
        user_id=7,
        username="alice",
        not_allowlisted="must-not-appear",
    )

    assert events._record_identifiers(record) == {
        "request_id": "req-1",
        "submission_id": 42,
        "problem_id": 0,
        "user_id": 7,
        "username": "alice",
    }


def test_exception_payload_is_none_without_exception():
    assert events._exception_payload(_record()) is None


def test_exception_payload_is_structured_and_redacted():
    events.configure_redaction({"MYSQL_PASSWORD": "database-secret-123"})
    try:
        raise RuntimeError(
            "database-secret-123 Bearer bearer-token-456 "
            "mysql://root:password@localhost/db"
        )
    except RuntimeError as error:
        record = _record(exc_info=(type(error), error, error.__traceback__))

    result = events._exception_payload(record)
    encoded = json.dumps(result)

    assert result["type"] == "builtins.RuntimeError"
    assert "RuntimeError" in result["stack_trace"]
    assert "database-secret-123" not in encoded
    assert "bearer-token-456" not in encoded
    assert "root:password" not in encoded
    assert encoded.count("<redacted>") >= 3


def test_build_payload_has_versioned_schema_context_unicode_and_protected_fields():
    events.configure_redaction({"API_KEY": "payload-secret-123"})
    token = context.replace_context(
        request_id="request-1",
        trace_id="trace-1",
        task_id="task-1",
        task_name="oj.task",
        root_task_id="root-1",
        parent_task_id="parent-1",
        user_id=9,
        username="张三",
    )
    try:
        record = _record(
            "你好 payload-secret-123",
            event_id="event-1",
            event_dataset="numoj.audit.auth",
            event_action="login.succeeded",
            event_outcome="success",
            submission_id=88,
            problem_id=6,
            event_fields={
                "source": {"ip": "127.0.0.1"},
                "authorization": "Bearer field-token-789",
                "schema": {"version": 999},
                "event": {"dataset": "evil"},
                "log": {"level": "evil"},
                "service": {"name": "evil"},
                "process": {"pid": -1},
                "message": "evil",
                "error": {"type": "evil"},
                "trace": {"id": "evil"},
                "_private": "evil",
            },
        )
        payload = events.build_payload(record)
    finally:
        context.reset_context(token)

    assert payload["@timestamp"] == "2024-01-01T00:00:00.123Z"
    assert payload["schema"] == {
        "name": events.SCHEMA_NAME,
        "version": events.SCHEMA_VERSION,
    }
    assert payload["event"] == {
        "id": "event-1",
        "dataset": "numoj.audit.auth",
        "action": "login.succeeded",
        "outcome": "success",
    }
    assert payload["message"] == "你好 <redacted>"
    assert payload["trace"] == {"id": "trace-1"}
    assert payload["request"] == {"id": "request-1"}
    assert payload["task"] == {
        "id": "task-1",
        "name": "oj.task",
        "root_id": "root-1",
        "parent_id": "parent-1",
    }
    assert payload["user"] == {"id": 9, "name": "张三"}
    assert payload["labels"] == {"submission_id": 88, "problem_id": 6}
    assert payload["source"] == {"ip": "127.0.0.1"}
    assert payload["authorization"] == "<redacted>"
    assert "_private" not in payload
    assert payload["service"]["name"] == "numericaloj"
    assert payload["process"]["pid"] == record.process


def test_build_payload_caches_event_id_and_payload_object():
    record = _record(event_fields={"custom": 1})

    first = events.build_payload(record)
    token = context.replace_context(request_id="later-request")
    try:
        second = events.build_payload(record)
    finally:
        context.reset_context(token)

    assert second is first
    assert len(first["event"]["id"]) == 32
    assert "request" not in first


def test_build_payload_includes_sanitized_exception():
    try:
        raise ValueError("Bearer exception-token-123")
    except ValueError as error:
        record = _record(
            "failed",
            level=logging.ERROR,
            exc_info=(type(error), error, error.__traceback__),
        )

    payload = events.build_payload(record)

    assert payload["log"]["level"] == "error"
    assert payload["error"]["type"] == "builtins.ValueError"
    assert payload["error"]["message"] == "Bearer <redacted>"
    assert "exception-token-123" not in payload["error"]["stack_trace"]


def test_encode_payload_is_compact_sorted_unicode_json_without_newline():
    encoded = events.encode_payload(_base_payload(zeta="雪", alpha=1))

    assert b"\n" not in encoded
    assert "雪".encode("utf-8") in encoded
    assert encoded.startswith(b'{"@timestamp"')
    assert json.loads(encoded)["schema"]["version"] == events.SCHEMA_VERSION


def test_encode_payload_compacts_oversized_metadata_and_marks_event():
    payload = _base_payload(oversized="x" * 100_000)
    original_size = len(events.encode_payload(payload))

    encoded = events.encode_payload(payload, max_bytes=4_096)
    result = json.loads(encoded)

    assert len(encoded) <= 4_096
    assert "oversized" not in result
    assert result["event"]["truncated"] is True
    assert result["event"]["original_bytes"] == original_size


def test_encode_payload_uses_emergency_shape_when_allowed_field_is_huge():
    payload = _base_payload(source={"raw": "x" * 100_000})

    encoded = events.encode_payload(payload, max_bytes=2_000)
    result = json.loads(encoded)

    assert len(encoded) <= 2_000
    assert "source" not in result
    assert set(result) == {"@timestamp", "schema", "event", "log", "service", "message"}
    assert result["event"]["truncated"] is True


def test_encode_payload_extreme_limit_is_bounded_and_does_not_leak_message_secret():
    events.configure_redaction({"API_KEY": "emergency-secret-123"})
    payload = _base_payload(
        service={"name": "x" * 1_000},
        message="emergency-secret-123 " + "y" * 1_000,
    )

    encoded = events.encode_payload(payload, max_bytes=128)

    assert len(encoded) <= 128
    assert b"emergency-secret-123" not in encoded


def test_json_formatter_produces_single_line_versioned_redacted_json():
    events.configure_redaction({"API_KEY": "formatter-secret-123"})
    try:
        raise LookupError("Bearer formatter-token-456")
    except LookupError as error:
        record = _record(
            "Unicode 雪 formatter-secret-123",
            exc_info=(type(error), error, error.__traceback__),
            event_fields={"password": "not-logged"},
        )

    formatted = events.JsonFormatter().format(record)
    payload = json.loads(formatted)

    assert "\n" not in formatted
    assert payload["schema"]["version"] == events.SCHEMA_VERSION
    assert payload["message"] == "Unicode 雪 <redacted>"
    assert payload["password"] == "<redacted>"
    assert "formatter-secret-123" not in formatted
    assert "formatter-token-456" not in formatted


def test_unix_datagram_handler_sends_bounded_json_and_reuses_connection(tmp_path):
    fake_socket = _FakeDatagramSocket()
    factory = _SocketFactory([fake_socket])
    handler = events.UnixDatagramHandler(tmp_path / "events.sock")
    fields = {f"large_{index}": "雪" * 10_000 for index in range(12)}
    first = _record("first", event_fields=fields)
    second = _record("second")

    with patch.object(events.socket, "socket", side_effect=factory):
        handler.emit(first)
        handler.emit(second)

    assert len(factory.created) == 1
    assert factory.calls == [(events.socket.AF_UNIX, events.socket.SOCK_DGRAM)]
    assert fake_socket.blocking is False
    assert fake_socket.connected_to == str(tmp_path / "events.sock")
    assert len(fake_socket.packets) == 2
    assert all(len(packet) <= events.MAX_DATAGRAM_BYTES for packet in fake_socket.packets)
    assert all(json.loads(packet)["schema"]["version"] == 1 for packet in fake_socket.packets)
    assert json.loads(fake_socket.packets[0])["event"]["truncated"] is True
    handler.close()


def test_unix_datagram_handler_fails_open_when_socket_missing(tmp_path):
    factory = _SocketFactory(error=FileNotFoundError("collector unavailable"))
    handler = events.UnixDatagramHandler(tmp_path / "missing.sock")

    with patch.object(events.socket, "socket", side_effect=factory):
        handler.emit(_record())

    assert handler._socket is None
    assert handler._pid is None


def test_unix_datagram_handler_closes_failed_send_and_recovers(tmp_path):
    failed = _FakeDatagramSocket(send_error=OSError("queue full"))
    recovered = _FakeDatagramSocket()
    factory = _SocketFactory([failed, recovered])
    handler = events.UnixDatagramHandler(tmp_path / "events.sock")

    with patch.object(events.socket, "socket", side_effect=factory):
        handler.emit(_record("failed"))
        handler.emit(_record("recovered"))

    assert failed.closed is True
    assert recovered.packets
    assert handler._socket is recovered
    handler.close()


def test_unix_datagram_handler_reconnects_after_fork_pid_change(tmp_path):
    parent_socket = _FakeDatagramSocket()
    child_socket = _FakeDatagramSocket()
    factory = _SocketFactory([parent_socket, child_socket])
    handler = events.UnixDatagramHandler(tmp_path / "events.sock")
    records = [_record("parent"), _record("child")]

    with (
        patch.object(events.socket, "socket", side_effect=factory),
        patch.object(events.os, "getpid", side_effect=[100, 101]),
    ):
        handler.emit(records[0])
        handler.emit(records[1])

    assert parent_socket.closed is True
    assert len(parent_socket.packets) == 1
    assert len(child_socket.packets) == 1
    assert handler._pid == 101
    handler.close()


def test_configure_logging_is_idempotent_force_replaces_owned_handlers():
    events._configured_pid = None
    external = logging.NullHandler()
    with _isolated_logging_tree() as (root, _children, capture_warnings):
        root.addHandler(external)
        events.configure_logging(level="INFO", socket_path="/tmp/test-events.sock")
        first_owned = [
            handler for handler in root.handlers if getattr(handler, "_numoj_handler", False)
        ]

        assert root.level == logging.INFO
        assert len(first_owned) == 2
        assert isinstance(first_owned[0], logging.StreamHandler)
        assert isinstance(first_owned[0].formatter, events.JsonFormatter)
        assert any(isinstance(handler, events.UnixDatagramHandler) for handler in first_owned)
        assert external in root.handlers
        capture_warnings.assert_called_once_with(True)

        events.configure_logging(level="DEBUG", socket_path="/tmp/ignored.sock")
        second_owned = [
            handler for handler in root.handlers if getattr(handler, "_numoj_handler", False)
        ]
        assert second_owned == first_owned
        assert root.level == logging.INFO

        events.configure_logging(
            level="WARNING",
            socket_path="/tmp/replaced.sock",
            force=True,
        )
        replacement = [
            handler for handler in root.handlers if getattr(handler, "_numoj_handler", False)
        ]
        assert len(replacement) == 2
        assert replacement != first_owned
        assert all(handler._closed for handler in first_owned)
        assert external in root.handlers


def test_configure_logging_reconfigures_after_fork_and_invalid_level_falls_back():
    events._configured_pid = None
    with (
        _isolated_logging_tree() as (root, _children, _capture_warnings),
        patch.object(events.os, "getpid", side_effect=[100, 101]),
    ):
        events.configure_logging(level="not-a-level", socket_path="/tmp/parent.sock")
        parent_handlers = tuple(root.handlers)
        assert root.level == logging.INFO

        events.configure_logging(level="DEBUG", socket_path="/tmp/child.sock")
        child_handlers = tuple(root.handlers)

    assert child_handlers != parent_handlers
    assert all(handler._closed for handler in parent_handlers)
    assert root.level == logging.DEBUG


def test_configure_warning_keeps_audit_access_and_task_info_events(capsys):
    """运行日志等级不能吞掉安全审计、访问日志和任务生命周期事件。"""
    events._configured_pid = None
    fake_socket = _FakeDatagramSocket()
    factory = _SocketFactory([fake_socket])
    with (
        _isolated_logging_tree(),
        patch.object(events.socket, "socket", side_effect=factory),
    ):
        events.configure_logging(level="WARNING", socket_path="/tmp/events.sock")
        events.emit_audit(
            "auth",
            action="login.succeeded",
            outcome="success",
            message="登录成功",
        )
        events.emit_event(
            "access.http",
            action="request.completed",
            outcome="success",
            message="访问完成",
        )
        events.emit_event(
            "task.lifecycle",
            action="task.completed",
            outcome="success",
            message="任务完成",
        )
        events.emit_event(
            "runtime.application",
            action="diagnostic.info",
            outcome="success",
            message="普通 INFO 应按等级过滤",
        )

    stdout_payloads = [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.strip()
    ]
    socket_payloads = [json.loads(packet) for packet in fake_socket.packets]
    required = {
        "numoj.audit.auth",
        "numoj.access.http",
        "numoj.task.lifecycle",
    }

    assert {payload["event"]["dataset"] for payload in stdout_payloads} == required
    assert {payload["event"]["dataset"] for payload in socket_payloads} == required
    assert all(
        payload["event"]["dataset"] != "numoj.runtime.application"
        for payload in stdout_payloads + socket_payloads
    )


def test_configured_level_filter_uses_strict_namespace_boundaries():
    level_filter = events._ConfiguredLevelFilter(logging.WARNING)

    for logger_name in (
        "numoj.audit",
        "numoj.audit.auth",
        "numoj.access.http",
        "numoj.task.lifecycle",
    ):
        assert level_filter.filter(_record(name=logger_name, level=logging.INFO)) is True

    for logger_name in (
        "numoj.auditevil",
        "numoj.accessorial",
        "numoj.tasker",
        "numoj.runtime.application",
    ):
        assert level_filter.filter(_record(name=logger_name, level=logging.INFO)) is False
        assert level_filter.filter(_record(name=logger_name, level=logging.WARNING)) is True


def test_emit_event_creates_structured_record_with_exception():
    captured = []

    class Capture(logging.Handler):
        def emit(self, record):
            captured.append(record)

    logger = logging.Logger("numoj.test-dataset", logging.DEBUG)
    logger.addHandler(Capture())
    caught = None
    try:
        raise ValueError("boom")
    except ValueError as error:
        caught = error
        with patch.object(events.logging, "getLogger", return_value=logger):
            events.emit_event(
                "test.dataset",
                action="item.created",
                outcome="success",
                message="已创建",
                exception=error,
                item={"id": 3},
            )

    assert len(captured) == 1
    record = captured[0]
    assert record.event_dataset == "numoj.test.dataset"
    assert record.event_action == "item.created"
    assert record.event_outcome == "success"
    assert record.event_fields == {"item": {"id": 3}}
    assert record.getMessage() == "已创建"
    assert record.exc_info[1] is caught


def test_emit_event_is_fail_open_when_logger_fails():
    failing_logger = MagicMock()
    failing_logger.log.side_effect = RuntimeError("logging unavailable")

    with patch.object(events.logging, "getLogger", return_value=failing_logger):
        assert events.emit_event(
            "runtime.application",
            action="failure.tested",
            message="不会向调用方抛异常",
        ) is None


def test_emit_audit_delegates_to_namespaced_event():
    with patch.object(events, "emit_event") as emit_event:
        events.emit_audit(
            "submission",
            action="submission.created",
            outcome="success",
            message="提交已创建",
            submission={"id": 12},
        )

    emit_event.assert_called_once_with(
        "audit.submission",
        action="submission.created",
        outcome="success",
        message="提交已创建",
        submission={"id": 12},
    )
