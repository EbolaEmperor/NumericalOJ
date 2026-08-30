"""Celery 可观测性 signal 注册、上下文传播与生命周期事件测试。"""

from __future__ import annotations

from collections import ChainMap
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from backend.oj_modules.observability import celery as celery_observability


class _FakeSignal:
    def __init__(self):
        self.receivers = {}
        self.connections = []

    def connect(self, *, weak, dispatch_uid):
        self.connections.append({"weak": weak, "dispatch_uid": dispatch_uid})

        def decorator(receiver):
            self.receivers[dispatch_uid] = receiver
            return receiver

        return decorator


class _FakeSignals:
    def __init__(self):
        self.setup_logging = _FakeSignal()
        self.before_task_publish = _FakeSignal()
        self.after_task_publish = _FakeSignal()
        self.task_prerun = _FakeSignal()
        self.task_retry = _FakeSignal()
        self.task_failure = _FakeSignal()
        self.task_postrun = _FakeSignal()
        self.task_revoked = _FakeSignal()

    def receiver(self, dispatch_uid):
        for signal in self.__dict__.values():
            if dispatch_uid in signal.receivers:
                return signal.receivers[dispatch_uid]
        raise KeyError(dispatch_uid)


def _install(monkeypatch, *, level="INFO"):
    fake_signals = _FakeSignals()
    monkeypatch.setattr(celery_observability, "signals", fake_signals)
    app = SimpleNamespace(conf=SimpleNamespace())
    celery_observability.install_celery_observability(app, level=level)
    return app, fake_signals


@pytest.mark.parametrize(
    ("value", "expected_identity", "expected"),
    [
        ({"id": "task-1"}, True, {"id": "task-1"}),
        (ChainMap({"id": "task-2"}), True, {"id": "task-2"}),
        (None, False, {}),
        ([('id', 'task-3')], False, {}),
        ("id=task-4", False, {}),
    ],
)
def test_mapping_preserves_mappings_and_normalizes_other_values(
    value,
    expected_identity,
    expected,
):
    result = celery_observability._mapping(value)

    assert dict(result) == expected
    if expected_identity:
        assert result is value
    else:
        assert result == {}


def test_install_celery_observability_configures_app_and_registers_all_signals(
    monkeypatch,
):
    app, fake_signals = _install(monkeypatch)

    assert app._numoj_observability_installed is True
    assert app.conf.worker_hijack_root_logger is False
    assert app.conf.worker_redirect_stdouts is True
    assert app.conf.worker_redirect_stdouts_level == "INFO"
    expected_uids = {
        "numoj.observability.setup_logging",
        "numoj.observability.before_task_publish",
        "numoj.observability.after_task_publish",
        "numoj.observability.task_prerun",
        "numoj.observability.task_retry",
        "numoj.observability.task_failure",
        "numoj.observability.task_postrun",
        "numoj.observability.task_revoked",
    }
    actual_uids = {
        connection["dispatch_uid"]
        for signal in fake_signals.__dict__.values()
        for connection in signal.connections
    }
    assert actual_uids == expected_uids
    assert all(
        connection["weak"] is False
        for signal in fake_signals.__dict__.values()
        for connection in signal.connections
    )


def test_install_celery_observability_is_idempotent(monkeypatch):
    app, fake_signals = _install(monkeypatch)
    connection_counts = {
        name: len(signal.connections)
        for name, signal in fake_signals.__dict__.items()
    }

    celery_observability.install_celery_observability(app, level="DEBUG")

    assert {
        name: len(signal.connections)
        for name, signal in fake_signals.__dict__.items()
    } == connection_counts


def test_setup_logging_uses_install_level_and_forces_unified_configuration(monkeypatch):
    _, fake_signals = _install(monkeypatch, level="WARNING")
    configure_logging = MagicMock()
    suppress_unsafe_loggers = MagicMock()
    monkeypatch.setattr(celery_observability, "configure_logging", configure_logging)
    monkeypatch.setattr(
        celery_observability,
        "_suppress_unsafe_lifecycle_loggers",
        suppress_unsafe_loggers,
    )

    fake_signals.receiver("numoj.observability.setup_logging")(ignored=True)

    configure_logging.assert_called_once_with(level="WARNING", force=True)
    suppress_unsafe_loggers.assert_called_once_with()


def test_suppress_unsafe_lifecycle_loggers_filters_only_default_task_trace(monkeypatch):
    trace_logger = logging.getLogger("celery.app.trace")
    monkeypatch.setattr(trace_logger, "filters", [])
    monkeypatch.setattr(trace_logger, "disabled", False)

    celery_observability._suppress_unsafe_lifecycle_loggers()
    celery_observability._suppress_unsafe_lifecycle_loggers()

    assert trace_logger.disabled is False
    assert len(trace_logger.filters) == 1
    trace_filter = trace_logger.filters[0]
    unsafe_record = logging.LogRecord(
        "celery.app.trace",
        logging.ERROR,
        __file__,
        1,
        "Task %(name)s[%(id)s] raised unexpected: %(exc)s",
        (),
        None,
    )
    internal_record = logging.LogRecord(
        "celery.app.trace",
        logging.ERROR,
        __file__,
        1,
        "Process cleanup failed",
        (),
        None,
    )
    assert trace_filter.filter(unsafe_record) is False
    assert trace_filter.filter(internal_record) is True


def test_before_task_publish_propagates_nonempty_context_to_dict_headers(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    propagation_context = MagicMock(
        return_value={"request_id": "request-1", "user_id": 42},
    )
    monkeypatch.setattr(
        celery_observability,
        "propagation_context",
        propagation_context,
    )
    headers = {"id": "task-1"}

    fake_signals.receiver("numoj.observability.before_task_publish")(
        headers=headers,
        body="ignored",
    )

    assert headers == {
        "id": "task-1",
        celery_observability._HEADER: {
            "request_id": "request-1",
            "user_id": 42,
        },
    }
    propagation_context.assert_called_once_with()


def test_before_task_publish_ignores_empty_context_and_non_dict_headers(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    propagation_context = MagicMock(return_value={})
    monkeypatch.setattr(
        celery_observability,
        "propagation_context",
        propagation_context,
    )
    receiver = fake_signals.receiver("numoj.observability.before_task_publish")
    headers = {"id": "task-1"}

    receiver(headers=headers)
    receiver(headers=ChainMap({"id": "task-2"}))
    receiver(headers=None)

    assert headers == {"id": "task-1"}
    propagation_context.assert_called_once_with()


def test_after_task_publish_emits_structured_metadata_with_sender_precedence(
    monkeypatch,
):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    headers = {
        "id": "task-1",
        "task": "header.task",
        "root_id": "root-1",
        "parent_id": "parent-1",
        "retries": 2,
        "eta": "2030-01-01T00:00:00Z",
    }

    fake_signals.receiver("numoj.observability.after_task_publish")(
        sender="sender.task",
        headers=headers,
        body=("secret task arguments",),
    )

    emit_event.assert_called_once_with(
        "task.lifecycle",
        action="task.published",
        outcome="success",
        message="Celery 任务已发布",
        task={
            "id": "task-1",
            "name": "sender.task",
            "root_id": "root-1",
            "parent_id": "parent-1",
            "retries": 2,
            "eta": "2030-01-01T00:00:00Z",
        },
    )
    assert "secret task arguments" not in repr(emit_event.call_args)


def test_after_task_publish_handles_missing_or_non_mapping_headers(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    receiver = fake_signals.receiver("numoj.observability.after_task_publish")

    receiver(headers=None)
    receiver(headers=[("task", "unsafe")])

    assert emit_event.call_count == 2
    assert emit_event.call_args_list[0].kwargs["task"] == {
        "id": None,
        "name": None,
        "root_id": None,
        "parent_id": None,
        "retries": None,
        "eta": None,
    }
    assert emit_event.call_args_list[1].kwargs["task"] == (
        emit_event.call_args_list[0].kwargs["task"]
    )


def test_task_prerun_restores_propagated_context_and_emits_start_metadata(
    monkeypatch,
):
    _, fake_signals = _install(monkeypatch)
    token = object()
    replace_context = MagicMock(return_value=token)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "replace_context", replace_context)
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    monkeypatch.setattr(celery_observability.time, "monotonic", lambda: 12.5)
    request = SimpleNamespace(
        headers={
            celery_observability._HEADER: {
                "request_id": "request-1",
                "user_id": 42,
            },
        },
        root_id="root-1",
        parent_id="parent-1",
        retries=3,
        delivery_info={"routing_key": "judge"},
    )
    task = SimpleNamespace(name="oj.tasks.evaluate", request=request)

    fake_signals.receiver("numoj.observability.task_prerun")(
        task_id="task-1",
        task=task,
        args=("secret",),
    )

    replace_context.assert_called_once_with(
        request_id="request-1",
        user_id=42,
        task_id="task-1",
        task_name="oj.tasks.evaluate",
        root_task_id="root-1",
        parent_task_id="parent-1",
    )
    assert request._numoj_context_token is token
    assert request._numoj_started_at == 12.5
    emit_event.assert_called_once_with(
        "task.lifecycle",
        action="task.started",
        outcome="unknown",
        message="Celery 任务开始执行",
        task={
            "id": "task-1",
            "name": "oj.tasks.evaluate",
            "root_id": "root-1",
            "parent_id": "parent-1",
            "retries": 3,
            "queue": "judge",
        },
    )
    assert "secret" not in repr(emit_event.call_args)


def test_task_prerun_handles_missing_request_and_invalid_header_payload(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    replace_context = MagicMock(return_value=object())
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "replace_context", replace_context)
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    task = SimpleNamespace(name="oj.tasks.empty", request=None)

    fake_signals.receiver("numoj.observability.task_prerun")(
        task_id="task-2",
        task=task,
    )

    replace_context.assert_called_once_with(
        task_id="task-2",
        task_name="oj.tasks.empty",
        root_task_id=None,
        parent_task_id=None,
    )
    assert emit_event.call_args.kwargs["task"] == {
        "id": "task-2",
        "name": "oj.tasks.empty",
        "root_id": None,
        "parent_id": None,
        "retries": None,
        "queue": None,
    }


@pytest.mark.parametrize(
    "reason",
    [
        RuntimeError("broker unavailable: stdout=private-value"),
        "countdown requested with private-value",
        None,
    ],
)
def test_task_retry_only_records_exception_type_and_message_fingerprint(
    monkeypatch,
    reason,
):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    request = SimpleNamespace(id="task-1", task="oj.tasks.evaluate", retries=2)

    fake_signals.receiver("numoj.observability.task_retry")(
        request=request,
        reason=reason,
    )

    kwargs = emit_event.call_args.kwargs
    assert emit_event.call_args.args == ("task.lifecycle",)
    assert kwargs["action"] == "task.retried"
    assert kwargs["outcome"] == "failure"
    assert kwargs["level"] == logging.WARNING
    assert "exception" not in kwargs
    assert kwargs["task"] == {
        "id": "task-1",
        "name": "oj.tasks.evaluate",
        "retries": 2,
    }
    expected_type = (
        f"{type(reason).__module__}.{type(reason).__qualname__}"
        if reason is not None
        else None
    )
    fingerprint = celery_observability.content_fingerprint(
        str(reason) if reason is not None else None,
    )
    assert kwargs["failure"] == {
        "exception": {
            "type": expected_type,
            "message": {
                "bytes": fingerprint["bytes"],
                "sha256": fingerprint["sha256"],
            },
        },
    }
    assert "private-value" not in repr(emit_event.call_args)


def test_task_failure_emits_only_exception_fingerprint_and_safe_identifiers(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    exception = ValueError("invalid result; stderr=private-value")
    sender = SimpleNamespace(name="oj.tasks.evaluate")

    fake_signals.receiver("numoj.observability.task_failure")(
        task_id="task-1",
        exception=exception,
        sender=sender,
        args=("secret",),
        kwargs={"token": "secret"},
        traceback="raw traceback",
    )

    kwargs = emit_event.call_args.kwargs
    assert emit_event.call_args.args == ("task.lifecycle",)
    assert kwargs["action"] == "task.failed"
    assert kwargs["outcome"] == "failure"
    assert kwargs["message"] == "Celery 任务执行失败"
    assert kwargs["level"] == logging.ERROR
    assert "exception" not in kwargs
    assert kwargs["task"] == {"id": "task-1", "name": "oj.tasks.evaluate"}
    fingerprint = celery_observability.content_fingerprint(str(exception))
    assert kwargs["failure"] == {
        "exception": {
            "type": "builtins.ValueError",
            "message": {
                "bytes": fingerprint["bytes"],
                "sha256": fingerprint["sha256"],
            },
        },
    }
    assert "secret" not in repr(emit_event.call_args)
    assert "private-value" not in repr(emit_event.call_args)


def test_error_metadata_survives_exception_with_broken_string_conversion():
    class BrokenMessageError(Exception):
        def __str__(self):
            raise RuntimeError("cannot stringify")

    metadata = celery_observability._error_metadata(BrokenMessageError())

    assert metadata == {
        "type": f"{BrokenMessageError.__module__}.{BrokenMessageError.__qualname__}",
        "message": {"bytes": 0, "sha256": None},
    }


def test_task_postrun_reports_success_duration_and_resets_context(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    reset_context = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    monkeypatch.setattr(celery_observability, "reset_context", reset_context)
    monkeypatch.setattr(celery_observability.time, "monotonic", lambda: 12.345)
    token = object()
    request = SimpleNamespace(
        _numoj_started_at=10.0,
        _numoj_context_token=token,
        retries=1,
    )
    task = SimpleNamespace(name="oj.tasks.evaluate", request=request)

    fake_signals.receiver("numoj.observability.task_postrun")(
        task_id="task-1",
        task=task,
        state="SUCCESS",
        retval="secret result",
    )

    emit_event.assert_called_once_with(
        "task.lifecycle",
        action="task.completed",
        outcome="success",
        message="Celery 任务执行结束",
        task={
            "id": "task-1",
            "name": "oj.tasks.evaluate",
            "state": "SUCCESS",
            "retries": 1,
        },
        duration={"milliseconds": 2345.0},
    )
    reset_context.assert_called_once_with(token)
    assert request._numoj_context_token is None
    assert "secret result" not in repr(emit_event.call_args)


def test_task_postrun_handles_failure_without_start_time_or_context_token(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    reset_context = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    monkeypatch.setattr(celery_observability, "reset_context", reset_context)
    request = SimpleNamespace(retries=0)
    task = SimpleNamespace(name="oj.tasks.evaluate", request=request)

    fake_signals.receiver("numoj.observability.task_postrun")(
        task_id="task-2",
        task=task,
        state="FAILURE",
    )

    assert emit_event.call_args.kwargs["outcome"] == "failure"
    assert emit_event.call_args.kwargs["duration"] == {"milliseconds": None}
    reset_context.assert_not_called()


@pytest.mark.parametrize(
    "reset_error",
    [LookupError("different context"), RuntimeError("already used"), ValueError("bad token")],
)
def test_task_postrun_swallows_context_reset_errors_and_clears_saved_token(
    monkeypatch,
    reset_error,
):
    _, fake_signals = _install(monkeypatch)
    monkeypatch.setattr(celery_observability, "emit_event", MagicMock())
    reset_context = MagicMock(side_effect=reset_error)
    monkeypatch.setattr(celery_observability, "reset_context", reset_context)
    token = object()
    request = SimpleNamespace(_numoj_context_token=token, retries=0)
    task = SimpleNamespace(name="oj.tasks.evaluate", request=request)

    fake_signals.receiver("numoj.observability.task_postrun")(
        task_id="task-1",
        task=task,
        state="SUCCESS",
    )

    reset_context.assert_called_once_with(token)
    assert request._numoj_context_token is None


def test_task_revoked_emits_normalized_warning_metadata(monkeypatch):
    _, fake_signals = _install(monkeypatch)
    emit_event = MagicMock()
    monkeypatch.setattr(celery_observability, "emit_event", emit_event)
    request = SimpleNamespace(id="task-1", task="oj.tasks.evaluate")

    fake_signals.receiver("numoj.observability.task_revoked")(
        request=request,
        terminated=1,
        signum="SIGTERM",
        expired=0,
    )

    emit_event.assert_called_once_with(
        "task.lifecycle",
        action="task.revoked",
        outcome="failure",
        message="Celery 任务被撤销",
        level=logging.WARNING,
        task={"id": "task-1", "name": "oj.tasks.evaluate"},
        revoke={"terminated": True, "signal": "SIGTERM", "expired": False},
    )
