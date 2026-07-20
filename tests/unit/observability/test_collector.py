from __future__ import annotations

import errno
import io
import json
import logging
import os
from pathlib import Path
import signal
import socket
import stat
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from oj_modules.observability import collector


def _event(dataset: str = "numoj.runtime.application", **fields):
    return {
        "@timestamp": "2026-01-02T03:04:05.000Z",
        "schema": {
            "name": collector.SCHEMA_NAME,
            "version": collector.SCHEMA_VERSION,
        },
        "event": {
            "id": "event-1",
            "dataset": dataset,
            "action": "test",
            "outcome": "success",
        },
        "message": "test event",
        **fields,
    }


def _packet(dataset: str = "numoj.runtime.application") -> bytes:
    return json.dumps(_event(dataset), ensure_ascii=False).encode()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _fake_router(tmp_path: Path):
    root = collector.init_log_tree(tmp_path / "logs")
    return SimpleNamespace(root=root, write=MagicMock())


def test_init_log_tree_creates_fixed_tree_with_private_permissions(tmp_path):
    root = collector.init_log_tree(tmp_path / "logs")

    assert root == tmp_path / "logs"
    assert _mode(root) == 0o700
    assert {path.name for path in root.iterdir()} == set(collector.LOG_DIRECTORIES)
    assert all(path.is_dir() and _mode(path) == 0o700 for path in root.iterdir())

    root.chmod(0o777)
    (root / "audit").chmod(0o755)
    collector.init_log_tree(root)
    assert _mode(root) == 0o700
    assert _mode(root / "audit") == 0o700


def test_assert_safe_directory_rejects_file_and_symlink(tmp_path):
    missing = tmp_path / "missing"
    collector._assert_safe_directory(missing)
    assert missing.is_dir()
    assert _mode(missing) == 0o700

    regular_file = tmp_path / "regular"
    regular_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(RuntimeError, match="不是安全目录"):
        collector._assert_safe_directory(regular_file)

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(RuntimeError, match="不是安全目录"):
        collector._assert_safe_directory(link)


def test_init_log_tree_rejects_symlink_parent_and_child(tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(RuntimeError, match="父路径不能是符号链接"):
        collector.init_log_tree(linked_parent / "logs")

    root = collector.init_log_tree(tmp_path / "logs")
    audit = root / "audit"
    audit.rmdir()
    audit.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError, match="不是安全目录"):
        collector.init_log_tree(root)


def test_init_log_tree_rejects_symlinked_log_file(tmp_path):
    root = collector.init_log_tree(tmp_path / "logs")
    outside = tmp_path / "outside.log"
    outside.write_text("untouched", encoding="utf-8")
    (root / "services" / "web.log").symlink_to(outside)

    with pytest.raises(RuntimeError, match="不能包含符号链接"):
        collector.init_log_tree(root)

    assert outside.read_text(encoding="utf-8") == "untouched"


def test_secure_handler_writes_with_0600_and_rejects_symlink(tmp_path):
    target = tmp_path / "secure.jsonl"
    target.write_text("", encoding="utf-8")
    target.chmod(0o666)
    handler = collector.SecureRotatingFileHandler(
        target, maxBytes=1024, backupCount=1, encoding="utf-8", delay=True
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.handle(logging.LogRecord("test", logging.INFO, __file__, 1, "line", (), None))
    handler.close()

    assert target.read_text(encoding="utf-8") == "line\n"
    assert _mode(target) == 0o600

    destination = tmp_path / "destination.jsonl"
    destination.write_text("untouched", encoding="utf-8")
    link = tmp_path / "linked.jsonl"
    link.symlink_to(destination)
    linked_handler = collector.SecureRotatingFileHandler(
        link, maxBytes=1024, backupCount=1, encoding="utf-8", delay=True
    )
    with pytest.raises(OSError):
        linked_handler._open()
    linked_handler.close()
    assert destination.read_text(encoding="utf-8") == "untouched"


def test_secure_handler_rejects_non_regular_descriptor_and_closes_it(tmp_path):
    target = tmp_path / "not-regular.jsonl"
    handler = collector.SecureRotatingFileHandler(
        target, maxBytes=1024, backupCount=1, encoding="utf-8", delay=True
    )
    real_close = os.close
    closed = []

    def record_close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    with (
        patch.object(
            collector.os,
            "fstat",
            return_value=SimpleNamespace(st_mode=stat.S_IFDIR),
        ),
        patch.object(collector.os, "close", side_effect=record_close),
        pytest.raises(RuntimeError, match="不是普通文件"),
    ):
        handler._open()

    handler.close()
    assert len(closed) == 1


def test_log_router_routes_all_datasets_and_unknown_fallback(tmp_path):
    router = collector.LogRouter(tmp_path / "logs")
    try:
        for dataset, relative_path in collector.DATASET_PATHS.items():
            assert router.write(_event(dataset)) == relative_path
        assert router.write(_event("numoj.unknown")) == "runtime/application.jsonl"
    finally:
        router.close()

    for relative_path in set(collector.DATASET_PATHS.values()):
        path = tmp_path / "logs" / relative_path
        assert path.is_file()
        assert _mode(path) == 0o600
        assert all(
            json.loads(line)["schema"]["version"] == 1
            for line in path.read_text().splitlines()
        )


def test_log_router_sanitizes_and_rotates_with_bounded_backups(tmp_path):
    secret = "collector-secret-value"
    with patch.dict(os.environ, {"COLLECTOR_API_KEY": secret}, clear=False):
        router = collector.LogRouter(tmp_path / "logs", max_bytes=220, backups=2)
        for index in range(12):
            router.write(
                _event(
                    "numoj.audit.auth",
                    password="must-not-survive",
                    details=f"Bearer {secret} iteration-{index}",
                )
            )
        cached = router._handler("audit/auth.jsonl")
        assert cached is router._handler("audit/auth.jsonl")
        router.close()
        assert router._handlers == {}

    files = sorted((tmp_path / "logs" / "audit").glob("auth.jsonl*"))
    assert [path.name for path in files] == ["auth.jsonl", "auth.jsonl.1", "auth.jsonl.2"]
    assert all(_mode(path) == 0o600 for path in files)
    combined = "".join(path.read_text(encoding="utf-8") for path in files)
    assert secret not in combined
    assert "must-not-survive" not in combined
    assert "<redacted>" in combined
    assert all(json.loads(line) for path in files for line in path.read_text().splitlines())


def test_log_router_rejects_symlink_target_before_open(tmp_path):
    router = collector.LogRouter(tmp_path / "logs")
    destination = tmp_path / "outside.jsonl"
    destination.write_text("outside", encoding="utf-8")
    target = router.root / "audit" / "auth.jsonl"
    target.symlink_to(destination)
    try:
        with pytest.raises(RuntimeError, match="符号链接日志文件"):
            router.write(_event("numoj.audit.auth"))
    finally:
        router.close()
    assert destination.read_text(encoding="utf-8") == "outside"


@pytest.mark.parametrize(
    ("packet", "message"),
    [
        (b"x" * (collector.MAX_DATAGRAM_BYTES + 1), "超出上限"),
        (b"\xff", "不是有效 UTF-8 JSON"),
        (b"{", "不是有效 UTF-8 JSON"),
        (b"[]", "必须是 JSON object"),
        (b"{}", "schema 名称无效"),
        (json.dumps({"schema": "bad"}).encode(), "schema 名称无效"),
        (json.dumps({"schema": {"name": "other", "version": 1}}).encode(), "schema 名称无效"),
        (
            json.dumps(
                {"schema": {"name": collector.SCHEMA_NAME, "version": 999}}
            ).encode(),
            "schema 版本无效",
        ),
    ],
)
def test_log_router_write_packet_rejects_invalid_packets(tmp_path, packet, message):
    router = collector.LogRouter(tmp_path / "logs")
    try:
        with pytest.raises(ValueError, match=message):
            router.write_packet(packet)
    finally:
        router.close()


def test_log_router_write_packet_accepts_versioned_object(tmp_path):
    router = collector.LogRouter(tmp_path / "logs")
    try:
        assert router.write_packet(_packet("numoj.task.lifecycle")) == "runtime/tasks.jsonl"
    finally:
        router.close()
    payload = json.loads((tmp_path / "logs/runtime/tasks.jsonl").read_text())
    assert payload["event"]["dataset"] == "numoj.task.lifecycle"


def test_utc_now_is_millisecond_utc_timestamp():
    value = collector._utc_now()
    assert value.endswith("Z")
    assert len(value.rsplit(".", 1)[1].removesuffix("Z")) == 3
    assert value.startswith("20")


def test_external_event_builds_schema_and_redacts_fields():
    secret = "external-secret-value"
    collector.configure_redaction({"EXTERNAL_TOKEN": secret})
    fake_uuid = SimpleNamespace(hex="fixed-event-id")
    with (
        patch.object(collector, "_utc_now", return_value="2026-02-03T04:05:06.789Z"),
        patch.object(collector, "uuid4", return_value=fake_uuid),
        patch.object(collector.os, "getpid", return_value=123),
        patch.dict(os.environ, {"NUMOJ_ENVIRONMENT": "staging"}, clear=False),
    ):
        payload = collector._external_event(
            "numoj.infrastructure.mysql",
            action="daemon.message",
            outcome="unknown",
            level="error",
            message=f"Bearer {secret}",
            component="mysql",
            credentials={"password": "plain"},
        )

    assert payload["@timestamp"] == "2026-02-03T04:05:06.789Z"
    assert payload["schema"] == {"name": collector.SCHEMA_NAME, "version": 1}
    assert payload["event"] == {
        "id": "fixed-event-id",
        "dataset": "numoj.infrastructure.mysql",
        "action": "daemon.message",
        "outcome": "unknown",
    }
    assert payload["service"] == {
        "name": "numericaloj",
        "component": "mysql",
        "environment": "staging",
    }
    assert payload["process"] == {"pid": 123, "name": "log-collector"}
    assert secret not in payload["message"]
    assert payload["credentials"] == "<redacted>"


def test_atomic_json_replaces_file_redacts_and_cleans_temporary(tmp_path):
    path = tmp_path / "status.json"
    path.write_text('{"old": true}\n', encoding="utf-8")
    path.chmod(0o644)
    collector.configure_redaction({"STATUS_SECRET": "status-secret-value"})

    collector._atomic_json(
        path,
        {"state": "running", "password": "plain", "message": "status-secret-value"},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "message": "<redacted>",
        "password": "<redacted>",
        "state": "running",
    }
    assert _mode(path) == 0o600
    assert not list(tmp_path.glob(".status.json.tmp-*"))


def test_atomic_text_replaces_file_with_private_permissions(tmp_path):
    path = tmp_path / "cursor"
    path.write_text("old\n", encoding="utf-8")
    path.chmod(0o644)

    collector._atomic_text(path, "new\n")

    assert path.read_text(encoding="utf-8") == "new\n"
    assert _mode(path) == 0o600
    assert not list(tmp_path.glob(".cursor.tmp-*"))


def test_journal_cursor_validation_persistence_and_command_whitelist(tmp_path):
    follower = collector.JournalFollower(_fake_router(tmp_path), MagicMock())
    assert follower._read_cursor() is None

    for invalid in ("", "x" * 4097, "cursor\ncontrol\x01"):
        follower.cursor_path.write_text(invalid, encoding="utf-8")
        assert follower._read_cursor() is None

    follower._write_cursor("cursor-123")
    assert follower._read_cursor() == "cursor-123"
    assert _mode(follower.cursor_path) == 0o600
    assert not list(follower.cursor_path.parent.glob(".journal.cursor.tmp-*"))
    command = follower._command()
    assert command[:4] == ["journalctl", "--follow", "--output=json", "--no-pager"]
    assert command[-2:] == ["--after-cursor", "cursor-123"]
    assert [command[index + 1] for index, value in enumerate(command) if value == "--unit"] == list(
        collector.JOURNAL_UNITS
    )

    follower.cursor_path.unlink()
    assert follower._command()[-1] == "--since=now"
    follower._write_cursor("")
    follower._write_cursor("x" * 4097)
    follower._write_cursor("bad\x01cursor")
    assert not follower.cursor_path.exists()


def test_journal_read_cursor_handles_os_error(tmp_path):
    follower = collector.JournalFollower(_fake_router(tmp_path), MagicMock())
    with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
        assert follower._read_cursor() is None


def test_journal_timestamp_uses_microseconds_and_falls_back():
    assert collector.JournalFollower._timestamp(
        {"__REALTIME_TIMESTAMP": "1700000000123456"}
    ) == "2023-11-14T22:13:20.123Z"
    assert collector.JournalFollower._timestamp(
        {"_SOURCE_REALTIME_TIMESTAMP": "1700000000000000"}
    ) == "2023-11-14T22:13:20.000Z"
    with patch.object(collector, "_utc_now", return_value="fallback"):
        assert collector.JournalFollower._timestamp({}) == "fallback"
        assert collector.JournalFollower._timestamp({"__REALTIME_TIMESTAMP": "bad"}) == "fallback"


def test_journal_consume_ignores_invalid_json_and_non_whitelisted_units(tmp_path):
    router = _fake_router(tmp_path)
    follower = collector.JournalFollower(router, MagicMock())

    for line in ("{", "[]", json.dumps({"_SYSTEMD_UNIT": "ssh.service", "MESSAGE": "x"})):
        follower._consume(line)

    router.write.assert_not_called()


def test_journal_consume_routes_redacts_truncates_and_persists_cursor(tmp_path):
    router = _fake_router(tmp_path)
    follower = collector.JournalFollower(router, MagicMock())
    secret = "journal-secret-value"
    collector.configure_redaction({"MYSQL_PASSWORD": secret})
    long_message = f"password={secret} Bearer {secret} " + ("x" * 65_600)
    row = {
        "_SYSTEMD_UNIT": "mysql.service",
        "MESSAGE": long_message,
        "PRIORITY": "3",
        "SYSLOG_IDENTIFIER": "mysqld",
        "_PID": "321",
        "__CURSOR": "journal-cursor",
        "__REALTIME_TIMESTAMP": "1700000000123456",
    }

    follower._consume(json.dumps(row))

    payload = router.write.call_args.args[0]
    assert payload["@timestamp"] == "2023-11-14T22:13:20.123Z"
    assert payload["event"]["dataset"] == "numoj.infrastructure.mysql"
    assert payload["log"]["level"] == "error"
    assert payload["infrastructure"] == {
        "unit": "mysql.service",
        "identifier": "mysqld",
        "pid": "321",
        "priority": "3",
        "cursor": "journal-cursor",
        "message_bytes": len(long_message.encode()),
        "truncated": True,
    }
    assert secret not in payload["message"]
    assert "<redacted>" in payload["message"]
    assert "<truncated:" in payload["message"]
    follower._checkpoint_cursor(force=True)
    assert follower.cursor_path.read_text(encoding="utf-8") == "journal-cursor\n"


def test_journal_cursor_checkpoints_after_one_second(tmp_path):
    follower = collector.JournalFollower(_fake_router(tmp_path), MagicMock())
    follower._last_cursor_flush = 100.0
    timer = MagicMock()

    with (
        patch.object(collector.time, "monotonic", side_effect=[100.0, 101.0]),
        patch.object(collector.threading, "Timer", return_value=timer) as constructor,
    ):
        follower._checkpoint_cursor("cursor-one")
        assert not follower.cursor_path.exists()
        constructor.assert_called_once_with(1.0, follower._flush_cursor_timer)
        timer.start.assert_called_once_with()
        follower._flush_cursor_timer()

    assert follower.cursor_path.read_text(encoding="utf-8") == "cursor-one\n"
    assert follower._pending_cursor is None


def test_journal_cursor_checkpoints_latest_value_at_hundred_events(tmp_path):
    follower = collector.JournalFollower(_fake_router(tmp_path), MagicMock())
    follower._last_cursor_flush = 100.0
    timer = MagicMock()

    with (
        patch.object(collector.time, "monotonic", return_value=100.0),
        patch.object(collector.threading, "Timer", return_value=timer) as constructor,
    ):
        for index in range(1, collector._CURSOR_CHECKPOINT_EVENTS + 1):
            follower._checkpoint_cursor(f"cursor-{index}")

    constructor.assert_called_once()
    timer.cancel.assert_called_once_with()
    assert follower.cursor_path.read_text(encoding="utf-8") == "cursor-100\n"
    assert follower._pending_cursor_events == 0


def test_journal_consume_supports_unit_fallback_without_cursor(tmp_path):
    router = _fake_router(tmp_path)
    follower = collector.JournalFollower(router, MagicMock())
    follower._consume(
        json.dumps(
            {
                "UNIT": "redis-server.service",
                "MESSAGE": "ready",
                "PRIORITY": "99",
                "SYSLOG_PID": "9",
            }
        )
    )

    payload = router.write.call_args.args[0]
    assert payload["event"]["dataset"] == "numoj.infrastructure.redis"
    assert payload["log"]["level"] == "info"
    assert payload["infrastructure"]["pid"] == "9"
    assert not follower.cursor_path.exists()


def test_journal_status_and_collector_event_are_structured(tmp_path):
    router = _fake_router(tmp_path)
    follower = collector.JournalFollower(router, MagicMock())
    with patch.object(collector, "_utc_now", return_value="now"):
        follower._status("running", pid=42)
    assert json.loads(follower.status_path.read_text()) == {
        "pid": 42,
        "state": "running",
        "updated_at": "now",
    }
    assert _mode(follower.status_path) == 0o600

    follower._collector_event(
        action="journal.test",
        outcome="success",
        level="info",
        message="ok",
        reason="expected",
    )
    payload = router.write.call_args.args[0]
    assert payload["event"]["dataset"] == "numoj.infrastructure.collector"
    assert payload["service"]["component"] == "journal-collector"
    assert payload["collector"] == {"reason": "expected"}


def test_journal_run_reports_unavailable_without_starting_process(tmp_path):
    follower = collector.JournalFollower(_fake_router(tmp_path), MagicMock())
    follower._status = MagicMock()
    follower._collector_event = MagicMock()

    with patch.object(collector.shutil, "which", return_value=None):
        follower.run()

    follower._status.assert_called_once_with("unavailable", reason="journalctl_not_found")
    follower._collector_event.assert_called_once_with(
        action="journal.unavailable",
        outcome="failure",
        level="warning",
        message="未找到 journalctl，基础设施日志采集未启用",
        reason="journalctl_not_found",
    )


def test_journal_run_reports_start_error_and_honors_backoff_stop(tmp_path):
    stop_event = MagicMock()
    stop_event.is_set.return_value = False
    stop_event.wait.return_value = True
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    follower._status = MagicMock()
    follower._collector_event = MagicMock()

    with (
        patch.object(collector.shutil, "which", return_value="/usr/bin/journalctl"),
        patch.object(
            collector.subprocess,
            "run",
            return_value=MagicMock(returncode=0, stderr=""),
        ),
        patch.object(collector.subprocess, "Popen", side_effect=OSError("boom")),
    ):
        follower.run()

    assert follower._status.call_args_list[0] == call(
        "starting", units=list(collector.JOURNAL_UNITS)
    )
    assert call("error", reason="OSError", message="boom") in follower._status.call_args_list
    assert follower._status.call_args_list[-1] == call("stopped")
    assert follower._collector_event.call_args.kwargs["action"] == "journal.start_failed"
    stop_event.wait.assert_called_once_with(1)


def test_journal_run_reports_permission_exit_and_uses_restricted_environment(tmp_path):
    stop_event = MagicMock()
    stop_event.is_set.return_value = False
    stop_event.wait.return_value = True
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    follower._status = MagicMock()
    follower._collector_event = MagicMock()
    process = MagicMock(pid=88)
    process.stdout = io.StringIO("")
    process.stderr = io.StringIO("Permission denied: password=secret-value")
    process.wait.return_value = 1

    with (
        patch.object(collector.shutil, "which", return_value="/usr/bin/journalctl"),
        patch.object(
            collector.subprocess,
            "run",
            return_value=MagicMock(returncode=0, stderr=""),
        ),
        patch.object(collector.subprocess, "Popen", return_value=process) as popen,
    ):
        follower.run()

    kwargs = popen.call_args.kwargs
    assert kwargs["env"] == {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
    }
    assert kwargs["stdin"] is collector.subprocess.DEVNULL
    assert call(
        "error",
        reason="permission_denied",
        return_code=1,
        message="Permission denied: password=<redacted>",
    ) in follower._status.call_args_list
    exited = follower._collector_event.call_args.kwargs
    assert exited["action"] == "journal.exited"
    assert exited["reason"] == "permission_denied"
    assert "secret-value" not in exited["error_message"]
    assert follower._process is None
    stop_event.wait.assert_called_once_with(1)


def test_journal_run_flushes_pending_cursor_before_process_restart(tmp_path):
    stop_event = MagicMock()
    stop_event.is_set.return_value = False
    stop_event.wait.return_value = True
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    follower._status = MagicMock()
    follower._collector_event = MagicMock()
    row = json.dumps(
        {
            "_SYSTEMD_UNIT": "docker.service",
            "MESSAGE": "ready",
            "__CURSOR": "cursor-before-exit",
        }
    )
    process = MagicMock(pid=89)
    process.stdout = io.StringIO(f"{row}\n")
    process.stderr = io.StringIO("")
    process.wait.return_value = 1

    with (
        patch.object(collector.shutil, "which", return_value="/usr/bin/journalctl"),
        patch.object(
            collector.subprocess,
            "run",
            return_value=MagicMock(returncode=0, stderr=""),
        ),
        patch.object(collector.subprocess, "Popen", return_value=process),
    ):
        follower.run()

    assert follower.cursor_path.read_text(encoding="utf-8") == "cursor-before-exit\n"
    assert follower._cursor_timer is None


def test_journal_stderr_drain_keeps_only_bounded_tail():
    tail = [""]
    content = "prefix" + ("x" * 5_000) + "suffix"

    collector.JournalFollower._drain_stderr(io.StringIO(content), tail)

    assert len(tail[0]) == collector._JOURNAL_STDERR_TAIL_CHARS
    assert tail[0].endswith("suffix")
    assert "prefix" not in tail[0]


def test_journal_run_terminates_process_and_joins_stderr_after_stdout_error(tmp_path):
    class FailingStdout(io.StringIO):
        def __iter__(self):
            raise OSError("stdout failed")

    stop_event = MagicMock()
    stop_event.is_set.return_value = False
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    follower._status = MagicMock()
    process = MagicMock(pid=90)
    process.stdout = FailingStdout("")
    process.stderr = io.StringIO("diagnostic")
    process.poll.return_value = None
    process.wait.return_value = 1

    with (
        patch.object(collector.shutil, "which", return_value="/usr/bin/journalctl"),
        patch.object(
            collector.subprocess,
            "run",
            return_value=MagicMock(returncode=0, stderr=""),
        ),
        patch.object(collector.subprocess, "Popen", return_value=process),
        pytest.raises(OSError, match="stdout failed"),
    ):
        follower.run()

    process.terminate.assert_called_once_with()
    assert process.wait.called
    assert follower._process is None
    assert process.stdout.closed
    assert process.stderr.closed


def test_journal_run_surfaces_permission_hint_before_following(tmp_path):
    stop_event = MagicMock()
    stop_event.is_set.return_value = False
    stop_event.wait.return_value = True
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    follower._status = MagicMock()
    follower._collector_event = MagicMock()

    with (
        patch.object(collector.shutil, "which", return_value="/usr/bin/journalctl"),
        patch.object(
            collector.subprocess,
            "run",
            return_value=MagicMock(
                returncode=0,
                stderr=(
                    "Hint: You are currently not seeing messages from other users "
                    "and the system. Add this user to systemd-journal."
                ),
            ),
        ) as probe,
        patch.object(collector.subprocess, "Popen") as popen,
    ):
        follower.run()

    popen.assert_not_called()
    assert call(
        "error",
        reason="permission_denied",
        message=probe.return_value.stderr,
    ) in follower._status.call_args_list
    event = follower._collector_event.call_args.kwargs
    assert event["action"] == "journal.preflight_failed"
    assert event["reason"] == "permission_denied"
    stop_event.wait.assert_called_once_with(1)


def test_journal_stop_sets_event_and_terminates_running_process(tmp_path):
    stop_event = MagicMock()
    follower = collector.JournalFollower(_fake_router(tmp_path), stop_event)
    process = MagicMock()
    process.poll.return_value = None
    follower._process = process

    follower.stop()

    stop_event.set.assert_called_once_with()
    process.terminate.assert_called_once_with()

    process.terminate.side_effect = OSError("gone")
    follower.stop()
    assert process.terminate.call_count == 2


def test_collector_server_initializes_paths_and_clamps_router_limits(tmp_path):
    server = collector.CollectorServer(
        tmp_path / "logs", max_bytes=0, backups=0, collect_journal=0
    )
    try:
        assert server.router.max_bytes == 1
        assert server.router.backups == 1
        assert server.socket_path == server.router.root / "run" / collector.EVENT_SOCKET.name
        assert server.lock_path == server.router.root / "run" / "collector.lock"
        assert server.journal.stop_event is server.stop_event
        assert server.collect_journal is False
    finally:
        server.close()


def test_collector_defaults_are_shared_across_entry_points(tmp_path):
    router = collector.LogRouter(tmp_path / "router")
    server = collector.CollectorServer(tmp_path / "server", collect_journal=False)
    try:
        assert router.max_bytes == collector.DEFAULT_MAX_BYTES
        assert router.backups == collector.DEFAULT_BACKUPS
        assert server.router.max_bytes == collector.DEFAULT_MAX_BYTES
        assert server.router.backups == collector.DEFAULT_BACKUPS
    finally:
        router.close()
        server.close()


def test_collector_lock_is_exclusive_and_released(tmp_path):
    first = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    second = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    try:
        first._acquire_lock()
        assert first._lock_fd is not None
        assert _mode(first.lock_path) == 0o600
        with pytest.raises(RuntimeError, match="已有日志采集器"):
            second._acquire_lock()
        assert second._lock_fd is None

        first._release_lock()
        second._acquire_lock()
        assert second._lock_fd is not None
    finally:
        first.close()
        second.close()


def test_collector_acquire_lock_closes_descriptor_on_unexpected_error(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    real_close = os.close
    closed = []

    def record_close(descriptor):
        closed.append(descriptor)
        real_close(descriptor)

    with (
        patch.object(collector.fcntl, "flock", side_effect=OSError(errno.EIO, "io")),
        patch.object(collector.os, "close", side_effect=record_close),
        pytest.raises(OSError),
    ):
        server._acquire_lock()
    server.close()
    assert len(closed) == 1
    assert server._lock_fd is None


def test_collector_release_lock_closes_fd_even_when_unlock_fails(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    server._acquire_lock()
    descriptor = server._lock_fd
    with (
        patch.object(collector.fcntl, "flock", side_effect=OSError(errno.EIO, "io")),
        pytest.raises(OSError),
    ):
        server._release_lock()
    assert server._lock_fd is None
    with pytest.raises(OSError):
        os.fstat(descriptor)
    server.close()


def test_collector_bind_socket_configures_private_datagram_and_lock(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    fake_socket = MagicMock()

    def fake_bind(path):
        Path(path).touch()

    fake_socket.bind.side_effect = fake_bind
    with patch.object(collector.socket, "socket", return_value=fake_socket) as constructor:
        server._bind_socket()

    constructor.assert_called_once_with(socket.AF_UNIX, socket.SOCK_DGRAM)
    fake_socket.bind.assert_called_once_with(str(server.socket_path))
    fake_socket.settimeout.assert_called_once_with(1.0)
    assert server._socket is fake_socket
    assert server._lock_fd is not None
    assert _mode(server.socket_path) == 0o600
    server.close()
    fake_socket.close.assert_called_once_with()


def test_collector_bind_socket_rejects_existing_non_socket_and_releases_lock(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    server.socket_path.write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(RuntimeError, match="拒绝覆盖非 socket 路径"):
        server._bind_socket()

    assert server.socket_path.read_text(encoding="utf-8") == "do not overwrite"
    assert server._lock_fd is None
    server.close()


def test_collector_bind_socket_failure_closes_socket_and_releases_lock(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    fake_socket = MagicMock()
    fake_socket.bind.side_effect = OSError("bind denied")

    with (
        patch.object(collector.socket, "socket", return_value=fake_socket),
        pytest.raises(OSError, match="bind denied"),
    ):
        server._bind_socket()

    fake_socket.close.assert_called_once_with()
    assert server._lock_fd is None
    server.close()


def test_collector_serve_routes_packets_rejects_invalid_and_always_closes(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    fake_socket = MagicMock()

    def stop_and_fail():
        server.stop_event.set()
        raise OSError("closed")

    packets = iter((_packet(), b"bad"))

    def receive(_size):
        try:
            return next(packets)
        except StopIteration:
            return stop_and_fail()

    fake_socket.recv.side_effect = receive

    def fake_bind():
        server._socket = fake_socket

    server._bind_socket = MagicMock(side_effect=fake_bind)
    original_write = server.router.write
    with patch.object(server.router, "write", wraps=original_write) as write:
        server.serve()

    server._bind_socket.assert_called_once_with()
    assert server._socket is None
    assert any(
        invocation.args[0]["event"]["action"] == "collector.started"
        for invocation in write.call_args_list
    )
    assert any(
        invocation.args[0]["event"]["action"] == "event.rejected"
        and invocation.args[0]["collector"]["packet_bytes"] == 3
        for invocation in write.call_args_list
    )
    assert any(
        invocation.args[0]["event"]["action"] == "collector.stopped"
        for invocation in write.call_args_list
    )


def test_collector_serve_starts_and_joins_optional_journal_thread(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=True)
    fake_socket = MagicMock()
    server.stop_event.set()

    def fake_bind():
        server._socket = fake_socket

    server._bind_socket = MagicMock(side_effect=fake_bind)
    thread = MagicMock()
    with patch.object(collector.threading, "Thread", return_value=thread) as constructor:
        server.serve()

    constructor.assert_called_once_with(
        target=server._run_journal,
        name="journal-follower",
        daemon=True,
    )
    thread.start.assert_called_once_with()
    thread.join.assert_called_once_with(timeout=5)


def test_collector_journal_wrapper_marks_unexpected_thread_failure(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=True)
    server.journal.run = MagicMock(side_effect=OSError("private daemon output"))
    server.journal._status = MagicMock()
    server.router.write = MagicMock()

    server._run_journal()

    server.journal._status.assert_called_once_with(
        "error",
        reason="collector_exception",
        error_type="builtins.OSError",
    )
    event = server.router.write.call_args.args[0]
    assert event["event"]["action"] == "journal.collector_failed"
    assert event["collector"] == {"error_type": "builtins.OSError"}
    assert "private daemon output" not in json.dumps(event, ensure_ascii=False)
    server.close()


def test_collector_journal_wrapper_is_fail_open_when_reporting_also_fails(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=True)
    server.journal.run = MagicMock(side_effect=RuntimeError("thread failed"))
    server.journal._status = MagicMock(side_effect=OSError("disk full"))
    server.router.write = MagicMock(side_effect=OSError("disk full"))

    server._run_journal()

    server.journal._status.assert_called_once()
    server.router.write.assert_called_once()
    server.router.write.side_effect = None
    server.close()


def test_collector_close_releases_resources_even_if_stop_event_log_fails(tmp_path):
    server = collector.CollectorServer(tmp_path / "logs", collect_journal=False)
    server._journal_thread = MagicMock()
    server._socket = MagicMock()
    server.socket_path = MagicMock()
    server.socket_path.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFSOCK)
    server.router.write = MagicMock(side_effect=RuntimeError("log failure"))
    server.router.close = MagicMock()
    server._release_lock = MagicMock()

    with pytest.raises(RuntimeError, match="log failure"):
        server.close()

    assert server.stop_event.is_set()
    assert server._journal_thread is None
    server.socket_path.unlink.assert_called_once_with()
    server.router.close.assert_called_once_with()
    server._release_lock.assert_called_once_with()


def test_serve_collector_installs_stop_callbacks_and_restores_signals(tmp_path):
    server = MagicMock()
    callbacks = {}
    restored = []

    def fake_signal(signum, handler):
        if callable(handler):
            callbacks[signum] = handler
            return f"old-{signum}"
        restored.append((signum, handler))
        return None

    def run_serve():
        callbacks[signal.SIGTERM](signal.SIGTERM, None)

    server.serve.side_effect = run_serve
    with (
        patch.object(collector, "CollectorServer", return_value=server) as constructor,
        patch.object(collector.signal, "signal", side_effect=fake_signal),
    ):
        collector.serve_collector(
            root=tmp_path / "logs", max_bytes=123, backups=4, collect_journal=False
        )

    constructor.assert_called_once_with(
        tmp_path / "logs", max_bytes=123, backups=4, collect_journal=False
    )
    server.stop.assert_called_once_with()
    assert restored == [
        (signal.SIGINT, f"old-{signal.SIGINT}"),
        (signal.SIGTERM, f"old-{signal.SIGTERM}"),
    ]


def test_serve_collector_restores_signals_when_server_fails(tmp_path):
    server = MagicMock()
    server.serve.side_effect = RuntimeError("serve failed")
    handlers = {
        signal.SIGINT: object(),
        signal.SIGTERM: object(),
    }
    registrations = []

    def fake_signal(signum, handler):
        registrations.append((signum, handler))
        return handlers[signum]

    with (
        patch.object(collector, "CollectorServer", return_value=server),
        patch.object(collector.signal, "signal", side_effect=fake_signal),
        pytest.raises(RuntimeError, match="serve failed"),
    ):
        collector.serve_collector(root=tmp_path / "logs")

    assert registrations[-2:] == list(handlers.items())
