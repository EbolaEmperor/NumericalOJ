"""单写日志路由器，以及 MySQL/Redis/Docker journald 采集。"""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import fcntl
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
from typing import Any, Mapping
from uuid import uuid4

from .events import (
    EVENT_SOCKET,
    LOG_ROOT,
    MAX_DATAGRAM_BYTES,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    build_event_envelope,
    configure_redaction,
    redact_text,
    sanitize,
    validate_event_payload,
)


DATASET_PATHS = {
    "numoj.runtime.application": "runtime/application.jsonl",
    "numoj.task.lifecycle": "runtime/tasks.jsonl",
    "numoj.access.http": "access/http.jsonl",
    "numoj.audit.auth": "audit/auth.jsonl",
    "numoj.audit.submissions": "audit/submissions.jsonl",
    "numoj.infrastructure.mysql": "infrastructure/mysql.jsonl",
    "numoj.infrastructure.redis": "infrastructure/redis.jsonl",
    "numoj.infrastructure.docker": "infrastructure/docker.jsonl",
    "numoj.infrastructure.collector": "infrastructure/collector.jsonl",
}

DEFAULT_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_BACKUPS = 10

_CURSOR_CHECKPOINT_EVENTS = 100
_CURSOR_CHECKPOINT_SECONDS = 1.0
_JOURNAL_STDERR_TAIL_CHARS = 4_096

LOG_DIRECTORIES = (
    "access",
    "audit",
    "infrastructure",
    "run",
    "runtime",
    "services",
    "state",
    "supervisor",
)

JOURNAL_UNITS = {
    "mysql.service": "mysql",
    "mysqld.service": "mysql",
    "mariadb.service": "mysql",
    "redis.service": "redis",
    "redis-server.service": "redis",
    "docker.service": "docker",
}

_PRIORITY_LEVELS = {
    "0": "critical",
    "1": "critical",
    "2": "critical",
    "3": "error",
    "4": "warning",
    "5": "notice",
    "6": "info",
    "7": "debug",
}

_JOURNAL_PERMISSION_MARKERS = (
    "permission denied",
    "not seeing messages from other users",
    "systemd-journal",
)


def _assert_safe_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700)
        metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError(f"日志路径不是安全目录: {path}")
    path.chmod(0o700)


def init_log_tree(root: Path = LOG_ROOT) -> Path:
    """创建固定日志树；拒绝根目录或子目录符号链接。"""
    root = Path(root)
    if root.exists() or root.is_symlink():
        _assert_safe_directory(root)
    else:
        if root.parent.is_symlink():
            raise RuntimeError(f"日志根目录父路径不能是符号链接: {root.parent}")
        root.mkdir(mode=0o700)
    for relative in LOG_DIRECTORIES:
        _assert_safe_directory(root / relative)
    for entry in root.rglob("*"):
        if entry.is_symlink():
            raise RuntimeError(f"日志树不能包含符号链接: {entry}")
    return root


class SecureRotatingFileHandler(RotatingFileHandler):
    """使用 O_NOFOLLOW 和 0600 权限打开活动日志文件。"""

    def _open(self):
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.baseFilename, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise RuntimeError(f"日志目标不是普通文件: {self.baseFilename}")
            os.fchmod(descriptor, 0o600)
            return os.fdopen(
                descriptor,
                self.mode,
                encoding=self.encoding,
                errors=self.errors,
            )
        except Exception:
            os.close(descriptor)
            raise


class LogRouter:
    """验证并按 dataset 路由 JSONL；所有文件只由当前进程写入。"""

    def __init__(
        self,
        root: Path = LOG_ROOT,
        *,
        max_bytes=DEFAULT_MAX_BYTES,
        backups=DEFAULT_BACKUPS,
    ):
        configure_redaction()
        self.root = init_log_tree(root)
        self.max_bytes = max(1, int(max_bytes))
        self.backups = max(1, int(backups))
        self._handlers: dict[str, SecureRotatingFileHandler] = {}
        self._handlers_lock = threading.Lock()

    def _handler(self, relative_path: str) -> SecureRotatingFileHandler:
        with self._handlers_lock:
            handler = self._handlers.get(relative_path)
            if handler is not None:
                return handler
            target = self.root / relative_path
            _assert_safe_directory(target.parent)
            if target.is_symlink():
                raise RuntimeError(f"拒绝写入符号链接日志文件: {target}")
            handler = SecureRotatingFileHandler(
                target,
                maxBytes=self.max_bytes,
                backupCount=self.backups,
                encoding="utf-8",
                delay=True,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._handlers[relative_path] = handler
            return handler

    def write(self, payload: Mapping[str, Any]) -> str:
        normalized = sanitize(dict(payload))
        event = normalized.get("event") if isinstance(normalized, dict) else None
        dataset = event.get("dataset") if isinstance(event, dict) else None
        relative_path = DATASET_PATHS.get(
            str(dataset),
            DATASET_PATHS["numoj.runtime.application"],
        )
        line = json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        record = logging.LogRecord(
            "numoj.collector",
            logging.INFO,
            __file__,
            0,
            line,
            (),
            None,
        )
        self._handler(relative_path).handle(record)
        return relative_path

    def write_packet(self, packet: bytes) -> str:
        if len(packet) > MAX_DATAGRAM_BYTES:
            raise ValueError("日志 datagram 超出上限")
        try:
            payload = json.loads(packet.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("日志 datagram 不是有效 UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("日志事件必须是 JSON object")
        if not validate_event_payload(payload):
            schema = payload.get("schema")
            if not isinstance(schema, dict) or schema.get("name") != SCHEMA_NAME:
                raise ValueError("日志 schema 名称无效")
            raise ValueError("日志 schema 版本无效")
        return self.write(payload)

    def close(self) -> None:
        with self._handlers_lock:
            handlers = tuple(self._handlers.values())
            self._handlers.clear()
        for handler in handlers:
            handler.close()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _external_event(
    dataset: str,
    *,
    action: str,
    outcome: str,
    level: str,
    message: str,
    component: str,
    **fields: Any,
) -> dict[str, Any]:
    return build_event_envelope(
        dataset,
        action=action,
        outcome=outcome,
        level=level,
        logger_name="numoj.infrastructure.collector",
        component=component,
        message=message,
        timestamp=_utc_now(),
        event_id=uuid4().hex,
        environment=os.environ.get("NUMOJ_ENVIRONMENT", "production"),
        process={"pid": os.getpid(), "name": "log-collector"},
        **fields,
    )


def _atomic_text(path: Path, content: str) -> None:
    """以 0600 临时文件原子替换文本目标，并拒绝跟随符号链接。"""
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(
        temporary,
        flags,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    content = json.dumps(
        sanitize(dict(payload)),
        ensure_ascii=False,
        sort_keys=True,
    )
    _atomic_text(path, f"{content}\n")


class JournalFollower:
    """从 systemd journal 断点续采固定 daemon 白名单。"""

    def __init__(self, router: LogRouter, stop_event: threading.Event):
        self.router = router
        self.stop_event = stop_event
        self.cursor_path = router.root / "state" / "journal.cursor"
        self.status_path = router.root / "state" / "journal-status.json"
        self._process: subprocess.Popen[str] | None = None
        self._process_lock = threading.Lock()
        self._cursor_lock = threading.Lock()
        self._cursor_timer: threading.Timer | None = None
        self._pending_cursor: str | None = None
        self._pending_cursor_events = 0
        self._last_cursor_flush = time.monotonic()

    def _status(self, state: str, **fields: Any) -> None:
        payload = {"state": state, "updated_at": _utc_now(), **fields}
        _atomic_json(self.status_path, payload)

    def _collector_event(self, *, action: str, outcome: str, level: str, message: str, **fields):
        self.router.write(_external_event(
            "numoj.infrastructure.collector",
            action=action,
            outcome=outcome,
            level=level,
            message=message,
            component="journal-collector",
            collector=fields,
        ))

    def _read_cursor(self) -> str | None:
        try:
            cursor = self.cursor_path.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError):
            return None
        if not cursor or len(cursor) > 4096 or any(ord(char) < 32 for char in cursor):
            return None
        return cursor

    def _write_cursor(self, cursor: str) -> None:
        if not cursor or len(cursor) > 4096 or any(ord(char) < 32 for char in cursor):
            return
        _atomic_text(self.cursor_path, f"{cursor}\n")

    def _schedule_cursor_flush_locked(self, delay: float) -> None:
        if self._cursor_timer is not None:
            return
        timer = threading.Timer(max(0.0, delay), self._flush_cursor_timer)
        timer.daemon = True
        self._cursor_timer = timer
        timer.start()

    def _flush_cursor_locked(self, now: float) -> None:
        cursor = self._pending_cursor
        if not cursor:
            return
        self._write_cursor(cursor)
        timer, self._cursor_timer = self._cursor_timer, None
        if timer is not None and timer is not threading.current_thread():
            timer.cancel()
        self._pending_cursor = None
        self._pending_cursor_events = 0
        self._last_cursor_flush = now

    def _flush_cursor_timer(self) -> None:
        with self._cursor_lock:
            self._cursor_timer = None
            if not self._pending_cursor:
                return
            try:
                self._flush_cursor_locked(time.monotonic())
            except OSError:
                # 短暂 I/O 故障不应杀死定时线程；保留最新 cursor 并继续重试。
                if not self.stop_event.is_set():
                    self._schedule_cursor_flush_locked(_CURSOR_CHECKPOINT_SECONDS)

    def _checkpoint_cursor(self, cursor: str | None = None, *, force=False) -> None:
        if cursor and (
            len(cursor) > 4096 or any(ord(char) < 32 for char in cursor)
        ):
            return
        with self._cursor_lock:
            if cursor:
                self._pending_cursor = cursor
                self._pending_cursor_events += 1
            if not self._pending_cursor:
                return
            now = time.monotonic()
            elapsed = now - self._last_cursor_flush
            if (
                force
                or self._pending_cursor_events >= _CURSOR_CHECKPOINT_EVENTS
                or elapsed >= _CURSOR_CHECKPOINT_SECONDS
            ):
                self._flush_cursor_locked(now)
                return
            self._schedule_cursor_flush_locked(
                _CURSOR_CHECKPOINT_SECONDS - elapsed
            )

    def _command(self) -> list[str]:
        command = ["journalctl", "--follow", "--output=json", "--no-pager"]
        for unit in JOURNAL_UNITS:
            command.extend(("--unit", unit))
        cursor = self._read_cursor()
        if cursor:
            command.extend(("--after-cursor", cursor))
        else:
            command.append("--since=now")
        return command

    def _preflight(
        self,
        executable: str,
        environment: Mapping[str, str],
    ) -> tuple[bool, str | None, str | None]:
        """在进入长驻 follow 前暴露权限错误，避免采集器假装健康。"""
        command = [executable, "--output=json", "--no-pager", "--lines=1"]
        for unit in JOURNAL_UNITS:
            command.extend(("--unit", unit))
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=dict(environment),
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, type(exc).__name__, redact_text(str(exc), max_chars=4_096)
        stderr = redact_text(result.stderr or "", max_chars=4_096)
        normalized = stderr.lower()
        if any(marker in normalized for marker in _JOURNAL_PERMISSION_MARKERS):
            return False, "permission_denied", stderr
        if result.returncode != 0:
            return False, "probe_failed", stderr or f"exit={result.returncode}"
        return True, None, None

    @staticmethod
    def _timestamp(row: Mapping[str, Any]) -> str:
        raw = row.get("__REALTIME_TIMESTAMP") or row.get("_SOURCE_REALTIME_TIMESTAMP")
        try:
            value = int(str(raw)) / 1_000_000
        except (TypeError, ValueError):
            return _utc_now()
        return datetime.fromtimestamp(value, timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")

    def _consume(self, line: str) -> None:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(row, dict):
            return
        unit = str(row.get("_SYSTEMD_UNIT") or row.get("UNIT") or "")
        component = JOURNAL_UNITS.get(unit)
        if component is None:
            return
        original_message = str(row.get("MESSAGE", ""))
        message = redact_text(original_message, max_chars=65_536)
        original_bytes = len(original_message.encode("utf-8", errors="replace"))
        truncated = len(original_message) > 65_536
        payload = _external_event(
            f"numoj.infrastructure.{component}",
            action="daemon.message",
            outcome="unknown",
            level=_PRIORITY_LEVELS.get(str(row.get("PRIORITY")), "info"),
            message=message,
            component=component,
            infrastructure={
                "unit": unit,
                "identifier": row.get("SYSLOG_IDENTIFIER"),
                "pid": row.get("_PID") or row.get("SYSLOG_PID"),
                "priority": row.get("PRIORITY"),
                "cursor": row.get("__CURSOR"),
                "message_bytes": original_bytes,
                "truncated": truncated,
            },
        )
        payload["@timestamp"] = self._timestamp(row)
        self.router.write(payload)
        cursor = str(row.get("__CURSOR") or "")
        if cursor:
            self._checkpoint_cursor(cursor)

    @staticmethod
    def _drain_stderr(stream, tail: list[str]) -> None:
        """持续排空 stderr，仅在内存保留有界尾部，避免子进程管道写满。"""
        try:
            while chunk := stream.read(4_096):
                tail[0] = (tail[0] + chunk)[-_JOURNAL_STDERR_TAIL_CHARS:]
        except (OSError, ValueError):
            return

    @staticmethod
    def _wait_for_process(process: subprocess.Popen[str]) -> int:
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            return process.wait(timeout=5)

    def run(self) -> None:
        executable = shutil.which("journalctl")
        if not executable:
            self._status("unavailable", reason="journalctl_not_found")
            self._collector_event(
                action="journal.unavailable",
                outcome="failure",
                level="warning",
                message="未找到 journalctl，基础设施日志采集未启用",
                reason="journalctl_not_found",
            )
            return

        backoff = 1
        while not self.stop_event.is_set():
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
            }
            ready, reason, error_message = self._preflight(executable, environment)
            if not ready:
                self._status("error", reason=reason, message=error_message)
                self._collector_event(
                    action="journal.preflight_failed",
                    outcome="failure",
                    level="warning",
                    message="journalctl 预检失败，基础设施日志尚未采集",
                    reason=reason,
                    error_message=error_message,
                    retry_seconds=backoff,
                )
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, 60)
                continue

            command = self._command()
            command[0] = executable
            self._status("starting", units=list(JOURNAL_UNITS))
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=environment,
                    bufsize=1,
                )
            except OSError as exc:
                self._status("error", reason=type(exc).__name__, message=str(exc))
                self._collector_event(
                    action="journal.start_failed",
                    outcome="failure",
                    level="error",
                    message="journalctl 启动失败",
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, 60)
                continue

            with self._process_lock:
                self._process = process
            self._status("running", units=list(JOURNAL_UNITS), pid=process.pid)
            assert process.stdout is not None
            assert process.stderr is not None
            stderr_tail = [""]
            stderr_thread = threading.Thread(
                target=self._drain_stderr,
                args=(process.stderr, stderr_tail),
                name="journal-stderr",
                daemon=True,
            )
            stderr_started = False
            stopping = False
            try:
                stderr_thread.start()
                stderr_started = True
                for line in process.stdout:
                    if self.stop_event.is_set():
                        stopping = True
                        break
                    self._consume(line)
                stopping = stopping or self.stop_event.is_set()
                if stopping and process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                return_code = self._wait_for_process(process)
            finally:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                    try:
                        self._wait_for_process(process)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                with self._process_lock:
                    if self._process is process:
                        self._process = None
                if stderr_started:
                    stderr_thread.join(timeout=5)
                if stderr_started and stderr_thread.is_alive():
                    try:
                        process.stderr.close()
                    except (OSError, ValueError):
                        pass
                    stderr_thread.join(timeout=1)
                for stream in (process.stdout, process.stderr):
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
                self._checkpoint_cursor(force=True)

            if stopping:
                break
            stderr = redact_text(
                stderr_tail[0],
                max_chars=_JOURNAL_STDERR_TAIL_CHARS,
            )
            reason = "permission_denied" if "permission" in stderr.lower() else "exited"
            self._status(
                "error",
                reason=reason,
                return_code=return_code,
                message=stderr,
            )
            self._collector_event(
                action="journal.exited",
                outcome="failure",
                level="warning",
                message="journalctl 采集进程退出，将自动重试",
                reason=reason,
                return_code=return_code,
                error_message=stderr,
                retry_seconds=backoff,
            )
            if self.stop_event.wait(backoff):
                break
            backoff = min(backoff * 2, 60)

        self._checkpoint_cursor(force=True)
        self._status("stopped")

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self._checkpoint_cursor(force=True)
        except OSError:
            # 仍须终止 journalctl；run() 的 finally 会再次尝试 checkpoint。
            pass
        with self._process_lock:
            process = self._process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass


class CollectorServer:
    def __init__(
        self,
        root: Path = LOG_ROOT,
        *,
        max_bytes=DEFAULT_MAX_BYTES,
        backups=DEFAULT_BACKUPS,
        collect_journal=True,
    ):
        self.router = LogRouter(root, max_bytes=max_bytes, backups=backups)
        self.socket_path = self.router.root / "run" / EVENT_SOCKET.name
        self.lock_path = self.router.root / "run" / "collector.lock"
        self.collect_journal = bool(collect_journal)
        self.stop_event = threading.Event()
        self.journal = JournalFollower(self.router, self.stop_event)
        self._lock_fd: int | None = None
        self._socket: socket.socket | None = None
        self._journal_thread: threading.Thread | None = None

    def _run_journal(self) -> None:
        """隔离 journald follower 故障，避免线程静默死亡后状态仍显示 running。"""
        try:
            self.journal.run()
        except Exception as exc:
            error_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
            try:
                self.journal._status(
                    "error",
                    reason="collector_exception",
                    error_type=error_type,
                )
            except Exception:
                pass
            try:
                self.router.write(_external_event(
                    "numoj.infrastructure.collector",
                    action="journal.collector_failed",
                    outcome="failure",
                    level="error",
                    message="journald 采集线程异常退出",
                    component="journal-collector",
                    collector={"error_type": error_type},
                ))
            except Exception:
                pass

    def _acquire_lock(self) -> None:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(descriptor)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise RuntimeError("已有日志采集器正在运行") from exc
            raise
        self._lock_fd = descriptor

    def _bind_socket(self) -> None:
        self._acquire_lock()
        server = None
        try:
            try:
                metadata = self.socket_path.lstat()
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISSOCK(metadata.st_mode):
                    raise RuntimeError(f"拒绝覆盖非 socket 路径: {self.socket_path}")
                self.socket_path.unlink()
            server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            previous_umask = os.umask(0o177)
            try:
                server.bind(str(self.socket_path))
            finally:
                os.umask(previous_umask)
            self.socket_path.chmod(0o600)
            server.settimeout(1.0)
            self._socket = server
        except Exception:
            if server is not None:
                server.close()
            self._release_lock()
            raise

    def _release_lock(self) -> None:
        if self._lock_fd is None:
            return
        descriptor, self._lock_fd = self._lock_fd, None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def stop(self) -> None:
        self.stop_event.set()
        self.journal.stop()

    def serve(self) -> None:
        self._bind_socket()
        try:
            self.router.write(_external_event(
                "numoj.infrastructure.collector",
                action="collector.started",
                outcome="success",
                level="info",
                message="统一日志采集器已启动",
                component="log-collector",
                collector={"journal_enabled": self.collect_journal},
            ))
            if self.collect_journal:
                self._journal_thread = threading.Thread(
                    target=self._run_journal,
                    name="journal-follower",
                    daemon=True,
                )
                self._journal_thread.start()
            assert self._socket is not None
            while not self.stop_event.is_set():
                try:
                    packet = self._socket.recv(MAX_DATAGRAM_BYTES + 1)
                except socket.timeout:
                    continue
                except OSError:
                    if self.stop_event.is_set():
                        break
                    raise
                try:
                    self.router.write_packet(packet)
                except ValueError as exc:
                    self.router.write(_external_event(
                        "numoj.infrastructure.collector",
                        action="event.rejected",
                        outcome="failure",
                        level="warning",
                        message="统一日志采集器拒绝了无效事件",
                        component="log-collector",
                        collector={"reason": str(exc), "packet_bytes": len(packet)},
                    ))
        finally:
            self.close()

    def close(self) -> None:
        self.stop()
        if self._journal_thread is not None:
            self._journal_thread.join(timeout=5)
            self._journal_thread = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        try:
            metadata = self.socket_path.lstat()
            if stat.S_ISSOCK(metadata.st_mode):
                self.socket_path.unlink()
        except FileNotFoundError:
            pass
        try:
            self.router.write(_external_event(
                "numoj.infrastructure.collector",
                action="collector.stopped",
                outcome="success",
                level="info",
                message="统一日志采集器已停止",
                component="log-collector",
            ))
        finally:
            self.router.close()
            self._release_lock()


def serve_collector(
    *,
    root: Path = LOG_ROOT,
    max_bytes=DEFAULT_MAX_BYTES,
    backups=DEFAULT_BACKUPS,
    collect_journal=True,
) -> None:
    server = CollectorServer(
        root,
        max_bytes=max_bytes,
        backups=backups,
        collect_journal=collect_journal,
    )

    def _stop(_signum, _frame):
        server.stop()

    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, _stop)
    try:
        server.serve()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
