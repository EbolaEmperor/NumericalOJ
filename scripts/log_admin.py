#!/usr/bin/env python3
"""NumericalOJ 日志初始化、采集、检索与健康检查工具。"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.oj_modules.observability.collector import (  # noqa: E402
    DATASET_PATHS,
    DEFAULT_BACKUPS,
    DEFAULT_MAX_BYTES,
    LOG_DIRECTORIES,
    init_log_tree,
    serve_collector,
)
from backend.oj_modules.observability.events import (  # noqa: E402
    LOG_ROOT,
    SCHEMA_NAME,
    SCHEMA_VERSION,
    validate_event_payload,
)


def _dataset_path(dataset: str) -> Path:
    normalized = str(dataset).strip()
    if not normalized.startswith("numoj."):
        normalized = f"numoj.{normalized}"
    try:
        relative = DATASET_PATHS[normalized]
    except KeyError as exc:
        choices = ", ".join(sorted(DATASET_PATHS))
        raise ValueError(f"未知 dataset {dataset!r}；可选值：{choices}") from exc
    return LOG_ROOT / relative


def _rotated_files(active: Path) -> list[Path]:
    candidates = []
    for candidate in active.parent.glob(f"{active.name}.*"):
        try:
            index = int(candidate.name.removeprefix(f"{active.name}."))
        except ValueError:
            continue
        if candidate.is_file() and not candidate.is_symlink():
            candidates.append((index, candidate))
    candidates.sort(reverse=True)
    return [path for _, path in candidates] + (
        [active] if active.is_file() and not active.is_symlink() else []
    )


def _iter_lines(dataset: str) -> Iterable[str]:
    for path in _rotated_files(_dataset_path(dataset)):
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            yield from stream


def _last_lines(path: Path, limit: int, *, block_size: int = 64 * 1024) -> list[str]:
    """从文件尾部按块读取至多 limit 行，避免为 tail 顺序扫描整个文件。"""
    with path.open("rb") as stream:
        stream.seek(0, os.SEEK_END)
        position = stream.tell()
        chunks: list[bytes] = []
        newline_count = 0
        while position > 0 and newline_count <= limit:
            size = min(block_size, position)
            position -= size
            stream.seek(position)
            chunk = stream.read(size)
            chunks.append(chunk)
            newline_count += chunk.count(b"\n")

    data = b"".join(reversed(chunks))
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if position > 0 and lines:
        # 当前缓冲区从一行中间开始；丢弃不完整的首行。
        lines.pop(0)
    return [line.decode("utf-8", errors="replace") for line in lines[-limit:]]


def _nested(payload: Any, *path: str) -> Any:
    value = payload
    for part in path:
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def command_init(_args) -> int:
    root = init_log_tree(LOG_ROOT)
    print(root)
    return 0


def command_serve(args) -> int:
    serve_collector(
        root=LOG_ROOT,
        max_bytes=args.max_bytes,
        backups=args.backups,
        collect_journal=not args.no_journal,
    )
    return 0


def command_list(_args) -> int:
    for dataset, relative in sorted(DATASET_PATHS.items()):
        print(f"{dataset}\t{relative}")
    return 0


def command_status(args) -> int:
    init_log_tree(LOG_ROOT)
    rows = []
    for dataset, relative in sorted(DATASET_PATHS.items()):
        path = LOG_ROOT / relative
        metadata = path.stat() if path.is_file() and not path.is_symlink() else None
        rows.append({
            "dataset": dataset,
            "path": str(path),
            "exists": metadata is not None,
            "bytes": metadata.st_size if metadata else 0,
            "updated_at": (
                datetime.fromtimestamp(metadata.st_mtime, timezone.utc).isoformat()
                if metadata
                else None
            ),
            "rotated_files": max(0, len(_rotated_files(path)) - (1 if metadata else 0)),
        })
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for row in rows:
            print(
                f"{row['dataset']:<36} {row['bytes']:>12} bytes  "
                f"rotated={row['rotated_files']:<2} {row['path']}"
            )
    return 0


def command_tail(args) -> int:
    remaining = args.lines
    groups: list[list[str]] = []
    active = _dataset_path(args.dataset)
    for path in reversed(_rotated_files(active)):
        lines = _last_lines(path, remaining)
        if lines:
            groups.append(lines)
            remaining -= len(lines)
        if remaining <= 0:
            break
    for lines in reversed(groups):
        for line in lines:
            print(line)
    return 0


def _matches(payload: dict[str, Any], field: str, expected: str) -> bool:
    candidates = {
        "request_id": (
            _nested(payload, "request", "id"),
            _nested(payload, "trace", "id"),
            _nested(payload, "labels", "request_id"),
        ),
        "submission_id": (
            _nested(payload, "submission", "id"),
            _nested(payload, "labels", "submission_id"),
        ),
        "task_id": (
            _nested(payload, "task", "id"),
            _nested(payload, "labels", "task_id"),
        ),
    }[field]
    return any(value is not None and str(value) == expected for value in candidates)


def command_find(args) -> int:
    filters = [
        (name, str(value))
        for name, value in (
            ("request_id", args.request_id),
            ("submission_id", args.submission_id),
            ("task_id", args.task_id),
        )
        if value is not None
    ]
    if len(filters) != 1:
        raise ValueError("find 必须且只能指定一个 ID 条件")
    field, expected = filters[0]
    datasets = [args.dataset] if args.dataset else sorted(DATASET_PATHS)
    found = 0
    for dataset in datasets:
        for line in _iter_lines(dataset):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and _matches(payload, field, expected):
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
                found += 1
                if found >= args.limit:
                    return 0
    return 0 if found else 1


def command_validate(args) -> int:
    datasets = [args.dataset] if args.dataset else sorted(DATASET_PATHS)
    checked = invalid = 0
    for dataset in datasets:
        for path in _rotated_files(_dataset_path(dataset)):
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                for line_number, line in enumerate(stream, 1):
                    checked += 1
                    try:
                        payload = json.loads(line)
                        valid = validate_event_payload(payload)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        valid = False
                    if not valid:
                        invalid += 1
                        print(f"INVALID {path}:{line_number}", file=sys.stderr)
                        if invalid >= args.max_errors:
                            print(
                                json.dumps({"checked": checked, "invalid": invalid}),
                                file=sys.stderr,
                            )
                            return 1
    print(json.dumps({"checked": checked, "invalid": invalid}))
    return 1 if invalid else 0


def _socket_listener_ready(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        probe.settimeout(0.2)
        probe.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _collector_lock_held(path: Path) -> bool:
    """仅当另一个进程持有安全的 collector.lock 时返回 True。"""
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except (FileNotFoundError, OSError):
        return False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return False
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            return exc.errno in (errno.EACCES, errno.EAGAIN)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def command_doctor(_args) -> int:
    root = init_log_tree(LOG_ROOT)
    issues = []
    root_mode = stat.S_IMODE(root.stat().st_mode)
    if root_mode & 0o077:
        issues.append(f"日志根目录权限过宽: {root_mode:04o}")
    for relative in LOG_DIRECTORIES:
        path = root / relative
        if path.is_symlink() or not path.is_dir():
            issues.append(f"日志子目录不安全: {path}")
    socket_path = root / "run" / "events.sock"
    lock_held = _collector_lock_held(root / "run" / "collector.lock")
    socket_ready = False
    try:
        socket_metadata = socket_path.lstat()
        is_socket = stat.S_ISSOCK(socket_metadata.st_mode)
        listener_ready = is_socket and _socket_listener_ready(socket_path)
        socket_ready = listener_ready and lock_held
        if is_socket and stat.S_IMODE(socket_metadata.st_mode) & 0o077:
            issues.append("采集器 socket 权限过宽")
        if is_socket and not listener_ready:
            issues.append("采集器 socket 不可连接，可能是异常退出遗留")
    except FileNotFoundError:
        pass
    if not lock_held:
        issues.append("采集器锁未被持有，采集器可能未运行")
    journal_status = root / "state" / "journal-status.json"
    status_payload = None
    try:
        status_payload = json.loads(journal_status.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        issues.append("尚无有效的 journald 采集状态")
    if isinstance(status_payload, dict) and status_payload.get("state") != "running":
        issues.append(
            f"journald 采集未运行: {status_payload.get('state') or 'unknown'}"
        )
    for path in root.rglob("*"):
        if path.is_symlink():
            issues.append(f"日志树包含符号链接: {path}")
            continue
        if path.is_file() and stat.S_IMODE(path.stat().st_mode) & 0o077:
            issues.append(f"日志文件权限过宽: {path}")
    report = {
        "log_root": str(root),
        "collector_lock_held": lock_held,
        "socket_ready": socket_ready,
        "journal": status_payload,
        "issues": issues,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if issues or not socket_ready else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="创建安全日志目录树")
    init_parser.set_defaults(handler=command_init)

    serve_parser = commands.add_parser("serve", help="运行统一日志采集器")
    serve_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    serve_parser.add_argument("--backups", type=int, default=DEFAULT_BACKUPS)
    serve_parser.add_argument("--no-journal", action="store_true")
    serve_parser.set_defaults(handler=command_serve)

    list_parser = commands.add_parser("list", help="列出 dataset 与落盘路径")
    list_parser.set_defaults(handler=command_list)

    status_parser = commands.add_parser("status", help="显示各类日志大小与更新时间")
    status_parser.add_argument("--json", action="store_true")
    status_parser.set_defaults(handler=command_status)

    tail_parser = commands.add_parser("tail", help="查看一个 dataset 的最近事件")
    tail_parser.add_argument("dataset")
    tail_parser.add_argument("--lines", type=int, default=100)
    tail_parser.set_defaults(handler=command_tail)

    find_parser = commands.add_parser("find", help="按关联 ID 跨日志检索")
    find_parser.add_argument("--request-id")
    find_parser.add_argument("--submission-id")
    find_parser.add_argument("--task-id")
    find_parser.add_argument("--dataset")
    find_parser.add_argument("--limit", type=int, default=100)
    find_parser.set_defaults(handler=command_find)

    validate_parser = commands.add_parser("validate", help="验证 JSONL 与 schema")
    validate_parser.add_argument("--dataset")
    validate_parser.add_argument("--max-errors", type=int, default=20)
    validate_parser.set_defaults(handler=command_validate)

    doctor_parser = commands.add_parser("doctor", help="检查目录、socket 与 journald 状态")
    doctor_parser.set_defaults(handler=command_doctor)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "lines", 1) <= 0 or getattr(args, "limit", 1) <= 0:
        parser.error("数量参数必须为正整数")
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"日志工具失败: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
