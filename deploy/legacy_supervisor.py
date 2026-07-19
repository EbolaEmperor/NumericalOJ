#!/usr/bin/env python3
"""Safely stop the socket-less Supervisor processes used before in-place deploys."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import sys
import time


LEGACY_CONFIGS = {"web": "web.conf", "celery": "celery.conf"}


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    uid: int
    cwd: Path
    argv: tuple[str, ...]


def _read_process(pid: int) -> ProcessInfo | None:
    process_dir = Path("/proc") / str(pid)
    try:
        status = (process_dir / "status").read_text(
            encoding="utf-8", errors="replace"
        )
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        uid = int(uid_line.split()[1])
        cwd = Path(os.readlink(process_dir / "cwd"))
        raw_argv = (process_dir / "cmdline").read_bytes().rstrip(b"\0")
    except (OSError, StopIteration, ValueError):
        return None
    argv = tuple(
        os.fsdecode(argument) for argument in raw_argv.split(b"\0") if argument
    )
    return ProcessInfo(pid=pid, uid=uid, cwd=cwd, argv=argv)


def _supervisord_arguments(argv: tuple[str, ...]) -> tuple[str, ...] | None:
    if not argv:
        return None
    entry_index = 0
    entry_name = Path(argv[0]).name
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", entry_name):
        if len(argv) < 2 or Path(argv[1]).name != "supervisord":
            return None
        entry_index = 1
    elif entry_name != "supervisord":
        return None
    return argv[entry_index + 1 :]


def _configuration_argument(arguments: tuple[str, ...]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument in {"-c", "--configuration"}:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith("--configuration="):
            return argument.partition("=")[2]
    return None


def legacy_service(
    process: ProcessInfo,
    root: Path,
    *,
    expected_uid: int,
) -> str | None:
    """Return the legacy service name only for an exact process identity match."""
    if process.pid <= 1 or process.uid != expected_uid:
        return None
    root = root.resolve()
    if process.cwd.resolve() != root:
        return None
    arguments = _supervisord_arguments(process.argv)
    if arguments is None:
        return None
    configuration = _configuration_argument(arguments)
    if not configuration:
        return None
    configuration_path = Path(configuration)
    if not configuration_path.is_absolute():
        configuration_path = process.cwd / configuration_path
    configuration_path = configuration_path.resolve()
    for service, filename in LEGACY_CONFIGS.items():
        if configuration_path == (root / filename).resolve():
            return service
    return None


def discover(root: Path, service: str, *, expected_uid: int | None = None) -> list[int]:
    if service not in LEGACY_CONFIGS:
        raise ValueError(f"unknown legacy service: {service}")
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        raise RuntimeError("legacy Supervisor discovery requires Linux /proc")
    uid = os.getuid() if expected_uid is None else expected_uid
    matches = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        process = _read_process(int(entry.name))
        if process and legacy_service(process, root, expected_uid=uid) == service:
            matches.append(process.pid)
    return sorted(matches)


def stop_expected(
    root: Path,
    service: str,
    expected_pids: set[int],
    *,
    timeout: int,
) -> None:
    if not expected_pids or any(pid <= 1 for pid in expected_pids):
        raise ValueError("expected legacy Supervisor PIDs must be positive")
    uid = os.getuid()
    discovered = set(discover(root, service, expected_uid=uid))
    unexpected = discovered - expected_pids
    if unexpected:
        raise RuntimeError(
            f"new legacy {service} Supervisor appeared: {sorted(unexpected)}"
        )

    signalled = set()
    for pid in sorted(expected_pids):
        process = _read_process(pid)
        if process is None:
            continue
        if legacy_service(process, root, expected_uid=uid) != service:
            raise RuntimeError(f"legacy Supervisor PID {pid} changed identity")
        os.kill(pid, signal.SIGTERM)
        signalled.add(pid)

    deadline = time.monotonic() + timeout
    while signalled:
        for pid in tuple(signalled):
            process = _read_process(pid)
            if (
                process is None
                or legacy_service(process, root, expected_uid=uid) != service
            ):
                signalled.remove(pid)
        if not signalled:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"legacy {service} Supervisor did not stop: {sorted(signalled)}"
            )
        time.sleep(0.2)


def _parse_pids(value: str) -> set[int]:
    try:
        return {int(item) for item in value.split()}
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "PIDs must be space-separated integers"
        ) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    subparsers = parser.add_subparsers(dest="action", required=True)

    list_parser = subparsers.add_parser("list")
    list_parser.add_argument("--service", choices=LEGACY_CONFIGS, required=True)

    stop_parser = subparsers.add_parser("stop")
    stop_parser.add_argument("--service", choices=LEGACY_CONFIGS, required=True)
    stop_parser.add_argument("--expected-pids", type=_parse_pids, required=True)
    stop_parser.add_argument("--timeout", type=int, required=True)

    args = parser.parse_args(argv)
    try:
        if args.action == "list":
            print(" ".join(str(pid) for pid in discover(args.root, args.service)))
        else:
            if args.timeout <= 0:
                raise ValueError("timeout must be positive")
            stop_expected(
                args.root,
                args.service,
                args.expected_pids,
                timeout=args.timeout,
            )
    except Exception as exc:
        print(f"[legacy_supervisor] failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
