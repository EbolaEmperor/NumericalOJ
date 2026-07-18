#!/usr/bin/env python3
"""精确识别 NumericalOJ 的 Supervisor 与应用进程。

部署脚本不能依赖模糊的 ``ps | grep``。本模块只使用 Linux ``/proc`` 中的
NUL 分隔 argv 与 cwd，并且只接受生产目录下两种已知 Supervisor 配置路径。
它只负责识别，不发送信号，因此可以独立单测。
"""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Iterable


KINDS = {"web", "celery"}
_CELERY_POOL_TITLE = re.compile(
    r"(?:\[celeryd: (?:judge|agent|agent_judge)@"
    r"[A-Za-z0-9][A-Za-z0-9._-]*:ForkPoolWorker-[0-9]+\]"
    r"|celeryd: (?:judge|agent|agent_judge)@"
    r"[A-Za-z0-9][A-Za-z0-9._-]*:ForkPoolWorker-[0-9]+)"
)


def _read_cmdline(proc_root: Path, pid: int) -> list[str] | None:
    try:
        raw = (proc_root / str(pid) / "cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None
    if not raw:
        return None
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def _read_cwd(proc_root: Path, pid: int) -> str | None:
    try:
        return os.path.realpath(os.readlink(proc_root / str(pid) / "cwd"))
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def _configuration_arg(argv: list[str]) -> str | None:
    for index, argument in enumerate(argv):
        if argument in {"-c", "--configuration"}:
            return argv[index + 1] if index + 1 < len(argv) else None
        if argument.startswith("--configuration="):
            return argument.split("=", 1)[1]
    return None


def _normalized_config(config: str, cwd: str) -> str:
    path = Path(config)
    if not path.is_absolute():
        path = Path(cwd) / path
    return os.path.realpath(path)


def _is_python(argument: str) -> bool:
    return Path(argument).name in {"python", "python3", "python3.12"}


def _has_entrypoint(argv: list[str], executable: str, module: str | None = None) -> bool:
    """只接受真实 argv 入口，不在任意参数位置搜索看起来相似的字符串。"""
    if not argv:
        return False
    if Path(argv[0]).name == executable:
        return True
    if _is_python(argv[0]) and len(argv) >= 2 and Path(argv[1]).name == executable:
        return True
    return bool(
        module
        and _is_python(argv[0])
        and len(argv) >= 3
        and argv[1] == "-m"
        and argv[2] == module
    )


def is_supervisor_process(
    pid: int,
    target: str,
    kind: str,
    *,
    proc_root: Path = Path("/proc"),
) -> bool:
    if kind not in KINDS:
        raise ValueError(f"unknown supervisor kind: {kind}")
    target = os.path.realpath(target)
    cwd = _read_cwd(proc_root, pid)
    argv = _read_cmdline(proc_root, pid)
    if cwd != target or not argv:
        return False
    if not _has_entrypoint(argv, "supervisord", "supervisor.supervisord"):
        return False
    config = _configuration_arg(argv)
    if not config:
        return False
    allowed = {
        os.path.realpath(Path(target) / f"{kind}.conf"),
        os.path.realpath(Path(target) / "deploy" / "supervisor" / f"{kind}.conf"),
    }
    return _normalized_config(config, cwd) in allowed


def is_app_process(
    pid: int,
    target: str,
    kind: str,
    *,
    proc_root: Path = Path("/proc"),
) -> bool:
    if kind not in KINDS:
        raise ValueError(f"unknown app kind: {kind}")
    target = os.path.realpath(target)
    cwd = _read_cwd(proc_root, pid)
    argv = _read_cmdline(proc_root, pid)
    if cwd != target or not argv:
        return False

    if kind == "web":
        return "oj:app" in argv and _has_entrypoint(argv, "gunicorn", "gunicorn")

    has_app = any(
        argument == "oj.celery"
        or argument == "-Aoj.celery"
        or argument == "--app=oj.celery"
        for argument in argv
    )
    if not has_app:
        for index, argument in enumerate(argv[:-1]):
            if argument in {"-A", "--app"} and argv[index + 1] == "oj.celery":
                has_app = True
                break
    celery_entry = _has_entrypoint(argv, "celery", "celery")
    if celery_entry:
        return has_app and "worker" in argv

    # 安装 setproctitle 时，Celery pool 子进程会把 argv[0] 改为这一固定形态。
    return _CELERY_POOL_TITLE.fullmatch(argv[0]) is not None


def is_celery_queue_process(
    pid: int,
    target: str,
    queue: str,
    *,
    proc_root: Path = Path("/proc"),
) -> bool:
    if not is_app_process(pid, target, "celery", proc_root=proc_root):
        return False
    argv = _read_cmdline(proc_root, pid) or []
    for index, argument in enumerate(argv):
        if argument in {"-Q", "--queues"} and index + 1 < len(argv):
            return queue in argv[index + 1].split(",")
        if argument.startswith("--queues="):
            return queue in argument.split("=", 1)[1].split(",")
    return False


def iter_pids(proc_root: Path = Path("/proc")) -> Iterable[int]:
    if not proc_root.is_dir():
        raise RuntimeError(f"process filesystem is unavailable: {proc_root}")
    try:
        return sorted(int(entry.name) for entry in proc_root.iterdir() if entry.name.isdigit())
    except OSError as exc:
        raise RuntimeError(f"cannot enumerate process filesystem: {proc_root}") from exc


def matching_pids(
    target: str,
    kind: str,
    process_type: str,
    *,
    proc_root: Path = Path("/proc"),
    queue: str | None = None,
) -> list[int]:
    if queue is not None:
        if process_type != "app" or kind != "celery":
            raise ValueError("queue filter only applies to celery app processes")
        predicate = lambda pid, target, kind, proc_root: is_celery_queue_process(  # noqa: E731
            pid, target, queue, proc_root=proc_root
        )
    else:
        predicate = is_supervisor_process if process_type == "supervisor" else is_app_process
    return [
        pid
        for pid in iter_pids(proc_root)
        if predicate(pid, target, kind, proc_root=proc_root)
    ]


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("process_type", choices=("supervisor", "app"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--kind", required=True, choices=sorted(KINDS))
    parser.add_argument("--pid", type=int)
    parser.add_argument("--queue", choices=("celery", "agent", "judge"))
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    if args.queue is not None and (args.process_type != "app" or args.kind != "celery"):
        raise SystemExit("--queue only applies to celery app processes")
    if args.pid is not None:
        if args.queue is not None:
            return 0 if is_celery_queue_process(args.pid, args.target, args.queue) else 1
        predicate = is_supervisor_process if args.process_type == "supervisor" else is_app_process
        return 0 if predicate(args.pid, args.target, args.kind) else 1
    for pid in matching_pids(
        args.target, args.kind, args.process_type, queue=args.queue
    ):
        print(pid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
