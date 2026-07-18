#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""在 WSGI 服务启动前执行一次 Web 进程启动恢复任务。"""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oj import run_startup_jobs  # noqa: E402


def main():
    run_startup_jobs()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
