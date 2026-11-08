#!/usr/bin/env python3
"""只在可证明支持的本机开发部署中延迟完整镜像解包。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.backup import container_client, development  # noqa: E402
from deploy.bootstrap import _load_config  # noqa: E402
from scripts.mysql_admin import settings_from_config  # noqa: E402


def _supported_engine(info):
    if not isinstance(info, dict):
        return False
    version = info.get("ServerVersion")
    # 仅启用已核对官方实现的稳定 29.x；不推测未来主版本或预发布版本。
    match = re.fullmatch(r"29\.(\d+)\.(\d+)(?:\+[A-Za-z0-9.-]+)?", version) if isinstance(version, str) else None
    if match is None or (29, int(match[1]), int(match[2])) < (29, 1, 3):
        return False
    status = info.get("DriverStatus")
    return isinstance(status, list) and ["driver-type", "io.containerd.snapshotter.v1"] in status


def enabled(root, builder, *, config=None, run=subprocess.run):
    """失败或能力未知时保留原导出方式；本函数不启动、构建或删除资源。"""
    if not isinstance(builder, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", builder):
        return False
    try:
        development.reserve_facts(root, settings_from_config(config if config is not None else _load_config(root)))
        docker = container_client._docker()
        environment = container_client.docker_environment()
        info = run([docker, "info", "--format", "{{json .}}"], capture_output=True, text=True,
                   check=False, timeout=30, env=environment)
        if info.returncode or not _supported_engine(json.loads(info.stdout)):
            return False
        details = run([docker, "buildx", "inspect", builder, "--format", "{{json .}}"],
                      capture_output=True, text=True, check=False, timeout=30, env=environment)
        if details.returncode:
            return False
        payload = json.loads(details.stdout)
        return isinstance(payload, dict) and payload.get("Driver") == "docker"
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--builder", default="default")
    args = parser.parse_args(argv)
    print(int(enabled(args.root.resolve(), args.builder)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
