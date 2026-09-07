#!/usr/bin/env python3
"""为已有 NVIDIA 驱动准备原生 CDI；不安装 CUDA，不重启 Docker。"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from deploy.backup import apt

PACKAGE = "nvidia-container-toolkit-base"
VERSION = "1.20.0-1"
URL = f"https://nvidia.github.io/libnvidia-container/stable/deb/amd64/{PACKAGE}_{VERSION}_amd64.deb"
SHA256 = "28a6f2d41913897effe923b46234998f878fc21b32941ea9a2b878efa62b2267"
PACKAGE_BYTES = 5696308
CTK = "/usr/bin/nvidia-ctk"


def download(directory: Path, *, opener=urllib.request.urlopen) -> Path:
    destination = directory / f"{PACKAGE}_{VERSION}_amd64.deb"
    digest = hashlib.sha256()
    total = 0
    with opener(URL, timeout=30) as source, destination.open("xb") as target:
        if source.geturl() != URL:
            raise apt.ProvisioningError("NVIDIA CDI 包发生未允许的重定向")
        while chunk := source.read(64 * 1024):
            total += len(chunk)
            if total > PACKAGE_BYTES:
                raise apt.ProvisioningError("NVIDIA CDI 包体积异常")
            target.write(chunk)
            digest.update(chunk)
        target.flush()
        os.fsync(target.fileno())
    if total != PACKAGE_BYTES or digest.hexdigest() != SHA256:
        raise apt.ProvisioningError("NVIDIA CDI 包大小或 SHA-256 不匹配")
    return destination


def ensure(*, run=apt.run_command, opener=urllib.request.urlopen):
    smi = shutil.which("nvidia-smi")
    if smi is None:
        print("无 NVIDIA 驱动，跳过 CDI 准备")
        return
    devices = apt._checked(run, [smi, "--query-gpu=uuid", "--format=csv,noheader"], purpose="读取宿主 GPU UUID")
    uuids = devices.stdout.split()
    if not uuids or any(not re.fullmatch(r"GPU-[0-9a-fA-F-]{36}", value) for value in uuids):
        raise apt.ProvisioningError("宿主 GPU UUID 无效")
    apt.read_debian_identity(Path("/etc/os-release"))
    arch = apt._checked(run, [apt.DPKG, "--print-architecture"], purpose="读取宿主架构").stdout.strip()
    if arch != "amd64":
        raise apt.ProvisioningError("固定 CDI 包仅支持 amd64")
    installed = apt._installed_packages(run).get(PACKAGE)
    if installed != VERSION:
        # 现有不同版本应由维护者明确升级；避免部署时意外降级或替换。
        if installed is not None:
            raise apt.ProvisioningError(f"已有 {PACKAGE} {installed}，需要显式协调版本")
        apt._checked(run, [apt.SUDO, "-v"], purpose="验证 CDI 安装权限", interactive=True)
        with tempfile.TemporaryDirectory(prefix="numoj-nvidia-cdi-") as temporary:
            package = download(Path(temporary), opener=opener)
            spec = apt.BootstrapPackage(URL, SHA256, PACKAGE, VERSION, "amd64", "")
            apt._verify_bootstrap_metadata(package, spec, run)
            apt._run_guarded_install(run, target=str(package), target_package=PACKAGE,
                                     target_version=VERSION, mutable_existing=frozenset())
    if apt._installed_packages(run).get(PACKAGE) != VERSION:
        raise apt.ProvisioningError("CDI 组件安装后版本不匹配")
    apt._checked(run, [apt.SUDO, "-v"], purpose="验证 CDI 刷新权限", interactive=True)
    apt._checked(run, [apt.SUDO, "/usr/bin/systemctl", "enable", "--now", "nvidia-cdi-refresh.path"], purpose="启用 CDI 自动刷新")
    apt._checked(run, [apt.SUDO, "/usr/bin/systemctl", "restart", "nvidia-cdi-refresh.service"], purpose="刷新 GPU CDI 描述")
    listing = apt._checked(run, [CTK, "cdi", "list"], purpose="核验 GPU CDI 设备").stdout.split()
    if any(f"nvidia.com/gpu={uuid}" not in listing for uuid in uuids):
        raise apt.ProvisioningError("CDI 未包含每块宿主 GPU 的 UUID")
    print(f"NVIDIA CDI ready: {VERSION}, {len(uuids)} GPU(s)")


if __name__ == "__main__":
    try:
        ensure()
    except (OSError, apt.ProvisioningError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
