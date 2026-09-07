"""安装共享 GPU 依赖；宿主已有的 CUDA 库不重复下载。"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

CUDA_ROOT = Path("/usr/local/cuda-12.6")
GPU_ENV = Path("/opt/vibehub-gpu")
# 这些发行包的原生库/工具由宿主 Toolkit 提供。保留完整解析图供审计，
# 安装时使用 --no-deps，防止 pip 再沿 PyTorch 依赖链下载另一份 CUDA。
HOST_PACKAGES = frozenset({
    "nvidia-cublas-cu12", "nvidia-cuda-cupti-cu12", "nvidia-cuda-nvdisasm",
    "nvidia-cuda-nvrtc-cu12", "nvidia-cuda-runtime-cu12", "nvidia-cufft-cu12",
    "nvidia-cufile-cu12", "nvidia-curand-cu12", "nvidia-cusolver-cu12",
    "nvidia-cusparse-cu12", "nvidia-nvjitlink-cu12", "nvidia-nvtx-cu12",
})


def installation_lock(text: str) -> str:
    """只剔除宿主提供的发行包及即将从源码编译的 vLLM，保留其余哈希。"""
    output = []
    include = True
    for line in text.splitlines(keepends=True):
        if re.match(r"^[A-Za-z0-9]", line):
            name = re.split(r"[= @\[]", line, maxsplit=1)[0].lower().replace("_", "-")
            include = name not in HOST_PACKAGES | {"vllm"}
        if include:
            output.append(line)
    return "".join(output)



def main() -> None:
    subprocess.run(["python", "-m", "venv", "--system-site-packages", str(GPU_ENV)], check=True)
    root = Path(__file__).parent
    lock = root / "requirements-gpu-install.lock"
    lock.write_text(installation_lock((root / "requirements-gpu.lock").read_text()))
    subprocess.run([str(GPU_ENV / "bin/python"), "-m", "pip", "install",
                    "--no-cache-dir", "--no-deps", "--require-hashes",
                    "--progress-bar", "off", "-r", str(lock)], check=True)


if __name__ == "__main__":
    main()
