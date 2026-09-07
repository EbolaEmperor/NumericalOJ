"""使用只读宿主 Toolkit 构建共享 vLLM 环境，不重复安装 CUDA。"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

CUDA_ROOT = Path("/usr/local/cuda-12.6")
GPU_ENV = Path("/opt/vibehub-gpu")
VLLM_COMMIT = "bcf2be96120005e9aea171927f85055a6a5c0cf6"
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
    nvcc = subprocess.check_output([str(CUDA_ROOT / "bin/nvcc"), "--version"], text=True)
    if not re.search(r"release 12\.6,", nvcc):
        raise RuntimeError("构建必须挂载宿主 CUDA 12.6 Toolkit")
    manifest = json.loads((CUDA_ROOT / "version.json").read_text())
    env = dict(os.environ)
    env.update({
        "CUDA_HOME": str(CUDA_ROOT),
        "PATH": f"{GPU_ENV}/bin:{CUDA_ROOT}/bin:{env['PATH']}",
        "LD_LIBRARY_PATH": ":".join([
            f"{CUDA_ROOT}/lib64",
            *(f"{GPU_ENV}/lib/python3.12/site-packages/nvidia/{name}/lib"
              for name in ("cudnn", "nccl", "cusparselt", "nvshmem")),
        ]),
        "TORCH_CUDA_ARCH_LIST": "8.6",
        "MAX_JOBS": "8",
        "NVCC_THREADS": "2",
        "VLLM_TARGET_DEVICE": "cuda",
        "VLLM_USE_PRECOMPILED": "0",
        "SETUPTOOLS_SCM_PRETEND_VERSION": "0.18.0",
    })

    def run(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(args, check=True, env=env, cwd=cwd)

    root = Path(__file__).parent
    run("python", "-m", "venv", "--system-site-packages", str(GPU_ENV))
    python = str(GPU_ENV / "bin/python")
    lock = root / "requirements-gpu-install.lock"
    lock.write_text(installation_lock((root / "requirements-gpu.lock").read_text()))
    run(python, "-m", "pip", "install", "--no-cache-dir", "--no-deps",
        "--require-hashes", "-r", str(lock))
    with tempfile.TemporaryDirectory(prefix="vibehub-vllm-") as temporary:
        source = Path(temporary)
        run("git", "init", str(source))
        run("git", "remote", "add", "origin", "https://github.com/vllm-project/vllm.git", cwd=source)
        run("git", "fetch", "--depth=1", "origin", VLLM_COMMIT, cwd=source)
        run("git", "checkout", "--detach", "FETCH_HEAD", cwd=source)
        # 官方脚本移除 torch/vision/audio 固定约束，沿用已锁定的 cu126 环境。
        run(python, "use_existing_torch.py", "--prefix", cwd=source)
        run(python, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation",
            "--wheel-dir", str(source / "wheels"), cwd=source)
        wheel, = (source / "wheels").glob("vllm-*.whl")
        run(python, "-m", "pip", "install", "--no-deps", "--no-cache-dir", str(wheel))
    (root / "gpu-build.json").write_text(json.dumps({
        "vllm_commit": VLLM_COMMIT,
        "vllm_version": "0.18.0+cu126",
        "torch_version": "2.10.0+cu126",
        "cuda_root": str(CUDA_ROOT),
        "cuda_components": manifest,
        "cuda_architectures": ["8.6"],
        "host_provided_distributions": sorted(HOST_PACKAGES),
    }, ensure_ascii=False, indent=2) + "\n")


if __name__ == "__main__":
    main()
