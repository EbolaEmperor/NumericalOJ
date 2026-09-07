"""使用只读宿主 Toolkit 构建共享 vLLM 环境，不重复安装 CUDA。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tarfile
import time
from urllib.request import urlopen

from install_gpu import CUDA_ROOT, GPU_ENV, HOST_PACKAGES

VLLM_COMMIT = "bcf2be96120005e9aea171927f85055a6a5c0cf6"


def fetch_source(record: dict, destination: Path) -> Path:
    """流式下载官方归档并校验；仅网络失败重试，哈希不符立即停止。"""
    destination.mkdir()
    archive = destination / "source.tar.gz"
    for attempt in range(5):
        try:
            digest = hashlib.sha256()
            with urlopen(record["url"], timeout=120) as response, archive.open("wb") as target:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    target.write(chunk)
            break
        except (OSError, TimeoutError):
            if attempt == 4:
                raise
            time.sleep(2 ** attempt)
    if digest.hexdigest() != record["sha256"]:
        raise RuntimeError(f"源码归档 SHA-256 不符：{record['url']}")
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    archive.unlink()
    extracted, = destination.iterdir()
    if not extracted.is_dir():
        raise RuntimeError("源码归档必须包含一个根目录")
    print(f"源码校验通过：{record['revision']}", flush=True)
    return extracted


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
            f"{CUDA_ROOT}/extras/CUPTI/lib64",
            *(f"{GPU_ENV}/lib/python3.12/site-packages/nvidia/{name}/lib"
              for name in ("cudnn", "nccl", "cusparselt", "nvshmem")),
        ]),
        "TORCH_CUDA_ARCH_LIST": "8.6",
        # 上游以 MAX_JOBS / NVCC_THREADS 设置 Ninja 并发；生产 40 线程保留余量。
        "MAX_JOBS": "32",
        "NVCC_THREADS": "2",
        "VLLM_TARGET_DEVICE": "cuda",
        "VLLM_USE_PRECOMPILED": "0",
        "SETUPTOOLS_SCM_PRETEND_VERSION": "0.18.0",
    })

    def run(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(args, check=True, env=env, cwd=cwd)

    root = Path(__file__).parent
    python = str(GPU_ENV / "bin/python")
    records = json.loads((root / "sources-gpu.json").read_text())
    with tempfile.TemporaryDirectory(prefix="vibehub-vllm-") as temporary:
        directory = Path(temporary)
        sources = {name: fetch_source(record, directory / name) for name, record in records.items()}
        source = sources["vllm"]
        env["VLLM_CUTLASS_SRC_DIR"] = str(sources["cutlass"])
        env["VLLM_FLASH_ATTN_SRC_DIR"] = str(sources["flash-attention"])
        env["TRITON_KERNELS_SRC_DIR"] = str(sources["triton-kernels"] / "python/triton_kernels/triton_kernels")
        env["FLASH_MLA_SRC_DIR"] = str(sources["flashmla"])
        env["QUTLASS_SRC_DIR"] = str(sources["qutlass"])
        # GitHub 归档不含子模块；沿用 FlashAttention 固定的 CUTLASS 提交。
        shutil.copytree(sources["flash-cutlass"], sources["flash-attention"] / "csrc/cutlass",
                        dirs_exist_ok=True)
        # 官方脚本移除 torch/vision/audio 固定约束，沿用已锁定的 cu126 环境。
        run(python, "use_existing_torch.py", "--prefix", cwd=source)
        run(python, "-m", "pip", "wheel", ".", "--verbose", "--no-deps", "--no-build-isolation",
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
