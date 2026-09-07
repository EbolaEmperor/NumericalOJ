"""共享 GPU 镜像不能经传递依赖重新下载 CUDA 或预编译 vLLM。"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "vibehub_build_gpu", ROOT / "docker/vibehub-runtime/build_gpu.py",
)
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def test_installation_lock_preserves_hashes_and_excludes_only_external_packages():
    source = """# 原始锁文件
nvidia-cuda-runtime-cu12==12.6.77 \\
    --hash=sha256:runtime
    # via torch
nvidia-cudnn-cu12==9.10.2.21 \\
    --hash=sha256:cudnn
torch @ https://example.org/torch-cu126.whl \\
    --hash=sha256:torch
vllm==0.18.0 \\
    --hash=sha256:precompiled
wheel==0.46.3 \\
    --hash=sha256:wheel
"""
    filtered = BUILD.installation_lock(source)
    assert "cuda-runtime" not in filtered
    assert "sha256:runtime" not in filtered
    assert "precompiled" not in filtered
    for fragment in ("sha256:cudnn", "sha256:torch", "sha256:wheel", "torch-cu126.whl"):
        assert fragment in filtered


def test_resolved_gpu_installation_has_no_toolkit_or_precompiled_vllm():
    lock = (ROOT / "docker/vibehub-runtime/requirements-gpu.lock").read_text()
    filtered = BUILD.installation_lock(lock)
    for name in BUILD.HOST_PACKAGES | {"vllm"}:
        assert not any(line.startswith(name + "==") for line in filtered.splitlines())
    assert "torch @ https://" in filtered
    assert "2.10.0%2Bcu126" in filtered
    assert "nvidia-cudnn-cu12==9.10.2.21" in filtered
    assert "nvidia-nccl-cu12==2.27.5" in filtered


def test_only_trusted_base_build_receives_host_cuda_context():
    deploy = (ROOT / "deploy.sh").read_text()
    start = deploy.index("phase='构建 VibeHub 受信基础候选镜像'")
    end = deploy.index("vibehub_runtime_candidate_id=", start)
    assert "--build-context host_cuda=/usr/local/cuda-12.6" in deploy[start:end]
    dockerfile = (ROOT / "docker/vibehub-runtime/Dockerfile").read_text()
    assert "--mount=type=bind,from=host_cuda,target=/usr/local/cuda-12.6" in dockerfile
    assert "COPY --from=gpu-builder /opt/vibehub-gpu /opt/vibehub-gpu" in dockerfile
    assert "COPY --from=host_cuda" not in dockerfile
