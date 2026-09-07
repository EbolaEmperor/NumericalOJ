# VibeHub 作品共用的受信任基础镜像。
# 管理员需要先构建并预置；用户作品构建期可以联网安装依赖。
# 上游 tag 同时绑定不可变摘要；升级 Python 基础镜像必须显式更新并重新验收。
FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS web

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/data/home \
    TMPDIR=/tmp \
    VIBEHUB_SOCKET=/run/vibehub/app.sock \
    VIBEHUB_HEALTH_PATH=/healthz

WORKDIR /app
RUN python -m pip install --no-cache-dir \
        numpy==2.5.0 pillow==12.2.0 arcengine==0.9.3 \
    && mkdir -p /app /data/home \
    && chown -R 65532:65532 /app /data
COPY uds_relay.py /usr/local/bin/vibehub-uds-relay
RUN chmod 0555 /usr/local/bin/vibehub-uds-relay

# 在已有稳定层之后追加共用依赖，保留现有作品的 numpy / pillow / arcengine。
COPY requirements-web.txt requirements-web.lock /opt/vibehub-runtime/
RUN python -m pip install --no-cache-dir --require-hashes \
        -r /opt/vibehub-runtime/requirements-web.lock

# vLLM 的 NumPy 约束与普通作品不同；GPU 环境独立，按需显式选择解释器。
# 只挂载宿主 CUDA 12.6；不把 Toolkit 复制进镜像，也不安装其它 CUDA 版本。
FROM web AS gpu-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates libnuma-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-gpu.txt requirements-gpu.lock /opt/vibehub-runtime/
COPY build_gpu.py /opt/vibehub-runtime/build_gpu.py
RUN --mount=type=bind,from=host_cuda,target=/usr/local/cuda-12.6 \
    python /opt/vibehub-runtime/build_gpu.py

FROM web
# Triton 在运行时编译 launcher，保留 C/C++ 编译器；CUDA 编译器仍来自只读宿主挂载。
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libnuma1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=gpu-builder /opt/vibehub-gpu /opt/vibehub-gpu
COPY --from=gpu-builder /opt/vibehub-runtime/ /opt/vibehub-runtime/

# 运行器仍会强制 --user 65532:65532；这里让直接调试也保持非 root。
USER 65532:65532
