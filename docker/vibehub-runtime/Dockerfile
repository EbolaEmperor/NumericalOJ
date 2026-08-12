# VibeHub 作品的最小受信任基础镜像。
# 管理员需要先构建并预置；用户作品的离线构建不会拉取任何基础镜像。
# 上游 tag 同时绑定不可变摘要；升级 Python 基础镜像必须显式更新并重新验收。
FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

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

# 运行器仍会强制 --user 65532:65532；这里让直接调试也保持非 root。
USER 65532:65532
