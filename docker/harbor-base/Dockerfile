# full 模式直接继承本次完整 Agent 候选，复用其全部依赖及缓存。
# lite 模式由部署脚本直接增加标签，不使用此 Dockerfile。
ARG AGENT_IMAGE=numericaloj-agent-judge:latest
FROM ${AGENT_IMAGE}

# 仅补充 Harbor 作答目录并核验已有工具，不重新安装任何依赖。
RUN set -eu; \
    mkdir -p /app; \
    claude --version; \
    codex --version; \
    opencode --version; \
    pi --version; \
    timeout --version
