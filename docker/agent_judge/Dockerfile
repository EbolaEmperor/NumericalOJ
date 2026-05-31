# 打榜赛 Agent-as-Judge 评测镜像：预装 claude CLI + 常见工具链 + report 命令。
# 构建（在 why-server 上一次性执行）：
#   docker build -t numericaloj-agent-judge:latest docker/agent_judge
FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# 换国内镜像源，容器内 apt 更稳（why-server 在国内）
RUN sed -i 's@deb.debian.org@mirrors.aliyun.com@g; s@security.debian.org@mirrors.aliyun.com@g' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || true

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv build-essential gcc g++ make \
        git curl ca-certificates octave \
    && rm -rf /var/lib/apt/lists/*

# pip / npm 国内镜像
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple || true \
    && npm config set registry https://registry.npmmirror.com

# 预装 claude CLI（关键：不放进评测关键路径）
RUN npm install -g @anthropic-ai/claude-code --registry=https://registry.npmmirror.com

# report 上报命令
COPY report /usr/local/bin/report
RUN chmod +x /usr/local/bin/report

WORKDIR /workspace
