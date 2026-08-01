# 打榜赛 Agent-as-Judge 轻量评测镜像：预装 Claude Code、Pi CLI + 常用工具链。
# 构建（上下文必须是 docker/，这样可复用 agent_judge/report 与 run_harness）：
#   docker build -f docker/agent_judge-lite/Dockerfile -t numericaloj-agent-judge-lite:latest docker
FROM node:24-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.197

ENV DEBIAN_FRONTEND=noninteractive
# 关闭 claude CLI 的非必要外联（遥测/自动更新/错误上报）——受限容器内若开启会卡住
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_ERROR_REPORTING=1

# 国内网络下 apt / npm 更稳；lite 镜像不启用 non-free，也不安装 Intel MKL。
RUN sed -i 's@deb.debian.org@mirrors.aliyun.com@g; s@security.debian.org@mirrors.aliyun.com@g' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || true

# 常用编译/运行环境：C/C++/Fortran、OpenBLAS/LAPACK/Eigen、git/curl。
# Python 科学计算包尽量走 Debian apt，避免 pip 把 numpy 升到不兼容的 ABI。
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
        bash coreutils build-essential gcc g++ gfortran make \
        python3 python3-pip python3-venv \
        libopenblas-dev liblapack-dev liblapacke-dev libeigen3-dev \
        python3-numpy python3-scipy python3-pandas python3-matplotlib python3-sympy \
        python3-sklearn python3-pil python3-networkx python3-openpyxl \
        python3-requests python3-bs4 python3-lxml python3-pytest python3-redis \
        python3-filelock python3-tqdm \
    && rm -rf /var/lib/apt/lists/*

# 仅保留基础英文 LaTeX 能力：不装 texlive-full，不装中文语言包。
RUN apt-get update && apt-get install -y --no-install-recommends \
        texlive-latex-base \
        texlive-latex-recommended \
        texlive-fonts-recommended \
        latexmk \
        dvipng \
        dvisvgm \
        ghostscript \
    && rm -rf /var/lib/apt/lists/*

# pip / npm 国内镜像。pip 只补 Agent 评测常见 API 客户端，避免 OCR/ML/浏览器自动化重包。
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple || true \
    && npm config set registry https://registry.npmmirror.com

RUN pip3 install --no-cache-dir --break-system-packages \
        openai anthropic dashscope google-genai httpx tenacity python-dotenv

# 轻量版安装 Claude Code 与 Pi，不安装 Codex / opencode。
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
        --registry=https://registry.npmmirror.com
RUN npm install -g --ignore-scripts \
        @earendil-works/pi-coding-agent \
        --registry=https://registry.npmmirror.com

# report / run_harness 与原版镜像复用同一份脚本。
COPY agent_judge/report /usr/local/bin/report
COPY agent_judge/run_harness /usr/local/bin/run_harness
RUN chmod +x /usr/local/bin/report /usr/local/bin/run_harness

WORKDIR /workspace
