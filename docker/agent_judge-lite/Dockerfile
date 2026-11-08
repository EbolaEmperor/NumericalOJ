# Agent 轻量评测镜像及 Harbor 通用基座：预装四种 Harness CLI，不安装 TeX。
# 构建（上下文必须是 docker/，这样可复用 agent_judge/run_harness）：
#   docker build -t numericaloj-lean4:latest docker/lean4
#   docker build -f docker/agent_judge-lite/Dockerfile -t numericaloj-agent-judge-lite:latest docker
ARG LEAN4_IMAGE=numericaloj-lean4:latest
FROM ${LEAN4_IMAGE} AS lean4_runtime

# 与生产 Node 24.20 工具链保持同版，固定多架构摘要，避免 CI 随标签漂移。
FROM node:24.20.0-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e

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

# pip / npm 国内镜像。pip 只补 Agent 评测常见 API 客户端，避免 OCR/ML/浏览器自动化重包。
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple || true \
    && npm config set registry https://registry.npmmirror.com

RUN pip3 install --no-cache-dir --break-system-packages \
        openai anthropic dashscope google-genai httpx tenacity python-dotenv

# 轻量版缩减的是系统工具链，不缩减启动弹窗提供的 Harness 集合。
ARG CLAUDE_CODE_VERSION=2.1.205
ARG CODEX_CLI_VERSION=0.144.5
ARG OPENCODE_VERSION=1.18.3
ARG PI_CODING_AGENT_VERSION=0.82.1
RUN npm install -g \
        @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
        @openai/codex@${CODEX_CLI_VERSION} \
        opencode-ai@${OPENCODE_VERSION} \
        --registry=https://registry.npmmirror.com
RUN npm install -g --ignore-scripts \
        @earendil-works/pi-coding-agent@${PI_CODING_AGENT_VERSION} \
        --registry=https://registry.npmmirror.com

# Codex 0.144.5 的 app-server 即使使用 danger-full-access 也会探测并启动
# bubblewrap。按镜像缓存约束追加在 Harness 安装层之后，不改动前面的系统包层。
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/*

# lite 只缩减通用工具链，不缩减 Agent 可用的语言环境。Lean/Mathlib 与
# 生产 Agent 镜像复用同一个固定证明镜像和启动 wrapper。
COPY --from=lean4_runtime /opt/elan /opt/elan
COPY --from=lean4_runtime /opt/numoj-lean-project /opt/numoj-lean-project
COPY --from=lean4_runtime /opt/numoj-lean-path /opt/numoj-lean-path
COPY agent_judge/lean /usr/local/bin/lean
ENV ELAN_HOME=/opt/elan
ENV PATH=/usr/local/bin:/opt/elan/bin:${PATH}
RUN chmod 0755 /usr/local/bin/lean \
    && test -f /opt/numoj-lean-project/.lake/build/lib/lean/Mathlib.olean

# 与完整镜像保持相同的 C/C++ 数值计算开发库（含 CHOLMOD）。放在 Lean
# 之后、高频变动的 Harness 文件之前，保留前面依赖层的缓存。
RUN apt-get update && apt-get install -y --no-install-recommends \
        libfftw3-dev libsuitesparse-dev libgsl-dev \
        libboost-dev libboost-math-dev libmpfr-dev \
        libnlopt-dev libnlopt-cxx-dev libceres-dev libarmadillo-dev \
    && rm -rf /var/lib/apt/lists/*

# FaithSieve 原稿页图所需 PDF 工具及通用 Agent 的 OCR 工具；保留现有镜像缓存。
RUN apt-get update && apt-get install -y --no-install-recommends \
        poppler-utils tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir --break-system-packages sympy==1.14.0 mpmath==1.3.0

# 与完整镜像复用同一份 Harness 入口。
COPY agent_judge/faithsieve_tool.py /usr/local/share/numoj/faithsieve_tool.py
COPY agent_judge/run_harness /usr/local/bin/run_harness
COPY agent_judge/pi_web_search_mcp.ts /usr/local/share/numoj/pi_web_search_mcp.ts
RUN chmod +x /usr/local/bin/run_harness

# Harbor 默认模板复用预建镜像，必须预先具备 /app；通用 Agent 仍使用 /workspace。
# 构建时核验 Harbor 所需的四套 CLI 与 GNU 超时工具，并防止 TeX 被间接带回。
RUN set -eu; \
    mkdir -p /app; \
    claude --version; \
    codex --version; \
    opencode --version; \
    pi --version; \
    timeout --version; \
    for executable in tex latex pdflatex xelatex lualatex latexmk; do \
        if command -v "$executable" >/dev/null 2>&1; then \
            echo "Harbor 轻量基座不应包含 TeX：$executable" >&2; exit 1; \
        fi; \
    done

WORKDIR /workspace
