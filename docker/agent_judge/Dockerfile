# 打榜赛 Agent-as-Judge 评测镜像：预装 Agent Harness CLI + 常见工具链 + report 命令。
# 构建（在 why-server 上一次性执行）：
#   docker build -t numericaloj-agent-judge:latest docker/agent_judge
FROM node:24-bookworm

ENV DEBIAN_FRONTEND=noninteractive
# 关闭 claude CLI 的非必要外联（遥测/自动更新/错误上报）——受限容器内若开启会卡住
ENV CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_TELEMETRY=1 \
    DISABLE_AUTOUPDATER=1 \
    DISABLE_ERROR_REPORTING=1

# 换国内镜像源，容器内 apt 更稳（why-server 在国内）；并启用 non-free（Intel MKL 在 non-free）
RUN sed -i 's@deb.debian.org@mirrors.aliyun.com@g; s@security.debian.org@mirrors.aliyun.com@g' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || true \
    && sed -i 's@^Components: .*@Components: main contrib non-free non-free-firmware@' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || true

# 工具链 + 数值计算库（OpenBLAS / Intel MKL / LAPACK(E) / Eigen3）+ Python 科学计算常用包。
# Python 包走 apt（python3-*）：与系统 BLAS/LAPACK 链接、避免 PEP668 externally-managed 报错。
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv build-essential gcc g++ gfortran make \
        git curl ca-certificates octave \
        libopenblas-dev liblapack-dev liblapacke-dev libeigen3-dev intel-mkl \
        python3-numpy python3-scipy python3-pandas python3-matplotlib python3-sympy \
    && rm -rf /var/lib/apt/lists/*

# texlive-full 体积很大（~5GB）、装得慢，单独成一层（便于缓存、失败不连累上层）
RUN apt-get update && apt-get install -y --no-install-recommends \
        texlive-full \
    && rm -rf /var/lib/apt/lists/*

# pip / npm 国内镜像
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple || true \
    && npm config set registry https://registry.npmmirror.com

# ============ 评测高频依赖（基于线上 1800+ 份学生提交的 import/requirements 统计）============
# OCR / 媒体 / PDF 运行期二进制 + 常见图形运行库（opencv / easyocr / paddle 需要 libGL/glib）。
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim \
        ffmpeg poppler-utils \
        libgl1 libglib2.0-0 libsm6 libxext6 libxrender1 \
    && rm -rf /var/lib/apt/lists/*

# 学生高频 Python 包（pip，--break-system-packages 绕过 PEP668 externally-managed）。
# numpy/scipy/pandas/matplotlib/sympy 已由 apt 装好并链接系统 BLAS，pip 识别为已满足、不重复装。
# 覆盖：LLM/API 客户端、成像、天文、各类 PDF/OCR 库、常用工具。
RUN pip3 install --no-cache-dir --break-system-packages \
        openai anthropic dashscope google-genai httpx requests tenacity \
        tqdm python-dotenv ipython pytest redis filelock \
        pillow opencv-python-headless imageio imageio-ffmpeg \
        scikit-learn scikit-image \
        astropy astroquery \
        pymupdf pypdf pypdf2 pdfplumber pdfminer.six beautifulsoup4 lxml \
        pytesseract

# 重 ML / OCR 栈：每个单独成 best-effort 层（装失败不连累上层与镜像构建）。
# 注意：easyocr / paddleocr 的模型权重仍在首次评测时按需下载，这里只预装 Python 包本体。
RUN pip3 install --no-cache-dir --break-system-packages torch torchvision \
        || echo "WARN: torch/torchvision 预装失败（best-effort，评测时可现装）"
RUN pip3 install --no-cache-dir --break-system-packages easyocr \
        || echo "WARN: easyocr 预装失败（best-effort）"
RUN pip3 install --no-cache-dir --break-system-packages paddlepaddle paddleocr \
        || echo "WARN: paddlepaddle/paddleocr 预装失败（best-effort）"
RUN pip3 install --no-cache-dir --break-system-packages rapidocr-onnxruntime onnxruntime \
        || echo "WARN: rapidocr-onnxruntime 预装失败（best-effort）"

# ============ 无头 GUI / Web 交互演示测试栈 ============
# 用于「实时交互演示」类规则（Tkinter/Qt GUI、Flask/Web 演示）：判题 Agent 在无头容器里
# 可用 xvfb-run 跑 GUI、用 headless chromium + selenium/playwright 驱动 Web 演示，并用 scrot 截图验证。
# fonts-wqy-zenhei：让 GUI/浏览器能正确渲染中文标签。
RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb x11-utils xauth python3-tk scrot fonts-wqy-zenhei \
        chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Web 自动化 Python 驱动：selenium 走上面的 apt chromium/chromedriver；pyvirtualdisplay 便于
# 在代码里临时拉起 Xvfb 虚拟显示。
RUN pip3 install --no-cache-dir --break-system-packages selenium pyvirtualdisplay

# playwright 自带浏览器，单独 best-effort 层（下载失败不连累上层）。
RUN pip3 install --no-cache-dir --break-system-packages playwright \
        && playwright install chromium \
        || echo "WARN: playwright/浏览器 预装失败（best-effort，评测时可现装）"

# 关键收尾：把 numpy 钉回 <2。上面的 pip 依赖（torch/paddle 等）会顺带把 numpy 升到 2.x，
# 而 apt 的 numpy/pandas/matplotlib 是按 numpy 1.x ABI 编译的，被 numpy2 一升就崩
# （“numpy.dtype size changed / _ARRAY_API not found”）。numpy 1.26 是全栈公约数：
# torch/paddle/easyocr/opencv/sklearn 均兼容，且让 apt 的 pandas/matplotlib 恢复可用。
RUN pip3 install --no-cache-dir --break-system-packages --force-reinstall "numpy<2"

# 预装 Agent Harness CLI（关键：不放进评测关键路径）
# Agent Harness 属于判题协议的一部分。Claude/Codex/OpenCode 保持现有显式版本；
# Pi 按产品口径信任上游 latest，不人为锁定。ARG 紧邻唯一使用它们的步骤，避免版本
# 更新使前面的 30GB 工具链缓存全部失效。
ARG CLAUDE_CODE_VERSION=2.1.197
ARG CODEX_CLI_VERSION=0.144.5
ARG OPENCODE_VERSION=1.18.3
ARG AI_SDK_OPENAI_COMPATIBLE_VERSION=2.0.51
ARG AI_SDK_ANTHROPIC_VERSION=3.0.85
RUN npm install -g \
        @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} \
        @openai/codex@${CODEX_CLI_VERSION} \
        opencode-ai@${OPENCODE_VERSION} \
        @ai-sdk/openai-compatible@${AI_SDK_OPENAI_COMPATIBLE_VERSION} \
        @ai-sdk/anthropic@${AI_SDK_ANTHROPIC_VERSION} \
        --registry=https://registry.npmmirror.com
RUN npm install -g --ignore-scripts \
        @earendil-works/pi-coding-agent \
        --registry=https://registry.npmmirror.com

# report 上报命令
COPY report /usr/local/bin/report
COPY run_harness /usr/local/bin/run_harness
COPY pi_web_search_mcp.ts /usr/local/share/numoj/pi_web_search_mcp.ts
RUN chmod +x /usr/local/bin/report /usr/local/bin/run_harness

WORKDIR /workspace
