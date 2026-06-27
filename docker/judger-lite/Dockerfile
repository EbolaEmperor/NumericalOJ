FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null; \
    true

# 本机轻量判题镜像：不安装 Intel oneAPI MKL，也不安装 texlive-full。
# TeX 仅保留 LaTeX/XeLaTeX、常用字体、中文包和 latexmk，满足 matplotlib/Octave
# 常见绘图与少量 LaTeX 渲染需求。
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make \
    python3 python3-pip python3-venv \
    octave \
    coreutils \
    ca-certificates \
    libopenblas-dev \
    libeigen3-dev \
    liblapacke-dev \
    gnuplot \
    texlive-xetex \
    texlive-latex-recommended \
    texlive-fonts-recommended \
    texlive-lang-chinese \
    latexmk \
    fonts-noto-cjk \
    fonts-freefont-otf \
    cm-super \
    dvipng \
    dvisvgm \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --break-system-packages \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    numpy scipy matplotlib pandas sympy pillow networkx scikit-learn requests openpyxl

# 运行时根文件系统只读、$HOME(/home/runner) 只读，matplotlib 无法写
# ~/.config/matplotlib，会每次回退到 /tmp 重建字体缓存（首次 savefig ~9s → TLE）。
# 预生成字体缓存到镜像内只读可读的 MPLCONFIGDIR，运行时直接命中缓存，不再重建。
ENV MPLCONFIGDIR=/opt/mplconfig
RUN mkdir -p /opt/mplconfig \
    && MPLCONFIGDIR=/opt/mplconfig python3 -c "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt; plt.plot([0,1],[0,1]); plt.savefig('/tmp/_warm.png')" \
    && chmod -R a+rX /opt/mplconfig \
    && rm -f /tmp/_warm.png

# 判题容器运行时使用 --read-only，fontconfig 不能更新 /var/cache/fontconfig。
# 在最终字体集合上预生成缓存，避免 Octave/gnuplot 首次 print('-dpng') 扫描字体到数秒级。
RUN fc-cache -fsv \
    && chmod -R a+rX /var/cache/fontconfig

RUN mkdir -p /opt/library

RUN useradd -m -s /bin/false runner

WORKDIR /sandbox
