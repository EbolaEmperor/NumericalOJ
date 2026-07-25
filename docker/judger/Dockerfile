# 固定到生产 default builder 已缓存、并用于当前稳定镜像的基础镜像。
# 升级基础系统时应显式更新摘要，并在维护窗口预热新的重型工具链缓存。
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|http://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null; \
    true

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make \
    python3 python3-pip python3-venv \
    octave \
    texlive-full \
    coreutils \
    ca-certificates \
    libopenblas-dev \
    libeigen3-dev \
    liblapacke-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --break-system-packages \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    numpy scipy matplotlib pandas sympy pillow networkx scikit-learn requests openpyxl

# Octave 无头绘图后端：print/saveas '-dpng' 依赖 gnuplot，slim 镜像默认无任何
# graphics toolkit（否则报 "no graphics toolkits are available!"，画不出 output.png）。
# 单独成层，复用上面的 texlive/pip 缓存，重建更快。
RUN apt-get update && apt-get install -y --no-install-recommends gnuplot \
    && rm -rf /var/lib/apt/lists/*

# 运行时根文件系统只读、$HOME(/home/runner) 只读，matplotlib 无法写
# ~/.config/matplotlib，会每次回退到 /tmp 重建字体缓存（首次 savefig ~9s → TLE）。
# 预生成字体缓存到镜像内只读可读的 MPLCONFIGDIR，运行时直接命中缓存，不再重建。
ENV MPLCONFIGDIR=/opt/mplconfig
RUN mkdir -p /opt/mplconfig \
    && MPLCONFIGDIR=/opt/mplconfig python3 -c "import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt; plt.plot([0,1],[0,1]); plt.savefig('/tmp/_warm.png')" \
    && chmod -R a+rX /opt/mplconfig \
    && rm -f /tmp/_warm.png

# Intel oneAPI MKL（数值库题：#include <mkl.h> 以及 cblas/lapacke/Fortran 接口）。
# 旧的进程内判题器链接宿主机 MKL（题面所谓"评测环境已配置好编译链接参数"），
# 容器化后需在镜像内提供等价的 MKL。MKL 同时提供 Fortran 原生符号（dsyev_ 等）、
# CBLAS（cblas_*）、LAPACKE（LAPACKE_*），故沿用 <cblas.h>/<lapacke.h> 通用头的
# 老解法也能正常链接。单独成层，便于复用上方缓存。
RUN apt-get update && apt-get install -y --no-install-recommends gnupg curl ca-certificates \
    && curl -fsSL https://apt.repos.intel.com/intel-gpg-keys/GPG-PUB-KEY-INTEL-SW-PRODUCTS.PUB \
       | gpg --dearmor -o /usr/share/keyrings/oneapi-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/oneapi-archive-keyring.gpg] https://apt.repos.intel.com/oneapi all main" \
       > /etc/apt/sources.list.d/oneAPI.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends intel-oneapi-mkl-devel \
    && rm -rf /var/lib/apt/lists/*

# 屏蔽 oneAPI 不同版本的目录差异（lib/intel64 vs lib），统一软链到 /opt/mkl/{include,lib}，
# 供 judger_core 的编译命令以固定路径引用；并写入 ld.so 配置便于运行时加载。
ENV MKLROOT=/opt/intel/oneapi/mkl/latest
RUN mkdir -p /opt/mkl \
    && if [ -d "$MKLROOT/lib/intel64" ]; then MKLLIB="$MKLROOT/lib/intel64"; else MKLLIB="$MKLROOT/lib"; fi \
    && ln -sfn "$MKLLIB" /opt/mkl/lib \
    && ln -sfn "$MKLROOT/include" /opt/mkl/include \
    && echo /opt/mkl/lib > /etc/ld.so.conf.d/mkl.conf \
    && ldconfig

# 判题容器运行时使用 --read-only，fontconfig 不能更新 /var/cache/fontconfig。
# 在最终字体集合上预生成缓存，避免 Octave/gnuplot 首次 print('-dpng') 扫描字体到数秒级。
RUN fc-cache -fsv \
    && chmod -R a+rX /var/cache/fontconfig

RUN mkdir -p /opt/library

ARG JUDGER_RUNNER_UID=65532
ARG JUDGER_RUNNER_GID=65532
RUN groupadd --gid "${JUDGER_RUNNER_GID}" runner \
    && useradd --uid "${JUDGER_RUNNER_UID}" --gid "${JUDGER_RUNNER_GID}" \
        -m -s /bin/false runner

WORKDIR /sandbox
