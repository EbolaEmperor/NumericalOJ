# NumericalOJ 测试镜像：真实工具链 + python 依赖
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

# why-server 的国际 IPv6 不通：强制 apt 走 IPv4，并尽量切到清华 Debian 镜像（best-effort）。
RUN set -eux; \
    echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources; \
    elif [ -f /etc/apt/sources.list ]; then \
      sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential gcc g++ \
        octave \
        libopenblas-dev liblapacke-dev \
        coreutils \
        default-mysql-client \
        git \
        ca-certificates \
        texlive-xetex texlive-latex-recommended texlive-fonts-recommended \
        texlive-lang-chinese fonts-noto-cjk latexmk; \
    rm -rf /var/lib/apt/lists/*

# Octave 等 Debian 包可能传递安装系统 Python，但测试入口必须始终使用
# 官方基础镜像的 /usr/local Python 3.12 及与之绑定的 pip3。
RUN test "$(command -v python3)" = "/usr/local/bin/python3"; \
    test "$(command -v pip3)" = "/usr/local/bin/pip3"; \
    python3 -c 'import sys; assert sys.version_info[:2] == (3, 12), sys.version'; \
    pip3 --version | grep -F '(python 3.12)'

WORKDIR /app
COPY requirements/production.txt requirements/test.txt /app/requirements/
# pip 走清华镜像（IPv4 可达），避免 pypi.org IPv6 超时。
RUN python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple \
        -r requirements/production.txt -r requirements/test.txt

# 复制仓库代码；运行拓扑由 Compose 通过环境变量注入，始终保留并测试
# tracked oj_modules/config.py 的解析逻辑、代码默认值和文档契约。
COPY . /app/

CMD ["bash", "tests/ci/run-ci.sh"]
