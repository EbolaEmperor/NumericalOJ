# NumericalOJ 测试镜像：真实工具链 + python 依赖
FROM debian:12-slim

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
        python3 python3-pip python3-dev \
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

WORKDIR /app
COPY requirements.txt requirements-test.txt /app/
# pip 走清华镜像（IPv4 可达），避免 pypi.org IPv6 超时。
RUN pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple \
        -r requirements.txt -r requirements-test.txt

# 复制仓库代码（.dockerignore 排除无关项），再用 CI 配置覆盖 config.py
COPY . /app/
COPY tests/ci/config.ci.py /app/config.py

CMD ["bash", "tests/ci/run-ci.sh"]
