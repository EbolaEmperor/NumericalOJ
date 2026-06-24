FROM debian:bookworm-slim

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
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --break-system-packages \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    numpy scipy matplotlib pandas sympy pillow networkx scikit-learn requests openpyxl

RUN useradd -m -s /bin/false runner

WORKDIR /sandbox
