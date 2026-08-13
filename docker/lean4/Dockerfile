# Lean 与 Mathlib 作为一个独立镜像供正式证明判题和交互式 goal state 共用。
FROM debian:bookworm-slim

ARG LEAN_VERSION=v4.32.0
ARG MATHLIB_VERSION=v4.32.0

ENV DEBIAN_FRONTEND=noninteractive
ENV ELAN_HOME=/opt/elan
ENV PATH=/opt/elan/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git zstd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://elan.lean-lang.org/elan-init.sh \
    | sh -s -- -y --default-toolchain "leanprover/lean4:${LEAN_VERSION}"

RUN git clone --depth 1 --branch "${MATHLIB_VERSION}" \
      https://github.com/leanprover-community/mathlib4.git \
      /opt/numoj-lean-project \
    && cd /opt/numoj-lean-project \
    && lake exe cache get \
    && lake env printenv LEAN_PATH > /opt/numoj-lean-path \
    && find /opt/numoj-lean-project -type d -name .git -prune \
        -exec rm -rf '{}' + \
    && chmod -R a+rX /opt/numoj-lean-project \
    && chmod 0644 /opt/numoj-lean-path

ENV HOME=/home/runner

COPY run_lean_judge.sh /usr/local/bin/numoj-lean-judge
COPY run_lean_lsp.sh /usr/local/bin/numoj-lean-lsp

ARG JUDGER_RUNNER_UID=65532
ARG JUDGER_RUNNER_GID=65532
RUN groupadd --gid "${JUDGER_RUNNER_GID}" runner \
    && useradd --uid "${JUDGER_RUNNER_UID}" --gid "${JUDGER_RUNNER_GID}" \
        -m -s /bin/sh runner \
    && chmod 0755 /usr/local/bin/numoj-lean-judge \
                  /usr/local/bin/numoj-lean-lsp

WORKDIR /sandbox
