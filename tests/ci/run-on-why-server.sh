#!/usr/bin/env bash
# 在本机执行：把代码同步到 why-server 的独立 CI 目录（绝不碰生产 /home/ebola/oj），
# 然后在远端 docker-compose 起 mysql+redis+test 并逐模块跑测试。
set -euo pipefail

REMOTE="${REMOTE:-why-server}"
REMOTE_DIR="${REMOTE_DIR:-/home/ebola/oj-ci}"

echo ">>> 同步代码到 ${REMOTE}:${REMOTE_DIR}"
ssh "$REMOTE" "mkdir -p ${REMOTE_DIR}"
rsync -avz --delete \
  --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='tmp/' --exclude='uploads/' --exclude='static/' \
  --exclude='competitions/' --exclude='test-results/' \
  ./ "${REMOTE}:${REMOTE_DIR}/"

echo ">>> 远端 docker compose 构建并运行（逐模块）"
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f tests/ci/docker-compose.ci.yml down -v --remove-orphans || true"
set +e
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f tests/ci/docker-compose.ci.yml up --build --abort-on-container-exit --exit-code-from test"
rc=$?
set -e

echo ">>> 拉回 JUnit 结果"
mkdir -p ./test-results
rsync -avz "${REMOTE}:${REMOTE_DIR}/test-results/" ./test-results/ || true

echo ">>> 清理远端容器"
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f tests/ci/docker-compose.ci.yml down -v --remove-orphans || true"
exit $rc
