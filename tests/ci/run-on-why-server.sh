#!/usr/bin/env bash
# 在本机执行：把代码同步到一台非生产服务器的独立 CI 目录，
# 然后在远端 docker-compose 起 mysql+redis+test 并逐模块跑测试。
set -euo pipefail

REMOTE="${REMOTE:-}"
REMOTE_DIR="${REMOTE_DIR:-/home/ebola/oj-ci}"
COMPOSE_FILE="${COMPOSE_FILE:-tests/ci/docker-compose.local.yml}"

if [ -z "$REMOTE" ]; then
  echo "ERROR: REMOTE must be set to a non-production host." >&2
  echo "Example: REMOTE=dev-ci-host REMOTE_DIR=/home/me/oj-ci bash tests/ci/run-on-why-server.sh" >&2
  exit 2
fi

case "$REMOTE" in
  why-server|ebola@why-server|why-server:*|computing|ebola@computing|computing:*)
    echo "ERROR: CI/tests are forbidden on the production host (why-server/computing). Use a local machine or another non-production server." >&2
    exit 2
    ;;
esac

remote_hostname="$(ssh "$REMOTE" 'hostname' 2>/dev/null || true)"
if [ "$remote_hostname" = "computing" ]; then
  echo "ERROR: CI/tests are forbidden on the production host whose hostname is computing." >&2
  exit 2
fi

echo ">>> 同步代码到 ${REMOTE}:${REMOTE_DIR}"
ssh "$REMOTE" "mkdir -p ${REMOTE_DIR}"
rsync -avz --delete \
  --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='tmp/' --exclude='uploads/' --exclude='static/' \
  --exclude='competitions/' --exclude='test-results/' \
  ./ "${REMOTE}:${REMOTE_DIR}/"

echo ">>> 远端 docker compose 构建并运行（逐模块）"
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f ${COMPOSE_FILE} down -v --remove-orphans || true"
set +e
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f ${COMPOSE_FILE} up --build --abort-on-container-exit --exit-code-from test"
rc=$?
set -e

echo ">>> 拉回 JUnit 结果"
mkdir -p ./test-results
rsync -avz "${REMOTE}:${REMOTE_DIR}/test-results/" ./test-results/ || true

echo ">>> 清理远端容器"
ssh "$REMOTE" "cd ${REMOTE_DIR} && docker compose -f ${COMPOSE_FILE} down -v --remove-orphans || true"
exit $rc
