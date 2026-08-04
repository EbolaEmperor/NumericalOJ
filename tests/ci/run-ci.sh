#!/usr/bin/env bash
# 在 test 容器内逐个模块顺序跑 pytest，逐模块打印结果 + JUnit XML，任一失败整体非零退出。
set -u

python3 - <<'PY' || exit 2
import subprocess
import sys

if sys.version_info[:2] != (3, 12):
    raise SystemExit(f"CI 必须使用 Python 3.12，当前为 {sys.version.split()[0]}")

pip_version = subprocess.check_output(["pip3", "--version"], text=True).strip()
if "(python 3.12)" not in pip_version:
    raise SystemExit(f"pip3 未绑定 Python 3.12：{pip_version}")

print(f">>> CI Python 基线：{sys.version.split()[0]} / {pip_version}")
PY

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# 判题运行根使用内置默认 <OJ_ROOT>/judger；同时创建 clean checkout 中不存在的
# Git 忽略运行目录，使同一个入口既能在 /app 容器内运行，也能直接用于 GitHub runner。
mkdir -p \
  test-results judger tmp uploads ranking_uploads user_libraries library \
  logs/supervisor logs/services

# CI 镜像的 .dockerignore 禁止复制本地 .env。单元测试读取 tracked config.py 的
# 代码默认值；DB/E2E 在各自 pytest 进程启动前切换到自包含 config.ci.py。
# 真实 AI 链路默认 skip；不要把生产密钥挂进 CI。
export OJ_LIVE_AI=0
echo ">>> CI 使用占位符 AI 配置，AI live 测试将 skip (OJ_LIVE_AI=0)"

# tests/conftest.py 在任何建库、清表或 FLUSHDB 前都会验证此显式开关，
# 并同时校验专用测试库、非零 Redis DB、主机与检出路径。
: "${NUMOJ_TEST_ENV:?必须由隔离的 CI 容器显式设置 NUMOJ_TEST_ENV=1}"

# 默认执行 unit → db → CLI e2e；传入路径时只运行调用方指定的模块。
# GitHub Actions 用独立 job 跑 unit，再让带 MySQL/Redis/Docker 的 job 跑 db/e2e。
if (($#)); then
  MODULES=("$@")
else
  MODULES=(
    "tests/unit"
    "tests/db"
    "tests/e2e"
  )
fi

declare -a NAMES
declare -a RESULTS
overall=0
production_config="$(mktemp)"
cp config.py "$production_config"
trap 'rm -f "$production_config"' EXIT

echo "=================== NumericalOJ CI 开始 ==================="
for mod in "${MODULES[@]}"; do
  [ -e "$mod" ] || { echo "跳过(不存在): $mod"; continue; }
  safe=$(echo "$mod" | tr '/.' '__')
  case "$mod" in
    tests/unit*) cp "$production_config" config.py ;;
    *) cp tests/ci/config.ci.py config.py ;;
  esac
  echo ""
  echo "------- 运行模块: $mod -------"
  python3 -m pytest "$mod" -v --timeout=180 \
      --junitxml="test-results/${safe}.xml"
  rc=$?
  NAMES+=("$mod")
  if [ $rc -eq 0 ]; then RESULTS+=("✅ PASS"); else RESULTS+=("❌ FAIL($rc)"); overall=1; fi
done

echo ""
echo "=================== 汇总 ==================="
for i in "${!NAMES[@]}"; do
  printf "%-45s %s\n" "${NAMES[$i]}" "${RESULTS[$i]}"
done
echo "==========================================="
[ $overall -eq 0 ] && echo "全部通过 ✅" || echo "存在失败 ❌"
exit $overall
