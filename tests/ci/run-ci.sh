#!/usr/bin/env bash
# 在 test 容器内逐个模块顺序跑 pytest，逐模块打印结果 + JUnit XML，任一失败整体非零退出。
set -u

cd /app
# 判题运行根用内置默认 <OJ_ROOT>/judger（/app/judger）；不再预建 /tmp/judger_runs。
mkdir -p test-results judger

# CI 不读取生产 config.py。真实 AI 链路测试默认 skip；需要验证外部 AI 服务时，
# 使用单独的非生产配置和专门流程，不要把生产密钥挂进 CI 容器。
export OJ_LIVE_AI=0
echo ">>> CI 使用占位符 AI 配置，AI live 测试将 skip (OJ_LIVE_AI=0)"

# 逐模块有序列表（unit → db → CLI e2e）
MODULES=(
  "tests/unit"
  "tests/db"
  "tests/e2e"
)

declare -a NAMES
declare -a RESULTS
overall=0

echo "=================== NumericalOJ CI 开始 ==================="
for mod in "${MODULES[@]}"; do
  [ -e "$mod" ] || { echo "跳过(不存在): $mod"; continue; }
  safe=$(echo "$mod" | tr '/.' '__')
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
