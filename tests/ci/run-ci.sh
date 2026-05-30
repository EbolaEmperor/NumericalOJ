#!/usr/bin/env bash
# 在 test 容器内逐个模块顺序跑 pytest，逐模块打印结果 + JUnit XML，任一失败整体非零退出。
set -u

cd /app
# 判题运行根用内置默认 <OJ_ROOT>/judger（/app/judger）；不再预建 /tmp/judger_runs。
mkdir -p test-results judger

# ── 注入线上真实 AI 配置（运行时，绝不入库）─────────────────────────────────
# docker-compose 把生产 /home/ebola/oj/config.py 只读挂到 /run/prod_config.py。
# 把其中的 AI 相关键覆盖进 /app/config.py（占位符），其余（MySQL/Redis 指向
# compose 服务）保持不变。注入成功则 export OJ_LIVE_AI=1，开启真实 AI 链路测试；
# 文件缺失或解析失败则回退占位符，AI live 测试自动 skip。
export OJ_LIVE_AI=0
if [ -r /run/prod_config.py ]; then
  if python3 tests/ci/merge_prod_ai_config.py /run/prod_config.py /app/config.py; then
    export OJ_LIVE_AI=1
    echo ">>> 已注入线上 AI 配置，开启真实 AI 链路测试 (OJ_LIVE_AI=1)"
  else
    echo ">>> 线上 AI 配置注入失败，回退占位符 (AI live 测试将 skip)"
  fi
else
  echo ">>> 未挂载 /run/prod_config.py，使用占位符 AI 配置 (AI live 测试将 skip)"
fi

# 逐模块有序列表（unit → db → integration）
MODULES=(
  "tests/unit"
  "tests/db"
  "tests/integration/test_judging_smoke.py"
  "tests/integration/test_auth.py"
  "tests/integration/test_problem_core.py"
  "tests/integration/test_submission.py"
  "tests/integration/test_admin_problem.py"
  "tests/integration/test_admin_user.py"
  "tests/integration/test_homework.py"
  "tests/integration/test_class_management.py"
  "tests/integration/test_ranking.py"
  "tests/integration/test_repository.py"
  "tests/integration/test_ai_detection.py"
  "tests/integration/test_forum.py"
  "tests/integration/test_grading.py"
  "tests/integration/test_rejudge.py"
  "tests/integration/test_games.py"
  "tests/integration/test_ai_tutor.py"
  "tests/integration/test_live_ai.py"
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
