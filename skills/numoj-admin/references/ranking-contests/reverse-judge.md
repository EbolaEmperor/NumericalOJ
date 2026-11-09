# 反向评测（`reverse_judge`）

管理员配置比赛和 AI 端点池，参赛者每次提交一个参赛题目包，并选择一个 AI 作答端点。
系统构建题目环境、检查参考解，按比赛要求审核题目，再让所选 AI 作答并计分。
若 AI 得分百分比为 `p`，参赛者得分为 `100 - p`。

## 先读取当前站点的格式说明

编写、转换或检查参赛题目包前，先通过 CLI 获取并阅读线上 Harbor 格式说明：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking harbor-guide
```

需要保存供后续阅读时，使用 `-o`：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking harbor-guide -o ./harbor-format-guide.md
```

题目包结构、配置和脚本的编写与执行方式都以返回的文档为准。不要从 skill 的历史资料
或已有提交推断当前格式。每场反向评测的默认附件还提供题目模板，可以通过 CLI 下载：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking download-attachment <competition_id> \
  harbor-template -o ./harbor-template.zip
```

## 配置比赛

先用 `ranking detail <competition_id> --tab edit` 读取当前配置，再按用户要求修改。
反向评测的题目包由参赛者逐次提交；配置比赛时不使用 `upload-reference` 或
`upload-script` 上传另一套题目或评测脚本。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode reverse_judge \
  --max-score 100 \
  --submit-limit 10 \
  --agent-timeout 1800
```

主作答端点池供参赛者选择。沿用已有配置时，从当前比赛返回的端点中核对 `harness`、
`model` 和状态；不要根据历史快照替换端点池。需要新配置时，下面的命令会用一个端点
替换整个主池，仅在用户要求这样配置时使用：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-endpoint <competition_id> \
  --harness pi \
  --protocol openai \
  --agent-base-url https://llm.example.com/v1 \
  --api-key-env NUMOJ_AGENT_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --concurrency-limit 2 \
  --timeout-seconds 1800
```

### 可选质量门禁

质量门禁审核每次提交的参赛题目包，使用独立端点池，由系统自动调度，参赛者不能选择。
审核标准按当前比赛要求编写；仅在用户要求沿用《算法与数据结构》课程标准时，参考
[课程审核标准示例]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-prompt.txt)。

审核默认限时 30 分钟，可通过 `--timeout-seconds` 保存比赛级时限。先保存审核标准和门禁
端点，再启用门禁：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate <competition_id> \
  --prompt @quality-gate-criteria.txt \
  --timeout-seconds 1800
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate-endpoint <competition_id> \
  --harness claude_code \
  --agent-base-url https://llm.example.com \
  --api-key-env NUMOJ_QUALITY_GATE_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --concurrency-limit 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate <competition_id> --enabled
```

配置完成后读取 `ranking detail <competition_id> --tab edit`，确认 `agent_judge_ready: true`；
启用门禁时还应确认 `quality_gate_ready: true`。端点中的 `has_key` 只表示已配置密钥，
接口不会返回密钥本身。

## 提交与检查

管理员代为提交会创建真实提交并启动评测，仅在用户明确要求时执行。`--code-zip` 是参赛者
提交的题目包；`--agent-endpoint-id` 从当前比赛 `answer_endpoints` 中选择。
若用户要求与某次提交配置一致，先读取那次提交和当前端点，核对 harness 与 model 后再提交。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --code-zip harbor-task.zip \
  --agent-endpoint-id <answer_endpoint_id>
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking reverse-stream <competition_id> <submission_id> --max-lines 10
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submissions <competition_id> --username <username>
```

提交成功后记录返回的提交 ID，再用读取命令检查状态；不要因终端断开而重复提交。
需要下载文件时，`code` 是最初上传的参赛题目包，`ai-answer` 是 AI 完成作答后的产物归档：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking download-submission <submission_id> code -o ./task-package.zip
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking download-submission <submission_id> ai-answer -o ./ai-answer.zip
```
