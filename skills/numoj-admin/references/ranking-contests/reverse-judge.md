# 反向评测（`reverse_judge`）

`reverse_judge` 是管理员创建和配置的一场**反向评测比赛**。参赛者参加比赛时，每次提交一个
自己设计的题目 ZIP；本文统一把这个 ZIP 称为**参赛题目包**。参赛题目包是参赛者上传到反向
评测比赛中的提交物，不是管理员为整场反向评测比赛上传的题目包；比赛配置本身也没有另一份
“反向评测题目包”。

每次提交时，参赛者还要选择一个 AI 作答端点。系统先运行参赛题目包中出题者提供的标准答案，
随后让 AI 在同一参赛题目包的 `template/` 中作答，并运行其中的 `judge.sh`。若 AI 得分百分比为
`p`，参赛者得分为 `100 - p`；因此参赛题目必须可解、可复现且评测确定，不能用无效题或基础
设施故障取分。

本文还使用**AI 答案归档**表示 AI 完成作答后的文件归档。它来自参赛题目包中的 `template/`，
可以通过 `download-submission ... ai-answer` 下载，但它不是参赛题目包。

## 配置

反向评测比赛只接受参赛者以 ZIP 形式提交参赛题目包；管理员配置比赛时不使用
`upload-reference` 或 `upload-script` 上传另一套题目或评测脚本。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode reverse_judge \
  --answer-format json \
  --submission-method zip \
  --max-score 100 \
  --submit-limit 10 \
  --agent-timeout 1800 \
  --reverse-finalize-timeout 600

# 主端点池：参赛者提交时从启用端点中选择。
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-endpoint <competition_id> \
  --harness pi \
  --protocol openai \
  --agent-base-url https://llm.example.com/v1 \
  --api-key-env NUMOJ_AGENT_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --concurrency-limit 2 \
  --timeout-seconds 1800 \
  --reverse-finalize-timeout 600
```

参赛题目包根目录（或 ZIP 内唯一的顶层目录）必须包含：

```text
problem/     # 题面与公开材料
template/    # AI 作答的初始目录
solution/    # 出题者标准答案
judge.sh     # 评测入口
```

系统会分别以参赛题目包中的 `solution/` 和 AI 完成后的 `template/` 运行 `judge.sh`，并要求其
在该参赛题目包根目录生成 `result.json`。该文件须包含正数 `max_score` 和非负 `score`；可选
`test_points` 用于逐点说明。参赛者提供的标准答案必须获得满分，否则评测会在第一阶段停止。

### 可选质量门禁

质量门禁审核的是每次提交的参赛题目包，使用独立端点池，由系统自动调度，参赛者不能选择。
建议先保存审核标准和门禁端点，验证后再启用。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate <competition_id> \
  --prompt @quality-gate-criteria.txt
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate-endpoint <competition_id> \
  --harness claude_code \
  --agent-base-url https://llm.example.com \
  --api-key-env NUMOJ_QUALITY_GATE_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --concurrency-limit 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate <competition_id> --enabled
```

启用后，提交必须同时满足「有审核标准」和「至少一个已启用的质量门禁端点」；否则会被阻止。

## 提交与检查

`--code-zip` 在本题型中专指参赛者提交给反向评测比赛的**参赛题目包**，且必须选择一个主
AI 作答端点：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --code-zip reverse-problem.zip \
  --agent-endpoint-id <answer_endpoint_id>
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking reverse-stream <competition_id> <submission_id> --max-lines 10
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking download-submission <submission_id> ai-answer -o ./ai-answer.zip
```

最后一条命令下载的是 AI 答案归档，不是参赛者最初上传的参赛题目包。

## 线上示例：比赛 #10 反向评测

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/description.md)
- [主 AI 作答端点池]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/answer-endpoints.json)
- [完整质量门禁标准]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-prompt.txt)
- [独立质量门禁端点池]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-endpoints.json)

`quality-gate-prompt.txt` 是线上返回的完整 Prompt，可直接作为以下命令的输入：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate 10 \
  --prompt "@$NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-prompt.txt"
```

端点详情中的 `has_key` 只表示线上已配置 API 密钥，接口不会返回密钥本身。
