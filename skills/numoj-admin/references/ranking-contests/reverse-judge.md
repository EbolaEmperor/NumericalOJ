# 反向评测（`reverse_judge`）

`reverse_judge` 是管理员创建和配置的一场**反向评测比赛**。参赛者参加比赛时，每次提交一个
自己设计的 Harbor 任务，通过 ZIP 或配置好的 Git 仓库提交；本文统一称为**参赛题目包**。
比赛配置本身没有另一份由管理员上传的“反向评测题目包”。

每次提交时，参赛者还要选择一个 AI 作答端点。系统先显示构建环境步骤与实时日志，再通过 Harbor 官方执行器运行参考解自检，
随后让 AI 按照 `instruction.md` 在任务环境中作答，并执行任务验证。若 AI 得分百分比为
`p`，参赛者得分为 `100 - p`；因此参赛题目必须可解、可复现且评测确定，不能用无效题或
基础设施故障取分。

本文还使用**AI 答案归档**表示 AI 完成作答后的产物归档，可以通过
`download-submission ... ai-answer` 下载；提交的 Harbor 任务包与 AI 答案归档是两份不同的产物。

## 配置

每场反向评测默认包含只读附件 `harbor-template.zip`。其中的通用 Dockerfile 使用
`numericaloj-harbor-base:1`；部署会预构建该环境，保持默认环境不变即可直接复用。


反向评测只接受 Harbor 任务格式；旧的 `problem/`、`template/`、`solution/`、`judge.sh`
格式已弃用。参赛者可以上传 ZIP，也可以通过比赛配置的 Git 仓库提交。管理员配置比赛时
不使用 `upload-reference` 或 `upload-script` 上传另一套题目或评测脚本。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode reverse_judge \
  --max-score 100 \
  --submit-limit 10 \
  --agent-timeout 1800

# 主端点池：参赛者提交时从启用端点中选择。
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

参赛题目包根目录（或 ZIP 内唯一的顶层目录）放置一个 Harbor 任务。典型 Linux 任务结构为：

```text
task.toml              # 元数据、超时与运行资源配置
instruction.md         # 给 AI 的题面与交付要求
environment/
  Dockerfile           # 任务环境与初始文件
solution/
  solve.sh             # 可执行参考解
tests/
  test.sh              # 验证入口
```

目前接受 Linux 单任务，运行环境支持 `environment/Dockerfile` 或预构建 Docker 镜像，
不接受 Compose 或多步骤任务。需要归档交付物时，在 `task.toml` 顶层按需声明 `artifacts`，
例如 `artifacts = ["/app"]`；省略或为空时不生成答案归档，奖励照常计分。
验证器统一在该轮作答环境中执行，直接检查最终状态；`artifacts` 仅用于产物归档。

Harbor 官方 Trial 直接读取 `instruction.md` 作为任务指令；其中只写题目与必要的函数、
文件和输入输出接口，不列隐藏测试数量、分组或运维指引。环境工具、依赖和初始文件由
Dockerfile 准备，资源与超时由 `task.toml` 和比赛运行配置控制；GNU `timeout` 仅在具体
脚本使用它时才是依赖。旧 `--reverse-finalize-timeout` 参数仅为兼容保留，Harbor 反向评测不使用它。
`solution/solve.sh` 在任务环境中生成参考结果，`tests/test.sh` 验证最终状态，
并将数值奖励写入 `/logs/verifier/reward.txt` 或 `/logs/verifier/reward.json`。
所有指标必须是有限数值；优先以 `reward`、其次以 `score` 作为 `0` 到 `1` 的主奖励。
没有主奖励时，仅在所有指标均为 `0` 到 `1` 时取平均值；其他辅助指标原样保留，
非归一化指标不显示为满分为 1 的得分项，也不参与无主奖励时的量纲猜测。
平台要求提供参考解并通过满分自检，否则评测会在第一阶段停止。Harbor 自身允许省略参考解，
但省略后无法满足反向评测的自检要求。

格式说明与执行语义以 [Harbor 官方任务文档](https://docs.harborframework.com/tasks/overview)
为准。题目公开材料应放入任务环境或写入 `instruction.md`；隐藏的验证数据与参考解分别放在
`tests/` 和 `solution/`，由 Harbor 在验证和 Oracle 阶段分别提供，不复制进 AI 的初始环境。

### 可选质量门禁

审核默认限时 30 分钟，可在编辑比赛页“审核标准”旁调整为 1–120 分钟；
CLI 使用 `ranking save-quality-gate <competition_id> --timeout-seconds 1800` 保存比赛级时限。

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
  --code-zip harbor-task.zip \
  --agent-endpoint-id <answer_endpoint_id>
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking reverse-stream <competition_id> <submission_id> --max-lines 10
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking download-submission <submission_id> ai-answer -o ./ai-answer.zip
```

最后一条命令下载的是 AI 答案归档，不是参赛者最初上传的参赛题目包。

## 配置参考：比赛 #10 反向评测

以下 JSON 是历史线上配置快照；公开题目描述和质量门禁标准已更新为 Harbor 格式模板。
现有线上比赛的题面、附件与门禁标准需要由管理员在发布新格式时同步更新。

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/description.md)
- [主 AI 作答端点池]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/answer-endpoints.json)
- [完整质量门禁标准]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-prompt.txt)
- [独立质量门禁端点池]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-endpoints.json)

`quality-gate-prompt.txt` 可直接作为以下命令的输入：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-quality-gate 10 \
  --prompt "@$NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge/quality-gate-prompt.txt"
```

端点详情中的 `has_key` 只表示线上已配置 API 密钥，接口不会返回密钥本身。
