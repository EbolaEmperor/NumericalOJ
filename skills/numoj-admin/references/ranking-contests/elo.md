# ELO 对战评分（`elo`）

`elo` 适用于无法由单份标准答案给分、但可比较两份提交优劣的比赛。每场对战由评分脚本裁决，
系统再以 ELO 参数更新 rating；它不使用标准答案、Agent 规则或 Agent 端点。

## 配置

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode elo \
  --answer-format zip \
  --submission-method zip \
  --script-timeout 120 \
  --elo-initial-rating 1500 \
  --elo-k-factor 32 \
  --elo-max-matches 200 \
  --elo-match-interval 60 \
  --elo-initial-burst 5 \
  --elo-max-pairs-per-round 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking upload-script <competition_id> elo_scoring.py
```

评分脚本调用约定为：

```text
python elo_scoring.py <answer_a_path> <answer_b_path>
```

脚本必须在 stdout 最后一条有效 JSON 行输出 `winner`：`0` 表示平局，`1` 表示 A 胜，`2`
表示 B 胜；可附带 `details`。例如：

```json
{"winner": 1, "details": {"reason": "A 的方案更优"}}
```

上传评分脚本后才可启动匹配。停止、重置、删除对战记录或重建 rating 均会影响所有参赛者，
操作前先检查对战列表。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking elo-start <competition_id>
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking matches <competition_id> --page 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking elo-stop <competition_id>
# 仅在明确需要清空 ELO 状态时使用：
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking elo-reset <competition_id>
```

## 提交与检查

普通提交仍需答案文件、代码 ZIP 和基座模型：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --base-model <base_model> \
  --answer-file answer.zip \
  --code-zip code.zip
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking matches <competition_id> --page 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking leaderboard <competition_id> --limit 20
```

## 线上示例：比赛 #2 论文摘要挑战赛

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/description.md)
- [完整 ELO 评分脚本]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/scoring_script.py)

这是一个包含实际 ELO 参数和完整评分实现的线上实例。
