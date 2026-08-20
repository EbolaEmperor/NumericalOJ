# 标准答案评分（`absolute`）

`absolute` 适用于答案可与标准答案进行确定性比较的比赛。系统以 Python 子进程执行
评分脚本，必须同时上传与 `answer_format` 相符的标准答案，以及 `.py` 评分脚本；缺少任一
项会阻止参赛者提交。

## 配置

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode absolute \
  --answer-format json \
  --submission-method zip \
  --max-score 100 \
  --script-timeout 120

python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking upload-reference <competition_id> reference.json
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking upload-script <competition_id> scoring.py
```

先设定 `--answer-format`，再上传同后缀的标准答案；切换答案格式会清除旧标准答案，必须重新
上传。该模式不使用 Agent 端点、Agent 规则或 ELO 参数。

评分脚本的调用约定为：

```text
python scoring.py <user_answer_path> <reference_answer_path> <max_score>
```

脚本须以退出码 0 结束，并在 stdout 最后一条有效 JSON 行输出至少包含数值 `score`：

```json
{"score": 87.5, "details": {"optional": "可选的评分说明"}}
```

系统会将分数截断到 `0..max_score`。评分脚本和标准答案通过比赛后台配置，不会作为普通比赛
附件展示给参赛者。

## 提交与检查

普通提交同时需要答案文件和代码 ZIP，并需要基座模型字段：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --base-model <base_model> \
  --answer-file answer.json \
  --code-zip code.zip
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking my-submissions <competition_id> --limit 5
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking leaderboard <competition_id> --limit 20
```

详情与排行榜已确认无误后再用 `--active` 开放比赛。

## 线上示例：比赛 #1 图片批改练习赛

采集时间：2026-08-21。比赛配置和题面来自管理员 CLI 的只读查询；评分脚本来自用户授权的
生产目录只读访问。

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/absolute/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/absolute/description.md)
- [完整评分脚本]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/absolute/grader.py)

`grader.py` 是线上比赛 #1 当前使用的完整脚本，没有删减、脱敏或占位。该比赛不需要 Agent
端点或质量门禁；标准答案当前未包含在示例中。
