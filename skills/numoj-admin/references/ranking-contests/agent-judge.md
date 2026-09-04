# Agent-as-Judge（`agent_judge`）

`agent_judge` 让评测 Agent 在容器内按管理员定义的规则审查参赛者代码或项目。比赛至少需要
一条评分规则和一个启用的评测端点；规则分值之和会同步为比赛满分。可使用 ZIP 或 Git 提交，
但 Git 模式必须配置包含 `<username>` 的仓库命名规则。

## 配置

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode agent_judge \
  --answer-format json \
  --submission-method git \
  --git-format 'git@example.org:course/<username>.git' \
  --submit-limit 10 \
  --agent-timeout 1800 \
  --agent-orchestration single

python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-rules <competition_id> @rules.json
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking save-endpoint <competition_id> \
  --harness claude_code \
  --protocol openai \
  --agent-base-url https://llm.example.com/v1 \
  --api-key-env NUMOJ_AGENT_API_KEY \
  --env-file agent-secrets.env \
  --model example-model \
  --concurrency-limit 2 \
  --timeout-seconds 1800
```

`rules.json` 是规则对象数组；每项包含正整数 `rule_id`、非空 `rule_text`、非负 `value`，以及
可选的 `rule_name` 和 `dependencies`（其他规则 ID 数组）。依赖不能自指或成环。数组顺序就是
规则的 `ordering`；从 `ranking detail <competition_id> --tab edit` 读取的规则也会显式包含该字段。

`--agent-orchestration single` 使用单次评测流程；`topological` 按规则依赖图调度。端点池也可用
`save-endpoints <competition_id> @endpoints.json --env-file agent-secrets.env` 一次替换。端点对象可
包含 `api_key_env`、`harness`、`protocol`、`base_url`、`model`、`concurrency_limit`、`status` 和模型
能力字段；不要将实际 `api_key` 或端点 JSON 提交到仓库。

## 提交与检查

ZIP 模式下：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --base-model <base_model> \
  --code-zip code.zip
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking judge-stream <competition_id> <submission_id> --max-lines 10
```

Git 模式下不传 Git URL，系统根据 `<username>` 规则和当前登录用户名推导仓库地址：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking git <competition_id> check
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking git <competition_id> submit
```

## 线上示例：比赛 #8 期末大项目 - 钱学森问题的扩展求解

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/agent-judge/competition.json)

- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/agent-judge/description.md)
- [主评测端点池]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/agent-judge/endpoints.json)
- [27 条完整线上评分规则]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/agent-judge/rules.json)

`rules.json` 完整保留线上返回的 `rule_id`、`rule_name`、`rule_text`、`value`、`dependencies`
和 `ordering`，可直接作为 `ranking save-rules 8 @rules.json` 的输入。详情接口不返回端点 API 密钥；
`endpoints.json` 中的 `has_key` 仅表示线上已经配置密钥。
