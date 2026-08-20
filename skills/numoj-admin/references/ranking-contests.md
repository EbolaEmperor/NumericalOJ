# 打榜赛（Ranking competitions）

本文是 `numoj-admin ranking` 的入口参考。

## 模块与题型

打榜赛以一次提交为单位记录附件、代码包、基座模型、评分状态及排行榜。`scoring_mode`
决定如何评分，`answer_format`（`json` 或 `zip`）决定普通答案文件后缀，
`submission_method`（`zip` 或 `git`）决定提交通道。新建比赛后默认配置并不等于可提交；
必须完成所属题型的就绪条件。

| 评分模式 | 适用场景 | 核心配置 | 排行榜分值 |
| --- | --- | --- | --- |
| `absolute` | 有确定标准答案的客观评分 | 标准答案和 Python 评分脚本 | 脚本返回的 `score`，限制到 `0..max_score` |
| `elo` | 两份方案需相互比较的挑战赛 | 成对比较评分脚本和 ELO 参数 | 动态 ELO rating |
| `agent_judge` | AI 按管理员规则审查项目或代码 | 评分规则、评测 Agent 端点池；可选 Git 提交 | 通过规则的分值总和 |
| `reverse_judge` | 参赛者出题，让所选 AI 尽量无法完成 | AI 作答端点池；可选独立质量门禁 | `100 - AI 得分百分比` |

## 通用 CLI 工作流

以下命令使用 SKILL.md 中声明的绝对根目录变量
`$NUMOJ_ADMIN_SKILL_ROOT`，因此无需依赖当前工作目录。

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" auth status
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking --help
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking <subcommand> --help
```

`ranking list`、`detail`、`leaderboard`、`submissions`、`matches` 和各类状态查询是
读取操作；创建、编辑、上传、重测、批量操作、ELO 控制和申诉处理都会改变线上状态。执行
后者前应先用读取命令确认比赛 ID、当前评分模式和影响范围。

### 创建、检查与通用资料

```bash
# 仅创建比赛壳；随后立刻按题型设置 scoring_mode 和其余参数。
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking create \
  --title "示例打榜赛" \
  --summary "一句话说明" \
  --description @description.md \
  --max-score 100

# 非 --full 的详情适合检查公开配置和就绪状态。
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking list --limit 20
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking detail <competition_id> --tab edit
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking leaderboard <competition_id> --limit 20
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submissions <competition_id> --page 1

# 所有题型都可附加给参赛者可见的材料。
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking upload-attachment <competition_id> handbook.pdf
```

`detail --tab edit` 在 AI 题型下会包含规则或质量门禁内容。端点返回的 `has_key`
只表示密钥是否已配置，不会返回 API 密钥本身。

比赛开放前再次执行 `ranking detail <competition_id> --tab edit`：

- `agent_judge` 应显示 `agent_judge_ready: true`；
- `reverse_judge` 还应在启用质量门禁时显示 `quality_gate_ready: true`；
- `absolute` 与 `elo` 需确认对应上传已完成；详情中的附件清单可辅助核对。

提交文件、提交命令和运行状态随题型变化，见下列专门文档。`ranking submit` 会以当前
登录账号创建真实提交，仅应在明确需要管理员测试提交时使用。

## 各题型详细配置文档

请依据我指定的打榜赛题型，选择下面的一个详细配置文档来阅读。如果我没有明确要求打榜赛的题型，请根据我的题目要求帮我选择一个合适的题型。

- [标准答案评分（absolute）]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/absolute.md)
- [ELO 对战评分（elo）]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo.md)
- [Agent-as-Judge（agent_judge）]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/agent-judge.md)
- [反向评测（reverse_judge）]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/reverse-judge.md)
