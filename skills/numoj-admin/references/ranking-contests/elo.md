# ELO 对战评分（`elo`）

`elo` 适用于无法由单份标准答案给分、但可比较两份提交优劣的比赛。每场对战由评分脚本裁决，
系统再以 ELO 参数更新 rating；它不使用标准答案、Agent 规则或 Agent 端点。

## 配置

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --scoring-mode elo \
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
python elo_scoring.py <submission_a_dir> <submission_b_dir>
```

系统会先安全解压两份作品包，再把评分脚本和两个提交目录一同挂载到 Agent Judge
容器。评分脚本在该容器内运行，两个参数分别指向已解压的 A、B 作品目录；容器沿用
Agent Judge 的资源限制并可访问外网。当前协议把容器内双方代码视为可信内容，评分
脚本可以直接读取或执行目录中的程序。

脚本必须在 stdout 最后一条有效 JSON 行输出 `winner`：`0` 表示平局，`1` 表示 A 胜，`2`
表示 B 胜。对战详情通过 `details` 输出；`details` 必须包含 `format` 和 `content`，并在
`text`、`html` 两种格式中选择一种。

### 文本详情

使用 `format: "text"` 时，`content` 是原样展示的纯文本：

```json
{"winner": 1, "details": {"format": "text", "content": "A 的方案更优"}}
```

需要展示多项统计时，先由评分脚本把结构化结果格式化为字符串：

```python
import json

detail_data = {"wins_a": 2, "wins_b": 1, "summary": "A 的方案更优"}
print(json.dumps({
    "winner": 1,
    "details": {
        "format": "text",
        "content": json.dumps(detail_data, ensure_ascii=False, indent=2),
    },
}, ensure_ascii=False))
```

### HTML 详情

使用 `format: "html"` 时，`content` 会作为 HTML 片段放入独立沙箱。片段可以包含
`<style>`、`<script>`、图表、复杂布局和交互控件，并可用可选的 `height` 指定
240–1200px 的展示高度：

```python
import json

html = """
<style>
  .arena { display: grid; grid-template-columns: 1fr auto 1fr; gap: 16px; }
  .winner { border: 2px solid #16845b; padding: 12px; }
  .loser { border: 1px solid #d4d4d8; padding: 12px; }
</style>
<div class="arena"><section class="winner">A · 胜</section><b>VS</b><section class="loser">B</section></div>
<button id="toggle-reason">查看判定依据</button>
<pre id="reason" hidden>A 在稳定性与完成度上领先。</pre>
<script>
  document.querySelector('#toggle-reason').addEventListener('click', () => {
    document.querySelector('#reason').toggleAttribute('hidden');
  });
</script>
"""
print(json.dumps({
    "winner": 1,
    "details": {"format": "html", "content": html, "height": 520},
}, ensure_ascii=False))
```

HTML 允许加载任意 HTTP(S) 外部脚本、样式、图片和媒体，也允许发起 HTTP(S) 与 WebSocket
请求。它不具备主站同源权限，不能访问 NumericalOJ 的 DOM、Cookie 或本地存储；表单、弹窗、
顶层页面控制、对象和嵌套页面仍被禁止。

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

ELO 只提交一个 ZIP 作品包，不使用标准答案字段：

```bash
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking submit <competition_id> \
  --base-model <base_model> \
  --code-zip submission.zip
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking matches <competition_id> --page 1
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking leaderboard <competition_id> --limit 20
```

## 线上示例：比赛 #2 论文摘要挑战赛

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/description.md)
- [完整 ELO 评分脚本]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/scoring_script.py)

这是一个包含实际 ELO 参数和完整评分实现的线上实例。
