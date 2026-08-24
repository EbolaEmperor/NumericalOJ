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

ELO 提供两种 runtime 模式来运行评分脚本，用 `elo_runtime_mode` 按比赛内容选用：

- `legacy`（默认）：**单容器运行时**。评分脚本与双方作品在同一个可联网的
  Agent Judge 容器中运行，脚本可以直接读取或执行目录中的程序。适合作品本身
  是纯文件（文档、数据、配置等）、评测不需要执行不可信代码的比赛，例如
  论文摘要挑战赛这类"提交 .tex 解读、比较内容质量"的赛题。
- `isolated`：**隔离运行时**。评分脚本与被测作品分处不同容器，被测代码在断网
  工作容器中由可信运行器看管执行。适合需要实际运行作品代码的比赛（如回合
  对抗赛），被测代码之间、被测代码与评分脚本之间互相不可见。

两种运行时的裁决输出协议相同：脚本必须在 stdout 最后一条有效 JSON 行输出
`winner`：`0` 表示平局，`1` 表示 A 胜，`2` 表示 B 胜。对战详情通过 `details`
输出；`details` 必须包含 `format` 和 `content`，并在 `text`、`html` 两种格式中
选择一种。

## 单容器运行时（`elo_runtime_mode = legacy`，默认）

评分脚本调用约定为：

```text
python elo_scoring.py <submission_a_dir> <submission_b_dir>
```

系统会先安全解压两份作品包，再把评分脚本和两个提交目录一同挂载到 Agent Judge
容器。评分脚本在该容器内运行，两个参数分别指向已解压的 A、B 作品目录；容器沿用
Agent Judge 的资源限制并可访问外网。

注意：该运行时把容器内双方作品视为评分脚本可直接处理的内容。如果评测过程会
执行作品中的代码，被执行的代码与对手作品、评分脚本同处一个容器，可以互相读写
并联网；因此仅在作品不含需要执行的代码（或完全信任参赛代码）时选用。

## 隔离运行时（`elo_runtime_mode = isolated`）

每场对战由宿主仲裁者编排三个平级容器（不嵌套）：

- 两个**工作容器**：各挂载一方作品，**断网**（`--network none`），运行可信的
  通用运行器。被测代码的**入口文件、语言、解释器与交互协议全部由评分脚本决定**
  （经 `spawn`/`interact` 原语），运行器只负责看管进程、在工作容器内强制执行时限、
  超时强杀。被测代码看不到对手作品与评分脚本，也没有网络，无法内嵌在线 agent。
- 一个**裁判容器**：只挂载评分脚本，保持联网（沿用 Agent Judge 网络），供脚本
  调用 LLM 等外部服务；脚本看不到任何作品文件，只能通过主机 API 间接调用双方。

### 评分脚本协议（隔离模式）

隔离模式下评分脚本**没有路径参数**（`sys.argv` 不含作品目录），改经同目录自动注入的
`elo_host_api` 模块，用一组通用原语驱动每方的受监管进程：

```python
import elo_host_api

# 启动被测进程：入口文件、解释器、参数、环境、工作目录全部自定
elo_host_api.spawn("A", ["python3", "-u", "solver.py"], env={"SEED": "1"})
elo_host_api.spawn("B", ["./main", "--mode", "fast"])       # 编译型二进制同样可以

# 交互：写入数据（可选）并限时读取输出；计时在工作容器内，只覆盖被测进程
r = elo_host_api.interact("A", data='{"turn":1}\n', timeout_ms=1000, until="newline")
# 成功：{"ok": True, "output": "<str>", "elapsed_ms": x}
# 失败：{"ok": False, "error": "timeout|oversize|bot_exited|bot_not_running|...", ...}
# until 支持 "newline"（读一行）/ "eof"（读到进程退出）/ {"bytes": K}（读满 K 字节）

elo_host_api.proc_status("A")     # {"ok": True, "alive": bool, "exit_code": ...}
elo_host_api.kill("A")            # 终止被测进程

# 一次性命令（编译、静态分析等）与产物导出
result = elo_host_api.run_worker("A", ["xelatex", "-interaction=nonstopmode", "main.tex"],
                                 timeout_ms=60000, export_files=["main.pdf"])
# {"ok": True, "exit_code": 0, "stdout": "...", "stderr": "...",
#  "files": {"main.pdf": "<base64>"}, "timed_out": False}

# 不执行命令，直接读取作品文件（单文件 8MiB、合计 16MiB）
elo_host_api.fetch_files("A", ["report.txt"])
```

- `spawn(side, argv, env=None, workdir=None)`：在某方断网工作容器内启动被测进程；
  已有进程会先被终止。**入口与语言不受限**——只要工作容器镜像里有对应解释器/编译器。
- `interact(side, data=None, timeout_ms=1000, until="newline")`：写入数据并限时读取
  输出。**计时在工作容器内部执行**（单调时钟只覆盖被测进程本身），宿主↔容器的通信
  开销不占用比赛时限；`elapsed_ms` 为容器内测得的真实耗时。超时/超限会终止被测进程。
  实测单次交互纯通信开销约 0.3ms（p99 < 1ms），对"每回合 1 秒"级别的时限无影响。
- `kill(side)` / `proc_status(side)`：终止 / 查询被测进程。
- `run_worker(side, argv, timeout_ms, workdir=, export_files=)`：执行受信一次性命令
  并按白名单导出产物（单文件 8MiB、合计 16MiB）。
- `fetch_files(side, paths)`：不执行命令，按白名单读取作品文件（base64 返回）。
- 脚本仍需在 stdout 最后一行输出 `{"winner": 0|1|2, "details": ...}`，输出协议
  与单容器运行时相同。

**兼容封装**：沿用"作品根目录 `bot.py` + `{"ready": true}` 握手 + 换行 JSON 回合"
这一约定的既有评分脚本，可继续用 `call_bot(side, payload, timeout_ms)`、
`wait_ready(side, timeout_ms)`、`bot_status(side)`——它们在内部就是用上述原语实现，
行为与旧版一致（含 `elapsed_ms`、超时强杀与错误码）。新比赛建议直接使用原语。

回合制比赛的完整官方示例见
[elo-isolated 示例]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo-isolated/)
（含比赛参数快照、题目描述与完整评分脚本）。

### 时限与超时配置

- 比赛级 `--script-timeout`（`scoring_script_timeout_seconds`）是**整场对战**的总
  时限（含容器启动与全部回合）。回合制比赛按最坏情况估算：
  `回合上限 × 2 × 单回合时限 + 启动/清理余量`。例如 20×20 棋盘、每方每回合 1 秒，
  建议配置 900 秒左右；超时会按"评测失败"记录（winner=-1，不调分）。
- 运行器启动宽限 30 秒、交互看门狗宽限 2 秒、exec 看门狗宽限 5 秒，可用环境变量
  `ELO_ISOLATED_WORKER_STARTUP_GRACE_SECONDS`、`ELO_ISOLATED_CALL_GRACE_MS`、
  `ELO_ISOLATED_EXEC_GRACE_MS` 调整（见 `docs/runtime-configuration.md`）。

### 运行时切换

```bash
# 两种运行时可按比赛内容互切；评分脚本需与所选运行时的协议匹配
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --elo-runtime-mode isolated --script-timeout 900
python3 "$NUMOJ_ADMIN_SKILL_ROOT/scripts/numoj_admin.py" ranking edit <competition_id> \
  --elo-runtime-mode legacy
```

运行时切换不影响历史对战记录与 ELO 分数；新对战立即按所选运行时执行。

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

## 线上示例

### 比赛 #2 论文摘要挑战赛（单容器运行时）

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/description.md)
- [完整 ELO 评分脚本]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo/scoring_script.py)

这是一个包含实际 ELO 参数和完整评分实现的线上实例。

### 比赛 #11 镜像迷踪（隔离运行时）

- [比赛完整参数与状态]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo-isolated/competition.json)
- [公开题目描述]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo-isolated/description.md)
- [完整 ELO 评分脚本]($NUMOJ_ADMIN_SKILL_ROOT/references/ranking-contests/elo-isolated/scoring_script.py)

回合对抗赛的完整官方示例：题目描述只约定参赛者的输入输出契约，评分脚本经
`elo_host_api` 驱动双方 bot 对局并生成可回放的对战详情。
