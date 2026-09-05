# Claude 续聊后残留子任务阻塞结束：调查与修复

调查日期：2026-09-05。下文时间均为北京时间；原生 JSONL 的时间戳为 UTC。

结论：本次长时间不结束的直接原因是 NumOJ `run_harness` 的自定义等待逻辑。
Claude Code 已识别旧 workflow 停止，并完成恢复后的工作；包装层却将历史 journal 中
没有结束记录的子任务继续视为运行中。证据支持“历史任务状态残留”，不能据此认定存在
操作系统意义上的 zombie 进程；旧任务的 PID 存活从来不是包装层的判断依据。

## 取证范围与文件

- NumOJ session：`4965e758114947fa848f6ada1a59046c`。
- 第一轮 task：`4965e758114947fa848f6ada1a59046c`。
- 第二轮 task：`9e55d2c611994097afb4e8620005f717`。
- Claude session：`7647d124-ade8-4d3e-a744-b48731cf3fda`。
- Workflow run：`wf_7f2b5de5-1a0`。
- 生产 checkout：`15e7f93ebcda6b62f3b329910fb36ffa9d9eb25a`。
- 原生 trace 记录的 Claude Code 版本：`2.1.205`。

通过 `ssh why-server` 确认主机为 `computing`，只读下载原生 project、两轮规范 trace
和生产 `run_harness`；仅对这两个 task 和对应 session 执行 SELECT，使用日志管理入口
只读导出关联事件。未修改生产数据、运行测试、部署或重启生产服务。

本地证据在 Git 忽略的 [调查目录](../../tmp/agent-investigation-4965e758/)：

- [原生 trace 压缩包](../../tmp/agent-investigation-4965e758/claude-project.tar)。
- [两轮规范 trace 与生产脚本](../../tmp/agent-investigation-4965e758/turn-traces.tar)。
- [父会话 JSONL](../../tmp/agent-investigation-4965e758/7647d124-ade8-4d3e-a744-b48731cf3fda.jsonl)。
- [文件长度与 SHA-256 清单](../../tmp/agent-investigation-4965e758/evidence-manifest.json)。

下载的生产脚本与修改前本地脚本逐字节相同，SHA-256 为
`9acc3bb60876f653942b63d3f72c184d5ff5759c8515f5253bc461773745ab0e`。
原始会话内容仅留在本地调查目录，不加入版本控制。

## 证据链

| 时间 | 已核验事实 | 证据 |
| --- | --- | --- |
| 02:10:14 | 第一轮创建 | `agent_session_turns` / `agent_task_runs` SELECT |
| 02:42:27 | 第一轮 Failed，错误为 `Agent harness 运行失败：Agent workspace 总大小不能超过 536870912 字节` | `agent_task_runs.message` SELECT |
| 04:19:09 | 第二轮复用原生 session 创建 | `agent_session_turns.base_native_session_id` SELECT |
| 04:19:12.118 | Claude 对旧 workflow `wkqxr0x6a` 发出 `stopped` 通知，说明上次退出后没有完成记录，可以用 `resumeFromRunId` 恢复 | 父 JSONL 第 20 行 |
| 04:19:41.044 | 父 agent 调用 `Workflow` 恢复原 run | 父 JSONL 第 33 行 |
| 04:20:03.638 | 前一次恢复漏传 args，父 agent 补参数后重新恢复；本次任务 ID 为 `w2jlr94tk` | 父 JSONL 第 41—42 行 |
| 05:11:54.922 | Claude 原生通知 `w2jlr94tk` 为 `completed` | 父 JSONL 第 63 行；workflow 结果文件也已落盘 |
| 05:14:05.428 | 父 agent 给出完整最终答复，报告文件此前已成功写入 | 父 JSONL 第 76—81 行；第二轮规范 trace 第 329 行 |
| 09:32:03 | 第二轮被手动停止，状态 Canceled | `agent_task_runs`、`agent_sessions` SELECT |
| 09:32:05.884 | 原生会话收到了包装层注入的英文自动续跑消息 | 父 JSONL 第 84 行；文字与旧脚本内部 continuation 完全一致 |

Workflow journal 共 327 行。第一轮结束时已有 139 行，包含 80 个 `started` 和 59 个
`result`；剩余 188 行来自本次续跑，包含 94 个 `started` 和 94 个 `result`。
按 agentId 汇总后，最终恰有 21 个未闭合的 `started`，全部属于第一轮。
这些 agent 的 transcript 最后时间都在 02:42:26.004 及以前，本轮没有继续写入。

例如 `a179b04ef40aa2a2d` 在 journal 第 98 行启动，最后活动为 02:42:25.928；
`ac8e2f12ccda14135` 在第 139 行启动，最后活动为 02:42:26.004。
它们均无对应 result。当前轮的 94 个 agent 均已闭合。

旧 `_claude_subagent_snapshot()` 从整个 session 的 journal 读取 `started/result`，
按 agentId 将未闭合项标记为 `running`。旧 `_run_claude_interactive()` 收到 result 后，
以 `active_subagents or background_launch_observed` 决定继续等待；有任意 running
时取消结束条件，且没有将这 21 个旧记录排除。该逻辑由提交 `d474587` 引入，目的是
避免后台 Workflow 在父模型第一条阶段性 result 后被提前销毁。

原生 JSONL 和规范 trace 没有完整保存 SDK 的 result/control/state 帧，因此不能宣称
下载了 05:14 当时的原始 result 或 idle 帧。归因基于上述持久化证据、逐字节一致的
生产脚本，以及下面的离线重放和真实 CLI 联调。

## 原生架构已经具备所需判断

当前官方 [headless 文档](https://code.claude.com/docs/en/headless#background-tasks-at-exit)
说明 Claude 自行管理后台 subagent/workflow 的收尾。
[SDK 更新记录](https://github.com/anthropics/claude-agent-sdk-typescript/blob/main/CHANGELOG.md)
说明 `session_state_changed` 自 0.2.83 起需显式开启。
不能把父模型的一个 result 或任意默认 idle 单独等同于所有后台工作结束。

本次另从官方 npm 下载了固定版本 `@anthropic-ai/claude-code-linux-arm64@2.1.205`，
核对其原生实现和 schema，而非根据最新版文档推测旧版本行为：

- `session_state_changed` 支持 `running`、`requires_action`、`idle`。
- `CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS=1` 开启该事件。
- 2.1.205 的原生等待函数 `Tdm` 在
  `CLAUDE_CODE_BG_TASKS_REPORT_RUNNING=1` 时，若仍有后台任务、teammate 或待处理通知，
  不发出等待阶段的 idle。这个开关让 CLI 自身将后台工作计入 running。
- `background_tasks_changed` 则是原生进程当前活跃任务集合的完整快照，不能从历史
  transcript 重建它。NumOJ 无需再复制这套存活判断。

在本机禁网、只读根文件系统、非 root 的 Linux 容器中，运行同版本真实 CLI，
用容器内假 Anthropic 端点返回确定性响应，让真实 Workflow 启动一个子 agent。
未调用生产或任何外部模型。

| 原生配置 | 实际事件顺序 |
| --- | --- |
| 只开启状态事件 | running → 后台任务启动 → `result: PARENT_WAIT` → idle → 子任务完成 → running → `result: FINAL_DONE` → idle |
| 同时开启后台任务计入 running | running → 后台任务启动 → `result: PARENT_WAIT` → 子任务完成 → `result: FINAL_DONE` → idle |

第二种配置下，父模型收集子任务结果并继续，是 Claude 自己的任务通知机制完成的。
NumOJ 没有插入额外提示、延迟计时器或自行等待 journal。
完整事件见 [默认原生事件](../../tmp/agent-investigation-4965e758/native-default-events.json)
及 [开启原生后台状态后的事件](../../tmp/agent-investigation-4965e758/native-smoke-result.json)。

## 最终修改

[run_harness](../../docker/agent_judge/run_harness) 的交互 Claude adapter：

1. 显式开启上述两个原生开关，保持 stream-json 双向控制通道。
2. result 只记录结果和用量；由原生 idle 宣告正常轮次结束。启动阶段尚无 result 的
   idle 不会吞掉用户请求；错误结果后直接 EOF 仍按失败处理。
3. 删除基于后台工具名、journal running 状态、发现宽限期和静默时长的结束判断，
   删除 `All background subagents ...` 自动续跑消息。
4. journal/transcript 仅作详情展示，启动前记录文件边界以隐藏未续写的历史子任务；
   即使展示侧仍标记 running，也不能否决原生 idle。
5. 无 session ID 的控制帧不再清空已知 session。保留用户插话回执、interrupt 回执及
   收尾时有限等待控制回执的既有契约。

没有删除、修改或回填原生会话历史，也没有改变 Claude 版本、模型提示词或调研工作流。
未来升级 CLI 应重跑原生生命周期联调，核对两个原生状态开关的契约。

## 验证与限制

- Python 3.12 编译检查通过；完整单元测试 **3385 passed**。
- Harness 专项 **87 passed**，覆盖真实续跑展示、原生 idle 否决残留 running、启动 idle、
  缺少 idle 的异常 EOF、停止后无自动 continuation、插话和用量。
- 前端 typecheck、70 个 Vitest、75 个 Node 测试及 build 通过。
- [离线证据重放](../../tmp/agent-investigation-4965e758/replay.py) 使用下载的真实 journal
  和 transcript、重建两轮文件边界，并模拟 result/idle：旧生产脚本无视 idle，继续
  读取直到模拟 EOF 才失败；修复脚本在原生 idle 返回 0。它不是对历史 SDK 帧的逐帧回放。
- [真实 adapter 联调](../../tmp/agent-investigation-4965e758/native-adapter-result.json)：
  同版本真实 Claude CLI + 修改后的 run_harness，额外注入始终 running 的展示记录，
  仍完整输出 `PARENT_WAIT`、`FINAL_DONE` 并于原生 idle 返回 0。
- 尝试按正式 Dockerfile 重建 agent_judge-lite，但本机缺少前置
  `numericaloj-lean4:latest`，构建在第一阶段失败，尚未完成整套镜像构建。
  上述真实 CLI 联调使用独立的本地 Python 3.12 Linux 容器，不能替代全工具链镜像验证。
- 未部署生产；现有 Canceled/Failed 记录保持原样。正式生效需要后续按部署入口重建镜像并发布。
