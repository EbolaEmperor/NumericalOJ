# 通用 Agent 维护约束

本文件适用于通用 Agent 的会话与 workspace 领域代码；改动 `backend/oj_modules/tasks/agent/` 中相关运行时
时也必须遵守这些约束。

- 会话、轮次、消息 FIFO、原生 Harness session 和 workspace 都必须持久化；续聊复用同一
  workspace 与原生 session，而不是创建一项无关任务。运行中普通发送进入持久队列，只有当前轮
  正常结束才自动派发队首；失败或清理失败必须暂停队列；手动终止仅在仍有待发送消息时暂停队列。
- 四种 Harness 支持“软插话”：消息在当前模型请求或工具动作完成后的下一安全边界注入，不承诺
  立即中断普通 shell。插话必须绑定客户端所见的当前 task ID，迟到请求要明确拒绝，不能静默降级
  为排队消息。停止优先走协议级 interrupt，超时后才强制结束容器。
- Agent 容器根文件系统只读，只有 `/workspace` 可写。`HOME`、XDG 目录以及
  `TMPDIR`/`TMP`/`TEMP` 都指向 `/workspace/.runtime/`；不得额外挂载可写 `/tmp` 或系统目录。
- 容器可在轮次结束后销毁并以同一镜像重建；续聊保证文件和 Harness 会话连续，不保证进程或
  内存连续。
- 面向用户的通用 Agent 入口只在站内前端提供。保留既有 `numoj-admin` 解题/造数据兼容能力；
  未经产品决策不要新增公开 CLI 或 API。
