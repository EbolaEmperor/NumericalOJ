# FaithSieve 书面证明评测

本项目依据 Wang、Dai、Wu、Wen 的 *FaithSieve: Fine-Grained Evaluation of Math Proofs with Faithful Formal Evidence*（arXiv:2608.26310v1）实现手动书面题的辅助批改。论文原文：https://arxiv.org/html/2608.26310v1

管理员从纯人工批改书面题的题目页或提交详情页启动评测。后端创建 `judge` 类型的通用 Agent 会话，把 `skills/faithsieve/` 投影到 runtime；镜像提供 PDF/OCR、Lean 4、固定 mathlib 和受限数值检查依赖，无需宿主 Lean 服务。

skill 不是一个单 Agent 提示词，而是论文流程的编排器。它强制派出彼此隔离的子 Agent，依次完成忠实拆分与审计、证明状态树与审计、全树风险扫描、局部复核、义务生成、独立语义检查、证明搜索、证据融合、必要时的前缀复查和最终一致性审计。自然语言写入一个 `report` 字符串，只有状态、分数、ID 和工件路径等需要程序处理的值才单列 JSON 字段。

数值验证仅覆盖封闭的数值等式链和单个比较。数值子 Agent 对照原稿忠实理解实际数学记法，再使用 SymPy 等工具做符号运算；实现不预设固定字符串 grammar，也不维护自定义数值解析器。含变量、一般函数、量词、分支条件，或无法可靠解析和精确决定的命题返回 `inconclusive`。Lean 路径严格分成命题编译、独立语义检查和证明搜索；搜索失败不等于反驳。

批量入口只选择本题每个用户名下 ID 最大的一条提交。`faithsieve_grading_runs` 保存排队、运行和终态；领取名额时使用 MySQL 命名锁，全站最多同时运行 20 条。每个控制任务等待 Agent 结束后读取 `faithsieve_result.json`，验证最小协议，再把确定性结论写回提交。基础设施失败、无效结果或 `inconclusive` 不覆盖原成绩。

最终结果仍只含 `verdict`、`score`、`comment`。论文方法先产出正确性或最早实质错误，0–5 分是 NumOJ 的后置适配；首错、局部义务、形式证据与不确定性全部写入 `comment`。论文没有公开语义门最终阈值、关键项阈值、证明/反证预算或数值容差，实现不得自行猜测。尤其 `τ` 未由 runtime policy 显式注入时，对应 Lean 义务只能记为 `inconclusive`；这是避免伪造论文参数的已知覆盖率限制。
