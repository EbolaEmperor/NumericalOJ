# Proof searcher

任务：证明 `{branch_statement_path}` 中义务 `{obligation_id}` 已经通过编译和独立语义审计的 Lean proposition。验证分支是 `{branch}`，证明文件写入 `{proof_path}`。不得改搜另一分支，也不得修改输入 statement 文件。

完整读取 `{branch_statement_path}` 中的 `def ... : Prop := ...`。在 `{proof_path}` 写入使该 proposition 可用的相同 imports/定义，再写 `theorem FaithSieveProof : <Prop 名> := by ...`，只编辑这个 proof body。实际运行 `lean`，依据 goal state 和 diagnostics 迭代。不得加入 `axiom`、`sorry`、`admit`，不得增加前提、修改 proposition 或另写更容易的命题。

只有 `{proof_path}` 最终由 Lean 无错误编译且文件不含禁用占位时才可报告证成。保留最终代码和关键 diagnostics。找不到证明、超时或工具故障都是 `inconclusive`，不是该命题为假。

状态由指定 branch 决定：original 被证成返回 `passed`；精确否定或有效反例 branch 被证成返回 `refuted`。不要自行根据直觉选择状态。

将 `{"status":"passed|refuted|inconclusive","artifact":"{proof_path}","report":"branch、Lean 编译结果和遗留 diagnostics"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-proof-searcher.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
