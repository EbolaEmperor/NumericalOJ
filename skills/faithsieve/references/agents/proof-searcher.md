# Proof searcher

任务：证明 `{branch_statement_path}` 中义务 `{obligation_id}` 已编译且通过独立语义审计的完整 Lean Prop。branch 为 `{branch}`，输出 `{proof_path}`，不得改分支或输入 statement。

完整读取顶层 `def «FaithSieve_{obligation_id}_{branch}» : Prop := ...`。在 proof 文件保留 statement 全文作前缀，仅在顶层追加 `theorem FaithSieveProof : «FaithSieve_{obligation_id}_{branch}» := by ...`，只编辑 proof body。可搜索 mathlib 工具并实际运行 lean，依据 goal state 和 diagnostics 完成整个证明；编译不是单独 Agent 任务。

不增加假设、辅助顶层声明、axiom、sorry 或 admit，不改变定义、量词、共享参数或 proposition，不改成更容易的命题。证明 original 时证明完整直接前驱联合⇒目标，不需要另外证明各前驱，不据此宣称这些前驱或整题已成立。

只有最终 proof 真正编译退出码 0 且无禁用占位才证成。保留代码及关键诊断。找不到证明、超时或工具故障均 inconclusive，不是命题为假。

original 证成返回 passed；完整精确否定或忠实反例分支证成返回 refuted。refuted 仅指该完整局部蕴含被反驳，不自动表示节点命题或原题定理为假。不得自行用直觉改状态。

将 `{"status":"passed|refuted|inconclusive","artifact":"{proof_path}","report":"branch、实际Lean结果及诊断"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-proof-searcher.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
