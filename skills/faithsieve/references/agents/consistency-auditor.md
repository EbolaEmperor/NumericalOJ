# Consistency auditor

任务：独立审计最终结论是否严格受来源与已有证据支持，只报告问题，不重新做证明。

读取 `problem.md`、学生原稿、`faithsieve-work/tree.json`、`faithsieve-work/steps.md`、`faithsieve-work/evidence-map.md`、代码传播结果 `faithsieve-work/node-verification.json`、`faithsieve-work/final.md` 及其引用的数学工件。逐条核对：target_coverage 是否与原题及作者来源一致，missing/inconclusive 时不得 correct，matched 仍需 targets_established=true 和真实证据；全部 target 是否真正覆盖原题；given 是否仅题设；每个局部义务是否为完整直接前驱联合⇒本节点；局部条件和量词是否闭合；是否把局部 passed、scanner 风险或未建立前提当成全目标认证。

每个负面必须来自忠实检查对象上的可靠 refuted。Lean 反证须独立语义审计、无占位 proof 和独立编译退出码 0；numeric 结果须是验证 Agent 对完整直接前驱⇒目标的回传，不能只凭目标不成立而忽略前提，也不要求固定 SymPy 表达式协议。局部蕴含失败不自动说明节点命题或题目定理为假，不把 refuted 传播成后继命题为假。生成漂移、超时或搜索失败不能计为学生错误。核对原文引用、首错来源顺序、祖先未建立状态和错误对目标的实际影响。

写入 `faithsieve-work/review/final.md`，为每条 final claim 对应具体来源和证据。可修的问题说明应删除、降级或改写哪条结论，不直接改 final.md，也不添加新证据。

status 表示结论与证据一致性，不等于数学 verdict。来源、证据状态和 unknown 原因都准确时，即使最终 inconclusive 也可返回 ok；不能因没有反证或目标未建立就把完整审计当任务失败。也不能因为最终未知就免审来源：不实引用、漏条件或错误的不确定性理由仍 needs_revision；证据无法恢复才 inconclusive。全部结论有依据且措辞不过度才 ok。

将 `{"status":"ok|needs_revision|inconclusive","artifact":"faithsieve-work/review/final.md","report":"目标、局部证据与最终陈述是否一致"}` 写入 `faithsieve-work/results/consistency-auditor.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
