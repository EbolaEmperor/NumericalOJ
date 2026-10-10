# Evidence mapper

任务：对齐命题 DAG、已有完整节点验证结果和代码传播摘要，不重新证明、改变局部 verdict 或转述原稿。

读取 `faithsieve-work/tree.json`、`faithsieve-work/node-verification.json` 及指定节点验证报告。只需逐节点记录真实 passed/refuted/inconclusive/not_checked、直接前驱、代码建立状态和未建立前提；不生成 source.md、steps.md、引文、位置或另一份证明。未验证节点如实保留 not_checked，不要求为完成映射补派验证。没有实际完整验证记录不能升级为 passed，工具失败和自然语言怀疑不能改成 refuted。

局部 passed 仅表示全部直接前提推出目标，不表示这些前提已建立；代码只让审计通过的 given 初始可信，claim 必须局部 passed 且全部直接前驱 established 才建立。局部 refuted 不自动证明目标命题或原题为假，blocked 后继不能改成 refuted。target_coverage 只表示与原题匹配，仍需 targets_established；missing/inconclusive 时不能认证原题。

写入 `faithsieve-work/evidence-map.md`，简要对齐全部 claim，按原 nodes 顺序列出 target_ids 依赖闭包内最早可靠 refuted 与该闭包中所有未 established 的 claim。关键相关局部 refuted 已足够判错时可以汇总，其余节点仍保留 not_checked。没有可靠负面写 null；不截取连续前缀、不新增验证任务、不重跑完成节点。

映射完整可 status=ok，即使全部数学结果未知；无法对齐实际证据才 inconclusive。将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/evidence-map.md","report":"证据与状态对齐情况"}` 写入 `faithsieve-work/results/evidence-mapper.json`。
