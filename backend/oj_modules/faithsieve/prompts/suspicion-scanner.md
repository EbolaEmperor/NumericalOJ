# Suspicion scanner

任务：扫描全部待证命题的直接依赖关系，标注可能的数学风险，不作最终数学判断。

读取题面 `problem.md`、原稿 `faithsieve-work/source/submission.md`、拆分 `faithsieve-work/steps.md` 与命题 DAG `faithsieve-work/tree.json`。逐一核对全部 claim，局部责任为其全部直接前驱 statements 联合推出该节点 statement。重点看遗漏条件、域与量词、见证依赖、分支覆盖和未绑定符号；given 的身份不能由风险评分决定。

将 `faithsieve-work/scan.md` 写成按 nodes 中全部 claim 原顺序排列的表格：node_id、0–1 suspicion、uncertain、可能的问题类型与简洁理由。每个 claim 恰好一行。风险只作标注，按稳定拓扑顺序审核所有 claim，同层按原 nodes 顺序，不据风险重新排序；没有阈值裁剪、焦点窗口或以低风险替代实际验证。

`focus_unit` 表示关注的 claim ID，选择最高风险，平分时取原稿顺序较早者；全部无特别疑点时可为 null。仍完整列出所有节点，不在此宣布推理错误、命题为假或证明正确。

将 `{"status":"ok|inconclusive","focus_unit":"N4|null","artifact":"faithsieve-work/scan.md","report":"风险标注与完整覆盖情况"}` 写入 `faithsieve-work/results/suspicion-scanner.json`。完整扫描可以返回 ok，即使数学仍不确定。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
