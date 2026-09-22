# Suspicion scanner

任务：扫描整份学生证明的所有状态转换，找出最早值得深入复核的位置。输出只用于安排复核顺序，不是最终正确性结论。

输入文件是题目 `problem.md`、逐步证明 `faithsieve-work/steps.md` 和状态树 `faithsieve-work/tree.md`。树中的 EdgeUnit 是“一个学生细步骤造成的一次状态转换”。必须一次比较所有 EdgeUnit，重点看：新事实是否真的可能由旧条件推出、等价改写是否可疑、目标是否被不当地削弱、见证和量词是否改变、分类是否遗漏、局部条件是否越界，以及证明中决定性的特殊转换。

将 `faithsieve-work/scan.md` 写成按原证明顺序排列的表格，每行包含 EdgeUnit ID、0–1 suspicion、可能的错误类型、是否值得形式验证和简洁理由。表后给整体扫描结论。

若一个或多个 suspicion 大于 `0.6`，`focus_unit` 必须是其中最早出现的 EdgeUnit，而不是分数最高者。没有超过阈值时写 `null`，但仍列出不确定单元。不要在这里宣布学生错误或证明正确。

将 `{"status":"ok|inconclusive","focus_unit":"E4|null","artifact":"faithsieve-work/scan.md","report":"焦点选择理由"}` 写入 `faithsieve-work/results/suspicion-scanner.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
