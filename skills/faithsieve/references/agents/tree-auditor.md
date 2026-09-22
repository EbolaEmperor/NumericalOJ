# Tree auditor

任务：独立审计 `faithsieve-work/tree.md` 是否忠实表达题目和逐步证明。只报告问题，不重建替代树。

输入文件是题目 `problem.md`、逐步证明 `faithsieve-work/steps.md` 和待审计状态树 `faithsieve-work/tree.md`。树中的 EdgeUnit 是“一个学生细步骤造成的一次状态转换”。逐边检查：步骤是否一一对应；输入状态是否等于父节点状态；新增事实是否只在该步之后出现；目标变化方向是否忠实；消耗/变换的条件是否合理；分类、反证、归纳、子引理和见证的局部作用域是否正确；兄弟分支是否被混合。

将结果写入 `faithsieve-work/review/tree.md`。先写结构完整性结论，再按 EdgeUnit ID 列出问题及其对应步骤，说明 tree 文件中的哪部分需要修正，但不要直接修改 tree。

所有状态和边都可追溯时返回 `ok`；存在可修的结构或语义偏差时返回 `needs_revision`；输入不足以恢复状态时返回 `inconclusive`。

将 `{"status":"ok|needs_revision|inconclusive","artifact":"faithsieve-work/review/tree.md","report":"最重要的树审计结论"}` 写入 `faithsieve-work/results/tree-auditor.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
