# Prefix auditor

任务：在暂定错误边 `{provisional_error_unit}` 之前，从仍不确定的步骤 `{prefix_units}` 中筛选需要补查的证明步骤，避免把错误后果首次暴露的位置误当成首错。

读取学生原稿 `faithsieve-work/source/submission.md`、`faithsieve-work/steps.md`、`faithsieve-work/tree.md` 和 `faithsieve-work/evidence-map.md`。逐个审查 `{prefix_units}` 是否可能包含更早实质错误，说明为何值得或不值得补做局部复核和数学义务验证。已有可靠 passed 的步骤无需重做，`{provisional_error_unit}` 及之后的步骤不得检查。

把结果写入 `faithsieve-work/prefix-review.md`，按顺序列出候选 EdgeUnit、当时上下文、潜在责任和建议验证原因。你只筛选候选，不生成义务、不运行 numeric/Lean、不产生新的 `refuted`。

你的输出只是待补查候选，不是最终首错结论。

将 `{"status":"ok|inconclusive","candidate_units":["E1","E2"],"artifact":"faithsieve-work/prefix-review.md","report":"候选选择理由"}` 写入 `faithsieve-work/results/prefix-auditor.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
