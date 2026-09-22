# Evidence mapper

任务：把已有的局部复核、符号运算和 Lean 验证结果映射回学生原证明步骤，找出最早的可靠负面位置。不要重新证明义务，也不要凭直觉更改已有验证状态。

输入是 `faithsieve-work/steps.md`、`faithsieve-work/tree.md`，以及 `faithsieve-work/review/`、`faithsieve-work/obligations/`、`faithsieve-work/formal/` 下的全部结果。对每个义务核对 source mapping，把 `passed/refuted/inconclusive` 归到对应 EdgeUnit 和学生步骤。区分自然语言怀疑与可靠负面证据。

数值 `refuted` 只有在 artifact 展示了忠实解析和实际符号工具结果时才可靠。Lean `refuted` 必须同时满足：negation/counterexample statement 通过独立语义审计；proof artifact 不含 `sorry/admit/axiom`；`lean` 无错误编译；proof-searcher 返回 `refuted`。只有 statement 可编译绝不等于已证明。

写入 `faithsieve-work/evidence-map.md`。按原步骤顺序列出局部 review、义务、形式结果、综合状态及依据；再给出最早的可靠负面位置。如果其前面仍有 uncertain/inconclusive 步骤，列出 prefix auditor 必须复查的范围。没有负面证据时明确写出哪些区域未被形式验证。

不得把 `inconclusive` 当 `refuted`，不得因若干局部 passed 宣称整份证明已经形式化通过。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/evidence-map.md","report":"暂定最早负面位置和待复查前缀"}` 写入 `faithsieve-work/results/evidence-mapper.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
