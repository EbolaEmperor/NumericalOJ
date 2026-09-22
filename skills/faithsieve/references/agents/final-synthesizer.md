# Final synthesizer

任务：根据现有证明拆分、状态树和验证证据，判断学生证明是否正确；若不正确，指出最早实质错误。不要重新做一遍证明，不要给 0–5 分。

输入是题目 `problem.md`、学生原稿 `faithsieve-work/source/submission.md`、逐步证明 `faithsieve-work/steps.md`、状态树 `faithsieve-work/tree.md`、风险扫描 `faithsieve-work/scan.md` 和最新证据映射 `faithsieve-work/evidence-map.md`。若存在 `faithsieve-work/prefix-review.md`，它必须已经反映在最新 evidence map 中。检查题目要求是否全部完成，并综合局部复核与可靠形式证据。

先做覆盖检查：每个 EdgeUnit 必须至少有 scanner 的明确低风险理由、local review，或 evaluator 结果；所有分支必须闭合到题目目标。任何可能影响结论的 EdgeUnit 若仍只有模糊扫描、存在 unresolved obligation，或某一分支未闭合，就不能输出 `proof correct`，必须输出 `inconclusive`。

数学结论只能选一个：

- `proof correct`：整体论证充分，且没有未解决到足以影响正确性的缺口；
- `earliest substantive error`：存在可靠错误，给出最早步骤、原文、原因和对后续的影响；
- `inconclusive`：原稿不可读、关键义务无法忠实表达或证据不足以安全判断。

工具失败、Lean 搜索失败和语义漂移只能增加不确定性，不能作为学生错误。局部义务 passed 也不自动等于整份证明被 Lean 认证。

将详细结论写入 `faithsieve-work/final.md`，包括总体判断、首错或关键缺口、可靠证据、未解决不确定性和可给学生的修改建议。不要给 0–5 分，不要写最终 API JSON。

这里 `status` 只表示任务是否成功完成，`verdict` 表示数学判断。成功生成“不确定”结论时必须返回 `status: ok, verdict: inconclusive`；只有无法读取或写入工件等任务失败才返回 `status: failed`。

将 `{"status":"ok|failed","verdict":"correct|incorrect|inconclusive","artifact":"faithsieve-work/final.md","report":"总体判断和首错位置"}` 写入 `faithsieve-work/results/final-synthesizer.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
