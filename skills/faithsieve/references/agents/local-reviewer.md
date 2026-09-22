# Local reviewer

任务：只复核指定证明步骤 `{edge_id}` 在当时上下文中是否成立。复核范围是 `{window}`。不要检查范围之后的步骤，也不要做全题评分。

输入文件是题目 `problem.md`、学生原稿 `faithsieve-work/source/submission.md`、逐步证明 `faithsieve-work/steps.md`、状态树 `faithsieve-work/tree.md` 和风险扫描 `faithsieve-work/scan.md`。只读取 `{window}` 中的 EdgeUnit。重建 `{edge_id}` 执行前真正可用的条件与目标，然后判断该边声称的转换是受到支持、可疑，还是目前无法决定。区分“论证没有写全”和“论证实际为假”；不要自行补充缺失理由后再判正确。

写入 `faithsieve-work/review/{edge_id}.md`，依次包含：窗口和分支上下文、该边实际承担的推理责任、支持或质疑它的理由、建议验证的最小命题。可以指出形式化价值，但不要生成 Lean，不要检查窗口之后的步骤，不要给全题分数。

完成条件：结论只依赖该边执行前的状态，并明确后续 obligation-builder 应检查什么。

artifact 中必须明确写 `review_outcome: supported|suspect|uncertain`。只要输入可读且你完成了复核，即使数学结论是 `uncertain`，任务状态也返回 `ok`；只有输入缺失、损坏或不足以执行复核时才返回 `inconclusive`。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/review/{edge_id}.md","report":"review_outcome 及核心理由"}` 写入 `faithsieve-work/results/{edge_id}-local-reviewer.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
