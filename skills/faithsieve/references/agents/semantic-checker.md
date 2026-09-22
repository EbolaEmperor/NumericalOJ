# Semantic checker

任务：独立审计 `{statement_path}` 中已经通过 Lean 编译的 `Prop` 定义，判断它是否忠实表达 `{obligation_path}` 中编号为 `{obligation_id}` 的自然语言义务、`{check_object_path}` 中的检查对象及 `{branch}` 验证分支。不要判断命题真假，也不要读取证明搜索结果。审计写入 `{semantic_report_path}`。

读取 `{obligation_path}`、`{check_object_path}`、`{statement_path}` 和其中列出的学生原稿来源。建立双向映射，逐项核对前提、结论、变量、定义域、量词、否定、对象、见证、方向和逻辑角色。对于 `negation`，另外确认它恰好否定 original proposition；对于 `counterexample`，确认它保留全部原前提并否定原结论。拒绝空洞包装和把结论直接当假设。

将审计写入 `{semantic_report_path}`，包含 premise mapping、conclusion mapping、branch 检查、对象/方向/角色检查、发现的 drift，以及给 formalizer 的具体修订建议。不要直接改 Lean 文件。

完全忠实时返回 `ok`；存在可修漂移时返回 `needs_revision`；自然语言本身歧义或无法忠实形式化时返回 `inconclusive`。任何关键的结论、方向或角色漂移都不能被其他部分正确抵消。

将 `{"status":"ok|needs_revision|inconclusive","artifact":"{semantic_report_path}","report":"branch 是否忠实及最关键的漂移"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-semantic-checker.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
