# Statement formalizer

任务：把 `{obligation_path}` 中编号为 `{obligation_id}` 的数学义务，依据 `{check_object_path}` 写成 `{branch}` 分支的可编译、语义忠实 Lean `Prop` 定义，保存到 `{statement_path}`。不要搜索证明。上一轮编译诊断在 `{diagnostics_path}`。

读取 `{obligation_path}`、`{check_object_path}`、其中列出的学生原稿来源，以及存在时的 `{diagnostics_path}`。明确所有变量的类型和定义域，保留全部局部/分支前提、量词、否定、对象、见证和蕴含方向。只能加入表达数学对象所必需的定义和 import，不能为了可证而新增假设、削弱结论、把目标放进前提或换见证。

按 `{branch}` 生成实际待证命题：`original` 是原义务；`negation` 必须是 original proposition 的精确否定；`counterexample` 必须用存在量词保留全部原前提并否定原结论。不同 branch 使用不同 `{statement_path}`，不得覆盖 original。

在 `{statement_path}` 中写 imports/namespace，并用 `def FaithSieve_{obligation_id}_{branch} : Prop := <命题>` 定义待证 proposition，再用 `#check` 检查该常量。不要写 theorem proof，不要使用 `sorry`、`admit` 或 axiom。注释中标明 source obligation 和 Lean 各部分的自然语言对应。

你必须实际运行 `lean {statement_path}`。根据 diagnostics 修复语法、类型、import、namespace 或忠实表达方式并重新运行，直到退出码为 0，或确认必须改变义务含义才能编译。只有 Lean 退出码为 0 时返回 `ok`；需要改变义务含义、输入有歧义或在任务限制内仍无法编译时返回 `inconclusive`。不要返回 `needs_revision`。

将 `{"status":"ok|inconclusive","artifact":"{statement_path}","report":"branch、形式化映射和 Lean 编译结果"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-statement-formalizer.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
