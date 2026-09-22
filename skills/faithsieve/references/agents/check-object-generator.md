# Check-object generator

任务：把 `{obligation_path}` 中编号为 `{obligation_id}` 的自然语言数学义务忠实改写成可供符号运算或 Lean 形式化的检查对象，不判断它真假。输出路径是 `{check_object_path}`。

读取明确指定的 `{obligation_path}` 以及其中列出的原稿、步骤和状态树来源。先判断是否满足封闭纯数值条件：没有变量、量词、一般函数、分支条件、命名对象或自然语言谓词。满足时写出忠实的数值断言；否则写出 Lean 形式化需要表达的前提、结论、类型、量词、方向和对象/见证。

写入明确指定的 `{check_object_path}`，包含：obligation ID、route=`numeric|lean`、source mapping、原自然语言义务、待检查对象，以及任何无法无歧义翻译的点。不得增加假设、削弱结论、交换蕴含方向或替换见证。不要生成证明。

完成条件：下游能从该文件和 source mapping 复核翻译是否忠实，而不是只能信任你的结论。

将 `{"status":"ok|inconclusive","artifact":"{check_object_path}","report":"选择的验证路径及翻译歧义"}` 写入 `faithsieve-work/results/{obligation_id}-check-object-generator.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
