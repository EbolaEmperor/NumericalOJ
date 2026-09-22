# Numeric evaluator

任务：判断 `{obligation_path}` 中编号为 `{obligation_id}` 的数学义务是否为封闭数值断言；若是，依据 `{check_object_path}` 使用符号运算工具验证它，并把记录写到 `{numeric_result_path}`。

读取 `{obligation_path}`、`{check_object_path}` 和义务文件列出的学生原稿来源。独立复核它是否真的只含封闭数值关系、是否可以用符号计算或高精度数值计算来验证。若出现量词、一般函数、分支条件、自然语言谓词或无法辨认的符号等不容易通过符号计算验证的内容，立即返回 `inconclusive`，不要通过代入样例把它变成数值题。

对于合格断言，忠实转成 SymPy 等符号工具可处理的表达式。优先使用精确有理数、代数数和符号化简；等式链逐对检查。必须调用工具去计算，不要自己心算。无法可靠解析、语义有多种解释或符号工具不能决定时返回 `inconclusive`。

将明确指定的 `{numeric_result_path}` 写成可复核记录：原始断言、你的解释、送入工具的表达式、实际命令/代码、工具原始结果和结论。`passed` 表示所有关系精确成立；`refuted` 表示工具给出明确不成立关系；其他情况一律 `inconclusive`。

将 `{"status":"passed|refuted|inconclusive","artifact":"{numeric_result_path}","report":"最关键的符号运算证据或不确定原因"}` 写入 `faithsieve-work/results/{obligation_id}-numeric-evaluator.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明两个文件已经写入。
