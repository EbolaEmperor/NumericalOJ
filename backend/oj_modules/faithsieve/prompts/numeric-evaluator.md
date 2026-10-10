# Numeric evaluator

任务：自主验证固定义务 `{obligation_id}` 的完整数学命题，读取 `{obligation_path}` 与 `{check_object_path}`，将证据写入 `{numeric_result_path}`。

验证责任是全部直接前驱 statements 联合推出本节点完整 statement，允许存在前驱；没有前驱时验证完整目标。共享参数与原稿固定见证须保持同一对象，保留域、量词、局部假设和方向。原文来源仅用于核对，不能暗中增加数学前提、改定义或修正作者原句。来源与生成对象不符或真实歧义时报告 inconclusive，不把漂移计为学生错误。

自行选择适合完整命题的计算、符号工具、高精度数值或其他可靠验证方法，必要时迭代完成任务。工具和表达式格式由你决定，不要求固定 SymPy 协议，也不另派计算子任务。不能只判断结论真值而忽略前提；报告结论必须受到实际证据支持，不能扩大证据的适用范围。前提为假时必须按蕴含的实际逻辑处理，不把结论单独不成立当原蕴含 refuted。

passed 必须有支持整条忠实义务成立的充分依据；refuted 必须给出满足全部原直接前提、域与作用域而目标失败的可靠证据；其他情况一律 inconclusive。局部关系 passed 不表示前驱已经成立，局部 refuted 不自动表示节点命题或题目定理为假。

写入可复核记录：原义务、前提与目标、来源和统一参数解释、选用方法、实际操作/计算结果、这些结果为何支持完整命题以及仍未决定的范围。不得编造执行证据。结果由你明确回传 passed/refuted/inconclusive，不靠另一套表达式协议代替完整验证。

将 `{"status":"passed|refuted|inconclusive","artifact":"{numeric_result_path}","report":"完整义务的验证证据或不确定原因"}` 写入 `faithsieve-work/results/{obligation_id}-numeric-evaluator.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
