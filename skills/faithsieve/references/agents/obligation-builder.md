# Obligation builder

任务：核对 claim `{node_id}` 的固定主义务说明，不改变节点、前驱或验证责任。

读取本节点与全部直接前驱的完整命题、必要题面及学生原文来源。唯一义务为“全部直接前驱 statements 联合推出本节点 statement”，ID 固定 `{node_id}-O1`、路径 `faithsieve-work/obligations/{node_id}/{node_id}-O1.md`。没有前驱时，责任是证明节点完整命题，不能把该 claim 当 given。

义务由编排代码确定，新工作流不需要派发本角色生成或拆分。若作为资料核对使用，只核对固定责任与原文来源，不另造 O2、桥梁子任务、依赖 ID 或更易验证的命题。给定条件只来自题面；前驱 claim 仅是局部蕴含的条件，不代表其已经成立。局部假设、域、量词及见证依赖必须完整封装，不增加、删掉或改写它们。

上游表示与原文不符时返回 `inconclusive` 并指出来源，不能修原稿或把生成漂移计为学生错误。保持定义、类型、量词、否定及方向；缺来源的新增前提不能靠约定或解释选择获得认证，忠实表达不了原责任则明确不确定。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/obligations/{node_id}/index.md","report":"固定主义务的来源核对"}` 写入 `faithsieve-work/results/{node_id}-obligation-builder.json`。不得增加其他义务。确认 JSON 可解析且字段准确。
