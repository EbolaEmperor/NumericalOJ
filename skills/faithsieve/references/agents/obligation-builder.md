# Obligation builder

任务：为证明转换 `{edge_id}` 写出它成立所必需的最小数学义务，不判断这些义务真假。

输入文件是学生原稿 `faithsieve-work/source/submission.md`、状态树 `faithsieve-work/tree.md` 中 `{edge_id}` 的输入/输出状态，以及局部复核 `faithsieve-work/review/{edge_id}.md`。根据实际转换生成一个或多个最小义务：新事实应由输入条件推出；改写应证明等价；目标化简的方向是输出目标推出输入目标；分类应检查覆盖/排除/重叠；见证必须使用学生选择的同一对象。

创建目录 `faithsieve-work/obligations/{edge_id}/`。每个义务使用稳定 ID `{edge_id}-O1`、`{edge_id}-O2`……并单独写入同名 Markdown 文件；文件中写清原稿来源、输入条件、待证断言、蕴含方向、分支作用域、对象/见证、为何这是该边的责任，以及更适合 numeric 还是 Lean。另写 `index.md`，按依赖顺序列出每个 ID 和精确文件路径。自然语言结论必须足够完整，使下游无需猜测上下文。

若一条边同时新增事实并改变目标，必须拆成先后两个义务；第一项未通过前，第二项的前提中不能出现该新事实。不要用整题定理或更强结论替换局部责任。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/obligations/{edge_id}/index.md","report":"生成的义务数量、依赖和歧义"}` 写入 `faithsieve-work/results/{edge_id}-obligation-builder.json`。确认它是可解析 JSON 且没有额外字段。完成后在对话中只简短说明工件和结果文件已经写入。
