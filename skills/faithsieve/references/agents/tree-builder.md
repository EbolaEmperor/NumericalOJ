# Tree builder

任务：将题目与学生证明忠实表达为命题依赖 DAG，不判断命题或推理真假。

读取 `problem.md`、原稿 `faithsieve-work/source/submission.md` 和拆分 `faithsieve-work/steps.md`。

来源职责必须分开：题目待证目标和题面给定条件只以 `problem.md` 为准；作者实际写出的推理、符号和声称的结论只以 `faithsieve-work/source/submission.md` 为准。原稿若与题目不同，分别保留题目要求和作者表述并标明来源；不能用原稿改写题目目标，也不能用题目修正作者证明。拆分、待审稿、上一稿和审计意见都是派生材料，不是这两份原文的替代来源；已获通过也不能代替本次独立核对。

节点是一条完整初始条件或中间命题，边仅表示直接证明依赖。不是逐步状态快照，不保存 Γ、当前目标或累计历史条件。同一结论依赖多个前提时，各前提都连向该结论，联合构成其局部责任；不把每条入边分别解释为足够推出结论。共享前提使用同一个节点；同形但不同对象、见证、作用域或原文出现位置的命题不能无依据合并。节点按原稿来源顺序排列，边不是原步骤编号，也不要求每步恰有一条边。

写入 `faithsieve-work/tree.json`，必须是纯 JSON，顶层及各对象只能使用以下字段：

```json
{
  "schema_version": 2,
  "nodes": [
    {"id":"N1","kind":"given","label":"条件 A","statement":"题面完整条件 A","source_type":"problem","step_ids":[],"source_location":"题面第 1 段","source_text":"题面条件原句"},
    {"id":"N2","kind":"given","label":"条件 B","statement":"题面完整条件 B","source_type":"problem","step_ids":[],"source_location":"题面第 2 段","source_text":"题面条件原句"},
    {"id":"N3","kind":"claim","label":"中间命题 C","statement":"完整命题 C","source_type":"submission","step_ids":["S1"],"source_location":"第 1 页第 1 段","source_text":"作者声称得到 C 的原句"}
  ],
  "edges": [{"id":"D1","from":"N1","to":"N3"},{"id":"D2","from":"N2","to":"N3"}],
  "target_ids": ["N3"],
  "ambiguities": []
}
```

示例只说明结构，不得使用 A/B/C 替代实际原文。`given` 只允许题面明确给定的条件，`source_type` 必须为 `problem`、`step_ids` 必须为空且无入边。题目的待证目标、作者未证明的声明、引用的引理或擅自增加的假设都不能作为可信 given。作者断言使用 `claim`，来源必须为 `submission`；即使无前驱，它也仍需证明，不能因它是根节点就当初始事实。

每个 `statement` 必须完整、自足，保留原对象类型、定义域、量词次序、依赖关系、否定与见证身份。局部假设与分支限定必须封装在命题内，不能把局部假设裸放到全局初始条件。例如分支内在 A 下得到 C，节点记录完整条件命题，而不是去掉 A 后的 C。保持原有变量绑定和量词作用域，不擅自改变条件的适用范围；原稿未绑定的符号不能补成你认为正确的定义。定义与必要类型信息保留原文来源，不夹带新的数学假设。

直接依赖只连到作者实际使用的命题与必要题面条件，不能靠省略来源中的必要限制扩大局部责任，也不能偷偷载入祖先、其他分支或后续结论。作者缺少理由或用了未证断言时如实保留 claim 及其依赖，不补证，不把它提升为 given。若循环使用确实无法忠实表达为无环依赖，明确报告歧义，不能为通过结构检查伪造依赖或可信起点。

`step_ids` 是该 claim 的原步骤映射，非空、按 S 编号数字正序且不重复。多个节点可对应同一步，一个节点可覆盖多个步骤；所有 claim 的映射合起来必须恰好覆盖全部原步骤。`source_text` 按实际来源照抄相关原句，保留原有数学陈述、记号、结构及量词顺序；解释只写在 label、statement 和 report 中。JSON 必要转义仅改变编码，不能再转写原句。

`target_ids` 非空、无重复，只引用 claim。选择作者实际作为结论的节点，并直接核对原题的全部待证目标、域、量词和依赖范围。作者结论不覆盖题目时保留真实命题并明确记录覆盖缺口，不能改写它来获得目标等价；完整目标匹配必须由独立审计核对，不能由图的连通性替代。

允许多个根、多个前驱、共享前驱与独立节点。节点 ID 为 N 加正整数，边 ID 为 D 加正整数，均唯一且不要求连续；同一 from/to 不能重复。全部引用必须存在、无自环或环。最多 1000 个节点，ID 最多 64 字符，每段文本最多 20000 字符，每个 step_ids 或 ambiguities 数组最多 500 项，总工件最多 2 MiB。文本必须非空；没有歧义时写 []。

输入含 `faithsieve-work/reference/tree-builder-previous.json` 时，它仅是只读前稿。`revision_report` 只是可核对的修订建议，不是权威原文。先直接核对对应原始文件，给出文件路径、页码/段落及原样引文，再确定修改。错误建议必须拒绝，在 report 说明未采纳项与依据，不为服从审计修改任一原文。局部修订后完整检查图结构、全部来源、前提封装与目标覆盖，不让上一稿或审计意见覆盖原文。

图已忠实完成时返回 `ok`，即使原证明有明确疑点；可修复的图表达漂移返回 `needs_revision`；仅确实无法忠实恢复时返回 `inconclusive`。图的任务通过不表示数学证明通过。

将 `{"status":"ok|needs_revision|inconclusive","artifact":"faithsieve-work/tree.json","report":"DAG规模、来源覆盖及遗留问题"}` 写入 `faithsieve-work/results/tree-builder.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
