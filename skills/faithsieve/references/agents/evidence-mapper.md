# Evidence mapper

任务：把已有局部复核和数学工具证据完整映射到 claim 及学生原文，不重新证明或更改验证状态。

读取 `faithsieve-work/tree.json`、`faithsieve-work/steps.md`、`faithsieve-work/node-verification.json` 及指定 review、obligation、formal 工件。按 nodes 中全部 claim 的原顺序记录局部 `passed/refuted/inconclusive`、对应直接前驱和来源。没有实际证明的结果不能改成 passed；自然语言怀疑、工具失败或搜索未成功不能改成 refuted。

numeric 的局部状态以验证 Agent 对完整义务的实际结果为准；核对其证据是否覆盖完整验证责任、是否保留全部前提及目标，不能强制另一套 SymPy/表达式复验。Lean refuted 必须有独立语义审计通过的精确否定或忠实反例命题、不含 sorry/admit/axiom 的 proof，以及独立 lean 编译退出码 0。只有 statement 可编译不等于证明完成。refuted 表示该节点的联合蕴含失败，不能据此直接声称节点命题或原题定理为假。

`node-verification.json` 的 established/status/premise_ids/blocking_premise_ids 是代码传播结果：只有已审计题设初始可信，claim 必须局部 passed 且全部直接前驱 established 才建立；局部 passed 但前驱未建立仍 blocked。不得把 blocked/unknown 或若干局部 passed 夸大为整证认证。target_coverage 独立表示原题目标覆盖，missing/inconclusive 时即使图中全部目标 established 也不能认证题目；不得改写宿主覆盖状态。

写入 `faithsieve-work/evidence-map.md`，完整列出每个 claim 的局部证据、代码传播状态与对应原稿。在全部 target_ids 的依赖闭包中给出按 nodes 原顺序最早的可靠 refuted 节点；同时列出该闭包中尚未 established 的全部 claim，包括目标自身。它们是依赖缺口，不是连续步骤前缀，也不因此重新生成或复查已完成任务。没有可靠负面时写 null，仍如实说明目标依赖中的未解决范围。

status 表示映射任务是否完成。可完整读取并对齐所有 claim 时返回 ok，即使全部局部 inconclusive、没有可靠负面或目标未建立；只有证据无法对齐、不能形成完整映射时返回 inconclusive。不要为得到首错而改写状态。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/evidence-map.md","report":"完整映射、可靠负面及依赖缺口"}` 写入 `faithsieve-work/results/evidence-mapper.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
