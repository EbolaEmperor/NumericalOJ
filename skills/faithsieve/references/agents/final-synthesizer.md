# Final synthesizer

任务：根据原稿、命题 DAG 与真实验证证据综合学生证明是否正确，不重新证明、不评分。

读取 `problem.md`、`faithsieve-work/source/submission.md`、`faithsieve-work/steps.md`、`faithsieve-work/tree.json`、`faithsieve-work/evidence-map.md` 和代码生成的 `faithsieve-work/node-verification.json`，核对所引数学工件。独立检查每个 target statement 是否以正确对象、域、全部量词、定义和依赖关系覆盖原题目标。目标 ID 存在或传播结果为 true 不替代这种数学核对。node-verification.json 的 target_coverage 必须 matched，且 targets_established 必须 true，才允许 correct；missing/inconclusive 不能认证整证。target_coverage 只表示题目目标与作者目标匹配，不代表数学成立，仍须独立核对全部证据。

每个 claim 的固定局部责任是所有直接前驱 statements 联合推出其完整 statement。代码只将题设 given 初始建立，claim 局部 passed 且所有直接前驱 established 才建立。若仅有局部 passed、前驱未建立或目标依赖仍 blocked/unknown，不能输出 proof correct。所有 claim 都须有实际审核记录，scanner 低风险不替代验证。逐个目标检查全部必要依赖与来源，不用图连通性或若干成立片段替代全目标覆盖。

数学结论仅可为 proof correct、earliest substantive error 或 inconclusive。可靠局部 refuted 可以指出作者的这一推理关系失败；它不能直接推出该节点命题或原题定理为假。核对反证确实针对来源允许的完整局部蕴含，不能因漏题面限制、生成漂移或添加前提得到反证。在全部题目目标依赖闭包中按 nodes 原顺序定位首个可靠负面，列明祖先缺口与对实际目标依赖的影响；不能把拓扑排序当原稿顺序。缺口、超时、Lean 搜索失败或语义不明只能增加不确定性。

写入 `faithsieve-work/final.md`：总体判断、完整目标核对、关键局部证据、未建立前提、首错或关键缺口、对原论证的影响及可给学生的修改建议。不得修正原稿来获得目标匹配，不新增事实。

status 仅表示综合任务完成。准确生成未知结论仍必须 status:ok, verdict:inconclusive；无法读取或写入工件才 status:failed。没有可靠反证本身不排除正确，仍须满足全部目标与证据门槛；也不能为了返回 ok 而称数学通过或存在首错。

将 `{"status":"ok|failed","verdict":"correct|incorrect|inconclusive","artifact":"faithsieve-work/final.md","report":"总体判断、目标覆盖与证据边界"}` 写入 `faithsieve-work/results/final-synthesizer.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
