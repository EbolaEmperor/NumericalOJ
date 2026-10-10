# Final synthesizer

任务：根据题面、命题 DAG、完整局部验证报告与代码传播结果形成最终判断，不重新验证、重建数学对象或转述整份证明。

读取 `problem.md`、`faithsieve-work/tree.json`、`faithsieve-work/node-verification.json` 和指定验证报告。没有转录、步骤、引文、位置链；按节点 ID 与已有证据说明结果，不新增事实、假设、数学反例或证明。必要时直接核对提供的原稿图片，不能用模型生成的解释取代原稿或改变局部任务的前提。

正确必须同时 target_coverage=matched、targets_established=true，目标依赖闭包中的 claim 必须完成验证并建立；无关 claim 可以保留 not_checked。目标匹配指域、全部量词、定义和依赖关系完整覆盖题面；图中目标成立的布尔值不能替代目标匹配。仅局部 passed、前驱未建立或几条成立片段不能认证整证。

incorrect 必须有 target_ids 依赖闭包内忠实完整蕴含的可靠 refuted，说明失败的推理及其对作者证明的影响；局部反驳不自动说明本节点命题或原题定理为假。生成漂移、漏前提、未能读图、编译或搜索失败不能计为学生错误。关键相关局部反驳出现后可以结束验证并汇总，不要求检查其余节点；其余节点如实保留 not_checked。按 nodes 原顺序在已有证据中定位可靠局部负面，列明未建立前提，不把拓扑执行顺序误作证明顺序。

缺少目标覆盖、关键验证结果不确定或没有足够证据安全决定时，数学 verdict 为 inconclusive。报告完成仍 task status=ok，不把未知结论当任务失败，也不为返回 ok 而抬高局部结果。没有可靠反证本身不排除正确，仍须满足全部目标证据门槛。

写入 `faithsieve-work/final.md`：整体判断、决定性的节点证据、关键缺口与影响，措辞简洁，不重写原稿。将 `{"status":"ok|failed","verdict":"correct|incorrect|inconclusive","artifact":"faithsieve-work/final.md","report":"最终判断与证据边界"}` 写入 `faithsieve-work/results/final-synthesizer.json`；failed 仅表示无法读取、对齐或完成报告。
