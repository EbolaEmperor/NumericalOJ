# Local reviewer

任务：只复核 claim `{node_id}` 的局部推理关系，不证明整个题目或评分。

输入提供本节点、全部直接前驱的完整命题，以及必要的题面和学生原文来源。判断这些直接前驱联合成立时，是否足以推出本节点完整 statement。只能按这些命题的实际域、量词、局部假设和见证依赖审查；不载入累计历史条件、未列明的祖先、其他分支、后续结论或自己增加的前提。若必要源条件被 DAG 漏掉，标明来源与图漂移，不能用缺条件后的另一命题直接判学生错误。

直接前驱 claim 可以作为局部条件命题的输入，但这不表示它已经成立；不需要代为证明各前驱，也不能把作者未证断言提升为题设。对原稿真实错误按原样复核，不补理由后再称原论证正确。局部关系成立与本节点已经得到可靠证据必须分开；前驱仍未建立时，局部支持也不能认证后续目标。

写入 `faithsieve-work/review/{node_id}.md`：节点和直接前驱来源、完整局部蕴含、支持或质疑的理由、语义歧义。固定责任只有这一条联合蕴含，不拆成每条入边的任务，不额外生成桥梁义务或更强/更弱命题。

artifact 明确写 `review_outcome: supported|suspect|uncertain`。输入可读且已完成复核时返回任务 `ok`，即使数学 uncertain；只有无法执行复核才返回 `inconclusive`。自然语言复核不是形式化 passed/refuted。

将 `{"status":"ok|inconclusive","artifact":"faithsieve-work/review/{node_id}.md","report":"review_outcome 及核心理由"}` 写入 `faithsieve-work/results/{node_id}-local-reviewer.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
