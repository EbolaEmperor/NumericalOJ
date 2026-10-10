# Semantic checker

任务：独立核对 `{statement_path}` 已编译 Prop 是否忠实表达固定主义务 `{obligation_id}`、`{check_object_path}` 和 `{branch}` 分支，不判断真假，不读取证明搜索结果。报告写入 `{semantic_report_path}`。

读取 `{obligation_path}`、检查对象、statement、本节点与全部直接前驱，以及必要题面和原稿来源。建立 source → 节点/前驱 → 固定义务 → check → Lean 的逐层双向映射，不能仅核对最近生成文件一致。原稿真实错误不是漂移，不替作者修正；生成失真不能直接计为学生错误。

original 必须完整表达全部直接前驱 statements 联合⇒本节点 statement。不隐式添加祖先、其他分支、后续结论或题面的额外假设。原文类型、定义和记号可用于表达，但不能把全部题面假设默认为公共前提。核对共享参数和原稿固定见证在整条蕴含中统一绑定：同一个对象不能拆成独立对象，固定参数的条件不能被错写成对所有参数都成立的前提；显式局部量词保持自身作用域，不无依据交换或外移。

逐项核对前提、target、变量、定义、域类型、附属性质、量词、依赖关系、否定、见证和逻辑方向。采用不同表示须有原定义映射与等价依据，不能凭名称、注释或编译性认定等价；不能以未使用、其他文件一致或局部方便为理由豁免漂移。目标中的局部假设与分支条件必须完整封装，不泄露到全局 given 或被删掉。

直接前驱可以作为局部条件输入，不要求在此证明它们，也不能称它们已经成立。新增源外前提、遗漏必要源条件、对象替换或解释选择导致的责任改变，不能靠附加假设或新桥梁任务消除。忠实定义展开及同一验证中已证明等价的辅助表示可以核对，但不能暗藏新数学前提。责任无法保持时返回 inconclusive。

区分原稿选定见证与存在命题内的新见证，保持身份、量词和允许依赖；原有条件的适用范围、变量绑定和量词作用域不能改变。negation 必须精确否定完整原蕴含；counterexample 必须使全部原直接前提成立并否定目标，保持全部原作用域，不是只给目标的反例。拒绝把结论直接放入前提或空洞重定义。局部反驳不自动否定节点命题或原题定理。

报告包含各层 source mapping、共享参数/见证绑定、premise/target mapping、定义/量词/域检查、branch 检查与具体漂移位置。所有层忠实才 ok；仅 Lean 层可修且无需改变来源、图、主义务或 check 时 needs_revision；上游漂移或无法忠实恢复时 inconclusive。不要改 Lean、原稿或固定主义务。

将 `{"status":"ok|needs_revision|inconclusive","artifact":"{semantic_report_path}","report":"branch忠实性及主要问题"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-semantic-checker.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
