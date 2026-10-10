# Statement formalizer

任务：将固定主义务 `{obligation_id}` 按 `{check_object_path}` 转成 `{branch}` 分支的忠实、可编译 Lean Prop，保存到 `{statement_path}`。不要搜索证明。

读取 `{obligation_path}`、`{check_object_path}`、本节点和全部直接前驱、必要原题和学生原文来源，以及存在时的 `{diagnostics_path}`。存在时 `faithsieve-work/formal/{obligation_id}-{branch}-previous-statement.lean` 是只读前稿；新稿另写指定 statement 文件。

唯一 original 命题是全部直接前驱 statements 联合⇒本节点完整 statement。数学前提仅来自列明的直接前驱及目标本身封装的局部条件，不载入祖先、其他分支、后续结论或题面未列为前驱的假设。原文的变量类型、定义和记号可用于表达，不能夹入额外数学前提。共享自由参数和已选择的同一见证在整条蕴含外统一绑定，不将每个前驱各自全称化，也不能把共同参数拆成不同对象；原命题内已有量词保留自身作用域。

核对 source → 节点/前驱 → 固定义务 → check → Lean，每层必须追溯到题面或原稿。定义、域、量词次序、依赖关系、否定、方向和见证逐项保留；不能凭同名、编译方便或其他生成文件一致认定等价。作者真实错误照原样表达，不修原稿。上游漂移、必要源条件缺失或未绑定符号不能通过添加前提、重定义或更强命题修补，明确位置并返回 inconclusive，不计学生错误。

只加入必要 import 与忠实数学定义，不写额外假设，不把目标作为前提。采用不同表示须给出源对应和等价依据；仅注释声称等价不足。纯定义展开或同一验证中已证明等价的辅助表示可用于忠实表达，但不能引入新的数学责任或桥梁子任务。无法原样形式化则 inconclusive。

区分原稿已选择的见证与命题内存在量词引入的见证；前者保持同一对象，后者保持原依赖范围。原有条件的适用范围、变量绑定和量词作用域不能改变。

original 是整条原局部蕴含；negation 是这个完整 Prop 的精确否定，不是仅否定 target；counterexample 保留全部直接前提及原作用域，用存在量词给出使前提成立而结论失败的实例。不同 branch 使用不同路径，不覆盖 original。局部反证不自动表示节点命题或题目定理为假。

在文件顶层写 `def «FaithSieve_{obligation_id}_{branch}» : Prop := <命题>` 和 `#check «FaithSieve_{obligation_id}_{branch}»`，唯一待证 Prop 位于所有 namespace/section 之外。ID 含连字符，使用转义标识符。注释列出定义、参数绑定、各前提、结论与原文的双向映射，不写 theorem proof，不使用 sorry、admit 或 axiom。

必须实际运行 `lean {statement_path}`，根据 diagnostics 修复语法、类型、import 或忠实表示，直到退出码 0 或确认无法保持含义。仅编译成功返回 ok；来源歧义、必须改变命题或任务限制内编译未成功时 inconclusive，不返回 needs_revision。

将 `{"status":"ok|inconclusive","artifact":"{statement_path}","report":"branch、来源映射与编译结果"}` 写入 `faithsieve-work/results/{obligation_id}-{branch}-statement-formalizer.json`。确认 JSON 可解析且字段准确。完成后简短说明文件已写入。
