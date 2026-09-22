---
name: faithsieve
description: Grade one NumOJ written mathematics submission by locating the earliest invalid proof step with independent subagents and checked symbolic or Lean evidence.
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, Task
---

# FaithSieve

批改当前工作区中的 `problem.md` 和 `submission.pdf`，最后写出 `faithsieve_result.json`。不要修改输入文件。

必须实际使用 Task 子 Agent。你作为主 Agent 只负责下面的编排、工具执行、工件传递和最终评分，不得自己包办子 Agent 的职责。派发某个角色前，读取并直接采用该角色文件中的提示词；把其中占位符换成实际路径或 ID。

子 Agent 的长结果和机器状态都写入各自提示词中已经固定的路径。每个 Task 结束后，主 Agent 从对应 JSON 文件读取并校验状态，不依赖对话返回值。若某一阶段 subagent 任务失败需要重试，请先删除原有文件，再派发新的 subagent 重试，文件还是写在原来的路径。

## 1. 提取原稿

执行：

```bash
mkdir -p faithsieve-work/{source,review,obligations,formal,results}
pdftotext -layout submission.pdf faithsieve-work/source/submission.txt
```

读取题面和提取文本。若缺页、乱码或公式明显丢失，用 `pdftoppm` 渲染相关页并结合 OCR/图像检查，整理为 `faithsieve-work/source/submission.md`；否则直接整理提取文本。不可辨认内容写 `[无法辨认]`，禁止猜测。

## 2. 拆分并审计证明

派发 [decomposer](references/agents/decomposer.md)，任务结束后读取 `faithsieve-work/results/decomposer.json`。再派发 [decomposition-auditor](references/agents/decomposition-auditor.md)，任务结束后读取 `faithsieve-work/results/decomposition-auditor.json`。

审计返回 `needs_revision` 时，把 auditor 的 `report` 发回原 decomposer 修订，再审一次。第二次仍未通过，最终结果为 `inconclusive`。

## 3. 建立并审计证明状态树

派发 [tree-builder](references/agents/tree-builder.md)，任务结束后读取 `faithsieve-work/results/tree-builder.json`。再派发 [tree-auditor](references/agents/tree-auditor.md)，任务结束后读取 `faithsieve-work/results/tree-auditor.json`。失败时返回生成者修订一次并复审；重试覆盖原 result 文件，仍失败则 `inconclusive`。

## 4. 选择检查窗口

派发 [suspicion-scanner](references/agents/suspicion-scanner.md)。它一次读取整棵树并输出 `faithsieve-work/scan.md`。任务结束后从 `faithsieve-work/results/suspicion-scanner.json` 读取：

```json
{"status":"ok|inconclusive","focus_unit":"edge_4|null","artifact":"faithsieve-work/scan.md","report":"自然语言理由"}
```

存在风险大于 `0.6` 的单元时选择最早的一个，而非最高分的一个。窗口包括焦点及之前最多六个连续 EdgeUnit。没有焦点时检查 scanner 标出的所有不确定单元；全树未发现异常也仍须进入最终综合，不能直接判正确。

## 5. 局部复核并生成义务

对窗口内每个 EdgeUnit 派发独立的 [local-reviewer](references/agents/local-reviewer.md)。派发某一条边时，把 `{edge_id}` 填为该 EdgeUnit ID，把 `{window}` 填为按原顺序排列的窗口 EdgeUnit ID 列表，再调用 Task。结束后读取 `faithsieve-work/results/<edge-id>-local-reviewer.json`。互不依赖的任务可以并行。

随后对每个 EdgeUnit 派发 [obligation-builder](references/agents/obligation-builder.md)，把 `{edge_id}` 填为当前 EdgeUnit ID 后调用 Task。结束后读取 `faithsieve-work/results/<edge-id>-obligation-builder.json`。它创建 `faithsieve-work/obligations/<edge-id>/index.md`，并把每个义务单独写成 `<edge-id>-O1.md`、`<edge-id>-O2.md`……。

义务必须检查学生实际写出的转换：新事实由旧条件推出；改写确实等价；目标化简满足“新目标足以推出旧目标”；新事实加目标化简必须先验证新事实；分类讨论检查覆盖、排除和重叠；见证必须是学生选择的同一对象。

## 6. 验证义务

从每个 `index.md` 读取义务 ID 和准确文件路径。派发 [check-object-generator](references/agents/check-object-generator.md) 时，把 `{obligation_id}` 填为当前义务 ID，`{obligation_path}` 填为该义务 Markdown 的准确路径，`{check_object_path}` 填为 `faithsieve-work/formal/<obligation-id>-check.md`。结束后读取 `faithsieve-work/results/<obligation-id>-check-object-generator.json`。

封闭数值断言派发 [numeric-evaluator](references/agents/numeric-evaluator.md)。沿用当前 `{obligation_id}`、`{obligation_path}` 和 `{check_object_path}`，把 `{numeric_result_path}` 填为 `faithsieve-work/formal/<obligation-id>-numeric.md` 后调用 Task。结束后读取 `faithsieve-work/results/<obligation-id>-numeric-evaluator.json`。

其他断言按以下顺序执行：

1. 先选择 `original`、`negation` 或 `counterexample` branch。派发 [statement-formalizer](references/agents/statement-formalizer.md) 时沿用当前 `{obligation_id}`、`{obligation_path}` 和 `{check_object_path}`，把 `{branch}` 填为所选 branch，`{statement_path}` 填为 `faithsieve-work/formal/<obligation-id>-<branch>-statement.lean`，`{diagnostics_path}` 填为同目录的 `<obligation-id>-<branch>-diagnostics.txt`；没有诊断时先创建空 diagnostics 文件。结束后读取 `faithsieve-work/results/<obligation-id>-<branch>-statement-formalizer.json`。
2. 主 Agent 用 `lean` 编译。错误 diagnostics 发回 formalizer 修订。
3. 编译成功后派发独立 [semantic-checker](references/agents/semantic-checker.md)。沿用当前 obligation ID/path、check-object path、branch 和 statement path，把 `{semantic_report_path}` 填为 `faithsieve-work/formal/<obligation-id>-<branch>-semantics.md`。结束后读取 `faithsieve-work/results/<obligation-id>-<branch>-semantic-checker.json`。存在语义漂移就返回 formalizer 修订，并重新编译、重新审计。
4. 语义审计通过后，statement 文件不再修改。派发 [proof-searcher](references/agents/proof-searcher.md) 时，把 `{obligation_id}` 填为当前义务 ID，`{branch}` 填为当前 branch，`{branch_statement_path}` 填为该 statement 文件，`{proof_path}` 填为 `faithsieve-work/formal/<obligation-id>-<branch>-proof.lean`。结束后读取 `faithsieve-work/results/<obligation-id>-<branch>-proof-searcher.json`。返回后主 Agent 确认最终文件不含 `sorry/admit/axiom`，再运行 `lean`。

验证任务统一返回：

```json
{"status":"passed|refuted|inconclusive","artifact":"工件路径","report":"工具过程、证据和诊断"}
```

## 7. 定位首错并综合

派发 [evidence-mapper](references/agents/evidence-mapper.md)，任务结束后读取 `faithsieve-work/results/evidence-mapper.json`。重新映射时覆盖同一结果文件。

若出现可靠 `refuted`，派发 [prefix-auditor](references/agents/prefix-auditor.md)。把 `{provisional_error_unit}` 填为暂定最早负面 EdgeUnit，`{prefix_units}` 填为它之前仍不确定的 EdgeUnit ID 列表。结束后读取 `faithsieve-work/results/prefix-auditor.json`。它只给出需要补查的 `candidate_units`，不自己形式验证。

派发 [final-synthesizer](references/agents/final-synthesizer.md)，结束后读取 `faithsieve-work/results/final-synthesizer.json`。再派发 [consistency-auditor](references/agents/consistency-auditor.md)，结束后读取 `faithsieve-work/results/consistency-auditor.json`。若 auditor 发现问题，把报告发回 final synthesizer 修订一次，并覆盖原结果文件。

## 8. 评分并写结果

主 Agent 根据最终综合给 0–5 整数分：

- 5：证明正确且充分。
- 4：主证明完整且核心正确，仅有不影响结论的轻微缺漏。
- 3：主思路可行，并且已经形成通向结论的主证明骨架，至少正确完成了一个对结论有决定作用的中间环节。即使存在关键缺口或错误，修复后仍可沿用学生现有的核心方法和论证路线，不需要重新构造主要证明。
- 2：包含正确的计算、引理或局部方法，但尚未形成通向结论的有效主链。最早的关键错误破坏了核心桥梁，修复时需要补入新的中心论证、改换主要策略，或者重写错误后的大部分证明。
- 1：只有少量相关观察、公式或尝试，没有建立有效推进。
- 0：没有有效进展，内容与题目无关，或核心方向根本错误。

区分 2 分和 3 分时，依次检查：学生是否提出了可行的主策略；是否正确完成了至少一个对结论有决定作用的中间环节；修复最早关键缺口后，后续论证是否能够沿现有路线继续，而不是重新发明核心证明。三项都成立才评 3 分；若只有正确片段，但核心连接仍需新思路或大幅重写，则评 2 分。不要根据答案篇幅、公式数量或表面完成度区分。

评分为 2 分或 3 分时，写入 `comment` 的批阅意见必须明确说明：学生的主证明骨架是否成立，以及修复问题属于沿原路线局部补桥，还是需要重做核心路线。

将总体判断、最早错误、影响和仍不确定之处合并成学生可读的中文 `comment`，写入工作区根目录：

```json
{"verdict":"correct|incorrect|inconclusive","score":0,"comment":"中文批阅意见"}
```

只允许 `verdict`、`score`、`comment` 三个字段。用标准 JSON 解析器重新读取确认格式。最终回复只说明文件已经写入。
